import pathlib
import tempfile
import unittest

from cloudquota import budget, cluster_transfer as ct, loan, reserve
from cloudquota.store import one, open_db, report, rows, verify_replay


class ClusterTransferTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = open_db(str(pathlib.Path(self.tmp.name) / "transfer.sqlite"))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    # ------------------------------------------------------------------ fixtures

    def _fixed_scene(self):
        """Tenant T at cluster甲 (alpha): budget 8/8, started A(4), unstarted B(2, lease to 40).
        A loan of 2 from another tenant matures at 25. Cluster乙 (beta) has two nodes in
        distinct failure domains. Transfer request arrives at 10, beta ack at 12."""
        budget.revise(self.db, "bT", "T", 8, 8, 1, 0)
        budget.revise(self.db, "bL", "lender", 10, 10, 1, 0)
        loan.offer(self.db, "o", "lender", 4, 4, 2, 2, 30)
        self.assertEqual(loan.issue(self.db, "iL", "L", "o", "T", 2, 2, 25, 5), "issued")
        # alpha nodes (single-cluster ledger) and beta proven nodes
        reserve.node(self.db, "na", "z-a1", 8, 8)
        reserve.node(self.db, "na2", "z-a2", 8, 8)
        ct.register_cluster(self.db, "alpha", 1, 9)
        ct.register_cluster(self.db, "beta", 1, 9)
        ct.register_node(self.db, "bn1", "beta", "z-b1", 4, 4, 1)
        ct.register_node(self.db, "bn2", "beta", "z-b2", 4, 4, 1)
        # replica A: 4/4, started; replica B: 2/2 interruptible, unstarted, lease to 40
        reserve.request(self.db, "wA", "T", "svc", 4, 4)
        reserve.request(self.db, "wB", "T", "svc", 2, 2, interruptible=True)
        self.assertEqual(reserve.place(self.db, "pA", "rA", "wA", 60, 6), "reserved:na")
        self.assertTrue(reserve.place(self.db, "pB", "rB", "wB", 40, 7).startswith("reserved"))
        self.assertEqual(loan.allocate(self.db, "rA", 6), "budget:T")
        self.assertEqual(loan.allocate(self.db, "rB", 7), "budget:T")
        self.assertEqual(reserve.start(self.db, "sA", "rA", 1, 8), "started")
        # budget lot for T at alpha and a loan lot that must stay distinct
        self.assertEqual(ct.register_lot(self.db, "e1", "lot-budget", "alpha", "T",
                                         "budget", 8, 8, 0, 60, "T", 9), "accepted")
        self.assertEqual(ct.register_lot(self.db, "e2", "lot-loan", "alpha", "T",
                                         "loan", 2, 2, 5, 25, "L", 9), "accepted")

    def _request(self, transfer_id="X1", displaces="rB"):
        return ct.request_transfer(
            self.db, "req1", transfer_id, "T", "alpha", "beta", "lot-budget", 2, 2,
            valid_from=10, valid_until=35, deadline=20, at=10,
            replica="C", displaces_reservation=displaces)

    # ------------------------------------------------------------------ path 1

    def test_path1_customer_release_moves_idle_budget_and_delivers_C_before_deadline(self):
        self._fixed_scene()
        self.assertEqual(self._request(), "requested")
        # B's start receipt may be late: before it arrives, customer signs the release.
        self.assertEqual(ct.customer_signoff(self.db, "sg1", "so1", "X1", "rB", "released", 11),
                         "released")
        self.assertEqual(ct.prepare_source(self.db, "pr1", "X1", ["rB"], 11),
                         "source_prepared")
        # B's seat is returned and the late start receipt must be rejected.
        self.assertEqual(one(self.db, "SELECT released FROM reservations WHERE id='rB'")["released"], 1)
        self.assertEqual(reserve.start(self.db, "sBlate", "rB", 1, 13), "late_or_stale")
        # A keeps running on alpha against the original entitlement.
        self.assertEqual(one(self.db, "SELECT started,released FROM reservations WHERE id='rA'"),
                         {"started": 1, "released": 0})
        # beta ack at 12
        self.assertEqual(ct.target_ack(self.db, "ack1", "X1", True, 12), "committed")
        self.assertEqual(ct.start_delivery(self.db, "d1", "X1", 15), "delivered_on_time")
        outcome = ct.customer_outcome(self.db, "X1")
        self.assertEqual(outcome["state"], "delivered")
        self.assertEqual(len(outcome["delivered"]), 1)
        d = outcome["delivered"][0]
        self.assertEqual((d["replica"], d["cluster"], d["on_time"]), ("C", "beta", True))
        # B only ever receives a withdrawal notice; its promise was not silently deleted.
        kinds = [n[0] for n in outcome["notices"]]
        self.assertIn("replica_withdrawn", kinds)
        self.assertEqual(len(outcome["withdrawn"]), 0)
        # Source budget lot shrank; the loan lot is untouched and still traceable.
        lot = one(self.db, "SELECT * FROM cluster_lots WHERE id='lot-budget'")
        self.assertEqual((lot["cpu"], lot["mem"], lot["status"]), (6, 6, "active"))
        loan_lot = one(self.db, "SELECT * FROM cluster_lots WHERE id='lot-loan'")
        self.assertEqual(loan_lot["status"], "active")
        self.assertEqual(loan_lot["due"], 25)
        # beta holds the promised budget entitlement, not a blend with the loan.
        dst = one(self.db, "SELECT * FROM cluster_lots WHERE id='X1:dst_lot'")
        self.assertEqual((dst["kind"], dst["status"], dst["origin_cluster"]),
                         ("budget", "active", "alpha"))
        self.assertEqual(one(self.db, "SELECT source_kind,source_id FROM funding WHERE reservation_id='rA'"),
                         {"source_kind": "budget", "source_id": "T"})

    def test_duplicate_beta_ack_and_reordered_messages_commit_once(self):
        self._fixed_scene()
        self._request()
        ct.customer_signoff(self.db, "sg1", "so1", "X1", "rB", "released", 11)
        ct.prepare_source(self.db, "pr1", "X1", ["rB"], 11)
        # Ack from beta arrives twice (retry); the redelivered envelope is identical.
        self.assertEqual(ct.target_ack(self.db, "ack1", "X1", True, 12), "committed")
        self.assertEqual(ct.target_ack(self.db, "ack1", "X1", True, 12), "committed")
        with self.assertRaises(ValueError):
            ct.target_ack(self.db, "ack1", "X1", False, 12)  # same id, different payload
        # Late prepare after commit replays the original recorded verdict, no new rows.
        self.assertEqual(ct.prepare_source(self.db, "pr1", "X1", ["rB"], 11), "source_prepared")
        self.assertEqual(len(rows(self.db, "SELECT * FROM transfer_earmarks WHERE transfer_id='X1'")), 1)
        self.assertEqual(len(rows(self.db, "SELECT * FROM transfer_seats WHERE transfer_id='X1'")), 1)

    # ------------------------------------------------------------------ path 2

    def test_path2_started_B_blocks_transfer_fallback_purchase_delivers_by_30_with_compensation(self):
        self._fixed_scene()
        self._request()
        # B's start receipt wins the race against the release signature.
        self.assertEqual(reserve.start(self.db, "sB", "rB", 1, 11), "started")
        self.assertEqual(ct.customer_signoff(self.db, "sg1", "so1", "X1", "rB", "released", 12),
                         "released")
        self.assertEqual(ct.prepare_source(self.db, "pr1", "X1", ["rB"], 12),
                         "source_reservation_committed")
        self.assertEqual(one(self.db, "SELECT released FROM reservations WHERE id='rB'")["released"], 0)
        # The failed transfer must not masquerade as success.
        self.assertEqual(one(self.db, "SELECT state FROM transfers WHERE id='X1'")["state"], "requested")
        # Operator keeps A and B at alpha and covers C with an independent new purchase.
        self.assertEqual(ct.fallback_purchase(
            self.db, "fp1", "X1", "lot-new", 2, 2, valid_until=35, at=22,
            replica="C", node_id="bn1"), "fallback_purchased")
        self.assertEqual(ct.start_purchase(self.db, "sp1", "X1", 28),
                         "purchased_after_missed_deadline")
        outcome = ct.customer_outcome(self.db, "X1")
        self.assertEqual(outcome["state"], "fallback_delivered")
        self.assertEqual(outcome["delivered"][0]["on_time"], False)
        self.assertEqual(outcome["delivered"][0]["cluster"], "beta")
        bill_kinds = {b[0] for b in outcome["billing"]}
        self.assertEqual(bill_kinds, {"compensation", "purchase"})
        self.assertNotIn("transfer", bill_kinds)
        new_lot = one(self.db, "SELECT * FROM cluster_lots WHERE id='lot-new'")
        self.assertEqual((new_lot["kind"], new_lot["origin_cluster"]), ("purchase", None))
        # Original budget lot never moved; both alpha replicas remain.
        self.assertEqual(one(self.db, "SELECT cpu FROM cluster_lots WHERE id='lot-budget'")["cpu"], 8)
        self.assertEqual(len(rows(self.db, "SELECT * FROM reservations WHERE released=0")), 2)

    def test_customer_refusal_routes_to_fallback_and_keeps_alpha_promises(self):
        self._fixed_scene()
        self._request()
        self.assertEqual(ct.customer_signoff(self.db, "sg1", "so1", "X1", "rB", "refused", 11),
                         "refused")
        self.assertEqual(ct.prepare_source(self.db, "pr1", "X1", ["rB"], 11),
                         "customer_refused_release")
        self.assertEqual(ct.fallback_purchase(self.db, "fp1", "X1", "lot-new", 2, 2, 35, 21,
                                              replica="C"), "fallback_purchased")
        self.assertEqual(ct.start_purchase(self.db, "sp1", "X1", 29),
                         "purchased_after_missed_deadline")
        self.assertEqual(one(self.db, "SELECT released FROM reservations WHERE id='rB'")["released"], 0)
        notices = [n[0] for n in ct.customer_outcome(self.db, "X1")["notices"]]
        self.assertIn("deadline_missed", notices)

    # ------------------------------------------------------------------ loan/budget separation

    def test_loan_cannot_be_blended_into_budget_transfer_and_dies_at_due(self):
        self._fixed_scene()
        # Asking the budget lot for 4 free units while only 2 are idle fails explicitly.
        big = ct.request_transfer(self.db, "reqBig", "XB", "T", "alpha", "beta",
                                  "lot-budget", 4, 4, 10, 35, 20, 10)
        self.assertEqual(big, "requested")
        self.assertEqual(ct.prepare_source(self.db, "prB", "XB", [], 11),
                         "uncommitted_reservation_blocks")
        # A loan lot may move only inside the loan maturity; window past due is rejected.
        bad = ct.request_transfer(self.db, "reqLoan", "XL", "T", "alpha", "beta",
                                  "lot-loan", 2, 2, 10, 26, 20, 10)
        self.assertEqual(bad, "window_exceeds_loan_due")
        ok = ct.request_transfer(self.db, "reqLoan2", "XL2", "T", "alpha", "beta",
                                 "lot-loan", 2, 2, 10, 25, 27, 10)
        self.assertEqual(ok, "requested")
        # The loan matures at 25; once the window has passed, no new commitment can use it.
        self.assertEqual(ct.prepare_source(self.db, "prL", "XL2", [], 25), "loan_expired")
        # Lender floor and due date remain attached to the loan original.
        offer = one(self.db, "SELECT floor_cpu,floor_mem,until_ts FROM offers WHERE id='o'")
        self.assertEqual((offer["floor_cpu"], offer["floor_mem"], offer["until_ts"]), (2, 2, 30))
        loan_row = one(self.db, "SELECT due FROM loans WHERE id='L'")
        self.assertEqual(loan_row["due"], 25)

    def test_budget_revision_down_between_request_and_prepare_is_rejected(self):
        self._fixed_scene()
        self._request()
        ct.customer_signoff(self.db, "sg1", "so1", "X1", "rB", "released", 11)
        # Operator cuts T's basic budget below the registered lot; transfer cannot proceed.
        self.assertEqual(budget.revise(self.db, "bT2", "T", 5, 5, 2, 11), "overcommitted")
        self.assertEqual(ct.prepare_source(self.db, "pr1", "X1", ["rB"], 11), "budget_reduced")
        self.assertEqual(one(self.db, "SELECT state FROM transfers WHERE id='X1'")["state"], "requested")

    # ------------------------------------------------------------------ interleaving / loss / retries

    def test_release_signoff_must_exist_before_prepare_and_late_one_is_kept(self):
        self._fixed_scene()
        self._request()
        # No signature yet: prepare parks the saga instead of taking the seat.
        self.assertEqual(ct.prepare_source(self.db, "pr0", "X1", ["rB"], 11),
                         "awaiting_customer_release")
        self.assertEqual(ct.customer_signoff(self.db, "sg1", "so1", "X1", "rB", "released", 12),
                         "released")
        # Signature dated after the prepare moment cannot be used retroactively.
        self.assertEqual(ct.prepare_source(self.db, "pr1", "X1", ["rB"], 11),
                         "awaiting_customer_release")
        self.assertEqual(ct.prepare_source(self.db, "pr2", "X1", ["rB"], 12),
                         "source_prepared")
        # Cancel the saga, then a further signature arrives: retained as late evidence.
        self.assertEqual(ct.cancel_transfer(self.db, "cc1", "X1", 13, "beta link down"), "cancelled")
        self.assertEqual(ct.customer_signoff(self.db, "sglate", "so2", "X1", "rB", "released", 14),
                         "late_signoff_kept")
        kept = one(self.db, "SELECT verdict FROM transfer_signoffs WHERE id='so2'")["verdict"]
        self.assertEqual(kept, "late:released")
        # Earmark and seat were rolled back; nothing is promised at beta.
        self.assertEqual(one(self.db, "SELECT status FROM transfer_earmarks WHERE transfer_id='X1'")["status"],
                         "released")
        self.assertEqual(one(self.db, "SELECT status FROM transfer_seats WHERE transfer_id='X1'")["status"],
                         "released")
        self.assertEqual(one(self.db, "SELECT status FROM cluster_lots WHERE id='X1:dst_lot'")["status"],
                         "void")

    def test_lost_beta_ack_keeps_saga_resumable_without_double_promise(self):
        self._fixed_scene()
        self._request()
        ct.customer_signoff(self.db, "sg1", "so1", "X1", "rB", "released", 11)
        ct.prepare_source(self.db, "pr1", "X1", ["rB"], 11)
        # Ack is lost (no call made). Re-delivery with the same event id later resumes;
        # meanwhile a second transfer for the same remaining budget must still see the hold.
        other = ct.request_transfer(self.db, "req2b", "X2", "T", "alpha", "beta",
                                    "lot-budget", 2, 2, 11, 30, 20, 11)
        self.assertEqual(other, "requested")
        # Only 6/6 remain after the 2-unit hold... X2 would need another B-like release;
        # with rB already released and no other unstarted lot-funded reservations, headroom
        # is exactly 6 so it can prepare on a different node seat.
        self.assertEqual(ct.prepare_source(self.db, "pr2", "X2", [], 12), "source_prepared")
        self.assertEqual(len(rows(self.db, "SELECT * FROM transfer_earmarks WHERE status='held'")), 2)
        # Both acks land in reverse order (X2 first); each commits its own units only.
        self.assertEqual(ct.target_ack(self.db, "ack2", "X2", True, 12), "committed")
        self.assertEqual(ct.target_ack(self.db, "ack1", "X1", True, 12), "committed")
        lot = one(self.db, "SELECT * FROM cluster_lots WHERE id='lot-budget'")
        self.assertEqual((lot["cpu"], lot["mem"], lot["status"]), (4, 4, "active"))
        # No entitlement unit is promised on both legs: sum of earmarks equals removed units.
        e = rows(self.db, "SELECT * FROM transfer_earmarks WHERE status='committed'")
        self.assertEqual(sum(x["cpu"] for x in e), 4)

    def test_retry_request_is_idempotent_and_never_creates_a_second_saga(self):
        self._fixed_scene()
        self.assertEqual(self._request(), "requested")
        self.assertEqual(self._request(), "requested")
        self.assertEqual(len(rows(self.db, "SELECT * FROM transfers")), 1)
        with self.assertRaises(ValueError):
            ct.request_transfer(self.db, "req1", "X1", "T", "alpha", "beta",
                                "lot-budget", 3, 3, 10, 35, 20, 10)  # same id, other size

    # ------------------------------------------------------------------ capacity proofs / shrink

    def test_source_and_target_proof_generation_changes_abort_the_transfer(self):
        self._fixed_scene()
        self._request()
        ct.customer_signoff(self.db, "sg1", "so1", "X1", "rB", "released", 11)
        # Source cluster re-proves with a new generation before prepare.
        ct.register_cluster(self.db, "alpha", 2, 11)
        self.assertEqual(ct.prepare_source(self.db, "pr1", "X1", ["rB"], 11),
                         "source_capacity_stale")
        ct.register_cluster(self.db, "alpha", 1, 11)  # older proof is stale
        self.assertEqual(ct.register_cluster(self.db, "alpha", 3, 12), "accepted")
        # Rebuild a fresh saga pinned to the new source proof.
        self.assertEqual(ct.request_transfer(self.db, "req2", "X3", "T", "alpha", "beta",
                                             "lot-budget", 2, 2, 12, 35, 20, 12), "requested")
        self.assertEqual(ct.customer_signoff(self.db, "sg2", "so3", "X3", "rB", "released", 12),
                         "released")
        self.assertEqual(ct.prepare_source(self.db, "pr3", "X3", ["rB"], 12), "source_prepared")
        # Destination node shrinks (new generation, smaller box) before the ack.
        self.assertEqual(ct.register_node(self.db, "bn1", "beta", "z-b1", 1, 1, 2), "accepted")
        self.assertEqual(ct.target_ack(self.db, "ack3", "X3", True, 13), "target_capacity_lost")
        self.assertEqual(one(self.db, "SELECT state FROM transfers WHERE id='X3'")["state"],
                         "failed_target")
        # Rolled back: the source lot is whole again and the promised lot is void.
        self.assertEqual(one(self.db, "SELECT cpu,status FROM cluster_lots WHERE id='lot-budget'"),
                         {"cpu": 8, "status": "active"})
        self.assertEqual(one(self.db, "SELECT status FROM cluster_lots WHERE id='X3:dst_lot'")["status"],
                         "void")
        self.assertEqual(one(self.db, "SELECT status FROM transfer_seats WHERE transfer_id='X3'")["status"],
                         "released")

    def test_beta_without_seat_cannot_announce_acceptance(self):
        self._fixed_scene()
        self._request()
        ct.customer_signoff(self.db, "sg1", "so1", "X1", "rB", "released", 11)
        # Shrink both beta nodes under the 2/2 requirement before prepare.
        ct.register_node(self.db, "bn1", "beta", "z-b1", 1, 1, 2)
        ct.register_node(self.db, "bn2", "beta", "z-b2", 1, 1, 2)
        self.assertEqual(ct.prepare_source(self.db, "pr1", "X1", ["rB"], 11),
                         "target_no_capacity")
        self.assertEqual(one(self.db, "SELECT state FROM transfers WHERE id='X1'")["state"],
                         "failed_target")
        self.assertEqual(ct.start_delivery(self.db, "d1", "X1", 15), "failed_target")

    def test_two_beta_failure_domains_are_actually_available_for_c(self):
        self._fixed_scene()
        self._request()
        ct.customer_signoff(self.db, "sg1", "so1", "X1", "rB", "released", 11)
        ct.prepare_source(self.db, "pr1", "X1", ["rB"], 11)
        seat = one(self.db, "SELECT * FROM transfer_seats WHERE transfer_id='X1'")
        self.assertIn(seat["zone"], ("z-b1", "z-b2"))
        # The other domain stays free for an independent placement.
        free = {n["id"]: ct._node_free(self.db, n["id"])
                for n in rows(self.db, "SELECT * FROM cluster_nodes")}
        other = "bn2" if seat["node_id"] == "bn1" else "bn1"
        self.assertGreaterEqual(free[other][0], 2)

    # ------------------------------------------------------------------ guarantees

    def test_same_entitlement_cannot_be_promised_on_both_sides(self):
        self._fixed_scene()
        self._request()
        ct.customer_signoff(self.db, "sg1", "so1", "X1", "rB", "released", 11)
        ct.prepare_source(self.db, "pr1", "X1", ["rB"], 11)
        # While prepared, the earmark is excluded from alpha's redeemable view.
        alpha = ct.cluster_entitlement(self.db, "alpha", "T", 12)
        self.assertEqual((alpha["budget"]["cpu"], alpha["budget"]["mem"]), (6, 6))
        beta = ct.cluster_entitlement(self.db, "beta", "T", 12)
        self.assertNotIn("budget", beta)  # promised, not yet active
        ct.target_ack(self.db, "ack1", "X1", True, 12)
        beta = ct.cluster_entitlement(self.db, "beta", "T", 13)
        self.assertEqual((beta["budget"]["cpu"], beta["budget"]["mem"]), (2, 2))
        alpha = ct.cluster_entitlement(self.db, "alpha", "T", 13)
        self.assertEqual((alpha["budget"]["cpu"], alpha["budget"]["mem"]), (6, 6))
        self.assertEqual(alpha["loan"]["cpu"], 2)  # loan remains a separate kind

    def test_cancel_after_delivery_keeps_received_result_and_original_confirmations(self):
        self._fixed_scene()
        self._request()
        ct.customer_signoff(self.db, "sg1", "so1", "X1", "rB", "released", 11)
        ct.prepare_source(self.db, "pr1", "X1", ["rB"], 11)
        ct.target_ack(self.db, "ack1", "X1", True, 12)
        ct.start_delivery(self.db, "d1", "X1", 15)
        self.assertEqual(ct.cancel_transfer(self.db, "cc1", "X1", 16, "rollback request"),
                         "delivered")
        outcome = ct.customer_outcome(self.db, "X1")
        self.assertEqual(len(outcome["delivered"]), 1)
        self.assertEqual(outcome["delivered"][0]["delivered_at"], 15)
        # Original notices and sign-offs are append-only evidence.
        self.assertGreaterEqual(len(outcome["notices"]), 2)
        self.assertEqual(len(outcome["signoffs"]), 1)

    def test_invalid_inputs_never_create_commitments(self):
        self._fixed_scene()
        self.assertEqual(ct.register_cluster(self.db, "", 1, 0), "invalid_proof")
        self.assertEqual(ct.register_node(self.db, "x", "beta", "z", -1, 1, 1), "invalid_capacity")
        self.assertEqual(ct.request_transfer(self.db, "bad", "X", "T", "alpha", "alpha",
                                             "lot-budget", 2, 2, 10, 35, 20, 10),
                         "same_cluster_transfer")
        self.assertEqual(ct.customer_signoff(self.db, "badsg", "so", "X1", "rB", "maybe", 1),
                         "invalid_signoff")
        self.assertIsNone(one(self.db, "SELECT * FROM clusters WHERE id=''"))
        self.assertIsNone(one(self.db, "SELECT * FROM transfers WHERE id='X'"))

    def test_late_committed_delivery_is_kept_and_billed_with_compensation(self):
        self._fixed_scene()
        self._request()
        ct.customer_signoff(self.db, "sg1", "so1", "X1", "rB", "released", 11)
        ct.prepare_source(self.db, "pr1", "X1", ["rB"], 11)
        ct.target_ack(self.db, "ack1", "X1", True, 12)
        # The committed transfer cannot be un-promised; a late start still lands, with a credit.
        self.assertEqual(ct.start_delivery(self.db, "d1", "X1", 24), "delivered_late")
        outcome = ct.customer_outcome(self.db, "X1")
        self.assertEqual(outcome["delivered"][0]["on_time"], False)
        self.assertEqual(outcome["delivered"][0]["delivered_at"], 24)
        kinds = {b[0] for b in outcome["billing"]}
        self.assertEqual(kinds, {"transfer", "compensation"})
        # Replaying the delivery event returns the original verdict, never a second row.
        self.assertEqual(ct.start_delivery(self.db, "d1", "X1", 24), "delivered_late")
        self.assertEqual(len(rows(self.db, "SELECT * FROM transfer_billing WHERE transfer_id='X1'")), 2)

    def test_fallback_purchase_without_beta_seat_leaves_no_phantom_entitlement(self):
        self._fixed_scene()
        self._request()
        ct.customer_signoff(self.db, "sg1", "so1", "X1", "rB", "refused", 11)
        ct.prepare_source(self.db, "pr1", "X1", ["rB"], 11)
        for nid in ("bn1", "bn2"):
            ct.register_node(self.db, nid, "beta", "z", 1, 1, 2)
        self.assertEqual(ct.fallback_purchase(self.db, "fp1", "X1", "lot-new", 2, 2, 35, 22,
                                              replica="C"), "target_no_capacity")
        self.assertIsNone(one(self.db, "SELECT * FROM cluster_lots WHERE id='lot-new'"))
        self.assertEqual(one(self.db, "SELECT state FROM transfers WHERE id='X1'")["state"], "requested")

    def test_audit_report_replays_every_transfer_mutation(self):
        self._fixed_scene()
        self._request()
        ct.customer_signoff(self.db, "sg1", "so1", "X1", "rB", "released", 11)
        ct.prepare_source(self.db, "pr1", "X1", ["rB"], 11)
        ct.target_ack(self.db, "ack1", "X1", True, 12)
        ct.start_delivery(self.db, "d1", "X1", 15)
        state = report(self.db)
        self.assertTrue(verify_replay(self.db)["consistent"])
        for name in ("clusters", "cluster_nodes", "cluster_lots", "transfers",
                     "transfer_earmarks", "transfer_seats", "transfer_signoffs",
                     "transfer_deliveries", "transfer_notices", "transfer_billing"):
            self.assertIn(name, state)
            self.assertTrue(state[name], name)


if __name__ == "__main__":
    unittest.main()
