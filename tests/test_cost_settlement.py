import pathlib
import tempfile
import unittest

from cloudquota import budget, cost_settlement, loan, reserve
from cloudquota.cli import run
from cloudquota.store import one, open_db, rows, verify_replay

cs = cost_settlement


def main_scenario(db, mode="reservation"):
    """The 0-60 minute shared-node period from the closing runbook.

    A runs 4 units on N during [0,30); B's 4-unit reservation holds [30,60)
    but only starts at minute 50 (a trusted original later corrects it to
    45).  Meter: 12 yuan first half, 18 second; 6 yuan of the second half
    is a confirmed datacenter incident borne by the platform.  B's seat is
    funded by C's loan L1; the agreed lender yield is billed separately.
    """
    budget.revise(db, "bA", "A", 8, 8, 1, 0)
    budget.revise(db, "bB", "B", 0, 0, 1, 0)
    budget.revise(db, "bC", "C", 10, 10, 1, 0)
    reserve.node(db, "N", "z", 8, 8)
    loan.offer(db, "oC", "C", 4, 4, 0, 0, 100)
    loan.issue(db, "iL", "L1", "oC", "B", 4, 4, 100, 1)
    reserve.request(db, "wA", "A", "svcA", 4, 4)
    reserve.place(db, "pA", "rA", "wA", 30, 0)
    reserve.start(db, "sA", "rA", 1, 0)
    reserve.request(db, "wB", "B", "svcB", 4, 4)
    reserve.place(db, "pB", "rB", "wB", 60, 30)
    reserve.start(db, "sB", "rB", 1, 50)
    cs.rate(db, "v1", 0.1, 0.02, 0)
    cs.contract(db, "rA", "A", mode)
    cs.contract(db, "rB", "B", mode)
    cs.meter(db, "m1", "N", 0, 30, 12, 60)
    cs.meter(db, "m2", "N", 30, 60, 18, 60)
    cs.incident(db, "inc1", "N", 45, 60, 6, 60)
    cs.yield_agreement(db, "y1", "L1", 2, 30)


def simple_tenant(db, units=4, lease=60, start=0, meter_amount=24, node="N"):
    budget.revise(db, "bT", "T", 8, 8, 1, 0)
    reserve.node(db, node, "z", 8, 8)
    reserve.request(db, "wT", "T", "g", units, units)
    reserve.place(db, "pT", "rT", "wT", lease, 0)
    reserve.start(db, "sT", "rT", 1, start)
    cs.rate(db, "v1", 0.1, 0.02, 0)
    cs.contract(db, "rT", "T", "reservation")
    if meter_amount is not None:
        cs.meter(db, "m1", node, 0, 60, meter_amount, 60)


class CostSettlementTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = open_db(str(pathlib.Path(self.tmp.name) / "test.sqlite"))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_close_snapshot_attributes_charges_yield_and_platform_loss(self):
        main_scenario(self.db)
        snap = cs.close(self.db, "c1", 0, 60, 60)
        self.assertEqual(snap["tenants"]["A"]["node_micro"], 12_000_000)
        self.assertEqual(snap["tenants"]["B"]["node_micro"], 5_600_000)
        self.assertEqual(snap["tenants"]["B"]["yield_micro"], 2_000_000)
        self.assertEqual(snap["lender_yields"], {"C": 2_000_000})
        platform = snap["platform"]
        self.assertEqual(platform["meter_micro"], 30_000_000)
        self.assertEqual(platform["incident_micro"], 6_000_000)
        self.assertEqual(platform["charged_micro"], 17_600_000)
        self.assertEqual(platform["loss_micro"], 12_400_000)
        self.assertEqual(platform["residual_micro"], 6_400_000)
        b_lines = snap["tenants"]["B"]["lines"]
        # the un-started seat [30,50) is a commitment fee, never run usage
        self.assertIn({"kind": "commit", "ref": "rB", "start_min": 30, "end_min": 50,
                       "units": 4, "rate_version": "v1", "amount_micro": 1_600_000}, b_lines)
        self.assertFalse(any(l["kind"] == "run" and l["start_min"] < 50 for l in b_lines))
        # the platform-borne incident never becomes a customer line
        self.assertFalse(any(l["kind"] == "incident" for t in snap["tenants"].values() for l in t["lines"]))
        self.assertFalse(any(l["amount_micro"] == 6_000_000 for l in b_lines))
        # closing is idempotent and the period cannot be closed twice
        self.assertEqual(cs.close(self.db, "c1", 0, 60, 60), snap)
        self.assertEqual(cs.close(self.db, "c2", 0, 60, 60), "period_already_closed")

    def test_late_start_original_corrects_bill_only_via_supplement(self):
        main_scenario(self.db)
        cs.close(self.db, "c1", 0, 60, 60)
        inv = cs.invoice(self.db, "invB", "B", 0, 60, 61)
        self.assertEqual(inv["total_micro"], 7_600_000)
        before = rows(self.db, "SELECT * FROM invoice_lines WHERE invoice_id='invB' ORDER BY seq")
        self.assertEqual(cs.payment(self.db, "pay1", "invB", 5, 62), "accepted")
        self.assertEqual(cs.dispute(self.db, "d1", "invB", "run window overstated", 62), "open")
        # minute 63: trusted original corrects the actual start from 50 to 45
        self.assertEqual(cs.start_doc(self.db, "doc1", "rB", 45, 63), "accepted")
        mid = cs.statement(self.db, "B", 0, 60)
        self.assertEqual(mid["invoiced_micro"], 7_600_000)   # issued bill is not silently overwritten
        self.assertEqual(mid["current_micro"], 9_200_000)
        self.assertEqual(mid["unbilled_micro"], 1_600_000)   # delta waits for a voucher
        self.assertEqual(mid["received_micro"], 5_000_000)
        self.assertEqual(mid["outstanding_micro"], 2_600_000)
        self.assertEqual(cs.voucher(self.db, "v9", "invB", "supplement", "start_doc:ghost", 64), "unknown_cause")
        self.assertEqual(cs.voucher(self.db, "v9", "invB", "supplement", "", 64), "missing_cause")
        v = cs.voucher(self.db, "v1", "invB", "supplement", "start_doc:doc1", 64)
        self.assertEqual(v["delta_micro"], 1_600_000)
        after = rows(self.db, "SELECT * FROM invoice_lines WHERE invoice_id='invB' ORDER BY seq")
        self.assertEqual(before, after)  # the issued invoice stays immutable
        st = cs.statement(self.db, "B", 0, 60)
        self.assertEqual(st["invoiced_micro"], 9_200_000)
        self.assertEqual(st["received_micro"], 5_000_000)
        self.assertEqual(st["outstanding_micro"], 4_200_000)  # carryover from actual receipts
        self.assertEqual(st["unbilled_micro"], 0)
        # payment and dispute keep their anchor on the original invoice
        self.assertEqual(one(self.db, "SELECT invoice_id FROM payments WHERE id='pay1'")["invoice_id"], "invB")
        self.assertEqual(st["disputes"][0]["invoice_id"], "invB")
        self.assertEqual(cs.resolve(self.db, "d1", "upheld", "v1"), "upheld")
        self.assertEqual(cs.resolve(self.db, "d1", "upheld"), "dispute_closed")
        # no new evidence -> no further delta
        self.assertEqual(cs.voucher(self.db, "v2", "invB", "supplement", "start_doc:doc1", 65), "no_delta")
        # platform loss now reflects the corrected fulfilment
        platform = cs.view(self.db, 0, 60)["platform"]
        self.assertEqual(platform["charged_micro"], 19_200_000)
        self.assertEqual(platform["loss_micro"], 10_800_000)
        self.assertEqual(platform["incident_micro"], 6_000_000)
        self.assertEqual(platform["residual_micro"], 4_800_000)
        # the close snapshot itself is immutable history
        self.assertEqual(cs.close(self.db, "c1", 0, 60, 60)["platform"]["charged_micro"], 17_600_000)
        self.assertTrue(verify_replay(self.db)["consistent"])

    def test_usage_mode_waives_unstarted_seat_and_blocks_exclusive_claim(self):
        main_scenario(self.db, mode="usage")
        snap = cs.close(self.db, "c1", 0, 60, 60)
        self.assertEqual(snap["tenants"]["B"]["node_micro"], 4_000_000)  # run [50,60) only
        self.assertFalse(any(l["kind"] == "commit" for l in snap["tenants"]["B"]["lines"]))
        # the un-started segment is resalable, not billed
        self.assertIn({"reservation_id": "rB", "tenant": "B", "start_min": 30, "end_min": 50},
                      snap["resalable"])
        inv = cs.invoice(self.db, "invB", "B", 0, 60, 61)
        self.assertEqual(inv["total_micro"], 6_000_000)  # 4 run + 2 lender yield
        # a usage-mode customer cannot claim an exclusive seat for the free segment
        self.assertEqual(cs.dispute(self.db, "d1", "invB", "seat was resold", 62,
                                    claim="exclusive_seat", ref="rB"), "no_exclusive_claim")
        self.assertEqual(cs.dispute(self.db, "d2", "invB", "meter looks wrong", 62), "open")
        self.assertEqual(cs.start_doc(self.db, "doc1", "rB", 45, 63), "accepted")
        v = cs.voucher(self.db, "v1", "invB", "supplement", "start_doc:doc1", 64)
        self.assertEqual(v["delta_micro"], 2_000_000)  # run [45,60) = 6 instead of 4
        self.assertEqual(cs.statement(self.db, "B", 0, 60)["invoiced_micro"], 8_000_000)
        platform = cs.view(self.db, 0, 60)["platform"]
        self.assertEqual(platform["loss_micro"], 12_000_000)  # unsold held seat stays with platform
        self.assertEqual(platform["residual_micro"], 6_000_000)

    def test_overlapping_meter_slices_never_double_counted(self):
        simple_tenant(self.db)
        self.assertEqual(cs.meter(self.db, "mX", "N", 10, 40, 5, 60), "meter_overlap")
        self.assertEqual(cs.meter(self.db, "m1", "N", 0, 60, 24, 60), "duplicate")
        self.assertEqual(cs.meter(self.db, "m1", "N", 0, 60, 25, 60), "slice_conflict")
        self.assertEqual(cs.meter(self.db, "mG", "ghost", 0, 30, 1, 60), "unknown_node")
        self.assertEqual(cs.meter(self.db, "mZ", "N", 0, 10, 1, 60, supersedes="ghost"), "unknown_slice")
        # replace the single slice with two halves via a causal supersede chain
        self.assertEqual(cs.meter(self.db, "m1a", "N", 0, 30, 10, 61, supersedes="m1"), "accepted")
        self.assertEqual(cs.meter(self.db, "m1b", "N", 0, 30, 11, 62, supersedes="m1"), "already_superseded")
        self.assertEqual(cs.meter(self.db, "m2", "N", 30, 60, 14, 61), "accepted")
        snap = cs.close(self.db, "c1", 0, 60, 60)
        # 10 + 14, never 24 + 10 + 14: the superseded original is excluded
        self.assertEqual(snap["platform"]["meter_micro"], 24_000_000)
        self.assertEqual(snap["platform"]["charged_micro"], 24_000_000)
        self.assertEqual(snap["platform"]["loss_micro"], 0)
        self.assertTrue(verify_replay(self.db)["consistent"])

    def test_incident_spanning_windows_is_capped_by_meter(self):
        simple_tenant(self.db, units=2, meter_amount=None)
        cs.meter(self.db, "m1", "N", 0, 30, 12, 60)
        cs.meter(self.db, "m2", "N", 30, 60, 18, 60)
        # accident straddles both slices: 4 yuan against the first, 4 against the second
        self.assertEqual(cs.incident(self.db, "inc1", "N", 20, 40, 8, 60), "accepted")
        snap = cs.close(self.db, "c1", 0, 60, 60)
        self.assertEqual(snap["platform"]["incident_micro"], 8_000_000)
        self.assertEqual(snap["platform"]["charged_micro"], 12_000_000)
        self.assertEqual(snap["platform"]["loss_micro"], 18_000_000)
        self.assertEqual(snap["platform"]["residual_micro"], 10_000_000)

    def test_incident_exceeding_metered_cost_blocks_close(self):
        simple_tenant(self.db, units=2, meter_amount=None)
        cs.meter(self.db, "m1", "N", 0, 30, 12, 60)
        cs.meter(self.db, "m2", "N", 30, 60, 18, 60)
        cs.incident(self.db, "inc1", "N", 20, 40, 8, 60)
        cs.incident(self.db, "inc2", "N", 10, 30, 10, 60)  # 4 + 10 > 12 on the first slice
        self.assertEqual(cs.close(self.db, "c1", 0, 60, 60), "incident_exceeds_meter")

    def test_loan_partial_repayment_never_double_bills_principal(self):
        main_scenario(self.db)
        self.assertEqual(loan.repay(self.db, "pay1", "L1", 1, 1), "partial")
        self.assertEqual(loan.repay(self.db, "pay1", "L1", 1, 1), "duplicate")
        cs.close(self.db, "c1", 0, 60, 60)
        inv = cs.invoice(self.db, "invB", "B", 0, 60, 61)
        self.assertEqual(inv["total_micro"], 7_600_000)  # unchanged by principal repayment
        kinds = {l["kind"] for l in rows(self.db, "SELECT * FROM invoice_lines WHERE invoice_id='invB'")}
        self.assertEqual(kinds, {"commit", "run", "loan_yield"})
        st = cs.statement(self.db, "B", 0, 60)
        # outstanding principal is informational only, never added to the amount due
        self.assertEqual(st["loan_principal_outstanding"], {"L1": [3, 3]})
        self.assertEqual(st["outstanding_micro"], 7_600_000)

    def test_partial_payment_and_reversal_carry_actual_receipts(self):
        simple_tenant(self.db)
        cs.close(self.db, "c1", 0, 60, 60)
        self.assertEqual(cs.invoice(self.db, "inv1", "T", 0, 60, 61)["total_micro"], 24_000_000)
        self.assertEqual(cs.payment(self.db, "p1", "inv1", 10, 62), "accepted")
        self.assertEqual(cs.payment(self.db, "p1", "inv1", 10, 62), "duplicate")
        self.assertEqual(cs.payment(self.db, "p1", "inv1", 11, 62), "receipt_conflict")
        self.assertEqual(cs.payment(self.db, "p2", "inv1", 15, 62), "overpayment")
        v = cs.voucher(self.db, "rev1", "inv1", "reversal", "ticket:CX-9", 63)
        self.assertEqual(v["delta_micro"], -24_000_000)
        st = cs.statement(self.db, "T", 0, 60)
        self.assertEqual(st["invoiced_micro"], 0)
        self.assertEqual(st["received_micro"], 10_000_000)
        self.assertEqual(st["outstanding_micro"], -10_000_000)  # credit carried to next month
        self.assertEqual(cs.payment(self.db, "p3", "inv1", 1, 64), "invoice_reversed")
        self.assertEqual(cs.voucher(self.db, "rev2", "inv1", "reversal", "ticket:CX-9", 64), "already_reversed")
        self.assertEqual(cs.voucher(self.db, "sup1", "inv1", "supplement", "ticket:CX-9", 64), "invoice_reversed")
        self.assertTrue(verify_replay(self.db)["consistent"])

    def test_same_named_workloads_bill_their_owning_tenant(self):
        budget.revise(self.db, "bA", "A", 2, 2, 1, 0)
        budget.revise(self.db, "bB", "B", 2, 2, 1, 0)
        reserve.node(self.db, "N1", "za", 2, 2)
        reserve.node(self.db, "N2", "zb", 2, 2)
        reserve.request(self.db, "wA", "A", "svc", 2, 2)
        reserve.request(self.db, "wB", "B", "svc", 2, 2)  # same workload name, other tenant
        self.assertEqual(reserve.place(self.db, "pA", "rA", "wA", 60, 0), "reserved:N1")
        self.assertEqual(reserve.place(self.db, "pB", "rB", "wB", 60, 0), "reserved:N2")
        reserve.start(self.db, "sA", "rA", 1, 0)
        reserve.start(self.db, "sB", "rB", 1, 0)
        cs.rate(self.db, "v1", 0.1, 0.02, 0)
        cs.contract(self.db, "rA", "A", "reservation")
        cs.contract(self.db, "rB", "B", "reservation")
        cs.meter(self.db, "m1", "N1", 0, 60, 12, 60)
        cs.meter(self.db, "m2", "N2", 0, 60, 12, 60)
        snap = cs.close(self.db, "c1", 0, 60, 60)
        self.assertEqual(snap["tenants"]["A"]["total_micro"], 12_000_000)
        self.assertEqual(snap["tenants"]["B"]["total_micro"], 12_000_000)
        cs.invoice(self.db, "invA", "A", 0, 60, 61)
        cs.invoice(self.db, "invB", "B", 0, 60, 61)
        refs_a = {l["ref"] for l in rows(self.db, "SELECT * FROM invoice_lines WHERE invoice_id='invA'")}
        refs_b = {l["ref"] for l in rows(self.db, "SELECT * FROM invoice_lines WHERE invoice_id='invB'")}
        self.assertEqual(refs_a, {"rA"})
        self.assertEqual(refs_b, {"rB"})

    def test_rate_version_change_splits_lines_at_boundary(self):
        self.assertEqual(cs.rate(self.db, "v1", 0.1, 0.02, 0), "accepted")
        self.assertEqual(cs.rate(self.db, "v1", 0.1, 0.02, 0), "exists")
        self.assertEqual(cs.rate(self.db, "v1", 0.2, 0.02, 0), "rate_conflict")
        self.assertEqual(cs.rate(self.db, "v2", 0.2, 0.04, 30), "accepted")
        self.assertEqual(cs.rate(self.db, "v3", 0.3, 0.05, 30), "effective_conflict")
        self.assertEqual(cs.rate(self.db, "v4", 0.1, 0.2, 40), "invalid_rate")
        budget.revise(self.db, "bT", "T", 2, 2, 1, 0)
        reserve.node(self.db, "N", "z", 2, 2)
        reserve.request(self.db, "wT", "T", "g", 1, 1)
        reserve.place(self.db, "pT", "rT", "wT", 60, 0)
        reserve.start(self.db, "sT", "rT", 1, 40)
        cs.contract(self.db, "rT", "T", "reservation")
        cs.meter(self.db, "m1", "N", 0, 60, 5, 60)
        snap = cs.close(self.db, "c1", 0, 60, 60)
        lines = snap["tenants"]["T"]["lines"]
        self.assertIn({"kind": "commit", "ref": "rT", "start_min": 0, "end_min": 30, "units": 1,
                       "rate_version": "v1", "amount_micro": 600_000}, lines)
        self.assertIn({"kind": "commit", "ref": "rT", "start_min": 30, "end_min": 40, "units": 1,
                       "rate_version": "v2", "amount_micro": 400_000}, lines)
        self.assertIn({"kind": "run", "ref": "rT", "start_min": 40, "end_min": 60, "units": 1,
                       "rate_version": "v2", "amount_micro": 4_000_000}, lines)
        self.assertEqual(snap["tenants"]["T"]["total_micro"], 5_000_000)
        self.assertEqual(snap["platform"]["loss_micro"], 0)

    def test_close_requires_verifiable_originals(self):
        budget.revise(self.db, "bT", "T", 4, 4, 1, 0)
        reserve.node(self.db, "N", "z", 4, 4)
        reserve.request(self.db, "wT", "T", "g", 4, 4)
        reserve.place(self.db, "pT", "rT", "wT", 60, 0)
        reserve.start(self.db, "sT", "rT", 1, 0)
        self.assertEqual(cs.close(self.db, "c1", 0, 60, 60), "missing_rate")
        cs.rate(self.db, "v1", 0.1, 0.02, 0)
        self.assertEqual(cs.close(self.db, "c1", 0, 60, 60), "missing_contract")
        cs.contract(self.db, "rT", "T", "reservation")
        self.assertEqual(cs.close(self.db, "c1", 0, 60, 60), "meter_gap")
        cs.meter(self.db, "m1", "N", 0, 30, 12, 60)
        self.assertEqual(cs.close(self.db, "c1", 0, 60, 60), "meter_gap")
        cs.meter(self.db, "m2", "N", 30, 60, 12, 60)
        self.assertEqual(cs.close(self.db, "c1", 0, 60, 60)["platform"]["meter_micro"], 24_000_000)
        # invoice gating and idempotency
        inv = cs.invoice(self.db, "inv1", "T", 0, 60, 61)
        self.assertEqual(inv["total_micro"], 24_000_000)
        self.assertEqual(cs.invoice(self.db, "inv1", "T", 0, 60, 61), inv)
        self.assertEqual(cs.invoice(self.db, "inv1", "other", 0, 60, 61), "invoice_conflict")
        self.assertEqual(cs.invoice(self.db, "inv2", "T", 0, 60, 61), "already_invoiced")

    def test_invoice_requires_closed_period(self):
        simple_tenant(self.db)
        self.assertEqual(cs.invoice(self.db, "inv1", "T", 0, 60, 61), "period_not_closed")

    def test_slice_and_incident_outside_period_rejected_at_close(self):
        simple_tenant(self.db, meter_amount=None)
        cs.meter(self.db, "m1", "N", 50, 70, 5, 60)
        self.assertEqual(cs.close(self.db, "c1", 0, 60, 60), "slice_out_of_period")

    def test_incident_outside_period_rejected_at_close(self):
        simple_tenant(self.db)
        cs.incident(self.db, "inc1", "N", 50, 70, 2, 60)
        self.assertEqual(cs.close(self.db, "c1", 0, 60, 60), "incident_out_of_period")

    def test_nothing_to_bill_and_empty_period_close(self):
        snap = cs.close(self.db, "c1", 0, 60, 60)
        self.assertEqual(snap["tenants"], {})
        self.assertEqual(cs.invoice(self.db, "invX", "X", 0, 60, 61), "nothing_to_bill")

    def test_original_and_contract_validation(self):
        simple_tenant(self.db)
        self.assertEqual(cs.contract(self.db, "ghost", "T", "reservation"), "unknown_reservation")
        self.assertEqual(cs.contract(self.db, "rT", "other", "reservation"), "tenant_mismatch")
        self.assertEqual(cs.contract(self.db, "rT", "T", "flat"), "invalid_mode")
        self.assertEqual(cs.contract(self.db, "rT", "T", "reservation"), "exists")
        self.assertEqual(cs.contract(self.db, "rT", "T", "usage"), "contract_conflict")
        self.assertEqual(cs.start_doc(self.db, "d1", "ghost", 5, 60), "unknown_reservation")
        self.assertEqual(cs.start_doc(self.db, "d1", "rT", 70, 60), "invalid_start_doc")
        self.assertEqual(cs.start_doc(self.db, "d1", "rT", 30, 60), "accepted")
        self.assertEqual(cs.start_doc(self.db, "d1", "rT", 30, 60), "duplicate")
        self.assertEqual(cs.start_doc(self.db, "d1", "rT", 31, 60), "doc_conflict")
        self.assertEqual(cs.release_doc(self.db, "d2", "rT", 70, 60), "invalid_release_doc")
        self.assertEqual(cs.release_doc(self.db, "d2", "rT", 55, 60), "accepted")
        self.assertEqual(cs.meter(self.db, "mB", "N", 40, 40, 1, 60), "invalid_slice")
        self.assertEqual(cs.incident(self.db, "iB", "ghost", 1, 2, 1, 60), "unknown_node")
        self.assertEqual(cs.yield_agreement(self.db, "yB", "ghost", 1, 0), "unknown_loan")
        self.assertEqual(cs.dispute(self.db, "q1", "ghost", "x", 1), "unknown_invoice")
        self.assertEqual(cs.payment(self.db, "q2", "ghost", 1, 1), "unknown_invoice")
        self.assertEqual(cs.voucher(self.db, "q3", "ghost", "supplement", "ticket:1", 1), "unknown_invoice")

    def test_released_seat_stops_billing_at_release_original(self):
        simple_tenant(self.db)
        cs.release_doc(self.db, "rel1", "rT", 20, 59)
        snap = cs.close(self.db, "c1", 0, 60, 60)
        self.assertEqual(snap["tenants"]["T"]["node_micro"], 8_000_000)  # run [0,20) only
        self.assertEqual(snap["platform"]["loss_micro"], 16_000_000)

    def test_settlement_fixture_replays_through_cli_and_audit(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        out = run(str(pathlib.Path(self.tmp.name) / "settle.sqlite"),
                  root / "fixtures" / "settle_normal.json", "settle")
        statement = out["results"][-1]["result"]
        self.assertEqual(statement["invoiced_micro"], 22_400_000)
        self.assertEqual(statement["received_micro"], 10_000_000)
        self.assertEqual(statement["outstanding_micro"], 12_400_000)
        self.assertTrue(out["state"]["audit_replay"]["consistent"])
        self.assertGreater(out["state"]["audit_replay"]["events"], 10)
        self.assertTrue(out["state"]["invoices"])
        self.assertTrue(out["state"]["payments"])
        self.assertTrue(out["state"]["meter_slices"])
        self.assertTrue(out["state"]["period_closes"])


if __name__ == "__main__":
    unittest.main()
