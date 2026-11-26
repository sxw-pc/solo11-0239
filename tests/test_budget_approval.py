"""Multi-party budget approval + emergency authorization tests.

The fixed incident (tenant 甲 / "jia"):

* budget revision 4 = 8; application R asks for 16 from minute 20;
* submitter 林 ("lin") controls seat A and uses a delegation for seat B that
  was revoked at minute 18 (the original revocation stays on record);
* the genuinely independent seat C only signs at minute 21;
* at minute 19 a competing valid revision 5 raises the budget to 10;
* at minute 20 reservation Q asks for 12.

Two lawful outcomes are pinned:

1. emergency path: duty lead 周 independently confirms the incident at 20 and
   grants +4 until 22; Q lands only as an interruptible emergency-backed seat;
2. formal path: R is rejected on the revision conflict, a fresh application R2
   based on revision 5 is approved by two disinterested owners, Q at 20 stays
   denied, and a later request succeeds after R2 becomes effective.
"""
import json
import pathlib
import tempfile
import unittest

from cloudquota import approval as ap
from cloudquota import budget, reserve
from cloudquota.cli import run
from cloudquota.store import one, open_db, report, rows, verify_replay


class ApprovalScene(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = open_db(str(pathlib.Path(self.tmp.name) / "approval.sqlite"))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    # ------------------------------------------------------------ scene builder

    def build_world(self, with_rev5=True, node_cpu=20, node_mem=20):
        db = self.db
        people = [
            ("lin", "林", "ops,applicant"),
            ("wang", "王", "approver,finance"),
            ("chen", "陈", "approver,capacity"),
            ("ding", "丁", "approver,finance"),
            ("zhou", "周值班", "duty_lead"),
            ("shen", "沈复核", "reviewer,audit"),
            ("zhao", "赵控制人", "controller"),
        ]
        for pid, name, roles in people:
            self.assertEqual(ap.register_principal(db, pid, name, roles=roles,
                                                    secret="k-" + pid), "accepted")
        self.assertEqual(ap.register_seat(db, "A", "lin", "general", 100, 100, 0, 100), "accepted")
        self.assertEqual(ap.register_seat(db, "B", "wang", "finance", 100, 100, 0, 100), "accepted")
        self.assertEqual(ap.register_seat(db, "C", "chen", "capacity", 100, 100, 0, 100), "accepted")
        self.assertEqual(ap.register_seat(db, "D", "ding", "finance", 100, 100, 0, 100), "accepted")
        # 甲's beneficiary controller is zhao; lin is the applicant/operator.
        ap.declare_controller(db, "jia", "zhao", at=0)
        # Original budget revision 4 = 8.
        self.assertEqual(budget.revise(db, "b4", "jia", 8, 8, 4, 0, actor="ops-cli"), "accepted")
        if with_rev5:
            # Competing legal revision 5 at minute 19 -> 10.
            self.assertEqual(budget.revise(db, "b5", "jia", 10, 10, 5, 19, actor="finance-owner"),
                             "accepted")
        reserve.node(db, "n1", "z1", node_cpu, node_mem)

    def submit_R(self, event="evR", app="R", at=10, base=4, eff=20, cpu=16, mem=16):
        return ap.submit_application(
            self.db, event, app, "jia", base, cpu, mem, eff, "acct-jia-001", "lin", at)

    def collusive_A_B(self, at_b=20):
        db = self.db
        # Delegation for B is still in the table but was revoked at minute 18.
        ap.grant_delegation(db, "dBA", "B", "lin", 0)
        ap.revoke_delegation(db, "ev-rev-dBA", "dBA", 18, revoked_by="governance")
        a = ap.sign_as(db, "sA", "sigA", "R", "A", "lin", 11)
        b = ap.sign_as(db, "sB", "sigB", "R", "B", "lin", at_b, delegation_id="dBA")
        return a, b

    # ------------------------------------------------------------ fixed incident

    def test_collusive_A_and_revoked_proxy_do_not_approve_R(self):
        self.build_world()
        self.assertEqual(self.submit_R(), "submitted")
        a, b = self.collusive_A_B()
        self.assertEqual(a, "interested_party")
        self.assertEqual(b, "delegation_revoked")
        view = ap.tally(self.db, "R")
        # Naive seat counting says two; real independent headcount is zero.
        self.assertEqual(view["independent_count"], 0)
        self.assertFalse(view["quorum_met"])
        self.assertEqual({(s["seat_id"], s["verdict"]) for s in view["signatures"]},
                         {("A", "interested_party"), ("B", "delegation_revoked")})

    def test_competing_revision_rejects_R_and_Q_at_minute_20_is_denied(self):
        self.build_world()
        self.submit_R()
        self.collusive_A_B()
        # Truly independent C only signs at minute 21.
        self.assertEqual(ap.sign_as(self.db, "sC", "sigC", "R", "C", "chen", 21), "valid")
        view = ap.tally(self.db, "R")
        self.assertEqual(view["independent_count"], 1)
        self.assertFalse(view["quorum_met"])  # only one disinterested owner; finance missing
        # Even if someone tried to commit, base revision 4 is gone (current = 5): conflict.
        self.assertEqual(ap.commit_application(self.db, "cR", "R", 21, actor="runner"),
                         "base_revision_conflict")
        row = one(self.db, "SELECT status,status_reason,resulting_revision FROM budget_applications WHERE id='R'")
        self.assertEqual(row["status"], "rejected")
        self.assertIn("base_revision_superseded", row["status_reason"])
        self.assertIsNone(row["resulting_revision"])
        # No phantom 16-unit revision was ever written.
        self.assertIsNone(one(self.db, "SELECT 1 FROM budget_history WHERE tenant='jia' AND cpu=16"))
        self.assertEqual(budget.available(self.db, "jia", 20)[:2], (10, 10))
        # Q for 12 at minute 20 must be rejected against the real 10-unit budget.
        reserve.request(self.db, "Q", "jia", "gQ", 12, 12)
        self.assertEqual(reserve.place(self.db, "pQ", "rQ", "Q", 22, 20), "entitlement_denied")
        self.assertIsNone(one(self.db, "SELECT id FROM reservations WHERE id='rQ'"))
        # The rejected application is visible in the audit report.
        rep = ap.audit_report(self.db, tenant="jia")
        rejected_ids = {x["id"] for x in rep["findings"]["rejected_applications"]}
        self.assertIn("R", rejected_ids)
        self.assertTrue(verify_replay(self.db)["consistent"])

    # ------------------------------------------------------------ emergency path

    def _emergency(self, eid="em1", extra=4, expires=22):
        self.assertEqual(ap.register_incident(
            self.db, "inc1", "jia", "zhou", 20, requested_by="lin",
            note="capacity outage confirmed by duty lead"), "incident_confirmed")
        return ap.authorize_emergency(
            self.db, "ea1", eid, "jia", extra, extra, 20, expires, "lin",
            incident_id="inc1")

    def test_emergency_path_Q_gets_interruptible_seat_real_approver_and_expiry_disposition(self):
        self.build_world()
        self.assertEqual(self._emergency(), "emergency_authorized")
        # Identical scene, but the placeable quota is now 10 (rev 5) + 4 emergency = 14.
        view0 = ap.capacity_view(self.db, "jia", 20)
        self.assertEqual((view0["placeable_cpu"], view0["placeable_mem"]), (14, 14))
        reserve.request(self.db, "Q", "jia", "gQ", 12, 12, interruptible=True)
        verdict = reserve.place(self.db, "pQ", "rQ", "Q", 22, 20)
        self.assertTrue(verdict.startswith("reserved:"), verdict)
        r = one(self.db, "SELECT source,started,released FROM reservations WHERE id='rQ'")
        self.assertEqual(r["source"], "emergency:em1")
        self.assertEqual((r["started"], r["released"]), (0, 0))
        # Unique funding source is the emergency authorization; draw is only the marginal +2
        # over the legal revision-5 budget of 10 (cap was +4).
        self.assertEqual(one(self.db, "SELECT source_kind,source_id FROM funding WHERE reservation_id='rQ'"),
                         {"source_kind": "emergency", "source_id": "em1"})
        self.assertEqual(one(self.db, "SELECT cpu_draw,mem_draw FROM emergency_draws WHERE reservation_id='rQ'"),
                         {"cpu_draw": 2, "mem_draw": 2})
        # A non-interruptible workload cannot use emergency slack.
        reserve.request(self.db, "Qi", "jia", "gQi", 1, 1, interruptible=False)
        self.assertEqual(reserve.place(self.db, "pQi", "rQi", "Qi", 21, 20),
                         "emergency_interruptible_only")
        # The seat can start (it is funded) but stays interruptible in nature.
        self.assertEqual(reserve.start(self.db, "stQ", "rQ", 1, 21), "started")
        # At minute 22 the authorization auto-expires and the temporary seat is disposed of.
        self.assertEqual(ap.expire_emergency(self.db, 22), ["rQ"])
        self.assertEqual(one(self.db, "SELECT released FROM reservations WHERE id='rQ'")["released"], 1)
        view = ap.emergency_view(self.db, "em1")
        self.assertEqual(view["status"], "expired")
        self.assertEqual(view["accountable_id"], "zhou")
        self.assertEqual(view["accountable_name"], "周值班")
        self.assertEqual(len(view["dispositions"]), 1)
        self.assertEqual(view["dispositions"][0]["kind"], "interrupted_at_expiry")
        self.assertEqual(view["historical_draw_cpu"], 2)  # usage that happened stays visible
        self.assertEqual(view["active_seat_ids"], [])
        # The structured audit report names the real emergency approver and disposition.
        report_view = ap.audit_report(self.db, "jia")
        self.assertEqual(len(report_view["emergencies"]), 1)
        self.assertEqual(report_view["emergencies"][0]["accountable_id"], "zhou")
        self.assertEqual(report_view["emergencies"][0]["dispositions"][0]["reservation_id"], "rQ")
        self.assertTrue(verify_replay(self.db)["consistent"])

    def test_emergency_cap_cannot_exceed_limit_and_exhaustion_denies_further_draw(self):
        db = self.db
        # Base budget 8 exactly; no competing revision.
        self.build_world(with_rev5=False, node_cpu=30, node_mem=30)
        # Authorization above the hard +4 cap is refused.
        ap.register_incident(db, "incX", "jia", "zhou", 20, requested_by="lin")
        self.assertEqual(ap.authorize_emergency(
            db, "eaX", "emX", "jia", 5, 5, 20, 22, "lin", incident_id="incX"),
            "emergency_limit_exceeded")
        self.assertIsNone(one(db, "SELECT id FROM emergency_auth WHERE id='emX'"))
        self._emergency()
        # Q1 = 12 consumes the whole +4 emergency cap (8 + 4 = 12).
        reserve.request(db, "Q1", "jia", "g1", 12, 12, interruptible=True)
        self.assertEqual(reserve.place(db, "p1", "r1", "Q1", 22, 20), "reserved:n1")
        self.assertEqual(one(db, "SELECT cpu_draw,mem_draw FROM emergency_draws WHERE reservation_id='r1'"),
                         {"cpu_draw": 4, "mem_draw": 4})
        # Any further emergency draw is impossible: cap exhausted.
        reserve.request(db, "Q2", "jia", "g2", 1, 1, interruptible=True)
        self.assertEqual(reserve.place(db, "p2", "r2", "Q2", 21, 20),
                         "emergency_quota_exhausted")
        self.assertIsNone(one(db, "SELECT id FROM reservations WHERE id='r2'"))

    def test_emergency_window_boundary_blocks_late_lease_and_post_expiry_placement(self):
        self.build_world()
        self._emergency(expires=22)
        reserve.request(self.db, "Q", "jia", "g", 12, 12, interruptible=True)
        self.assertEqual(reserve.place(self.db, "pLong", "rLong", "Q", 23, 20),
                         "emergency_window_exceeded")
        # At minute 23 the authorization has lapsed even without the sweep.
        self.assertEqual(reserve.place(self.db, "pLate", "rLate", "Q", 24, 23),
                         "emergency_expired")

    def test_failed_post_review_blocks_new_reservations_but_keeps_usage_and_accountability(self):
        db = self.db
        self.build_world()
        self._emergency()
        reserve.request(db, "Q", "jia", "gQ", 12, 12, interruptible=True)
        reserve.place(db, "pQ", "rQ", "Q", 22, 20)
        used_before = budget.usage(db, "jia")
        audit_before = one(db, "SELECT COUNT(*) n FROM audit_log")["n"]
        # Independent post-hoc review fails while Q is still live.
        self.assertEqual(ap.review_emergency(
            db, "rv1", "em1", "shen", 21, False, note="confirmation chain incomplete"),
            "review_failed")
        hold = one(db, "SELECT * FROM reservation_holds WHERE tenant='jia'")
        self.assertEqual(hold["reason"], "emergency_review_failed")
        # Every new placement is stopped, even a small one base budget could cover.
        reserve.request(db, "Q2", "jia", "g2", 1, 1)
        self.assertEqual(reserve.place(db, "pQ2", "rQ2", "Q2", 24, 22),
                         "new_reservations_blocked")
        self.assertIsNone(one(db, "SELECT id FROM reservations WHERE id='rQ2'"))
        # The already-occurred usage is untouched, not rewritten out of history.
        self.assertEqual(budget.usage(db, "jia"), used_before)
        live = one(db, "SELECT released,source FROM reservations WHERE id='rQ'")
        self.assertEqual((live["released"], live["source"]), (0, "emergency:em1"))
        self.assertGreaterEqual(one(db, "SELECT COUNT(*) n FROM audit_log")["n"], audit_before)
        # The accountable duty lead and failed reviewer are both on the durable record.
        em = one(db, "SELECT status,accountable_id,reviewer_id,review_verdict FROM emergency_auth WHERE id='em1'")
        self.assertEqual((em["status"], em["accountable_id"], em["reviewer_id"], em["review_verdict"]),
                         ("review_failed", "zhou", "shen", "failed"))
        # Expiry sweep still records the term-end disposition; the failed verdict is not erased.
        ap.expire_emergency(db, 22)
        self.assertEqual(one(db, "SELECT status FROM emergency_auth WHERE id='em1'")["status"],
                         "review_failed")
        self.assertEqual(len(ap.emergency_view(db, "em1")["dispositions"]), 1)
        # Audit chain remains fully replayable.
        self.assertTrue(verify_replay(db)["consistent"])
        # Remediation/lift restores new placements against the real revision-5 budget.
        self.assertEqual(ap.lift_hold(db, "jia", 24), "lifted")
        self.assertEqual(reserve.place(db, "pQ3", "rQ3", "Q2", 26, 24), "reserved:n1")

    def test_review_must_be_independent_and_second_review_does_not_overwrite(self):
        self.build_world()
        self._emergency()
        # The accountable duty lead cannot review their own authorization.
        self.assertEqual(ap.review_emergency(self.db, "rv0", "em1", "zhou", 23, True),
                         "reviewer_not_independent")
        self.assertEqual(ap.review_emergency(self.db, "rv1", "em1", "shen", 23, True, note="ok"),
                         "review_passed")
        self.assertEqual(ap.review_emergency(self.db, "rv2", "em1", "shen", 24, False),
                         "already_reviewed")
        self.assertEqual(one(self.db, "SELECT review_verdict FROM emergency_auth WHERE id='em1'")["review_verdict"],
                         "passed")

    # ------------------------------------------------------------ formal second path

    def test_formal_refile_on_rev5_two_disinterested_owners_then_Q_can_reapply(self):
        db = self.db
        self.build_world()
        self.submit_R()
        self.collusive_A_B()
        ap.sign_as(db, "sC", "sigC-R", "R", "C", "chen", 21)
        ap.commit_application(db, "cR", "R", 21)  # conflict-rejects R
        # Re-file against revision 5; window cannot be back-dated to minute 20.
        self.assertEqual(ap.submit_application(
            db, "evR2past", "R2past", "jia", 5, 16, 16, 20, "acct-jia-001", "lin", 21),
            "effective_window_in_past")
        self.assertEqual(ap.submit_application(
            db, "evR2", "R2", "jia", 5, 16, 16, 23, "acct-jia-001", "lin", 21),
            "submitted")
        r_digest = one(db, "SELECT digest FROM budget_applications WHERE id='R'")["digest"]
        r2_digest = one(db, "SELECT digest FROM budget_applications WHERE id='R2'")["digest"]
        self.assertNotEqual(r_digest, r2_digest)
        # R's signature/token cannot be moved onto R2: the old token fails verification.
        old_token = ap.token_for(db, "chen", r_digest)
        self.assertEqual(ap.cast_signature(
            db, "bt", "sigBad", "R2", "C", "chen", 21, token=old_token), "bad_signature")
        self.assertEqual(ap.sign_as(db, "sC2", "sigC2", "R2", "C", "chen", 22), "valid")
        # One independent owner is not enough: finance owner D completes the two-person rule.
        self.assertEqual(ap.commit_application(db, "cR2early", "R2", 22), "approval_incomplete")
        self.assertEqual(ap.sign_as(db, "sD", "sigD", "R2", "D", "ding", 22), "valid")
        view = ap.tally(db, "R2")
        self.assertTrue(view["quorum_met"])
        self.assertEqual(view["independent_count"], 2)
        self.assertEqual(set(view["domains"]), {"capacity", "finance"})
        # Commit writes revision 6 exactly once with the fixed content.
        self.assertEqual(ap.commit_application(db, "cR2", "R2", 22, actor="cto"), "committed")
        app = one(db, "SELECT status,resulting_revision FROM budget_applications WHERE id='R2'")
        self.assertEqual((app["status"], app["resulting_revision"]), ("committed", 6))
        auth = one(db, "SELECT * FROM budget_authority WHERE tenant='jia' AND revision=6")
        self.assertEqual(auth["authority_kind"], "approved_application")
        self.assertEqual(auth["application_id"], "R2")
        self.assertEqual(auth["principals"], "chen,ding")
        self.assertEqual(auth["actor"], "cto")
        self.assertEqual(auth["digest"], r2_digest)
        # Replaying the commit event returns the recorded verdict and writes no second revision.
        self.assertEqual(ap.commit_application(db, "cR2", "R2", 22, actor="cto"), "committed")
        self.assertEqual(len(rows(db, "SELECT * FROM budget_history WHERE tenant='jia' AND revision=6")), 1)
        # Q at minute 20 remains denied even after R2 exists (effectivity starts at 23).
        reserve.request(db, "Q", "jia", "gQ", 12, 12)
        self.assertEqual(reserve.place(db, "pQ-old", "rQold", "Q", 22, 20), "entitlement_denied")
        # After minute 23 a fresh application/reservation succeeds against the legal 16.
        # Unlike the emergency seat, this is an ordinary (non-interruptible) budget-funded seat.
        reserve.request(db, "Q2", "jia", "gQ2", 16, 16, interruptible=False)
        self.assertEqual(reserve.place(db, "pQ2", "rQ2", "Q2", 30, 23), "reserved:n1")
        self.assertEqual(one(db, "SELECT source FROM reservations WHERE id='rQ2'")["source"],
                         "budget:jia")
        self.assertEqual(budget.available(db, "jia", 23)[:2], (0, 0))  # 16 granted, 16 reserved
        self.assertTrue(verify_replay(db)["consistent"])

    # ------------------------------------------------------------ mutual proxy

    def test_mutual_proxy_between_applicant_and_tenant_controller_adds_no_independent_vote(self):
        db = self.db
        ap.register_principal(db, "ma", "马申请", roles="applicant", secret="k-ma")
        ap.register_principal(db, "zhao2", "赵控制", roles="controller,approver", secret="k-zhao2")
        ap.declare_controller(db, "hu", "zhao2")
        ap.relate_principals(db, "rel-mp", "ma", "zhao2", kind="mutual_proxy")
        ap.register_seat(db, "M1", "ma", "general", 100, 100, 0, 100)
        ap.register_seat(db, "M2", "zhao2", "finance", 100, 100, 0, 100)
        budget.revise(db, "bh", "hu", 8, 8, 4, 0)
        ap.submit_application(db, "eh", "H", "hu", 4, 16, 16, 20, "acct", "ma", 10)
        # Valid (non-revoked) mutual delegations.
        ap.grant_delegation(db, "d1", "M1", "zhao2", 0)
        ap.grant_delegation(db, "d2", "M2", "ma", 0)
        self.assertEqual(ap.sign_as(db, "x1", "sx1", "H", "M1", "zhao2", 12, delegation_id="d1"),
                         "interested_party")
        self.assertEqual(ap.sign_as(db, "x2", "sx2", "H", "M2", "ma", 12, delegation_id="d2"),
                         "interested_party")
        view = ap.tally(db, "H")
        self.assertEqual(view["independent_count"], 0)
        self.assertFalse(view["quorum_met"])
        # Two genuinely independent owners can still approve.
        ap.register_principal(db, "i1", "独立一", roles="approver,capacity", secret="k-i1")
        ap.register_principal(db, "i2", "独立二", roles="approver,finance", secret="k-i2")
        ap.register_seat(db, "I1", "i1", "capacity", 100, 100, 0, 100)
        ap.register_seat(db, "I2", "i2", "finance", 100, 100, 0, 100)
        ap.sign_as(db, "xi1", "si1", "H", "I1", "i1", 13)
        ap.sign_as(db, "xi2", "si2", "H", "I2", "i2", 13)
        self.assertTrue(ap.tally(db, "H")["quorum_met"])

    # ------------------------------------------------------------ tenure overlap / late sig

    def test_overlapping_seat_tenures_collapse_same_person_and_late_signature_rejected(self):
        db = self.db
        ap.register_principal(db, "opsh", "运维", roles="applicant", secret="k-opsh")
        ap.register_principal(db, "ce", "岑", roles="approver,capacity", secret="k-ce")
        # Old seat [0,20), overlapping successor seat [18,40).
        ap.register_seat(db, "T1", "ce", "capacity", 100, 100, 0, 20)
        ap.register_seat(db, "T2", "ce", "capacity", 100, 100, 18, 40)
        budget.revise(db, "bt", "tt", 8, 8, 1, 0)
        ap.submit_application(db, "et", "T", "tt", 1, 16, 16, 30, "acct", "opsh", 5,
                              required_domains=[])
        self.assertEqual(ap.sign_as(db, "t1", "st1", "T", "T1", "ce", 19), "valid")
        self.assertEqual(ap.sign_as(db, "t2", "st2", "T", "T2", "ce", 19), "valid")
        view = ap.tally(db, "T")
        self.assertEqual(view["independent_count"], 1)  # one natural person, two overlapping seats
        self.assertFalse(view["quorum_met"])
        # Signature from a different seat whose tenure ended at 20 is late and not counted.
        ap.register_seat(db, "TL", "ce", "capacity", 100, 100, 0, 20)
        self.assertEqual(ap.sign_as(db, "tlate", "stlate", "T", "TL", "ce", 20),
                         "seat_tenure_ended")
        late = [s for s in ap.tally(db, "T")["signatures"] if s["signature_id"] == "stlate"][0]
        self.assertEqual((late["counted"], late["verdict"]), (0, "seat_tenure_ended"))
        # Re-casting from the same seat/person is a duplicate ballot, not a second approver.
        self.assertEqual(ap.sign_as(db, "t1again", "st1again", "T", "T1", "ce", 19),
                         "duplicate_signature")

    def test_revocation_after_an_earlier_signature_does_not_retroactively_invalidate_it(self):
        db = self.db
        ap.register_principal(db, "op", "申请人", roles="applicant", secret="k-op")
        ap.register_principal(db, "ho", "何", roles="approver,finance", secret="k-ho")
        ap.register_principal(db, "ag", "代理", roles="approver", secret="k-ag")
        ap.register_seat(db, "HO", "ho", "finance", 100, 100, 0, 100)
        budget.revise(db, "b", "tt", 8, 8, 1, 0)
        ap.submit_application(db, "e", "A1", "tt", 1, 9, 9, 20, "acct", "op", 5,
                              required_approvals=1, required_domains=[])
        ap.grant_delegation(db, "d", "HO", "ag", 0)
        self.assertEqual(ap.sign_as(db, "s1", "sg1", "A1", "HO", "ag", 10, delegation_id="d"),
                         "valid")
        # Revoked later at 18: the act at 10 was within authority and stays counted.
        ap.revoke_delegation(db, "r1", "d", 18)
        self.assertTrue(ap.tally(db, "A1")["quorum_met"])

    # ------------------------------------------------------------ content tampering

    def test_modified_application_content_breaks_digest_and_commit(self):
        db = self.db
        self.build_world(with_rev5=False)
        self.submit_R(base=4)
        ap.sign_as(db, "sC", "sigC", "R", "C", "chen", 11)
        # Tamper with the fixed target after submission/signature.
        db.execute("UPDATE budget_applications SET cpu=32 WHERE id='R'")
        db.commit()
        view = ap.tally(db, "R")
        self.assertFalse(view["digest_ok"])
        self.assertTrue(all(s["verdict"] == "digest_mismatch" for s in view["signatures"]))
        self.assertFalse(view["quorum_met"])
        self.assertEqual(ap.commit_application(db, "cR", "R", 12), "digest_mismatch")
        self.assertEqual(one(db, "SELECT status,status_reason FROM budget_applications WHERE id='R'")["status"],
                         "rejected")
        self.assertIsNone(one(db, "SELECT 1 FROM budget_history WHERE tenant='jia' AND cpu=32"))
        # The tampering update itself is captured by audit triggers and replays consistently.
        self.assertTrue(verify_replay(db)["consistent"])

    def test_direct_sign_without_explicit_token_is_accepted_but_wrong_token_rejected(self):
        db = self.db
        ap.register_principal(db, "p1", "普批", roles="approver,capacity")
        ap.register_seat(db, "P1", "p1", "capacity", 100, 100, 0, 100)
        budget.revise(db, "b", "tt", 8, 8, 1, 0)
        ap.submit_application(db, "e", "A", "tt", 1, 9, 9, 20, "acct", "p1", 5,
                              required_approvals=1, required_domains=[])
        # p1 is both applicant and seat holder here -> interested, proving the call is
        # authenticated and evaluated rather than rejected for a missing token.
        self.assertEqual(ap.sign(db, "s", "g", "A", "P1", "p1", 6), "interested_party")

    def test_bad_signature_token_is_rejected_and_real_signature_can_follow(self):
        db = self.db
        self.build_world(with_rev5=False)
        self.submit_R()
        digest = one(db, "SELECT digest FROM budget_applications WHERE id='R'")["digest"]
        self.assertEqual(ap.cast_signature(
            db, "evBad", "bad1", "R", "C", "chen", 11, token="0" * 64), "bad_signature")
        # No ballot row consumed the seat.
        self.assertIsNone(one(db, "SELECT id FROM approval_signatures WHERE id='bad1'"))
        good = ap.sign_token("k-chen", digest)
        self.assertEqual(ap.cast_signature(
            db, "evGood", "good1", "R", "C", "chen", 11, token=good), "valid")

    # ------------------------------------------------------------ scope

    def test_seat_amount_and_tenant_scope_are_enforced(self):
        db = self.db
        ap.register_principal(db, "small", "小批", roles="approver,finance", secret="k")
        ap.register_seat(db, "SL", "small", "finance", 4, 4, 0, 100)
        ap.register_principal(db, "other", "外租户审批", roles="approver", secret="k2")
        ap.register_seat(db, "SO", "other", "general", 100, 100, 0, 100, tenants="some-other")
        budget.revise(db, "b", "jia", 8, 8, 4, 0)
        ap.submit_application(db, "e", "R", "jia", 4, 16, 16, 20, "a", "small", 5)
        self.assertEqual(ap.sign_as(db, "s1", "g1", "R", "SL", "small", 6), "seat_amount_scope")
        self.assertEqual(ap.sign_as(db, "s2", "g2", "R", "SO", "other", 6), "seat_tenant_scope")

    # ------------------------------------------------------------ duplicates

    def test_duplicate_applications_and_replays(self):
        db = self.db
        self.build_world(with_rev5=False)
        self.assertEqual(self.submit_R(event="e1", app="R"), "submitted")
        # Same event id replays the original verdict.
        self.assertEqual(self.submit_R(event="e1", app="R"), "submitted")
        # Same application identity/content through a new event.
        self.assertEqual(self.submit_R(event="e2", app="R"), "application_exists")
        # New identity but identical fixed terms is a business duplicate.
        self.assertEqual(self.submit_R(event="e3", app="R-copy"), "duplicate_application")
        # Same identity with changed content is an immutable-content conflict.
        self.assertEqual(self.submit_R(event="e4", app="R", cpu=32), "application_conflict")

    def test_explicit_rejection_is_terminal_and_conflicted_holder_not_laundered_by_agent(self):
        db = self.db
        self.build_world(with_rev5=False)
        self.submit_R()
        # Governance formally rejects R before any commit; it can no longer be committed.
        self.assertEqual(ap.reject_application(db, "rj", "R", 12, reason="funding rejected"),
                         "rejected")
        # Even with two otherwise-independent signatures, the terminal rejection holds.
        ap.sign_as(db, "sC", "gC", "R", "C", "chen", 13)
        ap.sign_as(db, "sD", "gD", "R", "D", "ding", 13)
        self.assertEqual(ap.commit_application(db, "c", "R", 14), "application_rejected")
        self.assertIsNone(one(db, "SELECT 1 FROM budget_history WHERE tenant='jia' AND cpu=16"))
        # A conflicted seat holder cannot be laundered through an independent agent:
        # zhao controls tenant jia and holds Z; independent chen acts for Z via delegation.
        ap.register_principal(db, "zseat", "赵席", roles="approver", secret="k-zseat")
        ap.declare_controller(db, "jia", "zseat", at=0)
        ap.register_seat(db, "Z", "zseat", "finance", 100, 100, 0, 100)
        ap.grant_delegation(db, "dZ", "Z", "chen", 0)
        ap.submit_application(db, "e2", "Rz", "jia", 4, 9, 9, 20, "a", "lin", 5,
                              required_approvals=1, required_domains=[])
        self.assertEqual(ap.sign_as(db, "sz", "gz", "Rz", "Z", "chen", 6, delegation_id="dZ"),
                         "interested_holder")
        self.assertFalse(ap.tally(db, "Rz")["quorum_met"])

    # ------------------------------------------------------------ input validation

    def test_invalid_inputs_create_nothing(self):
        db = self.db
        self.assertEqual(ap.register_principal(db, "", "x"), "invalid_principal")
        self.assertEqual(ap.register_seat(db, "S", "missing", "finance", 1, 1, 10, 5),
                         "invalid_seat")
        self.assertEqual(ap.submit_application(
            db, "e", "A", "jia", 4, -1, 1, 20, "acct", "lin", 10), "invalid_application")
        self.assertEqual(ap.submit_application(
            db, "e2", "A2", "jia", 99, 16, 16, 20, "acct", "lin", 10), "unknown_principal")
        # Emergency without a confirmed incident is refused.
        ap.register_principal(db, "lin", "林", roles="applicant")
        self.assertEqual(ap.authorize_emergency(
            db, "ea", "em", "jia", 4, 4, 20, 22, "lin"), "incident_not_confirmed")

    # ------------------------------------------------------------ audit report / cli

    def test_capacity_compliance_distinguishes_clean_emergency_and_phantom_usage(self):
        db = self.db
        self.build_world()
        reserve.request(db, "Q", "jia", "gQ", 12, 12, interruptible=True)
        # Before emergency authority, Q is denied: zero usage, compliant.
        self.assertEqual(reserve.place(db, "pQ0", "rQ0", "Q", 22, 20), "entitlement_denied")
        clean = ap.capacity_compliance(db, "jia", 20)
        self.assertTrue(clean["compliant"])
        self.assertEqual((clean["used_cpu"], clean["unauthorized_cpu"]), (0, 0))
        # Duty lead confirms and grants emergency; Q is now lawfully emergency-backed.
        self._emergency()
        self.assertEqual(reserve.place(db, "pQ", "rQ", "Q", 22, 20), "reserved:n1")
        backed = ap.capacity_compliance(db, "jia", 20)
        self.assertEqual((backed["used_cpu"], backed["shortfall_cpu"],
                          backed["emergency_backed_cpu"], backed["unauthorized_cpu"]),
                         (12, 2, 2, 0))
        self.assertTrue(backed["compliant"])
        # A bypassed/phantom 8-unit reservation with no funding is detected as unauthorized.
        db.execute("INSERT INTO requests VALUES(?,?,?,?,?,?)",
                   ("ghost", "jia", "gg", 8, 8, 1))
        db.execute("INSERT INTO reservations VALUES(?,?,?,?,?,?,?,?)",
                   ("rghost", "ghost", "n1", "unallocated", 22, 0, 0, 1))
        db.commit()
        phantom = ap.capacity_compliance(db, "jia", 20)
        self.assertFalse(phantom["compliant"])
        self.assertEqual(phantom["unauthorized_cpu"], 8)
        findings = ap.governance_findings(db)
        self.assertIn("rghost", findings["active_reservations_without_funding"])
        self.assertTrue(verify_replay(db)["consistent"])

    def test_store_report_includes_governance_tables_and_replays(self):
        self.build_world()
        self.submit_R()
        self.collusive_A_B()
        ap.sign_as(self.db, "sC", "sigC", "R", "C", "chen", 21)
        state = report(self.db)
        for name in ("budget_applications", "approval_signatures", "budget_authority",
                     "approval_seats", "approval_delegations", "emergency_auth",
                     "reservation_holds"):
            self.assertIn(name, state)
        self.assertTrue(state["audit_replay"]["consistent"])

    def test_cli_fixture_runs_approval_and_emergency_ops(self):
        fixture = {
            "actions": [
                {"op": "approval.principal", "args": {"principal_id": "lin", "name": "林",
                                                       "roles": "applicant", "secret": "k-lin"}},
                {"op": "approval.principal", "args": {"principal_id": "wang", "name": "王",
                                                       "roles": "approver,finance", "secret": "k-wang"}},
                {"op": "approval.principal", "args": {"principal_id": "chen", "name": "陈",
                                                       "roles": "approver,capacity", "secret": "k-chen"}},
                {"op": "approval.principal", "args": {"principal_id": "zhou", "name": "周",
                                                       "roles": "duty_lead", "secret": "k-zhou"}},
                {"op": "approval.seat", "args": {"seat_id": "A", "holder_id": "lin",
                                                  "domain": "general", "max_cpu": 100,
                                                  "max_mem": 100, "valid_from": 0, "valid_until": 100}},
                {"op": "approval.seat", "args": {"seat_id": "B", "holder_id": "wang",
                                                  "domain": "finance", "max_cpu": 100,
                                                  "max_mem": 100, "valid_from": 0, "valid_until": 100}},
                {"op": "approval.seat", "args": {"seat_id": "C", "holder_id": "chen",
                                                  "domain": "capacity", "max_cpu": 100,
                                                  "max_mem": 100, "valid_from": 0, "valid_until": 100}},
                {"op": "budget.revise", "args": {"event_id": "b4", "tenant": "jia", "cpu": 8,
                                                  "mem": 8, "revision": 4, "effective": 0}},
                {"op": "budget.revise", "args": {"event_id": "b5", "tenant": "jia", "cpu": 10,
                                                  "mem": 10, "revision": 5, "effective": 19}},
                {"op": "approval.delegation", "args": {"delegation_id": "dBA", "seat_id": "B",
                                                        "agent_id": "lin", "granted_at": 0}},
                {"op": "approval.revoke_delegation", "args": {"event_id": "rd",
                                                               "delegation_id": "dBA", "at": 18}},
                {"op": "approval.submit", "args": {"event_id": "er", "application_id": "R",
                                                     "tenant": "jia", "base_revision": 4,
                                                     "cpu": 16, "mem": 16, "effective_from": 20,
                                                     "funding_account": "acct",
                                                     "applicant_id": "lin", "at": 10}},
                {"op": "approval.sign_as", "args": {"event_id": "s1", "signature_id": "g1",
                                                     "application_id": "R", "seat_id": "A",
                                                     "signer_id": "lin", "at": 11}},
                {"op": "approval.sign_as", "args": {"event_id": "s2", "signature_id": "g2",
                                                     "application_id": "R", "seat_id": "B",
                                                     "signer_id": "lin", "at": 20,
                                                     "delegation_id": "dBA"}},
                {"op": "approval.sign_as", "args": {"event_id": "s3", "signature_id": "g3",
                                                     "application_id": "R", "seat_id": "C",
                                                     "signer_id": "chen", "at": 21}},
                {"op": "approval.commit", "args": {"event_id": "cr", "application_id": "R", "at": 21}},
                {"op": "emergency.incident", "args": {"incident_id": "i1", "tenant": "jia",
                                                        "confirmed_by": "zhou", "at": 20,
                                                        "requested_by": "lin"}},
                {"op": "emergency.authorize", "args": {"event_id": "ea", "emergency_id": "e1",
                                                         "tenant": "jia", "cpu_extra": 4,
                                                         "mem_extra": 4, "at": 20, "expires_at": 22,
                                                         "requested_by": "lin", "incident_id": "i1"}},
                {"op": "reserve.node", "args": {"node_id": "n1", "zone": "z1", "cpu": 20, "mem": 20}},
                {"op": "reserve.request", "args": {"request_id": "Q", "tenant": "jia", "grp": "g",
                                                    "cpu": 12, "mem": 12, "interruptible": True}},
                {"op": "reserve.place", "args": {"event_id": "p", "reservation_id": "rQ",
                                                  "request_id": "Q", "lease_until": 22, "at": 20}},
                {"op": "emergency.expire", "args": {"at": 22}},
                {"op": "approval.audit_report", "args": {"tenant": "jia"}},
            ]
        }
        fx = pathlib.Path(self.tmp.name) / "fixture.json"
        fx.write_text(json.dumps(fixture), encoding="utf-8")
        out = run(str(pathlib.Path(self.tmp.name) / "cli.sqlite"), fx)
        ops = [(x["op"], x["result"]) for x in out["results"]]
        self.assertIn(("approval.commit", "base_revision_conflict"), ops)
        self.assertIn(("reserve.place", "reserved:n1"), ops)
        self.assertIn(("emergency.expire", ["rQ"]), ops)
        self.assertTrue(out["state"]["audit_replay"]["consistent"])
        # Entire CLI payload must be JSON serializable for `cli.py main`.
        json.dumps(out, ensure_ascii=False)

    def test_shipped_governance_fixture_runs_and_replays(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        db_file = str(pathlib.Path(self.tmp.name) / "shipped.sqlite")
        out = run(db_file, root / "fixtures" / "approval_governance.json", "approval")
        verdicts = {op: res for op, res in ((x["op"], x["result"]) for x in out["results"])}
        self.assertEqual(verdicts["approval.commit"], "base_revision_conflict")
        self.assertEqual(verdicts["reserve.place"], "reserved:n1")
        self.assertEqual(verdicts["emergency.review"], "review_failed")
        self.assertTrue(out["state"]["audit_replay"]["consistent"])


if __name__ == "__main__":
    unittest.main()
