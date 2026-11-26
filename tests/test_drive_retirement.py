"""Evidence tests for physical drive retirement, destruction and reuse.

The scenarios follow the D1/D2/K case:

* D1 (serial SN-D1) carried customer A's V1; the logical copy moved at t=20;
  the wipe tool printed success at t=21 while firmware still reported two
  inaccessible regions S1/S2; the recycler arrived at t=22 with only the
  printout and no physical witness.
* Key K still wraps customer B's V2 on the running D2, so K must survive
  until every envelope dependency is safely rekeyed.

Every disruption named in the work order has a dedicated test: wrong serial,
receipt replay, expanding hidden-region scope, interrupted D2 rekey, a late
third K envelope, early recycler signature, failed two-person witnessing,
plus unique certificate numbers and the original resource suite.
"""
import tempfile
import unittest

from cloudquota import (
    drive_asset,
    drive_sanitize,
    key_envelope,
    volume_copy,
    drive_retirement as dr,
)
from cloudquota.store import open_db, one


class RetirementCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = open_db(self.tmp.name + "/retire.sqlite")

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    # -- world builders ----------------------------------------------------

    def seed_world(self, with_copy_bytes=True):
        db = self.db
        self.assertEqual(
            drive_asset.attach(db, "att-d1", "D1", "SN-D1", "replica-D1", "ctl-1", 10),
            "captured")
        self.assertEqual(
            drive_asset.attach(db, "att-d2", "D2", "SN-D2", "replica-D2", "ctl-2", 11),
            "captured")
        self.assertEqual(key_envelope.record(db, "ke-d1", "K", "D1", "V1", 2, "hsm"), "captured")
        self.assertEqual(key_envelope.record(db, "ke-d2", "K", "D2", "V2", 3, "hsm"), "captured")
        self.assertEqual(
            drive_sanitize.receipt(db, "rcp-wipe", "D1", "overwrite+verify", 21,
                                   "wipe-tool-9", "success"),
            "captured")
        if with_copy_bytes:
            self.assertEqual(
                volume_copy.record(db, "vc-1", "V1", "blk-1", "replica-D1", 2, 7,
                                   b"customer-a-secret-bytes", 19),
                "captured")
        self.assertEqual(dr.open_case(db, "case-d1", "D1", "SN-D1", at=18), "quarantined")
        self.assertEqual(dr.firmware_report(db, "fw-1", "D1", ["S1", "S2"], 21), "captured")
        self.assertEqual(dr.link_receipt(db, "link-rcp", "D1", "rcp-wipe"), "receipt_linked")
        self.assertEqual(dr.record_migration(db, "mig-v1", "D1", "V1", 20, 0, "replica-NEW"),
                         "migration_recorded")

    def full_custody(self, drive="D1"):
        db = self.db
        self.assertEqual(dr.remove_drive(db, "ev-remove", drive, 18), "recorded")
        self.assertEqual(dr.transport_drive(db, "ev-ship", drive, 23), "recorded")
        self.assertEqual(dr.receive_drive(db, "ev-receive", drive, 24), "recorded")
        self.assertEqual(dr.inspect_drive(db, "ev-inspect", drive, 25), "recorded")

    def two_witnesses(self):
        db = self.db
        self.assertEqual(dr.register_witness(db, "w-alice", "Alice", at=29), "witness_registered")
        self.assertEqual(dr.register_witness(db, "w-bob", "Bob", at=29), "witness_registered")
        return ["w-alice", "w-bob"]

    def complete_d2_rekey(self, job="rk-d2", at=29):
        db = self.db
        self.assertEqual(dr.start_rekey(db, job, "D2", "V2", "K", "K-NEW", 26), "rekey_started")
        self.assertEqual(dr.mark_reencrypted(db, job, 28), "reencrypted")
        self.assertEqual(dr.verify_readback(db, job, at, True), "readback_verified")

    def destroy_k(self, cert="CERT-KEY-K", at=36, survey="svc-k"):
        db = self.db
        self.assertEqual(dr.survey_dependencies(db, survey, "K", 31), "survey_recorded")
        self.assertEqual(dr.destroy_key(db, cert, "K", at, survey_id=survey), "key_destroyed")

    def path_b_ready_for_cert(self):
        """Everything before the reuse certificate."""
        self.full_custody()
        self.complete_d2_rekey()
        self.destroy_k()
        self.assertEqual(
            dr.verify_hidden_areas(self.db, "hv-1", "D1", 37, ["S1", "S2"],
                                   verifier="special-lab"),
            "hidden_areas_verified")
        self.assertEqual(dr.register_witness(self.db, "w-ivy", "Ivy", at=38),
                         "witness_registered")
        self.assertEqual(dr.review_reuse(self.db, "review-1", "D1", 38), "reuse_approved")


# ---------------------------------------------------------------------------
# Canonical minute-22 situation
# ---------------------------------------------------------------------------

class CanonicalD1Test(RetirementCase):
    def test_tool_success_is_not_safe_departure(self):
        self.seed_world()
        db = self.db
        proof = dr.evaluate(db, "D1")

        # Identity was checked against the physical asset registry.
        self.assertEqual(proof["identity"]["status"], "verified")
        self.assertEqual(proof["identity"]["expected_serial"], "SN-D1")

        # The tool receipt exists and succeeded, but its scope is the tool run.
        self.assertTrue(proof["sanitize"]["tool_success"])
        self.assertFalse(proof["sanitize"]["whole_drive_proven"])
        self.assertEqual(len(proof["sanitize"]["receipts"]), 1)

        # Firmware hidden regions remain uncovered by an overwrite receipt.
        self.assertEqual(proof["media"]["total"], 2)
        self.assertEqual(proof["media"]["uncovered"], ["S1", "S2"])

        # Logical migration emptied the catalog and replica bytes remain in the
        # platform ledger, but none of that proves media clearance.
        self.assertTrue(proof["logical"]["all_catalog_copies_moved"])
        self.assertFalse(proof["logical"]["proves_media_clearance"])
        self.assertGreaterEqual(proof["logical"]["historical_copy_count"], 1)

        # K must be retained because D2/V2 is still an active dependency.
        self.assertIn("K", proof["keys_retained"])
        k = proof["keys"]["K"]
        active_pairs = {(d["drive"], d["volume"]) for d in k["active_dependencies"]}
        self.assertIn(("D2", "V2"), active_pairs)
        self.assertEqual(k["state"], "retained")

        # No proof of impossibility yet and the drive cannot leave.
        self.assertEqual(proof["data_recovery"], "not_established")
        self.assertFalse(proof["may_leave"])
        self.assertEqual(proof["verdict"], "not_releasable")
        self.assertIn("hidden_regions_unverified", proof["blockers"])

        # Recycler at minute 22 is refused, even with the success printout.
        verdict = dr.authorize_release(db, "rel-22", "D1", "RecyclerCo", 22)
        self.assertNotEqual(verdict, "released")
        self.assertIsNone(one(db, "SELECT * FROM releases WHERE release_id='rel-22'"))

    def test_database_completed_flag_alone_never_allows_pickup(self):
        self.seed_world()
        db = self.db
        self.assertEqual(dr.admin_mark_completed(db, "D1"), "marked_completed_without_proof")
        row = one(db, "SELECT state,completed FROM retirement_cases WHERE drive='D1'")
        self.assertEqual(row["state"], "completed")
        self.assertEqual(row["completed"], 1)

        proof = dr.evaluate(db, "D1")
        self.assertTrue(proof["database_completed_flag"])
        self.assertFalse(proof["may_leave"])
        self.assertNotEqual(
            dr.authorize_release(db, "rel-x", "D1", "RecyclerCo", 22), "released")
        self.assertIsNone(one(db, "SELECT * FROM releases WHERE release_id='rel-x'"))

    def test_empty_current_copy_catalog_does_not_clear_hidden_areas(self):
        self.seed_world()
        db = self.db
        # Migration attestation says zero copies remain in the live catalog.
        ov = dr.logical_overview(db, "D1")
        self.assertTrue(ov["all_catalog_copies_moved"])
        # Yet the historical byte record is still readable in the ledger.
        self.assertTrue(any(c["volume"] == "V1" for c in ov["historical_copy_records"]))
        # And firmware regions are untouched by catalog emptiness.
        self.assertEqual(dr.media_coverage(db, "D1")["uncovered"], ["S1", "S2"])
        self.assertIn("hidden_regions_unverified", dr.evaluate(db, "D1")["blockers"])


# ---------------------------------------------------------------------------
# Chain-of-custody tracking: serial, removal, transport, receipt, inspection
# ---------------------------------------------------------------------------

class CustodyTrackingTest(RetirementCase):
    def _verified_case(self):
        drive_asset.attach(self.db, "att", "D1", "SN1", "rep1", "ctl", 1)
        dr.open_case(self.db, "c", "D1", "SN1", 1)

    def test_each_missing_handoff_is_a_blocker(self):
        self._verified_case()
        db = self.db
        # No custody events at all.
        self.assertEqual(
            set(dr.custody_chain(db, "D1")["problems"]),
            {"missing_remove", "missing_transport", "missing_receive", "missing_inspect"})

        dr.remove_drive(db, "e1", "D1", 2)
        self.assertNotIn("missing_remove", dr.custody_chain(db, "D1")["problems"])
        dr.transport_drive(db, "e2", "D1", 3)
        dr.receive_drive(db, "e3", "D1", 4)
        problems = dr.custody_chain(db, "D1")["problems"]
        self.assertNotIn("missing_transport", problems)
        self.assertNotIn("missing_receive", problems)
        self.assertIn("missing_inspect", problems)

    def test_chronology_inversions_are_detected(self):
        self._verified_case()
        db = self.db
        dr.remove_drive(db, "e1", "D1", 2)
        dr.transport_drive(db, "e2", "D1", 10)
        # Receipt timestamped before shipment.
        dr.receive_drive(db, "e3", "D1", 5)
        dr.inspect_drive(db, "e4", "D1", 6)
        self.assertIn("receive_before_transport", dr.custody_chain(db, "D1")["problems"])
        self.assertIn("receive_before_transport", dr.evaluate(db, "D1")["blockers"])

    def test_final_destination_is_recorded_on_release(self):
        self.seed_world()
        self.full_custody()
        w = self.two_witnesses()
        db = self.db
        dr.certify_shred(db, "S", "D1", 30, w)
        dr.handover_fragments(db, "F", "D1", 31, "S", receiver="R", signer="C")
        self.assertEqual(
            dr.authorize_release(db, "REL", "D1", "R", 32,
                                 destination="certified_material_recovery"),
            "released")
        proof = dr.evaluate(db, "D1")
        self.assertEqual(proof["destination"], "certified_material_recovery")
        self.assertTrue(proof["released"])


# ---------------------------------------------------------------------------
# Required disruption 1: wrong serial label
# ---------------------------------------------------------------------------

class WrongSerialTest(RetirementCase):
    def test_mismatched_label_is_detected_and_blocks_every_terminal_path(self):
        drive_asset.attach(self.db, "att", "D1", "SN-REAL", "rep1", "ctl", 10)
        verdict = dr.open_case(self.db, "case", "D1", "SN-WRONG", at=18)
        self.assertEqual(verdict, "serial_mismatch")
        self.assertEqual(dr.verify_serial(self.db, "D1"), "serial_mismatch")

        # Even with otherwise perfect paperwork, nothing terminal is allowed.
        self.full_custody()
        w = self.two_witnesses()
        self.assertEqual(dr.certify_shred(self.db, "SHRED-X", "D1", 30, w), "serial_mismatch")
        self.assertNotEqual(
            dr.authorize_release(self.db, "rel", "D1", "recycler", 32), "released")
        proof = dr.evaluate(self.db, "D1")
        self.assertEqual(proof["blockers"][0], "serial_mismatch")
        self.assertFalse(proof["may_leave"])

    def test_verify_serial_against_asset_registry_after_open(self):
        drive_asset.attach(self.db, "att", "D9", "SN-9", "rep9", "ctl", 10)
        self.assertEqual(dr.open_case(self.db, "c9", "D9", at=1), "quarantined")
        self.assertEqual(dr.verify_serial(self.db, "D9", "SN-OTHER", 2), "serial_mismatch")
        self.assertEqual(dr.verify_serial(self.db, "D9", "SN-9", 3), "identity_verified")
        self.assertEqual(dr.evaluate(self.db, "D9")["identity"]["status"], "verified")


# ---------------------------------------------------------------------------
# Required disruption 2: tool receipt replay
# ---------------------------------------------------------------------------

class ReceiptReplayTest(RetirementCase):
    def test_seed_receipt_replay_conflict_and_drive_binding(self):
        db = self.db
        self.assertEqual(drive_sanitize.receipt(db, "r1", "D1", "wipe", 21, "tool", "success"),
                         "captured")
        # Identical resubmission is an idempotent replay...
        self.assertEqual(drive_sanitize.receipt(db, "r1", "D1", "wipe", 21, "tool", "success"),
                         "replayed")
        # ...same id with different content is a conflict.
        self.assertEqual(drive_sanitize.receipt(db, "r1", "D1", "wipe", 21, "tool", "failed"),
                         "receipt_conflict")

        dr.open_case(db, "c1", "D1", "SN-D1", 18)
        drive_asset.attach(db, "a1", "D1", "SN-D1", "rep1", "ctl", 10)
        # Linking is idempotent.
        self.assertEqual(dr.link_receipt(db, "l1", "D1", "r1"), "receipt_linked")
        self.assertEqual(dr.link_receipt(db, "l1", "D1", "r1"), "replayed")
        # The same physical printout cannot be consumed by another link/case.
        self.assertEqual(dr.link_receipt(db, "l2", "D1", "r1"), "receipt_already_linked")
        # Unknown receipt id.
        self.assertEqual(dr.link_receipt(db, "l3", "D1", "missing"), "receipt_not_found")

    def test_receipt_from_another_drive_is_rejected(self):
        db = self.db
        drive_asset.attach(db, "a2", "D2", "SN-D2", "rep2", "ctl", 10)
        drive_sanitize.receipt(db, "r-d2", "D2", "wipe", 21, "tool", "success")
        dr.open_case(db, "c1", "D1", "SN-D1", 18)
        # Replaying D2's printout against D1 must fail the drive binding.
        self.assertEqual(dr.link_receipt(db, "l", "D1", "r-d2"), "receipt_drive_mismatch")

    def test_failed_receipt_cannot_be_linked_as_clearance(self):
        db = self.db
        drive_sanitize.receipt(db, "bad", "D1", "wipe", 21, "tool", "failed")
        dr.open_case(db, "c", "D1", "SN-D1", 18)
        self.assertEqual(dr.link_receipt(db, "l", "D1", "bad"), "receipt_not_successful")


# ---------------------------------------------------------------------------
# Required disruption 3: hidden sector scope expansion
# ---------------------------------------------------------------------------

class HiddenSectorExpansionTest(RetirementCase):
    def test_partial_verification_is_a_gap(self):
        self.seed_world()
        self.assertEqual(
            dr.verify_hidden_areas(self.db, "hv", "D1", 30, ["S1"]), "coverage_gap")
        cov = dr.media_coverage(self.db, "D1")
        self.assertFalse(cov["coverage_complete"])
        self.assertIn("S2", cov["uncovered"])

    def test_expanded_firmware_scope_reopens_completed_verification(self):
        self.seed_world()
        db = self.db
        self.assertEqual(dr.verify_hidden_areas(db, "hv", "D1", 30, ["S1", "S2"]),
                         "hidden_areas_verified")
        self.assertTrue(dr.media_coverage(db, "D1")["coverage_complete"])

        # Firmware later enlarges the defect list.
        self.assertEqual(dr.firmware_report(db, "fw-2", "D1", [{"sector": "S3"}], 33),
                         "captured")
        cov = dr.media_coverage(db, "D1")
        self.assertEqual(cov["total"], 3)
        self.assertEqual(cov["uncovered"], ["S3"])
        self.assertTrue(cov["scope_expanded_after_verification"])
        self.assertIn("hidden_regions_unverified", dr.evaluate(db, "D1")["blockers"])

    def test_expansion_after_reuse_certificate_blocks_release(self):
        self.seed_world()
        self.path_b_ready_for_cert()
        db = self.db
        self.assertEqual(dr.certify_reuse(db, "REUSE-1", "D1", 39, ["w-ivy"]),
                         "reuse_certified")
        self.assertEqual(dr.sign_final(db, "SG-1", "D1", "REUSE-1", 40,
                                       kind="rewarehouse", signer="Wu"),
                         "signoff_recorded")
        # New hidden region appears after certification but before pickup.
        dr.firmware_report(db, "fw-2", "D1", ["S3", "S4"], 41)
        proof = dr.evaluate(db, "D1")
        self.assertIn("hidden_regions_unverified", proof["blockers"])
        self.assertFalse(proof["may_leave"])
        self.assertEqual(dr.authorize_release(db, "rel", "D1", "buyer", 42),
                         "hidden_regions_unverified")


# ---------------------------------------------------------------------------
# Required disruption 4: D2 re-encryption interrupted
# ---------------------------------------------------------------------------

class RekeyInterruptionTest(RetirementCase):
    def test_interrupted_rekey_keeps_k_and_drive_quarantined(self):
        self.seed_world()
        self.full_custody()
        db = self.db
        self.assertEqual(dr.start_rekey(db, "rk", "D2", "V2", "K", "K2", 26), "rekey_started")
        self.assertEqual(dr.interrupt_rekey(db, "rk", 27, "power-loss"), "rekey_interrupted")

        # Progressing an interrupted job is refused.
        self.assertEqual(dr.mark_reencrypted(db, "rk", 28), "rekey_interrupted")
        # K cannot be destroyed; V2 would lose readability.
        self.assertEqual(dr.destroy_key(db, "KC", "K", 29), "rekey_interrupted")
        self.assertIn("K", dr.retained_keys(db))

        # Even a bogus "completed" database flag cannot release D1.
        dr.admin_mark_completed(db, "D1")
        verdict = dr.authorize_release(db, "rel", "D1", "recycler", 40)
        self.assertNotEqual(verdict, "released")
        proof = dr.evaluate(db, "D1")
        self.assertFalse(proof["may_leave"])
        self.assertIsNone(one(db, "SELECT * FROM releases WHERE release_id='rel'"))

    def test_readback_must_follow_reencryption_and_can_fail(self):
        db = self.db
        # K really wraps the running D2/V2 volume, otherwise destruction of an
        # unused key would correctly succeed.
        key_envelope.record(db, "ke", "K", "D2", "V2", 1, "hsm")
        dr.start_rekey(db, "rk", "D2", "V2", "K", "K2", 1)
        self.assertEqual(dr.verify_readback(db, "rk", 2), "reencryption_incomplete")
        dr.mark_reencrypted(db, "rk", 3)
        self.assertEqual(dr.verify_readback(db, "rk", 4, ok=False), "readback_failed")
        self.assertEqual(dr.destroy_key(db, "KC", "K", 5), "rekey_interrupted")

    def test_fresh_rekey_job_recovers_from_interruption(self):
        self.seed_world()
        db = self.db
        dr.start_rekey(db, "rk-bad", "D2", "V2", "K", "K2", 26)
        dr.interrupt_rekey(db, "rk-bad", 27)
        # A new independent-key job completes and verifies readback.
        self.complete_d2_rekey(job="rk-good")
        self.destroy_k()
        state = one(db, "SELECT state FROM key_states WHERE key_id='K'")
        self.assertEqual(state["state"], "destroyed")

    def test_new_key_must_be_independent(self):
        self.assertEqual(
            dr.start_rekey(self.db, "rk", "D2", "V2", "K", "K", 1),
            "new_key_not_independent")


# ---------------------------------------------------------------------------
# Required disruption 5: late third K envelope
# ---------------------------------------------------------------------------

class LateEnvelopeTest(RetirementCase):
    def test_third_envelope_arriving_late_blocks_destruction(self):
        self.seed_world()
        self.complete_d2_rekey()
        db = self.db
        # Survey knows only the D1 and D2 wrappings.
        self.assertEqual(dr.survey_dependencies(db, "sv-1", "K", 30), "survey_recorded")

        # A third wrapping is recorded after the survey.
        self.assertEqual(key_envelope.record(db, "ke-d3", "K", "D3", "V3", 9, "hsm-eu"),
                         "captured")
        verdict = dr.destroy_key(db, "KC-LATE", "K", 31, survey_id="sv-1")
        self.assertEqual(verdict, "late_envelope")
        self.assertIn("K", dr.retained_keys(db))
        self.assertIsNone(one(db, "SELECT * FROM key_states WHERE key_id='K'"))

        # Merely re-trying does not help: V3 is still active.
        self.assertEqual(dr.destroy_key(db, "KC-LATE", "K", 32, survey_id="sv-1"),
                         "late_envelope")

    def test_third_envelope_must_be_rekeyed_and_resurveyed(self):
        self.seed_world()
        self.complete_d2_rekey()
        db = self.db
        dr.survey_dependencies(db, "sv-1", "K", 30)
        key_envelope.record(db, "ke-d3", "K", "D3", "V3", 9, "hsm-eu")

        # Resolve the third dependency with its own verified rekey.
        dr.start_rekey(db, "rk-d3", "D3", "V3", "K", "K3", 32)
        self.assertEqual(dr.complete_rekey(db, "rk-d3", 34), "readback_verified")

        # Old survey is stale; the key still cannot be destroyed under it.
        self.assertEqual(dr.destroy_key(db, "KC-1", "K", 35, survey_id="sv-1"),
                         "survey_outdated")
        dr.survey_dependencies(db, "sv-2", "K", 35)
        self.assertEqual(dr.destroy_key(db, "KC-2", "K", 36, survey_id="sv-2"),
                         "key_destroyed")
        # Idempotent replay and unique destruction certificate.
        self.assertEqual(dr.destroy_key(db, "KC-2", "K", 36, survey_id="sv-2"),
                         "replayed")
        self.assertEqual(dr.destroy_key(db, "KC-OTHER", "K", 37), "key_already_destroyed")


# ---------------------------------------------------------------------------
# Required disruption 6: recycler signs early
# ---------------------------------------------------------------------------

class EarlySignoffTest(RetirementCase):
    def test_carrier_receipt_before_disposition_is_refused(self):
        self.seed_world()
        db = self.db
        # t=22: recycler signs before any shred/handover exists.
        self.assertEqual(
            dr.record_carrier_receipt(db, "carrier-1", "D1", 22, "RecyclerCo", "Driver Dan"),
            "premature_signoff")
        self.assertIsNone(one(db, "SELECT * FROM carrier_receipts WHERE receipt_id='carrier-1'"))

    def test_backdated_early_signature_is_detected_by_chronology(self):
        self.seed_world()
        self.full_custody()
        w = self.two_witnesses()
        db = self.db
        # A backdated final-signoff row written directly (e.g. forged paper
        # entered into the database ahead of the actual shred).
        db.execute(
            "INSERT INTO custody_events(id,drive,kind,at,actor,location,detail) "
            "VALUES('early-paper','D1','signoff',22,'Driver Dan','dock','{}')")
        db.commit()

        self.assertEqual(dr.certify_shred(db, "SHRED-1", "D1", 30, w), "shred_certified")
        self.assertEqual(dr.handover_fragments(db, "FRAG-1", "D1", 31, "SHRED-1",
                                               receiver="RecyclerCo", signer="Carol"),
                         "fragment_certificate_issued")
        proof = dr.evaluate(db, "D1")
        self.assertIn("premature_signoff", proof["blockers"])
        self.assertFalse(proof["may_leave"])
        self.assertEqual(dr.authorize_release(db, "rel", "D1", "RecyclerCo", 32),
                         "premature_signoff")

    def test_handover_cannot_predate_shred_certificate(self):
        self.seed_world()
        self.two_witnesses()
        db = self.db
        dr.certify_shred(db, "SHRED-1", "D1", 30, ["w-alice", "w-bob"])
        self.assertEqual(
            dr.handover_fragments(db, "FRAG-EARLY", "D1", 22, "SHRED-1",
                                  receiver="R", signer="C"),
            "premature_signoff")
        # No shred cert at all.
        self.assertEqual(
            dr.handover_fragments(db, "FRAG-NONE", "D2", 31, receiver="R", signer="C"),
            "unknown_drive")

    def test_carrier_receipt_after_valid_handover_is_recorded(self):
        self.seed_world()
        self.full_custody()
        w = self.two_witnesses()
        db = self.db
        dr.certify_shred(db, "SHRED-1", "D1", 30, w)
        dr.handover_fragments(db, "FRAG-1", "D1", 31, "SHRED-1", receiver="R", signer="C")
        self.assertEqual(
            dr.record_carrier_receipt(db, "CARRIER-1", "D1", 32, "RecyclerCo", "Driver Dan"),
            "carrier_receipt_recorded")
        self.assertEqual(
            dr.record_carrier_receipt(db, "CARRIER-1", "D1", 32, "RecyclerCo", "Driver Dan"),
            "replayed")
        self.assertTrue(dr.can_release(db, "D1", 33))

    def test_release_timestamp_before_completion_is_refused(self):
        self.seed_world()
        self.full_custody()
        w = self.two_witnesses()
        dr.certify_shred(self.db, "SHRED-1", "D1", 30, w)
        dr.handover_fragments(self.db, "FRAG-1", "D1", 31, "SHRED-1", receiver="R", signer="C")
        self.assertEqual(
            dr.authorize_release(self.db, "rel-early", "D1", "R", 25),
            "release_before_completion")


# ---------------------------------------------------------------------------
# Required disruption 7: two-person witness failure
# ---------------------------------------------------------------------------

class WitnessFailureTest(RetirementCase):
    def test_two_distinct_valid_witnesses_required(self):
        self.seed_world()
        db = self.db
        dr.register_witness(db, "w1", "Alice")
        # Only one witness.
        self.assertEqual(dr.certify_shred(db, "S1", "D1", 30, ["w1"]),
                         "insufficient_witnesses")
        # Same person listed twice.
        self.assertEqual(dr.certify_shred(db, "S2", "D1", 30, ["w1", "w1"]),
                         "duplicate_witness")
        # Unknown witness id.
        self.assertEqual(dr.certify_shred(db, "S3", "D1", 30, ["w1", "ghost"]),
                         "unknown_witness")

    def test_invalid_witness_blocks_certification(self):
        self.seed_world()
        db = self.db
        dr.register_witness(db, "w1", "Alice")
        dr.register_witness(db, "w2", "Bob")
        self.assertEqual(dr.invalidate_witness(db, "w2", 29, "conflict of interest"),
                         "witness_invalidated")
        self.assertEqual(dr.certify_shred(db, "S", "D1", 30, ["w1", "w2"]),
                         "witness_invalid")

    def test_witness_invalidated_after_cert_voids_release_proof(self):
        self.seed_world()
        self.full_custody()
        w = self.two_witnesses()
        db = self.db
        self.assertEqual(dr.certify_shred(db, "SHRED-1", "D1", 30, w), "shred_certified")
        self.assertEqual(dr.handover_fragments(db, "FRAG-1", "D1", 31, "SHRED-1",
                                              receiver="R", signer="C"),
                         "fragment_certificate_issued")
        # Much later one witness's accreditation is revoked.
        dr.invalidate_witness(db, "w-bob", 40, "credential revoked")
        proof = dr.evaluate(db, "D1")
        self.assertIn("witness_invalid", proof["blockers"])
        self.assertFalse(proof["physical_destruction_proven"])
        self.assertEqual(dr.authorize_release(db, "rel", "D1", "R", 41), "witness_invalid")


# ---------------------------------------------------------------------------
# Required: unique non-repeatable certificate numbers and path separation
# ---------------------------------------------------------------------------

class CertificateUniquenessAndPathTest(RetirementCase):
    def test_certificate_number_cannot_be_reused(self):
        self.seed_world()
        w = self.two_witnesses()
        db = self.db
        self.assertEqual(dr.certify_shred(db, "CERT-1", "D1", 30, w), "shred_certified")
        self.assertEqual(dr.certify_shred(db, "CERT-1", "D1", 30, w), "replayed")
        # Same number, different content/drive -> hard conflict.
        self.assertEqual(dr.certify_shred(db, "CERT-1", "D1", 31, w),
                         "certificate_number_reused")
        self.assertEqual(dr.issue_certificate(db, "CERT-1", "reuse", "D1", 31),
                         "certificate_number_reused")

    def test_shred_fragment_certificate_cannot_prove_reuse(self):
        self.seed_world()
        self.path_b_ready_for_cert()
        w = self.two_witnesses()
        db = self.db
        # Physical path happens first.
        self.assertEqual(dr.certify_shred(db, "SHRED-1", "D1", 39, w), "shred_certified")
        self.assertEqual(dr.handover_fragments(db, "FRAG-1", "D1", 40, "SHRED-1",
                                               receiver="R", signer="C"),
                         "fragment_certificate_issued")
        # A shredded drive cannot be certified for reuse...
        self.assertEqual(dr.certify_reuse(db, "REUSE-1", "D1", 41, ["w-ivy"]),
                         "path_already_shredded")
        # ...and the fragment certificate cannot be used as a reuse signoff.
        self.assertEqual(dr.sign_final(db, "SG-BAD", "D1", "FRAG-1", 41,
                                       kind="rewarehouse", signer="Wu"),
                         "certificate_kind_mismatch")

    def test_minted_certificate_numbers_are_unique(self):
        nums = {dr.mint_certificate_number("shred") for _ in range(100)}
        self.assertEqual(len(nums), 100)


# ---------------------------------------------------------------------------
# Approved path A: controlled two-person shredding + fragment certificate
# ---------------------------------------------------------------------------

class PathAPhysicalDestructionTest(RetirementCase):
    def test_d1_shred_path_end_to_end(self):
        self.seed_world()
        self.full_custody()
        w = self.two_witnesses()
        db = self.db

        self.assertEqual(dr.certify_shred(db, "SHRED-2026-0001", "D1", 30, w,
                                          actor="onsite two-person team"),
                         "shred_certified")
        self.assertEqual(
            dr.handover_fragments(db, "FRAG-2026-0001", "D1", 31, "SHRED-2026-0001",
                                  receiver="Certified Disposal Inc.", signer="Commissioner Li",
                                  carrier="Secure Logistics", weight_kg=0.42),
            "fragment_certificate_issued")

        proof = dr.evaluate(db, "D1")
        self.assertEqual(proof["path"], "shred")
        self.assertTrue(proof["physical_destruction_proven"])
        self.assertEqual(proof["data_recovery"], "impossible_physical_destruction")
        self.assertTrue(proof["may_leave"])
        self.assertEqual(proof["verdict"], "releasable_shredded_fragments")
        self.assertEqual(proof["blockers"], [])

        # K is deliberately retained for the still-running D2/V2.
        self.assertIn("K", proof["keys_retained"])
        self.assertNotIn("K", proof["keys_destroyed"])
        self.assertEqual(
            one(db, "SELECT state FROM key_states WHERE key_id='K'"), None)

        # Only fragments go to the material stream; D1 is not resold as a drive.
        self.assertEqual(
            dr.authorize_release(db, "REL-1", "D1", "Certified Disposal Inc.", 32,
                                 destination="certified_shred_fragment_stream"),
            "released")
        rel = one(db, "SELECT * FROM releases WHERE release_id='REL-1'")
        self.assertEqual(rel["verdict"], "released")
        self.assertIn("fragment", rel["destination"])
        self.assertEqual(dr.authorize_release(db, "REL-1", "D1", "Certified Disposal Inc.", 32),
                         "replayed")

    def test_flexible_shred_and_release_signatures(self):
        self.seed_world()
        self.full_custody()
        db = self.db
        dr.register_witness(db, "w1", "A")
        dr.register_witness(db, "w2", "B")
        # entity-first ordering through the flexible alias
        self.assertEqual(dr.shred(db, "D1", "SHRED-FLEX", 30, ["w1", "w2"]), "shred_certified")
        dr.handover_fragments(db, "FRAG-FLEX", "D1", 31, "SHRED-FLEX", receiver="R", signer="C")
        # drive-first release with generated release id
        self.assertEqual(dr.release(db, "D1", "RecyclerCo", 32), "released")


# ---------------------------------------------------------------------------
# Approved path B: rekey D2, destroy K, verify hidden areas, reuse/signoff
# ---------------------------------------------------------------------------

class PathBReuseTest(RetirementCase):
    def test_d1_reuse_path_end_to_end_with_rewarehouse_signoff(self):
        self.seed_world()
        self.path_b_ready_for_cert()
        db = self.db

        self.assertEqual(dr.certify_reuse(db, "REUSE-2026-0001", "D1", 39, ["w-ivy"]),
                         "reuse_certified")
        self.assertEqual(
            dr.sign_final(db, "SG-WH-1", "D1", "REUSE-2026-0001", 40,
                          kind="rewarehouse", signer="Warehouse Wu", receiver="WH-7"),
            "signoff_recorded")

        proof = dr.evaluate(db, "D1")
        self.assertEqual(proof["path"], "reuse")
        self.assertEqual(proof["media"]["uncovered"], [])
        self.assertIn("K", proof["keys_destroyed"])
        self.assertNotIn("K", proof["keys_retained"])
        self.assertEqual(
            proof["data_recovery"],
            "impossible_cryptographic_erasure_and_verified_media")
        self.assertTrue(proof["may_leave"])
        self.assertEqual(proof["verdict"], "releasable_reusable_drive")

        self.assertEqual(
            dr.authorize_release(db, "REL-B", "D1", "Warehouse WH-7", 41,
                                 destination="rewarehouse_stock_bin_7"),
            "released")

    def test_factory_signoff_is_an_alternative_real_acceptance(self):
        self.seed_world()
        self.path_b_ready_for_cert()
        db = self.db
        dr.certify_reuse(db, "REUSE-F", "D1", 39, ["w-ivy"])
        self.assertEqual(
            dr.factory_signoff(db, "SG-F", "D1", "REUSE-F", 40, signer="Factory QA Qin"),
            "signoff_recorded")
        proof = dr.evaluate(db, "D1")
        self.assertTrue(proof["may_leave"])
        self.assertEqual(
            dr.authorize_release(db, "REL-F", "D1", "Refurb Buyer", 41,
                                 destination="factory_outgoing"),
            "released")

    def test_reuse_requires_destroyed_drive_key(self):
        self.seed_world()
        self.full_custody()
        db = self.db
        # D2 rekeyed but K deliberately not destroyed.
        self.complete_d2_rekey()
        dr.verify_hidden_areas(db, "hv", "D1", 37, ["S1", "S2"])
        dr.register_witness(db, "w", "Ivy")
        dr.review_reuse(db, "rv", "D1", 38)
        self.assertEqual(dr.choose_path(db, "D1", "reuse", 36), "path_selected")
        self.assertEqual(dr.certify_reuse(db, "REUSE-NOKEY", "D1", 39, ["w"]),
                         "drive_key_not_destroyed")
        self.assertIn("drive_key_not_destroyed", dr.evaluate(db, "D1")["blockers"])

    def test_failed_reuse_review_blocks_certificate(self):
        self.seed_world()
        self.path_b_ready_for_cert()
        db = self.db
        self.assertEqual(dr.review_reuse(db, "review-bad", "D1", 38,
                                         approved=False, note="residual damage"),
                         "reuse_rejected")
        # Latest review is a rejection; certification is refused.
        self.assertEqual(dr.certify_reuse(db, "REUSE-X", "D1", 39, ["w-ivy"]),
                         "reuse_review_failed")


# ---------------------------------------------------------------------------
# Interruption / quarantine invariants and small unit behaviours
# ---------------------------------------------------------------------------

class QuarantineAndIntegrationTest(RetirementCase):
    def test_interrupted_disposition_keeps_drive_quarantined(self):
        self.seed_world()
        db = self.db
        # Some custody progress, but disposition never finishes.
        self.full_custody()
        dr.start_rekey(db, "rk", "D2", "V2", "K", "K2", 26)
        dr.interrupt_rekey(db, "rk", 27)
        dr.admin_mark_completed(db, "D1")
        proof = dr.evaluate(db, "D1")
        self.assertTrue(proof["quarantined"])
        self.assertFalse(proof["released"])
        self.assertFalse(proof["may_leave"])

    def test_unknown_drive_has_no_proof(self):
        verdict = dr.authorize_release(self.db, "r", "NOPE", "co", 1)
        self.assertEqual(verdict, "unknown_drive")
        self.assertEqual(dr.evaluate(self.db, "NOPE")["verdict"], "unknown_drive")

    def test_firmware_report_replay_and_conflict(self):
        db = self.db
        self.assertEqual(dr.firmware_report(db, "f", "D1", ["S1"], 1), "captured")
        self.assertEqual(dr.firmware_report(db, "f", "D1", ["S1"], 1), "replayed")
        self.assertEqual(dr.firmware_report(db, "f", "D1", ["S2"], 1),
                         "firmware_report_conflict")

    def test_key_with_no_envelopes_can_be_destroyed(self):
        self.assertEqual(dr.destroy_key(self.db, "KC", "ORPHAN", 1), "key_destroyed")
        self.assertIn("ORPHAN", dr.destroyed_keys(self.db))

    def test_quarantine_helper_records_hold_event(self):
        # Alternate house-style entry point: (record_id, drive, at, serial).
        result = dr.quarantine(self.db, "q1", "D7", 5, "SN-7")
        self.assertIn(result, ("quarantined", "serial_unverified"))
        chain = dr.custody_chain(self.db, "D7")
        self.assertIn("quarantine", chain["present"])

    def test_fleet_overview_separates_releasable_and_held_devices(self):
        # D1 finishes physical destruction; D2 only has a case and stays held.
        self.seed_world()
        self.full_custody()
        w = self.two_witnesses()
        db = self.db
        dr.certify_shred(db, "SHRED-1", "D1", 30, w)
        dr.handover_fragments(db, "FRAG-1", "D1", 31, "SHRED-1", receiver="R", signer="C")
        dr.authorize_release(db, "REL-1", "D1", "R", 32)
        dr.open_case(db, "case-d2", "D2", "SN-D2", at=18)

        fleet = dr.fleet_overview(db)
        self.assertIn("D1", fleet["may_leave"])
        self.assertIn("D2", fleet["quarantined"])
        self.assertIn("K", fleet["keys_retained"])  # D2/V2 still active

        doc = dr.customer_proof(db, "D1")
        self.assertEqual(doc["shred_certificate"], "SHRED-1")
        self.assertEqual(doc["fragment_handover_certificate"], "FRAG-1")
        self.assertIsNone(doc["reuse_certificate"])
        self.assertIn("K", doc["retained_shared_keys"])

    def test_seed_test_style_still_importable_and_green(self):
        # The seeded isolation modules remain the system of record and the
        # retirement engine reads their tables directly.
        db = self.db
        self.assertEqual(drive_asset.attach(db, "a", "drive-1", "serial-1", "replica-1",
                                            "ctl", 10), "captured")
        self.assertEqual(key_envelope.record(db, "k", "key-1", "drive-1", "vol-1", 2, "hsm"),
                         "captured")
        self.assertEqual(drive_sanitize.receipt(db, "r", "drive-1", "crypto", 20,
                                                "tool-1", "success"), "captured")
        deps = dr.key_dependencies(db, "key-1")
        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0]["resolution"], "active")


if __name__ == "__main__":
    unittest.main()
