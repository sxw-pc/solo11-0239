import pathlib
import tempfile
import unittest

from cloudquota import attest, agent_command, reserve, device_trust as dt
from cloudquota.store import open_db, one, rows


def quote(db, qid, node, device, nonce, counter, measurement, at, issuer="issuer-x"):
    return attest.quote(db, qid, node, device, nonce, counter, measurement, at, issuer)


def receipt(db, rid, node, device, command_digest, generation, result, at):
    return agent_command.receipt(db, rid, node, device, command_digest, generation, result, at)


class DeviceTrustBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = open_db(str(pathlib.Path(self.tmp.name) / "trust.sqlite"))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def enroll(self, device="K", node="N1", generation=1, at=0, fp="fp-K", serial="cert-K"):
        self.assertIn(dt.register_device(self.db, device, serial, fp, node, at, generation),
                      ("registered", "exists"))
        self.assertIn(dt.allow_measurement(self.db, "m-v1", "agent-1", 0), ("allowed", "exists"))
        return device, node

    def challenge_and_quote(self, cid, qid, device, node, nonce, counter, measurement, at):
        self.assertEqual(dt.issue_challenge(self.db, cid, nonce, device, at - 1, node), "issued")
        self.assertEqual(quote(self.db, qid, node, device, nonce, counter, measurement, at), "captured")
        return dt.evaluate_quote(self.db, qid)

    def command_digest(self, cid, device, node, generation, at):
        result, digest = dt.dispatch_command(self.db, cid, device, node, generation, at)
        self.assertEqual(result, "dispatched")
        return digest


class ScenarioTwoDispositions(DeviceTrustBase):
    """The minute-10..15 migration drama, from the same captured evidence."""

    def _common_evidence(self):
        self.enroll()
        # minute 10: chip K on N1 answers challenge A, boot counter 8
        self.assertEqual(self.challenge_and_quote("cA", "q10", "K", "N1", "nonce-A", 8, "m-v1", 10),
                         ("valid", "instance_quote"))
        # minute 11: the handover order exists but access/photo verification only lands at 15
        self.assertEqual(dt.begin_migration(self.db, "mig-1", "K", "N1", "N2", 11, "order-77"), "begun")
        # minute 12: N2 also presents K answering a fresh challenge B, counter 9
        self.assertEqual(dt.issue_challenge(self.db, "cB", "nonce-B", "K", 12, "N2"), "issued")
        self.assertEqual(quote(self.db, "q12", "N2", "K", "nonce-B", 9, "m-v1", 12), "captured")
        self.assertEqual(dt.evaluate_quote(self.db, "q12"), ("held", "possession_conflict"))
        # minute 13: both agents sign "capacity update ok", both pointing at generation 2
        d1 = self.command_digest("cmd-1", "K", "N1", 2, 13)
        d2 = self.command_digest("cmd-2", "K", "N2", 2, 13)
        self.assertEqual(receipt(self.db, "r13-N1", "N1", "K", d1, 2, "ok", 13), "captured")
        self.assertEqual(receipt(self.db, "r13-N2", "N2", "K", d2, 2, "ok", 13), "captured")
        self.assertEqual(dt.evaluate_receipt(self.db, "r13-N1"), ("held", "possession_conflict"))
        self.assertEqual(dt.evaluate_receipt(self.db, "r13-N2"), ("held", "possession_conflict"))

    def test_path_a_verified_handover_only_n2_new_generation_is_trusted(self):
        self._common_evidence()
        # minute 15: order original, access, photo, old-machine power-off corroborate each other
        self.assertEqual(dt.removal_evidence(self.db, "mig-1", "access-9", "photo-9", 11, 15), "removal_verified")
        # field challenge on the new machine, answered live by K on N2 (counter 10);
        # once removal is verified, this quote itself completes the takeover evidence
        self.assertEqual(dt.issue_challenge(self.db, "cC", "nonce-C", "K", 15, "N2"), "issued")
        self.assertEqual(quote(self.db, "q15", "N2", "K", "nonce-C", 10, "m-v1", 15), "captured")
        self.assertEqual(dt.evaluate_quote(self.db, "q15"), ("valid", "takeover_quote"))
        self.assertEqual(dt.install_evidence(self.db, "mig-1", "cC", "q15", 15), "installed")
        self.assertEqual(dt.decide_migration(self.db, "mig-1", 15), "verified")

        finals = {x["receipt_id"]: x for x in dt.finalize_receipts(self.db, "K", 15)}
        # N1's minute-13 receipt: anomalous original, never to be believed
        self.assertEqual(finals["r13-N1"]["verdict"], "anomalous_original")
        # N2's minute-13 receipt: real signature but pre-takeover generation, not authoritative
        self.assertEqual(finals["r13-N2"]["verdict"], "stale_generation")

        device = one(self.db, "SELECT * FROM dt_devices WHERE device='K'")
        self.assertEqual((device["node"], device["generation"], device["status"]), ("N2", 2, "active"))
        self.assertIsNone(one(self.db, "SELECT * FROM dt_isolation"))

        # only N2's new generation can execute; N1 backfill stays refused
        d3 = self.command_digest("cmd-3", "K", "N2", 2, 16)
        self.assertEqual(receipt(self.db, "r16", "N2", "K", d3, 2, "ok", 16), "captured")
        self.assertEqual(dt.evaluate_receipt(self.db, "r16"), ("trusted", "causal_chain_verified"))
        d4 = self.command_digest("cmd-4", "K", "N1", 1, 17)
        self.assertEqual(receipt(self.db, "r17", "N1", "K", d4, 1, "ok", 17), "captured")
        self.assertEqual(dt.evaluate_receipt(self.db, "r17")[0], "anomalous_original")

        # capacity entry: N2 trusted, N1 fail-closed
        self.assertEqual(reserve.node(self.db, "N2", "z", 5, 5, 2, device="K"), "accepted")
        self.assertTrue(reserve.node(self.db, "N1", "z", 5, 5, 1, device="K").startswith("untrusted_capacity:"))

    def test_path_b_uncorroborated_evidence_quarantines_everything(self):
        self._common_evidence()
        # security team cannot independently corroborate the handover
        self.assertEqual(dt.quarantine_device(self.db, "K", 15, "unverifiable_physical_handover"), "quarantined")
        # both minute-13 receipts get their final classification inside quarantine
        finals = {x["receipt_id"]: x for x in rows(self.db, "SELECT * FROM dt_receipt_verdicts")}
        self.assertEqual(finals["r13-N1"]["verdict"], "quarantined")
        self.assertEqual(finals["r13-N2"]["verdict"], "quarantined")
        # finalize_receipts is idempotent once nothing remains held
        self.assertEqual(dt.finalize_receipts(self.db, "K", 15), [])

        # reboot and re-challenge cannot reset suspicion
        self.assertEqual(dt.issue_challenge(self.db, "cD", "nonce-D", "K", 16, "N2"), "device_quarantined")
        self.assertEqual(dt.evaluate_quote(self.db, "q10"), ("valid", "instance_quote"))  # old verdict preserved
        # any later quote is rejected, any later receipt rejected
        self.assertEqual(quote(self.db, "q18", "N2", "K", "stolen-nonce", 11, "m-v1", 18), "captured")
        self.assertEqual(dt.evaluate_quote(self.db, "q18")[0], "quarantined")
        d5 = self.command_digest("cmd-5", "K", "N2", 3, 19)
        self.assertEqual(receipt(self.db, "r19", "N2", "K", d5, 3, "ok", 19), "captured")
        self.assertEqual(dt.evaluate_receipt(self.db, "r19"), ("quarantined", "device_under_isolation"))
        self.assertTrue(reserve.node(self.db, "N2", "z", 1, 1, 3, device="K").startswith("untrusted_capacity:"))

        # both nodes are isolated; re-register with a spare physical chip
        self.assertEqual({r["node"] for r in rows(self.db, "SELECT * FROM dt_isolation")}, {"N1", "N2"})
        self.assertEqual(dt.re_register(self.db, "K2", "cert-K2", "fp-K2", "N2", 20, 3), "registered")
        self.assertEqual(self.challenge_and_quote("cE", "q20", "K2", "N2", "nonce-E", 1, "m-v1", 20),
                         ("valid", "instance_quote"))
        d6 = self.command_digest("cmd-6", "K2", "N2", 3, 21)
        self.assertEqual(receipt(self.db, "r21", "N2", "K2", d6, 3, "ok", 21), "captured")
        self.assertEqual(dt.evaluate_receipt(self.db, "r21"), ("trusted", "causal_chain_verified"))
        self.assertEqual(one(self.db, "SELECT status FROM dt_devices WHERE device='K'")["status"], "quarantined")


class ForgeryAndReplay(DeviceTrustBase):
    def test_cloned_certificate_fingerprint_is_detected(self):
        self.enroll()
        self.assertEqual(dt.register_device(self.db, "K-evil", "cert-other", "fp-K", "N9", 5), "clone_detected")
        # re-registering the same identity is idempotent, a swapped certificate is not
        self.assertEqual(dt.register_device(self.db, "K", "cert-K", "fp-K", "N1", 0), "exists")
        self.assertEqual(dt.register_device(self.db, "K", "cert-swapped", "fp-K", "N1", 0), "identity_conflict")

    def test_challenge_nonce_is_single_use_and_bound_to_device(self):
        self.enroll()
        self.assertEqual(self.challenge_and_quote("cA", "q1", "K", "N1", "n-A", 8, "m-v1", 10),
                         ("valid", "instance_quote"))
        # replay the same nonce inside a second quote
        self.assertEqual(quote(self.db, "q2", "N1", "K", "n-A", 9, "m-v1", 11), "captured")
        self.assertEqual(dt.evaluate_quote(self.db, "q2"), ("nonce_replayed", "challenge_already_consumed"))
        # issuing the same nonce again breaks the single-use guarantee
        self.assertEqual(dt.issue_challenge(self.db, "cA2", "n-A", "K", 11), "nonce_not_single_use")
        # a challenge for another chip cannot be answered by K
        self.enroll(device="L", node="N3", fp="fp-L", serial="cert-L")
        self.assertEqual(dt.issue_challenge(self.db, "cL", "n-L", "L", 11, "N3"), "issued")
        self.assertEqual(quote(self.db, "qL", "N1", "K", "n-L", 9, "m-v1", 12), "captured")
        self.assertEqual(dt.evaluate_quote(self.db, "qL")[0], "challenge_device_mismatch")

    def test_boot_counter_rollback_is_per_chip_not_per_node(self):
        self.enroll()
        self.assertEqual(self.challenge_and_quote("c1", "q1", "K", "N1", "n1", 8, "m-v1", 10)[0], "valid")
        self.assertEqual(self.challenge_and_quote("c2", "q2", "K", "N1", "n2", 7, "m-v1", 11)[0],
                         "counter_rollback")
        # a different chip keeps its own independent counter
        self.enroll(device="L", node="N3", fp="fp-L", serial="cert-L")
        self.assertEqual(self.challenge_and_quote("c3", "q3", "L", "N3", "n3", 1, "m-v1", 12)[0], "valid")
        # equal counter is also a rollback (no fresh boot), only strictly greater advances
        self.assertEqual(self.challenge_and_quote("c4", "q4", "K", "N1", "n4", 8, "m-v1", 13)[0],
                         "counter_rollback")


class WhitelistAndRevocation(DeviceTrustBase):
    def test_measurement_must_be_allowed_at_quote_time(self):
        self.enroll()
        # whitelist only opens at minute 12; a minute-10 quote cannot use it retroactively
        self.assertEqual(dt.allow_measurement(self.db, "m-v2", "agent-2", 12, None), "allowed")
        self.assertEqual(dt.issue_challenge(self.db, "c1", "n1", "K", 9, "N1"), "issued")
        self.assertEqual(quote(self.db, "q1", "N1", "K", "n1", 8, "m-v2", 10), "captured")
        self.assertEqual(dt.evaluate_quote(self.db, "q1")[0], "measurement_not_allowed")
        # expired whitelist window does not authorize either
        self.assertEqual(dt.allow_measurement(self.db, "m-old", "agent-0", 0, 5), "allowed")
        self.assertEqual(dt.issue_challenge(self.db, "c2", "n2", "K", 9, "N1"), "issued")
        self.assertEqual(quote(self.db, "q2", "N1", "K", "n2", 8, "m-old", 10), "captured")
        self.assertEqual(dt.evaluate_quote(self.db, "q2")[0], "measurement_not_allowed")

    def test_late_revocation_invalidates_future_but_keeps_prior_trusted_actions(self):
        self.enroll()
        self.assertEqual(self.challenge_and_quote("c1", "q1", "K", "N1", "n1", 8, "m-v1", 10)[0], "valid")
        digest = self.command_digest("cmd-1", "K", "N1", 1, 11)
        self.assertEqual(receipt(self.db, "r1", "N1", "K", digest, 1, "ok", 11), "captured")
        self.assertEqual(dt.evaluate_receipt(self.db, "r1"), ("trusted", "causal_chain_verified"))
        # a challenge issued before revocation, answered by a quote timestamped before
        # revocation but arriving after it, is judged against quote time and stays valid
        self.assertEqual(dt.issue_challenge(self.db, "c3", "n3", "K", 12, "N1"), "issued")
        # revocation arrives late, at minute 14
        self.assertEqual(dt.revoke_device(self.db, "K", 14, "key_compromise"), "revoked")
        # prior trusted action is preserved as a real executed action
        self.assertEqual(dt.evaluate_receipt(self.db, "r1"), ("trusted", "causal_chain_verified"))
        # new evidence after revocation is refused
        self.assertEqual(dt.issue_challenge(self.db, "c2", "n2", "K", 15), "device_revoked")
        self.assertEqual(quote(self.db, "q2", "N1", "K", "forged", 9, "m-v1", 16), "captured")
        self.assertEqual(dt.evaluate_quote(self.db, "q2")[0], "cert_revoked")
        digest2 = self.command_digest("cmd-2", "K", "N1", 1, 17)
        self.assertEqual(receipt(self.db, "r2", "N1", "K", digest2, 1, "ok", 17), "captured")
        self.assertEqual(dt.evaluate_receipt(self.db, "r2")[0], "untrusted")
        self.assertEqual(quote(self.db, "q3", "N1", "K", "n3", 9, "m-v1", 13), "captured")
        self.assertEqual(dt.evaluate_quote(self.db, "q3"), ("valid", "instance_quote"))


class MigrationLifecycle(DeviceTrustBase):
    def test_legitimate_handover_retries_are_idempotent_and_ordered(self):
        self.enroll()
        self.assertEqual(self.challenge_and_quote("c1", "q1", "K", "N1", "n1", 8, "m-v1", 10)[0], "valid")
        self.assertEqual(dt.begin_migration(self.db, "m1", "K", "N1", "N2", 11, "order-1"), "begun")
        self.assertEqual(dt.begin_migration(self.db, "m1", "K", "N1", "N2", 11, "order-1"), "exists")
        # cannot install before the old machine's removal is independently verified
        self.assertEqual(dt.issue_challenge(self.db, "c2", "n2", "K", 11, "N2"), "issued")
        self.assertEqual(quote(self.db, "q2", "N2", "K", "n2", 9, "m-v1", 12), "captured")
        self.assertEqual(dt.evaluate_quote(self.db, "q2"), ("held", "possession_conflict"))
        self.assertEqual(dt.install_evidence(self.db, "m1", "c2", "q2", 12), "removal_not_verified")
        # conflicting evidence cannot overwrite the first statement
        self.assertEqual(dt.removal_evidence(self.db, "m1", "access-1", "photo-1", 11, 15), "removal_verified")
        self.assertEqual(dt.removal_evidence(self.db, "m1", "access-OTHER", "photo-1", 11, 15), "evidence_conflict")
        # removal verification makes the same evidence idempotent and unlocks the takeover
        self.assertEqual(dt.removal_evidence(self.db, "m1", "access-1", "photo-1", 11, 15), "removal_verified")
        self.assertEqual(dt.issue_challenge(self.db, "c3", "n3", "K", 15, "N2"), "issued")
        self.assertEqual(quote(self.db, "q3", "N2", "K", "n3", 10, "m-v1", 15), "captured")
        self.assertEqual(dt.evaluate_quote(self.db, "q3"), ("valid", "takeover_quote"))
        self.assertEqual(dt.install_evidence(self.db, "m1", "c3", "q3", 15), "installed")
        self.assertEqual(dt.install_evidence(self.db, "m1", "c3", "q3", 15), "installed")  # retry
        self.assertEqual(dt.decide_migration(self.db, "m1", 16), "verified")
        self.assertEqual(dt.decide_migration(self.db, "m1", 16), "verified")  # idempotent
        # a second legal migration starts from the new node; impossible power-off is rejected
        self.assertEqual(dt.begin_migration(self.db, "m2", "K", "N2", "N3", 30, "order-2"), "begun")
        self.assertEqual(dt.removal_evidence(self.db, "m2", "a", "p", 5, 31), "evidence_conflict")
        # the disputed quote from minute 12 keeps its held verdict; history is never rewritten
        self.assertEqual(dt.evaluate_quote(self.db, "q2"), ("held", "possession_conflict"))

    def test_one_chip_cannot_authorize_two_agents_in_overlapping_windows(self):
        self.enroll()
        self.assertEqual(self.challenge_and_quote("c1", "q1", "K", "N1", "n1", 8, "m-v1", 10)[0], "valid")
        # N2's valid-looking quote while N1 is still the active instance opens a dispute
        self.assertEqual(dt.issue_challenge(self.db, "c2", "n2", "K", 11, "N2"), "issued")
        self.assertEqual(quote(self.db, "q2", "N2", "K", "n2", 9, "m-v1", 12), "captured")
        self.assertEqual(dt.evaluate_quote(self.db, "q2"), ("held", "possession_conflict"))
        # global-max-counter heuristic is explicitly not used: nothing becomes trusted
        digest = self.command_digest("cmd-x", "K", "N2", 1, 12)
        self.assertEqual(receipt(self.db, "rx", "N2", "K", digest, 1, "ok", 12), "captured")
        self.assertEqual(dt.evaluate_receipt(self.db, "rx"), ("held", "possession_conflict"))
        self.assertTrue(reserve.node(self.db, "N2", "z", 1, 1, device="K").startswith("untrusted_capacity:"))
        self.assertEqual(one(self.db, "SELECT state FROM dt_disputes WHERE device='K'")["state"], "open")


class ReceiptBinding(DeviceTrustBase):
    def test_receipt_cannot_be_moved_between_machines(self):
        self.enroll()
        self.assertEqual(self.challenge_and_quote("c1", "q1", "K", "N1", "n1", 8, "m-v1", 10)[0], "valid")
        digest = self.command_digest("cmd-1", "K", "N1", 1, 11)
        self.assertEqual(receipt(self.db, "r-good", "N1", "K", digest, 1, "ok", 11), "captured")
        self.assertEqual(dt.evaluate_receipt(self.db, "r-good"), ("trusted", "causal_chain_verified"))

        # forged digest: no such dispatched command
        self.assertEqual(receipt(self.db, "r-forge", "N1", "K", "deadbeef", 1, "ok", 11), "captured")
        self.assertEqual(dt.evaluate_receipt(self.db, "r-forge"), ("untrusted", "unknown_command"))
        # N2 re-using N1's successful receipt digest
        self.assertEqual(receipt(self.db, "r-move", "N2", "K", digest, 1, "ok", 11), "captured")
        self.assertEqual(dt.evaluate_receipt(self.db, "r-move"), ("untrusted", "location_mismatch"))
        # another chip claiming the same command result
        self.enroll(device="L", node="N3", fp="fp-L", serial="cert-L")
        self.assertEqual(receipt(self.db, "r-chip", "N1", "L", digest, 1, "ok", 11), "captured")
        self.assertEqual(dt.evaluate_receipt(self.db, "r-chip"), ("untrusted", "command_target_mismatch"))
        # wrong generation binding
        self.assertEqual(receipt(self.db, "r-gen", "N1", "K", digest, 2, "ok", 11), "captured")
        self.assertEqual(dt.evaluate_receipt(self.db, "r-gen"), ("stale_generation", "receipt_generation_does_not_bind_command"))
        # no covering quote at all on a freshly enrolled silent chip
        self.assertEqual(dt.register_device(self.db, "M", "cert-M", "fp-M", "N4", 0, 1), "registered")
        dm = self.command_digest("cmd-m", "M", "N4", 1, 11)
        self.assertEqual(receipt(self.db, "r-silent", "N4", "M", dm, 1, "ok", 11), "captured")
        self.assertEqual(dt.evaluate_receipt(self.db, "r-silent"), ("untrusted", "no_covering_quote"))


class CapacityEntryAndReplay(DeviceTrustBase):
    def test_capacity_entry_requires_trusted_device_and_receipt_gate(self):
        self.enroll()
        # before any quote: fail closed
        self.assertTrue(reserve.node(self.db, "N1", "z", 4, 4, device="K").startswith("untrusted_capacity:"))
        self.assertEqual(self.challenge_and_quote("c1", "q1", "K", "N1", "n1", 8, "m-v1", 10)[0], "valid")
        self.assertEqual(reserve.node(self.db, "N1", "z", 4, 4, device="K"), "accepted")
        # unknown chip is rejected outright; legacy calls without device still work
        self.assertTrue(reserve.node(self.db, "N9", "z", 1, 1, device="ghost").startswith("untrusted_capacity:"))
        self.assertEqual(reserve.node(self.db, "Nlegacy", "z", 2, 2), "accepted")
        # receipt-bound capacity: only a trusted receipt unlocks the write
        digest = self.command_digest("cmd-1", "K", "N1", 1, 11)
        self.assertEqual(receipt(self.db, "r-cap", "N1", "K", digest, 1, "ok", 11), "captured")
        self.assertEqual(reserve.node(self.db, "N1", "z", 4, 4, device="K", receipt_id="r-cap"), "accepted")
        self.assertEqual(receipt(self.db, "r-bad", "N1", "K", "0" * 64, 1, "ok", 12), "captured")
        self.assertTrue(reserve.node(self.db, "N1", "z", 10, 10, device="K",
                                     receipt_id="r-bad").startswith("untrusted_capacity:untrusted"))
        # an untrusted gate blocks the generation advance even when gen is higher
        self.assertEqual(one(self.db, "SELECT generation FROM nodes WHERE id='N1'")["generation"], 1)

    def test_full_chain_replays_to_identical_verdicts(self):
        self.enroll()
        ops = [
            ("q", ("c1", "q1", "K", "N1", "n1", 8, "m-v1", 10), ("valid", "instance_quote")),
        ]
        first = [self.challenge_and_quote(*ops[0][1])]
        digest = self.command_digest("cmd-1", "K", "N1", 1, 11)
        self.assertEqual(receipt(self.db, "r1", "N1", "K", digest, 1, "ok", 11), "captured")
        first.append(dt.evaluate_receipt(self.db, "r1"))
        first.append(dt.evaluate_quote(self.db, "q1"))   # cached replay
        first.append(dt.evaluate_receipt(self.db, "r1"))
        self.assertEqual(first, [("valid", "instance_quote"),
                                 ("trusted", "causal_chain_verified"),
                                 ("valid", "instance_quote"),
                                 ("trusted", "causal_chain_verified")])
        # audit reconstruction still matches every table, including the new ones
        from cloudquota.store import verify_replay
        self.assertTrue(verify_replay(self.db)["consistent"])
        # every authoritative receipt resolves to exactly one proven device/node
        for row in rows(self.db, "SELECT * FROM dt_receipt_verdicts"):
            self.assertIn(row["verdict"], dt.FINAL_VERDICTS | {"held"})
        view = dt.trust_view(self.db)
        self.assertEqual({(v["receipt_id"], v["verdict"]) for v in view["receipt_verdicts"]},
                         {("r1", "trusted")})


if __name__ == "__main__":
    unittest.main()
