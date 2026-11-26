import hashlib
import pathlib
import tempfile
import unittest

from cloudquota import reserve, volume_client, volume_copy, volume_manifest, volume_recovery
from cloudquota.store import one, open_db, rows

A = b'v7-bytes-A-from-faulted-controller'
B = b'v7-bytes-B-confirmed-by-customer'
C = b'v6-bytes-C-last-good'
DIG_A = hashlib.sha256(A).hexdigest()
DIG_B = hashlib.sha256(B).hexdigest()
DIG_C = hashlib.sha256(C).hexdigest()


class VolumeRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = open_db(str(pathlib.Path(self.tmp.name) / 'recovery.sqlite'))
        self.seed_evidence()

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def seed_evidence(self):
        db = self.db
        # Two healthy nodes carrying the v7 forks, both behind one faulty
        # write controller, plus an independent node with the v6 good bytes.
        reserve.node(db, 'node-1', 'zone-a', 4, 4)
        reserve.node(db, 'node-2', 'zone-b', 4, 4)
        reserve.node(db, 'node-3', 'zone-c', 4, 4)
        reserve.node(db, 'node-4', 'zone-d', 4, 4)
        # v7 replicas: same bytes A, correct individual checksums, two nodes,
        # but one shared faulted write path (controller ctl-1 epoch 7).
        self.assertEqual(
            volume_copy.record(db, 'cp1', 'vol', 'blk', 'rep-1', 7, 7, A, 70), 'captured')
        self.assertEqual(
            volume_copy.record(db, 'cp2', 'vol', 'blk', 'rep-2', 7, 7, A, 70), 'captured')
        # v6 good bytes on a previously healthy generation.
        self.assertEqual(
            volume_copy.record(db, 'cp6', 'vol', 'blk', 'rep-6', 6, 6, C, 60), 'captured')
        # Controller directory claims v7 == A (the compromised directory).
        self.assertEqual(volume_manifest.record(
            db, 'mf7', 'vol', 'blk', 7, 7, DIG_A, 'ctl-1', 70), 'captured')
        self.assertEqual(volume_manifest.record(
            db, 'mf6', 'vol', 'blk', 6, 6, DIG_C, 'ctl-0', 60), 'captured')
        # Client holds an unsigned receipt record with the B digest.
        self.assertEqual(volume_client.receipt(
            db, 'r7', 'tenant', 'vol', 'blk', 7, DIG_B, 71), 'captured')
        # Fault registry: ctl-1 failed during epoch 7; ctl-0 and ctl-2 healthy.
        self.assertEqual(volume_recovery.report_controller(
            db, 'ctl-1', 7, 'faulted', 'split-brain write path', 72), 'captured')
        self.assertEqual(volume_recovery.report_controller(
            db, 'ctl-0', 6, 'active', 'healthy', 60), 'captured')
        self.assertEqual(volume_recovery.report_controller(
            db, 'ctl-2', 8, 'active', 'healthy', 80), 'captured')
        # Replica generation chains: both v7 copies descend from ctl-1@7.
        self.assertEqual(volume_recovery.record_lineage(
            db, 'rep-1', 'vol', 'blk', 'ctl-1', 7, 'node-1', 'rep-0'), 'captured')
        self.assertEqual(volume_recovery.record_lineage(
            db, 'rep-2', 'vol', 'blk', 'ctl-1', 7, 'node-2', 'rep-0'), 'captured')
        self.assertEqual(volume_recovery.record_lineage(
            db, 'rep-6', 'vol', 'blk', 'ctl-0', 6, 'node-3', None), 'captured')
        # A trusted issuer whose commitment scope covers versions 1..99.
        self.assertEqual(volume_recovery.register_issuer(
            db, 'issuer-1', 'issuer-secret', 1, 99), 'accepted')
        self.signed_r7 = self._signed_receipt('sr7', 'r7', 7, DIG_B)
        self.assertEqual(volume_recovery.register_signed_receipt(
            db, 'sr7', 'tenant', 'vol', 'blk', 7, DIG_B, 'issuer-1',
            self.signed_r7, 71), 'captured')

    def _signed_receipt(self, receipt_id, customer_id, version, digest):
        return volume_recovery.sign_receipt(
            'issuer-secret', receipt_id, 'tenant', 'vol', 'blk', version, digest)

    # ----------------------------------------------------- 1. same-controller

    def test_same_faulted_controller_replicas_are_one_vote(self):
        report = volume_recovery.diagnose(self.db, 'case-1', 'vol', 'blk', 73)
        self.assertEqual(report['verdict'], 'fork_detected')
        self.assertEqual(report['disputed_version'], 7)
        self.assertEqual(report['expected_digest'], DIG_B)
        self.assertEqual(report['suspect_digest'], DIG_A)
        # Every naive policy that ignores fault domains would pick A.
        self.assertTrue(report['naive_checks']['checksum_ok'])
        self.assertEqual(report['naive_checks']['two_replica_majority'][7], DIG_A)
        self.assertTrue(report['naive_checks']['directory']['confirms_suspect'])
        self.assertEqual(report['naive_checks']['would_propagate'], DIG_A)
        # But the two A replicas collapse into one faulted domain: zero
        # independent trusted votes, so A cannot win any real vote.
        cluster_a = next(c for c in report['replica_clusters'] if c['digest'] == DIG_A)
        self.assertEqual(cluster_a['replica_votes'], 2)
        self.assertEqual(cluster_a['trusted_domain_votes'], 0)
        self.assertEqual(len(cluster_a['faulted_domains']), 1)
        self.assertEqual(cluster_a['faulted_domains'][0]['controller'], 'ctl-1')
        # v6 C survives as the last verified good version with real bytes.
        self.assertEqual(report['last_good']['version'], 6)
        self.assertEqual(report['last_good']['digest'], DIG_C)
        self.assertTrue(report['last_good']['bytes_available'])
        # The receipt digest alone cannot rebuild B.
        self.assertFalse(report['original_bytes_available'])
        self.assertFalse(report['recoverable'])
        self.assertIn('missing_verified_original', report['recovery_blocker'])
        # Suspect evidence is quarantined rather than deleted.
        quarantined = rows(self.db,
            'SELECT replica FROM volume_quarantined_replicas WHERE case_id=?', ('case-1',))
        self.assertCountEqual([q['replica'] for q in quarantined], ['rep-1', 'rep-2'])
        # While under investigation the block refuses reads honestly.
        read = volume_recovery.read_block(self.db, 'read-1', 'vol', 'blk', 74)
        self.assertEqual(read['status'], 'refused')
        self.assertEqual(read['disputed_version'], 7)
        self.assertIsNone(read['data'])

    # --------------------------------------------------------- 2. forged receipt

    def test_forged_and_out_of_scope_receipts_are_rejected(self):
        bad_sig = 'deadbeef' * 8
        self.assertEqual(volume_recovery.register_signed_receipt(
            self.db, 'fake1', 'tenant', 'vol', 'blk', 7, DIG_B, 'issuer-1',
            bad_sig, 75), 'bad_signature')
        self.assertEqual(volume_recovery.register_signed_receipt(
            self.db, 'fake2', 'tenant', 'vol', 'blk', 7, DIG_B, 'no-such-issuer',
            bad_sig, 75), 'unknown_issuer')
        # Revoked issuer: even a correctly recomputed signature is refused.
        self.assertEqual(volume_recovery.register_issuer(
            self.db, 'issuer-evil', 'evil-secret', 1, 99, 'revoked'), 'accepted')
        sig = volume_recovery.sign_receipt(
            'evil-secret', 'fake3', 'tenant', 'vol', 'blk', 7, DIG_B)
        self.assertEqual(volume_recovery.register_signed_receipt(
            self.db, 'fake3', 'tenant', 'vol', 'blk', 7, DIG_B, 'issuer-evil',
            sig, 75), 'untrusted_issuer')
        # Commitment scope is part of verification, not just the signature.
        self.assertEqual(volume_recovery.register_issuer(
            self.db, 'issuer-narrow', 'narrow-secret', 1, 6), 'accepted')
        sig = volume_recovery.sign_receipt(
            'narrow-secret', 'fake4', 'tenant', 'vol', 'blk', 7, DIG_B)
        self.assertEqual(volume_recovery.register_signed_receipt(
            self.db, 'fake4', 'tenant', 'vol', 'blk', 7, DIG_B, 'issuer-narrow',
            sig, 75), 'outside_commit_scope')
        # A valid signature over bytes that contradict the client record.
        sig = volume_recovery.sign_receipt(
            'issuer-secret', 'fake5', 'tenant', 'vol', 'blk', 7, DIG_A)
        self.assertEqual(volume_recovery.register_signed_receipt(
            self.db, 'fake5', 'tenant', 'vol', 'blk', 7, DIG_A, 'issuer-1',
            sig, 75), 'client_record_mismatch')
        self.assertIsNone(one(self.db,
            'SELECT id FROM volume_signed_receipts WHERE id IN (?,?,?,?,?)',
            ('fake1', 'fake2', 'fake3', 'fake4', 'fake5')))

    # ------------------------------------------------------ 3. late B original

    def test_late_original_revives_unrecoverable_case_and_reopens_b(self):
        volume_recovery.diagnose(self.db, 'case-2', 'vol', 'blk', 73)
        # Without B bytes the platform must openly admit v7 is unrecoverable.
        self.assertEqual(volume_recovery.declare_unrecoverable(
            self.db, 'u1', 'case-2', 80), 'declared_unrecoverable')
        read = volume_recovery.read_block(self.db, 'read-2', 'vol', 'blk', 81)
        self.assertEqual(read['status'], 'refused')
        self.assertIn('unrecoverable', read['label'])
        # A digest presented as an "original" cannot conjure bytes into being.
        self.assertEqual(volume_recovery.submit_original(
            self.db, 'o-bad', 'case-2', 'sr7', A, 82), 'original_digest_mismatch')
        # Late arrival of the genuine B original revives the case.
        self.assertEqual(volume_recovery.submit_original(
            self.db, 'o1', 'case-2', 'sr7', B, 83), 'original_accepted')
        result = volume_recovery.rebuild_replicas(
            self.db, 'rb1', 'case-2', ['node-3', 'node-4'], 84)
        self.assertEqual(result, 'reopened')
        # Independent healthy write paths, distinct nodes, B bytes only.
        copies = rows(self.db,
            'SELECT * FROM volume_rebuild_copies WHERE case_id=?', ('case-2',))
        self.assertEqual(len(copies), 2)
        self.assertTrue(all(c['status'] == 'copied' and c['digest'] == DIG_B
                            for c in copies))
        self.assertEqual(len({c['node_id'] for c in copies}), 2)
        self.assertEqual(len({(c['controller'], c['epoch']) for c in copies}), 2)
        # The corrected directory now points at B; the faulty A manifest stays.
        self.assertEqual(one(self.db,
            'SELECT digest FROM volume_manifests WHERE id=?', ('case-2:directory',))['digest'],
            DIG_B)
        self.assertEqual(one(self.db, 'SELECT digest FROM volume_manifests WHERE id=?',
                             ('mf7',))['digest'], DIG_A)
        read = volume_recovery.read_block(self.db, 'read-3', 'vol', 'blk', 85)
        self.assertEqual(read['status'], 'served')
        self.assertEqual(read['data'], B)
        self.assertEqual(read['version'], 7)
        self.assertTrue(read['recovered'])
        # Retried repair must not mint a second truth for version 7.
        self.assertEqual(volume_recovery.rebuild_replicas(
            self.db, 'rb2', 'case-2', ['node-3', 'node-4'], 86), 'reopened')
        stored = rows(self.db,
            "SELECT * FROM volume_copies WHERE volume='vol' AND block_id='blk' "
            'AND version=7 AND digest=?', (DIG_B,))
        self.assertEqual(len(stored), 2)
        self.assertEqual(len({s['id'] for s in stored}), 2)

    # ------------------------------------------------------- 4. writes during

    def test_writes_are_refused_while_block_is_halted_or_serving_stale(self):
        volume_recovery.diagnose(self.db, 'case-3', 'vol', 'blk', 73)
        # Halted route: reads refused and writes refused.
        self.assertEqual(volume_recovery.choose_route(
            self.db, 'route-1', 'case-3', 'await_original', 74), 'halted')
        read = volume_recovery.read_block(self.db, 'r1', 'vol', 'blk', 75)
        self.assertEqual(read['status'], 'refused')
        self.assertEqual(volume_recovery.client_write(
            self.db, 'w1', 'vol', 'blk', 7, b'new-on-a', 76),
            'write_refused:block_halted')
        # Stale route: old bytes are readable but no write may pose as v7's heir.
        self.assertEqual(volume_recovery.choose_route(
            self.db, 'route-2', 'case-3', 'stale_readonly', 77), 'stale_readonly_open')
        read = volume_recovery.read_block(self.db, 'r2', 'vol', 'blk', 78)
        self.assertEqual(read['status'], 'stale')
        self.assertEqual(read['data'], C)
        self.assertFalse(read['is_latest'])
        self.assertEqual(read['disputed_version'], 7)
        self.assertIn('not_latest', read['label'])
        self.assertEqual(volume_recovery.client_write(
            self.db, 'w2', 'vol', 'blk', 6, b'child-of-C-pretending-v8', 79),
            'write_refused:version_7_disputed')
        # Once B is recovered, only writes based on the served v7 are accepted.
        self.assertEqual(volume_recovery.submit_original(
            self.db, 'o1', 'case-3', 'sr7', B, 83), 'original_accepted')
        self.assertEqual(volume_recovery.rebuild_replicas(
            self.db, 'rb1', 'case-3', ['node-3', 'node-4'], 84), 'reopened')
        self.assertEqual(volume_recovery.client_write(
            self.db, 'w3', 'vol', 'blk', 6, b'child-of-stale-C', 85),
            'stale_base_version')
        self.assertEqual(volume_recovery.client_write(
            self.db, 'w4', 'vol', 'blk', 7, b'real-v8-on-top-of-B', 86),
            'accepted:version_8')
        self.assertEqual(volume_recovery.client_write(
            self.db, 'w4', 'vol', 'blk', 7, b'real-v8-on-top-of-B', 86),
            'accepted:version_8')

    # --------------------------------------------------- 5. stale readonly cache

    def test_stale_readonly_route_serves_only_verified_v6(self):
        volume_recovery.diagnose(self.db, 'case-4', 'vol', 'blk', 73)
        # Stale route cannot be chosen when no verified older version exists:
        # retroactively mark the v6 generation as faulted.
        self.db.execute("DELETE FROM volume_controller_faults WHERE controller='ctl-0' AND epoch=6")
        self.db.commit()
        self.assertEqual(volume_recovery.report_controller(
            self.db, 'ctl-0', 6, 'faulted', 'retroactive failure', 72), 'captured')
        report = volume_recovery.diagnose(self.db, 'case-4', 'vol', 'blk', 73)
        self.assertIsNone(report['last_good'])
        self.assertEqual(volume_recovery.choose_route(
            self.db, 'route-x', 'case-4', 'stale_readonly', 74), 'no_verified_last_good')
        # Restore ctl-0 so case-5 can use the v6 fallback below.
        self.db.execute("DELETE FROM volume_controller_faults WHERE controller='ctl-0' AND epoch=6")
        self.db.commit()
        self.assertEqual(volume_recovery.report_controller(
            self.db, 'ctl-0', 6, 'active', 'healthy', 60), 'captured')
        volume_recovery.diagnose(self.db, 'case-5', 'vol', 'blk', 73)
        self.assertEqual(volume_recovery.choose_route(
            self.db, 'route-y', 'case-5', 'stale_readonly', 74), 'stale_readonly_open')
        read = volume_recovery.read_block(self.db, 'r3', 'vol', 'blk', 75)
        self.assertEqual(read['status'], 'stale')
        self.assertEqual(read['version'], 6)
        self.assertEqual(read['digest'], DIG_C)
        # The label can never market old bytes as the latest.
        self.assertNotIn('latest', read['label'].replace('not_latest', ''))
        # A digest-only claim of B still leaves v7 unrecoverable in this route.
        self.assertEqual(volume_recovery.declare_unrecoverable(
            self.db, 'u2', 'case-5', 76), 'declared_unrecoverable')
        after = volume_recovery.read_block(self.db, 'r4', 'vol', 'blk', 77)
        self.assertEqual(after['status'], 'stale')
        self.assertEqual(after['data'], C)

    # ---------------------------------------------------- 6. controller recovery

    def test_controller_failover_and_recovery_do_not_validate_old_bytes(self):
        volume_recovery.diagnose(self.db, 'case-6', 'vol', 'blk', 73)
        # Before any healthy controller exists... fault both healthy entries.
        self.db.execute("DELETE FROM volume_controller_faults WHERE controller='ctl-2' AND epoch=8")
        self.db.commit()
        self.assertEqual(volume_recovery.report_controller(
            self.db, 'ctl-2', 8, 'faulted', 'cascading failure', 73), 'captured')
        self.db.execute("DELETE FROM volume_controller_faults WHERE controller='ctl-0' AND epoch=6")
        self.db.commit()
        self.assertEqual(volume_recovery.report_controller(
            self.db, 'ctl-0', 6, 'faulted', 'cascading failure', 73), 'captured')
        self.assertEqual(volume_recovery.submit_original(
            self.db, 'o1', 'case-6', 'sr7', B, 74), 'original_accepted')
        self.assertEqual(volume_recovery.rebuild_replicas(
            self.db, 'rb0', 'case-6', ['node-3'], 75), 'no_healthy_controller')
        # Failover: a new generation takes over.
        self.assertEqual(volume_recovery.report_controller(
            self.db, 'ctl-3', 9, 'active', 'failover controller', 76), 'captured')
        self.assertEqual(volume_recovery.rebuild_replicas(
            self.db, 'rb1', 'case-6', ['node-3', 'node-4'], 77), 'reopened')
        copies = rows(self.db,
            'SELECT DISTINCT controller,epoch FROM volume_rebuild_copies WHERE case_id=?',
            ('case-6',))
        self.assertIn(('ctl-3', 9), {(c['controller'], c['epoch']) for c in copies})
        # Recovering the old faulted controller does not resurrect A: its
        # quarantined replicas stay out of service, reads still serve B.
        self.db.execute("DELETE FROM volume_controller_faults WHERE controller='ctl-1' AND epoch=7")
        self.db.commit()
        self.assertEqual(volume_recovery.report_controller(
            self.db, 'ctl-1', 7, 'recovered', 'rebooted after split-brain', 78), 'captured')
        read = volume_recovery.read_block(self.db, 'r5', 'vol', 'blk', 79)
        self.assertEqual(read['data'], B)
        quarantined = rows(self.db,
            'SELECT count(*) n FROM volume_quarantined_replicas WHERE case_id=?',
            ('case-6',))[0]['n']
        self.assertEqual(quarantined, 2)
        # Rebuilt replicas trace to the client original, never to A.
        lineage = rows(self.db,
            'SELECT parent_replica FROM volume_replica_lineage WHERE block_id=? '
            "AND parent_replica LIKE 'customer_original:%'", ('blk',))
        self.assertEqual(len(lineage), 2)

    # -------------------------------------------------- 7. partial copy failure

    def test_partial_replica_failure_retries_without_double_truth(self):
        volume_recovery.diagnose(self.db, 'case-7', 'vol', 'blk', 73)
        self.assertEqual(volume_recovery.submit_original(
            self.db, 'o1', 'case-7', 'sr7', B, 74), 'original_accepted')
        # node-4 fails mid-repair: one copy lands, one fails, block stays shut.
        verdict = volume_recovery.rebuild_replicas(
            self.db, 'rb1', 'case-7', ['node-3', 'node-4'], 75, fail_nodes=('node-4',))
        self.assertEqual(verdict, 'partial_rebuild')
        case = one(self.db, 'SELECT * FROM volume_recovery_cases WHERE case_id=?',
                   ('case-7',))
        self.assertEqual(case['status'], 'rebuilding')
        self.assertEqual(volume_recovery.read_block(
            self.db, 'r6', 'vol', 'blk', 76)['status'], 'refused')
        # The failed work order is visible and retry reuses the same slot.
        failed = rows(self.db,
            'SELECT * FROM volume_rebuild_copies WHERE case_id=? AND status=?',
            ('case-7', 'failed'))
        self.assertEqual([f['node_id'] for f in failed], ['node-4'])
        verdict = volume_recovery.rebuild_replicas(
            self.db, 'rb2', 'case-7', ['node-3', 'node-4'], 77)
        self.assertEqual(verdict, 'reopened')
        copies = rows(self.db,
            'SELECT * FROM volume_rebuild_copies WHERE case_id=?', ('case-7',))
        self.assertEqual(len(copies), 2)
        self.assertTrue(all(c['status'] == 'copied' for c in copies))
        # Exactly one rebuilt row per node/version — no duplicated truth.
        b_copies = rows(self.db,
            "SELECT id FROM volume_copies WHERE block_id='blk' AND version=7 AND digest=?",
            (DIG_B,))
        self.assertEqual(len(b_copies), 2)
        read = volume_recovery.read_block(self.db, 'r7', 'vol', 'blk', 78)
        self.assertEqual(read['status'], 'served')
        self.assertEqual(read['data'], B)

    # --------------------------------------------------- 8. reserve integration

    def test_rebuild_rejects_unknown_implicated_and_duplicated_nodes(self):
        volume_recovery.diagnose(self.db, 'case-8', 'vol', 'blk', 73)
        self.assertEqual(volume_recovery.submit_original(
            self.db, 'o1', 'case-8', 'sr7', B, 74), 'original_accepted')
        self.assertEqual(volume_recovery.rebuild_replicas(
            self.db, 'rb-a', 'case-8', ['node-9'], 75), 'unknown_node:node-9')
        # Quarantined nodes (the two A replicas' seats) are never reuse targets.
        self.assertEqual(volume_recovery.rebuild_replicas(
            self.db, 'rb-b', 'case-8', ['node-1', 'node-3'], 75),
            'node_not_eligible:node-1')
        self.assertEqual(volume_recovery.rebuild_replicas(
            self.db, 'rb-c', 'case-8', ['node-3', 'node-3'], 75),
            'duplicate_target_node')
        # Original is still required before any replication can start.
        self.assertEqual(volume_recovery.rebuild_replicas(
            self.db, 'rb-d', 'case-99', ['node-3'], 75), 'unknown_case')

    def test_repair_never_overwrites_last_good_with_suspect_bytes(self):
        volume_recovery.diagnose(self.db, 'case-9', 'vol', 'blk', 73)
        self.assertEqual(volume_recovery.choose_route(
            self.db, 'route-1', 'case-9', 'stale_readonly', 74), 'stale_readonly_open')
        good = one(self.db,
            "SELECT data FROM volume_copies WHERE replica='rep-6'")['data']
        self.assertEqual(good, C)
        # Any repair attempt without B must fail closed, leaving C intact.
        self.assertEqual(volume_recovery.rebuild_replicas(
            self.db, 'rb1', 'case-9', ['node-3', 'node-4'], 75), 'original_not_held')
        untouched = one(self.db,
            "SELECT data,digest FROM volume_copies WHERE replica='rep-6'")
        self.assertEqual(untouched['data'], C)
        self.assertEqual(untouched['digest'], DIG_C)
        read = volume_recovery.read_block(self.db, 'r8', 'vol', 'blk', 76)
        self.assertEqual((read['status'], read['data']), ('stale', C))


if __name__ == '__main__':
    unittest.main()
