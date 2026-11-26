"""Volume fork diagnosis and recoverable repair.

A digest only proves that two blobs hold the same bytes; it never proves that
those bytes are the version a client confirmed.  This module keeps four
identities apart for every write:

* the client request (a signed receipt carrying a digest, never the bytes);
* the controller generation that drove the write path;
* the committed version number claimed by the directory;
* the replica generation chain recorded per replica.

Replicas sharing one faulted write controller count as a single fault domain,
and a faulted domain casts no independent vote.  Missing original bytes can
never be synthesized from a receipt digest: version 7 is either re-derived
from verified original bytes or openly declared unrecoverable.
"""
import hashlib
import hmac

from .store import event, one, rows, transaction


REQUIRED_COPIES = 2


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _ensure_tables(db):
    db.execute('CREATE TABLE IF NOT EXISTS volume_receipt_issuers('
               'issuer_id TEXT PRIMARY KEY,secret TEXT,min_version INTEGER,'
               'max_version INTEGER,status TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS volume_signed_receipts('
               'id TEXT PRIMARY KEY,customer TEXT,volume TEXT,block_id TEXT,'
               'version INTEGER,digest TEXT,issuer_id TEXT,signature TEXT,at INTEGER)')
    db.execute('CREATE TABLE IF NOT EXISTS volume_controller_faults('
               'controller TEXT,epoch INTEGER,status TEXT,reason TEXT,at INTEGER,'
               'PRIMARY KEY(controller,epoch))')
    db.execute('CREATE TABLE IF NOT EXISTS volume_replica_lineage('
               'replica TEXT PRIMARY KEY,volume TEXT,block_id TEXT,controller TEXT,'
               'epoch INTEGER,node_id TEXT,parent_replica TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS volume_recovery_cases('
               'case_id TEXT PRIMARY KEY,volume TEXT,block_id TEXT,status TEXT,'
               'route TEXT,disputed_version INTEGER,expected_digest TEXT,'
               'suspect_digest TEXT,last_good_version INTEGER,last_good_digest TEXT,'
               'required_copies INTEGER,at INTEGER,updated_at INTEGER)')
    db.execute('CREATE TABLE IF NOT EXISTS volume_quarantined_replicas('
               'case_id TEXT,replica TEXT,node_id TEXT,controller TEXT,epoch INTEGER,'
               'version INTEGER,digest TEXT,reason TEXT,at INTEGER,'
               'PRIMARY KEY(case_id,replica))')
    db.execute('CREATE TABLE IF NOT EXISTS volume_customer_originals('
               'case_id TEXT PRIMARY KEY,volume TEXT,block_id TEXT,version INTEGER,'
               'digest TEXT,data BLOB,at INTEGER)')
    db.execute('CREATE TABLE IF NOT EXISTS volume_rebuild_copies('
               'case_id TEXT,replica TEXT,node_id TEXT,controller TEXT,epoch INTEGER,'
               'version INTEGER,digest TEXT,status TEXT,at INTEGER,'
               'PRIMARY KEY(case_id,replica))')
    db.execute('CREATE TABLE IF NOT EXISTS volume_block_service('
               'volume TEXT,block_id TEXT,mode TEXT,case_id TEXT,'
               'served_version INTEGER,served_digest TEXT,label TEXT,'
               'updated_at INTEGER,PRIMARY KEY(volume,block_id))')
    db.execute('CREATE TABLE IF NOT EXISTS volume_client_writes('
               'id TEXT PRIMARY KEY,volume TEXT,block_id TEXT,base_version INTEGER,'
               'version INTEGER,digest TEXT,data BLOB,at INTEGER)')
    db.commit()


# ---------------------------------------------------------------- signatures

def _canonical(receipt_id, customer, volume, block, version, digest):
    return '|'.join((receipt_id, customer, volume, block, str(version), digest))


def sign_receipt(secret, receipt_id, customer, volume, block, version, digest):
    """Signing helper mirroring what a trusted issuer would produce."""
    msg = _canonical(receipt_id, customer, volume, block, version, digest)
    return hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()


def register_issuer(db, issuer_id, secret, min_version, max_version, status='trusted'):
    _ensure_tables(db)
    if not issuer_id or not secret or min_version < 0 or max_version < min_version \
            or status not in ('trusted', 'revoked'):
        return 'invalid_issuer'
    with transaction(db):
        old = one(db, 'SELECT * FROM volume_receipt_issuers WHERE issuer_id=?', (issuer_id,))
        expected = (secret, min_version, max_version, status)
        if old:
            return 'replayed' if tuple(old[k] for k in
                    ('secret', 'min_version', 'max_version', 'status')) == expected \
                else 'issuer_conflict'
        db.execute('INSERT INTO volume_receipt_issuers VALUES(?,?,?,?,?)',
                   (issuer_id, *expected))
        return 'accepted'


def _verify_receipt(db, receipt_id, customer, volume, block, version, digest,
                    issuer_id, signature):
    issuer = one(db, 'SELECT * FROM volume_receipt_issuers WHERE issuer_id=?', (issuer_id,))
    if not issuer:
        return 'unknown_issuer'
    if issuer['status'] != 'trusted':
        return 'untrusted_issuer'
    if not issuer['min_version'] <= version <= issuer['max_version']:
        return 'outside_commit_scope'
    want = sign_receipt(issuer['secret'], receipt_id, customer, volume, block, version, digest)
    if not hmac.compare_digest(want, signature or ''):
        return 'bad_signature'
    # The unsigned client record must tell the same story when one exists.
    claim = one(db, """SELECT * FROM volume_client_receipts WHERE volume=?
        AND block_id=? AND version=?""", (volume, block, version))
    if claim and claim['digest'] != digest:
        return 'client_record_mismatch'
    return 'verified'


def register_signed_receipt(db, receipt_id, customer, volume, block, version,
                            digest, issuer_id, signature, at):
    _ensure_tables(db)
    if min(version, at) < 0 or not digest:
        return 'invalid_receipt'
    with transaction(db):
        old = one(db, 'SELECT * FROM volume_signed_receipts WHERE id=?', (receipt_id,))
        expected = (customer, volume, block, version, digest, issuer_id, signature, at)
        if old:
            return 'replayed' if tuple(old[k] for k in
                    ('customer', 'volume', 'block_id', 'version', 'digest',
                     'issuer_id', 'signature', 'at')) == expected else 'receipt_conflict'
        verdict = _verify_receipt(db, receipt_id, customer, volume, block, version,
                                  digest, issuer_id, signature)
        if verdict != 'verified':
            return verdict
        db.execute('INSERT INTO volume_signed_receipts VALUES(?,?,?,?,?,?,?,?,?)',
                   (receipt_id, *expected))
        return 'captured'


# ------------------------------------------------- controller fault registry

def report_controller(db, controller, epoch, status, reason, at):
    _ensure_tables(db)
    if not controller or epoch < 0 or at < 0 or \
            status not in ('active', 'faulted', 'recovered'):
        return 'invalid_fault_report'
    with transaction(db):
        old = one(db, 'SELECT * FROM volume_controller_faults WHERE controller=? AND epoch=?',
                  (controller, epoch))
        expected = (status, reason, at)
        if old:
            return 'replayed' if tuple(old[k] for k in
                    ('status', 'reason', 'at')) == expected else 'fault_conflict'
        db.execute('INSERT INTO volume_controller_faults VALUES(?,?,?,?,?)',
                   (controller, epoch, *expected))
        return 'captured'


def record_lineage(db, replica, volume, block, controller, epoch, node_id, parent_replica):
    _ensure_tables(db)
    if not replica or not controller or epoch < 0:
        return 'invalid_lineage'
    with transaction(db):
        old = one(db, 'SELECT * FROM volume_replica_lineage WHERE replica=?', (replica,))
        expected = (volume, block, controller, epoch, node_id, parent_replica)
        if old:
            return 'replayed' if tuple(old[k] for k in
                    ('volume', 'block_id', 'controller', 'epoch', 'node_id',
                     'parent_replica')) == expected else 'lineage_conflict'
        db.execute('INSERT INTO volume_replica_lineage VALUES(?,?,?,?,?,?,?)',
                   (replica, *expected))
        return 'captured'


# ---------------------------------------------------------------- diagnosis

def _fault_map(db):
    return {(f['controller'], f['epoch']): f for f in
            rows(db, 'SELECT * FROM volume_controller_faults')}


def _domain_of(copy, lineage, manifest_by_epoch, faults):
    lin = lineage.get(copy['replica'])
    if lin:
        domain = (lin['controller'], lin['epoch'])
        node = lin['node_id']
    else:
        man = manifest_by_epoch.get((copy['volume'], copy['block_id'], copy['epoch']))
        if man:
            domain, node = (man['controller'], copy['epoch']), None
        else:
            domain, node = ('unknown', copy['epoch']), None
    fault = faults.get(domain)
    trusted = domain[0] != 'unknown' and (not fault or fault['status'] != 'faulted')
    return domain, node, trusted, fault


def diagnose(db, case_id, volume, block, at, required_copies=REQUIRED_COPIES):
    """Cross replicas, directory and signed receipts; persist the fork case."""
    _ensure_tables(db)
    existing = one(db, 'SELECT * FROM volume_recovery_cases WHERE case_id=?', (case_id,))
    if existing and existing['status'] in ('reopened', 'unrecoverable_declared'):
        return _case_report(db, existing, verdict='already_resolved'
                            if existing['status'] == 'reopened' else 'unrecoverable_declared')

    copies = rows(db, 'SELECT * FROM volume_copies WHERE volume=? AND block_id=?',
                  (volume, block))
    manifests = rows(db, 'SELECT * FROM volume_manifests WHERE volume=? AND block_id=?',
                     (volume, block))
    signed = rows(db, """SELECT * FROM volume_signed_receipts WHERE volume=?
        AND block_id=?""", (volume, block))
    unsigned = rows(db, """SELECT * FROM volume_client_receipts WHERE volume=?
        AND block_id=?""", (volume, block))
    lineage = {x['replica']: x for x in rows(db,
               'SELECT * FROM volume_replica_lineage WHERE volume=? AND block_id=?',
               (volume, block))}
    faults = _fault_map(db)
    manifest_by_epoch = {(m['volume'], m['block_id'], m['epoch']): m for m in manifests}

    verified_receipts = [dict(version=s['version'], digest=s['digest'],
                              issuer_id=s['issuer_id']) for s in signed]
    receipt_digest = {s['version']: s['digest'] for s in signed}
    unsigned_digest = {u['version']: u['digest'] for u in unsigned}

    clusters = {}
    for c in copies:
        checksum_ok = _digest(c['data']) == c['digest']
        domain, node, trusted, fault = _domain_of(c, lineage, manifest_by_epoch, faults)
        key = (c['version'], c['digest'])
        cl = clusters.setdefault(key, dict(version=c['version'], digest=c['digest'],
                                           replicas=[], nodes=set(), domains=set(),
                                           trusted_domains=set(), faulted_domains=set(),
                                           checksum_ok=True))
        cl['replicas'].append(c['replica'])
        cl['nodes'].add(node or c['replica'])
        cl['domains'].add(domain)
        (cl['trusted_domains'] if trusted else cl['faulted_domains']).add(domain)
        cl['checksum_ok'] = cl['checksum_ok'] and checksum_ok

    # Naive policies deliberately ignore the fault domain: this is what the
    # standard checksum / two-replica majority / directory checks would pick.
    replica_counts = {}
    for (version, digest), cl in clusters.items():
        replica_counts.setdefault(version, []).append((len(cl['replicas']), digest))
    naive_majority = {}
    for version, tally in replica_counts.items():
        tally.sort(key=lambda t: (-t[0], t[1]))
        naive_majority[version] = tally[0][1]
    directory = {m['version']: m for m in manifests}

    disputed_version, expected_digest, suspect_digest = None, None, None
    for version in sorted(set(naive_majority) | set(receipt_digest) | set(unsigned_digest)):
        claimed = receipt_digest.get(version) or unsigned_digest.get(version)
        observed = naive_majority.get(version)
        if claimed and observed and claimed != observed:
            disputed_version, expected_digest, suspect_digest = version, claimed, observed

    # Last good version: matching bytes on a healthy write path, agreeing with
            # any receipt that exists for it.
    last_good = None
    if disputed_version is not None:
        for version in range(disputed_version - 1, -1, -1):
            candidates = [cl for k, cl in clusters.items() if k[0] == version]
            if len(candidates) != 1:
                continue
            cl = candidates[0]
            if cl['faulted_domains'] or not cl['trusted_domains']:
                continue
            claimed = receipt_digest.get(version) or unsigned_digest.get(version)
            if claimed and claimed != cl['digest']:
                continue
            last_good = dict(version=version, digest=cl['digest'],
                             bytes_available=True, replicas=sorted(cl['replicas']))
            break

    # Suspect bytes live on faulted domains; quarantine them as evidence.
    quarantined = []
    if disputed_version is not None:
        for c in copies:
            if c['version'] != disputed_version or c['digest'] != suspect_digest:
                continue
            domain, node, trusted, fault = _domain_of(c, lineage, manifest_by_epoch, faults)
            if trusted:
                continue
            reason = 'faulted_write_path:%s@epoch%s' % domain
            with transaction(db):
                db.execute('INSERT OR IGNORE INTO volume_quarantined_replicas'
                           ' VALUES(?,?,?,?,?,?,?,?,?)',
                           (case_id, c['replica'], node, domain[0], domain[1],
                            c['version'], c['digest'], reason, at))
            quarantined.append(dict(replica=c['replica'], node=node, controller=domain[0],
                                    epoch=domain[1], digest=c['digest'], reason=reason))

    original = one(db, 'SELECT * FROM volume_customer_originals WHERE case_id=?', (case_id,))
    original_available = bool(original and (not expected_digest or
                                            original['digest'] == expected_digest))
    bytes_present = any(c['digest'] == expected_digest for c in copies) or original_available

    naive_directory = None
    if disputed_version is not None and disputed_version in directory:
        m = directory[disputed_version]
        naive_directory = dict(version=m['version'], digest=m['digest'],
                               controller=m['controller'], epoch=m['epoch'],
                               confirms_suspect=m['digest'] == suspect_digest)

    report = dict(
        case_id=case_id, volume=volume, block=block,
        verdict='fork_detected' if disputed_version is not None else 'no_dispute',
        disputed_version=disputed_version,
        expected_digest=expected_digest,
        suspect_digest=suspect_digest,
        replica_clusters=[dict(
            version=cl['version'], digest=cl['digest'],
            replicas=sorted(cl['replicas']), nodes=sorted(n for n in cl['nodes'] if n),
            replica_votes=len(cl['replicas']),
            independent_domains=_domain_keys(cl['domains']),
            trusted_domain_votes=len(cl['trusted_domains']),
            faulted_domains=_domain_keys(cl['faulted_domains']),
            checksum_ok=cl['checksum_ok'])
            for cl in sorted(clusters.values(), key=lambda x: (x['version'], x['digest']))],
        naive_checks=dict(
            checksum_ok=all(cl['checksum_ok'] for cl in clusters.values()),
            two_replica_majority=naive_majority,
            directory=naive_directory,
            would_propagate=suspect_digest),
        verified_receipts=verified_receipts,
        unsigned_client_claims=[dict(version=v, digest=d) for v, d in
                                sorted(unsigned_digest.items())],
        last_good=last_good,
        quarantined=quarantined,
        original_bytes_available=bytes_present,
        recoverable=bytes_present,
        recovery_blocker=None if bytes_present else
        'missing_verified_original:receipt_digest_cannot_synthesize_bytes',
    )

    with transaction(db):
        if existing:
            db.execute("""UPDATE volume_recovery_cases SET status=?,route=?,
                disputed_version=?,expected_digest=?,suspect_digest=?,
                last_good_version=?,last_good_digest=?,updated_at=? WHERE case_id=?""",
                (existing['status'], existing['route'], disputed_version,
                 expected_digest, suspect_digest,
                 last_good and last_good['version'],
                 last_good and last_good['digest'], at, case_id))
        else:
            db.execute('INSERT INTO volume_recovery_cases VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                       (case_id, volume, block, 'open', None, disputed_version,
                        expected_digest, suspect_digest,
                        last_good and last_good['version'],
                        last_good and last_good['digest'], required_copies, at, at))
            db.execute('INSERT INTO volume_block_service VALUES(?,?,?,?,?,?,?,?) '
                       'ON CONFLICT(volume,block_id) DO UPDATE SET mode=excluded.mode,'
                       'case_id=excluded.case_id,label=excluded.label,updated_at=excluded.updated_at',
                       (volume, block, 'refused', case_id, None, None,
                        'refused:fork_under_investigation:v%s' % disputed_version, at))
    return report


def _domain_key(domain):
    return {'controller': domain[0], 'epoch': domain[1]}


def _domain_keys(domains):
    return [_domain_key(d) for d in sorted(domains)]


def _case_report(db, case, verdict):
    copies = rows(db, 'SELECT * FROM volume_rebuild_copies WHERE case_id=?', (case['case_id'],))
    service = one(db, 'SELECT * FROM volume_block_service WHERE volume=? AND block_id=?',
                  (case['volume'], case['block_id']))
    return dict(case_id=case['case_id'], volume=case['volume'], block=case['block_id'],
                verdict=verdict, status=case['status'], route=case['route'],
                disputed_version=case['disputed_version'],
                expected_digest=case['expected_digest'],
                suspect_digest=case['suspect_digest'],
                last_good_version=case['last_good_version'],
                last_good_digest=case['last_good_digest'],
                rebuild_copies=copies, service=service)


# ------------------------------------------------------------- route choice

def choose_route(db, event_id, case_id, route, at):
    _ensure_tables(db)
    if route not in ('await_original', 'stale_readonly'):
        return 'invalid_route'
    with transaction(db):
        case = one(db, 'SELECT * FROM volume_recovery_cases WHERE case_id=?', (case_id,))
        if not case:
            return event(db, event_id, 'recovery.route', dict(case_id=case_id, route=route),
                         'unknown_case')
        if case['status'] in ('reopened', 'unrecoverable_declared'):
            return event(db, event_id, 'recovery.route', dict(case_id=case_id, route=route),
                         'case_closed')
        if case['status'] == 'original_held':
            return event(db, event_id, 'recovery.route', dict(case_id=case_id, route=route),
                         'route_locked_original_held')
        payload = dict(case_id=case_id, route=route, at=at)
        if route == 'await_original':
            status, mode, label = 'await_original', 'refused', \
                'refused:awaiting_client_original:v%s' % case['disputed_version']
            served_v, served_d = None, None
        else:
            if case['last_good_version'] is None:
                return event(db, event_id, 'recovery.route', payload, 'no_verified_last_good')
            status, mode = 'serving_stale', 'stale_readonly'
            served_v, served_d = case['last_good_version'], case['last_good_digest']
            label = 'stale:version_%s_not_latest:v%s_disputed' % (
                served_v, case['disputed_version'])
        db.execute("""UPDATE volume_recovery_cases SET status=?,route=?,updated_at=?
            WHERE case_id=?""", (status, route, at, case_id))
        db.execute('INSERT INTO volume_block_service VALUES(?,?,?,?,?,?,?,?) '
                   'ON CONFLICT(volume,block_id) DO UPDATE SET mode=excluded.mode,'
                   'case_id=excluded.case_id,served_version=excluded.served_version,'
                   'served_digest=excluded.served_digest,label=excluded.label,'
                   'updated_at=excluded.updated_at',
                   (case['volume'], case['block_id'], mode, case_id, served_v, served_d,
                    label, at))
        return event(db, event_id, 'recovery.route', payload,
                     'halted' if route == 'await_original' else 'stale_readonly_open')


# ------------------------------------------------ client original retrieval

def submit_original(db, event_id, case_id, receipt_id, data, at):
    _ensure_tables(db)
    payload = dict(case_id=case_id, receipt_id=receipt_id, digest=_digest(data), at=at)
    with transaction(db):
        case = one(db, 'SELECT * FROM volume_recovery_cases WHERE case_id=?', (case_id,))
        if not case:
            return event(db, event_id, 'recovery.original', payload, 'unknown_case')
        signed = one(db, 'SELECT * FROM volume_signed_receipts WHERE id=?', (receipt_id,))
        if not signed:
            return event(db, event_id, 'recovery.original', payload, 'receipt_not_verified')
        check = _verify_receipt(db, signed['id'], signed['customer'], signed['volume'],
                                signed['block_id'], signed['version'], signed['digest'],
                                signed['issuer_id'], signed['signature'])
        if check != 'verified':
            return event(db, event_id, 'recovery.original', payload, check)
        if signed['version'] != case['disputed_version']:
            return event(db, event_id, 'recovery.original', payload, 'version_outside_dispute')
        if signed['digest'] != payload['digest']:
            return event(db, event_id, 'recovery.original', payload,
                         'original_digest_mismatch')
        old = one(db, 'SELECT * FROM volume_customer_originals WHERE case_id=?', (case_id,))
        if old:
            if old['digest'] != payload['digest']:
                return event(db, event_id, 'recovery.original', payload,
                             'conflicting_original')
            return event(db, event_id, 'recovery.original', payload, 'replayed')
        db.execute('INSERT INTO volume_customer_originals VALUES(?,?,?,?,?,?,?)',
                   (case_id, case['volume'], case['block_id'], signed['version'],
                    signed['digest'], data, at))
        db.execute("UPDATE volume_recovery_cases SET status='original_held',updated_at=? "
                   'WHERE case_id=?', (at, case_id))
        return event(db, event_id, 'recovery.original', payload, 'original_accepted')


def declare_unrecoverable(db, event_id, case_id, at):
    _ensure_tables(db)
    with transaction(db):
        case = one(db, 'SELECT * FROM volume_recovery_cases WHERE case_id=?', (case_id,))
        if not case:
            return event(db, event_id, 'recovery.unrecoverable',
                         dict(case_id=case_id), 'unknown_case')
        if case['status'] == 'reopened':
            return event(db, event_id, 'recovery.unrecoverable',
                         dict(case_id=case_id), 'already_repaired')
        original = one(db, 'SELECT * FROM volume_customer_originals WHERE case_id=?',
                       (case_id,))
        if original:
            return event(db, event_id, 'recovery.unrecoverable',
                         dict(case_id=case_id), 'original_held_repairable')
        service = one(db, 'SELECT * FROM volume_block_service WHERE volume=? AND block_id=?',
                      (case['volume'], case['block_id']))
        # A chosen route stays in force: halt remains a refusal, a stale
        # readonly fallback keeps serving the verified old bytes; only the
        # label becomes a permanent declaration.
        if service and service['mode'] == 'stale_readonly':
            mode, served_v, served_d = 'stale_readonly', \
                case['last_good_version'], case['last_good_digest']
            label = 'stale:version_%s_readonly:v%s_declared_unrecoverable' % (
                served_v, case['disputed_version'])
        else:
            mode, served_v, served_d = 'refused', None, None
            label = 'refused:v%s_declared_unrecoverable' % case['disputed_version']
        db.execute("UPDATE volume_recovery_cases SET status='unrecoverable_declared',"
                   'updated_at=? WHERE case_id=?', (at, case_id))
        db.execute('INSERT INTO volume_block_service VALUES(?,?,?,?,?,?,?,?) '
                   'ON CONFLICT(volume,block_id) DO UPDATE SET mode=excluded.mode,'
                   'label=excluded.label,updated_at=excluded.updated_at',
                   (case['volume'], case['block_id'], mode, case_id,
                    case['last_good_version'], case['last_good_digest'], label, at))
        return event(db, event_id, 'recovery.unrecoverable',
                     dict(case_id=case_id, at=at), 'declared_unrecoverable')


# ------------------------------------------------------------- replication

def _healthy_controllers(faults):
    best = {}
    for (controller, epoch), f in faults.items():
        if f['status'] == 'faulted':
            continue
        if controller not in best or epoch > best[controller][0]:
            best[controller] = (epoch, f['status'])
    return sorted((c, e[0]) for c, e in best.items())


def rebuild_replicas(db, event_id, case_id, node_ids, at, fail_nodes=()):
    """Rebuild independent replicas from the verified client original.

    Suspect copies are never read: every rebuilt byte comes from the held
    original.  Retries reuse deterministic replica ids, so one version can
    never accumulate two competing truths.
    """
    _ensure_tables(db)
    node_ids = list(node_ids)
    payload = dict(case_id=case_id, nodes=node_ids, fail_nodes=sorted(fail_nodes), at=at)
    with transaction(db):
        case = one(db, 'SELECT * FROM volume_recovery_cases WHERE case_id=?', (case_id,))
        if not case:
            return event(db, event_id, 'recovery.rebuild', payload, 'unknown_case')
        original = one(db, 'SELECT * FROM volume_customer_originals WHERE case_id=?',
                       (case_id,))
        if not original:
            return event(db, event_id, 'recovery.rebuild', payload, 'original_not_held')
        if len(node_ids) != len(set(node_ids)):
            return event(db, event_id, 'recovery.rebuild', payload, 'duplicate_target_node')
        implicated = {q['node_id'] for q in rows(db,
            'SELECT node_id FROM volume_quarantined_replicas WHERE case_id=?', (case_id,))}
        healthy = _healthy_controllers(_fault_map(db))
        if not healthy:
            return event(db, event_id, 'recovery.rebuild', payload, 'no_healthy_controller')
        for node in node_ids:
            if not one(db, 'SELECT id FROM nodes WHERE id=?', (node,)):
                return event(db, event_id, 'recovery.rebuild', payload,
                             'unknown_node:' + node)
            if node in implicated:
                return event(db, event_id, 'recovery.rebuild', payload,
                             'node_not_eligible:' + node)

        version, data, digest = original['version'], original['data'], original['digest']
        copied, failed = [], []
        for i, node in enumerate(node_ids):
            controller, epoch = healthy[i % len(healthy)]
            replica = '%s:rebuild:%s' % (case_id, node)
            if node in fail_nodes:
                failed.append(node)
                db.execute('INSERT OR IGNORE INTO volume_rebuild_copies'
                           ' VALUES(?,?,?,?,?,?,?,?,?)',
                           (case_id, replica, node, controller, epoch, version,
                            digest, 'failed', at))
                continue
            # Persist the real bytes through the isolated copy ledger.
            existing_copy = one(db, 'SELECT * FROM volume_copies WHERE id=?',
                                ('%s:copy:%s' % (case_id, node),))
            if not existing_copy:
                db.execute('INSERT INTO volume_copies VALUES(?,?,?,?,?,?,?,?,?)',
                           ('%s:copy:%s' % (case_id, node), case['volume'],
                            case['block_id'], replica, epoch, version, digest, data, at))
            db.execute('INSERT OR REPLACE INTO volume_replica_lineage VALUES(?,?,?,?,?,?,?)',
                       (replica, case['volume'], case['block_id'], controller, epoch,
                        node, 'customer_original:%s' % case_id))
            db.execute('INSERT OR REPLACE INTO volume_rebuild_copies VALUES(?,?,?,?,?,?,?,?,?)',
                       (case_id, replica, node, controller, epoch, version,
                        digest, 'copied', at))
            copied.append(dict(replica=replica, node=node, controller=controller, epoch=epoch))

        domains = {(c['controller'], c['epoch']) for c in copied}
        threshold = min(case['required_copies'], len(node_ids)) or 1
        verdict = 'reopened' if len(copied) >= threshold else 'partial_rebuild'
        if verdict == 'partial_rebuild':
            db.execute("UPDATE volume_recovery_cases SET status='rebuilding',updated_at=? "
                       'WHERE case_id=?', (at, case_id))
            return event(db, event_id, 'recovery.rebuild',
                         dict(payload, copied=copied, failed=failed), verdict)

        # Correct the directory through a healthy generation; the old faulty
        # manifest stays on record as evidence.
        controller, epoch = healthy[0]
        db.execute('INSERT OR IGNORE INTO volume_manifests VALUES(?,?,?,?,?,?,?,?)',
                   ('%s:directory' % case_id, case['volume'], case['block_id'], epoch,
                    version, digest, controller, at))
        db.execute("UPDATE volume_recovery_cases SET status='reopened',updated_at=? "
                   'WHERE case_id=?', (at, case_id))
        db.execute('INSERT INTO volume_block_service VALUES(?,?,?,?,?,?,?,?) '
                   'ON CONFLICT(volume,block_id) DO UPDATE SET mode=excluded.mode,'
                   'case_id=excluded.case_id,served_version=excluded.served_version,'
                   'served_digest=excluded.served_digest,label=excluded.label,'
                   'updated_at=excluded.updated_at',
                   (case['volume'], case['block_id'], 'open', case_id, version, digest,
                    'open:recovered_version_%s' % version, at))
        return event(db, event_id, 'recovery.rebuild',
                     dict(payload, copied=copied, failed=failed,
                          independent_domains=_domain_keys(domains)),
                     'reopened')


# -------------------------------------------------------------------- reads

def read_block(db, event_id, volume, block, at):
    """Return honestly labelled bytes: open data, stale data, or a refusal."""
    _ensure_tables(db)
    service = one(db, 'SELECT * FROM volume_block_service WHERE volume=? AND block_id=?',
                  (volume, block))
    if not service:
        versions = [c['version'] for c in rows(db,
                    'SELECT * FROM volume_copies WHERE volume=? AND block_id=?',
                    (volume, block))]
        if not versions:
            result = dict(status='refused', label='refused:no_data', data=None)
        else:
            latest = max(versions)
            digests = {c['digest'] for c in rows(db,
                'SELECT * FROM volume_copies WHERE volume=? AND block_id=? AND version=?',
                (volume, block, latest))}
            if len(digests) > 1:
                result = dict(status='refused', version=latest,
                              label='refused:unmanaged_disagreement', data=None)
            else:
                row = one(db, """SELECT * FROM volume_copies WHERE volume=?
                    AND block_id=? AND version=? LIMIT 1""", (volume, block, latest))
                result = dict(status='served', version=latest, digest=row['digest'],
                              data=row['data'], label='open:latest')
        event(db, event_id, 'recovery.read',
              dict(volume=volume, block=block, label=result['label'], at=at),
              result['status'])
        return result

    case = one(db, 'SELECT * FROM volume_recovery_cases WHERE case_id=?',
               (service['case_id'],))
    if service['mode'] == 'open':
        row = one(db, """SELECT * FROM volume_copies WHERE volume=? AND block_id=?
            AND version=? AND digest=? LIMIT 1""",
                  (volume, block, service['served_version'], service['served_digest']))
        original_row = one(db, 'SELECT data FROM volume_customer_originals WHERE case_id=?',
                           (service['case_id'],))
        result = dict(status='served', version=service['served_version'],
                      digest=service['served_digest'],
                      data=row['data'] if row else original_row['data'],
                      label=service['label'], recovered=True)
    elif service['mode'] == 'stale_readonly':
        row = one(db, """SELECT * FROM volume_copies WHERE volume=? AND block_id=?
            AND version=? AND digest=? LIMIT 1""",
                  (volume, block, case['last_good_version'], case['last_good_digest']))
        result = dict(status='stale', version=case['last_good_version'],
                      digest=case['last_good_digest'], data=row['data'],
                      label=service['label'], is_latest=False,
                      disputed_version=case['disputed_version'],
                      note='version_%s_writes_remain_quarantined' % case['disputed_version'])
    else:
        result = dict(status='refused', mode=service['mode'], label=service['label'],
                      disputed_version=case['disputed_version'],
                      expected_digest=case['expected_digest'],
                      suspect_digest=case['suspect_digest'], data=None)
    with transaction(db):
        event(db, event_id, 'recovery.read',
              dict(volume=volume, block=block, label=result['label'], at=at),
              result['status'])
    return result


# ------------------------------------------------------------------- writes

def client_write(db, event_id, volume, block, base_version, data, at):
    """Accept new writes only on top of the currently served truth."""
    _ensure_tables(db)
    digest = _digest(data)
    payload = dict(volume=volume, block=block, base_version=base_version,
                   digest=digest, at=at)
    with transaction(db):
        old = one(db, 'SELECT * FROM events WHERE id=?', (event_id,))
        service = one(db, 'SELECT * FROM volume_block_service WHERE volume=? AND block_id=?',
                      (volume, block))
        if service:
            case = one(db, 'SELECT * FROM volume_recovery_cases WHERE case_id=?',
                       (service['case_id'],))
            if service['mode'] == 'refused':
                return event(db, event_id, 'recovery.write', payload,
                             'write_refused:block_halted')
            if service['mode'] == 'stale_readonly':
                return event(db, event_id, 'recovery.write', payload,
                             'write_refused:version_%s_disputed' % case['disputed_version'])
            if base_version != service['served_version']:
                return event(db, event_id, 'recovery.write', payload, 'stale_base_version')
            new_version = service['served_version'] + 1
        else:
            latest = one(db, 'SELECT MAX(version) v FROM volume_copies WHERE volume=? '
                         'AND block_id=?', (volume, block))['v']
            latest = -1 if latest is None else latest
            if base_version != latest:
                return event(db, event_id, 'recovery.write', payload, 'stale_base_version')
            new_version = latest + 1
        if old:
            return old['verdict']
        db.execute('INSERT INTO volume_client_writes VALUES(?,?,?,?,?,?,?,?)',
                   (event_id, volume, block, base_version, new_version, digest, data, at))
        return event(db, event_id, 'recovery.write', payload,
                     'accepted:version_%s' % new_version)
