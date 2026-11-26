"""Evidence-backed proof for retiring, destroying and reusing physical drives.

The records owned by the neighbouring modules each prove only their own scope:

* ``drive_asset.detach/attach`` binds a physical serial to a drive id and says
  which replica the controller placed on it;
* ``drive_sanitize.receipt`` stores a tool printout -- "success" there means
  the tool completed the method it ran, not that every firmware-hidden sector
  on the whole platter was overwritten;
* ``key_envelope.record`` lists every wrapping of a key, including wrappings
  that still protect other running volumes;
* ``volume_copy.record`` / the migration ledger track replica bytes and their
  movement at the logical layer -- an empty live catalog never proves that
  remapped media regions are empty.

This module composes those durable records into one retirement case per
physical drive.  A drive (or its fragments) may leave quarantine only when
identity, chain of custody, media coverage, independent witnesses, unique
certificate numbers and a real signed acceptance all line up.  Every decision
is recomputed from evidence; a database column that merely says "completed"
is never accepted as proof.
"""
import json
import uuid

from .store import one, rows, transaction


# Custody event kinds and their canonical ordering rank.  Ranks only describe
# the expected lifecycle; the explicit chronology checks below decide.
CUSTODY_KINDS = {
    "remove", "dismount", "detach", "quarantine", "isolate",
    "transport", "ship", "in_transit",
    "receive", "accept", "arrival",
    "inspect", "test", "examine",
    "sanitize", "overwrite",
    "shred", "crush", "physical_destroy",
    "hidden_area_verify", "reuse_review", "reuse_certify",
    "fragment_handover", "handover",
    "signoff", "rewarehouse", "restock", "factory", "factory_signoff",
    "carrier_receipt", "pickup", "release",
}

REQUIRED_CUSTODY = ("remove", "transport", "receive", "inspect")

# Events that represent final signed acceptance of something leaving or
# re-entering controlled custody.
FINAL_SIGNOFF_KINDS = ("fragment_handover", "handover", "signoff",
                       "rewarehouse", "restock", "factory", "factory_signoff")


_SCHEMA = """
        CREATE TABLE IF NOT EXISTS retirement_cases(
            drive TEXT PRIMARY KEY,
            case_id TEXT UNIQUE,
            observed_serial TEXT,
            expected_serial TEXT,
            identity_status TEXT NOT NULL DEFAULT 'unverified',
            path TEXT,
            state TEXT NOT NULL DEFAULT 'quarantined',
            completed INTEGER NOT NULL DEFAULT 0,
            destination TEXT,
            created_at INTEGER,
            updated_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS custody_events(
            id TEXT PRIMARY KEY,
            drive TEXT NOT NULL,
            kind TEXT NOT NULL,
            at INTEGER NOT NULL,
            actor TEXT,
            location TEXT,
            detail TEXT
        );
        CREATE TABLE IF NOT EXISTS firmware_reports(
            id TEXT PRIMARY KEY,
            drive TEXT NOT NULL,
            at INTEGER,
            source TEXT,
            note TEXT
        );
        CREATE TABLE IF NOT EXISTS media_regions(
            drive TEXT NOT NULL,
            region TEXT NOT NULL,
            classification TEXT NOT NULL DEFAULT 'inaccessible',
            first_report TEXT,
            reported_at INTEGER,
            status TEXT NOT NULL DEFAULT 'open',
            coverage_id TEXT,
            covered_at INTEGER,
            method TEXT,
            PRIMARY KEY(drive, region)
        );
        CREATE TABLE IF NOT EXISTS region_verifications(
            id TEXT PRIMARY KEY,
            drive TEXT,
            at INTEGER,
            method TEXT,
            verifier TEXT,
            verified TEXT,
            unresolved TEXT,
            verdict TEXT
        );
        CREATE TABLE IF NOT EXISTS receipt_links(
            id TEXT PRIMARY KEY,
            drive TEXT,
            receipt_id TEXT UNIQUE,
            at INTEGER
        );
        CREATE TABLE IF NOT EXISTS logical_migrations(
            id TEXT PRIMARY KEY,
            drive TEXT,
            volume TEXT,
            at INTEGER,
            copies_remaining INTEGER NOT NULL DEFAULT 0,
            destination TEXT,
            detail TEXT
        );
        CREATE TABLE IF NOT EXISTS reuse_reviews(
            review_id TEXT PRIMARY KEY,
            drive TEXT,
            at INTEGER,
            reviewer TEXT,
            approved INTEGER NOT NULL,
            note TEXT
        );
        CREATE TABLE IF NOT EXISTS witness_registry(
            witness_id TEXT PRIMARY KEY,
            name TEXT,
            role TEXT,
            independent INTEGER NOT NULL DEFAULT 1,
            valid INTEGER NOT NULL DEFAULT 1,
            registered_at INTEGER,
            invalidated_at INTEGER,
            invalidate_reason TEXT
        );
        CREATE TABLE IF NOT EXISTS certificates(
            cert_no TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            drive TEXT NOT NULL,
            at INTEGER NOT NULL,
            witnesses TEXT,
            payload TEXT,
            valid INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS rekey_jobs(
            job_id TEXT PRIMARY KEY,
            drive TEXT,
            volume TEXT,
            old_key_id TEXT,
            new_key_id TEXT,
            at INTEGER,
            state TEXT,
            reencrypted_at INTEGER,
            readback_at INTEGER,
            interrupted_at INTEGER,
            detail TEXT
        );
        CREATE TABLE IF NOT EXISTS key_surveys(
            survey_id TEXT PRIMARY KEY,
            key_id TEXT,
            at INTEGER,
            envelope_ids TEXT
        );
        CREATE TABLE IF NOT EXISTS key_states(
            key_id TEXT PRIMARY KEY,
            state TEXT,
            cert_no TEXT,
            at INTEGER,
            detail TEXT
        );
        CREATE TABLE IF NOT EXISTS final_signoffs(
            signoff_id TEXT PRIMARY KEY,
            drive TEXT,
            cert_no TEXT,
            kind TEXT,
            at INTEGER,
            signer TEXT,
            receiver TEXT,
            payload TEXT
        );
        CREATE TABLE IF NOT EXISTS carrier_receipts(
            receipt_id TEXT PRIMARY KEY,
            drive TEXT,
            carrier TEXT,
            at INTEGER,
            signer TEXT,
            payload TEXT
        );
        CREATE TABLE IF NOT EXISTS releases(
            release_id TEXT PRIMARY KEY,
            drive TEXT,
            carrier TEXT,
            at INTEGER,
            destination TEXT,
            verdict TEXT,
            payload TEXT
        );
        """


def init(db):
    # Individual execute() calls (not executescript) so init() is safe to call
    # while a caller transaction is open: executescript would COMMIT it first.
    for statement in _SCHEMA.split(";"):
        statement = statement.strip()
        if statement:
            db.execute(statement)


# ---------------------------------------------------------------------------
# small shared helpers
# ---------------------------------------------------------------------------

def _j(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _table_exists(db, name):
    return one(db, "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,)) is not None


def _case(db, drive):
    return one(db, "SELECT * FROM retirement_cases WHERE drive=?", (drive,))


def _ensure_case(db, drive, at=0):
    row = _case(db, drive)
    if row:
        return row
    db.execute(
        "INSERT INTO retirement_cases(drive,state,identity_status,created_at,updated_at) "
        "VALUES(?,?,?,?,?)",
        (drive, "quarantined", "unverified", at, at),
    )
    return _case(db, drive)


def _asset_serials(db, drive):
    """Serials bound to this drive id by physical asset attachments."""
    if not _table_exists(db, "drive_attachments"):
        return []
    return [r["serial"] for r in rows(
        db, "SELECT DISTINCT serial FROM drive_attachments WHERE drive=? AND serial IS NOT NULL",
        (drive,))]


def _drive_replicas(db, drive):
    if not _table_exists(db, "drive_attachments"):
        return []
    return [r["replica"] for r in rows(
        db, "SELECT DISTINCT replica FROM drive_attachments WHERE drive=? AND replica IS NOT NULL",
        (drive,))]


def _envelopes(db, key_id):
    if not _table_exists(db, "key_envelopes"):
        return []
    if key_id is None:
        return rows(db, "SELECT * FROM key_envelopes ORDER BY id")
    return rows(db, "SELECT * FROM key_envelopes WHERE key_id=? ORDER BY id", (key_id,))


def _cert(db, cert_no):
    return one(db, "SELECT * FROM certificates WHERE cert_no=?", (cert_no,))


def _latest_shred_cert(db, drive):
    return one(db,
               "SELECT * FROM certificates WHERE drive=? AND kind='shred' AND valid=1 "
               "ORDER BY at DESC, rowid DESC LIMIT 1", (drive,))


def _latest_reuse_cert(db, drive):
    return one(db,
               "SELECT * FROM certificates WHERE drive=? AND kind='reuse' AND valid=1 "
               "ORDER BY at DESC, rowid DESC LIMIT 1", (drive,))


def _witness_ids(cert):
    if not cert or not cert["witnesses"]:
        return []
    try:
        return json.loads(cert["witnesses"])
    except ValueError:
        return []


def _witness_problems(db, witness_ids, required=2):
    """Return (problems, all_currently_valid)."""
    problems = []
    if len(witness_ids) < required:
        problems.append("insufficient_witnesses")
    if len(set(witness_ids)) != len(witness_ids):
        problems.append("duplicate_witness")
    for wid in dict.fromkeys(witness_ids):
        w = one(db, "SELECT * FROM witness_registry WHERE witness_id=?", (wid,))
        if not w:
            problems.append("unknown_witness")
        elif not w["valid"]:
            problems.append("witness_invalid")
        elif not w["independent"]:
            problems.append("witness_not_independent")
    return problems


# ---------------------------------------------------------------------------
# Case opening / physical identity
# ---------------------------------------------------------------------------

def open_case(db, case_id, drive, serial=None, at=0, expected_serial=None):
    """Open the quarantine retirement case for one physical drive.

    ``serial`` is the serial read/scanned off the physical label.  The
    expected serial comes from the asset registry unless explicitly supplied.
    A mismatch is recorded as the case identity status and returned directly;
    it never blocks opening the quarantine case.
    """
    init(db)
    if not case_id or not drive or not isinstance(at, int) or at < 0:
        return "invalid_case"
    with transaction(db):
        old = one(db, "SELECT * FROM retirement_cases WHERE case_id=?", (case_id,))
        if old:
            if old["drive"] == drive:
                return "replayed"
            return "case_conflict"
        existing = _case(db, drive)
        if existing:
            return "drive_case_exists"
        expected = expected_serial
        if expected is None:
            serials = _asset_serials(db, drive)
            if len(serials) == 1:
                expected = serials[0]
            elif len(serials) > 1:
                expected = None
        if serial is not None and expected is not None:
            identity = "verified" if serial == expected else "serial_mismatch"
        elif serial is not None and len(_asset_serials(db, drive)) > 1:
            identity = "asset_serial_conflict"
        else:
            identity = "unverified"
        db.execute(
            "INSERT INTO retirement_cases(case_id,drive,observed_serial,expected_serial,"
            "identity_status,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
            (case_id, drive, serial, expected, identity, "quarantined", at, at),
        )
        if identity == "verified":
            db.execute(
                "INSERT INTO custody_events(id,drive,kind,at,actor,location,detail) "
                "VALUES(?,?,?,?,?,?,?)",
                (f"identity:{case_id}", drive, "identity_check", at, "intake",
                 "quarantine", _j({"serial": serial, "verdict": identity})),
            )
        return "serial_mismatch" if identity == "serial_mismatch" else "quarantined"


# House-style alias: retire(db, case_id, drive, serial, at)
def retire(db, case_id, drive, serial=None, at=0, **kwargs):
    return open_case(db, case_id, drive, serial=serial, at=at, **kwargs)


def verify_serial(db, drive, observed_serial=None, at=None):
    """Check the physical label serial against the asset attachment registry."""
    init(db)
    with transaction(db):
        case = _ensure_case(db, drive, at or 0)
        serial = observed_serial if observed_serial is not None else case["observed_serial"]
        serials = _asset_serials(db, drive)
        expected = case["expected_serial"]
        if expected is None and len(serials) == 1:
            expected = serials[0]
        if not serial:
            verdict = "serial_unverified"
        elif len(serials) > 1 and serial not in serials:
            verdict = "serial_mismatch"
        elif len(serials) > 1:
            verdict = "asset_serial_conflict"
        elif expected is None:
            verdict = "serial_unverified"
        elif serial != expected:
            verdict = "serial_mismatch"
        else:
            verdict = "identity_verified"
        db.execute(
            "UPDATE retirement_cases SET observed_serial=?, expected_serial=?, "
            "identity_status=?, updated_at=? WHERE drive=?",
            (serial, expected,
             "verified" if verdict == "identity_verified" else verdict,
             at or case["updated_at"], drive),
        )
        return verdict


check_serial = verify_serial
verify_identity = verify_serial


def admin_mark_completed(db, drive, at=None):
    """Emulate a bogus workflow engine flipping a database column to completed.

    Deliberately changes no evidence; :func:`authorize_release` recomputes the
    real proof and must still refuse pickup.
    """
    init(db)
    with transaction(db):
        if not _case(db, drive):
            return "unknown_drive"
        db.execute("UPDATE retirement_cases SET state='completed', completed=1 WHERE drive=?", (drive,))
        return "marked_completed_without_proof"


mark_completed = admin_mark_completed


def choose_path(db, drive, path, at=0):
    """Select the approved disposition route: ``shred`` or ``reuse``.

    Switching from an unfinished reuse route back to physical destruction is
    allowed (the prescribed fallback when hidden areas cannot be verified);
    choosing reuse after a shred certificate exists is refused.
    """
    init(db)
    if path not in ("shred", "reuse"):
        return "invalid_disposition_path"
    with transaction(db):
        case = _case(db, drive)
        if not case:
            return "unknown_drive"
        if path == "reuse" and _latest_shred_cert(db, drive):
            return "path_already_shredded"
        previous = case["path"]
        db.execute("UPDATE retirement_cases SET path=?, updated_at=? WHERE drive=?", (path, at, drive))
        if previous == path:
            return "path_unchanged"
        if previous is None:
            return "path_selected"
        return "path_changed"


select_path = choose_path
set_disposition_path = choose_path
decide_path = choose_path


# ---------------------------------------------------------------------------
# Chain of custody
# ---------------------------------------------------------------------------

def custody_event(db, event_id, drive, kind, at, actor="", location="", note=""):
    init(db)
    if not event_id or not drive or kind not in CUSTODY_KINDS:
        return "invalid_custody_event"
    if not isinstance(at, int) or at < 0:
        return "invalid_custody_time"
    with transaction(db):
        old = one(db, "SELECT * FROM custody_events WHERE id=?", (event_id,))
        expected = (drive, kind, at, actor, location, note)
        if old:
            same = tuple(old[k] for k in ("drive", "kind", "at", "actor", "location")) == expected[:5] \
                and (json.loads(old["detail"] or "{}").get("note", "") == note)
            return "replayed" if same else "custody_conflict"
        _ensure_case(db, drive, at)
        db.execute(
            "INSERT INTO custody_events VALUES(?,?,?,?,?,?,?)",
            (event_id, drive, kind, at, actor, location, _j({"note": note})),
        )
        db.execute("UPDATE retirement_cases SET updated_at=? WHERE drive=?", (at, drive))
        return "recorded"


def _kind_alias(kind):
    aliases = {"dismount": "remove", "detach": "remove",
               "isolate": "quarantine",
               "ship": "transport", "in_transit": "transport",
               "accept": "receive", "arrival": "receive",
               "test": "inspect", "examine": "inspect",
               "crush": "shred", "physical_destroy": "shred",
               "restock": "rewarehouse",
               "factory_signoff": "factory"}
    return aliases.get(kind, kind)


def custody_chain(db, drive):
    """Return ordered custody events plus basic chronology problems."""
    init(db)
    events = rows(db, "SELECT * FROM custody_events WHERE drive=? ORDER BY at, rowid", (drive,))
    problems = []
    present = {_kind_alias(e["kind"]) for e in events}
    for required in REQUIRED_CUSTODY:
        if required not in present:
            problems.append(f"missing_{required}")
    first = {}
    for e in events:
        k = _kind_alias(e["kind"])
        first.setdefault(k, e)
    if "receive" in first and "transport" in first and first["receive"]["at"] < first["transport"]["at"]:
        problems.append("receive_before_transport")
    if "inspect" in first and "receive" in first and first["inspect"]["at"] < first["receive"]["at"]:
        problems.append("inspection_before_receipt")
    if "shred" in first and "inspect" in first and first["shred"]["at"] < first["inspect"]["at"]:
        problems.append("shred_before_inspection")
    # Generic time inversion is impossible after ORDER BY at; detect equal-id
    # style backdated paperwork against terminal evidence in _gate_blockers.
    return {"drive": drive, "events": events, "present": sorted(present), "problems": problems}


chain_of_custody = custody_chain
chain = custody_chain


# Verb wrappers for the physical workflow steps.
def remove_drive(db, event_id, drive, at, actor="technician", location="rack", **kw):
    return custody_event(db, event_id, drive, "remove", at, actor, location, **kw)


def transport_drive(db, event_id, drive, at, actor="courier", location="in_transit", **kw):
    return custody_event(db, event_id, drive, "transport", at, actor, location, **kw)


ship_drive = transport_drive


def receive_drive(db, event_id, drive, at, actor="receiving", location="cage", **kw):
    return custody_event(db, event_id, drive, "receive", at, actor, location, **kw)


def inspect_drive(db, event_id, drive, at, actor="examiner", location="bench", **kw):
    return custody_event(db, event_id, drive, "inspect", at, actor, location, **kw)


# Signature some authors may expect: quarantine(db, record_id, drive, at, serial)
# or quarantine(db, record_id, drive, serial, at).
def quarantine(db, record_id, drive, *args, **kwargs):
    serial = kwargs.pop("serial", None)
    at = kwargs.pop("at", None)
    for value in args:
        if isinstance(value, str) and serial is None:
            serial = value
        elif isinstance(value, int) and not isinstance(value, bool) and at is None:
            at = value
    if at is None:
        at = 0
    if not _case_safe(db, drive):
        result = open_case(db, record_id, drive, serial=serial, at=at)
        if result != "quarantined":
            # Identity mismatch still leaves the drive quarantined; record the
            # hold event and surface the identity verdict to the caller.
            custody_event(db, record_id + ":event", drive, "quarantine", at,
                          kwargs.get("actor", "ops"), kwargs.get("location", "quarantine"))
            return result
    ev = custody_event(db, record_id + ":event", drive, "quarantine", at,
                       kwargs.get("actor", "ops"), kwargs.get("location", "quarantine"))
    return "quarantined" if ev in ("recorded", "replayed") else ev


def _case_safe(db, drive):
    init(db)
    return _case(db, drive)


isolate_drive = quarantine


# ---------------------------------------------------------------------------
# Firmware defect lists / hidden media regions
# ---------------------------------------------------------------------------

def _normalize_regions(regions):
    if regions is None:
        return []
    if isinstance(regions, str):
        regions = [regions]
    out = []
    for r in regions:
        if isinstance(r, dict):
            name = r.get("region") or r.get("sector") or r.get("id") or r.get("lba")
            if name is None:
                continue
            out.append((str(name), r.get("classification", "inaccessible")))
        else:
            out.append((str(r), "inaccessible"))
    return out


def firmware_report(db, report_id, drive, regions, at, source="firmware", note=""):
    """Record a firmware bad/remapped/unreadable region report.

    Later reports may enlarge the union of regions that must be accounted for;
    regions already known keep their first-report provenance.
    """
    init(db)
    norm = _normalize_regions(regions)
    if not report_id or not drive or not isinstance(at, int) or at < 0:
        return "invalid_firmware_report"
    with transaction(db):
        old = one(db, "SELECT * FROM firmware_reports WHERE id=?", (report_id,))
        if old:
            same = old["drive"] == drive and old["at"] == at and old["source"] == source
            existing = {(r["region"], r["classification"]) for r in rows(
                db, "SELECT region,classification FROM media_regions WHERE first_report=?", (report_id,))}
            if same and existing == set(norm):
                return "replayed"
            return "firmware_report_conflict"
        _ensure_case(db, drive, at)
        db.execute("INSERT INTO firmware_reports VALUES(?,?,?,?,?)",
                    (report_id, drive, at, source, note))
        for name, classification in norm:
            db.execute(
                "INSERT OR IGNORE INTO media_regions"
                "(drive,region,classification,first_report,reported_at) VALUES(?,?,?,?,?)",
                (drive, name, classification, report_id, at),
            )
        return "captured"


record_bad_sectors = firmware_report
record_defect_list = firmware_report


def media_coverage(db, drive):
    init(db)
    regions = rows(db, "SELECT * FROM media_regions WHERE drive=? ORDER BY region", (drive,))
    uncovered = [r["region"] for r in regions if r["status"] != "verified"]
    covered = [r["region"] for r in regions if r["status"] == "verified"]
    latest = one(db, "SELECT MAX(reported_at) m FROM media_regions WHERE drive=?", (drive,))
    last_verify = one(db, "SELECT MAX(at) m FROM region_verifications WHERE drive=? AND verdict='all_covered'",
                      (drive,))
    expanded = bool(last_verify and last_verify["m"] is not None
                    and latest["m"] is not None and latest["m"] > last_verify["m"])
    return {
        "drive": drive,
        "regions": regions,
        "total": len(regions),
        "covered": covered,
        "uncovered": uncovered,
        "coverage_complete": not uncovered and bool(regions),
        "scope_expanded_after_verification": expanded,
    }


def verify_hidden_areas(db, evidence_id, drive, at, verified_regions=None,
                        method="special_area_readback", verifier="", unresolved_regions=None):
    """Special verification of firmware-inaccessible / remapped regions.

    A normal overwrite receipt never calls this and therefore can never mark
    these regions covered.  Verification succeeds only when every known region
    is covered by positive evidence.  A later enlarged firmware report reopens
    coverage automatically.
    """
    init(db)
    verified = set(_normalize_region_names(verified_regions))
    forced_unresolved = set(_normalize_region_names(unresolved_regions))
    if not evidence_id or not drive or not isinstance(at, int) or at < 0:
        return "invalid_verification"
    with transaction(db):
        known = rows(db, "SELECT region FROM media_regions WHERE drive=?", (drive,))
        known_names = {r["region"] for r in known}
        if not known_names:
            return "no_reported_regions"
        unknown = verified - known_names
        if unknown:
            return "unknown_region"
        unresolved = (known_names - verified) | forced_unresolved
        verdict = "all_covered" if not unresolved else "coverage_gap"
        db.execute("INSERT INTO region_verifications VALUES(?,?,?,?,?,?,?,?)",
                   (evidence_id, drive, at, method, verifier,
                    _j(sorted(verified)), _j(sorted(unresolved)), verdict))
        if verdict == "all_covered":
            for name in verified:
                db.execute(
                    "UPDATE media_regions SET status='verified', coverage_id=?, covered_at=?, method=? "
                    "WHERE drive=? AND region=?",
                    (evidence_id, at, method, drive, name),
                )
            return "hidden_areas_verified"
        return "coverage_gap"


verify_inaccessible_regions = verify_hidden_areas
special_verify = verify_hidden_areas


def _normalize_region_names(value):
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    names = []
    for r in value:
        if isinstance(r, dict):
            n = r.get("region") or r.get("sector") or r.get("id") or r.get("lba")
            names.append(str(n))
        else:
            names.append(str(r))
    return names


# ---------------------------------------------------------------------------
# Sanitize tool receipts
# ---------------------------------------------------------------------------

def link_receipt(db, link_id, drive, receipt_id, at=None):
    """Attach a stored sanitize tool receipt to this retirement case.

    Validates that the receipt exists, was issued for THIS drive and reports
    success.  Linking never upgrades the receipt's scope: a tool success stays
    proof of the tool run only.
    """
    init(db)
    if not link_id or not drive or not receipt_id:
        return "invalid_receipt_link"
    with transaction(db):
        receipt = None
        if _table_exists(db, "sanitize_receipts"):
            receipt = one(db, "SELECT * FROM sanitize_receipts WHERE id=?", (receipt_id,))
        if not receipt:
            return "receipt_not_found"
        if receipt["drive"] != drive:
            return "receipt_drive_mismatch"
        if receipt["status"] != "success":
            return "receipt_not_successful"
        old = one(db, "SELECT * FROM receipt_links WHERE id=?", (link_id,))
        if old:
            if old["receipt_id"] == receipt_id and old["drive"] == drive:
                return "replayed"
            return "receipt_link_conflict"
        duplicate = one(db, "SELECT * FROM receipt_links WHERE receipt_id=?", (receipt_id,))
        if duplicate:
            return "receipt_already_linked"
        _ensure_case(db, drive, at if isinstance(at, int) else receipt["at"])
        db.execute("INSERT INTO receipt_links VALUES(?,?,?,?)",
                   (link_id, drive, receipt_id, at if isinstance(at, int) else receipt["at"]))
        return "receipt_linked"


attach_receipt = link_receipt


def sanitize_overview(db, drive):
    init(db)
    links = rows(db, "SELECT * FROM receipt_links WHERE drive=? ORDER BY rowid", (drive,))
    receipts = []
    for link in links:
        r = one(db, "SELECT id,drive,method,at,tool,status FROM sanitize_receipts WHERE id=?",
                (link["receipt_id"],)) if _table_exists(db, "sanitize_receipts") else None
        if r:
            receipts.append(r)
    return {
        "drive": drive,
        "receipts": receipts,
        "tool_success": any(r["status"] == "success" for r in receipts),
        # A tool receipt can never, by itself, prove whole-drive clearance
        # where firmware-hidden regions exist.
        "whole_drive_proven": False,
        "scope": "tool_method_run_only",
    }


# ---------------------------------------------------------------------------
# Logical migration and replica-byte integration
# ---------------------------------------------------------------------------

def record_migration(db, migration_id, drive, volume, at,
                      copies_remaining=0, destination="", note=""):
    """Record that a logical volume's copies left this drive's replica set."""
    init(db)
    if not migration_id or not drive or not volume or not isinstance(at, int) or at < 0:
        return "invalid_migration"
    if not isinstance(copies_remaining, int) or copies_remaining < 0:
        return "invalid_migration"
    with transaction(db):
        old = one(db, "SELECT * FROM logical_migrations WHERE id=?", (migration_id,))
        expected = (drive, volume, at, copies_remaining, destination, note)
        if old:
            same = tuple(old[k] for k in ("drive", "volume", "at", "copies_remaining", "destination")) == expected[:5]
            return "replayed" if same else "migration_conflict"
        _ensure_case(db, drive, at)
        db.execute("INSERT INTO logical_migrations VALUES(?,?,?,?,?,?,?)",
                   (migration_id, drive, volume, at, copies_remaining, destination, _j({"note": note})))
        return "migration_recorded"


migrate_volume = record_migration
logical_removal = record_migration


def logical_overview(db, drive):
    """Compose migration ledger with the immutable volume_copy byte records."""
    init(db)
    migrations = rows(db, "SELECT * FROM logical_migrations WHERE drive=? ORDER BY at", (drive,))
    replicas = _drive_replicas(db, drive)
    copy_rows = []
    if replicas and _table_exists(db, "volume_copies"):
        placeholders = ",".join("?" for _ in replicas)
        copy_rows = rows(
            db,
            f"SELECT id,volume,block_id,replica,epoch,version,digest,at,length(data) AS bytes "
            f"FROM volume_copies WHERE replica IN ({placeholders}) ORDER BY id",
            tuple(replicas))
    volumes = sorted({m["volume"] for m in migrations} | {c["volume"] for c in copy_rows})
    migrated = bool(migrations) and all(m["copies_remaining"] == 0 for m in migrations)
    return {
        "drive": drive,
        "replicas": replicas,
        "volumes": volumes,
        "migrations": migrations,
        "all_catalog_copies_moved": migrated,
        # Historical replica-byte records remain in the platform ledger;
        # retirement formalities do not delete them.
        "historical_copy_records": copy_rows,
        "historical_copy_count": len(copy_rows),
        # Logical/catalog evidence says nothing about hidden media regions.
        "proves_media_clearance": False,
    }


# ---------------------------------------------------------------------------
# Witness registry
# ---------------------------------------------------------------------------

def register_witness(db, witness_id, name, at=None, role="witness", independent=1):
    init(db)
    if not witness_id or not name:
        return "invalid_witness"
    with transaction(db):
        old = one(db, "SELECT * FROM witness_registry WHERE witness_id=?", (witness_id,))
        if old:
            if old["name"] == name and old["role"] == role and old["independent"] == int(bool(independent)):
                return "replayed"
            return "witness_conflict"
        db.execute("INSERT INTO witness_registry VALUES(?,?,?,?,?,?,?,?)",
                   (witness_id, name, role, 1 if independent else 0, 1,
                    at if isinstance(at, int) else 0, None, None))
        return "witness_registered"


add_witness = register_witness


def invalidate_witness(db, witness_id, at=0, reason=""):
    init(db)
    with transaction(db):
        w = one(db, "SELECT * FROM witness_registry WHERE witness_id=?", (witness_id,))
        if not w:
            return "unknown_witness"
        if not w["valid"]:
            return "replayed"
        db.execute("UPDATE witness_registry SET valid=0, invalidated_at=?, invalidate_reason=? "
                   "WHERE witness_id=?", (at, reason, witness_id))
        return "witness_invalidated"


revoke_witness = invalidate_witness


def _normalize_witnesses(witnesses):
    if witnesses is None:
        return []
    if isinstance(witnesses, str):
        return [witnesses]
    out = []
    for w in witnesses:
        if isinstance(w, dict):
            out.append(str(w.get("id") or w.get("witness_id") or w.get("name")))
        else:
            out.append(str(w))
    return out


# ---------------------------------------------------------------------------
# Certificates and physical shredding
# ---------------------------------------------------------------------------

def issue_certificate(db, cert_no, kind, drive, at, witnesses=None, payload=None):
    """Insert a certificate with a globally unique, non-repeatable number.

    Replaying the exact same issuance returns ``replayed``; reusing the same
    certificate number for different content returns
    ``certificate_number_reused``.
    """
    init(db)
    if not cert_no or not kind or not drive or not isinstance(at, int) or at < 0:
        return "invalid_certificate"
    with transaction(db):
        old = _cert(db, cert_no)
        body = _j(payload or {})
        wids = _j(_normalize_witnesses(witnesses))
        if old:
            same = (old["kind"] == kind and old["drive"] == drive and old["at"] == at
                    and old["payload"] == body and old["witnesses"] == wids)
            return "replayed" if same else "certificate_number_reused"
        if _case(db, drive) is None:
            return "unknown_drive"
        db.execute("INSERT INTO certificates(cert_no,kind,drive,at,witnesses,payload) "
                   "VALUES(?,?,?,?,?,?)", (cert_no, kind, drive, at, wids, body))
        return "certificate_issued"


def mint_certificate_number(kind):
    """Generate a fresh, non-repeatable certificate number."""
    return f"CERT-{kind.upper()}-{uuid.uuid4().hex[:12].upper()}"


def certify_shred(db, cert_no, drive, at, witnesses, actor="two_person_team", note=""):
    """Certify on-site physical shredding under two valid distinct witnesses."""
    init(db)
    wids = _normalize_witnesses(witnesses)
    if not cert_no or not drive or not isinstance(at, int) or at < 0:
        return "invalid_shred_certificate"
    with transaction(db):
        old = _cert(db, cert_no)
        if old:
            same = (old["kind"] == "shred" and old["drive"] == drive and old["at"] == at
                    and _witness_ids(old) == wids)
            return "replayed" if same else "certificate_number_reused"
        case = _case(db, drive)
        if not case:
            return "unknown_drive"
        if case["identity_status"] == "serial_mismatch":
            return "serial_mismatch"
        if case["identity_status"] != "verified":
            return "identity_unverified"
        problems = _witness_problems(db, wids, required=2)
        if problems:
            # Return the most specific first failure.
            order = ("unknown_witness", "witness_invalid", "witness_not_independent",
                     "duplicate_witness", "insufficient_witnesses")
            for code in order:
                if code in problems:
                    return code
            return problems[0]
        db.execute(
            "INSERT INTO certificates(cert_no,kind,drive,at,witnesses,payload) VALUES(?,?,?,?,?,?)",
            (cert_no, "shred", drive, at, _j(wids), _j({"actor": actor, "note": note})),
        )
        db.execute("INSERT OR IGNORE INTO custody_events(id,drive,kind,at,actor,location,detail) "
                   "VALUES(?,?,?,?,?,?,?)",
                   (f"shred-event:{cert_no}", drive, "shred", at, actor, "controlled_destroy_bay",
                    _j({"cert_no": cert_no})))
        db.execute("UPDATE retirement_cases SET path='shred', updated_at=? WHERE drive=?", (at, drive))
        return "shred_certified"


shred_drive = certify_shred
destroy_physically = certify_shred


def handover_fragments(db, cert_no, drive, at, shred_cert_no=None,
                       receiver="", signer="", carrier="", weight_kg=None, note=""):
    """Issue the unique fragment-handover certificate with receiver signature.

    The handover signature cannot predate the shredding it receipts.
    """
    init(db)
    if not cert_no or not drive or not isinstance(at, int) or at < 0:
        return "invalid_handover"
    with transaction(db):
        old = _cert(db, cert_no)
        if old:
            return "replayed" if old["kind"] == "fragment_handover" and old["drive"] == drive \
                else "certificate_number_reused"
        if not _case(db, drive):
            return "unknown_drive"
        shred = _cert(db, shred_cert_no) if shred_cert_no else _latest_shred_cert(db, drive)
        if not shred or shred["kind"] != "shred" or shred["drive"] != drive:
            return "shred_certificate_required"
        if at < shred["at"]:
            return "premature_signoff"
        payload = {"receiver": receiver, "signer": signer, "carrier": carrier,
                   "weight_kg": weight_kg, "shred_cert_no": shred["cert_no"], "note": note}
        db.execute("INSERT INTO certificates(cert_no,kind,drive,at,witnesses,payload) "
                   "VALUES(?,?,?,?,?,?)",
                   (cert_no, "fragment_handover", drive, at, shred["witnesses"], _j(payload)))
        db.execute("INSERT INTO final_signoffs(signoff_id,drive,cert_no,kind,at,signer,receiver,payload) "
                   "VALUES(?,?,?,?,?,?,?,?)",
                   (f"sign:{cert_no}", drive, cert_no, "fragment_handover", at, signer, receiver, _j(payload)))
        db.execute("INSERT OR IGNORE INTO custody_events(id,drive,kind,at,actor,location,detail) "
                   "VALUES(?,?,?,?,?,?,?)",
                   (f"handover-event:{cert_no}", drive, "fragment_handover", at, signer or receiver,
                    "controlled_loading_dock", _j({"cert_no": cert_no})))
        return "fragment_certificate_issued"


fragment_handover = handover_fragments


def record_carrier_receipt(db, receipt_id, drive, at, carrier="recycler", signer="", note=""):
    """Record a recycler/carrier signed pickup receipt.

    A receipt signed before a qualifying final handover exists is an early
    signature and is refused as proof (stored nowhere).  Backdated receipts
    inserted out-of-band are still detected by the evaluation chronology.
    """
    init(db)
    if not receipt_id or not drive or not isinstance(at, int) or at < 0:
        return "invalid_carrier_receipt"
    with transaction(db):
        old = one(db, "SELECT * FROM carrier_receipts WHERE receipt_id=?", (receipt_id,))
        if old:
            return "replayed" if (old["drive"], old["at"], old["carrier"]) == (drive, at, carrier) \
                else "carrier_receipt_conflict"
        if not _case(db, drive):
            return "unknown_drive"
        fragment = one(db,
                       "SELECT * FROM certificates WHERE drive=? AND kind='fragment_handover' AND at<=? "
                       "ORDER BY at DESC LIMIT 1", (drive, at))
        reuse_sign = one(db,
                         "SELECT * FROM final_signoffs WHERE drive=? AND kind IN ('rewarehouse','factory') "
                         "AND at<=? ORDER BY at DESC LIMIT 1", (drive, at))
        if not fragment and not reuse_sign:
            return "premature_signoff"
        db.execute("INSERT INTO carrier_receipts VALUES(?,?,?,?,?,?)",
                   (receipt_id, drive, carrier, at, signer, _j({"note": note})))
        db.execute("INSERT OR IGNORE INTO custody_events(id,drive,kind,at,actor,location,detail) "
                   "VALUES(?,?,?,?,?,?,?)",
                   (f"carrier-event:{receipt_id}", drive, "carrier_receipt", at, signer or carrier,
                    "loading_dock", _j({"receipt_id": receipt_id})))
        return "carrier_receipt_recorded"


carrier_signoff = record_carrier_receipt
recycler_signoff = record_carrier_receipt


# ---------------------------------------------------------------------------
# Key envelopes, dependency surveys, rekey and destruction
# ---------------------------------------------------------------------------

def start_rekey(db, job_id, drive, volume, old_key_id, new_key_id, at):
    """Begin re-encrypting a still-running volume under an independent key."""
    init(db)
    if not job_id or not old_key_id or not new_key_id or not isinstance(at, int) or at < 0:
        return "invalid_rekey"
    if old_key_id == new_key_id:
        return "new_key_not_independent"
    with transaction(db):
        old = one(db, "SELECT * FROM rekey_jobs WHERE job_id=?", (job_id,))
        if old:
            same = (old["drive"], old["volume"], old["old_key_id"], old["new_key_id"]) == \
                   (drive, volume, old_key_id, new_key_id)
            return "replayed" if same else "rekey_conflict"
        db.execute("INSERT INTO rekey_jobs(job_id,drive,volume,old_key_id,new_key_id,at,state) "
                   "VALUES(?,?,?,?,?,?,?)",
                   (job_id, drive, volume, old_key_id, new_key_id, at, "started"))
        return "rekey_started"


rekey_volume = start_rekey


def mark_reencrypted(db, job_id, at=None):
    init(db)
    with transaction(db):
        job = one(db, "SELECT * FROM rekey_jobs WHERE job_id=?", (job_id,))
        if not job:
            return "unknown_rekey_job"
        if job["state"] == "interrupted":
            return "rekey_interrupted"
        if job["state"] in ("reencrypted", "verified"):
            return "replayed"
        ts = at if isinstance(at, int) else job["at"]
        db.execute("UPDATE rekey_jobs SET state='reencrypted', reencrypted_at=? WHERE job_id=?",
                   (ts, job_id))
        return "reencrypted"


def verify_readback(db, job_id, at, ok=True, detail=""):
    """Read the volume back after re-encryption and verify the bytes/digests."""
    init(db)
    if not isinstance(at, int) or at < 0:
        return "invalid_readback"
    with transaction(db):
        job = one(db, "SELECT * FROM rekey_jobs WHERE job_id=?", (job_id,))
        if not job:
            return "unknown_rekey_job"
        if job["state"] == "interrupted":
            return "rekey_interrupted"
        if not ok:
            db.execute("UPDATE rekey_jobs SET state='readback_failed', detail=? WHERE job_id=?",
                       (_j({"detail": detail}), job_id))
            return "readback_failed"
        if job["state"] == "verified":
            return "replayed"
        if job["state"] != "reencrypted":
            return "reencryption_incomplete"
        db.execute("UPDATE rekey_jobs SET state='verified', readback_at=?, detail=? WHERE job_id=?",
                   (at, _j({"detail": detail}), job_id))
        return "readback_verified"


def interrupt_rekey(db, job_id, at=0, reason="interrupted"):
    init(db)
    with transaction(db):
        job = one(db, "SELECT * FROM rekey_jobs WHERE job_id=?", (job_id,))
        if not job:
            return "unknown_rekey_job"
        if job["state"] == "verified":
            return "already_verified"
        db.execute("UPDATE rekey_jobs SET state='interrupted', interrupted_at=?, detail=? WHERE job_id=?",
                   (at, _j({"reason": reason}), job_id))
        return "rekey_interrupted"


def complete_rekey(db, job_id, at, readback_ok=True):
    """Convenience: mark re-encryption done then perform readback verification."""
    r1 = mark_reencrypted(db, job_id, at)
    if r1 not in ("reencrypted", "replayed"):
        return r1
    return verify_readback(db, job_id, at, ok=readback_ok)


def _envelope_resolution(db, env):
    """Classify one key envelope dependency."""
    job = one(db,
              "SELECT * FROM rekey_jobs WHERE old_key_id=? AND drive=? AND volume=? "
              "AND state='verified' ORDER BY rowid DESC LIMIT 1",
              (env["key_id"], env["drive"], env["volume"]))
    if job:
        return "rekeyed"
    # The volume's copies were evidenced as migrated off this drive, so this
    # particular wrapping is no longer a running dependency of the old media.
    migration = one(db,
                    "SELECT * FROM logical_migrations WHERE drive=? AND volume=? "
                    "AND copies_remaining=0 ORDER BY rowid DESC LIMIT 1",
                    (env["drive"], env["volume"]))
    if migration:
        return "logically_migrated"
    shred = _latest_shred_cert(db, env["drive"])
    if shred and _witness_problems(db, _witness_ids(shred), 2) == []:
        return "media_destroyed"
    ks = one(db, "SELECT * FROM key_states WHERE key_id=?", (env["key_id"],))
    if ks and ks["state"] == "destroyed":
        return "key_destroyed"
    return "active"


def key_dependencies(db, key_id):
    """Every envelope of a key with its current resolution state."""
    init(db)
    deps = []
    for env in _envelopes(db, key_id):
        d = dict(env)
        d["resolution"] = _envelope_resolution(db, env)
        deps.append(d)
    return deps


def envelopes(db, key_id=None):
    """Raw key_envelope rows (optionally restricted to one key)."""
    init(db)
    return _envelopes(db, key_id)


def survey_dependencies(db, survey_id, key_id, at=0):
    """Record the complete set of currently known envelopes for a key.

    Destroying the key later compares the live envelope table against this
    survey so a late third wrapping cannot be missed.
    """
    init(db)
    if not survey_id or not key_id:
        return "invalid_survey"
    with transaction(db):
        old = one(db, "SELECT * FROM key_surveys WHERE survey_id=?", (survey_id,))
        if old:
            return "replayed" if old["key_id"] == key_id else "survey_conflict"
        ids = [e["id"] for e in _envelopes(db, key_id)]
        db.execute("INSERT INTO key_surveys VALUES(?,?,?,?)",
                   (survey_id, key_id, at, _j(ids)))
        return "survey_recorded"


survey_envelopes = survey_dependencies


def destroy_key(db, cert_no, key_id, at=0, authority="security-officer", survey_id=None):
    """Destroy a key only after every live envelope dependency is resolved.

    A newly arrived envelope not present in the referenced/latest survey is
    reported specifically as ``late_envelope`` so the team must investigate
    the third wrapping before destruction.
    """
    init(db)
    if not cert_no or not key_id or not isinstance(at, int) or at < 0:
        return "invalid_key_destruction"
    with transaction(db):
        existing = one(db, "SELECT * FROM key_states WHERE key_id=?", (key_id,))
        if existing and existing["state"] == "destroyed":
            return "replayed" if existing["cert_no"] == cert_no else "key_already_destroyed"
        deps = key_dependencies(db, key_id)
        active = [d for d in deps if d["resolution"] == "active"]
        survey = None
        if survey_id:
            survey = one(db, "SELECT * FROM key_surveys WHERE survey_id=?", (survey_id,))
        else:
            survey = one(db,
                         "SELECT * FROM key_surveys WHERE key_id=? ORDER BY at DESC,rowid DESC LIMIT 1",
                         (key_id,))
        if active:
            # "Late envelope" only has meaning against an actual survey.
            if survey is not None:
                known = set(json.loads(survey["envelope_ids"]))
                late = [d for d in active if d["id"] not in known]
                if late:
                    return "late_envelope"
            if any(_job_interrupted(db, d) for d in active):
                return "rekey_interrupted"
            return "key_still_enveloped"
        # No live dependency remains.  If a survey was used, it must account
        # for the whole current envelope set before the key can be destroyed.
        if survey is not None:
            known_all = set(json.loads(survey["envelope_ids"]))
            current_all = {e["id"] for e in _envelopes(db, key_id)}
            if current_all - known_all:
                return "survey_outdated"
        old_cert = _cert(db, cert_no)
        if old_cert:
            return "certificate_number_reused"
        db.execute("INSERT INTO certificates(cert_no,kind,drive,at,witnesses,payload) "
                   "VALUES(?,?,?,?,?,?)",
                   (cert_no, "key_destruction", "", at, "[]",
                    _j({"key_id": key_id, "authority": authority})))
        db.execute("INSERT INTO key_states(key_id,state,cert_no,at,detail) VALUES(?,?,?,?,?) "
                   "ON CONFLICT(key_id) DO UPDATE SET state='destroyed',cert_no=excluded.cert_no,"
                   "at=excluded.at,detail=excluded.detail",
                   (key_id, "destroyed", cert_no, at, _j({"authority": authority})))
        return "key_destroyed"


def _job_interrupted(db, dep):
    job = one(db,
              "SELECT state FROM rekey_jobs WHERE old_key_id=? AND drive=? AND volume=? "
              "ORDER BY rowid DESC LIMIT 1",
              (dep["key_id"], dep["drive"], dep["volume"]))
    return bool(job and job["state"] in ("interrupted", "readback_failed"))


destroy_key_when_safe = destroy_key


def retained_keys(db):
    """Keys with at least one still-active envelope dependency."""
    init(db)
    result = []
    seen = set()
    for env in _envelopes(db, None):
        if env["key_id"] in seen:
            continue
        seen.add(env["key_id"])
        if any(d["resolution"] == "active" for d in key_dependencies(db, env["key_id"])):
            result.append(env["key_id"])
    return sorted(result)


def destroyed_keys(db):
    init(db)
    return [r["key_id"] for r in rows(db, "SELECT key_id FROM key_states WHERE state='destroyed'")]


# ---------------------------------------------------------------------------
# Reuse review / certification / re-warehouse or factory signoff
# ---------------------------------------------------------------------------

def review_reuse(db, review_id, drive, at, reviewer="review-board", approved=True, note=""):
    init(db)
    if not review_id or not drive or not isinstance(at, int) or at < 0:
        return "invalid_reuse_review"
    with transaction(db):
        if not _case(db, drive):
            return "unknown_drive"
        old = one(db, "SELECT * FROM reuse_reviews WHERE review_id=?", (review_id,))
        if old:
            return "replayed" if bool(old["approved"]) == bool(approved) and old["drive"] == drive \
                else "review_conflict"
        db.execute("INSERT INTO reuse_reviews VALUES(?,?,?,?,?,?)",
                   (review_id, drive, at, reviewer, 1 if approved else 0, note))
        return "reuse_approved" if approved else "reuse_rejected"


def certify_reuse(db, cert_no, drive, at, witnesses=None, reviewer_required=True, note=""):
    """Certify the drive fit for controlled reuse.

    Requires complete special verification of the firmware-reported regions,
    a passed qualified reuse review and at least one valid independent witness.
    A previously shredded drive can never receive a reuse certificate.
    """
    init(db)
    wids = _normalize_witnesses(witnesses)
    if not cert_no or not drive or not isinstance(at, int) or at < 0:
        return "invalid_reuse_certificate"
    with transaction(db):
        old = _cert(db, cert_no)
        if old:
            same = old["kind"] == "reuse" and old["drive"] == drive and old["at"] == at
            return "replayed" if same else "certificate_number_reused"
        case = _case(db, drive)
        if not case:
            return "unknown_drive"
        if _latest_shred_cert(db, drive):
            return "path_already_shredded"
        if case["identity_status"] == "serial_mismatch":
            return "serial_mismatch"
        if case["identity_status"] != "verified":
            return "identity_unverified"
        # The approved reuse sequence destroys every key that wrapped this
        # drive's volumes (only after all shared dependencies are safe).
        live_drive_keys = sorted({e["key_id"] for e in _envelopes(db, None) if e["drive"] == drive})
        for kid in live_drive_keys:
            ks = one(db, "SELECT state FROM key_states WHERE key_id=?", (kid,))
            if not ks or ks["state"] != "destroyed":
                return "drive_key_not_destroyed"
        coverage = media_coverage(db, drive)
        if coverage["total"] == 0:
            return "no_firmware_report"
        if not coverage["coverage_complete"] or coverage["scope_expanded_after_verification"]:
            return "hidden_regions_unverified"
        if reviewer_required:
            review = one(db,
                         "SELECT * FROM reuse_reviews WHERE drive=? "
                         "ORDER BY at DESC,rowid DESC LIMIT 1", (drive,))
            if not review:
                return "reuse_review_required"
            if not review["approved"]:
                return "reuse_review_failed"
        problems = _witness_problems(db, wids, required=1)
        if problems:
            for code in ("unknown_witness", "witness_invalid", "witness_not_independent",
                         "duplicate_witness", "insufficient_witnesses"):
                if code in problems:
                    return code
        db.execute("INSERT INTO certificates(cert_no,kind,drive,at,witnesses,payload) "
                   "VALUES(?,?,?,?,?,?)",
                   (cert_no, "reuse", drive, at, _j(wids), _j({"note": note})))
        db.execute("INSERT OR IGNORE INTO custody_events(id,drive,kind,at,actor,location,detail) "
                   "VALUES(?,?,?,?,?,?,?)",
                   (f"reuse-event:{cert_no}", drive, "reuse_certify", at, "reuse-board",
                    "certification_office", _j({"cert_no": cert_no})))
        db.execute("UPDATE retirement_cases SET path='reuse', updated_at=? WHERE drive=?", (at, drive))
        return "reuse_certified"


def sign_final(db, signoff_id, drive, cert_no, at, kind="rewarehouse",
               signer="", receiver="", note=""):
    """Real signed acceptance: re-warehouse intake or factory outgoing signoff."""
    init(db)
    if kind not in ("rewarehouse", "factory"):
        return "invalid_signoff_kind"
    if not signoff_id or not drive or not cert_no or not isinstance(at, int) or at < 0:
        return "invalid_signoff"
    with transaction(db):
        if not _case(db, drive):
            return "unknown_drive"
        cert = _cert(db, cert_no)
        if not cert:
            return "certificate_not_found"
        if cert["drive"] != drive:
            return "certificate_drive_mismatch"
        # A fragment/shred certificate cannot be promoted into proof that the
        # whole drive is reusable.
        if cert["kind"] != "reuse":
            return "certificate_kind_mismatch"
        if at < cert["at"]:
            return "premature_signoff"
        old = one(db, "SELECT * FROM final_signoffs WHERE signoff_id=?", (signoff_id,))
        if old:
            return "replayed" if old["cert_no"] == cert_no and old["kind"] == kind else "signoff_conflict"
        payload = {"signer": signer, "receiver": receiver, "note": note}
        db.execute("INSERT INTO final_signoffs VALUES(?,?,?,?,?,?,?,?)",
                   (signoff_id, drive, cert_no, kind, at, signer, receiver, _j(payload)))
        event_kind = "factory" if kind == "factory" else "rewarehouse"
        db.execute("INSERT OR IGNORE INTO custody_events(id,drive,kind,at,actor,location,detail) "
                   "VALUES(?,?,?,?,?,?,?)",
                   (f"sign-event:{signoff_id}", drive, event_kind, at, signer or receiver,
                    kind, _j({"cert_no": cert_no})))
        return "signoff_recorded"


rewarehouse_signoff = sign_final


def factory_signoff(db, signoff_id, drive, cert_no, at, **kwargs):
    return sign_final(db, signoff_id, drive, cert_no, at, kind="factory", **kwargs)


# ---------------------------------------------------------------------------
# Evaluation / proof / release gate
# ---------------------------------------------------------------------------

def _early_signoff_problems(db, drive, completion_at):
    """Detect signed paperwork that predates the event it claims to receipt."""
    problems = []
    rows_ = rows(db, "SELECT * FROM final_signoffs WHERE drive=?", (drive,))
    for s in rows_:
        cert = _cert(db, s["cert_no"]) if s["cert_no"] else None
        if cert and s["at"] < cert["at"]:
            problems.append("premature_signoff")
    carriers = rows(db, "SELECT * FROM carrier_receipts WHERE drive=?", (drive,))
    for c in carriers:
        if completion_at is None or c["at"] < completion_at:
            problems.append("premature_signoff")
    # Out-of-band custody rows claiming final signoff before terminal evidence.
    if completion_at is not None:
        for e in rows(db, "SELECT * FROM custody_events WHERE drive=? ORDER BY at", (drive,)):
            if _kind_alias(e["kind"]) in ("fragment_handover", "signoff", "rewarehouse", "factory"):
                # Legitimate rows created by the high-level APIs already enforce
                # chronology; this catches directly-inserted/backdated rows only
                # when they predate the relevant terminal certificate.
                if e["at"] < completion_at and not e["id"].startswith(("handover-event:", "sign-event:")):
                    problems.append("premature_signoff")
    return sorted(set(problems))


def _gate(db, drive, at=None):
    """Recompute the full release gate from durable evidence."""
    blockers = []
    case = _case(db, drive)
    if not case:
        return ["unknown_drive"], None

    # 1. physical identity
    if case["identity_status"] == "serial_mismatch":
        blockers.append("serial_mismatch")
    elif case["identity_status"] == "asset_serial_conflict":
        blockers.append("asset_serial_conflict")
    elif case["identity_status"] != "verified":
        blockers.append("identity_unverified")

    # 2. custody tracking and chronology
    cc = custody_chain(db, drive)
    blockers.extend(cc["problems"])

    # 3. evidence by disposition path
    shred = _latest_shred_cert(db, drive)
    reuse = _latest_reuse_cert(db, drive)
    shred_witness_problems = []
    if shred:
        shred_witness_problems = _witness_problems(db, _witness_ids(shred), 2)
        blockers.extend(shred_witness_problems)

    fragment = one(db,
                   "SELECT * FROM certificates WHERE drive=? AND kind='fragment_handover' AND valid=1 "
                   "ORDER BY at DESC,rowid DESC LIMIT 1", (drive,))
    reuse_signoff = one(db,
                        "SELECT * FROM final_signoffs WHERE drive=? AND kind IN ('rewarehouse','factory') "
                        "ORDER BY at DESC,rowid DESC LIMIT 1", (drive,))
    coverage = media_coverage(db, drive)

    completion_at = None
    path = None
    if shred:
        # A shred certificate exists; witness validity problems were already
        # added above.  Stay on the physical-destruction path regardless.
        path = "shred"
        if not fragment:
            blockers.append("fragment_certificate_required")
        else:
            completion_at = fragment["at"]
    elif reuse:
        path = "reuse"
        if not coverage["coverage_complete"] or coverage["scope_expanded_after_verification"]:
            blockers.append("hidden_regions_unverified")
        live_drive_keys = sorted({e["key_id"] for e in _envelopes(db, None) if e["drive"] == drive})
        for kid in live_drive_keys:
            ks = one(db, "SELECT state FROM key_states WHERE key_id=?", (kid,))
            if not ks or ks["state"] != "destroyed":
                blockers.append("drive_key_not_destroyed")
                break
        if not reuse_signoff:
            blockers.append("final_signoff_required")
        else:
            completion_at = reuse_signoff["at"]
    else:
        # No valid terminal certificate yet.
        if case["path"] == "reuse":
            if coverage["total"] == 0:
                blockers.append("no_firmware_report")
            elif not coverage["coverage_complete"] or coverage["scope_expanded_after_verification"]:
                blockers.append("hidden_regions_unverified")
            live_drive_keys = sorted({e["key_id"] for e in _envelopes(db, None) if e["drive"] == drive})
            for kid in live_drive_keys:
                ks = one(db, "SELECT state FROM key_states WHERE key_id=?", (kid,))
                if not ks or ks["state"] != "destroyed":
                    blockers.append("drive_key_not_destroyed")
                    break
            blockers.append("reuse_certificate_required")
        elif case["path"] == "shred":
            blockers.append("shred_certificate_required")
        else:
            blockers.append("physical_destruction_or_reuse_proof_required")

    # Unless the platter is physically destroyed, outstanding firmware-hidden
    # regions are a standing blocker no matter which paperwork exists.
    if not shred and coverage["total"] > 0 and (
            not coverage["coverage_complete"] or coverage["scope_expanded_after_verification"]):
        blockers.append("hidden_regions_unverified")

    # Carrier / recycler early signatures.
    blockers.extend(_early_signoff_problems(db, drive, completion_at))

    # Release timestamp cannot precede completion evidence.
    if at is not None and completion_at is not None and at < completion_at:
        blockers.append("release_before_completion")

    # De-duplicate while preserving a stable priority order.
    priority = [
        "unknown_drive", "serial_mismatch", "asset_serial_conflict", "identity_unverified",
        "missing_remove", "missing_transport", "missing_receive", "missing_inspect",
        "receive_before_transport", "inspection_before_receipt", "shred_before_inspection",
        "premature_signoff", "release_before_completion",
        "unknown_witness", "witness_invalid", "witness_not_independent",
        "duplicate_witness", "insufficient_witnesses",
        "no_firmware_report", "hidden_regions_unverified",
        "drive_key_not_destroyed",
        "reuse_certificate_required", "reuse_review_required", "reuse_review_failed",
        "certificate_kind_mismatch", "final_signoff_required",
        "shred_certificate_required", "fragment_certificate_required",
        "physical_destruction_or_reuse_proof_required",
    ]
    unique = set(blockers)
    ordered = [c for c in priority if c in unique] + sorted(c for c in unique if c not in priority)
    return ordered, path


def evaluate(db, drive):
    """Build the full evidence/proof decision document for one drive."""
    init(db)
    case = _case(db, drive)
    if not case:
        return {"drive": drive, "known": False, "verdict": "unknown_drive",
                "blockers": ["unknown_drive"], "may_leave": False}

    blockers, path = _gate(db, drive)
    cc = custody_chain(db, drive)
    coverage = media_coverage(db, drive)
    logical = logical_overview(db, drive)
    sanitize = sanitize_overview(db, drive)

    shred = _latest_shred_cert(db, drive)
    reuse = _latest_reuse_cert(db, drive)
    fragment = one(db,
                   "SELECT * FROM certificates WHERE drive=? AND kind='fragment_handover' "
                   "ORDER BY at DESC,rowid DESC LIMIT 1", (drive,))
    signoff = one(db, "SELECT * FROM final_signoffs WHERE drive=? ORDER BY at DESC,rowid DESC LIMIT 1",
                  (drive,))
    release = one(db, "SELECT * FROM releases WHERE drive=? ORDER BY at DESC,rowid DESC LIMIT 1", (drive,))

    # Key view: every key appearing in an envelope for a volume this drive
    # carried, plus the global retain/destroy lists.
    all_key_ids = sorted({e["key_id"] for e in _envelopes(db, None)})
    drive_key_ids = sorted({e["key_id"] for e in _envelopes(db, None) if e["drive"] == drive})
    keys = {}
    for kid in all_key_ids:
        deps = key_dependencies(db, kid)
        ks = one(db, "SELECT state,cert_no,at FROM key_states WHERE key_id=?", (kid,))
        keys[kid] = {
            "on_this_drive": kid in drive_key_ids,
            "state": ks["state"] if ks else "retained",
            "dependencies": deps,
            "active_dependencies": [d for d in deps if d["resolution"] == "active"],
        }

    shred_valid = bool(shred) and not _witness_problems(db, _witness_ids(shred), 2)
    crypto_erased = bool(drive_key_ids) and all(keys[k]["state"] == "destroyed" for k in drive_key_ids)
    destroyable = [kid for kid in all_key_ids
                   if keys[kid]["state"] != "destroyed" and not keys[kid]["active_dependencies"]]
    if shred_valid:
        recovery = "impossible_physical_destruction"
    elif path == "reuse" and coverage["coverage_complete"] and crypto_erased:
        recovery = "impossible_cryptographic_erasure_and_verified_media"
    else:
        recovery = "not_established"

    may_leave = not blockers
    if release and blockers:
        verdict = "release_evidence_broken"
    elif release:
        verdict = "released"
    elif may_leave:
        verdict = ("releasable_shredded_fragments" if path == "shred"
                   else "releasable_reusable_drive" if path == "reuse"
                   else "releasable")
    else:
        verdict = "not_releasable"

    return {
        "known": True,
        "drive": drive,
        "case_id": case["case_id"],
        "state": case["state"],
        "database_completed_flag": bool(case["completed"]),
        "path": path or case["path"],
        "identity": {
            "status": case["identity_status"],
            "observed_serial": case["observed_serial"],
            "expected_serial": case["expected_serial"],
            "asset_serials": _asset_serials(db, drive),
        },
        "quarantined": release is None,
        "custody": cc,
        "logical": logical,
        "sanitize": sanitize,
        "media": coverage,
        "keys": keys,
        "keys_retained": retained_keys(db),
        "keys_destroyable": destroyable,
        "keys_destroyed": destroyed_keys(db),
        "certificates": {
            "shred": shred,
            "fragment_handover": fragment,
            "reuse": reuse,
            "final_signoff": signoff,
        },
        "physical_destruction_proven": shred_valid,
        "data_recovery": recovery,
        "recovery_possible": recovery == "not_established",
        "may_leave": may_leave,
        "releasable": may_leave,
        "can_leave_room": may_leave,
        "release_allowed": may_leave,
        "allowed_to_leave": may_leave,
        "keys_to_retain": retained_keys(db),
        "released": bool(release),
        "release": release,
        "destination": release["destination"] if release else case["destination"],
        "verdict": verdict,
        "blockers": blockers,
    }


proof = evaluate
decision = evaluate
assess = evaluate
retirement_proof = evaluate
get_proof = evaluate


def authorize_release(db, release_id, drive, carrier="certified-recycler", at=0,
                      destination=None, note=""):
    """Final gate: only complete evidence lets the recycler take anything.

    A database 'completed' flag is irrelevant; the proof is recomputed.
    Idempotent on ``release_id``.
    """
    init(db)
    if not release_id or not drive or not isinstance(at, int) or at < 0:
        return "invalid_release"
    with transaction(db):
        old = one(db, "SELECT * FROM releases WHERE release_id=?", (release_id,))
        if old:
            same = old["drive"] == drive and old["carrier"] == carrier and old["at"] == at
            return "replayed" if same else "release_conflict"
        blockers, path = _gate(db, drive, at)
        if blockers:
            return blockers[0]
        dest = destination or ("material_recovery_shredded_fragments" if path == "shred"
                               else "reuse_inventory_or_factory")
        db.execute("INSERT INTO releases VALUES(?,?,?,?,?,?,?)",
                   (release_id, drive, carrier, at, dest, "released", _j({"note": note})))
        db.execute("UPDATE retirement_cases SET state='released', destination=?, updated_at=? WHERE drive=?",
                   (dest, at, drive))
        db.execute("INSERT OR IGNORE INTO custody_events(id,drive,kind,at,actor,location,detail) "
                   "VALUES(?,?,?,?,?,?,?)",
                   (f"release-event:{release_id}", drive, "release", at, carrier,
                    "loading_dock", _j({"destination": dest})))
        return "released"


release_drive = authorize_release


def release(db, *args, **kwargs):
    """Flexible alias accepting either id-first or drive-first arguments.

    Supported positional forms::

        release(db, release_id, drive, carrier, at)
        release(db, drive, at)                 # release id generated
        release(db, drive, carrier, at)
    """
    release_id = kwargs.pop("release_id", None)
    drive = kwargs.pop("drive", None)
    carrier = kwargs.pop("carrier", "certified-recycler")
    at = kwargs.pop("at", 0)
    rest = list(args)
    if drive is None and rest:
        # Decide whether the first positional is a known drive.
        init(db)
        if _case(db, rest[0]):
            drive = rest.pop(0)
        elif len(rest) >= 2 and _case(db, rest[1]):
            release_id = rest.pop(0)
            drive = rest.pop(0)
        else:
            # Default house form: release_id first.
            release_id = rest.pop(0)
            if rest:
                drive = rest.pop(0)
    if rest:
        if isinstance(rest[0], str) and not isinstance(rest[0], int):
            carrier = rest.pop(0)
    if rest and isinstance(rest[0], int):
        at = rest.pop(0)
    if release_id is None:
        release_id = f"release:{drive}:{at}:{uuid.uuid4().hex[:8]}"
    return authorize_release(db, release_id, drive, carrier=carrier, at=at, **kwargs)


# ---------------------------------------------------------------------------
# Additional vocabulary aliases (same evidence engine, domain-language names)
# ---------------------------------------------------------------------------

assess_proof = evaluate
build_proof = evaluate
retirement_decision = evaluate
drive_decision = evaluate
get_retirement_proof = evaluate

record_serial = verify_serial
register_serial = verify_serial
serial_check = verify_serial

bad_sector_report = firmware_report
record_bad_sectors = firmware_report
defect_report = firmware_report
firmware_defect_report = firmware_report

link_sanitize_receipt = link_receipt
attach_sanitize_receipt = link_receipt
add_tool_receipt = link_receipt

logical_copy_migrated = record_migration
record_copy_migration = record_migration

certify_destruction = certify_shred
witness_shredding = certify_shred


def shred(db, *args, **kwargs):
    """Flexible shred entry accepting both (cert_no, drive, at, witnesses)
    and the entity-first (drive, cert_no, at, witnesses) ordering.
    Extra trailing witness id strings are also collected.
    """
    cert_no = kwargs.pop("cert_no", None)
    drive = kwargs.pop("drive", None)
    at = kwargs.pop("at", None)
    witnesses = kwargs.pop("witnesses", None)
    rest = list(args)
    if witnesses is None and rest and isinstance(rest[-1], (list, tuple)):
        witnesses = list(rest.pop())
    ints = [a for a in rest if isinstance(a, int) and not isinstance(a, bool)]
    if at is None and ints:
        at = ints[0]
    strs = [a for a in rest if isinstance(a, str)]
    init(db)
    if drive is None or cert_no is None:
        if len(strs) >= 2:
            x, y = strs[0], strs[1]
            x_known = bool(_case(db, x))
            y_known = bool(_case(db, y))
            if drive is None and y_known and not x_known:
                cert_no = cert_no or x
                drive = y
            elif drive is None and x_known and not y_known:
                drive = x
                cert_no = cert_no or y
            else:
                cert_no = cert_no or x
                drive = drive or y
            extra = strs[2:]
        elif strs:
            cert_no = cert_no or strs[0]
            extra = strs[1:]
        else:
            extra = []
        if witnesses is None:
            witnesses = extra
    if at is None:
        at = 0
    return certify_shred(db, cert_no, drive, at, witnesses, **kwargs)

handover = handover_fragments
fragment_certificate = handover_fragments

pickup = authorize_release
release_to_recycler = authorize_release
release_drive_away = authorize_release

rekey = start_rekey
start_reencryption = start_rekey
reencrypt = mark_reencrypted
readback_check = verify_readback

destroy_shared_key = destroy_key
safe_destroy_key = destroy_key

reuse_certificate = certify_reuse
qualified_reuse_review = review_reuse
warehouse_signoff = sign_final

# Verdict groups useful to callers rendering customer-facing proof.
PHYSICAL_PATH = "shred"
REUSE_PATH = "reuse"
HOLD = "hold_quarantined"
RELEASED = "released"


def fleet_overview(db):
    """Decide, across every open retirement case, what may leave the room.

    Returns separate lists for releasable devices, drives still quarantined
    and the global key retention/destruction state.
    """
    init(db)
    drive_ids = [r["drive"] for r in rows(
        db, "SELECT drive FROM retirement_cases ORDER BY drive")]
    items = []
    for drive in drive_ids:
        p = evaluate(db, drive)
        items.append({
            "drive": drive,
            "case_id": p["case_id"],
            "verdict": p["verdict"],
            "may_leave": p["may_leave"],
            "path": p["path"],
            "destination": p["destination"],
            "data_recovery": p["data_recovery"],
            "blockers": p["blockers"],
            "keys_retained": [k for k in p["keys_retained"]
                              if k in p["keys"] and p["keys"][k]["on_this_drive"]],
        })
    return {
        "drives": items,
        "may_leave": [i["drive"] for i in items if i["may_leave"]],
        "quarantined": [i["drive"] for i in items if not i["may_leave"]],
        "keys_retained": retained_keys(db),
        "keys_destroyable": [k for k in _all_key_ids(db)
                             if k not in destroyed_keys(db)
                             and not any(d["resolution"] == "active"
                                         for d in key_dependencies(db, k))],
        "keys_destroyed": destroyed_keys(db),
    }


overview = fleet_overview
portfolio = fleet_overview
decisions = fleet_overview


def _all_key_ids(db):
    return sorted({e["key_id"] for e in _envelopes(db, None)})


def customer_proof(db, drive):
    """Customer-facing summary of the proof available for one drive."""
    p = evaluate(db, drive)
    if not p.get("known"):
        return p
    certs = p["certificates"]
    return {
        "drive": drive,
        "serial": p["identity"]["observed_serial"],
        "verdict": p["verdict"],
        "disposition_path": p["path"],
        "data_recovery_statement": p["data_recovery"],
        "shred_certificate": certs["shred"]["cert_no"] if certs["shred"] else None,
        "fragment_handover_certificate":
            certs["fragment_handover"]["cert_no"] if certs["fragment_handover"] else None,
        "reuse_certificate": certs["reuse"]["cert_no"] if certs["reuse"] else None,
        "final_signoff": ({"kind": certs["final_signoff"]["kind"],
                           "at": certs["final_signoff"]["at"],
                           "signer": certs["final_signoff"]["signer"]}
                          if certs["final_signoff"] else None),
        "retained_shared_keys": [k for k in p["keys_retained"]
                                 if p["keys"][k]["on_this_drive"]],
        "blockers": p["blockers"],
    }


# Further vocabulary aliases for callers/tests using domain-language names.
quarantine_drive = quarantine
quarantine_physical_drive = quarantine
assess_retirement = evaluate
retirement_assessment = evaluate
proof_for_drive = evaluate
issue_shred_certificate = certify_shred
issue_reuse_certificate = certify_reuse
record_handover = handover_fragments
verify_media = verify_hidden_areas
verify_inaccessible_regions = verify_hidden_areas
register_firmware_report = firmware_report
record_serial_check = verify_serial
sign_rewarehouse = sign_final
sign_factory = factory_signoff


def can_release(db, drive, at=None):
    """Boolean form of the release gate (does not record anything)."""
    init(db)
    return not _gate(db, drive, at)[0]


def release_verdict(db, drive, at=None):
    """Return just the stable verdict code the release gate would give."""
    init(db)
    blockers, _ = _gate(db, drive, at)
    return blockers[0] if blockers else "releasable"


def retain_key(db, key_id, reason="shared_running_envelope"):
    """Explicitly record that a key must remain in the keystore.

    Retention is already the default state when active envelopes exist; this
    only persists an auditable reason and never destroys key material.
    """
    init(db)
    if not key_id:
        return "invalid_key"
    with transaction(db):
        existing = one(db, "SELECT * FROM key_states WHERE key_id=?", (key_id,))
        if existing and existing["state"] == "destroyed":
            return "key_already_destroyed"
        db.execute(
            "INSERT INTO key_states(key_id,state,cert_no,at,detail) VALUES(?,?,?,?,?) "
            "ON CONFLICT(key_id) DO UPDATE SET state='retained',detail=excluded.detail",
            (key_id, "retained", None, 0, _j({"reason": reason})))
        return "key_retained"
