"""Coolant imbalance investigation, interception and regulatory discharge filing.

This module is the physical-conservation and custody layer on top of the
immutable source records:

* ``cloudquota.water_meter``  -- intake / return / drain meter samples
* ``cloudquota.valve_log``    -- actuator receipts (never flow evidence)
* ``cloudquota.site_hazard``  -- chemical samples near floor drains

The rules encoded here are the ones the incident narrative depends on:

* readings carry physical location, calibration validity and a measurement
  window; when a reading arrived is stored separately and never used as the
  physical order of water movement;
* a per-loop meter gap (intake - returned - drained) is an *investigation
  quantity*, not an environmental discharge figure;
* a "closed" valve receipt does not zero flow and a stuck valve must be
  inspected physically before isolation is accepted;
* shared sump volume is attributed to loops only as feasible intervals unless
  independent tracer evidence identifies the source; contaminated tracer
  evidence leaves the intervals open;
* concentration x flow is only a legal discharge mass when the sample and
  flow windows and the outlet location are aligned and the sample passes the
  permit limit;
* every intercepted unit has a custody destination (sump, marked tank,
  licensed disposer receipt, permitted outlet discharge, treatment residue or
  still unexplained);
* regulator reports are append-only versions: late meter data produces a
  correction/supplement, never an in-place rewrite of a served report.

The module only depends on the standard library and :mod:`cloudquota.store`.
"""
from __future__ import annotations

import hashlib
import json

from .store import one, rows, transaction

# ---------------------------------------------------------------------------
# Constants / vocabularies
# ---------------------------------------------------------------------------

WINDOW_MINUTES = 1

# Ledger buckets.  Bucket totals always sum to the recognised meter gap.
UNEXPLAINED = "unexplained"
RECOVERED = "recovered"                 # returned to a reusable buffer tank
INTERCEPTED = "intercepted_on_site"     # sealed sump / marked / residue tanks
DISCHARGED = "discharged_permitted"     # compliant permitted outlet
OFFSITE_DISPOSED = "offsite_disposed"   # accepted by licensed disposer

BUCKETS = (UNEXPLAINED, RECOVERED, INTERCEPTED, DISCHARGED, OFFSITE_DISPOSED)

CONTAINMENT = "containment"
BYPASS = "bypass_treatment"
_STRATEGY_ALIASES = {
    "contain": CONTAINMENT,
    "containment": CONTAINMENT,
    "seal": CONTAINMENT,
    "seal_sump": CONTAINMENT,
    "sealed_containment": CONTAINMENT,
    "bypass": BYPASS,
    "bypass_treatment": BYPASS,
    "treatment": BYPASS,
    "online_treatment": BYPASS,
}

TRACER_IDENTIFIED = "identified"
TRACER_INCONCLUSIVE = "inconclusive"
TRACER_CONTAMINATED = "contaminated"

# ---------------------------------------------------------------------------
# Small pure helpers (usable without a database)
# ---------------------------------------------------------------------------


def n(value):
    """Normalise integral floats (3.0) to int (3) for readable reports."""
    if value is None:
        return 0
    try:
        f = float(value)
    except (TypeError, ValueError):
        return value
    if abs(f - round(f)) < 1e-9:
        return int(round(f))
    return round(f, 6)


def minute_window(minute, width=WINDOW_MINUTES):
    """The conventional full-minute conservation window for ``minute``."""
    if minute is None:
        return None, None
    return int(minute), int(minute) + int(width)


def windows_relation(a_start, a_end, b_start, b_end):
    """Relate two half-open windows ``[start, end)``.

    Returns one of ``exact``, ``contains`` (a contains b), ``within``
    (a is within b), ``overlap``, ``disjoint`` or ``unknown``.
    """
    if None in (a_start, a_end, b_start, b_end):
        return "unknown"
    a_start, a_end = float(a_start), float(a_end)
    b_start, b_end = float(b_start), float(b_end)
    if a_start == b_start and a_end == b_end:
        return "exact"
    lo = max(a_start, b_start)
    hi = min(a_end, b_end)
    if hi <= lo:
        return "disjoint"
    if a_start <= b_start and a_end >= b_end:
        return "contains"
    if b_start <= a_start and b_end >= a_end:
        return "within"
    return "overlap"


def windows_aligned(flow_start, flow_end, sample_start, sample_end):
    """Strict alignment required before concentration may scale flow."""
    return windows_relation(flow_start, flow_end, sample_start, sample_end) == "exact"


def calibration_state(calibration_expires_at, at):
    if calibration_expires_at is None or at is None:
        return "unknown"
    return "current" if float(calibration_expires_at) >= float(at) else "expired"


def minute_gap(intake, returned, drained):
    """Conventional per-loop conservation gap: intake - return - drain."""
    return n((intake or 0) - (returned or 0) - (drained or 0))


def source_intervals(sump_amount, caps):
    """Feasible source attribution for a shared sump.

    ``caps`` maps circuit id to the largest volume that circuit could have
    contributed (its measured gap).  Under the closed-world assumption that
    only the registered loops feed the sump and contributions sum to the
    sump rise, each contribution lives in an interval::

        low_i  = max(0, sump - sum(other caps))
        high_i = min(cap_i, sump)

    For the narrative numbers sump=3, caps={A:3,B:1} this yields
    A in [2, 3], B in [0, 1].  Nothing here assigns a point value.

    The open-world column (``conservative_min == 0`` for every tenant) and
    the ``unidentified_external`` interval make clear that an unregistered
    source can never be force-allocated to a tenant.
    """
    s = max(0.0, float(sump_amount or 0))
    clean = {str(k): max(0.0, float(v or 0)) for k, v in caps.items()}
    total_cap = sum(clean.values())
    loops = {}
    for circuit, cap in clean.items():
        others = total_cap - cap
        low = max(0.0, s - others)
        high = min(cap, s)
        loops[circuit] = {
            "min": n(low),
            "max": n(high),
            "conservative_min": 0,
            "point": None,
        }
    external_low = max(0.0, s - total_cap)
    return {
        "sump_amount": n(s),
        "loops": loops,
        "closed_world_feasible": total_cap + 1e-9 >= s,
        "unidentified_external": {"min": n(external_low), "max": n(s)},
        "status": "uncertain",
    }


def discharge_mass(flow_volume, concentration,
                   flow_start=None, flow_end=None,
                   sample_start=None, sample_end=None,
                   flow_location=None, sample_location=None):
    """Only turn an aligned outlet sample into a pollutant mass.

    Returns a dict.  ``status == 'aligned'`` carries ``pollutant_mass``;
    anything else explains why multiplication is forbidden.
    """
    if flow_volume is None or concentration is None:
        return {"status": "missing_values", "pollutant_mass": None}
    if None in (flow_start, flow_end, sample_start, sample_end):
        return {"status": "missing_windows", "pollutant_mass": None}
    relation = windows_relation(flow_start, flow_end, sample_start, sample_end)
    if relation != "exact":
        return {"status": "unaligned_windows", "relation": relation,
                "pollutant_mass": None}
    if flow_location is not None and sample_location is not None \
            and flow_location != sample_location:
        return {"status": "location_mismatch", "pollutant_mass": None}
    volume = float(flow_volume)
    concentration = float(concentration)
    return {
        "status": "aligned",
        "relation": "exact",
        "flow_volume": n(volume),
        "concentration": n(concentration),
        "pollutant_mass": n(volume * concentration),
    }


def _checksum(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS wi_cases(
  id TEXT PRIMARY KEY, coolant TEXT, minute INTEGER,
  window_start INTEGER, window_end INTEGER, opened_at INTEGER,
  permit_id TEXT, status TEXT, note TEXT);
CREATE TABLE IF NOT EXISTS wi_loops(
  case_id TEXT NOT NULL, circuit TEXT NOT NULL, tenant TEXT,
  coolant TEXT, PRIMARY KEY(case_id, circuit));
CREATE TABLE IF NOT EXISTS wi_provenance(
  source_kind TEXT NOT NULL, source_id TEXT NOT NULL,
  location TEXT, sensor_id TEXT, observed_at INTEGER,
  window_start INTEGER, window_end INTEGER,
  calibrated_at INTEGER, calibration_period INTEGER,
  calibration_expires_at INTEGER, signature_ok INTEGER, note TEXT,
  PRIMARY KEY(source_kind, source_id));
CREATE TABLE IF NOT EXISTS wi_assessments(
  source_kind TEXT NOT NULL, source_id TEXT NOT NULL,
  abnormal INTEGER, compliant INTEGER, threshold REAL,
  assessed_at INTEGER, note TEXT,
  PRIMARY KEY(source_kind, source_id));
CREATE TABLE IF NOT EXISTS wi_levels(
  id TEXT PRIMARY KEY, case_id TEXT, kind TEXT, circuit TEXT,
  container TEXT, location TEXT, at INTEGER, received_at INTEGER,
  level_start REAL, level_end REAL, inflow REAL,
  window_start INTEGER, window_end INTEGER,
  sensor_id TEXT, calibrated_at INTEGER, calibration_period INTEGER,
  calibration_expires_at INTEGER, signature_ok INTEGER, payload TEXT);
CREATE TABLE IF NOT EXISTS wi_valve_inspections(
  id TEXT PRIMARY KEY, case_id TEXT, circuit TEXT, valve TEXT,
  receipt_id TEXT, at INTEGER, observed_position TEXT,
  condition TEXT, verdict TEXT, note TEXT,
  location TEXT, sensor_id TEXT, window_start INTEGER, window_end INTEGER,
  calibrated_at INTEGER, calibration_period INTEGER,
  calibration_expires_at INTEGER, signature_ok INTEGER);
CREATE TABLE IF NOT EXISTS wi_isolations(
  id TEXT PRIMARY KEY, case_id TEXT, valve TEXT, at INTEGER,
  method TEXT, verified INTEGER, zero_flow_confirmed INTEGER, verdict TEXT);
CREATE TABLE IF NOT EXISTS wi_tracers(
  id TEXT PRIMARY KEY, case_id TEXT, at INTEGER, status TEXT,
  source_circuit TEXT, fractions TEXT, sample_id TEXT, lab TEXT, note TEXT);
CREATE TABLE IF NOT EXISTS wi_controls(
  id TEXT PRIMARY KEY, case_id TEXT, at INTEGER, strategy TEXT,
  permit_id TEXT, equipment_id TEXT, equipment_accepted INTEGER,
  status TEXT, note TEXT);
CREATE TABLE IF NOT EXISTS wi_outlet_events(
  id TEXT PRIMARY KEY, case_id TEXT, outlet TEXT, at INTEGER,
  state TEXT, reason TEXT);
CREATE TABLE IF NOT EXISTS wi_transfers(
  id TEXT PRIMARY KEY, case_id TEXT, at INTEGER,
  source_location TEXT, dest_location TEXT, tank_no TEXT, amount REAL, note TEXT);
CREATE TABLE IF NOT EXISTS wi_handoffs(
  id TEXT PRIMARY KEY, case_id TEXT, at INTEGER, tank_no TEXT, amount REAL,
  gross_weight REAL, tare_weight REAL, net_weight REAL,
  disposer TEXT, license_no TEXT, receipt_no TEXT,
  status TEXT, reason TEXT, decided_at INTEGER);
CREATE TABLE IF NOT EXISTS wi_runs(
  id TEXT PRIMARY KEY, case_id TEXT, at INTEGER, outlet TEXT,
  treated REAL, discharged REAL, residue REAL, residue_tank TEXT,
  concentration REAL, limit_value REAL, compliant INTEGER,
  sample_id TEXT, flow_start INTEGER, flow_end INTEGER,
  sample_start INTEGER, sample_end INTEGER, alignment TEXT,
  outlet_location TEXT, status TEXT, pollutant_mass REAL);
CREATE TABLE IF NOT EXISTS wi_ledger(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  entry_group TEXT, case_id TEXT, at INTEGER,
  bucket TEXT, location TEXT, container TEXT,
  delta REAL, reason TEXT, ref_id TEXT);
CREATE UNIQUE INDEX IF NOT EXISTS wi_ledger_ref
  ON wi_ledger(ref_id) WHERE ref_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS wi_reports(
  id TEXT PRIMARY KEY, case_id TEXT, family TEXT, version INTEGER,
  kind TEXT, text TEXT, checksum TEXT, recipient TEXT,
  created_at INTEGER, served_at INTEGER, corrects TEXT);
CREATE TABLE IF NOT EXISTS wi_idem(
  id TEXT NOT NULL, kind TEXT NOT NULL,
  payload TEXT NOT NULL, result TEXT NOT NULL,
  PRIMARY KEY(id, kind));
"""


def _ensure(db):
    # The full script only runs on first use; afterwards a cheap catalog
    # probe avoids re-parsing/re-committing the schema on every operation.
    if one(db, "SELECT name FROM sqlite_master WHERE type='table' AND name='wi_cases'"):
        return
    db.executescript(_SCHEMA)
    db.commit()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _dump(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def _idem_old(db, action_id, kind):
    return one(db, "SELECT * FROM wi_idem WHERE id=? AND kind=?",
               (action_id, kind))


def _idem_finish(db, action_id, kind, payload, result):
    db.execute("INSERT INTO wi_idem(id,kind,payload,result) VALUES(?,?,?,?)",
               (action_id, kind, _dump(payload), result))
    return result


def _idem_replay(old, payload):
    """Return stored verdict for identical replay, else conflict marker."""
    if old is None:
        return None
    if json.loads(old["payload"]) == payload:
        return old["result"]
    return "__conflict__"


def _case(db, incident_id):
    if incident_id is not None:
        return one(db, "SELECT * FROM wi_cases WHERE id=?", (incident_id,))
    cases = rows(db, "SELECT * FROM wi_cases ORDER BY opened_at,id")
    if len(cases) == 1:
        return cases[0]
    if not cases:
        return None
    raise ValueError("incident_id is required when more than one case exists")


def _case_window(case, window_start, window_end, minute=None):
    if window_start is not None and window_end is not None:
        return int(window_start), int(window_end)
    if case is not None and case["window_start"] is not None:
        return case["window_start"], case["window_end"]
    m = minute
    if m is None and case is not None and case["minute"] is not None:
        m = case["minute"]
    return minute_window(m)


def _table_exists(db, name):
    return one(db, "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
               (name,)) is not None


def _prov(db, source_kind, source_id):
    return one(db, "SELECT * FROM wi_provenance WHERE source_kind=? AND source_id=?",
               (source_kind, source_id))


def _post(db, group, case_id, at, bucket, delta, reason, ref_id,
          location=None, container=None):
    """Post one signed ledger leg.  ``ref_id`` makes it idempotent."""
    if ref_id is not None and one(db, "SELECT seq FROM wi_ledger WHERE ref_id=?",
                                  (ref_id,)):
        return False
    db.execute(
        "INSERT INTO wi_ledger(entry_group,case_id,at,bucket,location,container,"
        "delta,reason,ref_id) VALUES(?,?,?,?,?,?,?,?,?)",
        (group, case_id, at, bucket, location, container,
         float(delta), reason, ref_id))
    return True


# ---------------------------------------------------------------------------
# Case and loop registration
# ---------------------------------------------------------------------------


def open_incident(db, incident_id, coolant=None, minute=None, at=None,
                  window_start=None, window_end=None, permit_id=None,
                  loops=None, tenant=None, note=None):
    """Open a conservation investigation case.

    ``loops`` may be a list of circuit ids or ``{circuit: tenant}`` mapping.
    """
    if not incident_id:
        return "invalid_incident"
    if minute is not None and minute < 0:
        return "invalid_incident"
    _ensure(db)
    ws, we = _case_window(None, window_start, window_end, minute)
    opened_at = at if at is not None else minute
    payload = dict(coolant=coolant, minute=minute, ws=ws, we=we,
                   opened_at=opened_at, permit_id=permit_id,
                   loops=loops, tenant=tenant, note=note)
    with transaction(db):
        old = one(db, "SELECT * FROM wi_cases WHERE id=?", (incident_id,))
        idem = _idem_old(db, incident_id, "open_incident")
        if old:
            same = (old["coolant"] == coolant and old["minute"] == minute
                    and old["window_start"] == ws and old["window_end"] == we)
            return "exists" if same else "incident_conflict"
        replay = _idem_replay(idem, payload)
        if replay is not None:
            return "replayed" if replay != "__conflict__" else "action_conflict"
        db.execute(
            "INSERT INTO wi_cases VALUES(?,?,?,?,?,?,?,?,?)",
            (incident_id, coolant, minute, ws, we, opened_at,
             permit_id, "open", note))
        if loops:
            items = loops.items() if isinstance(loops, dict) else [(c, None) for c in loops]
            for circuit, loop_tenant in items:
                db.execute("INSERT OR IGNORE INTO wi_loops VALUES(?,?,?,?)",
                           (incident_id, str(circuit), loop_tenant or tenant, coolant))
        _idem_finish(db, incident_id, "open_incident", payload, "opened")
        return "opened"


# Friendly aliases.
create_incident = open_case = start_incident = open_incident


def add_loop(db, incident_id, circuit, tenant=None, coolant=None):
    if not incident_id or not circuit:
        return "invalid_loop"
    _ensure(db)
    with transaction(db):
        if not one(db, "SELECT id FROM wi_cases WHERE id=?", (incident_id,)):
            return "unknown_incident"
        db.execute("INSERT OR IGNORE INTO wi_loops VALUES(?,?,?,?)",
                   (incident_id, str(circuit), tenant, coolant))
        return "registered"


# ---------------------------------------------------------------------------
# Provenance and rich evidence intake (wraps the original modules)
# ---------------------------------------------------------------------------


def attach_provenance(db, source_kind, source_id, location=None, sensor_id=None,
                      observed_at=None, at=None, window_start=None,
                      window_end=None, calibrated_at=None, calibration_days=None,
                      calibration_period=None, calibration_expires_at=None,
                      signature_ok=True, note=None):
    """Preserve physical location, calibration period and measurement window."""
    if not source_kind or not source_id:
        return "invalid_provenance"
    if window_start is not None and window_end is not None \
            and window_end < window_start:
        return "invalid_window"
    period = calibration_period if calibration_period is not None else calibration_days
    expires = calibration_expires_at
    if expires is None and calibrated_at is not None and period is not None:
        expires = int(calibrated_at) + int(period)
    obs = observed_at if observed_at is not None else at
    _ensure(db)
    expected = (location, sensor_id, obs, window_start, window_end,
                calibrated_at, period, expires,
                None if signature_ok is None else int(bool(signature_ok)), note)
    with transaction(db):
        old = _prov(db, source_kind, source_id)
        if old:
            current = tuple(old[k] for k in (
                "location", "sensor_id", "observed_at", "window_start",
                "window_end", "calibrated_at", "calibration_period",
                "calibration_expires_at", "signature_ok", "note"))
            return "replayed" if current == expected else "provenance_conflict"
        db.execute("INSERT INTO wi_provenance VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                   (source_kind, source_id, location, sensor_id, obs,
                    window_start, window_end, calibrated_at, period, expires,
                    None if signature_ok is None else int(bool(signature_ok)), note))
        return "provenance_recorded"


prove = attach_provenance


def meter_reading(db, reading_id, circuit, at, intake, returned, drained,
                  incident_id=None, location=None, sensor_id=None,
                  window_start=None, window_end=None,
                  calibrated_at=None, calibration_period=None,
                  calibration_expires_at=None, signature_ok=True, **kw):
    """Record an original water meter sample plus its physical provenance."""
    from . import water_meter
    status = water_meter.sample(db, reading_id, circuit, at, intake, returned, drained)
    if status not in ("captured", "replayed"):
        return status
    pstatus = attach_provenance(
        db, "water_sample", reading_id, location=location, sensor_id=sensor_id,
        observed_at=at, window_start=window_start, window_end=window_end,
        calibrated_at=calibrated_at, calibration_period=calibration_period,
        calibration_expires_at=calibration_expires_at,
        signature_ok=signature_ok)
    if pstatus not in ("provenance_recorded", "replayed"):
        return pstatus
    if incident_id:
        add_loop(db, incident_id, circuit, kw.get("tenant"))
    return "captured" if status == "captured" else "replayed"


def register_valve_receipt(db, receipt_id, circuit, valve, command, at, position,
                           location=None, sensor_id=None, window_start=None,
                           window_end=None, calibrated_at=None,
                           calibration_period=None, calibration_expires_at=None,
                           signature_ok=True):
    """Store an actuator receipt in the original table plus provenance."""
    from . import valve_log
    status = valve_log.receipt(db, receipt_id, circuit, valve, command, at, position)
    if status not in ("captured", "replayed"):
        return status
    pstatus = attach_provenance(
        db, "valve_receipt", receipt_id, location=location or valve,
        sensor_id=sensor_id, observed_at=at,
        window_start=window_start if window_start is not None else at,
        window_end=window_end if window_end is not None else (
            None if window_start is None and window_end is None else at + WINDOW_MINUTES),
        calibrated_at=calibrated_at, calibration_period=calibration_period,
        calibration_expires_at=calibration_expires_at,
        signature_ok=signature_ok)
    if pstatus not in ("provenance_recorded", "replayed"):
        return pstatus
    return "captured" if status == "captured" else "replayed"


def hazard_reading(db, sample_id, zone, sensor, at, kind, level,
                   abnormal=None, threshold=None, compliant=None,
                   incident_id=None, location=None, window_start=None,
                   window_end=None, calibrated_at=None,
                   calibration_period=None, calibration_expires_at=None,
                   signature_ok=True, note=None):
    """Record an original hazard/chemistry sample plus assessment/provenance."""
    from . import site_hazard
    status = site_hazard.sample(db, sample_id, zone, sensor, at, kind, level)
    if status not in ("captured", "replayed"):
        return status
    pstatus = attach_provenance(
        db, "hazard_sample", sample_id, location=location or zone,
        sensor_id=sensor, observed_at=at, window_start=window_start,
        window_end=window_end, calibrated_at=calibrated_at,
        calibration_period=calibration_period,
        calibration_expires_at=calibration_expires_at,
        signature_ok=signature_ok, note=note)
    if pstatus not in ("provenance_recorded", "replayed"):
        return pstatus
    if abnormal is None and threshold is not None:
        abnormal = level > threshold if threshold >= 0 else level < threshold
    if compliant is None and abnormal is not None:
        compliant = not abnormal
    if abnormal is not None:
        assess_sample(db, "hazard_sample", sample_id,
                      abnormal=abnormal, compliant=compliant,
                      threshold=threshold, assessed_at=at, note=note)
    return "captured" if status == "captured" else "replayed"


def assess_sample(db, source_kind, source_id, abnormal=None, compliant=None,
                  threshold=None, assessed_at=None, note=None):
    _ensure(db)
    with transaction(db):
        old = one(db, "SELECT * FROM wi_assessments WHERE source_kind=? AND source_id=?",
                  (source_kind, source_id))
        if old:
            return "replayed"
        db.execute("INSERT INTO wi_assessments VALUES(?,?,?,?,?,?,?)",
                   (source_kind, source_id,
                   None if abnormal is None else int(bool(abnormal)),
                   None if compliant is None else int(bool(compliant)),
                   threshold, assessed_at, note))
        return "assessed"


# ---------------------------------------------------------------------------
# Tank / sump level readings (late arrival is explicit)
# ---------------------------------------------------------------------------


def level_reading(db, reading_id, incident_id, container, at,
                  inflow=None, level_start=None, level_end=None,
                  kind="tank", circuit=None, location=None, received_at=None,
                  window_start=None, window_end=None, sensor_id=None,
                  calibrated_at=None, calibration_period=None,
                  calibration_days=None, calibration_expires_at=None,
                  signature_ok=True, **kw):
    """A tank/sump level reading.

    ``at`` / window describe when the physical change happened;
    ``received_at`` is when the reading arrived.  Analysis keys on the
    physical window and never on arrival order.  Calibration period and
    physical location are retained alongside the measurement window.
    """
    if not reading_id or not incident_id or at is None:
        return "invalid_reading"
    if inflow is None:
        if level_start is None or level_end is None:
            return "invalid_reading"
        inflow = level_end - level_start
    if inflow < 0:
        return "invalid_reading"
    ws = window_start if window_start is not None else at
    we = window_end if window_end is not None else at + WINDOW_MINUTES
    period = calibration_period if calibration_period is not None else calibration_days
    expires = calibration_expires_at
    if expires is None and calibrated_at is not None and period is not None:
        expires = int(calibrated_at) + int(period)
    sig = None if signature_ok is None else int(bool(signature_ok))
    _ensure(db)
    payload = dict(incident_id=incident_id, container=container, at=at,
                   inflow=inflow, level_start=level_start, level_end=level_end,
                   kind=kind, circuit=circuit, location=location,
                   received_at=received_at, ws=ws, we=we,
                   sensor_id=sensor_id, calibrated_at=calibrated_at,
                   calibration_period=period, expires=expires, signature_ok=sig)
    with transaction(db):
        idem = _idem_old(db, reading_id, "level_reading")
        replay = _idem_replay(idem, payload)
        if replay is not None:
            return replay if replay != "__conflict__" else "reading_conflict"
        db.execute("INSERT INTO wi_levels VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (reading_id, incident_id, kind, circuit, container,
                    location, at, received_at if received_at is not None else at,
                    level_start, level_end, float(inflow), ws, we,
                    sensor_id, calibrated_at, period, expires, sig, None))
        _idem_finish(db, reading_id, "level_reading", payload, "captured")
        return "captured"


def sump_reading(db, reading_id, incident_id, at, increase,
                 container="SHARED-SUMP", location="shared_sump", **kw):
    return level_reading(db, reading_id, incident_id, container, at,
                         inflow=increase, kind="sump", location=location, **kw)


def recovery_tank_reading(db, reading_id, incident_id, at, inflow,
                          container="BUFFER-TANK", location="recovery_buffer",
                          circuit=None, **kw):
    return level_reading(db, reading_id, incident_id, container, at,
                         inflow=inflow, kind="recovery_tank",
                         location=location, circuit=circuit, **kw)


tank_reading = level_reading


# ---------------------------------------------------------------------------
# Valve inspections and physical isolation
# ---------------------------------------------------------------------------


def inspect_valve(db, inspection_id, incident_id, valve, at,
                  observed_position=None, condition=None, circuit=None,
                  receipt_id=None, note=None, location=None, sensor_id=None,
                  window_start=None, window_end=None, calibrated_at=None,
                  calibration_period=None, calibration_days=None,
                  calibration_expires_at=None, signature_ok=True):
    """Record a physical inspection; detect a valve stuck against its receipt.

    Valve-position evidence retains its physical location, calibration and
    observation window just like flow/level/sample evidence.
    """
    if not inspection_id or not valve or at is None:
        return "invalid_inspection"
    if observed_position not in (None, "open", "closed", "unknown"):
        return "invalid_position"
    period = calibration_period if calibration_period is not None else calibration_days
    expires = calibration_expires_at
    if expires is None and calibrated_at is not None and period is not None:
        expires = int(calibrated_at) + int(period)
    ws = window_start if window_start is not None else at
    we = window_end if window_end is not None else ws + WINDOW_MINUTES
    sig = None if signature_ok is None else int(bool(signature_ok))
    _ensure(db)
    verdict = "inspection_recorded"
    if condition in ("stuck", "stuck_open", "stuck_closed"):
        verdict = condition
    elif observed_position == "open":
        closed_receipt = None
        if _table_exists(db, "valve_receipts"):
            sql = "SELECT * FROM valve_receipts WHERE valve=? AND position='closed'"
            args = [valve]
            if receipt_id:
                sql += " AND id=?"
                args.append(receipt_id)
            else:
                sql += " ORDER BY at DESC LIMIT 1"
            closed_receipt = one(db, sql, tuple(args)) if receipt_id else one(db, sql, (valve,))
        if closed_receipt or condition == "stuck_open":
            verdict = "stuck_open"
    elif observed_position == "closed":
        verdict = "verified_closed"
    payload = dict(incident_id=incident_id, valve=valve, at=at,
                   observed_position=observed_position, condition=condition,
                   circuit=circuit, receipt_id=receipt_id, note=note,
                   location=location, sensor_id=sensor_id, ws=ws, we=we,
                   calibrated_at=calibrated_at, period=period,
                   expires=expires, signature_ok=sig)
    with transaction(db):
        idem = _idem_old(db, inspection_id, "inspect_valve")
        replay = _idem_replay(idem, payload)
        if replay is not None:
            return replay if replay != "__conflict__" else "inspection_conflict"
        db.execute(
            "INSERT INTO wi_valve_inspections(id,case_id,circuit,valve,"
            "receipt_id,at,observed_position,condition,verdict,note,"
            "location,sensor_id,window_start,window_end,calibrated_at,"
            "calibration_period,calibration_expires_at,signature_ok) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (inspection_id, incident_id, circuit, valve, receipt_id, at,
             observed_position, condition, verdict, note,
             location, sensor_id, ws, we, calibrated_at, period, expires, sig))
        _idem_finish(db, inspection_id, "inspect_valve", payload, verdict)
        return verdict


valve_inspection = inspect_valve


def isolate_valve(db, isolation_id, incident_id, valve, at,
                  method="close_command", verified=False,
                  zero_flow_confirmed=False):
    """Accept a physical isolation.

    A close command / "closed" receipt alone is never accepted
    (``receipt_not_isolation``).  Known stuck valves are refused until a
    positive physical method (blind flange / double block-and-bleed) is
    verified.
    """
    if not isolation_id or not valve:
        return "invalid_isolation"
    _ensure(db)
    with transaction(db):
        idem = _idem_old(db, isolation_id, "isolate_valve")
        payload = dict(incident_id=incident_id, valve=valve, at=at,
                       method=method, verified=bool(verified),
                       zero=bool(zero_flow_confirmed))
        replay = _idem_replay(idem, payload)
        if replay is not None:
            return replay if replay != "__conflict__" else "isolation_conflict"
        stuck = one(db,
                    "SELECT verdict FROM wi_valve_inspections WHERE valve=? "
                    "AND verdict IN ('stuck_open','stuck_closed') "
                    "ORDER BY at DESC LIMIT 1", (valve,))
        latest = one(db,
                     "SELECT verdict,observed_position FROM wi_valve_inspections "
                     "WHERE valve=? ORDER BY at DESC LIMIT 1", (valve,))
        physical_methods = {"blind_flange", "double_block_bleed", "pipe_disconnect"}
        if stuck and method not in physical_methods:
            verdict = "valve_stuck_requires_positive_isolation"
        elif method == "close_command" and not (
                latest and latest["verdict"] == "verified_closed" and verified):
            verdict = "receipt_not_isolation"
        elif method in physical_methods and not verified:
            verdict = "physical_isolation_needs_verification"
        else:
            verdict = "isolated"
        db.execute("INSERT INTO wi_isolations VALUES(?,?,?,?,?,?,?,?)",
                   (isolation_id, incident_id, valve, at, method,
                    int(bool(verified)), int(bool(zero_flow_confirmed)), verdict))
        _idem_finish(db, isolation_id, "isolate_valve", payload, verdict)
        return verdict


confirm_isolation = isolate_valve


# ---------------------------------------------------------------------------
# Tracer source identification
# ---------------------------------------------------------------------------


def tracer_result(db, tracer_id, incident_id, at, status=None,
                  source_circuit=None, fractions=None, sample_id=None,
                  lab=None, contaminated=False, inconclusive=False, note=None):
    """Record independent tracer identification.

    ``fractions`` maps circuit id to identified volume/share.  Contaminated
    or inconclusive tracer results never collapse the feasible intervals.
    """
    if not tracer_id or not incident_id:
        return "invalid_tracer"
    if contaminated:
        status = TRACER_CONTAMINATED
    elif inconclusive or status in (None, "inconclusive", "unknown"):
        status = TRACER_INCONCLUSIVE if status != TRACER_IDENTIFIED else TRACER_IDENTIFIED
    if source_circuit or fractions:
        status = TRACER_IDENTIFIED
    if status not in (TRACER_IDENTIFIED, TRACER_INCONCLUSIVE, TRACER_CONTAMINATED):
        return "invalid_tracer_status"
    if status == TRACER_IDENTIFIED and not source_circuit and not fractions:
        return "identified_without_source"
    frac_json = _dump(fractions) if fractions is not None else None
    payload = dict(incident_id=incident_id, at=at, status=status,
                   source_circuit=source_circuit, fractions=fractions,
                   sample_id=sample_id, lab=lab, note=note)
    _ensure(db)
    with transaction(db):
        idem = _idem_old(db, tracer_id, "tracer_result")
        replay = _idem_replay(idem, payload)
        if replay is not None:
            return replay if replay != "__conflict__" else "tracer_conflict"
        db.execute("INSERT INTO wi_tracers VALUES(?,?,?,?,?,?,?,?,?)",
                   (tracer_id, incident_id, at, status, source_circuit,
                    frac_json, sample_id, lab, note))
        result = {"identified": "source_identified",
                  "inconclusive": "tracer_inconclusive",
                  "contaminated": "tracer_contaminated"}[status]
        _idem_finish(db, tracer_id, "tracer_result", payload, result)
        return result


record_tracer = tracer_result


# ---------------------------------------------------------------------------
# Investigation / conservation analysis (read-only)
# ---------------------------------------------------------------------------


def _meter_rows(db):
    if not _table_exists(db, "water_samples"):
        return []
    return rows(db, "SELECT * FROM water_samples ORDER BY circuit,id")


def _valve_rows(db):
    if not _table_exists(db, "valve_receipts"):
        return []
    return rows(db, "SELECT * FROM valve_receipts ORDER BY circuit,id")


def _hazard_rows(db):
    if not _table_exists(db, "hazard_samples"):
        return []
    return rows(db, "SELECT * FROM hazard_samples ORDER BY zone,id")


def investigate(db, incident_id=None, minute=None, window_start=None,
                window_end=None):
    """Compute per-loop gaps, shared-sump attribution and evidence warnings.

    Works both for a registered case and directly over the original tables
    filtered by ``minute``.  Never mutates state and never infers that a
    meter gap is an environmental discharge.
    """
    _ensure(db)
    case = _case(db, incident_id)
    cid = case["id"] if case else incident_id
    ws, we = _case_window(case, window_start, window_end, minute)

    registered = rows(db, "SELECT circuit FROM wi_loops WHERE case_id=?",
                      (cid,)) if cid else []
    loop_filter = {r["circuit"] for r in registered} if registered else None

    warnings = []
    circuits = []
    gaps = {}
    signatures = []
    provenance_complete = True

    for m in _meter_rows(db):
        if loop_filter is not None and m["circuit"] not in loop_filter:
            continue
        prov = _prov(db, "water_sample", m["id"])
        e_ws = prov["window_start"] if prov and prov["window_start"] is not None else m["at"]
        e_we = prov["window_end"] if prov and prov["window_end"] is not None else (
            m["at"] + WINDOW_MINUTES if e_ws == m["at"] else None)
        relation = windows_relation(e_ws, e_we, ws, we) if ws is not None else "unknown"
        in_window = relation in ("exact", "within", "contains") or (
            ws is None and (minute is None or m["at"] == minute))
        if not in_window:
            continue
        if relation not in ("exact",):
            warnings.append(f"meter_window_not_exact:{m['id']}:{relation}")
        calib = calibration_state(prov["calibration_expires_at"] if prov else None,
                                  m["at"])
        if calib == "expired":
            warnings.append(f"meter_calibration_expired:{m['id']}")
        elif calib == "unknown":
            provenance_complete = False
        sig = prov["signature_ok"] if prov else None
        if sig is None:
            signatures.append(None)
        else:
            signatures.append(bool(sig))
        gap = minute_gap(m["intake"], m["returned"], m["drained"])
        gaps[m["circuit"]] = n(gaps.get(m["circuit"], 0) + gap)
        circuits.append({
            "sample_id": m["id"], "circuit": m["circuit"], "at": m["at"],
            "intake": n(m["intake"]), "returned": n(m["returned"]),
            "drained": n(m["drained"]), "gap": gap,
            "window_start": e_ws, "window_end": e_we,
            "window_relation": relation, "calibration": calib,
            "signature_ok": None if sig is None else bool(sig),
            "location": prov["location"] if prov else None,
        })

    total_gap = n(sum(gaps.values()))

    # Levels (sump / tanks), keyed by physical window, not arrival time.
    levels = rows(db, "SELECT * FROM wi_levels WHERE case_id=? ORDER BY id",
                  (cid,)) if cid else rows(db, "SELECT * FROM wi_levels ORDER BY id")
    sump_total = 0
    sump_locations = set()
    recovery_total = 0
    tank_entries = []
    for lv in levels:
        relation = windows_relation(lv["window_start"], lv["window_end"], ws, we) \
            if ws is not None else "exact"
        if ws is not None and relation == "disjoint":
            continue
        if relation not in ("exact", "within", "contains") and ws is not None:
            warnings.append(f"level_window_not_exact:{lv['id']}:{relation}")
        inflow = n(lv["inflow"])
        tank_entries.append({
            "reading_id": lv["id"], "kind": lv["kind"],
            "container": lv["container"], "location": lv["location"],
            "circuit": lv["circuit"], "at": lv["at"],
            "received_at": lv["received_at"], "inflow": inflow,
            "late_arrival": lv["received_at"] is not None and lv["at"] is not None
                            and lv["received_at"] > lv["at"],
            "window_relation": relation,
            "window_start": lv["window_start"], "window_end": lv["window_end"],
            "calibration_expires_at": lv["calibration_expires_at"],
            "calibration": calibration_state(lv["calibration_expires_at"], lv["at"]),
            "signature_ok": None if lv["signature_ok"] is None
                            else bool(lv["signature_ok"]),
        })
        if lv["kind"] == "sump":
            sump_total += float(lv["inflow"] or 0)
            sump_locations.add(lv["container"] or lv["location"] or "sump")
        elif lv["kind"] == "recovery_tank":
            recovery_total += float(lv["inflow"] or 0)
    sump_total = n(sump_total)
    recovery_total = n(recovery_total)

    # Valve receipts + physical inspections.
    inspections = rows(db, "SELECT * FROM wi_valve_inspections WHERE case_id=? ORDER BY at",
                       (cid,)) if cid else rows(db, "SELECT * FROM wi_valve_inspections ORDER BY at")
    stuck_valves = {r["valve"] for r in inspections if r["verdict"] in
                    ("stuck_open", "stuck_closed")}
    valve_info = []
    for v in _valve_rows(db):
        if loop_filter is not None and v["circuit"] not in loop_filter:
            continue
        v_ins = [r for r in inspections if r["valve"] == v["valve"]]
        stuck = v["valve"] in stuck_valves
        if v["position"] == "closed":
            warnings.append(f"closed_receipt_is_not_zero_flow:{v['id']}")
        if stuck:
            warnings.append(f"valve_stuck:{v['valve']}")
        valve_info.append({
            "receipt_id": v["id"], "circuit": v["circuit"], "valve": v["valve"],
            "command": v["command"], "at": v["at"], "position": v["position"],
            "stuck": stuck,
            "latest_verdict": v_ins[-1]["verdict"] if v_ins else None,
        })

    # Hazard / chemical evidence.
    hazard_evidence = []
    for h in _hazard_rows(db):
        assess = one(db,
                     "SELECT * FROM wi_assessments WHERE source_kind='hazard_sample' "
                     "AND source_id=?", (h["id"],))
        abnormal = bool(assess["abnormal"]) if assess and assess["abnormal"] is not None \
            else None
        prov = _prov(db, "hazard_sample", h["id"])
        hazard_evidence.append({
            "sample_id": h["id"], "zone": h["zone"], "sensor": h["sensor"],
            "at": h["at"], "kind": h["kind"], "level": n(h["level"]),
            "abnormal": abnormal,
            "location": prov["location"] if prov else h["zone"],
        })
        if abnormal:
            warnings.append(f"abnormal_environmental_sample_unquantified:{h['id']}")

    # Attribution: feasible intervals, optionally narrowed by valid tracer.
    attribution = source_intervals(sump_total, gaps) if sump_total else None
    tracer = one(db, "SELECT * FROM wi_tracers WHERE case_id=? ORDER BY at DESC,id DESC LIMIT 1",
                 (cid,)) if cid else None
    source_status = "no_shared_sump" if not sump_total else "uncertain"
    tracer_view = None
    if tracer:
        fracs = json.loads(tracer["fractions"]) if tracer["fractions"] else None
        tracer_view = {"id": tracer["id"], "status": tracer["status"],
                       "source_circuit": tracer["source_circuit"],
                       "fractions": fracs}
        if tracer["status"] == TRACER_IDENTIFIED and attribution:
            source_status = TRACER_IDENTIFIED
            if fracs:
                values = {k: float(v) for k, v in fracs.items()}
                total = sum(values.values())
                # Shares in [0,1] summing to ~1 are proportions; otherwise
                # the tracer result is read as identified absolute volumes.
                proportional = (total > 0 and max(values.values()) <= 1.0000001
                                and abs(total - 1.0) <= 0.01)
                for circuit in attribution["loops"]:
                    if circuit not in values:
                        continue
                    if proportional:
                        point = n(values[circuit] * float(sump_total))
                    else:
                        point = n(values[circuit])
                    attribution["loops"][circuit]["point"] = point
                    attribution["loops"][circuit]["min"] = point
                    attribution["loops"][circuit]["max"] = point
                attribution["status"] = TRACER_IDENTIFIED
            elif tracer["source_circuit"] in attribution["loops"]:
                src = tracer["source_circuit"]
                for circuit, item in attribution["loops"].items():
                    point = sump_total if circuit == src else 0
                    item["point"] = point
                    item["min"] = point
                    item["max"] = point
                attribution["status"] = TRACER_IDENTIFIED
        elif tracer["status"] == TRACER_CONTAMINATED:
            source_status = TRACER_CONTAMINATED
            if attribution:
                attribution["status"] = TRACER_CONTAMINATED
            warnings.append("tracer_contaminated_source_remains_uncertain")
        else:
            source_status = TRACER_INCONCLUSIVE

    if not signatures:
        all_signatures = None
    else:
        known = [s for s in signatures if s is not None]
        all_signatures = all(known) if known else None
    if all_signatures:
        warnings.append("valid_signatures_do_not_cure_mixing_window_or_direction_errors")

    return {
        "incident_id": cid,
        "window_start": ws,
        "window_end": we,
        "coolant": case["coolant"] if case else None,
        "circuits": circuits,
        "circuit_gaps": gaps,
        "gaps": dict(gaps),
        "total_gap": total_gap,
        "naive_leak_total": total_gap,
        "leak_equals_environmental_discharge": False,
        "sump": ({"amount": sump_total, "containers": sorted(sump_locations),
                  "attribution": attribution} if sump_total else None),
        "attribution": attribution,
        "source_status": source_status,
        "levels": tank_entries,
        "recovery_total": recovery_total,
        "valves": valve_info,
        "stuck_valves": sorted(stuck_valves),
        "hazard_samples": hazard_evidence,
        "environmental_evidence": hazard_evidence,
        "confirmed_environmental_discharge": 0,
        "all_signatures_valid": all_signatures,
        "provenance_complete": provenance_complete,
        "warnings": sorted(set(warnings)),
    }


balance = conservation_report = analyze = investigate


# ---------------------------------------------------------------------------
# Control choice, outlet state, interception transfers
# ---------------------------------------------------------------------------


def choose_control(db, control_id, incident_id, strategy, at,
                   permit_id=None, equipment_id=None, equipment_accepted=False,
                   note=None):
    """The environmental lead chooses containment or accepted bypass treatment."""
    normalized = _STRATEGY_ALIASES.get(strategy)
    if normalized is None:
        return "unknown_strategy"
    _ensure(db)
    case = _case(db, incident_id)
    effective_permit = permit_id or (case["permit_id"] if case else None)
    payload = dict(incident_id=incident_id, at=at, strategy=normalized,
                   permit_id=effective_permit, equipment_id=equipment_id,
                   equipment_accepted=bool(equipment_accepted), note=note)
    with transaction(db):
        idem = _idem_old(db, control_id, "choose_control")
        replay = _idem_replay(idem, payload)
        if replay is not None:
            return replay if replay != "__conflict__" else "control_conflict"
        if not effective_permit:
            # Denial is not final: the same request may be retried once a
            # permit is in place, so no idempotency row is consumed.
            return "permit_required"
        if normalized == BYPASS and not equipment_accepted:
            return "equipment_not_accepted"
        db.execute("INSERT INTO wi_controls VALUES(?,?,?,?,?,?,?,?,?)",
                   (control_id, incident_id, at, normalized, effective_permit,
                    equipment_id, int(bool(equipment_accepted)), "selected", note))
        _idem_finish(db, control_id, "choose_control", payload, "control_selected")
        return "control_selected"


select_control = choose_control


def _control_strategy(db, incident_id):
    row = one(db, "SELECT strategy FROM wi_controls WHERE case_id=? "
                  "AND status='selected' ORDER BY at DESC,id DESC LIMIT 1",
              (incident_id,))
    return row["strategy"] if row else None


def seal_sump(db, action_id, incident_id, at, container="SHARED-SUMP",
              location="shared_sump", note=None):
    """Seal the shared sump.  Requires the containment control decision."""
    _ensure(db)
    payload = dict(incident_id=incident_id, at=at, container=container,
                   location=location, note=note)
    with transaction(db):
        idem = _idem_old(db, action_id, "outlet_state")
        replay = _idem_replay(idem, payload)
        if replay is not None:
            return replay if replay != "__conflict__" else "seal_conflict"
        if _control_strategy(db, incident_id) != CONTAINMENT:
            return "containment_control_required"
        db.execute("INSERT INTO wi_outlet_events VALUES(?,?,?,?,?,?)",
                   (action_id + ":seal", incident_id, "sump:" + container, at,
                    "sealed", note or "sump sealed"))
        _idem_finish(db, action_id, "seal_sump", payload, "sealed")
        return "sealed"


seal = seal_sump


def _record_outlet_event(db, event_id, incident_id, outlet, at, state, reason=None):
    db.execute("INSERT INTO wi_outlet_events VALUES(?,?,?,?,?,?)",
               (event_id, incident_id, outlet, at, state, reason))


def set_outlet_state(db, action_id, incident_id, outlet, at, state, reason=None):
    if state not in ("open", "closed", "disabled", "failed", "diverted"):
        return "invalid_outlet_state"
    _ensure(db)
    with transaction(db):
        idem = _idem_old(db, action_id, "seal_sump")
        payload = dict(incident_id=incident_id, outlet=outlet, at=at,
                       state=state, reason=reason)
        replay = _idem_replay(idem, payload)
        if replay is not None:
            return replay if replay != "__conflict__" else "outlet_conflict"
        _record_outlet_event(db, action_id, incident_id, outlet, at, state, reason)
        _idem_finish(db, action_id, "outlet_state", payload, state)
        return state


def disable_outlet(db, action_id, incident_id, outlet, at, reason=None):
    return set_outlet_state(db, action_id, incident_id, outlet, at,
                            "disabled", reason or "outlet disabled pending source ID")


close_outlet = disable_outlet


def pump_to_tank(db, transfer_id, incident_id, tank_no, amount, at,
                 source_location="shared_sump", dest_location=None, note=None):
    """Move intercepted liquid from sump into a marked tank (custody move)."""
    if not transfer_id or not tank_no or not amount or amount <= 0:
        return "invalid_transfer"
    _ensure(db)
    dest = dest_location or f"tank:{tank_no}"
    payload = dict(incident_id=incident_id, tank_no=tank_no, amount=amount, at=at,
                   source=source_location, dest=dest, note=note)
    with transaction(db):
        idem = _idem_old(db, transfer_id, "pump_to_tank")
        replay = _idem_replay(idem, payload)
        if replay is not None:
            return replay if replay != "__conflict__" else "transfer_conflict"
        if _control_strategy(db, incident_id) != CONTAINMENT:
            return "containment_control_required"
        sealed = one(db, "SELECT id FROM wi_outlet_events WHERE case_id=? AND state='sealed'",
                     (incident_id,))
        if not sealed:
            return "sump_not_sealed"
        db.execute("INSERT INTO wi_transfers VALUES(?,?,?,?,?,?,?,?)",
                   (transfer_id, incident_id, at, source_location, dest,
                    tank_no, float(amount), note))
        _post(db, transfer_id + ":out", incident_id, at, INTERCEPTED,
              -float(amount), "pump_to_marked_tank", "pump:" + transfer_id + ":out",
              location=source_location)
        _post(db, transfer_id + ":in", incident_id, at, INTERCEPTED,
              float(amount), "marked_tank", "pump:" + transfer_id + ":in",
              location=dest, container=tank_no)
        _idem_finish(db, transfer_id, "pump_to_tank", payload, "transferred")
        return "transferred"


transfer_to_tank = pump_to_tank


# ---------------------------------------------------------------------------
# Licensed disposer handoff: tank number + weighing + receipt required
# ---------------------------------------------------------------------------

_HANDOFF_FIELDS = ("tank_no", "disposer", "license_no", "receipt_no")


def create_handoff(db, handoff_id, incident_id, tank_no, at,
                  disposer=None, license_no=None, receipt_no=None,
                  amount=None, gross_weight=None, tare_weight=None,
                  net_weight=None, accepted=None, reason=None):
    """Record a disposer handoff attempt.

    One-shot usage passes ``accepted=True/False``.  Otherwise a pending
    handoff is created and :func:`accept_handoff` / :func:`reject_handoff`
    decide it later.  Accepted handoffs require tank number, licensed
    disposer, receipt number and a net weighing; rejected handoffs never
    remove volume from on-site custody.
    """
    if not handoff_id or not tank_no:
        return "invalid_handoff"
    if net_weight is None and gross_weight is not None and tare_weight is not None:
        net_weight = n(float(gross_weight) - float(tare_weight))
    payload = dict(incident_id=incident_id, tank_no=tank_no, at=at,
                   disposer=disposer, license_no=license_no,
                   receipt_no=receipt_no, amount=amount,
                   gross_weight=gross_weight, tare_weight=tare_weight,
                   net_weight=net_weight, accepted=accepted, reason=reason)
    _ensure(db)
    with transaction(db):
        idem = _idem_old(db, handoff_id, "handoff")
        replay = _idem_replay(idem, payload)
        if replay is not None:
            return replay if replay != "__conflict__" else "handoff_conflict"
        old = one(db, "SELECT * FROM wi_handoffs WHERE id=?", (handoff_id,))
        if old:
            return "handoff_exists"
        if accepted is False:
            if not reason:
                return "rejection_requires_reason"
            db.execute("INSERT INTO wi_handoffs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (handoff_id, incident_id, at, tank_no, amount,
                        gross_weight, tare_weight, net_weight, disposer,
                        license_no, receipt_no, "rejected", reason, at))
            return _idem_finish(db, handoff_id, "handoff", payload, "rejected")
        if accepted is True:
            err = _accepted_handoff_error(
                tank_no, disposer, license_no, receipt_no, amount, net_weight)
            if err:
                # Missing weighing/receipt: nothing is finalised and the same
                # handoff id may be retried once the paperwork exists.
                return err
            net = float(net_weight)
            handed_amount = float(amount) if amount is not None else net
            db.execute("INSERT INTO wi_handoffs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (handoff_id, incident_id, at, tank_no, handed_amount,
                        gross_weight, tare_weight, net, disposer, license_no,
                        receipt_no, "accepted", reason, at))
            _post_accepted_handoff(db, handoff_id, incident_id, at, tank_no, net,
                                   disposer)
            return _idem_finish(db, handoff_id, "handoff", payload,
                                "handoff_accepted")
        # Pending record.
        db.execute("INSERT INTO wi_handoffs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (handoff_id, incident_id, at, tank_no, amount,
                    gross_weight, tare_weight, net_weight, disposer,
                    license_no, receipt_no, "pending", reason, None))
        return _idem_finish(db, handoff_id, "handoff", payload, "pending")


disposer_handoff = handoff_to_disposer = transfer_to_disposer = create_handoff


def _accepted_handoff_error(tank_no, disposer, license_no, receipt_no,
                            amount, net_weight):
    missing = [name for name, val in (
        ("tank_no", tank_no), ("disposer", disposer),
        ("license_no", license_no), ("receipt_no", receipt_no)) if not val]
    if missing:
        return "incomplete_handoff:" + ",".join(missing)
    if net_weight is None or float(net_weight) <= 0:
        return "weighing_required"
    if amount is not None and abs(float(amount) - float(net_weight)) > 1e-6:
        return "weight_mismatch"
    return None


def _post_accepted_handoff(db, handoff_id, incident_id, at, tank_no, net, disposer):
    _post(db, handoff_id + ":out", incident_id, at, INTERCEPTED, -float(net),
          "licensed_disposer_handoff", "handoff:" + handoff_id + ":out",
          location=f"tank:{tank_no}", container=tank_no)
    _post(db, handoff_id + ":offsite", incident_id, at, OFFSITE_DISPOSED,
          float(net), "disposer_receipted", "handoff:" + handoff_id + ":offsite",
          location=disposer)


def accept_handoff(db, handoff_id, receipt_no=None, at=None,
                   gross_weight=None, tare_weight=None, net_weight=None,
                   amount=None):
    _ensure(db)
    with transaction(db):
        h = one(db, "SELECT * FROM wi_handoffs WHERE id=?", (handoff_id,))
        if not h:
            return "unknown_handoff"
        if h["status"] == "accepted":
            return "handoff_accepted"
        if h["status"] == "rejected":
            return "handoff_rejected_cannot_accept"
        receipt_no = receipt_no or h["receipt_no"]
        disposer = h["disposer"]
        license_no = h["license_no"]
        tank_no = h["tank_no"]
        net = net_weight if net_weight is not None else h["net_weight"]
        if net is None and gross_weight is not None and tare_weight is not None:
            net = n(float(gross_weight) - float(tare_weight))
        handed_amount = amount if amount is not None else h["amount"]
        err = _accepted_handoff_error(
            tank_no, disposer, license_no, receipt_no, handed_amount, net)
        if err:
            return err
        net = float(net)
        used_at = at or h["at"]
        # Update the single handoff row; post custody legs exactly once.
        db.execute("UPDATE wi_handoffs SET status='accepted',receipt_no=?,"
                   "net_weight=?,gross_weight=COALESCE(?,gross_weight),"
                   "tare_weight=COALESCE(?,tare_weight),amount=?,"
                   "decided_at=? WHERE id=?",
                   (receipt_no, net, gross_weight, tare_weight,
                    float(handed_amount) if handed_amount is not None else net,
                    used_at, handoff_id))
        _post_accepted_handoff(db, handoff_id, h["case_id"], used_at,
                               tank_no, net, disposer)
        return "handoff_accepted"


def reject_handoff(db, handoff_id, at=None, reason=None):
    _ensure(db)
    with transaction(db):
        h = one(db, "SELECT * FROM wi_handoffs WHERE id=?", (handoff_id,))
        if not h:
            return "unknown_handoff"
        if h["status"] == "rejected":
            return "rejected"
        if h["status"] == "accepted":
            return "already_accepted"
        if not reason:
            return "rejection_requires_reason"
        db.execute("UPDATE wi_handoffs SET status='rejected',reason=?,decided_at=? "
                   "WHERE id=?", (reason, at or h["at"], handoff_id))
        return "rejected"


disposer_reject = reject_handoff


# ---------------------------------------------------------------------------
# Bypass / online treatment and compliant outlet discharge
# ---------------------------------------------------------------------------


def enable_bypass(db, bypass_id, incident_id, at, equipment_id=None,
                  equipment_accepted=False, permit_id=None):
    """Enable accepted closed-loop bypass / online treatment equipment."""
    _ensure(db)
    payload = dict(incident_id=incident_id, at=at, equipment_id=equipment_id,
                   equipment_accepted=bool(equipment_accepted), permit_id=permit_id)
    with transaction(db):
        idem = _idem_old(db, bypass_id, "enable_bypass")
        replay = _idem_replay(idem, payload)
        if replay is not None:
            return replay if replay != "__conflict__" else "bypass_conflict"
        existing = one(db, "SELECT * FROM wi_controls WHERE case_id=? AND strategy=? "
                           "AND status='selected' ORDER BY at DESC,id DESC LIMIT 1",
                       (incident_id, BYPASS))
        if not existing:
            case = _case(db, incident_id)
            effective_permit = permit_id or (case["permit_id"] if case else None)
            if not effective_permit:
                return "permit_required"
            if not equipment_accepted:
                return "equipment_not_accepted"
            db.execute("INSERT INTO wi_controls VALUES(?,?,?,?,?,?,?,?,?)",
                       (bypass_id + ":control", incident_id, at, BYPASS,
                        effective_permit, equipment_id,
                        int(bool(equipment_accepted)), "selected",
                        "bypass enabled"))
        elif not existing["equipment_accepted"] and not equipment_accepted:
            return "equipment_not_accepted"
        _record_outlet_event(db, bypass_id + ":outlet-open", incident_id,
                             "treatment-outlet", at, "open", "bypass online")
        _idem_finish(db, bypass_id, "enable_bypass", payload, "bypass_enabled")
        return "bypass_enabled"


start_bypass = enable_bypass


def fail_treatment_outlet(db, failure_id, incident_id, at, outlet="treatment-outlet",
                          reason=None):
    """Mark the treatment outlet failed; all later discharges are refused."""
    return set_outlet_state(db, failure_id, incident_id, outlet, at,
                            "failed", reason or "outlet analysis/treatment failure")


outlet_failure = fail_treatment_outlet


def recover_treatment_outlet(db, recovery_id, incident_id, at,
                             outlet="treatment-outlet", reason=None):
    return set_outlet_state(db, recovery_id, incident_id, outlet, at,
                           "open", reason or "outlet restored; new sample required")


def divert_to_containment(db, action_id, incident_id, at, amount=None,
                          tank_no="EMERGENCY-TANK", outlet="treatment-outlet",
                          source_location="shared_sump",
                          reason="outlet_not_compliant"):
    """Trip failed/non-compliant treatment flow into sealed containment."""
    _ensure(db)
    payload = dict(incident_id=incident_id, at=at, amount=amount,
                   tank_no=tank_no, outlet=outlet,
                   source_location=source_location, reason=reason)
    with transaction(db):
        idem = _idem_old(db, action_id, "divert")
        replay = _idem_replay(idem, payload)
        if replay is not None:
            return replay if replay != "__conflict__" else "divert_conflict"
        _record_outlet_event(db, action_id + ":state", incident_id, outlet, at,
                             "diverted", reason)
        if amount:
            # Balanced custody move: source interception point -> emergency tank.
            _post(db, action_id + ":from", incident_id, at, INTERCEPTED,
                  -float(amount), "diverted_from_treatment_feed",
                  "divert:" + action_id + ":from", location=source_location)
            _post(db, action_id + ":to", incident_id, at, INTERCEPTED,
                  float(amount), "diverted_to_containment", "divert:" + action_id + ":to",
                  location=f"tank:{tank_no}", container=tank_no)
        _idem_finish(db, action_id, "divert", payload, "diverted_to_containment")
        return "diverted_to_containment"


def record_treatment_run(db, run_id, incident_id, at,
                         treated=None, discharged=None, residue=None,
                         outlet="treatment-outlet", residue_tank="RESIDUE-TANK",
                         concentration=None, limit_value=None, compliant=None,
                         sample_id=None, outlet_location=None,
                         flow_start=None, flow_end=None,
                         sample_start=None, sample_end=None,
                         flow_volume=None, **kw):
    """Book one aligned treatment run and its permitted outlet discharge.

    Conservation requires ``treated == discharged + residue``.  The outlet
    sample window must exactly align with the discharge flow window at the
    same outlet and must comply with ``limit_value``.  Any failure returns a
    non-``recorded`` verdict and posts no quantities; the operator must
    divert to containment.
    """
    if not run_id or not incident_id:
        return "invalid_run"
    discharged = discharged if discharged is not None else flow_volume
    if None in (treated, discharged, residue):
        return "invalid_run_amounts"
    if min(treated, discharged, residue) < 0:
        return "invalid_run_amounts"
    if abs(float(treated) - float(discharged) - float(residue)) > 1e-6:
        return "treatment_mass_imbalance"

    flow_start = at if flow_start is None else flow_start
    flow_end = at + WINDOW_MINUTES if flow_end is None else flow_end
    sample_start = sample_start if sample_start is not None else flow_start
    sample_end = sample_end if sample_end is not None else flow_end
    location = outlet_location or outlet

    alignment = windows_relation(flow_start, flow_end, sample_start, sample_end)
    mass = discharge_mass(discharged, concentration,
                          flow_start, flow_end, sample_start, sample_end,
                          location, location)
    pollutant_mass = mass.get("pollutant_mass")

    if compliant is None and concentration is not None and limit_value is not None:
        compliant = float(concentration) <= float(limit_value)

    payload = dict(incident_id=incident_id, at=at, treated=treated,
                   discharged=discharged, residue=residue, outlet=outlet,
                   residue_tank=residue_tank, concentration=concentration,
                   limit_value=limit_value, compliant=compliant,
                   sample_id=sample_id, flow_start=flow_start, flow_end=flow_end,
                   sample_start=sample_start, sample_end=sample_end,
                   alignment=alignment, location=location)
    _ensure(db)
    with transaction(db):
        idem = _idem_old(db, run_id, "treatment_run")
        replay = _idem_replay(idem, payload)
        if replay is not None:
            return replay if replay != "__conflict__" else "run_conflict"

        if _control_strategy(db, incident_id) != BYPASS:
            return "bypass_control_required"
        outlet_state = one(db,
                     "SELECT state FROM wi_outlet_events WHERE case_id=? AND outlet=? "
                     "ORDER BY at DESC,id DESC LIMIT 1", (incident_id, outlet))
        state = outlet_state["state"] if outlet_state else None
        if state == "failed":
            verdict = "treatment_outlet_failed"
            _insert_run(db, run_id, payload, alignment, pollutant_mass, verdict)
            return _idem_finish(db, run_id, "treatment_run", payload, verdict)
        if state is None:
            verdict = "bypass_not_enabled"
            _insert_run(db, run_id, payload, alignment, pollutant_mass, verdict)
            return _idem_finish(db, run_id, "treatment_run", payload, verdict)
        if state != "open":
            verdict = "outlet_not_open"
            _insert_run(db, run_id, payload, alignment, pollutant_mass, verdict)
            return _idem_finish(db, run_id, "treatment_run", payload, verdict)
        if alignment != "exact":
            verdict = "unaligned_windows"
            _insert_run(db, run_id, payload, alignment, pollutant_mass, verdict)
            return _idem_finish(db, run_id, "treatment_run", payload, verdict)
        if concentration is None or limit_value is None:
            verdict = "outlet_sample_required"
            _insert_run(db, run_id, payload, alignment, pollutant_mass, verdict)
            return _idem_finish(db, run_id, "treatment_run", payload, verdict)
        if compliant is False:
            verdict = "outlet_noncompliant"
            _insert_run(db, run_id, payload, alignment, pollutant_mass, verdict)
            return _idem_finish(db, run_id, "treatment_run", payload, verdict)

        verdict = "discharge_recorded"
        _insert_run(db, run_id, payload, alignment, pollutant_mass, verdict,
                    compliant=1)
        # treated leaves the shared sump/interception point ...
        _post(db, run_id + ":treated", incident_id, at, INTERCEPTED,
              -float(treated), "bypass_treatment_feed", "run:" + run_id + ":treated",
              location=kw.get("feed_location", "shared_sump"))
        # ... compliant volume is discharged ...
        _post(db, run_id + ":discharged", incident_id, at, DISCHARGED,
              float(discharged), "aligned_compliant_outlet", "run:" + run_id + ":discharged",
              location=location)
        # ... residue lands in a marked residue tank.
        if residue:
            _post(db, run_id + ":residue", incident_id, at, INTERCEPTED,
                  float(residue), "treatment_residue", "run:" + run_id + ":residue",
                  location=f"tank:{residue_tank}", container=residue_tank)
        return _idem_finish(db, run_id, "treatment_run", payload, verdict)


record_discharge = treatment_run = treat_and_discharge = record_treatment_run


def _insert_run(db, run_id, p, alignment, pollutant_mass, status, compliant=None):
    db.execute("INSERT INTO wi_runs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
               (run_id, p["incident_id"], p["at"], p["outlet"],
                float(p["treated"]), float(p["discharged"]), float(p["residue"]),
                p["residue_tank"], p["concentration"], p["limit_value"],
                compliant if compliant is not None else (
                    None if p["compliant"] is None else int(bool(p["compliant"]))),
                p["sample_id"], p["flow_start"], p["flow_end"],
                p["sample_start"], p["sample_end"], alignment,
                p["location"], status, pollutant_mass))


# ---------------------------------------------------------------------------
# Append-only regulatory report versions
# ---------------------------------------------------------------------------


def file_report(db, report_id, incident_id, text, served_at=None, at=None,
                kind="initial", recipient="regulator", family=None,
                corrects=None):
    """File one immutable report version with the regulator.

    The verbatim ``text`` and its checksum are stored.  Re-using a report id
    with different text is a conflict and never rewrites the served report.
    Corrections/supplements/withdrawals must use new ids via
    :func:`correct_report` / :func:`withdraw_report`.
    """
    if not report_id or not incident_id or text is None:
        return "invalid_report"
    if kind not in ("initial", "suspected", "correction", "supplement",
                    "withdrawal", "discharge", "declaration"):
        return "invalid_report_kind"
    _ensure(db)
    served = served_at if served_at is not None else at
    with transaction(db):
        old = one(db, "SELECT * FROM wi_reports WHERE id=?", (report_id,))
        if old:
            same = old["text"] == text and old["kind"] == kind
            return "replayed" if same else "report_id_conflict_immutable"
        fam = family or incident_id
        version = one(db, "SELECT COALESCE(MAX(version),0)+1 v FROM wi_reports "
                          "WHERE family=?", (fam,))["v"]
        if corrects and not one(db, "SELECT id FROM wi_reports WHERE id=?", (corrects,)):
            return "referenced_report_missing"
        db.execute("INSERT INTO wi_reports VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                   (report_id, incident_id, fam, version, kind, text,
                    _checksum(text), recipient, at if at is not None else served,
                    served, corrects))
        return "report_filed"


submit_report = add_report = file_report


def correct_report(db, correction_id, incident_id, text, at=None,
                   corrects=None, served_at=None, kind="correction",
                   recipient="regulator", reason=None):
    if not corrects:
        return "correction_requires_original"
    original = one(db, "SELECT * FROM wi_reports WHERE id=?", (corrects,))
    if not original:
        return "original_report_missing"
    return file_report(db, correction_id, incident_id, text,
                       served_at=served_at if served_at is not None else at,
                       at=at, kind=kind, recipient=recipient,
                       family=original["family"], corrects=corrects)


def supplement_report(db, supplement_id, incident_id, text, at=None,
                      corrects=None, served_at=None, recipient="regulator",
                      reason=None):
    return correct_report(db, supplement_id, incident_id, text, at=at,
                          corrects=corrects, served_at=served_at,
                          kind="supplement", recipient=recipient, reason=reason)


def withdraw_report(db, withdrawal_id, incident_id, text, at=None,
                    withdraws=None, served_at=None, reason=None):
    if not withdraws:
        return "withdrawal_requires_original"
    original = one(db, "SELECT * FROM wi_reports WHERE id=?", (withdraws,))
    if not original:
        return "original_report_missing"
    return file_report(db, withdrawal_id, incident_id, text,
                       served_at=served_at if served_at is not None else at,
                       at=at, kind="withdrawal",
                       recipient=original["recipient"],
                       family=original["family"], corrects=withdraws)


def report_versions(db, incident_id):
    """Every filed version, original text untouched, in version order."""
    _ensure(db)
    return rows(db, "SELECT id,case_id AS incident_id,family,version,kind,text,"
                    "checksum,recipient,created_at,served_at,corrects "
                    "FROM wi_reports WHERE case_id=? ORDER BY family,version,id",
                (incident_id,))


def latest_report(db, incident_id, family=None):
    _ensure(db)
    if family:
        return one(db, "SELECT * FROM wi_reports WHERE case_id=? AND family=? "
                       "ORDER BY version DESC LIMIT 1", (incident_id, family))
    return one(db, "SELECT * FROM wi_reports WHERE case_id=? "
                   "ORDER BY version DESC LIMIT 1", (incident_id,))


list_reports = report_versions


def file_discharge_declaration(db, report_id, incident_id, at, run_id=None,
                               text=None, served_at=None,
                               recipient="regulator"):
    """Declare actual outlet discharge to the regulator.

    The declared volume may only come from a recorded aligned, compliant
    treatment run (or the reconciled ``discharged_permitted`` bucket).  This
    is the enforcement point that stops anyone filing the unexplained meter
    gap (the narrative's phantom "4") as environmental discharge.
    """
    _ensure(db)
    basis_run = None
    pollutant_mass = None
    if run_id is not None:
        run = one(db, "SELECT * FROM wi_runs WHERE id=?", (run_id,))
        if not run or run["status"] != "discharge_recorded":
            return "no_declarable_discharge_run"
        volume = n(run["discharged"])
        pollutant_mass = n(run["pollutant_mass"])
        basis_run = run_id
    else:
        rec = reconcile(db, incident_id)
        volume = rec.get("discharged_permitted", 0)
        if not volume:
            return "no_compliant_aligned_discharge"
    if not volume or float(volume) <= 0:
        return "no_compliant_aligned_discharge"
    if text is None:
        mass_clause = (f", pollutant mass {pollutant_mass}"
                       if pollutant_mass is not None else "")
        run_clause = f"; treatment run {basis_run}" if basis_run else ""
        text = (f"Discharge declaration {incident_id}: permitted treatment "
                f"outlet volume {volume} units{mass_clause}, based on aligned "
                f"independent compliant sampling{run_clause}.")
    return file_report(db, report_id, incident_id, text, at=at,
                       served_at=served_at if served_at is not None else at,
                       kind="discharge", recipient=recipient)


declare_discharge = file_discharge_declaration


# ---------------------------------------------------------------------------
# Lazy recognition of meter gaps + level evidence in the balanced ledger
# ---------------------------------------------------------------------------


def _autopost(db, incident_id):
    """Idempotently recognise meter gaps and physical level evidence.

    Posting here (instead of at insert time) means readings may arrive in any
    order -- including a tank reading that only arrives at minute 23 but
    describes minute 20 -- and reconciliation stays a pure function of the
    aligned physical record set.
    """
    case = _case(db, incident_id)
    if not case:
        return
    ws, we = case["window_start"], case["window_end"]
    loops = {r["circuit"] for r in rows(db, "SELECT circuit FROM wi_loops WHERE case_id=?",
                                        (incident_id,))}
    # Meter gaps: one recognition leg per original sample row.
    if _table_exists(db, "water_samples"):
        for m in _meter_rows(db):
            if loops and m["circuit"] not in loops:
                continue
            if ws is not None and not (ws <= m["at"] < we):
                # Provenance windows may widen/narrow; default minute matches.
                prov = _prov(db, "water_sample", m["id"])
                if prov and prov["window_start"] is not None:
                    rel = windows_relation(prov["window_start"], prov["window_end"], ws, we)
                    if rel == "disjoint":
                        continue
                else:
                    continue
            gap = minute_gap(m["intake"], m["returned"], m["drained"])
            _post(db, "gap:" + m["id"], incident_id, m["at"], UNEXPLAINED,
                  float(gap), "meter_conservation_gap", "meter:" + m["id"])

    # Level evidence reclassifies unexplained into a physical destination.
    for lv in rows(db, "SELECT * FROM wi_levels WHERE case_id=?", (incident_id,)):
        if ws is not None:
            rel = windows_relation(lv["window_start"], lv["window_end"], ws, we)
            if rel == "disjoint":
                continue
        if lv["kind"] == "sump":
            bucket, location, container = INTERCEPTED, lv["location"] or "shared_sump", lv["container"]
            reason = "shared_sump_level_rise"
        elif lv["kind"] == "recovery_tank":
            bucket, location, container = RECOVERED, lv["location"], lv["container"]
            reason = "recovery_buffer_inflow"
        else:
            bucket, location, container = INTERCEPTED, lv["location"], lv["container"]
            reason = "tank_level_inflow"
        # Move out of unexplained and into destination (balanced pair).
        if _post(db, "level:" + lv["id"] + ":from", incident_id, lv["at"],
                 UNEXPLAINED, -float(lv["inflow"]), reason + ":unexplained",
                 "level-from:" + lv["id"]):
            _post(db, "level:" + lv["id"] + ":to", incident_id, lv["at"],
                  bucket, float(lv["inflow"]), reason,
                  "level-to:" + lv["id"], location=location, container=container)


# ---------------------------------------------------------------------------
# Reconciliation
# ---------------------------------------------------------------------------


def reconcile(db, incident_id=None):
    """Reconcile recognised gap against every physical destination.

    The result answers: how much was actually intercepted on site, recovered,
    lawfully discharged, sent off-site with a disposer receipt, or remains
    unexplained -- and where each amount currently is.
    """
    _ensure(db)
    case = _case(db, incident_id)
    cid = case["id"] if case else incident_id
    if not cid:
        return {"status": "unknown_incident"}

    with transaction(db):
        _autopost(db, cid)

    bucket_rows = rows(db, "SELECT bucket, COALESCE(SUM(delta),0) total "
                           "FROM wi_ledger WHERE case_id=? GROUP BY bucket", (cid,))
    buckets = {b: 0 for b in BUCKETS}
    for r in bucket_rows:
        buckets[r["bucket"]] = n(r["total"])

    location_rows = rows(
        db,
        "SELECT bucket,location,container,COALESCE(SUM(delta),0) total "
        "FROM wi_ledger WHERE case_id=? AND location IS NOT NULL "
        "GROUP BY bucket,location,container HAVING ABS(total)>1e-9 "
        "ORDER BY bucket,location", (cid,))
    destinations = [{
        "bucket": r["bucket"], "location": r["location"],
        "container": r["container"], "amount": n(r["total"]),
    } for r in location_rows]

    # Unexplained is a bucket too; location-less recognition legs live there.
    recognized = n(one(db,
        "SELECT COALESCE(SUM(delta),0) total FROM wi_ledger "
        "WHERE case_id=? AND reason='meter_conservation_gap'", (cid,))["total"])

    inv = investigate(db, cid)

    handoffs = rows(db, "SELECT * FROM wi_handoffs WHERE case_id=? ORDER BY at,id", (cid,))
    runs = rows(db, "SELECT * FROM wi_runs WHERE case_id=? ORDER BY at,id", (cid,))
    controls = rows(db, "SELECT * FROM wi_controls WHERE case_id=? ORDER BY at,id", (cid,))
    outlets = rows(db, "SELECT * FROM wi_outlet_events WHERE case_id=? ORDER BY at,id", (cid,))
    reports = report_versions(db, cid)

    total = n(sum(buckets.values()))
    unexplained = buckets[UNEXPLAINED]
    balanced = abs(float(total) - float(recognized)) < 1e-6 and unexplained >= -1e-9
    over_attributed = unexplained < -1e-9

    accepted_handoffs = [h for h in handoffs if h["status"] == "accepted"]
    rejected_handoffs = [h for h in handoffs if h["status"] == "rejected"]
    accepted_disposed = n(sum(float(h["net_weight"] or h["amount"] or 0)
                              for h in accepted_handoffs))

    return {
        "status": "reconciled" if balanced and not over_attributed else "imbalance",
        "incident_id": cid,
        "recognized_gap": recognized,
        "total_gap": inv["total_gap"],
        "buckets": buckets,
        "unexplained": unexplained,
        "unaccounted": unexplained,
        "recovered": buckets[RECOVERED],
        "intercepted": buckets[INTERCEPTED],
        "intercepted_on_site": buckets[INTERCEPTED],
        "discharged": buckets[DISCHARGED],
        "discharged_permitted": buckets[DISCHARGED],
        "offsite_disposed": buckets[OFFSITE_DISPOSED],
        "offsite_disposed_receipted": accepted_disposed,
        "total_destinations": total,
        "balanced": balanced,
        "over_attributed": over_attributed,
        "destinations": destinations,
        "attribution": inv["attribution"],
        "source_status": inv["source_status"],
        "control_strategy": controls[-1]["strategy"] if controls else None,
        "controls": [dict(c) for c in controls],
        "outlet_events": [dict(o) for o in outlets],
        "handoffs": [dict(h) for h in handoffs],
        "accepted_handoffs": [h["id"] for h in accepted_handoffs],
        "rejected_handoffs": [h["id"] for h in rejected_handoffs],
        "treatment_runs": [dict(r) for r in runs],
        "report_versions": [
            {"id": r["id"], "version": r["version"], "kind": r["kind"],
             "checksum": r["checksum"], "served_at": r["served_at"]}
            for r in reports],
        "reports_immutable": True,
        "warnings": inv["warnings"],
    }


reconciliation = reconcile


# ---------------------------------------------------------------------------
# Service facade for callers that prefer an object
# ---------------------------------------------------------------------------


class WaterIncidentService:
    """Thin method facade over the module-level db functions."""

    def __init__(self, db):
        self.db = db

    def __getattr__(self, name):
        fn = globals().get(name)
        if callable(fn):
            return lambda *a, **k: fn(self.db, *a, **k)
        raise AttributeError(name)


# Common alternative naming for the facade.
IncidentService = WaterIncidentService
WaterIncident = WaterIncidentService
CaseService = WaterIncidentService

# ---------------------------------------------------------------------------
# Naming aliases: the specification fixes behaviour, not the verb, so expose
# the same operations under the natural synonyms a caller may reach for.
# ---------------------------------------------------------------------------

create_case = open_case
start_case = open_incident
investigate_incident = investigate_imbalance = imbalance_report = investigate
incident_report = conservation = conservation_report
reconcile_incident = reconcile_volumes = final_accounting = reconcile
account = reconcile

record_meter_reading = add_meter_reading = meter_reading
record_sump_reading = sump_reading
record_tank_reading = add_tank_reading = tank_reading
record_recovery_reading = recovery_tank_reading
record_valve_receipt = register_valve_receipt
add_provenance = attach_provenance

attribute_sources = attribute_shared_sump = source_intervals
check_discharge = aligned_discharge_mass = discharge_mass
conservation_gap = circuit_balance = minute_conservation = minute_gap
balance_intervals = attribute_shared_sump

seal_sump_action = seal
contain = choose_control
start_online_treatment = enable_bypass
record_discharge_run = treatment_run

file_regulator_report = submit_regulatory_report = regulator_report = file_report
add_correction = correction = correct_report
add_withdrawal = withdrawal = withdraw_report
versions = report_versions

__all__ = [name for name in globals() if not name.startswith("_")]
