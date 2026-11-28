"""Device-trust authorization chain.

Binds the two independent evidence streams (hardware quotes in attest.py and
agent command receipts in agent_command.py) to a single physically possessed
chip identity.  A capacity report or physical command is only authoritative
when:

* the device certificate is registered, not cloned and not revoked;
* the quote answers a single-use challenge issued for that device;
* the measurement was on the allowed agent-version whitelist at quote time;
* the per-chip monotonic boot counter never rolls back;
* the device exclusively possessed the reporting node at that instant;
* the receipt is bound to a dispatched command digest, target device,
  generation and execution location, and is covered by a valid quote.

Quarantine is sticky: reboots and fresh challenges never clear suspicion.
Only independent field evidence (migration verification) or replacement with
a spare physical chip restores an authoritative agent.
"""
import hashlib

from .store import one, rows, transaction


# Final verdicts that must never be recomputed (evidence preserved).
FINAL_VERDICTS = {
    "trusted", "untrusted", "quarantined", "instance_retired",
    "anomalous_original", "stale_generation", "location_mismatch",
    "command_target_mismatch", "unknown_command", "no_possession",
    "no_covering_quote", "cert_revoked", "unknown_device",
}


def _digest(*parts):
    raw = "|".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(raw.encode()).hexdigest()


def _device(db, device):
    return one(db, "SELECT * FROM dt_devices WHERE device=?", (device,))


def _open_dispute(db, device):
    return one(db, "SELECT * FROM dt_disputes WHERE device=? AND state='open' ORDER BY opened_at DESC LIMIT 1", (device,))


def _instance_at(db, device, at, node=None):
    sql = "SELECT * FROM dt_instances WHERE device=? AND activated_at<=? AND (retired_at IS NULL OR retired_at>?)"
    args = [device, at, at]
    if node is not None:
        sql += " AND node=?"
        args.append(node)
    sql += " ORDER BY activated_at DESC LIMIT 1"
    return one(db, sql, tuple(args))


def _revoked_at(db, device):
    row = one(db, "SELECT MIN(revoked_at) t FROM dt_revocations WHERE device=?", (device,))
    return row["t"] if row else None


def _measurement_allowed(db, measurement, at):
    return one(db, """SELECT * FROM dt_measurements WHERE measurement=?
        AND valid_from<=? AND (valid_until IS NULL OR valid_until>?)""", (measurement, at, at))


def _covering_quote(db, device, node, at):
    return one(db, """SELECT q.* FROM device_quotes q JOIN dt_quote_verdicts v ON v.quote_id=q.id
        WHERE q.device=? AND q.node=? AND v.verdict='valid' AND q.at<=?
        ORDER BY q.at DESC LIMIT 1""", (device, node, at))


def _upsert_quote_verdict(db, quote_id, device, node, at, verdict, reason):
    db.execute("""INSERT INTO dt_quote_verdicts VALUES(?,?,?,?,?,?)
        ON CONFLICT(quote_id) DO UPDATE SET verdict=excluded.verdict,reason=excluded.reason""",
        (quote_id, device, node, at, verdict, reason))


def _upsert_receipt_verdict(db, receipt_id, device, node, at, verdict, reason):
    db.execute("""INSERT INTO dt_receipt_verdicts VALUES(?,?,?,?,?,?)
        ON CONFLICT(receipt_id) DO UPDATE SET verdict=excluded.verdict,reason=excluded.reason""",
        (receipt_id, device, node, at, verdict, reason))


# ---------------------------------------------------------------- enrollment

def register_device(db, device, cert_serial, fingerprint, node, at, generation=1):
    if not all((device, cert_serial, fingerprint, node)) or at < 0 or generation <= 0:
        return "invalid_device"
    with transaction(db):
        old = _device(db, device)
        if old:
            if old["fingerprint"] == fingerprint and old["cert_serial"] == cert_serial:
                return "exists"
            return "identity_conflict"
        if one(db, "SELECT device FROM dt_devices WHERE fingerprint=?", (fingerprint,)):
            return "clone_detected"
        db.execute("INSERT INTO dt_devices VALUES(?,?,?,?,?,?,?,?,?,?)",
                   (device, cert_serial, fingerprint, node, generation, "active", at, None, None, None))
        db.execute("INSERT INTO dt_instances VALUES(?,?,?,?,?,?,?,?)",
                   (f"{device}#{node}#gen{generation}", device, node, generation,
                    "active", at, None, None))
        return "registered"


def revoke_device(db, device, revoked_at, reason=""):
    if revoked_at < 0:
        return "invalid_revocation"
    with transaction(db):
        d = _device(db, device)
        if not d:
            return "unknown_device"
        if one(db, "SELECT 1 FROM dt_revocations WHERE device=? AND revoked_at=?", (device, revoked_at)):
            return "revoked"
        db.execute("INSERT INTO dt_revocations VALUES(?,?,?)", (device, revoked_at, reason))
        if d["status"] in ("active", "disputed"):
            db.execute("UPDATE dt_devices SET status='revoked' WHERE device=?", (device,))
        return "revoked"


def allow_measurement(db, measurement, version, valid_from, valid_until=None):
    if not measurement or not version or valid_from < 0 or (valid_until is not None and valid_until <= valid_from):
        return "invalid_measurement"
    with transaction(db):
        old = one(db, "SELECT 1 FROM dt_measurements WHERE measurement=? AND valid_from=?", (measurement, valid_from))
        if old:
            return "exists"
        db.execute("INSERT INTO dt_measurements VALUES(?,?,?,?)", (measurement, version, valid_from, valid_until))
        return "allowed"


def issue_challenge(db, challenge_id, nonce, device, at, node=None, issued_by="control-plane"):
    """The issuer proves single use: nonce is globally unique and consumed once."""
    if not challenge_id or not nonce or at < 0:
        return "invalid_challenge"
    with transaction(db):
        old = one(db, "SELECT * FROM dt_challenges WHERE challenge_id=?", (challenge_id,))
        if old:
            same = (old["nonce"], old["device"], old["node"]) == (nonce, device, node)
            return "exists" if same else "challenge_conflict"
        if one(db, "SELECT 1 FROM dt_challenges WHERE nonce=?", (nonce,)):
            return "nonce_not_single_use"
        d = _device(db, device)
        if not d:
            return "unknown_device"
        if d["status"] == "quarantined":
            return "device_quarantined"
        if d["status"] == "revoked":
            return "device_revoked"
        db.execute("INSERT INTO dt_challenges VALUES(?,?,?,?,?,?,?,?)",
                   (challenge_id, nonce, device, node, at, issued_by, None, None))
        return "issued"


# ------------------------------------------------------------- quote intake

def evaluate_quote(db, quote_id):
    """Verify a captured attest.quote row; returns (verdict, reason).

    Cryptographic validity (cert, single-use nonce, measurement whitelist,
    per-chip counter) is necessary but not sufficient: exclusive physical
    possession of the node is enforced separately and may hold the quote in
    an open possession dispute until field evidence resolves it.
    """
    with transaction(db):
        cached = one(db, "SELECT * FROM dt_quote_verdicts WHERE quote_id=?", (quote_id,))
        if cached:
            return cached["verdict"], cached["reason"]
        q = one(db, "SELECT * FROM device_quotes WHERE id=?", (quote_id,))
        if not q:
            return "unknown_quote", "quote_not_captured"
        device, node, at = q["device"], q["node"], q["at"]

        def fail(verdict, reason):
            _upsert_quote_verdict(db, quote_id, device, node, at, verdict, reason)
            return verdict, reason

        d = _device(db, device)
        if not d:
            return fail("unknown_device", "certificate_not_registered")
        if d["status"] == "quarantined":
            return fail("quarantined", "device_under_isolation")
        revoked = _revoked_at(db, device)
        if revoked is not None and revoked <= at:
            return fail("cert_revoked", f"revoked_at_{revoked}")

        ch = one(db, "SELECT * FROM dt_challenges WHERE nonce=?", (q["nonce"],))
        if not ch:
            return fail("unknown_challenge", "nonce_was_never_issued")
        if ch["consumed_quote"] is not None and ch["consumed_quote"] != quote_id:
            return fail("nonce_replayed", "challenge_already_consumed")
        if ch["device"] != device:
            return fail("challenge_device_mismatch", "challenge_bound_to_other_chip")
        if ch["node"] is not None and ch["node"] != node:
            return fail("challenge_node_mismatch", "challenge_bound_to_other_node")
        if ch["issued_at"] > at:
            return fail("challenge_after_quote", "quote_predicates_its_own_challenge")
        if not _measurement_allowed(db, q["measurement"], at):
            return fail("measurement_not_allowed", "agent_version_not_whitelisted_at_quote_time")
        if d["last_counter"] is not None and q["boot_counter"] <= d["last_counter"]:
            return fail("counter_rollback", f"counter_{q['boot_counter']}_not_above_{d['last_counter']}")

        instance = _instance_at(db, device, at)
        migration = one(db, "SELECT * FROM dt_migrations WHERE device=? AND state IN ('begun','removal_verified','installed') ORDER BY begun_at DESC LIMIT 1", (device,))
        if instance is None or instance["node"] != node:
            # A quote on the destination node is a legitimate takeover once an
            # independently verified removal proves the old machine lost possession
            # before this quote was produced; anything else is a possession conflict.
            if (migration and migration["to_node"] == node
                    and migration["state"] in ("removal_verified", "installed")
                    and migration["poweroff_at"] is not None and migration["poweroff_at"] < at):
                verdict, reason = "valid", "takeover_quote"
                db.execute("UPDATE dt_migrations SET install_quote_id=?,state='installed' WHERE migration_id=?",
                           (quote_id, migration["migration_id"]))
            else:
                if not _open_dispute(db, device):
                    db.execute("INSERT INTO dt_disputes VALUES(?,?,?,?,?,?,?)",
                               (f"disp-{device}-{at}", device, at, None, "open",
                                "same_chip_observed_on_two_nodes", migration["migration_id"] if migration else None))
                db.execute("UPDATE dt_devices SET status='disputed' WHERE device=?", (device,))
                db.execute("UPDATE dt_challenges SET consumed_at=?,consumed_quote=? WHERE challenge_id=?",
                           (at, quote_id, ch["challenge_id"]))
                if d["last_counter"] is None or q["boot_counter"] > d["last_counter"]:
                    db.execute("UPDATE dt_devices SET last_counter=?,last_quote_at=? WHERE device=?",
                               (q["boot_counter"], at, device))
                _upsert_quote_verdict(db, quote_id, device, node, at, "held", "possession_conflict")
                return "held", "possession_conflict"
        else:
            verdict, reason = "valid", "instance_quote"

        db.execute("UPDATE dt_challenges SET consumed_at=?,consumed_quote=? WHERE challenge_id=?",
                   (at, quote_id, ch["challenge_id"]))
        db.execute("UPDATE dt_devices SET last_counter=?,last_quote_at=? WHERE device=?",
                   (q["boot_counter"], at, device))
        if instance is not None and instance["node"] == node:
            db.execute("UPDATE dt_instances SET quote_id=? WHERE id=?", (quote_id, instance["id"]))
        _upsert_quote_verdict(db, quote_id, device, node, at, verdict, reason)
        return verdict, reason


# ----------------------------------------------------- migration / handover

def begin_migration(db, migration_id, device, from_node, to_node, at, order_ref):
    """Independent removal/install handover. The chip may not serve two nodes."""
    if not all((migration_id, device, from_node, to_node, order_ref)) or from_node == to_node or at < 0:
        return "invalid_migration"
    with transaction(db):
        old = one(db, "SELECT * FROM dt_migrations WHERE migration_id=?", (migration_id,))
        if old:
            same = (old["device"], old["from_node"], old["to_node"]) == (device, from_node, to_node)
            return "exists" if same else "migration_conflict"
        d = _device(db, device)
        if not d:
            return "unknown_device"
        if d["status"] == "quarantined":
            return "device_quarantined"
        # Source possession is read from the instance ledger, not the device row's
        # cached node (which only updates when a migration is decided).
        if not _instance_at(db, device, at, from_node):
            return "source_not_in_possession"
        if one(db, "SELECT 1 FROM dt_migrations WHERE device=? AND state IN ('begun','removal_verified','installed')", (device,)):
            return "migration_already_open"
        db.execute("INSERT INTO dt_migrations VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (migration_id, device, from_node, to_node, "begun", at, order_ref,
                    None, None, None, None, None, None, None, None))
        return "begun"


def removal_evidence(db, migration_id, access_ref, photo_ref, poweroff_at, at):
    """Old machine power-off plus independently verified access/photo evidence."""
    if not all((access_ref, photo_ref)) or poweroff_at < 0 or at < 0:
        return "invalid_evidence"
    with transaction(db):
        m = one(db, "SELECT * FROM dt_migrations WHERE migration_id=?", (migration_id,))
        if not m:
            return "unknown_migration"
        if m["state"] in ("verified", "quarantined", "conflict"):
            return "migration_closed"
        if poweroff_at < m["begun_at"] or at < poweroff_at:
            return "evidence_conflict"
        if m["access_ref"] is not None and (m["access_ref"], m["photo_ref"], m["poweroff_at"]) != (access_ref, photo_ref, poweroff_at):
            return "evidence_conflict"
        db.execute("""UPDATE dt_migrations SET access_ref=?,photo_ref=?,poweroff_at=?,state='removal_verified'
            WHERE migration_id=?""", (access_ref, photo_ref, poweroff_at, migration_id))
        return "removal_verified"


def install_evidence(db, migration_id, challenge_id, quote_id, at):
    """New-machine field challenge answered by the chip on the destination node."""
    with transaction(db):
        m = one(db, "SELECT * FROM dt_migrations WHERE migration_id=?", (migration_id,))
        if not m:
            return "unknown_migration"
        if m["state"] in ("verified", "quarantined", "conflict"):
            return "migration_closed"
        if m["state"] == "begun":
            return "removal_not_verified"
        ch = one(db, "SELECT * FROM dt_challenges WHERE challenge_id=?", (challenge_id,))
        if not ch or ch["device"] != m["device"] or (ch["node"] is not None and ch["node"] != m["to_node"]):
            return "challenge_target_mismatch"
        v = one(db, "SELECT * FROM dt_quote_verdicts WHERE quote_id=?", (quote_id,))
        q = one(db, "SELECT * FROM device_quotes WHERE id=?", (quote_id,))
        if not v or not q or q["device"] != m["device"] or q["node"] != m["to_node"]:
            return "quote_target_mismatch"
        if v["verdict"] != "valid":
            return "quote_not_valid"
        db.execute("UPDATE dt_migrations SET challenge_id=?,install_quote_id=?,state='installed' WHERE migration_id=?",
                   (challenge_id, quote_id, migration_id))
        return "installed"


def decide_migration(db, migration_id, at, field_quote_id=None):
    """Resolve a handoff. Requires order, access, photo and power-off to corroborate."""
    with transaction(db):
        m = one(db, "SELECT * FROM dt_migrations WHERE migration_id=?", (migration_id,))
        if not m:
            return "unknown_migration"
        if m["state"] in ("verified", "quarantined"):
            return m["state"]
        d = _device(db, m["device"])
        if not d or d["status"] == "quarantined":
            return "device_quarantined"
        evidence = (m["order_ref"], m["access_ref"], m["photo_ref"], m["poweroff_at"])
        if any(x is None for x in evidence):
            return "evidence_incomplete"
        install_quote = m["install_quote_id"] or field_quote_id
        if install_quote:
            q = one(db, "SELECT * FROM device_quotes WHERE id=?", (install_quote,))
            v = one(db, "SELECT verdict,reason FROM dt_quote_verdicts WHERE quote_id=?", (install_quote,))
            if not q or q["device"] != m["device"] or q["node"] != m["to_node"]:
                return "quote_target_mismatch"
            if v and v["verdict"] not in ("valid", "held"):
                return "quote_not_valid"
        else:
            return "evidence_incomplete"

        new_generation = (d["generation"] or 1) + 1
        old = _instance_at(db, m["device"], at, m["from_node"])
        if old:
            db.execute("UPDATE dt_instances SET state='retired',retired_at=? WHERE id=?",
                       (m["poweroff_at"], old["id"]))
        db.execute("INSERT INTO dt_instances VALUES(?,?,?,?,?,?,?,?)",
                   (f"{m['device']}#{m['to_node']}#gen{new_generation}", m["device"], m["to_node"],
                    new_generation, "active", at, None, install_quote))
        db.execute("UPDATE dt_devices SET node=?,generation=?,status='active' WHERE device=?",
                   (m["to_node"], new_generation, m["device"]))
        db.execute("""UPDATE dt_migrations SET state='verified',decided_at=?,new_generation=?,install_quote_id=?
            WHERE migration_id=?""", (at, new_generation, install_quote, migration_id))
        db.execute("UPDATE dt_disputes SET state='resolved',resolved_at=? WHERE device=? AND state='open'",
                   (at, m["device"]))
        return "verified"


# ------------------------------------------------------------- quarantine

def quarantine_device(db, device, at, reason):
    """Sticky isolation: preserves prior trusted actions, rejects all new ones."""
    with transaction(db):
        d = _device(db, device)
        if not d:
            return "unknown_device"
        if d["status"] == "quarantined":
            return "quarantined"
        db.execute("UPDATE dt_devices SET status='quarantined',quarantined_at=? WHERE device=?", (at, device))
        isolated = set()
        for inst in rows(db, "SELECT * FROM dt_instances WHERE device=? AND state='active'", (device,)):
            db.execute("UPDATE dt_instances SET state='retired',retired_at=? WHERE id=?", (at, inst["id"]))
            isolated.add(inst["node"])
        # Every node entangled in an undecided handover loses its management agent too.
        for m in rows(db, "SELECT * FROM dt_migrations WHERE device=? AND state IN ('begun','removal_verified','installed')", (device,)):
            isolated.update((m["from_node"], m["to_node"]))
        for node in sorted(isolated):
            if not one(db, "SELECT 1 FROM dt_isolation WHERE node=?", (node,)):
                db.execute("INSERT INTO dt_isolation VALUES(?,?,?,?)", (node, device, at, reason))
        db.execute("UPDATE dt_migrations SET state='quarantined' WHERE device=? AND state IN ('begun','removal_verified','installed')", (device,))
        db.execute("UPDATE dt_disputes SET state='resolved',resolved_at=? WHERE device=? AND state='open'", (at, device))
        # Held quotes can never be trusted now; held receipts get their final
        # classification through the same evaluation path as every other receipt.
        for row in rows(db, "SELECT * FROM dt_quote_verdicts WHERE verdict='held' AND device=?", (device,)):
            _upsert_quote_verdict(db, row["quote_id"], device, row["node"], row["at"], "quarantined", reason)
        for v in rows(db, "SELECT * FROM dt_receipt_verdicts WHERE verdict='held' AND device=?", (device,)):
            rc = one(db, "SELECT * FROM agent_receipts WHERE id=?", (v["receipt_id"],))
            _evaluate_receipt_locked(db, rc)
        return "quarantined"


def re_register(db, new_device, cert_serial, fingerprint, node, at, generation=1):
    """Replacement with a spare physical chip; the quarantined chip stays dead."""
    with transaction(db):
        if one(db, "SELECT 1 FROM dt_isolation WHERE node=?", (node,)):
            db.execute("DELETE FROM dt_isolation WHERE node=?", (node,))
        return register_device(db, new_device, cert_serial, fingerprint, node, at, generation)


# ------------------------------------------------------------- commands

def dispatch_command(db, command_id, device, node, generation, at):
    """Record the control-plane command and return the digest receipts must bind."""
    if not command_id or generation <= 0 or at < 0:
        return "invalid_command", None
    with transaction(db):
        old = one(db, "SELECT * FROM dt_commands WHERE command_id=?", (command_id,))
        if old:
            digest = old["digest"]
            same = (old["device"], old["node"], old["generation"]) == (device, node, generation)
            return ("exists" if same else "command_conflict"), digest
        digest = _digest(command_id, device, node, generation, at)
        db.execute("INSERT INTO dt_commands VALUES(?,?,?,?,?,?)",
                   (command_id, digest, device, node, generation, at))
        return "dispatched", digest


def _evaluate_receipt_locked(db, rc):
    receipt_id, device, node, at = rc["id"], rc["device"], rc["node"], rc["at"]

    def finish(verdict, reason):
        _upsert_receipt_verdict(db, receipt_id, device, node, at, verdict, reason)
        return verdict, reason

    d = _device(db, device)
    if not d:
        return finish("untrusted", "unknown_device")
    if d["status"] == "quarantined":
        return finish("quarantined", "device_under_isolation")
    revoked = _revoked_at(db, device)
    if revoked is not None and revoked <= at:
        return finish("untrusted", "cert_revoked")
    if _open_dispute(db, device) or d["status"] == "disputed":
        return finish("held", "possession_conflict")

    cmd = one(db, "SELECT * FROM dt_commands WHERE digest=?", (rc["command"],))
    if not cmd:
        return finish("untrusted", "unknown_command")
    if cmd["device"] != device:
        return finish("untrusted", "command_target_mismatch")
    if cmd["node"] != node:
        return finish("untrusted", "location_mismatch")
    if cmd["generation"] != rc["generation"]:
        return finish("stale_generation", "receipt_generation_does_not_bind_command")

    inst = _instance_at(db, device, at, node)
    if inst:
        if inst["generation"] != rc["generation"]:
            return finish("stale_generation", f"instance_generation_{inst['generation']}")
        if not _covering_quote(db, device, node, at):
            return finish("untrusted", "no_covering_quote")
        return finish("trusted", "causal_chain_verified")
    # No instance on this node at receipt time: distinguish the retired source
    # agent (anomalous original evidence) from a node that never possessed the chip.
    m = one(db, "SELECT * FROM dt_migrations WHERE device=? AND state='verified' ORDER BY decided_at DESC LIMIT 1", (device,))
    if m and node == m["from_node"] and at >= (m["poweroff_at"] or 0):
        return finish("anomalous_original", "retired_agent_reported_after_handover")
    # The destination node before takeover: a valid command signature under the
    # old generation is stale, never an authoritative execution on the new owner.
    if m and node == m["to_node"]:
        return finish("stale_generation", "predates_takeover_generation")
    return finish("untrusted", "no_possession")

def evaluate_receipt(db, receipt_id):
    """Attribute one captured agent_command.receipt row to a proven device."""
    with transaction(db):
        cached = one(db, "SELECT * FROM dt_receipt_verdicts WHERE receipt_id=?", (receipt_id,))
        rc = one(db, "SELECT * FROM agent_receipts WHERE id=?", (receipt_id,))
        if not rc:
            return "unknown_receipt", "receipt_not_captured"
        if cached and cached["verdict"] not in ("held",):
            return cached["verdict"], cached["reason"]
        return _evaluate_receipt_locked(db, rc)


def finalize_receipts(db, device, at):
    """Recompute held receipts after a migration decision or quarantine."""
    out = []
    with transaction(db):
        held = rows(db, "SELECT * FROM dt_receipt_verdicts WHERE device=? AND verdict='held'", (device,))
        for v in held:
            rc = one(db, "SELECT * FROM agent_receipts WHERE id=?", (v["receipt_id"],))
            verdict, reason = _evaluate_receipt_locked(db, rc)
            out.append({"receipt_id": v["receipt_id"], "node": rc["node"], "at": rc["at"],
                        "verdict": verdict, "reason": reason})
        return out


def authorize_capacity(db, node, device, at, receipt_id=None):
    """Gate for reserve.node: only a proven exclusive possessor may report."""
    with transaction(db):
        if receipt_id is not None:
            verdict, reason = evaluate_receipt(db, receipt_id)
            if verdict != "trusted":
                return verdict, reason
            rc = one(db, "SELECT * FROM agent_receipts WHERE id=?", (receipt_id,))
            if rc["node"] != node or rc["device"] != device:
                return "location_mismatch", "receipt_bound_elsewhere"
            return "trusted", "receipt_chain_verified"
        d = _device(db, device)
        if not d:
            return "unknown_device", "certificate_not_registered"
        if d["status"] == "quarantined":
            return "quarantined", "device_under_isolation"
        if d["status"] == "disputed" or _open_dispute(db, device):
            return "held", "possession_conflict"
        revoked = _revoked_at(db, device)
        if revoked is not None:
            if d["last_quote_at"] is not None and revoked <= d["last_quote_at"]:
                return "cert_revoked", f"revoked_at_{revoked}"
            if receipt_id is None and revoked <= at:
                return "cert_revoked", f"revoked_at_{revoked}"
        inst = _instance_at(db, device, d["last_quote_at"] if d["last_quote_at"] is not None else at, node)
        if not inst:
            return "no_possession", "no_active_instance_on_node"
        if not _covering_quote(db, device, node, d["last_quote_at"] if d["last_quote_at"] is not None else at):
            return "no_covering_quote", "instance_lacks_valid_quote"
        return "trusted", "instance_chain_verified"


def trust_view(db):
    """Audit snapshot tying every report and command to a proven device."""
    return {
        "devices": rows(db, "SELECT * FROM dt_devices ORDER BY device"),
        "instances": rows(db, "SELECT * FROM dt_instances ORDER BY device,activated_at"),
        "disputes": rows(db, "SELECT * FROM dt_disputes ORDER BY opened_at"),
        "migrations": rows(db, "SELECT * FROM dt_migrations ORDER BY begun_at"),
        "quote_verdicts": rows(db, "SELECT * FROM dt_quote_verdicts ORDER BY at,quote_id"),
        "receipt_verdicts": rows(db, "SELECT * FROM dt_receipt_verdicts ORDER BY at,receipt_id"),
        "isolation": rows(db, "SELECT * FROM dt_isolation ORDER BY since,node"),
        "commands": rows(db, "SELECT * FROM dt_commands ORDER BY issued_at,command_id"),
    }
