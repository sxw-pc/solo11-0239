"""Cross-cluster entitlement transfer.

A transfer is a saga between two independently proven cluster control planes.
Source entitlement (basic budget, grant or loan — never blended) is earmarked
before the destination announces acceptance, and every customer-facing fact
(release sign-off, seat, delivery, notice, billing line) is an append-only
record so retries, lost acks, reordered messages and cancellation can never
overwrite a result the customer already received.
"""
from .store import event, one, rows, transaction

# Saga states
REQUESTED = "requested"
SOURCE_PREPARED = "source_prepared"
COMMITTED = "committed"
DELIVERED = "delivered"
CANCELLED = "cancelled"
TARGET_FAILED = "failed_target"
FALLBACK_PURCHASED = "fallback_purchased"
FALLBACK_DELIVERED = "fallback_delivered"

TERMINAL = {CANCELLED, TARGET_FAILED, FALLBACK_PURCHASED, FALLBACK_DELIVERED, DELIVERED, COMMITTED}
OPEN_STATES = {REQUESTED, SOURCE_PREPARED}

# Lot / earmark / seat statuses
LOT_ACTIVE, LOT_PROMISED, LOT_TRANSFERRED, LOT_VOID = "active", "promised", "transferred", "void"
EARMARK_HELD, EARMARK_COMMITTED, EARMARK_RELEASED = "held", "committed", "released"
SEAT_RESERVED, SEAT_HELD, SEAT_OCCUPIED, SEAT_RELEASED = "reserved", "held", "occupied", "released"

KINDS = ("budget", "grant", "loan", "purchase")


# ---------------------------------------------------------------- cluster registry

def register_cluster(db, cluster_id, proof_generation, proven_at):
    if proof_generation <= 0 or proven_at < 0 or not cluster_id:
        return "invalid_proof"
    with transaction(db):
        old = one(db, "SELECT * FROM clusters WHERE id=?", (cluster_id,))
        if old:
            if proof_generation < old["proof_generation"]:
                return "stale_proof"
            if proof_generation == old["proof_generation"]:
                return "accepted"
        db.execute("INSERT INTO clusters VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET "
                   "proof_generation=excluded.proof_generation,proven_at=excluded.proven_at",
                   (cluster_id, proof_generation, proven_at))
        return "accepted"


def register_node(db, node_id, cluster, zone, cpu, mem, generation):
    if cpu < 0 or mem < 0 or generation <= 0 or not zone:
        return "invalid_capacity"
    with transaction(db):
        if not one(db, "SELECT id FROM clusters WHERE id=?", (cluster,)):
            return "unknown_cluster"
        old = one(db, "SELECT * FROM cluster_nodes WHERE id=?", (node_id,))
        if old:
            if old["cluster"] != cluster:
                return "node_cluster_conflict"
            if generation < old["generation"]:
                return "stale_capacity"
            if generation == old["generation"]:
                same = (old["zone"], old["cpu"], old["mem"]) == (zone, cpu, mem)
                return "accepted" if same else "stale_capacity"
        db.execute("INSERT INTO cluster_nodes VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
                   "zone=excluded.zone,cpu=excluded.cpu,mem=excluded.mem,generation=excluded.generation",
                   (node_id, cluster, zone, cpu, mem, generation))
        return "accepted"


def register_lot(db, event_id, lot_id, cluster, tenant, kind, cpu, mem,
                 valid_from, valid_until, source_ref, at,
                 floor_cpu=0, floor_mem=0, due=None):
    if kind not in KINDS or kind == "purchase":
        return "invalid_lot_kind"
    if cpu <= 0 or mem <= 0 or valid_from < 0 or valid_until <= valid_from or at < 0:
        return "invalid_lot"
    payload = dict(lot_id=lot_id, cluster=cluster, tenant=tenant, kind=kind, cpu=cpu, mem=mem,
                   valid_from=valid_from, valid_until=valid_until, source_ref=source_ref, at=at)
    with transaction(db):
        old = one(db, "SELECT * FROM events WHERE id=?", (event_id,))
        if old:
            return event(db, event_id, "transfer.register_lot", payload, old["verdict"])
        if one(db, "SELECT id FROM cluster_lots WHERE id=?", (lot_id,)):
            return event(db, event_id, "transfer.register_lot", payload, "lot_exists")
        if not one(db, "SELECT id FROM clusters WHERE id=?", (cluster,)):
            return event(db, event_id, "transfer.register_lot", payload, "unknown_cluster")
        # Attest against the resource original in the existing entitlement ledgers.
        if kind == "budget":
            b = one(db, "SELECT * FROM budget_history WHERE tenant=? AND effective<=? "
                        "ORDER BY effective DESC,revision DESC LIMIT 1", (tenant, at))
            if not b or b["cpu"] < cpu or b["mem"] < mem:
                return event(db, event_id, "transfer.register_lot", payload, "budget_origin_missing")
            due = None
        elif kind == "grant":
            g = one(db, "SELECT * FROM grants WHERE id=? AND tenant=? AND revoked=0", (source_ref, tenant))
            if not g or g["cpu"] < cpu or g["mem"] < mem or g["until_ts"] < valid_until:
                return event(db, event_id, "transfer.register_lot", payload, "grant_origin_invalid")
            due = g["until_ts"]
        else:  # loan: lender floor, maturity and outstanding principal stay attached
            ln = one(db, "SELECT * FROM loans WHERE id=? AND borrower=?", (source_ref, tenant))
            if not ln or ln["due"] < valid_until or ln["cpu"] - ln["repaid_cpu"] < cpu \
                    or ln["mem"] - ln["repaid_mem"] < mem:
                return event(db, event_id, "transfer.register_lot", payload, "loan_origin_invalid")
            offer = one(db, "SELECT * FROM offers WHERE id=?", (ln["offer_id"],))
            floor_cpu, floor_mem = offer["floor_cpu"], offer["floor_mem"]
            due = ln["due"]
        db.execute("INSERT INTO cluster_lots VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (lot_id, cluster, tenant, kind, cpu, mem, valid_from, valid_until,
                    LOT_ACTIVE, None, source_ref, due, floor_cpu, floor_mem))
        return event(db, event_id, "transfer.register_lot", payload, "accepted")


# ---------------------------------------------------------------- transfer request

def request_transfer(db, event_id, transfer_id, tenant, src_cluster, dst_cluster, lot_id,
                     cpu, mem, valid_from, valid_until, deadline, at,
                     replica=None, displaces_reservation=None):
    if cpu <= 0 or mem <= 0 or at < 0 or valid_from < at or valid_until <= valid_from \
            or deadline < at or not tenant:
        return "invalid_transfer"
    if src_cluster == dst_cluster:
        return "same_cluster_transfer"
    payload = dict(transfer_id=transfer_id, tenant=tenant, src_cluster=src_cluster,
                   dst_cluster=dst_cluster, lot_id=lot_id, cpu=cpu, mem=mem,
                   valid_from=valid_from, valid_until=valid_until, deadline=deadline, at=at,
                   replica=replica, displaces_reservation=displaces_reservation)
    with transaction(db):
        old = one(db, "SELECT * FROM events WHERE id=?", (event_id,))
        if old:
            return event(db, event_id, "transfer.request", payload, old["verdict"])
        if one(db, "SELECT id FROM transfers WHERE id=?", (transfer_id,)):
            return event(db, event_id, "transfer.request", payload, "transfer_exists")
        src = one(db, "SELECT * FROM clusters WHERE id=?", (src_cluster,))
        dst = one(db, "SELECT * FROM clusters WHERE id=?", (dst_cluster,))
        if not src or not dst:
            return event(db, event_id, "transfer.request", payload, "unknown_cluster")
        lot = one(db, "SELECT * FROM cluster_lots WHERE id=? AND status=?", (lot_id, LOT_ACTIVE))
        if not lot or lot["cluster"] != src_cluster or lot["tenant"] != tenant:
            return event(db, event_id, "transfer.request", payload, "unknown_source_lot")
        if cpu > lot["cpu"] or mem > lot["mem"]:
            return event(db, event_id, "transfer.request", payload, "transfer_exceeds_lot")
        if lot["kind"] == "loan" and lot["due"] is not None and valid_until > lot["due"]:
            return event(db, event_id, "transfer.request", payload, "window_exceeds_loan_due")
        if valid_from < lot["valid_from"] or valid_until > lot["valid_until"]:
            return event(db, event_id, "transfer.request", payload, "window_outside_lot")
        if displaces_reservation:
            r = one(db, "SELECT * FROM reservations WHERE id=?", (displaces_reservation,))
            if not r or r["released"]:
                return event(db, event_id, "transfer.request", payload, "unknown_displaced_reservation")
        db.execute("INSERT INTO transfers VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (transfer_id, tenant, src_cluster, dst_cluster, lot_id, cpu, mem,
                    valid_from, valid_until, src["proof_generation"], dst["proof_generation"],
                    at, deadline, REQUESTED, at, displaces_reservation))
        db.execute("INSERT INTO transfer_deliveries VALUES(?,?,?,?,?,?,?,?,?,?)",
                   (transfer_id + ":delivery", transfer_id, dst_cluster, "entitlement",
                    replica, cpu, mem, None, deadline, "expected"))
        return event(db, event_id, "transfer.request", payload, REQUESTED)


# ---------------------------------------------------------------- customer sign-off

def customer_signoff(db, event_id, signoff_id, transfer_id, reservation_id, verdict, at):
    if verdict not in ("released", "refused") or at < 0:
        return "invalid_signoff"
    payload = dict(signoff_id=signoff_id, transfer_id=transfer_id,
                   reservation_id=reservation_id, verdict=verdict, at=at)
    with transaction(db):
        old = one(db, "SELECT * FROM events WHERE id=?", (event_id,))
        if old:
            return event(db, event_id, "transfer.signoff", payload, old["verdict"])
        if one(db, "SELECT id FROM transfer_signoffs WHERE id=?", (signoff_id,)):
            return event(db, event_id, "transfer.signoff", payload, "signoff_exists")
        tr = one(db, "SELECT * FROM transfers WHERE id=?", (transfer_id,))
        if not tr:
            return event(db, event_id, "transfer.signoff", payload, "unknown_transfer")
        stored_verdict = verdict
        result = verdict
        if tr["state"] in TERMINAL:
            # A late signature is evidence and must be retained, never applied.
            stored_verdict = "late:" + verdict
            result = "late_signoff_kept"
            db.execute("INSERT INTO transfer_notices VALUES(?,?,?,?,?)",
                       (signoff_id + ":notice", transfer_id, "late_signoff", at,
                        f"signoff {verdict} for {reservation_id} arrived after {tr['state']}"))
        db.execute("INSERT INTO transfer_signoffs VALUES(?,?,?,?,?)",
                   (signoff_id, transfer_id, reservation_id, stored_verdict, at))
        return event(db, event_id, "transfer.signoff", payload, result)


# ---------------------------------------------------------------- internals

def _notice(db, transfer_id, kind, at, detail):
    db.execute("INSERT INTO transfer_notices VALUES(?,?,?,?,?)",
               (f"{transfer_id}:{kind}:{at}", transfer_id, kind, at, detail))


def _lot_funding_matches(db, lot, reservation_id):
    f = one(db, "SELECT * FROM funding WHERE reservation_id=?", (reservation_id,))
    if not f:
        return False
    if lot["kind"] == "budget":
        return f["source_kind"] == "budget"
    return f["source_kind"] == lot["kind"] and f["source_id"] == lot["source_ref"]


def _overlapping_unstarted(db, lot, valid_from):
    """Unstarted, unreleased reservations whose lease overlaps the transfer window
    and whose fixed funding source is the lot's original entitlement."""
    out = []
    for r in rows(db, "SELECT r.* FROM reservations r JOIN requests q ON q.id=r.request_id "
                      "WHERE r.started=0 AND r.released=0 AND r.lease_until>?", (valid_from,)):
        if _lot_funding_matches(db, lot, r["id"]):
            out.append(r)
    return out


def _active_lot_usage(db, lot):
    """Capacity of live reservations whose fixed funding source is this lot."""
    if lot["kind"] == "budget":
        row = one(db, """SELECT COALESCE(SUM(q.cpu),0) cpu,COALESCE(SUM(q.mem),0) mem
            FROM funding f JOIN reservations r ON r.id=f.reservation_id
            JOIN requests q ON q.id=r.request_id
            WHERE f.source_kind='budget' AND q.tenant=? AND r.released=0""",
                  (lot["tenant"],))
    else:
        row = one(db, """SELECT COALESCE(SUM(q.cpu),0) cpu,COALESCE(SUM(q.mem),0) mem
            FROM funding f JOIN reservations r ON r.id=f.reservation_id
            JOIN requests q ON q.id=r.request_id
            WHERE f.source_kind=? AND f.source_id=? AND r.released=0""",
                  (lot["kind"], lot["source_ref"]))
    return row["cpu"], row["mem"]


def _earmarked(db, lot_id):
    row = one(db, "SELECT COALESCE(SUM(cpu),0) cpu,COALESCE(SUM(mem),0) mem FROM transfer_earmarks "
                  "WHERE lot_id=? AND status!=?", (lot_id, EARMARK_RELEASED))
    return row["cpu"], row["mem"]


def _node_free(db, node_id):
    n = one(db, "SELECT * FROM cluster_nodes WHERE id=?", (node_id,))
    seats = one(db, "SELECT COALESCE(SUM(cpu),0) cpu,COALESCE(SUM(mem),0) mem FROM transfer_seats "
                    "WHERE node_id=? AND status!=?", (node_id, SEAT_RELEASED))
    res = one(db, """SELECT COALESCE(SUM(q.cpu),0) cpu,COALESCE(SUM(q.mem),0) mem
        FROM reservations r JOIN requests q ON q.id=r.request_id
        WHERE r.node_id=? AND r.released=0""", (node_id,))
    return n["cpu"] - seats["cpu"] - res["cpu"], n["mem"] - seats["mem"] - res["mem"]


def _pick_node(db, cluster, cpu, mem):
    for n in rows(db, "SELECT * FROM cluster_nodes WHERE cluster=? ORDER BY id", (cluster,)):
        free_cpu, free_mem = _node_free(db, n["id"])
        if free_cpu >= cpu and free_mem >= mem:
            return n
    return None


def _rollback_prepared(db, tr, at, reason):
    db.execute("UPDATE transfer_earmarks SET status=? WHERE transfer_id=?",
               (EARMARK_RELEASED, tr["id"]))
    db.execute("UPDATE transfer_seats SET status=? WHERE transfer_id=?",
               (SEAT_RELEASED, tr["id"]))
    db.execute("UPDATE cluster_lots SET status=? WHERE id=?",
               (LOT_VOID, tr["id"] + ":dst_lot"))
    db.execute("UPDATE transfer_deliveries SET status='withdrawn' WHERE transfer_id=? AND status='expected'",
               (tr["id"],))
    _notice(db, tr["id"], "rejected", at, reason)


# ---------------------------------------------------------------- source prepare

def prepare_source(db, event_id, transfer_id, release_reservations, at):
    if at < 0:
        return "invalid_transfer"
    release_reservations = tuple(release_reservations or ())
    payload = dict(transfer_id=transfer_id, release_reservations=list(release_reservations), at=at)
    with transaction(db):
        old = one(db, "SELECT * FROM events WHERE id=?", (event_id,))
        if old:
            return event(db, event_id, "transfer.prepare", payload, old["verdict"])
        tr = one(db, "SELECT * FROM transfers WHERE id=?", (transfer_id,))
        if not tr:
            return event(db, event_id, "transfer.prepare", payload, "unknown_transfer")
        if tr["state"] != REQUESTED:
            return event(db, event_id, "transfer.prepare", payload, tr["state"])
        if at > tr["deadline"]:
            return event(db, event_id, "transfer.prepare", payload, "deadline_exceeded")

        # Independent capacity proof of the source control plane.
        src = one(db, "SELECT * FROM clusters WHERE id=?", (tr["src_cluster"],))
        if src["proof_generation"] != tr["src_proof_generation"]:
            return event(db, event_id, "transfer.prepare", payload, "source_capacity_stale")
        lot = one(db, "SELECT * FROM cluster_lots WHERE id=?", (tr["lot_id"],))
        if not lot or lot["status"] != LOT_ACTIVE:
            return event(db, event_id, "transfer.prepare", payload, "source_lot_unavailable")

        # Re-verify the resource original instead of trusting the registration snapshot.
        if lot["kind"] == "budget":
            b = one(db, "SELECT * FROM budget_history WHERE tenant=? AND effective<=? "
                        "ORDER BY effective DESC,revision DESC LIMIT 1", (lot["tenant"], at))
            frozen = one(db, "SELECT frozen FROM tenant_state WHERE tenant=?", (lot["tenant"],))
            if frozen and frozen["frozen"]:
                return event(db, event_id, "transfer.prepare", payload, "tenant_frozen")
            if not b or b["cpu"] < lot["cpu"] or b["mem"] < lot["mem"]:
                return event(db, event_id, "transfer.prepare", payload, "budget_reduced")
        elif lot["kind"] == "grant":
            g = one(db, "SELECT * FROM grants WHERE id=? AND revoked=0", (lot["source_ref"],))
            if not g or g["until_ts"] < tr["valid_until"] or g["until_ts"] <= at:
                return event(db, event_id, "transfer.prepare", payload, "grant_expired")
        else:
            ln = one(db, "SELECT * FROM loans WHERE id=?", (lot["source_ref"],))
            if not ln or ln["due"] <= at or ln["due"] < tr["valid_until"] \
                    or ln["cpu"] - ln["repaid_cpu"] < lot["cpu"] \
                    or ln["mem"] - ln["repaid_mem"] < lot["mem"]:
                return event(db, event_id, "transfer.prepare", payload, "loan_expired")
        if at >= tr["valid_until"]:
            return event(db, event_id, "transfer.prepare", payload, "window_closed")

        # Releasing an unstarted reservation requires: right lease, interruptible,
        # same fixed funding source, and a customer release signature.
        named = tr["displaces_reservation"]
        wanted = set(release_reservations)
        if named:
            wanted.add(named)
        # An explicit customer refusal on the named reservation forces the fallback path.
        if named:
            refusal = one(db, "SELECT * FROM transfer_signoffs WHERE transfer_id=? AND reservation_id=? "
                              "AND verdict='refused'", (transfer_id, named))
            if refusal:
                return event(db, event_id, "transfer.prepare", payload, "customer_refused_release")
        for rid in sorted(wanted):
            r = one(db, "SELECT * FROM reservations WHERE id=?", (rid,))
            if not r or r["released"]:
                return event(db, event_id, "transfer.prepare", payload, "unknown_active_reservation")
            q = one(db, "SELECT * FROM requests WHERE id=?", (r["request_id"],))
            if r["started"]:
                return event(db, event_id, "transfer.prepare", payload, "source_reservation_committed")
            if not q["interruptible"]:
                return event(db, event_id, "transfer.prepare", payload, "reservation_not_interruptible")
            if r["lease_until"] <= tr["valid_from"]:
                return event(db, event_id, "transfer.prepare", payload, "lease_outside_window")
            if not _lot_funding_matches(db, lot, rid):
                return event(db, event_id, "transfer.prepare", payload, "reservation_not_from_lot")
            sign = one(db, "SELECT * FROM transfer_signoffs WHERE transfer_id=? AND reservation_id=? "
                           "AND verdict='released'", (transfer_id, rid))
            if not sign or sign["at"] > at:
                return event(db, event_id, "transfer.prepare", payload, "awaiting_customer_release")
        # Any other unstarted reservation still drawing on this lot blocks the transfer.
        blockers = [r["id"] for r in _overlapping_unstarted(db, lot, tr["valid_from"])
                    if r["id"] not in wanted]
        if blockers:
            return event(db, event_id, "transfer.prepare", payload, "uncommitted_reservation_blocks")

        for rid in sorted(wanted):
            db.execute("UPDATE reservations SET released=1 WHERE id=?", (rid,))
            _notice(db, transfer_id, "replica_withdrawn", at, f"reservation {rid} seat returned")

        used_cpu, used_mem = _active_lot_usage(db, lot)
        mark_cpu, mark_mem = _earmarked(db, lot["id"])
        free_cpu = lot["cpu"] - used_cpu - mark_cpu
        free_mem = lot["mem"] - used_mem - mark_mem
        if free_cpu < tr["cpu"] or free_mem < tr["mem"]:
            return event(db, event_id, "transfer.prepare", payload, "source_entitlement_busy")

        # Independent capacity proof of the destination control plane + a real seat.
        dst = one(db, "SELECT * FROM clusters WHERE id=?", (tr["dst_cluster"],))
        if dst["proof_generation"] != tr["dst_proof_generation"]:
            return event(db, event_id, "transfer.prepare", payload, "target_capacity_stale")
        node = _pick_node(db, tr["dst_cluster"], tr["cpu"], tr["mem"])
        if not node:
            _notice(db, transfer_id, "rejected", at, "no destination node seat")
            db.execute("UPDATE transfer_deliveries SET status='withdrawn' WHERE transfer_id=? AND status='expected'",
                       (transfer_id,))
            db.execute("UPDATE transfers SET state=?,updated_at=? WHERE id=?",
                       (TARGET_FAILED, at, transfer_id))
            return event(db, event_id, "transfer.prepare", payload, "target_no_capacity")

        earmark_id = transfer_id + ":earmark"
        seat_id = transfer_id + ":seat"
        target_lot_id = transfer_id + ":dst_lot"
        db.execute("INSERT INTO transfer_earmarks VALUES(?,?,?,?,?,?,?,?)",
                   (earmark_id, transfer_id, tr["src_cluster"], lot["id"], tr["cpu"], tr["mem"],
                    EARMARK_HELD, at))
        db.execute("INSERT INTO transfer_seats VALUES(?,?,?,?,?,?,?,?,?,?)",
                   (seat_id, transfer_id, tr["dst_cluster"], node["id"], node["zone"],
                    tr["cpu"], tr["mem"], SEAT_RESERVED, node["generation"], at))
        db.execute("INSERT INTO cluster_lots VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (target_lot_id, tr["dst_cluster"], tr["tenant"], lot["kind"], tr["cpu"], tr["mem"],
                    tr["valid_from"], tr["valid_until"], LOT_PROMISED, tr["src_cluster"], lot["id"],
                    lot["due"], lot["floor_cpu"], lot["floor_mem"]))
        db.execute("UPDATE transfers SET state=?,updated_at=? WHERE id=?",
                   (SOURCE_PREPARED, at, transfer_id))
        return event(db, event_id, "transfer.prepare", payload, SOURCE_PREPARED)


# ---------------------------------------------------------------- destination ack

def target_ack(db, event_id, transfer_id, confirmed, at):
    if at < 0:
        return "invalid_transfer"
    payload = dict(transfer_id=transfer_id, confirmed=bool(confirmed), at=at)
    with transaction(db):
        old = one(db, "SELECT * FROM events WHERE id=?", (event_id,))
        if old:
            return event(db, event_id, "transfer.target_ack", payload, old["verdict"])
        tr = one(db, "SELECT * FROM transfers WHERE id=?", (transfer_id,))
        if not tr:
            return event(db, event_id, "transfer.target_ack", payload, "unknown_transfer")
        if tr["state"] != SOURCE_PREPARED:
            return event(db, event_id, "transfer.target_ack", payload, tr["state"])

        if not confirmed:
            _rollback_prepared(db, tr, at, "destination rejected the entitlement")
            db.execute("UPDATE transfers SET state=?,updated_at=? WHERE id=?",
                       (TARGET_FAILED, at, transfer_id))
            return event(db, event_id, "transfer.target_ack", payload, TARGET_FAILED)

        # Lost/duplicate/shrink protection: re-prove the destination before committing.
        dst = one(db, "SELECT * FROM clusters WHERE id=?", (tr["dst_cluster"],))
        if dst["proof_generation"] != tr["dst_proof_generation"]:
            _rollback_prepared(db, tr, at, "destination proof generation changed")
            db.execute("UPDATE transfers SET state=?,updated_at=? WHERE id=?",
                       (TARGET_FAILED, at, transfer_id))
            return event(db, event_id, "transfer.target_ack", payload, "target_capacity_lost")
        seat = one(db, "SELECT * FROM transfer_seats WHERE transfer_id=?", (transfer_id,))
        node = one(db, "SELECT * FROM cluster_nodes WHERE id=?", (seat["node_id"],))
        if node["generation"] != seat["generation"]:
            _rollback_prepared(db, tr, at, "destination node shrunk: generation changed")
            db.execute("UPDATE transfers SET state=?,updated_at=? WHERE id=?",
                       (TARGET_FAILED, at, transfer_id))
            return event(db, event_id, "transfer.target_ack", payload, "target_capacity_lost")
        free_cpu, free_mem = _node_free(db, seat["node_id"])
        # The reserved seat itself already counts in _node_free, so capacity must stay non-negative.
        if free_cpu < 0 or free_mem < 0:
            _rollback_prepared(db, tr, at, "destination node shrunk below the reserved seat")
            db.execute("UPDATE transfers SET state=?,updated_at=? WHERE id=?",
                       (TARGET_FAILED, at, transfer_id))
            return event(db, event_id, "transfer.target_ack", payload, "target_capacity_lost")

        # Commit both legs in one transaction: the same units cannot be promised twice.
        db.execute("UPDATE transfer_earmarks SET status=? WHERE transfer_id=?",
                   (EARMARK_COMMITTED, transfer_id))
        db.execute("UPDATE transfer_seats SET status=? WHERE transfer_id=?",
                   (SEAT_HELD, transfer_id))
        db.execute("UPDATE cluster_lots SET status=? WHERE id=?",
                   (LOT_ACTIVE, transfer_id + ":dst_lot"))
        lot = one(db, "SELECT * FROM cluster_lots WHERE id=?", (tr["lot_id"],))
        remaining_cpu = lot["cpu"] - tr["cpu"]
        remaining_mem = lot["mem"] - tr["mem"]
        if remaining_cpu <= 0 or remaining_mem <= 0:
            db.execute("UPDATE cluster_lots SET status=?,cpu=?,mem=? WHERE id=?",
                       (LOT_TRANSFERRED, remaining_cpu, remaining_mem, lot["id"]))
        else:
            db.execute("UPDATE cluster_lots SET cpu=?,mem=? WHERE id=?",
                       (remaining_cpu, remaining_mem, lot["id"]))
        db.execute("UPDATE transfers SET state=?,updated_at=? WHERE id=?",
                   (COMMITTED, at, transfer_id))
        _notice(db, transfer_id, "accepted", at,
                f"destination {tr['dst_cluster']} accepted {tr['cpu']} cpu/{tr['mem']} mem until {tr['valid_until']}")
        return event(db, event_id, "transfer.target_ack", payload, COMMITTED)


# ---------------------------------------------------------------- delivery

def start_delivery(db, event_id, transfer_id, at):
    if at < 0:
        return "invalid_transfer"
    payload = dict(transfer_id=transfer_id, at=at)
    with transaction(db):
        old = one(db, "SELECT * FROM events WHERE id=?", (event_id,))
        if old:
            return event(db, event_id, "transfer.deliver", payload, old["verdict"])
        tr = one(db, "SELECT * FROM transfers WHERE id=?", (transfer_id,))
        if not tr:
            return event(db, event_id, "transfer.deliver", payload, "unknown_transfer")
        if tr["state"] != COMMITTED:
            return event(db, event_id, "transfer.deliver", payload, tr["state"])
        on_time = at <= tr["deadline"]
        db.execute("UPDATE transfer_seats SET status=? WHERE transfer_id=?",
                   (SEAT_OCCUPIED, transfer_id))
        db.execute("UPDATE transfer_deliveries SET status='received',delivered_at=? "
                   "WHERE transfer_id=? AND status='expected'", (at, transfer_id))
        db.execute("UPDATE transfers SET state=?,updated_at=? WHERE id=?",
                   (DELIVERED, at, transfer_id))
        db.execute("INSERT INTO transfer_billing VALUES(?,?,?,?,?,?,?)",
                   (transfer_id + ":bill", transfer_id, "transfer", tr["cpu"], tr["mem"],
                    "transferred_entitlement", at))
        verdict = "delivered_on_time" if on_time else "delivered_late"
        if not on_time:
            _notice(db, transfer_id, "deadline_missed", at,
                    f"committed delivery at {at} missed deadline {tr['deadline']}")
            db.execute("INSERT INTO transfer_billing VALUES(?,?,?,?,?,?,?)",
                       (transfer_id + ":compensation", transfer_id, "compensation", tr["cpu"], tr["mem"],
                        "service_credit", at))
        return event(db, event_id, "transfer.deliver", payload, verdict)


# ---------------------------------------------------------------- cancellation

def cancel_transfer(db, event_id, transfer_id, at, reason):
    if at < 0:
        return "invalid_transfer"
    payload = dict(transfer_id=transfer_id, at=at, reason=reason)
    with transaction(db):
        old = one(db, "SELECT * FROM events WHERE id=?", (event_id,))
        if old:
            return event(db, event_id, "transfer.cancel", payload, old["verdict"])
        tr = one(db, "SELECT * FROM transfers WHERE id=?", (transfer_id,))
        if not tr:
            return event(db, event_id, "transfer.cancel", payload, "unknown_transfer")
        if tr["state"] not in OPEN_STATES:
            # Received deliveries and original confirmations stay untouched.
            return event(db, event_id, "transfer.cancel", payload, tr["state"])
        if tr["state"] == SOURCE_PREPARED:
            _rollback_prepared(db, tr, at, reason)
        else:
            db.execute("UPDATE transfer_deliveries SET status='withdrawn' WHERE transfer_id=? AND status='expected'",
                       (transfer_id,))
        db.execute("UPDATE transfers SET state=?,updated_at=? WHERE id=?",
                   (CANCELLED, at, transfer_id))
        _notice(db, transfer_id, "cancelled", at, reason)
        return event(db, event_id, "transfer.cancel", payload, CANCELLED)


# ---------------------------------------------------------------- fallback purchase

def fallback_purchase(db, event_id, transfer_id, purchase_lot_id, cpu, mem,
                      valid_until, at, replica=None, node_id=None):
    if cpu <= 0 or mem <= 0 or valid_until <= at or at < 0:
        return "invalid_purchase"
    payload = dict(transfer_id=transfer_id, purchase_lot_id=purchase_lot_id, cpu=cpu, mem=mem,
                   valid_until=valid_until, at=at, replica=replica, node_id=node_id)
    with transaction(db):
        old = one(db, "SELECT * FROM events WHERE id=?", (event_id,))
        if old:
            return event(db, event_id, "transfer.fallback_purchase", payload, old["verdict"])
        tr = one(db, "SELECT * FROM transfers WHERE id=?", (transfer_id,))
        if not tr:
            return event(db, event_id, "transfer.fallback_purchase", payload, "unknown_transfer")
        if tr["state"] not in (REQUESTED, TARGET_FAILED, CANCELLED):
            return event(db, event_id, "transfer.fallback_purchase", payload, tr["state"])
        received = one(db, "SELECT id FROM transfer_deliveries WHERE transfer_id=? AND status='received'",
                       (transfer_id,))
        if received:
            return event(db, event_id, "transfer.fallback_purchase", payload, "delivery_exists")

        # Independent new entitlement: explicitly separate from the original lot.
        db.execute("INSERT INTO cluster_lots VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (purchase_lot_id, tr["dst_cluster"], tr["tenant"], "purchase", cpu, mem,
                    at, valid_until, LOT_ACTIVE, None, purchase_lot_id, None, 0, 0))
        if node_id:
            node = one(db, "SELECT * FROM cluster_nodes WHERE id=? AND cluster=?",
                       (node_id, tr["dst_cluster"]))
            if not node:
                return event(db, event_id, "transfer.fallback_purchase", payload, "unknown_node")
        else:
            node = _pick_node(db, tr["dst_cluster"], cpu, mem)
        if not node:
            db.execute("DELETE FROM cluster_lots WHERE id=?", (purchase_lot_id,))
            return event(db, event_id, "transfer.fallback_purchase", payload, "target_no_capacity")
        free_cpu, free_mem = _node_free(db, node["id"])
        if free_cpu < cpu or free_mem < mem:
            db.execute("DELETE FROM cluster_lots WHERE id=?", (purchase_lot_id,))
            return event(db, event_id, "transfer.fallback_purchase", payload, "target_no_capacity")

        db.execute("INSERT INTO transfer_seats VALUES(?,?,?,?,?,?,?,?,?,?)",
                   (transfer_id + ":purchase_seat", transfer_id, tr["dst_cluster"], node["id"],
                    node["zone"], cpu, mem, SEAT_HELD, node["generation"], at))
        db.execute("INSERT INTO transfer_deliveries VALUES(?,?,?,?,?,?,?,?,?,?)",
                   (transfer_id + ":purchase_delivery", transfer_id, tr["dst_cluster"], "purchase",
                    replica, cpu, mem, None, tr["deadline"], "expected"))
        db.execute("UPDATE transfers SET state=?,updated_at=? WHERE id=?",
                   (FALLBACK_PURCHASED, at, transfer_id))
        _notice(db, transfer_id, "deadline_missed", at,
                f"original deadline {tr['deadline']} missed; replica covered by independent purchase")
        db.execute("INSERT INTO transfer_billing VALUES(?,?,?,?,?,?,?)",
                   (transfer_id + ":compensation", transfer_id, "compensation", cpu, mem,
                    "service_credit", at))
        return event(db, event_id, "transfer.fallback_purchase", payload, FALLBACK_PURCHASED)


def start_purchase(db, event_id, transfer_id, at):
    if at < 0:
        return "invalid_purchase"
    payload = dict(transfer_id=transfer_id, at=at)
    with transaction(db):
        old = one(db, "SELECT * FROM events WHERE id=?", (event_id,))
        if old:
            return event(db, event_id, "transfer.start_purchase", payload, old["verdict"])
        tr = one(db, "SELECT * FROM transfers WHERE id=?", (transfer_id,))
        if not tr or tr["state"] != FALLBACK_PURCHASED:
            return event(db, event_id, "transfer.start_purchase", payload,
                         tr["state"] if tr else "unknown_transfer")
        db.execute("UPDATE transfer_seats SET status=? WHERE transfer_id=? AND status=?",
                   (SEAT_OCCUPIED, transfer_id, SEAT_HELD))
        db.execute("UPDATE transfer_deliveries SET status='received',delivered_at=? "
                   "WHERE transfer_id=? AND kind='purchase'", (at, transfer_id))
        db.execute("UPDATE transfers SET state=?,updated_at=? WHERE id=?",
                   (FALLBACK_DELIVERED, at, transfer_id))
        db.execute("INSERT INTO transfer_billing VALUES(?,?,?,?,?,?,?)",
                   (transfer_id + ":purchase_bill", transfer_id, "purchase", tr["cpu"], tr["mem"],
                   "new_purchase", at))
        purchase = one(db, "SELECT * FROM transfer_deliveries WHERE transfer_id=? AND kind='purchase'",
                       (transfer_id,))
        # Timeliness is judged against the customer's original promise, preserved on the row.
        verdict = "purchased_on_time" if at <= purchase["deadline"] else "purchased_after_missed_deadline"
        _notice(db, transfer_id, "accepted", at,
                f"purchased replica delivered at {at}; original transfer was never committed")
        return event(db, event_id, "transfer.start_purchase", payload, verdict)


# ---------------------------------------------------------------- read models

def cluster_entitlement(db, cluster, tenant, at):
    """Redeemable capacity per entitlement kind — kinds are never blended."""
    result = {}
    for lot in rows(db, "SELECT * FROM cluster_lots WHERE cluster=? AND tenant=? AND status=? "
                        "AND valid_from<=? AND valid_until>?",
                    (cluster, tenant, LOT_ACTIVE, at, at)):
        bucket = result.setdefault(lot["kind"], {"cpu": 0, "mem": 0, "lots": []})
        bucket["cpu"] += lot["cpu"]
        bucket["mem"] += lot["mem"]
        bucket["lots"].append(lot["id"])
    # Only held (uncommitted) earmarks are subtracted here: on commit the source
    # lot itself is reduced, so subtracting the committed earmark would count twice.
    for earmark in rows(db, "SELECT * FROM transfer_earmarks WHERE cluster=? AND status=?",
                        (cluster, EARMARK_HELD)):
        lot = one(db, "SELECT * FROM cluster_lots WHERE id=?", (earmark["lot_id"],))
        if not lot or lot["tenant"] != tenant:
            continue
        bucket = result.setdefault(lot["kind"], {"cpu": 0, "mem": 0, "lots": []})
        bucket["cpu"] -= earmark["cpu"]
        bucket["mem"] -= earmark["mem"]
    return result


def transfer_view(db, transfer_id):
    tr = one(db, "SELECT * FROM transfers WHERE id=?", (transfer_id,))
    if not tr:
        return None
    return {
        "transfer": tr,
        "earmarks": rows(db, "SELECT * FROM transfer_earmarks WHERE transfer_id=? ORDER BY id", (transfer_id,)),
        "seats": rows(db, "SELECT * FROM transfer_seats WHERE transfer_id=? ORDER BY id", (transfer_id,)),
        "signoffs": rows(db, "SELECT * FROM transfer_signoffs WHERE transfer_id=? ORDER BY at,id", (transfer_id,)),
        "deliveries": rows(db, "SELECT * FROM transfer_deliveries WHERE transfer_id=? ORDER BY id", (transfer_id,)),
        "notices": rows(db, "SELECT * FROM transfer_notices WHERE transfer_id=? ORDER BY at,id", (transfer_id,)),
        "billing": rows(db, "SELECT * FROM transfer_billing WHERE transfer_id=? ORDER BY id", (transfer_id,)),
    }


def customer_outcome(db, transfer_id):
    view = transfer_view(db, transfer_id)
    if not view:
        return None
    received = [d for d in view["deliveries"] if d["status"] == "received"]
    return {
        "transfer_id": transfer_id,
        "state": view["transfer"]["state"],
        "delivered": [
            {
                "replica": d["replica"], "cluster": d["cluster"], "kind": d["kind"],
                "cpu": d["cpu"], "mem": d["mem"], "delivered_at": d["delivered_at"],
                "deadline": d["deadline"], "on_time": d["delivered_at"] is not None
                and d["delivered_at"] <= d["deadline"],
            } for d in received
        ],
        "withdrawn": [d["id"] for d in view["deliveries"] if d["status"] == "withdrawn"],
        "notices": [(n["kind"], n["at"]) for n in view["notices"]],
        "billing": [(b["kind"], b["amount"], b["at"]) for b in view["billing"]],
        "signoffs": [(s["reservation_id"], s["verdict"], s["at"]) for s in view["signoffs"]],
    }
