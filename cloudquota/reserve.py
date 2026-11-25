from .budget import available
from .store import event, one, rows, transaction


def node(db, node_id, zone, cpu, mem, generation=1):
    with transaction(db):
        old = one(db, "SELECT * FROM nodes WHERE id=?", (node_id,))
        if old and generation <= old["generation"]:
            return "stale_capacity"
        db.execute("INSERT INTO nodes VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET zone=excluded.zone,cpu=excluded.cpu,mem=excluded.mem,generation=excluded.generation", (node_id, zone, cpu, mem, generation))
        return "accepted"


def request(db, request_id, tenant, grp, cpu, mem, interruptible=True):
    with transaction(db):
        old = one(db, "SELECT * FROM requests WHERE id=?", (request_id,))
        if old:
            return "exists" if all(old[k] == v for k, v in dict(tenant=tenant, grp=grp, cpu=cpu, mem=mem).items()) else "conflicting_request"
        db.execute("INSERT INTO requests VALUES(?,?,?,?,?,?)", (request_id, tenant, grp, cpu, mem, int(interruptible)))
        return "accepted"


def free_on_node(db, node_id):
    n = one(db, "SELECT * FROM nodes WHERE id=?", (node_id,))
    used = one(db, """SELECT COALESCE(SUM(q.cpu),0) cpu, COALESCE(SUM(q.mem),0) mem
      FROM reservations r JOIN requests q ON q.id=r.request_id WHERE r.node_id=? AND r.released=0""", (node_id,))
    return n["cpu"] - used["cpu"], n["mem"] - used["mem"]


def place(db, event_id, reservation_id, request_id, lease_until, at):
    payload = dict(reservation_id=reservation_id, request_id=request_id, lease_until=lease_until, at=at)
    with transaction(db):
        if one(db, "SELECT * FROM events WHERE id=?", (event_id,)):
            return one(db, "SELECT verdict FROM events WHERE id=?", (event_id,))["verdict"]
        q = one(db, "SELECT * FROM requests WHERE id=?", (request_id,))
        if not q:
            return event(db, event_id, "reserve.place", payload, "unknown_request")
        if one(db, "SELECT id FROM reservations WHERE request_id=?", (request_id,)):
            return event(db, event_id, "reserve.place", payload, "already_reserved")
        avail_cpu, avail_mem, state = available(db, q["tenant"], at)
        if state != "available" or avail_cpu < q["cpu"] or avail_mem < q["mem"]:
            return event(db, event_id, "reserve.place", payload, "entitlement_denied")
        end_cpu, end_mem, end_state = available(db, q["tenant"], lease_until)
        if end_state != "available" or end_cpu < q["cpu"] or end_mem < q["mem"]:
            return event(db, event_id, "reserve.place", payload, "source_expires_before_lease")
        occupied = {x["zone"] for x in rows(db, """SELECT n.zone FROM reservations r JOIN requests q ON q.id=r.request_id
            JOIN nodes n ON n.id=r.node_id WHERE q.grp=? AND r.released=0""", (q["grp"],))}
        for n in rows(db, "SELECT * FROM nodes ORDER BY id"):
            if n["zone"] in occupied:
                continue
            free_cpu, free_mem = free_on_node(db, n["id"])
            if free_cpu >= q["cpu"] and free_mem >= q["mem"]:
                db.execute("INSERT INTO reservations VALUES(?,?,?,?,?,?,?,?)", (reservation_id, request_id, n["id"], "unallocated", lease_until, 0, 0, n["generation"]))
                return event(db, event_id, "reserve.place", payload, f"reserved:{n['id']}")
        return event(db, event_id, "reserve.place", payload, "no_distinct_capacity")


def start(db, event_id, reservation_id, generation, at):
    payload = dict(reservation_id=reservation_id, generation=generation, at=at)
    with transaction(db):
        r = one(db, "SELECT * FROM reservations WHERE id=?", (reservation_id,))
        if not r:
            return event(db, event_id, "reserve.start", payload, "unknown_reservation")
        if generation != r["generation"] or r["released"] or at > r["lease_until"]:
            return event(db, event_id, "reserve.start", payload, "late_or_stale")
        db.execute("UPDATE reservations SET started=1 WHERE id=?", (reservation_id,))
        return event(db, event_id, "reserve.start", payload, "started")


def expire(db, at):
    with transaction(db):
        ids = [x["id"] for x in rows(db, "SELECT id FROM reservations WHERE started=0 AND released=0 AND lease_until<?", (at,))]
        for rid in ids:
            db.execute("UPDATE reservations SET released=1 WHERE id=?", (rid,))
        return ids


def policy(db, grp, min_alive):
    with transaction(db):
        db.execute("INSERT INTO group_policy VALUES(?,?) ON CONFLICT(grp) DO UPDATE SET min_alive=excluded.min_alive", (grp, min_alive))


def shrink(db, case_id, reservation_id):
    with transaction(db):
        r = one(db, "SELECT r.*,q.grp FROM reservations r JOIN requests q ON q.id=r.request_id WHERE r.id=?", (reservation_id,))
        if not r or r["released"]:
            return "unknown_active_reservation"
        p = one(db, "SELECT * FROM group_policy WHERE grp=?", (r["grp"],))
        if not p:
            return "missing_group_policy"
        active = one(db, """SELECT COUNT(*) count FROM reservations r JOIN requests q ON q.id=r.request_id
            WHERE q.grp=? AND r.released=0""", (r["grp"],))["count"]
        verdict = "approved" if active - 1 >= p["min_alive"] else "quorum_violation"
        db.execute("INSERT INTO shrink_cases VALUES(?,?,?,?)", (case_id, r["grp"], reservation_id, verdict))
        if verdict == "approved":
            db.execute("UPDATE reservations SET released=1 WHERE id=?", (reservation_id,))
        return verdict
