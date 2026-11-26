from .budget import available
from .store import event, one, rows, transaction


def node(db, node_id, zone, cpu, mem, generation=1):
    if cpu < 0 or mem < 0 or generation <= 0 or not zone:
        return "invalid_capacity"
    with transaction(db):
        old = one(db, "SELECT * FROM nodes WHERE id=?", (node_id,))
        if old and generation <= old["generation"]:
            same=(old["zone"],old["cpu"],old["mem"],old["generation"])==(zone,cpu,mem,generation)
            return "accepted" if same else "stale_capacity"
        db.execute("INSERT INTO nodes VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET zone=excluded.zone,cpu=excluded.cpu,mem=excluded.mem,generation=excluded.generation", (node_id, zone, cpu, mem, generation))
        return "accepted"


def request(db, request_id, tenant, grp, cpu, mem, interruptible=True):
    if cpu <= 0 or mem <= 0 or not tenant or not grp:
        return "invalid_request"
    with transaction(db):
        old = one(db, "SELECT * FROM requests WHERE id=?", (request_id,))
        if old:
            expected=dict(tenant=tenant,grp=grp,cpu=cpu,mem=mem,interruptible=int(interruptible))
            return "exists" if all(old[k]==v for k,v in expected.items()) else "conflicting_request"
        db.execute("INSERT INTO requests VALUES(?,?,?,?,?,?)", (request_id, tenant, grp, cpu, mem, int(interruptible)))
        return "accepted"


def free_on_node(db, node_id):
    n = one(db, "SELECT * FROM nodes WHERE id=?", (node_id,))
    used = one(db, """SELECT COALESCE(SUM(q.cpu),0) cpu, COALESCE(SUM(q.mem),0) mem
      FROM reservations r JOIN requests q ON q.id=r.request_id WHERE r.node_id=? AND r.released=0""", (node_id,))
    return n["cpu"] - used["cpu"], n["mem"] - used["mem"]


def place(db, event_id, reservation_id, request_id, lease_until, at):
    if at < 0 or lease_until <= at:
        return "invalid_lease_window"
    payload = dict(reservation_id=reservation_id, request_id=request_id, lease_until=lease_until, at=at)
    with transaction(db):
        old = one(db, "SELECT * FROM events WHERE id=?", (event_id,))
        if old:
            return event(db, event_id, "reserve.place", payload, old["verdict"])
        q = one(db, "SELECT * FROM requests WHERE id=?", (request_id,))
        if not q:
            return event(db, event_id, "reserve.place", payload, "unknown_request")
        if one(db, "SELECT id FROM reservations WHERE request_id=?", (request_id,)):
            return event(db, event_id, "reserve.place", payload, "already_reserved")
        # A failed emergency post-review arms a tenant-wide hold: stop new reservations.
        hold = one(db, "SELECT * FROM reservation_holds WHERE tenant=? AND lifted_at IS NULL",
                   (q["tenant"],))
        if hold:
            return event(db, event_id, "reserve.place", payload, "new_reservations_blocked")
        avail_cpu, avail_mem, state = available(db, q["tenant"], at)
        emergency = None
        if state != "available":
            return event(db, event_id, "reserve.place", payload, "entitlement_denied")
        if avail_cpu < q["cpu"] or avail_mem < q["mem"]:
            # The only lawful way to cover the deficit is a valid emergency authorization;
            # it may back an interruptible, time-boxed seat, never a phantom permanent budget.
            from .approval import match_emergency
            match = match_emergency(db, q["tenant"], q["cpu"], q["mem"], at,
                                    lease_until, q["interruptible"])
            if match is None:
                verdict = "entitlement_denied"
            elif match.get("ok"):
                emergency = match
                verdict = None
            else:
                verdict = match.get("code") or "entitlement_denied"
            if emergency is None:
                return event(db, event_id, "reserve.place", payload, verdict)
        if emergency is None:
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
                if emergency is not None:
                    em = emergency["auth"]
                    # Unique funding source preserved; the whole seat is attributable to the
                    # emergency case while the draw ledger tracks only the marginal extra cap.
                    db.execute("INSERT INTO funding VALUES(?,?,?)",
                               (reservation_id, "emergency", em["id"]))
                    db.execute("UPDATE reservations SET source=? WHERE id=?",
                               ("emergency:" + em["id"], reservation_id))
                    db.execute("INSERT INTO emergency_draws VALUES(?,?,?,?,?,?,?)",
                               (reservation_id, em["id"], q["tenant"],
                                emergency["draw_cpu"], emergency["draw_mem"], at, 0))
                else:
                    from .loan import allocate
                    source=allocate(db,reservation_id,at,in_transaction=True)
                    if source=="no_valid_source":
                        db.execute("DELETE FROM reservations WHERE id=?",(reservation_id,))
                        return event(db,event_id,"reserve.place",payload,"no_valid_source")
                return event(db, event_id, "reserve.place", payload, f"reserved:{n['id']}")
        return event(db, event_id, "reserve.place", payload, "no_distinct_capacity")


def start(db, event_id, reservation_id, generation, at):
    if at < 0 or generation <= 0:
        return "invalid_start"
    payload = dict(reservation_id=reservation_id, generation=generation, at=at)
    with transaction(db):
        r = one(db, "SELECT * FROM reservations WHERE id=?", (reservation_id,))
        if not r:
            return event(db, event_id, "reserve.start", payload, "unknown_reservation")
        if generation != r["generation"] or r["released"] or at > r["lease_until"]:
            return event(db, event_id, "reserve.start", payload, "late_or_stale")
        if not one(db, "SELECT * FROM funding WHERE reservation_id=?", (reservation_id,)):
            return event(db, event_id, "reserve.start", payload, "unfunded_reservation")
        db.execute("UPDATE reservations SET started=1 WHERE id=?", (reservation_id,))
        return event(db, event_id, "reserve.start", payload, "started")


def expire(db, at):
    with transaction(db):
        ids = [x["id"] for x in rows(db, "SELECT id FROM reservations WHERE started=0 AND released=0 AND lease_until<?", (at,))]
        for rid in ids:
            db.execute("UPDATE reservations SET released=1 WHERE id=?", (rid,))
        return ids


def policy(db, grp, min_alive):
    if min_alive < 0:
        return "invalid_group_policy"
    with transaction(db):
        db.execute("INSERT INTO group_policy VALUES(?,?) ON CONFLICT(grp) DO UPDATE SET min_alive=excluded.min_alive", (grp, min_alive))


def shrink(db, case_id, reservation_id):
    with transaction(db):
        old = one(db, "SELECT * FROM shrink_cases WHERE id=?", (case_id,))
        if old:
            return old["verdict"] if old["reservation_id"]==reservation_id else "case_identity_conflict"
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
