from .store import event, one, rows, transaction


def revise(db, event_id, tenant, cpu, mem, revision, effective):
    if min(cpu, mem, revision) < 0:
        raise ValueError("negative budget")
    payload = dict(tenant=tenant, cpu=cpu, mem=mem, revision=revision, effective=effective)
    with transaction(db):
        old = one(db, "SELECT * FROM events WHERE id=?", (event_id,))
        if old:
            return old["verdict"]
        current = one(db, "SELECT * FROM budgets WHERE tenant=?", (tenant,))
        if current and revision <= current["revision"]:
            return event(db, event_id, "budget.revise", payload, "stale_revision")
        db.execute("INSERT INTO budget_history VALUES(?,?,?,?,?)",(tenant,revision,cpu,mem,effective))
        db.execute("INSERT INTO budgets VALUES(?,?,?,?,?) ON CONFLICT(tenant) DO UPDATE SET cpu=excluded.cpu,mem=excluded.mem,revision=excluded.revision,effective=excluded.effective", (tenant, cpu, mem, revision, effective))
        used = usage(db, tenant)
        verdict = "overcommitted" if used[0] > cpu or used[1] > mem else "accepted"
        return event(db, event_id, "budget.revise", payload, verdict)


def grant(db, event_id, grant_id, tenant, cpu, mem, until_ts):
    payload = dict(id=grant_id, tenant=tenant, cpu=cpu, mem=mem, until=until_ts)
    with transaction(db):
        if one(db, "SELECT id FROM events WHERE id=?", (event_id,)):
            return "accepted"
        if one(db, "SELECT id FROM grants WHERE id=?", (grant_id,)):
            return event(db, event_id, "budget.grant", payload, "grant_exists")
        db.execute("INSERT INTO grants(id,tenant,cpu,mem,until_ts) VALUES(?,?,?,?,?)", (grant_id, tenant, cpu, mem, until_ts))
        return event(db, event_id, "budget.grant", payload, "accepted")


def revoke(db, event_id, grant_id):
    payload = dict(grant_id=grant_id)
    with transaction(db):
        if not one(db, "SELECT id FROM grants WHERE id=?", (grant_id,)):
            return event(db, event_id, "budget.revoke", payload, "unknown_grant")
        db.execute("UPDATE grants SET revoked=1 WHERE id=?", (grant_id,))
        return event(db, event_id, "budget.revoke", payload, "revoked")


def status(db, event_id, tenant, seq, frozen):
    payload = dict(tenant=tenant, seq=seq, frozen=bool(frozen))
    with transaction(db):
        old = one(db, "SELECT * FROM tenant_state WHERE tenant=?", (tenant,))
        if old and seq <= old["seq"]:
            return event(db, event_id, "budget.status", payload, "stale_status")
        db.execute("INSERT INTO tenant_state VALUES(?,?,?) ON CONFLICT(tenant) DO UPDATE SET seq=excluded.seq,frozen=excluded.frozen", (tenant, seq, int(frozen)))
        return event(db, event_id, "budget.status", payload, "frozen" if frozen else "active")


def usage(db, tenant):
    row = one(db, """SELECT COALESCE(SUM(q.cpu),0) cpu,COALESCE(SUM(q.mem),0) mem
        FROM reservations r JOIN requests q ON q.id=r.request_id WHERE q.tenant=? AND r.released=0""", (tenant,))
    return row["cpu"], row["mem"]


def available(db, tenant, at):
    b = one(db, "SELECT * FROM budget_history WHERE tenant=? AND effective<=? ORDER BY effective DESC,revision DESC LIMIT 1", (tenant, at))
    state = one(db, "SELECT * FROM tenant_state WHERE tenant=?", (tenant,))
    if not b:
        return (0, 0, "no_budget")
    if state and state["frozen"]:
        return (0, 0, "frozen")
    grants = rows(db, "SELECT * FROM grants WHERE tenant=? AND until_ts>=? AND revoked=0", (tenant, at))
    cpu = b["cpu"] + sum(x["cpu"] for x in grants)
    mem = b["mem"] + sum(x["mem"] for x in grants)
    loans = rows(db, "SELECT * FROM loans WHERE borrower=? AND due>=?", (tenant, at))
    cpu += sum(x["cpu"] - x["repaid_cpu"] for x in loans)
    mem += sum(x["mem"] - x["repaid_mem"] for x in loans)
    used_cpu, used_mem = usage(db, tenant)
    return cpu - used_cpu, mem - used_mem, "available"


def borrowing_status(db, tenant, at):
    state = one(db, "SELECT frozen FROM tenant_state WHERE tenant=?", (tenant,))
    if state and state["frozen"]:
        return "borrower_frozen"
    overdue = one(db, "SELECT id FROM loans WHERE borrower=? AND due<? AND (cpu>repaid_cpu OR mem>repaid_mem)", (tenant, at))
    return "overdue_debt" if overdue else "eligible"
