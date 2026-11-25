from .budget import borrowing_status, usage
from .store import event, one, rows, transaction
from contextlib import nullcontext


def offer(db, offer_id, lender, cpu, mem, floor_cpu, floor_mem, until_ts):
    if cpu <= 0 or mem <= 0 or floor_cpu < 0 or floor_mem < 0 or until_ts <= 0:
        return "invalid_offer"
    with transaction(db):
        old=one(db,"SELECT * FROM offers WHERE id=?",(offer_id,))
        if old:
            expected=(lender,cpu,mem,floor_cpu,floor_mem,until_ts)
            actual=tuple(old[k] for k in ("lender","cpu","mem","floor_cpu","floor_mem","until_ts"))
            return "exists" if actual==expected else "offer_identity_conflict"
        db.execute("INSERT INTO offers VALUES(?,?,?,?,?,?,?)", (offer_id, lender, cpu, mem, floor_cpu, floor_mem, until_ts))
        return "accepted"


def issue(db, event_id, loan_id, offer_id, borrower, cpu, mem, due, at):
    if cpu <= 0 or mem <= 0 or at < 0 or due <= at:
        return "invalid_loan"
    payload = dict(loan_id=loan_id, offer_id=offer_id, borrower=borrower, cpu=cpu, mem=mem, due=due, at=at)
    with transaction(db):
        if one(db, "SELECT id FROM events WHERE id=?", (event_id,)):
            return one(db, "SELECT verdict FROM events WHERE id=?", (event_id,))["verdict"]
        eligibility = borrowing_status(db, borrower, at)
        if eligibility != "eligible":
            return event(db, event_id, "loan.issue", payload, eligibility)
        o = one(db, "SELECT * FROM offers WHERE id=?", (offer_id,))
        if not o or at > o["until_ts"] or due > o["until_ts"]:
            return event(db, event_id, "loan.issue", payload, "offer_expired")
        budget = one(db, "SELECT * FROM budget_history WHERE tenant=? AND effective<=? ORDER BY effective DESC,revision DESC LIMIT 1", (o["lender"], at))
        if not budget:
            return event(db, event_id, "loan.issue", payload, "lender_no_budget")
        used_cpu, used_mem = usage(db, o["lender"])
        other = one(db, "SELECT COALESCE(SUM(cpu-repaid_cpu),0) cpu,COALESCE(SUM(mem-repaid_mem),0) mem FROM loans WHERE offer_id=? AND due>=?", (offer_id, at))
        all_loans = one(db, """SELECT COALESCE(SUM(l.cpu-l.repaid_cpu),0) cpu,COALESCE(SUM(l.mem-l.repaid_mem),0) mem
            FROM loans l JOIN offers o ON o.id=l.offer_id WHERE o.lender=? AND l.due>=?""", (o["lender"], at))
        free_cpu = min(o["cpu"] - other["cpu"], budget["cpu"] - used_cpu - o["floor_cpu"] - all_loans["cpu"])
        free_mem = min(o["mem"] - other["mem"], budget["mem"] - used_mem - o["floor_mem"] - all_loans["mem"])
        if cpu > free_cpu or mem > free_mem:
            return event(db, event_id, "loan.issue", payload, "lender_floor")
        db.execute("INSERT INTO loans(id,offer_id,borrower,cpu,mem,due) VALUES(?,?,?,?,?,?)", (loan_id, offer_id, borrower, cpu, mem, due))
        return event(db, event_id, "loan.issue", payload, "issued")


def repay(db, receipt_id, loan_id, cpu, mem):
    if cpu < 0 or mem < 0 or (cpu == 0 and mem == 0):
        return "invalid_repayment"
    with transaction(db):
        old = one(db, "SELECT * FROM repayments WHERE id=?", (receipt_id,))
        if old:
            return "duplicate" if (old["loan_id"], old["cpu"], old["mem"]) == (loan_id, cpu, mem) else "receipt_conflict"
        loan = one(db, "SELECT * FROM loans WHERE id=?", (loan_id,))
        if not loan:
            return "unknown_loan"
        if cpu < 0 or mem < 0 or cpu > loan["cpu"] - loan["repaid_cpu"] or mem > loan["mem"] - loan["repaid_mem"]:
            return "overpayment"
        db.execute("INSERT INTO repayments VALUES(?,?,?,?)", (receipt_id, loan_id, cpu, mem))
        db.execute("UPDATE loans SET repaid_cpu=repaid_cpu+?,repaid_mem=repaid_mem+? WHERE id=?", (cpu, mem, loan_id))
        return "settled" if cpu == loan["cpu"] - loan["repaid_cpu"] and mem == loan["mem"] - loan["repaid_mem"] else "partial"


def allocate(db, reservation_id, at, in_transaction=False):
    with (nullcontext() if in_transaction else transaction(db)):
        r = one(db, """SELECT r.*,q.tenant,q.cpu,q.mem FROM reservations r JOIN requests q ON q.id=r.request_id WHERE r.id=?""", (reservation_id,))
        if not r or r["released"]:
            return "unknown_active_reservation"
        old = one(db, "SELECT * FROM funding WHERE reservation_id=?", (reservation_id,))
        if old:
            return old["source_kind"] + ":" + old["source_id"]
        b = one(db, "SELECT * FROM budget_history WHERE tenant=? AND effective<=? ORDER BY effective DESC,revision DESC LIMIT 1", (r["tenant"], at))
        # Funding is attributed per reservation. Existing allocations consume their own source.
        base_used = one(db, """SELECT COALESCE(SUM(q.cpu),0) cpu,COALESCE(SUM(q.mem),0) mem
          FROM funding f JOIN reservations r ON r.id=f.reservation_id JOIN requests q ON q.id=r.request_id
          WHERE q.tenant=? AND f.source_kind='budget' AND r.released=0""", (r["tenant"],))
        source = None
        if b and b["cpu"] - base_used["cpu"] >= r["cpu"] and b["mem"] - base_used["mem"] >= r["mem"]:
            source = ("budget", r["tenant"])
        if not source:
            for g in rows(db, "SELECT * FROM grants WHERE tenant=? AND revoked=0 AND until_ts>=? ORDER BY until_ts,id", (r["tenant"], r["lease_until"])):
                taken = one(db, """SELECT COALESCE(SUM(q.cpu),0) cpu,COALESCE(SUM(q.mem),0) mem FROM funding f
                   JOIN reservations r ON r.id=f.reservation_id JOIN requests q ON q.id=r.request_id
                   WHERE f.source_kind='grant' AND f.source_id=? AND r.released=0""", (g["id"],))
                if g["cpu"] - taken["cpu"] >= r["cpu"] and g["mem"] - taken["mem"] >= r["mem"]:
                    source = ("grant", g["id"]); break
        if not source:
            for l in rows(db, "SELECT * FROM loans WHERE borrower=? AND due>=? ORDER BY due,id", (r["tenant"], r["lease_until"])):
                taken = one(db, """SELECT COALESCE(SUM(q.cpu),0) cpu,COALESCE(SUM(q.mem),0) mem FROM funding f
                   JOIN reservations r ON r.id=f.reservation_id JOIN requests q ON q.id=r.request_id
                   WHERE f.source_kind='loan' AND f.source_id=? AND r.released=0""", (l["id"],))
                if l["cpu"] - l["repaid_cpu"] - taken["cpu"] >= r["cpu"] and l["mem"] - l["repaid_mem"] - taken["mem"] >= r["mem"]:
                    source = ("loan", l["id"]); break
        if not source:
            return "no_valid_source"
        db.execute("INSERT INTO funding VALUES(?,?,?)", (reservation_id, *source))
        db.execute("UPDATE reservations SET source=? WHERE id=?", (source[0] + ":" + source[1], reservation_id))
        return source[0] + ":" + source[1]


def reclaim(db, case_id, loan_id, need_cpu, need_mem):
    if need_cpu <= 0 or need_mem <= 0:
        return "invalid_reclaim"
    with transaction(db):
        loan = one(db, "SELECT * FROM loans WHERE id=?", (loan_id,))
        if not loan:
            return "unknown_loan"
        old = one(db, "SELECT * FROM reclaim WHERE id=?", (case_id,))
        if old:
            same=(old["loan_id"],old["requested_cpu"],old["requested_mem"])==(loan_id,need_cpu,need_mem)
            return old["status"] if same else "case_identity_conflict"
        deficit_cpu, deficit_mem = need_cpu, need_mem
        for r in rows(db, """SELECT r.id,q.cpu,q.mem FROM funding f JOIN reservations r ON r.id=f.reservation_id
            JOIN requests q ON q.id=r.request_id WHERE f.source_kind='loan' AND f.source_id=?
            AND r.started=0 AND r.released=0 AND q.interruptible=1 ORDER BY r.id""", (loan_id,)):
            if deficit_cpu <= 0 and deficit_mem <= 0:
                break
            db.execute("UPDATE reservations SET released=1 WHERE id=?", (r["id"],))
            deficit_cpu -= r["cpu"]; deficit_mem -= r["mem"]
        status = "complete" if deficit_cpu <= 0 and deficit_mem <= 0 else "shortfall"
        db.execute("INSERT INTO reclaim VALUES(?,?,?,?,?,?,?)", (case_id, loan_id, need_cpu, need_mem, max(0,deficit_cpu), max(0,deficit_mem), status))
        return status
