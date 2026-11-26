import json
import sqlite3
from contextlib import contextmanager


SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, kind TEXT NOT NULL, payload TEXT NOT NULL, verdict TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS budgets(tenant TEXT PRIMARY KEY, cpu INTEGER NOT NULL, mem INTEGER NOT NULL, revision INTEGER NOT NULL, effective INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS budget_history(tenant TEXT NOT NULL,revision INTEGER NOT NULL,cpu INTEGER NOT NULL,mem INTEGER NOT NULL,effective INTEGER NOT NULL,PRIMARY KEY(tenant,revision));
CREATE TABLE IF NOT EXISTS grants(id TEXT PRIMARY KEY, tenant TEXT NOT NULL, cpu INTEGER NOT NULL, mem INTEGER NOT NULL, until_ts INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS tenant_state(tenant TEXT PRIMARY KEY, seq INTEGER NOT NULL, frozen INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS nodes(id TEXT PRIMARY KEY, zone TEXT NOT NULL, cpu INTEGER NOT NULL, mem INTEGER NOT NULL, generation INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY, tenant TEXT NOT NULL, grp TEXT NOT NULL, cpu INTEGER NOT NULL, mem INTEGER NOT NULL, interruptible INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS reservations(id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, node_id TEXT NOT NULL, source TEXT NOT NULL, lease_until INTEGER NOT NULL, started INTEGER NOT NULL DEFAULT 0, released INTEGER NOT NULL DEFAULT 0, generation INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS group_policy(grp TEXT PRIMARY KEY, min_alive INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS shrink_cases(id TEXT PRIMARY KEY, grp TEXT NOT NULL, reservation_id TEXT NOT NULL, verdict TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS offers(id TEXT PRIMARY KEY, lender TEXT NOT NULL, cpu INTEGER NOT NULL, mem INTEGER NOT NULL, floor_cpu INTEGER NOT NULL, floor_mem INTEGER NOT NULL, until_ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS loans(id TEXT PRIMARY KEY, offer_id TEXT NOT NULL, borrower TEXT NOT NULL, cpu INTEGER NOT NULL, mem INTEGER NOT NULL, due INTEGER NOT NULL, repaid_cpu INTEGER NOT NULL DEFAULT 0, repaid_mem INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS repayments(id TEXT PRIMARY KEY, loan_id TEXT NOT NULL, cpu INTEGER NOT NULL, mem INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS funding(reservation_id TEXT PRIMARY KEY, source_kind TEXT NOT NULL, source_id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reclaim(id TEXT PRIMARY KEY, loan_id TEXT NOT NULL, requested_cpu INTEGER NOT NULL, requested_mem INTEGER NOT NULL, shortage_cpu INTEGER NOT NULL, shortage_mem INTEGER NOT NULL, status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rate_cards(version TEXT PRIMARY KEY, run_micro INTEGER NOT NULL, commit_micro INTEGER NOT NULL, effective INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS meter_slices(id TEXT PRIMARY KEY, node_id TEXT NOT NULL, start_min INTEGER NOT NULL, end_min INTEGER NOT NULL, amount_micro INTEGER NOT NULL, received_at INTEGER NOT NULL, superseded_by TEXT);
CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY, node_id TEXT NOT NULL, start_min INTEGER NOT NULL, end_min INTEGER NOT NULL, amount_micro INTEGER NOT NULL, confirmed_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS contracts(reservation_id TEXT PRIMARY KEY, tenant TEXT NOT NULL, mode TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS start_docs(id TEXT PRIMARY KEY, reservation_id TEXT NOT NULL, actual_start INTEGER NOT NULL, received_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS release_docs(id TEXT PRIMARY KEY, reservation_id TEXT NOT NULL, released_at INTEGER NOT NULL, received_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS yield_agreements(id TEXT PRIMARY KEY, loan_id TEXT NOT NULL, lender TEXT NOT NULL, borrower TEXT NOT NULL, amount_micro INTEGER NOT NULL, agreed_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS period_closes(id TEXT PRIMARY KEY, start_min INTEGER NOT NULL, end_min INTEGER NOT NULL, closed_at INTEGER NOT NULL, snapshot TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS invoices(id TEXT PRIMARY KEY, tenant TEXT NOT NULL, period_start INTEGER NOT NULL, period_end INTEGER NOT NULL, issued_at INTEGER NOT NULL, status TEXT NOT NULL, UNIQUE(tenant,period_start,period_end));
CREATE TABLE IF NOT EXISTS invoice_lines(invoice_id TEXT NOT NULL, seq INTEGER NOT NULL, kind TEXT NOT NULL, ref TEXT NOT NULL, start_min INTEGER NOT NULL, end_min INTEGER NOT NULL, units INTEGER NOT NULL, rate_version TEXT, amount_micro INTEGER NOT NULL, PRIMARY KEY(invoice_id,seq));
CREATE TABLE IF NOT EXISTS vouchers(id TEXT PRIMARY KEY, invoice_id TEXT NOT NULL, kind TEXT NOT NULL, cause TEXT NOT NULL, issued_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS voucher_lines(voucher_id TEXT NOT NULL, seq INTEGER NOT NULL, kind TEXT NOT NULL, ref TEXT NOT NULL, start_min INTEGER NOT NULL, end_min INTEGER NOT NULL, units INTEGER NOT NULL, rate_version TEXT, amount_micro INTEGER NOT NULL, PRIMARY KEY(voucher_id,seq));
CREATE TABLE IF NOT EXISTS payments(id TEXT PRIMARY KEY, invoice_id TEXT NOT NULL, tenant TEXT NOT NULL, amount_micro INTEGER NOT NULL, received_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS disputes(id TEXT PRIMARY KEY, invoice_id TEXT NOT NULL, tenant TEXT NOT NULL, reason TEXT NOT NULL, claim TEXT, status TEXT NOT NULL, filed_at INTEGER NOT NULL, resolution TEXT, voucher_id TEXT);
CREATE TABLE IF NOT EXISTS audit_log(seq INTEGER PRIMARY KEY AUTOINCREMENT,table_name TEXT NOT NULL,row_id INTEGER NOT NULL,action TEXT NOT NULL,payload TEXT);
"""

BUSINESS_TABLES = [
    "events", "budgets", "budget_history", "grants", "tenant_state", "nodes", "requests",
    "reservations", "group_policy", "shrink_cases", "offers", "loans",
    "repayments", "funding", "reclaim",
    "rate_cards", "meter_slices", "incidents", "contracts", "start_docs", "release_docs",
    "yield_agreements", "period_closes", "invoices", "invoice_lines", "vouchers",
    "voucher_lines", "payments", "disputes",
]


def open_db(path):
    db = sqlite3.connect(path, timeout=10)
    db.row_factory = sqlite3.Row
    db.executescript(SCHEMA)
    for table in BUSINESS_TABLES:
        cols = [r["name"] for r in db.execute(f"PRAGMA table_info({table})")]
        for action, ref in (("insert", "NEW"), ("update", "NEW"), ("delete", "OLD")):
            fields = ",".join(f"'{c}',{ref}.\"{c}\"" for c in cols)
            db.execute(f"""CREATE TRIGGER IF NOT EXISTS audit_{table}_{action} AFTER {action.upper()} ON {table}
                BEGIN INSERT INTO audit_log(table_name,row_id,action,payload)
                VALUES('{table}',{ref}.rowid,'{action}',json_object({fields})); END""")
    return db


@contextmanager
def transaction(db):
    db.execute("BEGIN IMMEDIATE")
    try:
        yield
    except Exception:
        db.rollback()
        raise
    else:
        db.commit()


def one(db, sql, args=()):
    row = db.execute(sql, args).fetchone()
    return dict(row) if row else None


def rows(db, sql, args=()):
    return [dict(x) for x in db.execute(sql, args)]


def event(db, event_id, kind, payload, verdict):
    old = one(db, "SELECT * FROM events WHERE id=?", (event_id,))
    if old:
        if old["kind"] != kind or json.loads(old["payload"]) != payload:
            raise ValueError("event id reused with different content")
        return old["verdict"]
    db.execute("INSERT INTO events VALUES(?,?,?,?)", (event_id, kind, json.dumps(payload, ensure_ascii=False, sort_keys=True), verdict))
    return verdict


def report(db):
    state = {
        "budgets": rows(db, "SELECT * FROM budgets ORDER BY tenant"),
        "budget_history": rows(db, "SELECT * FROM budget_history ORDER BY tenant,revision"),
        "grants": rows(db, "SELECT * FROM grants ORDER BY id"),
        "nodes": rows(db, "SELECT * FROM nodes ORDER BY id"),
        "reservations": rows(db, "SELECT * FROM reservations ORDER BY id"),
        "loans": rows(db, "SELECT * FROM loans ORDER BY id"),
        "reclaim": rows(db, "SELECT * FROM reclaim ORDER BY id"),
        "events": rows(db, "SELECT * FROM events ORDER BY id"),
        "rate_cards": rows(db, "SELECT * FROM rate_cards ORDER BY version"),
        "meter_slices": rows(db, "SELECT * FROM meter_slices ORDER BY id"),
        "incidents": rows(db, "SELECT * FROM incidents ORDER BY id"),
        "contracts": rows(db, "SELECT * FROM contracts ORDER BY reservation_id"),
        "start_docs": rows(db, "SELECT * FROM start_docs ORDER BY id"),
        "release_docs": rows(db, "SELECT * FROM release_docs ORDER BY id"),
        "yield_agreements": rows(db, "SELECT * FROM yield_agreements ORDER BY id"),
        "period_closes": rows(db, "SELECT * FROM period_closes ORDER BY id"),
        "invoices": rows(db, "SELECT * FROM invoices ORDER BY id"),
        "invoice_lines": rows(db, "SELECT * FROM invoice_lines ORDER BY invoice_id,seq"),
        "vouchers": rows(db, "SELECT * FROM vouchers ORDER BY id"),
        "voucher_lines": rows(db, "SELECT * FROM voucher_lines ORDER BY voucher_id,seq"),
        "payments": rows(db, "SELECT * FROM payments ORDER BY id"),
        "disputes": rows(db, "SELECT * FROM disputes ORDER BY id"),
    }
    state["audit_replay"] = verify_replay(db)
    return state


def verify_replay(db):
    """Rebuild each current entity from durable row events and compare it with SQLite state."""
    reconstructed = {name: {} for name in BUSINESS_TABLES}
    for record in rows(db, "SELECT * FROM audit_log ORDER BY seq"):
        table = reconstructed[record["table_name"]]
        if record["action"] == "delete":
            table.pop(record["row_id"], None)
        else:
            table[record["row_id"]] = json.loads(record["payload"])
    mismatches = []
    for name in BUSINESS_TABLES:
        actual = {row["rowid"]: {k: v for k, v in row.items() if k != "rowid"}
                  for row in rows(db, f"SELECT rowid,* FROM {name}")}
        if actual != reconstructed[name]:
            mismatches.append(name)
    return {"consistent": not mismatches, "mismatches": mismatches,
            "events": one(db, "SELECT COUNT(*) n FROM audit_log")["n"]}
