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
CREATE TABLE IF NOT EXISTS clusters(id TEXT PRIMARY KEY, proof_generation INTEGER NOT NULL, proven_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS cluster_nodes(id TEXT PRIMARY KEY, cluster TEXT NOT NULL, zone TEXT NOT NULL, cpu INTEGER NOT NULL, mem INTEGER NOT NULL, generation INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS cluster_lots(id TEXT PRIMARY KEY, cluster TEXT NOT NULL, tenant TEXT NOT NULL, kind TEXT NOT NULL, cpu INTEGER NOT NULL, mem INTEGER NOT NULL, valid_from INTEGER NOT NULL, valid_until INTEGER NOT NULL, status TEXT NOT NULL, origin_cluster TEXT, source_ref TEXT, due INTEGER, floor_cpu INTEGER NOT NULL DEFAULT 0, floor_mem INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS transfers(id TEXT PRIMARY KEY, tenant TEXT NOT NULL, src_cluster TEXT NOT NULL, dst_cluster TEXT NOT NULL, lot_id TEXT NOT NULL, cpu INTEGER NOT NULL, mem INTEGER NOT NULL, valid_from INTEGER NOT NULL, valid_until INTEGER NOT NULL, src_proof_generation INTEGER NOT NULL, dst_proof_generation INTEGER NOT NULL, requested_at INTEGER NOT NULL, deadline INTEGER NOT NULL, state TEXT NOT NULL, updated_at INTEGER NOT NULL, displaces_reservation TEXT);
CREATE TABLE IF NOT EXISTS transfer_earmarks(id TEXT PRIMARY KEY, transfer_id TEXT NOT NULL, cluster TEXT NOT NULL, lot_id TEXT NOT NULL, cpu INTEGER NOT NULL, mem INTEGER NOT NULL, status TEXT NOT NULL, at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS transfer_seats(id TEXT PRIMARY KEY, transfer_id TEXT NOT NULL, cluster TEXT NOT NULL, node_id TEXT NOT NULL, zone TEXT NOT NULL, cpu INTEGER NOT NULL, mem INTEGER NOT NULL, status TEXT NOT NULL, generation INTEGER NOT NULL, at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS transfer_signoffs(id TEXT PRIMARY KEY, transfer_id TEXT NOT NULL, reservation_id TEXT, verdict TEXT NOT NULL, at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS transfer_deliveries(id TEXT PRIMARY KEY, transfer_id TEXT NOT NULL, cluster TEXT NOT NULL, kind TEXT NOT NULL, replica TEXT, cpu INTEGER NOT NULL, mem INTEGER NOT NULL, delivered_at INTEGER, deadline INTEGER, status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS transfer_notices(id TEXT PRIMARY KEY, transfer_id TEXT NOT NULL, kind TEXT NOT NULL, at INTEGER NOT NULL, detail TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS transfer_billing(id TEXT PRIMARY KEY, transfer_id TEXT NOT NULL, kind TEXT NOT NULL, cpu INTEGER NOT NULL, mem INTEGER NOT NULL, amount TEXT NOT NULL, at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log(seq INTEGER PRIMARY KEY AUTOINCREMENT,table_name TEXT NOT NULL,row_id INTEGER NOT NULL,action TEXT NOT NULL,payload TEXT);
"""

BUSINESS_TABLES = [
    "events", "budgets", "budget_history", "grants", "tenant_state", "nodes", "requests",
    "reservations", "group_policy", "shrink_cases", "offers", "loans",
    "repayments", "funding", "reclaim",
    "clusters", "cluster_nodes", "cluster_lots", "transfers", "transfer_earmarks",
    "transfer_seats", "transfer_signoffs", "transfer_deliveries", "transfer_notices",
    "transfer_billing",
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
        "clusters": rows(db, "SELECT * FROM clusters ORDER BY id"),
        "cluster_nodes": rows(db, "SELECT * FROM cluster_nodes ORDER BY id"),
        "cluster_lots": rows(db, "SELECT * FROM cluster_lots ORDER BY id"),
        "transfers": rows(db, "SELECT * FROM transfers ORDER BY id"),
        "transfer_earmarks": rows(db, "SELECT * FROM transfer_earmarks ORDER BY id"),
        "transfer_seats": rows(db, "SELECT * FROM transfer_seats ORDER BY id"),
        "transfer_signoffs": rows(db, "SELECT * FROM transfer_signoffs ORDER BY id"),
        "transfer_deliveries": rows(db, "SELECT * FROM transfer_deliveries ORDER BY id"),
        "transfer_notices": rows(db, "SELECT * FROM transfer_notices ORDER BY id"),
        "transfer_billing": rows(db, "SELECT * FROM transfer_billing ORDER BY id"),
        "events": rows(db, "SELECT * FROM events ORDER BY id"),
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
