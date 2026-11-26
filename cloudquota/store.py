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
CREATE TABLE IF NOT EXISTS approval_principals(id TEXT PRIMARY KEY, name TEXT NOT NULL, roles TEXT NOT NULL DEFAULT '', secret TEXT, active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS tenant_control(tenant TEXT PRIMARY KEY, controller_id TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', at INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS principal_relations(id TEXT PRIMARY KEY, principal_a TEXT NOT NULL, principal_b TEXT NOT NULL, kind TEXT NOT NULL, at INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS approval_seats(id TEXT PRIMARY KEY, holder_id TEXT NOT NULL, domain TEXT NOT NULL, tenants TEXT NOT NULL DEFAULT '*', max_cpu INTEGER NOT NULL, max_mem INTEGER NOT NULL, valid_from INTEGER NOT NULL, valid_until INTEGER NOT NULL, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS approval_delegations(id TEXT PRIMARY KEY, seat_id TEXT NOT NULL, delegator_id TEXT NOT NULL, agent_id TEXT NOT NULL, granted_at INTEGER NOT NULL, revoked_at INTEGER, revoke_event TEXT, revoked_by TEXT);
CREATE TABLE IF NOT EXISTS budget_applications(id TEXT PRIMARY KEY, digest TEXT NOT NULL, tenant TEXT NOT NULL, base_revision INTEGER NOT NULL, cpu INTEGER NOT NULL, mem INTEGER NOT NULL, effective_from INTEGER NOT NULL, effective_until INTEGER, funding_account TEXT NOT NULL, applicant_id TEXT NOT NULL, required_approvals INTEGER NOT NULL DEFAULT 2, required_domains TEXT NOT NULL DEFAULT '', sign_before INTEGER, submitted_at INTEGER NOT NULL, status TEXT NOT NULL, status_reason TEXT, resulting_revision INTEGER, committed_at INTEGER, commit_event TEXT);
CREATE TABLE IF NOT EXISTS approval_signatures(id TEXT PRIMARY KEY, application_id TEXT NOT NULL, seat_id TEXT NOT NULL, signer_id TEXT NOT NULL, holder_id TEXT NOT NULL, delegation_id TEXT, digest TEXT NOT NULL, token TEXT, signed_at INTEGER NOT NULL, verified INTEGER NOT NULL DEFAULT 0, counted INTEGER NOT NULL DEFAULT 0, verdict TEXT NOT NULL, reason TEXT, UNIQUE(application_id, seat_id, signer_id));
CREATE TABLE IF NOT EXISTS budget_authority(tenant TEXT NOT NULL, revision INTEGER NOT NULL, authority_kind TEXT NOT NULL, application_id TEXT, emergency_id TEXT, actor TEXT, principals TEXT, digest TEXT, at INTEGER NOT NULL, verdict TEXT, PRIMARY KEY(tenant,revision));
CREATE TABLE IF NOT EXISTS emergency_incidents(id TEXT PRIMARY KEY, tenant TEXT NOT NULL, confirmed_by TEXT NOT NULL, confirmed_at INTEGER NOT NULL, requested_by TEXT, duty_lead INTEGER NOT NULL DEFAULT 1, note TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS emergency_auth(id TEXT PRIMARY KEY, tenant TEXT NOT NULL, incident_id TEXT NOT NULL, cpu_extra INTEGER NOT NULL, mem_extra INTEGER NOT NULL, effective_from INTEGER NOT NULL, expires_at INTEGER NOT NULL, requested_by TEXT NOT NULL, authorized_by TEXT NOT NULL, accountable_id TEXT NOT NULL, at INTEGER NOT NULL, status TEXT NOT NULL, reviewed_at INTEGER, reviewer_id TEXT, review_verdict TEXT, review_note TEXT);
CREATE TABLE IF NOT EXISTS emergency_draws(reservation_id TEXT PRIMARY KEY, emergency_id TEXT NOT NULL, tenant TEXT NOT NULL, cpu_draw INTEGER NOT NULL, mem_draw INTEGER NOT NULL, at INTEGER NOT NULL, released INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS emergency_dispositions(id TEXT PRIMARY KEY, emergency_id TEXT NOT NULL, reservation_id TEXT NOT NULL, kind TEXT NOT NULL, at INTEGER NOT NULL, detail TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS reservation_holds(tenant TEXT PRIMARY KEY, reason TEXT NOT NULL, source_kind TEXT, source_id TEXT, at INTEGER NOT NULL, lifted_at INTEGER);
CREATE TABLE IF NOT EXISTS audit_log(seq INTEGER PRIMARY KEY AUTOINCREMENT,table_name TEXT NOT NULL,row_id INTEGER NOT NULL,action TEXT NOT NULL,payload TEXT);
"""

BUSINESS_TABLES = [
    "events", "budgets", "budget_history", "grants", "tenant_state", "nodes", "requests",
    "reservations", "group_policy", "shrink_cases", "offers", "loans",
    "repayments", "funding", "reclaim",
    "approval_principals", "tenant_control", "principal_relations", "approval_seats",
    "approval_delegations", "budget_applications", "approval_signatures", "budget_authority",
    "emergency_incidents", "emergency_auth", "emergency_draws", "emergency_dispositions",
    "reservation_holds",
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
        "approval_principals": rows(db, "SELECT * FROM approval_principals ORDER BY id"),
        "tenant_control": rows(db, "SELECT * FROM tenant_control ORDER BY tenant"),
        "principal_relations": rows(db, "SELECT * FROM principal_relations ORDER BY id"),
        "approval_seats": rows(db, "SELECT * FROM approval_seats ORDER BY id"),
        "approval_delegations": rows(db, "SELECT * FROM approval_delegations ORDER BY id"),
        "budget_applications": rows(db, "SELECT * FROM budget_applications ORDER BY id"),
        "approval_signatures": rows(db, "SELECT * FROM approval_signatures ORDER BY id"),
        "budget_authority": rows(db, "SELECT * FROM budget_authority ORDER BY tenant,revision"),
        "emergency_incidents": rows(db, "SELECT * FROM emergency_incidents ORDER BY id"),
        "emergency_auth": rows(db, "SELECT * FROM emergency_auth ORDER BY id"),
        "emergency_draws": rows(db, "SELECT * FROM emergency_draws ORDER BY emergency_id,reservation_id"),
        "emergency_dispositions": rows(db, "SELECT * FROM emergency_dispositions ORDER BY id"),
        "reservation_holds": rows(db, "SELECT * FROM reservation_holds ORDER BY tenant"),
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
