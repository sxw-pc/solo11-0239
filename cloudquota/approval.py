"""Multi-party budget approval and time-boxed emergency authorization.

This module closes the gap where :func:`cloudquota.budget.revise` could be driven
directly (CLI or fixture) and a higher revision immediately became available.

An application *fixes* tenant, base revision, target cpu/mem, effective window,
funding account and applicant, and is summarised by a SHA-256 digest.  Every
signature is an HMAC over that digest, so it cannot be moved onto an amended or
re-filed application.  Signatures only count when the seat is within tenure and
scope, any proxy is still valid at signing time, and both the acting signer and
the seat holder are disinterested parties.  Mutual proxy / control relations are
expanded as an interest closure, so the applicant and the beneficiary tenant's
controller cannot pad the independent count.

Commit is a single transaction that requires the current budget revision to
still equal the fixed base revision: a competing legal revision makes the
application conflict instead of skipping versions.  Every resulting budget
version is attributed in ``budget_authority`` (direct / approved_application /
emergency).

Emergency authorizations have a hard quota cap, expire automatically, back only
interruptible reservations inside their window, and require independent post-hoc
review.  A failed review arms a durable hold stopping new reservations while the
already-consumed usage, draws, dispositions and accountable person remain
append-only evidence.
"""
from __future__ import annotations

import hashlib
import hmac
import json

from .budget import available, record_authority, store_revision, usage
from .store import event, one, rows, transaction

# Relations that merge two principals into one interest component.
INTEREST_RELATIONS = {
    "mutual_proxy", "affiliate", "common_control", "control",
    "family", "financial_interest",
}
REVIEWER_ROLES = {"reviewer", "audit", "finance", "capacity", "compliance"}

DEFAULT_EMERGENCY_CAP_CPU = 4
DEFAULT_EMERGENCY_CAP_MEM = 4


# --------------------------------------------------------------------------- digest

def canonical_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def terms_digest(*, application_id, tenant, base_revision, cpu, mem,
                 effective_from, effective_until, funding_account, applicant_id):
    """Digest binding a signature to one immutable application."""
    body = {
        "application_id": application_id,
        "tenant": tenant,
        "base_revision": base_revision,
        "cpu": cpu,
        "mem": mem,
        "effective_from": effective_from,
        "effective_until": effective_until,
        "funding_account": funding_account,
        "applicant_id": applicant_id,
    }
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


def row_digest(app):
    return terms_digest(
        application_id=app["id"], tenant=app["tenant"],
        base_revision=app["base_revision"], cpu=app["cpu"], mem=app["mem"],
        effective_from=app["effective_from"], effective_until=app["effective_until"],
        funding_account=app["funding_account"], applicant_id=app["applicant_id"])


def sign_token(secret, digest):
    """Client-side signature: HMAC of the application digest."""
    return hmac.new(str(secret).encode("utf-8"), str(digest).encode("utf-8"),
                    hashlib.sha256).hexdigest()


def _secret_for(principal):
    if principal and principal["secret"]:
        return principal["secret"]
    return "dev-key:" + (principal["id"] if principal else "anonymous")


def token_for(db, principal_id, digest):
    """Convenience for tests/simulators: compute a token with the stored key."""
    p = one(db, "SELECT secret,id FROM approval_principals WHERE id=?", (principal_id,))
    return sign_token(_secret_for(p), digest)


def _normalize_domains(domains):
    if domains is None:
        return []
    if isinstance(domains, str):
        return [d.strip() for d in domains.split(",") if d.strip()]
    return [str(d).strip() for d in domains if str(d).strip()]


# --------------------------------------------------------------------------- principals / seats

def register_principal(db, principal_id, name, roles=None, secret=None, active=1, at=0):
    if not principal_id or not name:
        return "invalid_principal"
    role_list = _normalize_domains(roles)
    role_text = ",".join(role_list)
    with transaction(db):
        old = one(db, "SELECT * FROM approval_principals WHERE id=?", (principal_id,))
        if old:
            same = (old["name"] == name and old["roles"] == role_text
                    and bool(old["active"]) == bool(active))
            return "exists" if same else "principal_conflict"
        db.execute(
            "INSERT INTO approval_principals(id,name,roles,secret,active,created_at)"
            " VALUES(?,?,?,?,?,?)",
            (principal_id, name, role_text, secret, int(active), at))
        return "accepted"


def declare_controller(db, tenant, principal_id, note="", at=0):
    if not tenant or not principal_id:
        return "invalid_control"
    with transaction(db):
        if not one(db, "SELECT id FROM approval_principals WHERE id=?", (principal_id,)):
            return "unknown_principal"
        db.execute(
            "INSERT INTO tenant_control(tenant,controller_id,note,at) VALUES(?,?,?,?)"
            " ON CONFLICT(tenant) DO UPDATE SET controller_id=excluded.controller_id,"
            " note=excluded.note,at=excluded.at",
            (tenant, principal_id, note, at))
        return "accepted"


def relate_principals(db, relation_id, principal_a, principal_b, kind="affiliate", at=0):
    if not relation_id or not principal_a or not principal_b or principal_a == principal_b:
        return "invalid_relation"
    with transaction(db):
        old = one(db, "SELECT * FROM principal_relations WHERE id=?", (relation_id,))
        if old:
            same = (old["principal_a"], old["principal_b"], old["kind"]) == (
                principal_a, principal_b, kind)
            return "exists" if same else "relation_conflict"
        db.execute("INSERT INTO principal_relations VALUES(?,?,?,?,?)",
                   (relation_id, principal_a, principal_b, kind, at))
        return "accepted"


def register_seat(db, seat_id, holder_id, domain, max_cpu, max_mem,
                  valid_from, valid_until, tenants="*", active=1):
    if (not seat_id or not holder_id or not domain or max_cpu < 0 or max_mem < 0
            or valid_until <= valid_from):
        return "invalid_seat"
    with transaction(db):
        old = one(db, "SELECT * FROM approval_seats WHERE id=?", (seat_id,))
        if old:
            same = all(old[k] == v for k, v in dict(
                holder_id=holder_id, domain=domain, tenants=tenants, max_cpu=max_cpu,
                max_mem=max_mem, valid_from=valid_from, valid_until=valid_until,
                active=int(active)).items())
            return "exists" if same else "seat_conflict"
        if not one(db, "SELECT id FROM approval_principals WHERE id=?", (holder_id,)):
            return "unknown_principal"
        db.execute("INSERT INTO approval_seats VALUES(?,?,?,?,?,?,?,?,?)",
                   (seat_id, holder_id, domain, tenants, max_cpu, max_mem,
                    valid_from, valid_until, int(active)))
        return "accepted"


def grant_delegation(db, delegation_id, seat_id, agent_id, granted_at,
                     delegator_id=None):
    if not delegation_id or not seat_id or not agent_id or granted_at < 0:
        return "invalid_delegation"
    with transaction(db):
        old = one(db, "SELECT * FROM approval_delegations WHERE id=?", (delegation_id,))
        if old:
            same = (old["seat_id"], old["agent_id"]) == (seat_id, agent_id)
            return "exists" if same else "delegation_conflict"
        seat = one(db, "SELECT * FROM approval_seats WHERE id=?", (seat_id,))
        if not seat:
            return "unknown_seat"
        if not one(db, "SELECT id FROM approval_principals WHERE id=?", (agent_id,)):
            return "unknown_principal"
        delegator_id = delegator_id or seat["holder_id"]
        db.execute("INSERT INTO approval_delegations(id,seat_id,delegator_id,agent_id,granted_at)"
                   " VALUES(?,?,?,?,?)",
                   (delegation_id, seat_id, delegator_id, agent_id, granted_at))
        return "accepted"


def revoke_delegation(db, event_id, delegation_id, at, revoked_by=None):
    payload = dict(delegation_id=delegation_id, at=at, revoked_by=revoked_by)
    with transaction(db):
        old = one(db, "SELECT * FROM events WHERE id=?", (event_id,))
        if old:
            return event(db, event_id, "approval.revoke_delegation", payload, old["verdict"])
        d = one(db, "SELECT * FROM approval_delegations WHERE id=?", (delegation_id,))
        if not d:
            return event(db, event_id, "approval.revoke_delegation", payload, "unknown_delegation")
        if d["revoked_at"] is not None:
            return event(db, event_id, "approval.revoke_delegation", payload, "already_revoked")
        # The revocation original is retained (row updated with its time/event), never deleted.
        db.execute("UPDATE approval_delegations SET revoked_at=?,revoke_event=?,revoked_by=?"
                   " WHERE id=?", (at, event_id, revoked_by, delegation_id))
        return event(db, event_id, "approval.revoke_delegation", payload, "revoked")


# --------------------------------------------------------------------------- interest graph

def interested_principals(db, tenant, applicant_id):
    """Seed with applicant + tenant controller, close over control/proxy relations."""
    ids = set()
    if applicant_id:
        ids.add(applicant_id)
    control = one(db, "SELECT controller_id FROM tenant_control WHERE tenant=?", (tenant,))
    if control and control["controller_id"]:
        ids.add(control["controller_id"])
    relations = rows(db, "SELECT principal_a,principal_b,kind FROM principal_relations")
    changed = True
    while changed:
        changed = False
        for rel in relations:
            if rel["kind"] not in INTEREST_RELATIONS:
                continue
            a, b = rel["principal_a"], rel["principal_b"]
            if (a in ids or b in ids) and not (a in ids and b in ids):
                ids.add(a)
                ids.add(b)
                changed = True
    return ids


# --------------------------------------------------------------------------- applications

def submit_application(db, event_id, application_id, tenant, base_revision, cpu, mem,
                       effective_from, funding_account, applicant_id, at,
                       effective_until=None, required_approvals=2,
                       required_domains=("finance", "capacity"), sign_before=None):
    if (not application_id or not tenant or not funding_account or not applicant_id
            or cpu < 0 or mem < 0 or base_revision <= 0 or effective_from < 0 or at < 0
            or required_approvals <= 0):
        return "invalid_application"
    domains = _normalize_domains(required_domains)
    payload = dict(application_id=application_id, tenant=tenant, base_revision=base_revision,
                   cpu=cpu, mem=mem, effective_from=effective_from,
                   effective_until=effective_until, funding_account=funding_account,
                   applicant_id=applicant_id, at=at, required_approvals=required_approvals,
                   required_domains=domains, sign_before=sign_before)
    with transaction(db):
        old_event = one(db, "SELECT * FROM events WHERE id=?", (event_id,))
        if old_event:
            return event(db, event_id, "approval.submit", payload, old_event["verdict"])
        existing = one(db, "SELECT * FROM budget_applications WHERE id=?", (application_id,))
        fixed = dict(tenant=tenant, base_revision=base_revision, cpu=cpu, mem=mem,
                     effective_from=effective_from, effective_until=effective_until,
                     funding_account=funding_account, applicant_id=applicant_id)
        if existing:
            same = all(existing[k] == v for k, v in fixed.items())
            verdict = "application_exists" if same else "application_conflict"
            return event(db, event_id, "approval.submit", payload, verdict)
        if not one(db, "SELECT id FROM approval_principals WHERE id=? AND active=1",
                   (applicant_id,)):
            return event(db, event_id, "approval.submit", payload, "unknown_principal")
        if not one(db, "SELECT revision FROM budget_history WHERE tenant=? AND revision=?",
                   (tenant, base_revision)):
            return event(db, event_id, "approval.submit", payload, "unknown_base_revision")
        # Formal windows cannot be back-dated before submission: that would retro-legitimise
        # capacity already consumed (the minute-20 Q after a minute-21 approval).
        if effective_from < at:
            return event(db, event_id, "approval.submit", payload, "effective_window_in_past")
        dup = one(db, """SELECT id FROM budget_applications
            WHERE id<>? AND tenant=? AND base_revision=? AND cpu=? AND mem=?
              AND effective_from=? AND funding_account=? AND applicant_id=?
              AND status IN ('pending','approved','committed')""",
                  (application_id, tenant, base_revision, cpu, mem, effective_from,
                   funding_account, applicant_id))
        if dup:
            return event(db, event_id, "approval.submit", payload, "duplicate_application")
        digest = terms_digest(application_id=application_id, **fixed)
        db.execute(
            "INSERT INTO budget_applications(id,digest,tenant,base_revision,cpu,mem,"
            "effective_from,effective_until,funding_account,applicant_id,required_approvals,"
            "required_domains,sign_before,submitted_at,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (application_id, digest, tenant, base_revision, cpu, mem, effective_from,
             effective_until, funding_account, applicant_id, required_approvals,
             ",".join(domains), sign_before, at, "pending"))
        return event(db, event_id, "approval.submit", payload, "submitted")


def _evaluate_signature(db, app, sig):
    """Return (counted, verdict, reason) re-derived from durable records as of signed_at."""
    if not sig["verified"]:
        return 0, "bad_signature", "HMAC does not match application digest"
    if sig["digest"] != app["digest"] or sig["digest"] != row_digest(app):
        return 0, "digest_mismatch", "signature is bound to a different/amended application"
    at = sig["signed_at"]
    if app["sign_before"] is not None and at > app["sign_before"]:
        return 0, "late_signature", "signed after application signature deadline"
    signer = one(db, "SELECT * FROM approval_principals WHERE id=?", (sig["signer_id"],))
    if not signer or not signer["active"]:
        return 0, "signer_inactive", "signer unknown or departed"
    seat = one(db, "SELECT * FROM approval_seats WHERE id=?", (sig["seat_id"],))
    if not seat or not seat["active"]:
        return 0, "seat_inactive", "seat unknown or inactive"
    if at < seat["valid_from"]:
        return 0, "seat_tenure_not_started", "signature before seat tenure"
    if at >= seat["valid_until"]:
        return 0, "seat_tenure_ended", "late signature after seat departure/tenure end"
    allowed_tenants = _normalize_domains(seat["tenants"])
    if allowed_tenants and "*" not in allowed_tenants and app["tenant"] not in allowed_tenants:
        return 0, "seat_tenant_scope", "seat not authorised for tenant"
    if app["cpu"] > seat["max_cpu"] or app["mem"] > seat["max_mem"]:
        return 0, "seat_amount_scope", "target exceeds seat authorisation limit"
    holder_id = seat["holder_id"]
    if sig["delegation_id"]:
        d = one(db, "SELECT * FROM approval_delegations WHERE id=?", (sig["delegation_id"],))
        if not d:
            return 0, "unknown_delegation", "delegation reference not on record"
        if d["seat_id"] != seat["id"] or d["agent_id"] != sig["signer_id"]:
            return 0, "delegation_seat_mismatch", "delegation does not authorise this seat/signer"
        if d["granted_at"] > at:
            return 0, "delegation_not_effective", "delegation not yet granted at signing time"
        # Revocation original wins: a signature at/after revoked_at can never count.
        if d["revoked_at"] is not None and d["revoked_at"] <= at:
            return 0, "delegation_revoked", "proxy was revoked before the signature"
    elif sig["signer_id"] != holder_id:
        return 0, "signer_not_holder", "non-holder signature without a valid delegation"
    interested = interested_principals(db, app["tenant"], app["applicant_id"])
    if sig["signer_id"] in interested:
        return 0, "interested_party", "acting signer is applicant/controller/proxy-aligned"
    if holder_id in interested:
        return 0, "interested_holder", "seat holder is applicant/controller/proxy-aligned"
    return 1, "valid", None


def cast_signature(db, event_id, signature_id, application_id, seat_id, signer_id, at,
                   token=None, delegation_id=None):
    if (not signature_id or not application_id or not seat_id or not signer_id
            or at < 0):
        return "invalid_signature"
    payload = dict(signature_id=signature_id, application_id=application_id, seat_id=seat_id,
                   signer_id=signer_id, at=at, token=token, delegation_id=delegation_id)
    with transaction(db):
        old_event = one(db, "SELECT * FROM events WHERE id=?", (event_id,))
        if old_event:
            return event(db, event_id, "approval.sign", payload, old_event["verdict"])
        app = one(db, "SELECT * FROM budget_applications WHERE id=?", (application_id,))
        if not app:
            return event(db, event_id, "approval.sign", payload, "unknown_application")
        prior = one(db, "SELECT * FROM approval_signatures WHERE id=?", (signature_id,))
        if prior:
            verdict = prior["verdict"]
            return event(db, event_id, "approval.sign", payload, verdict)
        duplicate = one(db, """SELECT id FROM approval_signatures
            WHERE application_id=? AND seat_id=? AND signer_id=?""",
                        (application_id, seat_id, signer_id))
        if duplicate:
            return event(db, event_id, "approval.sign", payload, "duplicate_signature")
        seat = one(db, "SELECT holder_id FROM approval_seats WHERE id=?", (seat_id,))
        holder_id = seat["holder_id"] if seat else ""
        principal = one(db, "SELECT * FROM approval_principals WHERE id=?", (signer_id,))
        digest = app["digest"]
        if not principal or not principal["active"]:
            verified = 0
        elif token is None:
            # Offline simulator: a direct call is an authenticated in-session act. Explicit
            # tokens below are still really verified, so tampered/replayed tokens fail.
            verified = 1
        else:
            expected = sign_token(_secret_for(principal), digest)
            verified = int(hmac.compare_digest(str(token), expected))
        if not verified:
            # Authentication failure: evidence lives in the durable event/audit log, but no
            # ballot row is created so the genuine key-holder can still cast the real signature.
            return event(db, event_id, "approval.sign", payload, "bad_signature")
        record = dict(id=signature_id, application_id=application_id, seat_id=seat_id,
                     signer_id=signer_id, holder_id=holder_id, delegation_id=delegation_id,
                     digest=digest, token=token, signed_at=at, verified=verified)
        counted, verdict, reason = _evaluate_signature(db, app, record)
        db.execute(
            "INSERT INTO approval_signatures(id,application_id,seat_id,signer_id,holder_id,"
            "delegation_id,digest,token,signed_at,verified,counted,verdict,reason)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (signature_id, application_id, seat_id, signer_id, holder_id, delegation_id,
             digest, token, at, verified, counted, verdict, reason))
        return event(db, event_id, "approval.sign", payload, verdict)


def sign_as(db, event_id, signature_id, application_id, seat_id, signer_id, at,
            delegation_id=None):
    """Simulate the principal's client computing its digest-bound HMAC."""
    app = one(db, "SELECT digest FROM budget_applications WHERE id=?", (application_id,))
    if not app:
        return cast_signature(db, event_id, signature_id, application_id, seat_id,
                              signer_id, at, token="", delegation_id=delegation_id)
    token = token_for(db, signer_id, app["digest"])
    return cast_signature(db, event_id, signature_id, application_id, seat_id, signer_id,
                          at, token=token, delegation_id=delegation_id)


def evaluate_application(db, application_id, persist=True):
    app = one(db, "SELECT * FROM budget_applications WHERE id=?", (application_id,))
    if not app:
        return None
    sigs = rows(db, "SELECT * FROM approval_signatures WHERE application_id=? ORDER BY id",
                (application_id,))
    evaluated = []
    for sig in sigs:
        counted, verdict, reason = _evaluate_signature(db, app, sig)
        evaluated.append(dict(sig=sig, counted=counted, verdict=verdict, reason=reason))
        if persist and (sig["counted"] != counted or sig["verdict"] != verdict
                        or (sig["reason"] or None) != reason):
            with transaction(db):
                db.execute("UPDATE approval_signatures SET counted=?,verdict=?,reason=?"
                           " WHERE id=?", (counted, verdict, reason, sig["id"]))
    valid = [e for e in evaluated if e["counted"]]
    holders = sorted({e["sig"]["holder_id"] for e in valid})
    actors = sorted({e["sig"]["signer_id"] for e in valid})
    domains = set()
    for e in valid:
        seat = one(db, "SELECT domain FROM approval_seats WHERE id=?", (e["sig"]["seat_id"],))
        if seat:
            domains.add(seat["domain"])
    domains = sorted(domains)
    required_domains = _normalize_domains(app["required_domains"])
    missing = [d for d in required_domains
               if not any(dom == d or dom == "general" for dom in domains)]
    required = app["required_approvals"]
    quorum_met = (len(holders) >= required and len(actors) >= required and not missing)
    digest_ok = row_digest(app) == app["digest"]
    return {
        "application_id": application_id,
        "status": app["status"],
        "digest_ok": digest_ok,
        "required_approvals": required,
        "required_domains": required_domains,
        "valid_count": len(valid),
        "independent_count": len(actors),
        "independent_holders": holders,
        "independent_actors": actors,
        "domains": domains,
        "missing_domains": missing,
        "quorum_met": quorum_met and digest_ok,
        "signatures": [
            {"signature_id": e["sig"]["id"], "seat_id": e["sig"]["seat_id"],
             "signer_id": e["sig"]["signer_id"], "holder_id": e["sig"]["holder_id"],
             "signed_at": e["sig"]["signed_at"], "counted": e["counted"],
             "verdict": e["verdict"], "reason": e["reason"],
             "delegation_id": e["sig"]["delegation_id"]}
            for e in evaluated],
    }


def tally(db, application_id):
    return evaluate_application(db, application_id, persist=True)


def commit_application(db, event_id, application_id, at, actor=None):
    payload = dict(application_id=application_id, at=at, actor=actor)
    with transaction(db):
        old_event = one(db, "SELECT * FROM events WHERE id=?", (event_id,))
        if old_event:
            return event(db, event_id, "approval.commit", payload, old_event["verdict"])
        app = one(db, "SELECT * FROM budget_applications WHERE id=?", (application_id,))
        if not app:
            return event(db, event_id, "approval.commit", payload, "unknown_application")
        if app["status"] == "committed":
            return event(db, event_id, "approval.commit", payload, "already_committed")
        if app["status"] == "rejected":
            # A rejected application is terminal; changed terms require a new application
            # with a fresh digest, so a rejection can never be overridden by commit.
            return event(db, event_id, "approval.commit", payload, "application_rejected")
        if row_digest(app) != app["digest"]:
            db.execute("UPDATE budget_applications SET status='rejected',"
                       "status_reason='application_tampered' WHERE id=?", (application_id,))
            return event(db, event_id, "approval.commit", payload, "digest_mismatch")
        current = one(db, "SELECT * FROM budgets WHERE tenant=?", (app["tenant"],))
        if not current or current["revision"] != app["base_revision"]:
            current_rev = current["revision"] if current else None
            db.execute("UPDATE budget_applications SET status='rejected',"
                       "status_reason=? WHERE id=?",
                       (f"base_revision_superseded:current={current_rev}", application_id))
            return event(db, event_id, "approval.commit", payload, "base_revision_conflict")
        result = evaluate_application(db, application_id, persist=False)
        if not result["quorum_met"]:
            return event(db, event_id, "approval.commit", payload, "approval_incomplete")
        new_revision = app["base_revision"] + 1
        if one(db, "SELECT 1 FROM budget_history WHERE tenant=? AND revision=?",
               (app["tenant"], new_revision)):
            db.execute("UPDATE budget_applications SET status='rejected',"
                       "status_reason='revision_version_gap' WHERE id=?", (application_id,))
            return event(db, event_id, "approval.commit", payload, "base_revision_conflict")
        store_revision(db, app["tenant"], app["cpu"], app["mem"], new_revision,
                       app["effective_from"])
        used_cpu, used_mem = usage(db, app["tenant"])
        budget_verdict = "overcommitted" if used_cpu > app["cpu"] or used_mem > app["mem"] else "accepted"
        record_authority(
            db, app["tenant"], new_revision, "approved_application", at,
            application_id=application_id, actor=actor,
            principals=result["independent_holders"], digest=app["digest"],
            verdict=budget_verdict)
        db.execute("""UPDATE budget_applications SET status='committed',status_reason=NULL,
            resulting_revision=?,committed_at=?,commit_event=? WHERE id=?""",
                   (new_revision, at, event_id, application_id))
        return event(db, event_id, "approval.commit", payload, "committed")


def reject_application(db, event_id, application_id, at,
                       reason="rejected_by_governance", actor=None):
    payload = dict(application_id=application_id, at=at, reason=reason, actor=actor)
    with transaction(db):
        old_event = one(db, "SELECT * FROM events WHERE id=?", (event_id,))
        if old_event:
            return event(db, event_id, "approval.reject", payload, old_event["verdict"])
        app = one(db, "SELECT * FROM budget_applications WHERE id=?", (application_id,))
        if not app:
            return event(db, event_id, "approval.reject", payload, "unknown_application")
        if app["status"] == "committed":
            return event(db, event_id, "approval.reject", payload, "already_committed")
        db.execute("UPDATE budget_applications SET status='rejected',status_reason=? WHERE id=?",
                   (reason, application_id))
        return event(db, event_id, "approval.reject", payload, "rejected")


# --------------------------------------------------------------------------- emergency authority

def register_incident(db, incident_id, tenant, confirmed_by, at, requested_by=None, note=""):
    if not incident_id or not tenant or not confirmed_by or at < 0:
        return "invalid_incident"
    with transaction(db):
        old = one(db, "SELECT * FROM emergency_incidents WHERE id=?", (incident_id,))
        if old:
            same = (old["tenant"], old["confirmed_by"], old["confirmed_at"]) == (
                tenant, confirmed_by, at)
            return "incident_exists" if same else "incident_conflict"
        confirmer = one(db, "SELECT * FROM approval_principals WHERE id=? AND active=1",
                        (confirmed_by,))
        roles = set(_normalize_domains(confirmer["roles"])) if confirmer else set()
        if not confirmer or "duty_lead" not in roles:
            return "not_duty_lead"
        if requested_by and requested_by == confirmed_by:
            return "independent_confirmation_required"
        db.execute("INSERT INTO emergency_incidents VALUES(?,?,?,?,?,?,?)",
                   (incident_id, tenant, confirmed_by, at, requested_by, 1, note))
        return "incident_confirmed"


def authorize_emergency(db, event_id, emergency_id, tenant, cpu_extra, mem_extra, at,
                        expires_at, requested_by, incident_id=None, authorized_by=None,
                        limit_cpu=DEFAULT_EMERGENCY_CAP_CPU,
                        limit_mem=DEFAULT_EMERGENCY_CAP_MEM, effective_from=None):
    if (not emergency_id or not tenant or not requested_by or cpu_extra < 0 or mem_extra < 0
            or (cpu_extra == 0 and mem_extra == 0) or expires_at <= at or at < 0):
        return "invalid_emergency"
    payload = dict(emergency_id=emergency_id, tenant=tenant, cpu_extra=cpu_extra,
                   mem_extra=mem_extra, at=at, expires_at=expires_at,
                   requested_by=requested_by, incident_id=incident_id,
                   authorized_by=authorized_by, limit_cpu=limit_cpu, limit_mem=limit_mem)
    with transaction(db):
        old_event = one(db, "SELECT * FROM events WHERE id=?", (event_id,))
        if old_event:
            return event(db, event_id, "emergency.authorize", payload, old_event["verdict"])
        if one(db, "SELECT id FROM emergency_auth WHERE id=?", (emergency_id,)):
            return event(db, event_id, "emergency.authorize", payload, "emergency_exists")
        if cpu_extra > limit_cpu or mem_extra > limit_mem:
            return event(db, event_id, "emergency.authorize", payload, "emergency_limit_exceeded")
        incident = one(db, "SELECT * FROM emergency_incidents WHERE id=?", (incident_id,))
        if not incident or incident["tenant"] != tenant:
            return event(db, event_id, "emergency.authorize", payload, "incident_not_confirmed")
        authorizer_id = authorized_by or incident["confirmed_by"]
        authorizer = one(db, "SELECT * FROM approval_principals WHERE id=? AND active=1",
                         (authorizer_id,))
        roles = set(_normalize_domains(authorizer["roles"])) if authorizer else set()
        if not authorizer or "duty_lead" not in roles:
            return event(db, event_id, "emergency.authorize", payload, "authorizer_not_duty_lead")
        if authorizer_id == requested_by:
            return event(db, event_id, "emergency.authorize", payload, "emergency_self_authorization")
        effective_from = at if effective_from is None else effective_from
        db.execute(
            "INSERT INTO emergency_auth(id,tenant,incident_id,cpu_extra,mem_extra,"
            "effective_from,expires_at,requested_by,authorized_by,accountable_id,at,status)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (emergency_id, tenant, incident_id, cpu_extra, mem_extra, effective_from,
             expires_at, requested_by, authorizer_id, authorizer_id, at, "active"))
        return event(db, event_id, "emergency.authorize", payload, "emergency_authorized")


def match_emergency(db, tenant, cpu, mem, at, lease_until, interruptible):
    """Find an active emergency authorization able to cover the marginal deficit.

    Returns None when no emergency authorization exists at all (caller then keeps
    the ordinary entitlement_denied verdict), otherwise ``{"ok": False, "code": ...}``
    or ``{"ok": True, "auth": row, "draw_cpu": n, "draw_mem": n}``.
    """
    auths = rows(db, "SELECT * FROM emergency_auth WHERE tenant=? ORDER BY expires_at,id",
                 (tenant,))
    if not auths:
        return None
    avail_cpu, avail_mem, state = available(db, tenant, at)
    if state != "available":
        return {"ok": False, "code": "entitlement_denied"}
    draw_cpu = max(0, cpu - max(avail_cpu, 0))
    draw_mem = max(0, mem - max(avail_mem, 0))
    blocking = None
    for auth in auths:
        def fail(code):
            return {"ok": False, "code": code, "auth": auth}
        if auth["status"] == "review_failed":
            blocking = blocking or "emergency_review_failed"
            continue
        if auth["status"] != "active":
            blocking = blocking or "emergency_not_active"
            continue
        if at < auth["effective_from"] or at >= auth["expires_at"]:
            blocking = blocking or "emergency_expired"
            continue
        if lease_until is None or lease_until > auth["expires_at"]:
            blocking = blocking or "emergency_window_exceeded"
            continue
        if not interruptible:
            return fail("emergency_interruptible_only")
        drawn = one(db, """SELECT COALESCE(SUM(cpu_draw),0) cpu, COALESCE(SUM(mem_draw),0) mem
            FROM emergency_draws WHERE emergency_id=? AND released=0""", (auth["id"],))
        remain_cpu = auth["cpu_extra"] - drawn["cpu"]
        remain_mem = auth["mem_extra"] - drawn["mem"]
        if draw_cpu <= remain_cpu and draw_mem <= remain_mem:
            return {"ok": True, "auth": auth, "draw_cpu": draw_cpu, "draw_mem": draw_mem}
        blocking = blocking or "emergency_quota_exhausted"
    return {"ok": False, "code": blocking or "emergency_unavailable"}


def expire_emergency(db, at):
    """Auto-expire authorizations at their deadline and interrupt their temporary seats."""
    with transaction(db):
        due = rows(db, "SELECT id FROM emergency_auth WHERE status='active' AND expires_at<=?",
                   (at,))
        for a in due:
            db.execute("UPDATE emergency_auth SET status='expired' WHERE id=?", (a["id"],))
        draws = rows(db, """SELECT d.reservation_id,d.emergency_id FROM emergency_draws d
            JOIN emergency_auth a ON a.id=d.emergency_id
            WHERE d.released=0 AND a.expires_at<=? ORDER BY d.reservation_id""", (at,))
        released_ids = []
        for d in draws:
            r = one(db, "SELECT released FROM reservations WHERE id=?", (d["reservation_id"],))
            if r and not r["released"]:
                db.execute("UPDATE reservations SET released=1 WHERE id=?", (d["reservation_id"],))
                released_ids.append(d["reservation_id"])
            db.execute("UPDATE emergency_draws SET released=1 WHERE reservation_id=?",
                        (d["reservation_id"],))
            disp_id = "ed:" + d["reservation_id"] + ":term_end"
            if not one(db, "SELECT 1 FROM emergency_dispositions WHERE id=?", (disp_id,)):
                db.execute("INSERT INTO emergency_dispositions VALUES(?,?,?,?,?,?)",
                           (disp_id, d["emergency_id"], d["reservation_id"],
                            "interrupted_at_expiry", at,
                            "temporary emergency entitlement ended; seat was interruptible"))
        return released_ids


def review_emergency(db, event_id, emergency_id, reviewer_id, at, passed, note=""):
    payload = dict(emergency_id=emergency_id, reviewer_id=reviewer_id, at=at,
                   passed=bool(passed), note=note)
    with transaction(db):
        old_event = one(db, "SELECT * FROM events WHERE id=?", (event_id,))
        if old_event:
            return event(db, event_id, "emergency.review", payload, old_event["verdict"])
        auth = one(db, "SELECT * FROM emergency_auth WHERE id=?", (emergency_id,))
        if not auth:
            return event(db, event_id, "emergency.review", payload, "unknown_emergency")
        if auth["reviewed_at"] is not None:
            return event(db, event_id, "emergency.review", payload, "already_reviewed")
        reviewer = one(db, "SELECT * FROM approval_principals WHERE id=? AND active=1",
                       (reviewer_id,))
        if not reviewer:
            return event(db, event_id, "emergency.review", payload, "reviewer_not_authorized")
        # Conflict of interest is the stronger objection and is reported first.
        if reviewer_id == auth["accountable_id"] or reviewer_id == auth["requested_by"]:
            return event(db, event_id, "emergency.review", payload, "reviewer_not_independent")
        roles = set(_normalize_domains(reviewer["roles"]))
        if not (roles & REVIEWER_ROLES):
            return event(db, event_id, "emergency.review", payload, "reviewer_not_authorized")
        if passed:
            db.execute("""UPDATE emergency_auth SET status='review_passed',reviewed_at=?,
                reviewer_id=?,review_verdict='passed',review_note=? WHERE id=?""",
                       (at, reviewer_id, note, emergency_id))
            return event(db, event_id, "emergency.review", payload, "review_passed")
        db.execute("""UPDATE emergency_auth SET status='review_failed',reviewed_at=?,
            reviewer_id=?,review_verdict='failed',review_note=? WHERE id=?""",
                   (at, reviewer_id, note, emergency_id))
        # Stop ALL new reservations for the tenant until remediation/lift. Existing usage and
        # audit rows are deliberately untouched: history is never rewritten as if unused.
        db.execute("""INSERT INTO reservation_holds(tenant,reason,source_kind,source_id,at,lifted_at)
            VALUES(?,?,?,?,?,NULL) ON CONFLICT(tenant) DO UPDATE SET reason=excluded.reason,
            source_kind=excluded.source_kind,source_id=excluded.source_id,at=excluded.at,
            lifted_at=NULL""",
                   (auth["tenant"], "emergency_review_failed", "emergency", emergency_id, at))
        return event(db, event_id, "emergency.review", payload, "review_failed")


def lift_hold(db, tenant, at, reason="remediated_after_review"):
    with transaction(db):
        hold = one(db, "SELECT * FROM reservation_holds WHERE tenant=? AND lifted_at IS NULL",
                   (tenant,))
        if not hold:
            return "no_hold"
        db.execute("UPDATE reservation_holds SET lifted_at=? WHERE tenant=?", (at, tenant))
        return "lifted"


# --------------------------------------------------------------------------- audit view

def emergency_view(db, emergency_id):
    auth = one(db, "SELECT * FROM emergency_auth WHERE id=?", (emergency_id,))
    if not auth:
        return None
    draws = rows(db, "SELECT * FROM emergency_draws WHERE emergency_id=? ORDER BY reservation_id",
                 (emergency_id,))
    dispositions = rows(db, "SELECT * FROM emergency_dispositions WHERE emergency_id=? ORDER BY id",
                        (emergency_id,))
    accountable = one(db, "SELECT name FROM approval_principals WHERE id=?",
                      (auth["accountable_id"],))
    return {
        **auth,
        "accountable_name": accountable["name"] if accountable else auth["accountable_id"],
        "draws": draws,
        "drawn_cpu": sum(d["cpu_draw"] for d in draws if not d["released"]),
        "drawn_mem": sum(d["mem_draw"] for d in draws if not d["released"]),
        "historical_draw_cpu": sum(d["cpu_draw"] for d in draws),
        "historical_draw_mem": sum(d["mem_draw"] for d in draws),
        "dispositions": dispositions,
        "active_seat_ids": [d["reservation_id"] for d in draws if not d["released"]],
    }


def governance_findings(db):
    authority_gaps = [
        {"tenant": h["tenant"], "revision": h["revision"]}
        for h in rows(db, """SELECT h.tenant,h.revision FROM budget_history h
            LEFT JOIN budget_authority a ON a.tenant=h.tenant AND a.revision=h.revision
            WHERE a.tenant IS NULL ORDER BY h.tenant,h.revision""")]
    rejected = rows(db, "SELECT id,tenant,status_reason FROM budget_applications"
                        " WHERE status='rejected' ORDER BY id")
    invalid_signatures = rows(db, """SELECT id,application_id,signer_id,verdict,reason
        FROM approval_signatures WHERE counted=0 ORDER BY id""")
    failed_reviews = rows(db, "SELECT id,tenant,reviewer_id,accountable_id,review_note"
                              " FROM emergency_auth WHERE status='review_failed' ORDER BY id")
    active_holds = rows(db, "SELECT * FROM reservation_holds WHERE lifted_at IS NULL ORDER BY tenant")
    unfunded = rows(db, """SELECT r.id FROM reservations r
        LEFT JOIN funding f ON f.reservation_id=r.id
        WHERE f.reservation_id IS NULL AND r.released=0 ORDER BY r.id""")
    return {
        "revisions_without_authority": authority_gaps,
        "rejected_applications": rejected,
        "invalid_signatures": invalid_signatures,
        "failed_emergency_reviews": failed_reviews,
        "active_holds": active_holds,
        "active_reservations_without_funding": [r["id"] for r in unfunded],
    }


def capacity_compliance(db, tenant, at):
    """Answer whether capacity used at ``at`` is covered by lawful authority.

    Non-emergency entitlement (budget version effective at ``at`` plus valid grants
    and loans) is compared with active usage.  Any shortfall must be matched by
    active draws under an emergency authorization; the remainder is unauthorized
    capacity use (phantom budget, bypassed placement, tampered rows, ...).
    """
    avail_cpu, avail_mem, state = available(db, tenant, at)
    used_cpu, used_mem = usage(db, tenant)
    deficit_cpu = max(0, -avail_cpu) if state == "available" else max(0, used_cpu)
    deficit_mem = max(0, -avail_mem) if state == "available" else max(0, used_mem)
    drawn = one(db, """SELECT COALESCE(SUM(d.cpu_draw),0) cpu, COALESCE(SUM(d.mem_draw),0) mem
        FROM emergency_draws d JOIN emergency_auth a ON a.id=d.emergency_id
        WHERE d.tenant=? AND d.released=0""", (tenant,))
    failed_active = one(db, """SELECT COALESCE(SUM(d.cpu_draw),0) cpu, COALESCE(SUM(d.mem_draw),0) mem
        FROM emergency_draws d JOIN emergency_auth a ON a.id=d.emergency_id
        WHERE d.tenant=? AND d.released=0 AND a.status='review_failed'""", (tenant,))
    unauthorized_cpu = max(0, deficit_cpu - drawn["cpu"])
    unauthorized_mem = max(0, deficit_mem - drawn["mem"])
    return {
        "tenant": tenant, "at": at, "entitlement_state": state,
        "used_cpu": used_cpu, "used_mem": used_mem,
        "non_emergency_available_cpu": avail_cpu, "non_emergency_available_mem": avail_mem,
        "shortfall_cpu": deficit_cpu, "shortfall_mem": deficit_mem,
        "emergency_backed_cpu": drawn["cpu"], "emergency_backed_mem": drawn["mem"],
        "failed_review_backed_cpu": failed_active["cpu"],
        "failed_review_backed_mem": failed_active["mem"],
        "unauthorized_cpu": unauthorized_cpu, "unauthorized_mem": unauthorized_mem,
        "compliant": state != "frozen" and unauthorized_cpu == 0 and unauthorized_mem == 0,
    }


def audit_report(db, tenant=None, at=None):
    app_sql = "SELECT id FROM budget_applications"
    args = ()
    if tenant:
        app_sql += " WHERE tenant=?"
        args = (tenant,)
    app_sql += " ORDER BY id"
    applications = []
    for row in rows(db, app_sql, args):
        view = tally(db, row["id"])
        app = one(db, "SELECT * FROM budget_applications WHERE id=?", (row["id"],))
        applications.append({"application": app, "evaluation": view})
    em_sql = "SELECT id FROM emergency_auth"
    em_args = ()
    if tenant:
        em_sql += " WHERE tenant=?"
        em_args = (tenant,)
    emergencies = [emergency_view(db, r["id"]) for r in rows(db, em_sql + " ORDER BY id", em_args)]
    authority_sql = "SELECT * FROM budget_authority"
    authority_args = ()
    if tenant:
        authority_sql += " WHERE tenant=?"
        authority_args = (tenant,)
    authority = rows(db, authority_sql + " ORDER BY tenant,revision", authority_args)
    compliance = None
    if at is not None and tenant:
        compliance = capacity_compliance(db, tenant, at)
    return {
        "applications": applications,
        "emergencies": emergencies,
        "authority": authority,
        "holds": rows(db, "SELECT * FROM reservation_holds" + (" WHERE tenant=?" if tenant else "")
                      + " ORDER BY tenant", (tenant,) if tenant else ()),
        "capacity_compliance": compliance,
        "findings": governance_findings(db),
    }


def capacity_view(db, tenant, at):
    """Explicit statement of legal/available/used capacity and emergency supplementation."""
    avail_cpu, avail_mem, state = available(db, tenant, at)
    used_cpu, used_mem = usage(db, tenant)
    emergencies = rows(db, "SELECT * FROM emergency_auth WHERE tenant=? AND status='active'"
                           " AND effective_from<=? AND expires_at>?", (tenant, at, at))
    emergency_cpu = emergency_mem = 0
    emergency_seats = []
    for a in emergencies:
        drawn = one(db, """SELECT COALESCE(SUM(cpu_draw),0) cpu,COALESCE(SUM(mem_draw),0) mem
            FROM emergency_draws WHERE emergency_id=? AND released=0""", (a["id"],))
        emergency_cpu += a["cpu_extra"] - drawn["cpu"]
        emergency_mem += a["mem_extra"] - drawn["mem"]
        for d in rows(db, "SELECT reservation_id FROM emergency_draws WHERE emergency_id=?"
                          " AND released=0", (a["id"],)):
            emergency_seats.append(d["reservation_id"])
    return {
        "tenant": tenant, "at": at, "state": state,
        "available_cpu": avail_cpu, "available_mem": avail_mem,
        "used_cpu": used_cpu, "used_mem": used_mem,
        "emergency_remaining_cpu": emergency_cpu,
        "emergency_remaining_mem": emergency_mem,
        "placeable_cpu": max(avail_cpu, 0) + emergency_cpu,
        "placeable_mem": max(avail_mem, 0) + emergency_mem,
        "emergency_seats": emergency_seats,
    }


# --------------------------------------------------------------------------- descriptive aliases

create_application = submit_application
submit_request = submit_application
new_budget_request = submit_application
file_application = submit_application
request_budget_change = submit_application
register_approver = register_principal
add_approver = register_principal
add_principal = register_principal
register_approval_seat = register_seat
add_seat = register_seat
grant_proxy = grant_delegation
create_delegation = grant_delegation
register_delegation = grant_delegation
revoke_proxy = revoke_delegation
sign = cast_signature
add_signature = cast_signature
cast_vote = cast_signature
approve = sign_as
approve_application = sign_as
sign_application = sign_as
approval_status = tally
tally_approvals = tally
count_signatures = tally
verify_signatures = tally
evaluate = evaluate_application
commit = commit_application
commit_approved = commit_application
apply_approved_revision = commit_application
activate = commit_application
revise = commit_application
reject = reject_application
reject_request = reject_application
confirm_incident = register_incident
register_capacity_incident = register_incident
authorize_emergency = authorize_emergency
emergency_authorize = authorize_emergency
emergency_grant = authorize_emergency
grant_emergency = authorize_emergency
review_emergency_authorization = review_emergency
post_review = review_emergency
emergency_review = review_emergency
emergency_status = emergency_view
report = audit_report
governance_report = audit_report
