"""Monthly cost settlement and customer billing (月度关账成本分摊与客户结算).

All money is integer micro-yuan (1 yuan = 1_000_000 micro) so every line,
voucher and reconciliation total is exact.  Customer charges are rate-based:
rate-card versions are multiplied over reconstructed fulfilment intervals
(held vs running), never over the final reservation flags.  Meter originals
reconcile the platform's cost:

    meter_total == tenant_node_charges + platform_loss
    platform_loss == confirmed_incidents + residual

Attribution rules:
  * reserved but not started: commitment fee (mode "reservation") or free
    and resalable (mode "usage"); the mode comes from a recorded contract,
    never inferred from reservation state;
  * started but node unavailable: the confirmed incident amount is borne by
    the platform and never becomes a customer line;
  * loan-funded seats: the agreed lender yield is a separate bill line;
    loan principal is repaid in resource units via loan.repay and is never
    a money line on a customer bill;
  * released seats: billing stops at the trusted release original.

Issued invoices are immutable.  Late trusted originals (e.g. a start
receipt correcting the actual start minute) never rewrite an invoice;
they surface as supplement/reversal vouchers that cite the causing
original.  Disputes, partial payments and next-period carryover are
computed from actual receipts, not from report-time balances.
"""
import json
from fractions import Fraction

from .store import one, rows, transaction

MICRO = 1_000_000

# Causal-reference prefixes a voucher may cite; each maps to the table that
# must contain the referenced original.
CAUSE_TABLES = {
    "start_doc": "start_docs",
    "release_doc": "release_docs",
    "meter": "meter_slices",
    "incident": "incidents",
    "rate": "rate_cards",
    "yield": "yield_agreements",
}


def _micro(amount):
    return int(round(amount * MICRO))


def _overlap(a0, a1, b0, b1):
    return max(0, min(a1, b1) - max(a0, b0))


def _place_at(db, reservation_id):
    for ev in rows(db, "SELECT payload FROM events WHERE kind='reserve.place'"):
        payload = json.loads(ev["payload"])
        if payload.get("reservation_id") == reservation_id:
            return payload.get("at", 0)
    return 0


def _lifecycle(db, reservation_id):
    """Reconstruct actual fulfilment from trusted originals, not final flags."""
    r = one(db, """SELECT r.*, q.tenant, q.cpu, q.mem FROM reservations r
                   JOIN requests q ON q.id=r.request_id WHERE r.id=?""", (reservation_id,))
    if not r:
        return None
    started = None
    for ev in rows(db, "SELECT payload FROM events WHERE kind='reserve.start' AND verdict='started'"):
        payload = json.loads(ev["payload"])
        if payload.get("reservation_id") == reservation_id:
            started = payload["at"] if started is None else min(started, payload["at"])
    docs = rows(db, "SELECT * FROM start_docs WHERE reservation_id=? ORDER BY received_at, rowid", (reservation_id,))
    if docs:
        started = docs[-1]["actual_start"]  # latest trusted original wins
    release = None
    rdocs = rows(db, "SELECT * FROM release_docs WHERE reservation_id=? ORDER BY received_at, rowid", (reservation_id,))
    if rdocs:
        release = rdocs[-1]["released_at"]
    elif r["released"]:
        release = r["lease_until"]  # conservative fallback without a release original
    end = r["lease_until"] if release is None else min(release, r["lease_until"])
    return {"row": r, "place_at": _place_at(db, reservation_id), "start": started, "end": end}


def _segments(lc, start_min, end_min):
    lo = max(lc["place_at"], start_min)
    hi = min(lc["end"], end_min)
    if lo >= hi:
        return []
    started = lc["start"]
    if started is None:
        return [(lo, hi, "held")]
    out = []
    if lo < min(started, hi):
        out.append((lo, min(started, hi), "held"))
    if started < hi:
        out.append((max(started, lo), hi, "running"))
    return [(s, e, state) for s, e, state in out if s < e]


def _rate_at(db, at):
    return one(db, "SELECT * FROM rate_cards WHERE effective<=? ORDER BY effective DESC LIMIT 1", (at,))


def _rate_boundaries(db, lo, hi):
    return [r["effective"] for r in rows(db, "SELECT effective FROM rate_cards WHERE effective>? AND effective<?", (lo, hi))]


def _reservation_lines(db, rr, lc, segs, mode):
    lines, resalable = [], []
    units = rr["cpu"]
    for s, e, state in segs:
        cuts = [s] + _rate_boundaries(db, s, e) + [e]
        for a, b in zip(cuts, cuts[1:]):
            card = _rate_at(db, a)
            if not card:
                raise ValueError("missing_rate")
            if state == "running":
                lines.append(dict(kind="run", ref=rr["id"], start_min=a, end_min=b, units=units,
                                  rate_version=card["version"], amount_micro=card["run_micro"] * units * (b - a)))
            elif mode == "reservation":
                lines.append(dict(kind="commit", ref=rr["id"], start_min=a, end_min=b, units=units,
                                  rate_version=card["version"], amount_micro=card["commit_micro"] * units * (b - a)))
            else:  # usage mode: un-started seat is free and resalable
                resalable.append(dict(reservation_id=rr["id"], tenant=rr["tenant"], start_min=a, end_min=b))
    return lines, resalable


def _yield_lines(db, reservation_id):
    f = one(db, "SELECT * FROM funding WHERE reservation_id=? AND source_kind='loan'", (reservation_id,))
    if not f:
        return []
    return [dict(kind="loan_yield", ref=f["source_id"], start_min=y["agreed_at"], end_min=y["agreed_at"],
                 units=0, rate_version=None, amount_micro=y["amount_micro"])
            for y in rows(db, "SELECT * FROM yield_agreements WHERE loan_id=? ORDER BY id", (f["source_id"],))]


def _tenant_lines(db, tenant, start_min, end_min):
    lines, resalable = [], []
    for rr in rows(db, """SELECT r.id, r.node_id, q.tenant, q.cpu FROM reservations r
                          JOIN requests q ON q.id=r.request_id WHERE q.tenant=? ORDER BY r.id""", (tenant,)):
        lc = _lifecycle(db, rr["id"])
        segs = _segments(lc, start_min, end_min)
        if not segs:
            continue
        contract = one(db, "SELECT * FROM contracts WHERE reservation_id=?", (rr["id"],))
        if not contract:
            raise ValueError("missing_contract:" + rr["id"])
        new_lines, new_resalable = _reservation_lines(db, rr, lc, segs, contract["mode"])
        lines += new_lines + _yield_lines(db, rr["id"])
        resalable += new_resalable
    return lines, resalable


def _all_lines(db, start_min, end_min):
    per_tenant, active_nodes = {}, set()
    for rr in rows(db, """SELECT r.id, r.node_id, q.tenant, q.cpu FROM reservations r
                          JOIN requests q ON q.id=r.request_id ORDER BY r.id"""):
        lc = _lifecycle(db, rr["id"])
        segs = _segments(lc, start_min, end_min)
        if not segs:
            continue
        active_nodes.add(rr["node_id"])
        contract = one(db, "SELECT * FROM contracts WHERE reservation_id=?", (rr["id"],))
        if not contract:
            raise ValueError("missing_contract:" + rr["id"])
        lines, resalable = _reservation_lines(db, rr, lc, segs, contract["mode"])
        lines += _yield_lines(db, rr["id"])
        t_lines, t_resalable = per_tenant.setdefault(rr["tenant"], ([], []))
        t_lines += lines
        t_resalable += resalable
    return per_tenant, active_nodes


def view(db, start_min, end_min):
    """Current settlement view: tenant charges, lender yields, platform loss."""
    per_tenant, active_nodes = _all_lines(db, start_min, end_min)
    tenants, lender_yields, resalable = {}, {}, []
    for tenant, (lines, res) in sorted(per_tenant.items()):
        node = sum(l["amount_micro"] for l in lines if l["kind"] != "loan_yield")
        yield_total = sum(l["amount_micro"] for l in lines if l["kind"] == "loan_yield")
        tenants[tenant] = {"lines": lines, "node_micro": node, "yield_micro": yield_total,
                           "total_micro": node + yield_total}
        resalable += res
        billed_loans = {l["ref"] for l in lines if l["kind"] == "loan_yield"}
        for loan_id in sorted(billed_loans):
            for y in rows(db, "SELECT * FROM yield_agreements WHERE loan_id=?", (loan_id,)):
                lender_yields[y["lender"]] = lender_yields.get(y["lender"], 0) + y["amount_micro"]
    meter_total = 0
    for node_id in sorted(active_nodes):
        meter_total += sum(s["amount_micro"] for s in rows(db, """SELECT * FROM meter_slices
            WHERE node_id=? AND superseded_by IS NULL AND start_min>=? AND end_min<=?""", (node_id, start_min, end_min)))
    incident_total = 0
    for node_id in sorted(active_nodes):
        incident_total += sum(i["amount_micro"] for i in rows(db, """SELECT * FROM incidents
            WHERE node_id=? AND start_min>=? AND end_min<=?""", (node_id, start_min, end_min)))
    charged = sum(t["node_micro"] for t in tenants.values())
    loss = meter_total - charged
    return {"tenants": tenants, "lender_yields": lender_yields, "resalable": resalable,
            "platform": {"meter_micro": meter_total, "incident_micro": incident_total,
                         "charged_micro": charged, "loss_micro": loss,
                         "residual_micro": loss - incident_total}}


def rate(db, version, run_rate, commit_rate, effective):
    run_micro, commit_micro = _micro(run_rate), _micro(commit_rate)
    if effective < 0 or run_micro <= 0 or commit_micro < 0 or commit_micro > run_micro:
        return "invalid_rate"
    with transaction(db):
        old = one(db, "SELECT * FROM rate_cards WHERE version=?", (version,))
        if old:
            same = (old["run_micro"], old["commit_micro"], old["effective"]) == (run_micro, commit_micro, effective)
            return "exists" if same else "rate_conflict"
        if one(db, "SELECT version FROM rate_cards WHERE effective=?", (effective,)):
            return "effective_conflict"
        db.execute("INSERT INTO rate_cards VALUES(?,?,?,?)", (version, run_micro, commit_micro, effective))
        return "accepted"


def meter(db, slice_id, node_id, start_min, end_min, amount, received_at, supersedes=None):
    micro = _micro(amount)
    if end_min <= start_min or start_min < 0 or micro <= 0 or received_at < 0:
        return "invalid_slice"
    with transaction(db):
        old = one(db, "SELECT * FROM meter_slices WHERE id=?", (slice_id,))
        if old:
            same = (old["node_id"], old["start_min"], old["end_min"], old["amount_micro"],
                    old["received_at"]) == (node_id, start_min, end_min, micro, received_at)
            return "duplicate" if same else "slice_conflict"
        if not one(db, "SELECT id FROM nodes WHERE id=?", (node_id,)):
            return "unknown_node"
        if supersedes is not None:
            target = one(db, "SELECT * FROM meter_slices WHERE id=?", (supersedes,))
            if not target:
                return "unknown_slice"
            if target["superseded_by"] is not None:
                return "already_superseded"
            if target["node_id"] != node_id:
                return "slice_node_mismatch"
        for s in rows(db, "SELECT * FROM meter_slices WHERE node_id=? AND superseded_by IS NULL", (node_id,)):
            if s["id"] == supersedes:
                continue
            if _overlap(start_min, end_min, s["start_min"], s["end_min"]) > 0:
                return "meter_overlap"
        db.execute("INSERT INTO meter_slices VALUES(?,?,?,?,?,?,NULL)",
                   (slice_id, node_id, start_min, end_min, micro, received_at))
        if supersedes is not None:
            db.execute("UPDATE meter_slices SET superseded_by=? WHERE id=?", (slice_id, supersedes))
        return "accepted"


def incident(db, incident_id, node_id, start_min, end_min, amount, confirmed_at):
    micro = _micro(amount)
    if end_min <= start_min or start_min < 0 or micro <= 0 or confirmed_at < 0:
        return "invalid_incident"
    with transaction(db):
        old = one(db, "SELECT * FROM incidents WHERE id=?", (incident_id,))
        if old:
            same = (old["node_id"], old["start_min"], old["end_min"], old["amount_micro"],
                    old["confirmed_at"]) == (node_id, start_min, end_min, micro, confirmed_at)
            return "duplicate" if same else "incident_conflict"
        if not one(db, "SELECT id FROM nodes WHERE id=?", (node_id,)):
            return "unknown_node"
        db.execute("INSERT INTO incidents VALUES(?,?,?,?,?,?)",
                   (incident_id, node_id, start_min, end_min, micro, confirmed_at))
        return "accepted"


def contract(db, reservation_id, tenant, mode):
    if mode not in ("reservation", "usage"):
        return "invalid_mode"
    with transaction(db):
        r = one(db, """SELECT q.tenant FROM reservations r JOIN requests q ON q.id=r.request_id
                       WHERE r.id=?""", (reservation_id,))
        if not r:
            return "unknown_reservation"
        if r["tenant"] != tenant:
            return "tenant_mismatch"
        old = one(db, "SELECT * FROM contracts WHERE reservation_id=?", (reservation_id,))
        if old:
            return "exists" if (old["tenant"], old["mode"]) == (tenant, mode) else "contract_conflict"
        db.execute("INSERT INTO contracts VALUES(?,?,?)", (reservation_id, tenant, mode))
        return "accepted"


def start_doc(db, doc_id, reservation_id, actual_start, received_at):
    with transaction(db):
        old = one(db, "SELECT * FROM start_docs WHERE id=?", (doc_id,))
        if old:
            same = (old["reservation_id"], old["actual_start"], old["received_at"]) == (reservation_id, actual_start, received_at)
            return "duplicate" if same else "doc_conflict"
        r = one(db, "SELECT * FROM reservations WHERE id=?", (reservation_id,))
        if not r:
            return "unknown_reservation"
        if received_at < 0 or actual_start < _place_at(db, reservation_id) or actual_start > r["lease_until"]:
            return "invalid_start_doc"
        db.execute("INSERT INTO start_docs VALUES(?,?,?,?)", (doc_id, reservation_id, actual_start, received_at))
        return "accepted"


def release_doc(db, doc_id, reservation_id, released_at, received_at):
    with transaction(db):
        old = one(db, "SELECT * FROM release_docs WHERE id=?", (doc_id,))
        if old:
            same = (old["reservation_id"], old["released_at"], old["received_at"]) == (reservation_id, released_at, received_at)
            return "duplicate" if same else "doc_conflict"
        r = one(db, "SELECT * FROM reservations WHERE id=?", (reservation_id,))
        if not r:
            return "unknown_reservation"
        if received_at < 0 or released_at < _place_at(db, reservation_id) or released_at > r["lease_until"]:
            return "invalid_release_doc"
        db.execute("INSERT INTO release_docs VALUES(?,?,?,?)", (doc_id, reservation_id, released_at, received_at))
        return "accepted"


def yield_agreement(db, yield_id, loan_id, amount, agreed_at):
    micro = _micro(amount)
    if micro <= 0 or agreed_at < 0:
        return "invalid_yield"
    with transaction(db):
        old = one(db, "SELECT * FROM yield_agreements WHERE id=?", (yield_id,))
        if old:
            same = (old["loan_id"], old["amount_micro"], old["agreed_at"]) == (loan_id, micro, agreed_at)
            return "exists" if same else "yield_conflict"
        loan = one(db, """SELECT l.borrower, o.lender FROM loans l JOIN offers o ON o.id=l.offer_id
                          WHERE l.id=?""", (loan_id,))
        if not loan:
            return "unknown_loan"
        db.execute("INSERT INTO yield_agreements VALUES(?,?,?,?,?,?)",
                   (yield_id, loan_id, loan["lender"], loan["borrower"], micro, agreed_at))
        return "accepted"


def close(db, close_id, start_min, end_min, at):
    """Close a billing period: validate originals, then snapshot the settlement."""
    if end_min <= start_min or start_min < 0 or at < 0:
        return "invalid_window"
    with transaction(db):
        old = one(db, "SELECT * FROM period_closes WHERE id=?", (close_id,))
        if old:
            return json.loads(old["snapshot"])
        if one(db, "SELECT id FROM period_closes WHERE start_min=? AND end_min=?", (start_min, end_min)):
            return "period_already_closed"
        active_nodes, any_active = set(), False
        active_reservations = []
        for rr in rows(db, "SELECT id, node_id FROM reservations ORDER BY id"):
            lc = _lifecycle(db, rr["id"])
            if not _segments(lc, start_min, end_min):
                continue
            any_active = True
            active_reservations.append(rr)
            active_nodes.add(rr["node_id"])
        if any_active and not _rate_at(db, start_min):
            return "missing_rate"
        for rr in active_reservations:
            if not one(db, "SELECT reservation_id FROM contracts WHERE reservation_id=?", (rr["id"],)):
                return "missing_contract"
        for node_id in sorted(active_nodes):
            slices = rows(db, "SELECT * FROM meter_slices WHERE node_id=? AND superseded_by IS NULL", (node_id,))
            in_period = []
            for s in slices:
                if _overlap(start_min, end_min, s["start_min"], s["end_min"]) == 0:
                    continue
                if s["start_min"] < start_min or s["end_min"] > end_min:
                    return "slice_out_of_period"
                in_period.append(s)
            if sum(s["end_min"] - s["start_min"] for s in in_period) != end_min - start_min:
                return "meter_gap"
            incidents = [i for i in rows(db, "SELECT * FROM incidents WHERE node_id=?", (node_id,))
                         if _overlap(start_min, end_min, i["start_min"], i["end_min"]) > 0]
            for i in incidents:
                if i["start_min"] < start_min or i["end_min"] > end_min:
                    return "incident_out_of_period"
            for s in in_period:
                share = sum(Fraction(i["amount_micro"]) * _overlap(i["start_min"], i["end_min"], s["start_min"], s["end_min"])
                            / (i["end_min"] - i["start_min"]) for i in incidents)
                if share > s["amount_micro"]:
                    return "incident_exceeds_meter"
        snapshot = {"period": [start_min, end_min], "closed_at": at}
        snapshot.update(view(db, start_min, end_min))
        db.execute("INSERT INTO period_closes VALUES(?,?,?,?,?)",
                   (close_id, start_min, end_min, at, json.dumps(snapshot, ensure_ascii=False, sort_keys=True)))
        return snapshot


def _invoice_summary(db, inv):
    total = one(db, "SELECT COALESCE(SUM(amount_micro),0) s FROM invoice_lines WHERE invoice_id=?", (inv["id"],))["s"]
    count = one(db, "SELECT COUNT(*) n FROM invoice_lines WHERE invoice_id=?", (inv["id"],))["n"]
    return {"invoice": inv["id"], "tenant": inv["tenant"], "status": inv["status"],
            "total_micro": total, "lines": count}


def invoice(db, invoice_id, tenant, start_min, end_min, issued_at):
    if end_min <= start_min or start_min < 0 or issued_at < 0:
        return "invalid_window"
    with transaction(db):
        old = one(db, "SELECT * FROM invoices WHERE id=?", (invoice_id,))
        if old:
            if (old["tenant"], old["period_start"], old["period_end"]) != (tenant, start_min, end_min):
                return "invoice_conflict"
            return _invoice_summary(db, old)
        if not one(db, "SELECT id FROM period_closes WHERE start_min=? AND end_min=?", (start_min, end_min)):
            return "period_not_closed"
        if one(db, "SELECT id FROM invoices WHERE tenant=? AND period_start=? AND period_end=?",
               (tenant, start_min, end_min)):
            return "already_invoiced"
        try:
            lines, _ = _tenant_lines(db, tenant, start_min, end_min)
        except ValueError:
            return "missing_contract"
        if not lines:
            return "nothing_to_bill"
        db.execute("INSERT INTO invoices VALUES(?,?,?,?,?,'open')",
                   (invoice_id, tenant, start_min, end_min, issued_at))
        for seq, line in enumerate(lines):
            db.execute("INSERT INTO invoice_lines VALUES(?,?,?,?,?,?,?,?,?)",
                       (invoice_id, seq, line["kind"], line["ref"], line["start_min"], line["end_min"],
                        line["units"], line["rate_version"], line["amount_micro"]))
        return _invoice_summary(db, one(db, "SELECT * FROM invoices WHERE id=?", (invoice_id,)))


def _document_lines(db, invoice_id):
    out = [dict(l) for l in rows(db, """SELECT kind,ref,start_min,end_min,units,rate_version,amount_micro
                                        FROM invoice_lines WHERE invoice_id=? ORDER BY seq""", (invoice_id,))]
    for v in rows(db, "SELECT id FROM vouchers WHERE invoice_id=? ORDER BY rowid", (invoice_id,)):
        out += [dict(l) for l in rows(db, """SELECT kind,ref,start_min,end_min,units,rate_version,amount_micro
                                             FROM voucher_lines WHERE voucher_id=? ORDER BY seq""", (v["id"],))]
    return out


def _line_key(line):
    return (line["kind"], line["ref"], line["start_min"], line["end_min"],
            line["units"], line["rate_version"], line["amount_micro"])


def _net_lines(lines):
    """Cancel identical lines of opposite sign; what remains is the real balance."""
    net = {}
    for line in lines:
        key = _line_key(line)[:-1]
        net[key] = net.get(key, 0) + line["amount_micro"]
    return {key: amount for key, amount in net.items() if amount != 0}


def _expand(net):
    return [dict(kind=k[0], ref=k[1], start_min=k[2], end_min=k[3], units=k[4],
                 rate_version=k[5], amount_micro=amount) for k, amount in sorted(net.items())]


def _negate(line):
    return dict(line, amount_micro=-line["amount_micro"])


def _check_cause(db, cause):
    if ":" not in cause:
        return None  # free-form external reference (ticket, manual credit, ...)
    kind, ref = cause.split(":", 1)
    table = CAUSE_TABLES.get(kind)
    if table is None:
        return None
    key = "id" if table != "rate_cards" else "version"
    if not one(db, f"SELECT {key} FROM {table} WHERE {key}=?", (ref,)):
        return "unknown_cause"
    return None


def _voucher_summary(db, v):
    delta = one(db, "SELECT COALESCE(SUM(amount_micro),0) s FROM voucher_lines WHERE voucher_id=?", (v["id"],))["s"]
    return {"voucher": v["id"], "invoice": v["invoice_id"], "kind": v["kind"],
            "cause": v["cause"], "delta_micro": delta}


def voucher(db, voucher_id, invoice_id, kind, cause, issued_at):
    """Post a supplement (delta vs current view) or reversal (void) voucher.

    The issued invoice is never rewritten; every voucher cites the original
    that caused it.
    """
    if kind not in ("supplement", "reversal"):
        return "invalid_voucher"
    if not cause or issued_at < 0:
        return "missing_cause"
    with transaction(db):
        old = one(db, "SELECT * FROM vouchers WHERE id=?", (voucher_id,))
        if old:
            if (old["invoice_id"], old["kind"], old["cause"]) != (invoice_id, kind, cause):
                return "voucher_conflict"
            return _voucher_summary(db, old)
        inv = one(db, "SELECT * FROM invoices WHERE id=?", (invoice_id,))
        if not inv:
            return "unknown_invoice"
        bad_cause = _check_cause(db, cause)
        if bad_cause:
            return bad_cause
        prior = _document_lines(db, invoice_id)
        prior_net = _net_lines(prior)
        if kind == "supplement":
            if inv["status"] == "reversed":
                return "invoice_reversed"
            try:
                current, _ = _tenant_lines(db, inv["tenant"], inv["period_start"], inv["period_end"])
            except ValueError:
                return "missing_contract"
            current_net = _net_lines(current)
            if current_net == prior_net:
                return "no_delta"
            new_lines = [_negate(l) for l in _expand(prior_net)] + _expand(current_net)
        else:
            if inv["status"] == "reversed":
                return "already_reversed"
            new_lines = [_negate(l) for l in _expand(prior_net)]
            db.execute("UPDATE invoices SET status='reversed' WHERE id=?", (invoice_id,))
        db.execute("INSERT INTO vouchers VALUES(?,?,?,?,?)", (voucher_id, invoice_id, kind, cause, issued_at))
        for seq, line in enumerate(new_lines):
            db.execute("INSERT INTO voucher_lines VALUES(?,?,?,?,?,?,?,?,?)",
                       (voucher_id, seq, line["kind"], line["ref"], line["start_min"], line["end_min"],
                        line["units"], line["rate_version"], line["amount_micro"]))
        return _voucher_summary(db, one(db, "SELECT * FROM vouchers WHERE id=?", (voucher_id,)))


def payment(db, payment_id, invoice_id, amount, received_at):
    micro = _micro(amount)
    if micro <= 0 or received_at < 0:
        return "invalid_payment"
    with transaction(db):
        old = one(db, "SELECT * FROM payments WHERE id=?", (payment_id,))
        if old:
            same = (old["invoice_id"], old["amount_micro"], old["received_at"]) == (invoice_id, micro, received_at)
            return "duplicate" if same else "receipt_conflict"
        inv = one(db, "SELECT * FROM invoices WHERE id=?", (invoice_id,))
        if not inv:
            return "unknown_invoice"
        if inv["status"] == "reversed":
            return "invoice_reversed"
        billed = sum(l["amount_micro"] for l in _document_lines(db, invoice_id))
        received = one(db, "SELECT COALESCE(SUM(amount_micro),0) s FROM payments WHERE invoice_id=?",
                       (invoice_id,))["s"]
        if micro > billed - received:
            return "overpayment"
        db.execute("INSERT INTO payments VALUES(?,?,?,?,?)", (payment_id, invoice_id, inv["tenant"], micro, received_at))
        return "accepted"


def dispute(db, dispute_id, invoice_id, reason, filed_at, claim=None, ref=None):
    if not reason or filed_at < 0:
        return "invalid_dispute"
    with transaction(db):
        old = one(db, "SELECT * FROM disputes WHERE id=?", (dispute_id,))
        if old:
            same = (old["invoice_id"], old["reason"], old["claim"]) == (invoice_id, reason, claim)
            return "exists" if same else "dispute_conflict"
        inv = one(db, "SELECT * FROM invoices WHERE id=?", (invoice_id,))
        if not inv:
            return "unknown_invoice"
        if claim == "exclusive_seat":
            c = one(db, "SELECT * FROM contracts WHERE reservation_id=?", (ref,))
            if not c:
                return "unknown_reservation"
            if c["mode"] != "reservation":
                return "no_exclusive_claim"
        db.execute("INSERT INTO disputes(id,invoice_id,tenant,reason,claim,status,filed_at) VALUES(?,?,?,?,?,'open',?)",
                   (dispute_id, invoice_id, inv["tenant"], reason, claim, filed_at))
        return "open"


def resolve(db, dispute_id, resolution, voucher_id=None):
    if resolution not in ("upheld", "rejected"):
        return "invalid_resolution"
    with transaction(db):
        d = one(db, "SELECT * FROM disputes WHERE id=?", (dispute_id,))
        if not d:
            return "unknown_dispute"
        if d["status"] != "open":
            return "dispute_closed"
        if voucher_id is not None:
            v = one(db, "SELECT * FROM vouchers WHERE id=?", (voucher_id,))
            if not v or v["invoice_id"] != d["invoice_id"]:
                return "unknown_voucher"
        db.execute("UPDATE disputes SET status=?, resolution=?, voucher_id=? WHERE id=?",
                   (resolution, resolution, voucher_id, dispute_id))
        return resolution


def statement(db, tenant, start_min, end_min):
    """Monthly statement: amounts owed, actually received, and carryover.

    Carryover (outstanding_micro, negative = credit) derives from actual
    receipts, never from a balance cached at report time.
    """
    try:
        lines, resalable = _tenant_lines(db, tenant, start_min, end_min)
    except ValueError:
        return "missing_contract"
    current = sum(l["amount_micro"] for l in lines)
    inv = one(db, "SELECT * FROM invoices WHERE tenant=? AND period_start=? AND period_end=?",
              (tenant, start_min, end_min))
    invoiced, received, disputes = 0, 0, []
    if inv:
        invoiced = sum(l["amount_micro"] for l in _document_lines(db, inv["id"]))
        received = one(db, "SELECT COALESCE(SUM(amount_micro),0) s FROM payments WHERE invoice_id=?",
                       (inv["id"],))["s"]
        disputes = rows(db, "SELECT * FROM disputes WHERE invoice_id=? ORDER BY id", (inv["id"],))
    principal = {l["id"]: [l["cpu"] - l["repaid_cpu"], l["mem"] - l["repaid_mem"]]
                 for l in rows(db, "SELECT * FROM loans WHERE borrower=? ORDER BY id", (tenant,))}
    return {"tenant": tenant, "period": [start_min, end_min],
            "current_micro": current, "invoiced_micro": invoiced,
            "received_micro": received, "outstanding_micro": invoiced - received,
            "unbilled_micro": current - invoiced, "disputes": disputes,
            "resalable": resalable, "loan_principal_outstanding": principal}
