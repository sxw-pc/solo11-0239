"""Offline JSON event driver; each subsystem may run independently."""
import argparse
import json
from pathlib import Path

from . import budget, cluster_transfer, loan, reserve
from .store import open_db, report

COMMANDS = {
    "budget.revise": budget.revise,
    "budget.grant": budget.grant,
    "budget.revoke": budget.revoke,
    "budget.status": budget.status,
    "reserve.node": reserve.node,
    "reserve.request": reserve.request,
    "reserve.place": reserve.place,
    "reserve.start": reserve.start,
    "reserve.expire": reserve.expire,
    "reserve.policy": reserve.policy,
    "reserve.shrink": reserve.shrink,
    "loan.offer": loan.offer,
    "loan.issue": loan.issue,
    "loan.repay": loan.repay,
    "loan.allocate": loan.allocate,
    "loan.reclaim": loan.reclaim,
    "transfer.cluster": cluster_transfer.register_cluster,
    "transfer.node": cluster_transfer.register_node,
    "transfer.lot": cluster_transfer.register_lot,
    "transfer.request": cluster_transfer.request_transfer,
    "transfer.signoff": cluster_transfer.customer_signoff,
    "transfer.prepare": cluster_transfer.prepare_source,
    "transfer.target_ack": cluster_transfer.target_ack,
    "transfer.deliver": cluster_transfer.start_delivery,
    "transfer.cancel": cluster_transfer.cancel_transfer,
    "transfer.fallback_purchase": cluster_transfer.fallback_purchase,
    "transfer.start_purchase": cluster_transfer.start_purchase,
}


def run(db_path, fixture, subsystem=None):
    db = open_db(db_path)
    try:
        actions = json.loads(Path(fixture).read_text(encoding="utf-8"))["actions"]
        results = []
        for action in actions:
            name = action["op"]
            if name not in COMMANDS:
                raise ValueError("unknown operation " + name)
            result = COMMANDS[name](db, **action.get("args", {}))
            results.append({"op": name, "result": result})
        state = report(db)
        if subsystem and not any(x["op"].startswith(subsystem + ".") for x in results):
            raise ValueError("fixture has no operation for " + subsystem)
        return {"results": results, "state": state}
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("subsystem", choices=["budget", "reserve", "loan", "transfer", "all"])
    parser.add_argument("fixture")
    parser.add_argument("--db", default="cloudquota.sqlite")
    args = parser.parse_args()
    print(json.dumps(run(args.db, args.fixture, None if args.subsystem == "all" else args.subsystem), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
