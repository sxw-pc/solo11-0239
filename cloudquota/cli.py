"""Offline JSON event driver; each subsystem may run independently."""
import argparse
import json
from pathlib import Path

from . import budget, loan, reserve
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
}


def run(db_path, fixture, subsystem=None):
    db = open_db(db_path)
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
    db.close()
    return {"results": results, "state": state}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("subsystem", choices=["budget", "reserve", "loan", "all"])
    parser.add_argument("fixture")
    parser.add_argument("--db", default="cloudquota.sqlite")
    args = parser.parse_args()
    print(json.dumps(run(args.db, args.fixture, None if args.subsystem == "all" else args.subsystem), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
