"""Offline JSON event driver; each subsystem may run independently."""
import argparse
import json
from pathlib import Path

from . import budget, loan, reserve, attest, agent_command, device_trust
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
    "attest.quote": attest.quote,
    "agent.receipt": agent_command.receipt,
    "device.register": device_trust.register_device,
    "device.revoke": device_trust.revoke_device,
    "device.allow_measurement": device_trust.allow_measurement,
    "device.challenge": device_trust.issue_challenge,
    "device.evaluate_quote": device_trust.evaluate_quote,
    "device.begin_migration": device_trust.begin_migration,
    "device.removal_evidence": device_trust.removal_evidence,
    "device.install_evidence": device_trust.install_evidence,
    "device.decide_migration": device_trust.decide_migration,
    "device.quarantine": device_trust.quarantine_device,
    "device.re_register": device_trust.re_register,
    "device.dispatch_command": device_trust.dispatch_command,
    "device.evaluate_receipt": device_trust.evaluate_receipt,
    "device.finalize_receipts": device_trust.finalize_receipts,
    "device.authorize_capacity": device_trust.authorize_capacity,
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
    parser.add_argument("subsystem", choices=["budget", "reserve", "loan", "all"])
    parser.add_argument("fixture")
    parser.add_argument("--db", default="cloudquota.sqlite")
    args = parser.parse_args()
    print(json.dumps(run(args.db, args.fixture, None if args.subsystem == "all" else args.subsystem), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
