#!/usr/bin/env python3
"""
Run performance analysis on a Suricata rules file.

Usage:
    poetry run python3 ./src/scripts/create_rule_group_minimal.py \
        --name EmproviseBlockStrictOrder --order STRICT_ORDER \
        --rules ./chunk_a.rules --region us-east-1 --wait 300
"""

import argparse
import json
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError


class DateTimeEncoder(json.JSONEncoder):
    """JSON encoder that handles datetime objects."""

    def default(self, o):
        if isinstance(o, datetime):
            return o.isoformat()
        return super().default(o)


def validate_rules(path: Path, name: str) -> str:
    """Validate rules file and return content."""
    if not path.is_file():
        raise RuntimeError(f"Rules file not found: {path}")

    msg_patterns = (f' msg:"{name}:', f'(msg:"{name}:')
    sid_patterns = (" sid:", "(sid:")

    with open(path) as f:
        lines = f.readlines()

    for ln, line in enumerate(lines, 1):
        if not any(p in line for p in sid_patterns):
            raise RuntimeError(f"{path}:{ln}: sid not found")
        if not any(p in line for p in msg_patterns):
            raise RuntimeError(f"{path}:{ln}: msg must start with: {msg_patterns[0]}")

    return "".join(lines)


def run_analysis(region: str, rules: str, order: str, timeout: int) -> dict:
    """Run analysis and poll for results."""
    client = boto3.client(
        "network-firewall",
        region_name=region,
        config=Config(read_timeout=300, retries={"total_max_attempts": 1}),
    )

    report_id = client.start_rule_analysis(
        RuleGroup={
            "RulesSource": {"RulesString": rules},
            "StatefulRuleOptions": {"RuleOrder": order},
        },
        AnalysisType="SURICATA_RULES_PROFILING",
    )["AnalysisReportId"]

    print(f"Analysis started. Report ID: {report_id}", file=sys.stderr)

    deadline = datetime.now() + timedelta(seconds=timeout)
    while datetime.now() < deadline:
        result = client.get_rule_analysis_result(AnalysisReportId=report_id)
        if (status := result.get("Status", "")) not in ("IN_PROGRESS", "PENDING"):
            return {"report_id": report_id, "status": status, "result": result}
        print(f"Status: {status}, waiting...", file=sys.stderr)
        time.sleep(3)
    return {"report_id": report_id, "status": "TIMEOUT", "timed_out": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--name", required=True, help="Rule group name")
    parser.add_argument("--order", required=True, choices=["STRICT_ORDER", "DEFAULT_ACTION_ORDER"])
    parser.add_argument("--rules", required=True, type=Path, help="Path to rules file")
    parser.add_argument("--region", required=True, help="AWS region")
    parser.add_argument("--wait", type=int, default=60, help="Timeout in seconds")
    args = parser.parse_args()

    log_object = []
    rule_object = {"log": log_object, "region": args.region}

    def add_log(data):
        log_object.append(data)
        sys.stderr.write(f"{args.region}:analyse-file: {data}\n")

    try:  # finally: json.dump(ret)
        rules_content = validate_rules(args.rules, args.name)
        print(file=sys.stderr)
        print('-'*60, file=sys.stderr)
        print(f"Rule Analysis: {args.rules}", file=sys.stderr)
        result = run_analysis(args.region, rules_content, args.order, args.wait)
        add_log("completed")
    except KeyError as e:
        add_log("error")
        rule_object["error"] = f"{e}"
        result = rule_object
        raise
    except ClientError as e:
        add_log("error")
        rule_object["error"] = f"ClientError: {e}"
        result = rule_object
        pass
    finally:
        json.dump(
            {"region": args.region, "name": args.name, **result},
            sys.stdout,
            indent=2,
            cls=DateTimeEncoder,
        )

    return 1 if result.get("timed_out") else 0


if __name__ == "__main__":
    sys.exit(main())
