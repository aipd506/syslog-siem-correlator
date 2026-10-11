"""Command-line interface for syslog-siem-correlator (siemcorrelate)."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Sequence

from siemcorrelate.parsers import LogParseError, parse_log_line
from siemcorrelate.replay import replay_log_stream
from siemcorrelate.sigma import (
    SigmaParseError,
    SigmaRule,
    load_sigma_rule_file,
    load_sigma_rules_from_dir,
    parse_sigma_rule,
)
from siemcorrelate.window import CorrelationAlert, SlidingWindowCorrelator


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="siemcorrelate",
        description="Universal security log parser, temporal sliding window correlator, and SIGMA detection engine.",
    )
    parser.add_argument("--version", action="version", version="siemcorrelate 0.1.0")

    subparsers = parser.add_subparsers(dest="subcommand", help="Subcommand to execute")

    # parse
    p_parse = subparsers.add_parser("parse", help="Parse log events into canonical normalized JSON")
    p_parse.add_argument("-i", "--in", "--file", dest="input_file", help="Input log file path (reads stdin if omitted)")
    p_parse.add_argument(
        "-f", "--format",
        choices=["auto", "rfc5424", "rfc3164", "cef", "leef"],
        default="auto",
        help="Log syntax format (default: auto)",
    )
    p_parse.add_argument("-o", "--out", dest="output_file", help="Destination file for parsed events")
    p_parse.add_argument("-j", "--json", action="store_true", default=True, help="Output formatted JSONL")

    # correlate
    p_corr = subparsers.add_parser("correlate", help="Correlate log stream using temporal sliding window and rules")
    p_corr.add_argument("-i", "--in", "--input", dest="input_file", required=True, help="Input log file path")
    p_corr.add_argument("-w", "--window", type=int, default=300, help="Sliding window duration in seconds (default: 300)")
    p_corr.add_argument("-t", "--threshold", type=int, default=5, help="Event count trigger threshold (default: 5)")
    p_corr.add_argument("-g", "--group-by", default="src_ip", help="Entity field to group by (default: src_ip)")
    p_corr.add_argument("-r", "--rules", "--rules-dir", dest="rules_path", help="Path to SIGMA rule or directory of rules")
    p_corr.add_argument("-j", "--json", action="store_true", default=True, help="Output alerts in JSON format")

    # rules
    p_rules = subparsers.add_parser("rules", help="Manage and test SIGMA detection rules")
    p_rules.add_argument("--validate", help="Validate syntax of a SIGMA rule YAML file")
    p_rules.add_argument("--test-event", help="Test rule evaluation against sample event JSON string or file")
    p_rules.add_argument("--rule", help="Rule file to evaluate with --test-event")
    p_rules.add_argument("--list", dest="list_dir", help="Enumerate all valid rules in a directory")
    p_rules.add_argument("-j", "--json", action="store_true", default=True, help="Output in JSON format")

    # replay
    p_rep = subparsers.add_parser("replay", help="Replay historical logs with temporal pacing and live alerting")
    p_rep.add_argument("-f", "--file", "--input", dest="input_file", required=True, help="Historical log file to replay")
    p_rep.add_argument("-s", "--speed", default="instant", help="Replay pacing speed: instant, 1x, 10x (default: instant)")
    p_rep.add_argument("-r", "--rules", dest="rules_path", help="Path to SIGMA rules file or directory")
    p_rep.add_argument("-w", "--window", type=int, default=300, help="Sliding window duration in seconds (default: 300)")
    p_rep.add_argument("-t", "--threshold", type=int, default=5, help="Correlation event count threshold (default: 5)")
    p_rep.add_argument("-g", "--group-by", default="src_ip", help="Correlation group-by field (default: src_ip)")
    p_rep.add_argument("-j", "--json", action="store_true", default=True, help="Output generated alerts in JSON")

    return parser


def handle_parse(args: argparse.Namespace) -> int:
    lines: list[str] = []
    if args.input_file:
        if not os.path.isfile(args.input_file):
            sys.stderr.write(f"Error: Log file not found: {args.input_file}\n")
            return 3
        with open(args.input_file, "r", encoding="utf-8", errors="replace") as f:
            lines = [l.strip() for l in f if l.strip()]
    else:
        if not sys.stdin.isatty():
            lines = [l.strip() for l in sys.stdin if l.strip()]
        else:
            sys.stderr.write("Error: Log content must be provided via -i/--file or stdin.\n")
            return 2

    if not lines:
        sys.stderr.write("Error: No log entries to parse.\n")
        return 3

    parsed_events: list[dict] = []
    failed_count = 0
    for line in lines:
        try:
            ev = parse_log_line(line, format_name=args.format)
            parsed_events.append(ev)
        except LogParseError:
            failed_count += 1

    out_lines = [json.dumps(ev) for ev in parsed_events]
    output_text = "\n".join(out_lines)

    if args.output_file:
        with open(args.output_file, "w", encoding="utf-8") as f:
            f.write(output_text + "\n")
    else:
        print(output_text)

    return 0 if parsed_events else 3


def handle_correlate(args: argparse.Namespace) -> int:
    if not os.path.isfile(args.input_file):
        sys.stderr.write(f"Error: Input log file not found: {args.input_file}\n")
        return 3

    correlator = SlidingWindowCorrelator(
        window_seconds=args.window,
        threshold=args.threshold,
        group_by=args.group_by,
        rule_name=f"Threshold_{args.group_by}_{args.threshold}",
    )

    sigma_rules: list[SigmaRule] = []
    if args.rules_path:
        if os.path.isdir(args.rules_path):
            sigma_rules = load_sigma_rules_from_dir(args.rules_path)
        elif os.path.isfile(args.rules_path):
            try:
                sigma_rules = [load_sigma_rule_file(args.rules_path)]
            except SigmaParseError as err:
                sys.stderr.write(f"Error parsing SIGMA rule: {err}\n")
                return 4

    alerts: list[dict] = []
    with open(args.input_file, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = parse_log_line(line)
            except LogParseError:
                continue

            # Evaluate SIGMA rules
            for rule in sigma_rules:
                if rule.matches(event):
                    alerts.append({
                        "alert_type": "SIGMA",
                        "rule_name": rule.title,
                        "level": rule.level,
                        "timestamp": event.get("timestamp"),
                        "event": event,
                    })

            # Evaluate sliding window
            c_alerts = correlator.ingest(event)
            for ca in c_alerts:
                alerts.append(ca.to_dict())

    if args.json:
        print(json.dumps(alerts, indent=2))
    else:
        for a in alerts:
            print(f"[{a.get('alert_type', 'ALERT')}] {a.get('rule_name')} (Count: {a.get('count', 1)})")

    # Exit code 1 if alerts detected, 0 if clean
    return 1 if alerts else 0


def handle_rules(args: argparse.Namespace) -> int:
    if args.validate:
        if not os.path.isfile(args.validate):
            sys.stderr.write(f"Error: File not found: {args.validate}\n")
            return 3
        try:
            rule = load_sigma_rule_file(args.validate)
            print(json.dumps({
                "status": "VALID",
                "title": rule.title,
                "rule_id": rule.rule_id,
                "level": rule.level,
                "condition": rule.condition,
            }, indent=2))
            return 0
        except SigmaParseError as err:
            sys.stderr.write(f"Rule validation error: {err}\n")
            return 4

    elif args.test_event:
        if not args.rule:
            sys.stderr.write("Error: --rule is required when using --test-event\n")
            return 2
        try:
            rule = load_sigma_rule_file(args.rule)
        except SigmaParseError as err:
            sys.stderr.write(f"Rule parsing error: {err}\n")
            return 4

        # Read event JSON
        event_str = args.test_event
        if os.path.isfile(event_str):
            with open(event_str, "r", encoding="utf-8") as f:
                event_data = json.load(f)
        else:
            try:
                event_data = json.loads(event_str)
            except json.JSONDecodeError as err:
                sys.stderr.write(f"Error parsing event JSON: {err}\n")
                return 2

        matched = rule.matches(event_data)
        print(json.dumps({"rule": rule.title, "matched": matched}, indent=2))
        return 0 if matched else 1

    elif args.list_dir:
        if not os.path.isdir(args.list_dir):
            sys.stderr.write(f"Error: Rules directory not found: {args.list_dir}\n")
            return 3
        rules = load_sigma_rules_from_dir(args.list_dir)
        rule_list = [{"title": r.title, "id": r.rule_id, "level": r.level} for r in rules]
        print(json.dumps(rule_list, indent=2))
        return 0

    return 2


def handle_replay(args: argparse.Namespace) -> int:
    if not os.path.isfile(args.input_file):
        sys.stderr.write(f"Error: Log file not found: {args.input_file}\n")
        return 3

    sigma_rules: list[SigmaRule] = []
    if args.rules_path:
        if os.path.isdir(args.rules_path):
            sigma_rules = load_sigma_rules_from_dir(args.rules_path)
        elif os.path.isfile(args.rules_path):
            try:
                sigma_rules = [load_sigma_rule_file(args.rules_path)]
            except SigmaParseError as err:
                sys.stderr.write(f"Error parsing rules: {err}\n")
                return 4

    correlator = SlidingWindowCorrelator(
        window_seconds=args.window,
        threshold=args.threshold,
        group_by=args.group_by,
        rule_name=f"Replay_Threshold_{args.group_by}_{args.threshold}",
    )

    summary = replay_log_stream(
        log_file_or_lines=args.input_file,
        speed=args.speed,
        rules=sigma_rules,
        correlator=correlator,
    )

    if args.json:
        print(json.dumps(summary.to_dict(), indent=2))
    else:
        print(f"Replay finished: {summary.parsed_events} parsed, {len(summary.alerts)} alerts generated.")

    return 1 if summary.alerts else 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.subcommand:
        parser.print_help()
        return 2

    if args.subcommand == "parse":
        return handle_parse(args)
    elif args.subcommand == "correlate":
        return handle_correlate(args)
    elif args.subcommand == "rules":
        return handle_rules(args)
    elif args.subcommand == "replay":
        return handle_replay(args)

    return 2


if __name__ == "__main__":
    sys.exit(main())
