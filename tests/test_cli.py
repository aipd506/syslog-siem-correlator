"""Tests for siemcorrelate CLI subcommands and exit codes."""

import json
from io import StringIO
import pytest
from unittest.mock import patch

from siemcorrelate.cli import main


def test_cli_help_and_version():
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0

    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0

    assert main([]) == 2


def test_cli_parse_file(tmp_path):
    log_file = tmp_path / "syslog.txt"
    log_file.write_text("<34>Oct 11 12:00:00 srv1 sshd[10]: Failed password for user root\n", encoding="utf-8")

    out_file = tmp_path / "parsed.jsonl"
    rc = main(["parse", "-i", str(log_file), "-o", str(out_file)])
    assert rc == 0
    assert out_file.exists()

    with open(out_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["format"] == "RFC3164"
        assert data["hostname"] == "srv1"


def test_cli_correlate(tmp_path):
    log_file = tmp_path / "access.log"
    lines = [
        "CEF:0|Vendor|App|1.0|1|Login|5|src=10.0.0.99 msg=Failed",
        "CEF:0|Vendor|App|1.0|1|Login|5|src=10.0.0.99 msg=Failed",
        "CEF:0|Vendor|App|1.0|1|Login|5|src=10.0.0.99 msg=Failed",
    ]
    log_file.write_text("\n".join(lines), encoding="utf-8")

    # Threshold 3 should trigger alert and exit with 1
    rc = main(["correlate", "-i", str(log_file), "-w", "60", "-t", "3", "-g", "src_ip"])
    assert rc == 1

    # Threshold 10 should not trigger alert and exit with 0
    rc = main(["correlate", "-i", str(log_file), "-w", "60", "-t", "10", "-g", "src_ip"])
    assert rc == 0


def test_cli_rules_validate_and_test(tmp_path):
    rule_file = tmp_path / "ssh_rule.yml"
    rule_content = """
title: SSH Failures
level: medium
detection:
  selection:
    app_name: sshd
  condition: selection
"""
    rule_file.write_text(rule_content, encoding="utf-8")

    # Validate rule
    rc = main(["rules", "--validate", str(rule_file)])
    assert rc == 0

    # Test event matches
    event_json = json.dumps({"app_name": "sshd", "message": "auth error"})
    rc = main(["rules", "--rule", str(rule_file), "--test-event", event_json])
    assert rc == 0

    # Test event does not match
    event_json_nomatch = json.dumps({"app_name": "nginx", "message": "GET 200"})
    rc = main(["rules", "--rule", str(rule_file), "--test-event", event_json_nomatch])
    assert rc == 1


def test_cli_replay(tmp_path):
    log_file = tmp_path / "replay_test.log"
    log_file.write_text(
        "<14>1 2026-10-11T12:00:00Z web01 nginx 100 - - GET /admin 403\n"
        "<14>1 2026-10-11T12:00:01Z web01 nginx 100 - - GET /admin 403\n",
        encoding="utf-8",
    )

    rc = main(["replay", "-f", str(log_file), "-s", "instant", "-t", "2", "-g", "hostname"])
    assert rc == 1
