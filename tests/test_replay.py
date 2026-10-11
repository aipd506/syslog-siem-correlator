"""Tests for syslog-siem-correlator historical log replayer."""

import pytest

from siemcorrelate.replay import replay_log_stream
from siemcorrelate.sigma import parse_sigma_rule
from siemcorrelate.window import SlidingWindowCorrelator


def test_replay_instant(tmp_path):
    log_file = tmp_path / "audit.log"
    lines = [
        "<34>Oct 11 10:00:00 host1 sshd[100]: Failed password for root from 192.168.1.50 port 22",
        "<34>Oct 11 10:00:01 host1 sshd[101]: Failed password for root from 192.168.1.50 port 23",
        "<34>Oct 11 10:00:02 host1 sshd[102]: Failed password for root from 192.168.1.50 port 24",
    ]
    log_file.write_text("\n".join(lines), encoding="utf-8")

    correlator = SlidingWindowCorrelator(window_seconds=60.0, threshold=3, group_by="src_ip")
    rule = parse_sigma_rule("""
title: Root Login Failure
level: high
detection:
  selection:
    user: root
    message|contains: 'Failed password'
  condition: selection
""")

    summary = replay_log_stream(
        log_file_or_lines=str(log_file),
        speed="instant",
        rules=[rule],
        correlator=correlator,
    )

    assert summary.total_lines == 3
    assert summary.parsed_events == 3
    assert summary.failed_lines == 0
    # 3 SIGMA alerts + 1 correlation threshold alert
    assert len(summary.alerts) == 4
    types = [a.alert_type for a in summary.alerts]
    assert "SIGMA" in types
    assert "CORRELATION" in types
