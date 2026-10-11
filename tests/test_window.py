"""Tests for syslog-siem-correlator temporal sliding window correlation engine."""

import time
import pytest

from siemcorrelate.window import CorrelationAlert, SlidingWindowCorrelator


def test_sliding_window_threshold():
    correlator = SlidingWindowCorrelator(
        window_seconds=10.0,
        threshold=3,
        group_by="src_ip",
        rule_name="BruteForceAttempt",
    )

    t0 = 1000.0
    ev1 = {"epoch": t0, "src_ip": "192.168.1.10", "message": "fail 1"}
    ev2 = {"epoch": t0 + 2, "src_ip": "192.168.1.10", "message": "fail 2"}
    ev3 = {"epoch": t0 + 4, "src_ip": "192.168.1.10", "message": "fail 3"}

    assert correlator.ingest(ev1) == []
    assert correlator.ingest(ev2) == []

    # 3rd event within window triggers alert
    alerts = correlator.ingest(ev3)
    assert len(alerts) == 1
    assert alerts[0].rule_name == "BruteForceAttempt"
    assert alerts[0].group_value == "192.168.1.10"
    assert alerts[0].count == 3


def test_sliding_window_eviction():
    correlator = SlidingWindowCorrelator(
        window_seconds=10.0,
        threshold=3,
        group_by="src_ip",
    )

    t0 = 1000.0
    # Two events at t0, t0+1
    correlator.ingest({"epoch": t0, "src_ip": "10.0.0.1"})
    correlator.ingest({"epoch": t0 + 1, "src_ip": "10.0.0.1"})

    # Event at t0 + 15 (older events evicted because 1015 - 10 > 1001)
    ev3 = {"epoch": t0 + 15, "src_ip": "10.0.0.1"}
    alerts = correlator.ingest(ev3)
    assert len(alerts) == 0
    # Current window size should be 1
    assert correlator.get_window_size("10.0.0.1") == 1


def test_multiple_ip_grouping():
    correlator = SlidingWindowCorrelator(
        window_seconds=20.0,
        threshold=2,
        group_by="src_ip",
    )

    t0 = 2000.0
    correlator.ingest({"epoch": t0, "src_ip": "1.1.1.1"})
    correlator.ingest({"epoch": t0 + 1, "src_ip": "2.2.2.2"})

    # 1.1.1.1 reaches threshold
    al1 = correlator.ingest({"epoch": t0 + 2, "src_ip": "1.1.1.1"})
    assert len(al1) == 1
    assert al1[0].group_value == "1.1.1.1"

    # 2.2.2.2 reaches threshold
    al2 = correlator.ingest({"epoch": t0 + 3, "src_ip": "2.2.2.2"})
    assert len(al2) == 1
    assert al2[0].group_value == "2.2.2.2"


def test_prune_all():
    correlator = SlidingWindowCorrelator(
        window_seconds=5.0,
        threshold=5,
        group_by="user",
    )

    t0 = 500.0
    correlator.ingest({"epoch": t0, "user": "alice"})
    correlator.ingest({"epoch": t0 + 1, "user": "bob"})

    # Prune at t0 + 10
    pruned = correlator.prune_all(current_epoch=t0 + 10)
    assert pruned == 2
    assert correlator.get_window_size("alice") == 0
