"""Historical log event stream replayer with temporal simulation."""

from __future__ import annotations

import dataclasses
import time
from typing import Any, Callable, Sequence

from siemcorrelate.parsers import LogParseError, parse_log_line
from siemcorrelate.sigma import SigmaRule
from siemcorrelate.window import CorrelationAlert, SlidingWindowCorrelator


@dataclasses.dataclass
class ReplayAlert:
    alert_type: str  # "SIGMA" or "CORRELATION"
    rule_name: str
    severity: str
    timestamp: str
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_type": self.alert_type,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "timestamp": self.timestamp,
            "details": self.details,
        }


@dataclasses.dataclass
class ReplaySummary:
    total_lines: int
    parsed_events: int
    failed_lines: int
    alerts: list[ReplayAlert]
    duration_seconds: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_lines": self.total_lines,
            "parsed_events": self.parsed_events,
            "failed_lines": self.failed_lines,
            "alerts_count": len(self.alerts),
            "alerts": [a.to_dict() for a in self.alerts],
            "duration_seconds": round(self.duration_seconds, 4),
        }


def replay_log_stream(
    log_file_or_lines: str | Sequence[str],
    speed: str = "instant",
    rules: Sequence[SigmaRule] | None = None,
    correlator: SlidingWindowCorrelator | None = None,
    format_name: str = "auto",
    callback: Callable[[dict[str, Any], list[ReplayAlert]], None] | None = None,
) -> ReplaySummary:
    """Replay historical log events with pacing and live threat correlation."""
    start_real_time = time.time()
    rules = rules or []

    # Read lines
    if isinstance(log_file_or_lines, str):
        with open(log_file_or_lines, "r", encoding="utf-8", errors="replace") as f:
            lines = [line.strip() for line in f if line.strip()]
    else:
        lines = [line.strip() for line in log_file_or_lines if line.strip()]

    # Parse speed factor
    speed_factor = 0.0
    if speed != "instant":
        if speed.endswith("x"):
            try:
                speed_factor = float(speed[:-1])
            except ValueError:
                speed_factor = 1.0
        else:
            try:
                speed_factor = float(speed)
            except ValueError:
                speed_factor = 1.0

    total_lines = len(lines)
    parsed_count = 0
    failed_count = 0
    accumulated_alerts: list[ReplayAlert] = []

    last_event_epoch: float | None = None

    for line in lines:
        try:
            event = parse_log_line(line, format_name=format_name)
            parsed_count += 1
        except LogParseError:
            failed_count += 1
            continue

        current_epoch = float(event.get("epoch", time.time()))

        # Simulate temporal pacing if speed is not instant
        if speed_factor > 0.0 and last_event_epoch is not None:
            time_delta = current_epoch - last_event_epoch
            if 0 < time_delta <= 3600:  # Reasonable inter-event gap
                sleep_time = time_delta / speed_factor
                # Cap max sleep during simulation to 0.5s to avoid stalling
                time.sleep(min(sleep_time, 0.5))

        last_event_epoch = current_epoch
        event_alerts: list[ReplayAlert] = []

        # 1. Evaluate SIGMA rules
        for rule in rules:
            if rule.matches(event):
                alt = ReplayAlert(
                    alert_type="SIGMA",
                    rule_name=rule.title,
                    severity=rule.level,
                    timestamp=event.get("timestamp", ""),
                    details={
                        "rule_id": rule.rule_id,
                        "description": rule.description,
                        "src_ip": event.get("src_ip"),
                        "message": event.get("message"),
                    },
                )
                event_alerts.append(alt)
                accumulated_alerts.append(alt)

        # 2. Evaluate sliding window correlator
        if correlator:
            corr_alerts = correlator.ingest(event)
            for ca in corr_alerts:
                alt = ReplayAlert(
                    alert_type="CORRELATION",
                    rule_name=ca.rule_name,
                    severity="high",
                    timestamp=ca.triggered_at,
                    details=ca.to_dict(),
                )
                event_alerts.append(alt)
                accumulated_alerts.append(alt)

        if callback:
            callback(event, event_alerts)

    duration = time.time() - start_real_time
    return ReplaySummary(
        total_lines=total_lines,
        parsed_events=parsed_count,
        failed_lines=failed_count,
        alerts=accumulated_alerts,
        duration_seconds=duration,
    )
