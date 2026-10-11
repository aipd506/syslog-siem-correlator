"""O(1) amortized temporal sliding window event correlation engine using collections.deque."""

from __future__ import annotations

import collections
import dataclasses
import datetime
import time
from typing import Any


@dataclasses.dataclass
class CorrelationAlert:
    rule_name: str
    group_key: str
    group_value: str
    count: int
    window_seconds: float
    start_epoch: float
    end_epoch: float
    events: list[dict[str, Any]]
    triggered_at: str = dataclasses.field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "group_key": self.group_key,
            "group_value": self.group_value,
            "count": self.count,
            "window_seconds": self.window_seconds,
            "start_epoch": self.start_epoch,
            "end_epoch": self.end_epoch,
            "triggered_at": self.triggered_at,
            "events_sample_count": len(self.events),
        }


class SlidingWindowCorrelator:
    """In-memory O(1) amortized sliding temporal window event correlator."""

    def __init__(
        self,
        window_seconds: float = 300.0,
        threshold: int = 5,
        group_by: str = "src_ip",
        rule_name: str = "ThresholdRateLimitExceeded",
        repeat_interval: int | None = None,
    ) -> None:
        self.window_seconds = float(window_seconds)
        self.threshold = threshold
        self.group_by = group_by
        self.rule_name = rule_name
        self.repeat_interval = repeat_interval or threshold

        # Map group_value -> deque of event dictionaries
        self.queues: dict[str, collections.deque[dict[str, Any]]] = collections.defaultdict(collections.deque)
        # Track last alert count per group key to prevent repetitive duplicate alerts
        self.last_alerted_count: dict[str, int] = collections.defaultdict(int)

    def ingest(self, event: dict[str, Any]) -> list[CorrelationAlert]:
        """Ingest a single event and return any triggered alerts.

        Amortized time complexity: O(1) per event.
        """
        group_val = str(event.get(self.group_by) or "unknown")
        epoch = float(event.get("epoch", time.time()))

        q = self.queues[group_val]

        # Evict events outside the temporal window
        cutoff = epoch - self.window_seconds
        while q and float(q[0].get("epoch", 0.0)) < cutoff:
            q.popleft()

        # Append new event
        q.append(event)
        current_len = len(q)

        alerts: list[CorrelationAlert] = []

        # Check if threshold reached
        if current_len >= self.threshold:
            last_count = self.last_alerted_count[group_val]
            # Trigger when first hitting threshold or on repeat intervals
            if last_count < self.threshold or (current_len - last_count) >= self.repeat_interval:
                self.last_alerted_count[group_val] = current_len
                start_epoch = float(q[0].get("epoch", epoch))
                alert = CorrelationAlert(
                    rule_name=self.rule_name,
                    group_key=self.group_by,
                    group_value=group_val,
                    count=current_len,
                    window_seconds=self.window_seconds,
                    start_epoch=start_epoch,
                    end_epoch=epoch,
                    events=list(q),
                )
                alerts.append(alert)

        return alerts

    def ingest_many(self, events: list[dict[str, Any]]) -> list[CorrelationAlert]:
        """Ingest a sequence of events, returning all accumulated alerts."""
        alerts: list[CorrelationAlert] = []
        for e in events:
            alerts.extend(self.ingest(e))
        return alerts

    def prune_all(self, current_epoch: float | None = None) -> int:
        """Prune expired events from all active queues."""
        now = current_epoch if current_epoch is not None else time.time()
        cutoff = now - self.window_seconds
        total_pruned = 0
        empty_keys: list[str] = []

        for key, q in self.queues.items():
            before = len(q)
            while q and float(q[0].get("epoch", 0.0)) < cutoff:
                q.popleft()
            total_pruned += before - len(q)
            if not q:
                empty_keys.append(key)

        for key in empty_keys:
            del self.queues[key]
            if key in self.last_alerted_count:
                del self.last_alerted_count[key]

        return total_pruned

    def get_window_size(self, group_val: str) -> int:
        """Return the current number of events tracked in the window for a given key."""
        return len(self.queues.get(group_val, []))

    def reset(self) -> None:
        """Clear all active queues and state."""
        self.queues.clear()
        self.last_alerted_count.clear()
