"""
Rule-Engine: lädt config/rules.yaml, hält Window-Buffer pro Rule,
matcht eingehende MQTT-Events, triggert Callbacks.

Pattern:
    rules.yaml:
      rules:
        - id: backup-failed
          match:
            topic: "homelab/backup/job/failed"
            min_events: 1
            window_seconds: 60
          triage: {hint: "...", memory_tags: [...]}
          ntfy: {priority: high, topic: "host-critical"}
          suggest_topic: "homelab/brain/suggestion/incident"
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import paho.mqtt.client as mqtt
import yaml

from app.logging_config import get_logger

log = get_logger(__name__)


@dataclass(slots=True)
class Event:
    topic: str
    payload: dict[str, Any]
    received_at: float


@dataclass(slots=True)
class Rule:
    id: str
    topic_pattern: str
    min_events: int
    window_seconds: int
    triage: dict[str, Any]
    ntfy: dict[str, Any]
    suggest_topic: str
    include_retained: bool = False
    diagnose: list[dict[str, Any]] = field(default_factory=list)  # [{tool, args}]
    action: dict[str, Any] | None = None  # {tool, args, risk?, confidence_threshold?}
    events: list[Event] = field(default_factory=list)

    def prune(self, now: float) -> None:
        cutoff = now - self.window_seconds
        self.events = [e for e in self.events if e.received_at >= cutoff]

    def fingerprint(self) -> str:
        """Hash der aktuellen Match-Events — für Idempotenz-Check."""
        parts = sorted(f"{e.topic}:{e.received_at:.0f}" for e in self.events)
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:12]


def load_rules(path: Path) -> list[Rule]:
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    window_default = int(data.get("window_seconds_default", 60))
    rules: list[Rule] = []
    for raw in data.get("rules", []) or []:
        match = raw.get("match") or {}
        rules.append(
            Rule(
                id=raw["id"],
                topic_pattern=match["topic"],
                min_events=int(match.get("min_events", 1)),
                window_seconds=int(match.get("window_seconds", window_default)),
                triage=raw.get("triage") or {},
                ntfy=raw.get("ntfy") or {},
                suggest_topic=raw["suggest_topic"],
                include_retained=bool(match.get("include_retained", False)),
                diagnose=list(raw.get("diagnose") or []),
                action=raw.get("action") or None,
            )
        )
    log.info("rules.loaded", count=len(rules), path=str(path))
    return rules


class RuleEngine:
    def __init__(self, rules: list[Rule]) -> None:
        self._rules = rules
        self._last_fingerprints: dict[str, str] = {}

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules)

    def unique_patterns(self) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for r in self._rules:
            if r.topic_pattern in seen:
                continue
            seen.add(r.topic_pattern)
            out.append(r.topic_pattern)
        return out

    def on_event(self, topic: str, payload: dict[str, Any], retained: bool) -> list[Rule]:
        """Legt Event in alle matching Rules ab, retourniert triggernde Rules."""
        now = time.time()
        triggered: list[Rule] = []
        for rule in self._rules:
            if retained and not rule.include_retained:
                continue
            if not mqtt.topic_matches_sub(rule.topic_pattern, topic):
                continue
            rule.prune(now)
            rule.events.append(Event(topic=topic, payload=payload, received_at=now))
            if len(rule.events) < rule.min_events:
                continue
            fingerprint = rule.fingerprint()
            if self._last_fingerprints.get(rule.id) == fingerprint:
                continue
            self._last_fingerprints[rule.id] = fingerprint
            triggered.append(rule)
        return triggered

    def introspect(self) -> list[dict[str, Any]]:
        """Read-only Snapshot für /api/rules."""
        now = time.time()
        out: list[dict[str, Any]] = []
        for r in self._rules:
            r.prune(now)
            out.append(
                {
                    "id": r.id,
                    "topic_pattern": r.topic_pattern,
                    "min_events": r.min_events,
                    "window_seconds": r.window_seconds,
                    "events_in_window": len(r.events),
                    "suggest_topic": r.suggest_topic,
                    "has_diagnose": bool(r.diagnose),
                    "has_action": bool(r.action),
                }
            )
        return out
