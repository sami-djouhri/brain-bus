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
    # Mindestabstand zwischen zwei Meldungen. 0 = aus.
    # Ohne das feuert eine Regel ab min_events bei JEDEM weiteren Event erneut:
    # der fingerprint() hasht die Event-Zeitstempel, jedes neue Event ergibt einen
    # neuen Hash, der Idempotenz-Check greift also nur bei doppelter Zustellung.
    # Gemessen 2026-08-19: docker-network-unauthorized-connect 144 Meldungen an
    # einem Tag, jede mit LLM-Reasoning (Median 28 s) und urgent-Push.
    cooldown_seconds: int = 0
    # Payload-Felder, die das Subjekt der Meldung bestimmen (z.B. host+container).
    # Der Cooldown gilt dann je Subjekt: derselbe Container wird gedaempft, ein
    # anderer meldet sofort. Leer = regel-global (verschluckt fremde Subjekte!).
    cooldown_key_fields: list[str] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
    fired_at: dict[str, float] = field(default_factory=dict)
    suppressed: dict[str, int] = field(default_factory=dict)
    suppressed_at_last_fire: int = 0  # Stand beim Ausloesen, fuer die Meldung

    def cooldown_key(self, payload: dict[str, Any]) -> str:
        if not self.cooldown_key_fields:
            return ""
        parts: list[str] = []
        for spec in self.cooldown_key_fields:
            # "labels.container" findet auch verschachtelte Felder (Prometheus-Alerts).
            value: Any = payload
            for segment in spec.split("."):
                value = value.get(segment) if isinstance(value, dict) else None
                if value is None:
                    break
            if value is None and "." not in spec:
                # Flach nicht gefunden: eine Ebene tief suchen, damit ein
                # {"labels": {"container": ...}} nicht stillschweigend
                # auf den regel-globalen Schluessel zurueckfaellt.
                for nested in payload.values():
                    if isinstance(nested, dict) and spec in nested:
                        value = nested[spec]
                        break
            parts.append(str(value) if value is not None else "")
        return "|".join(parts)

    def prune_cooldowns(self, now: float) -> None:
        """Verhindert unbegrenztes Wachstum bei wechselnden Subjekten
        (ephemere `compose run`-Container tragen bei jedem Start einen neuen Namen)."""
        if not self.cooldown_seconds:
            return
        cutoff = now - self.cooldown_seconds
        stale = [k for k, ts in self.fired_at.items() if ts < cutoff]
        for k in stale:
            self.fired_at.pop(k, None)
            self.suppressed.pop(k, None)

    def prune(self, now: float) -> None:
        cutoff = now - self.window_seconds
        self.events = [e for e in self.events if e.received_at >= cutoff]

    def fingerprint(self) -> str:
        """Hash der aktuellen Match-Events, für Idempotenz-Check."""
        parts = sorted(f"{e.topic}:{e.received_at:.0f}" for e in self.events)
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:12]


def load_rules(path: Path) -> list[Rule]:
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    window_default = int(data.get("window_seconds_default", 60))
    # Bewusst standardmaessig AUS (0). Der Cooldown wirkt regel-global, nicht pro
    # Subjekt: ein globaler Default wuerde bei ssh-login-notify den zweiten Login
    # eines anderen Hosts und bei systemd-unit-failed die zweite Unit verschlucken.
    # Deshalb nur dort setzen, wo Dauerfeuer belegt ist (siehe rules.yaml).
    cooldown_default = int(data.get("cooldown_seconds_default", 0))
    rules: list[Rule] = []
    for raw in data.get("rules", []) or []:
        match = raw.get("match") or {}
        window_seconds = int(match.get("window_seconds", window_default))
        cooldown = int(raw.get("cooldown_seconds", cooldown_default))
        cooldown_key_fields = list(raw.get("cooldown_key_fields") or [])
        rules.append(
            Rule(
                id=raw["id"],
                topic_pattern=match["topic"],
                min_events=int(match.get("min_events", 1)),
                window_seconds=window_seconds,
                cooldown_seconds=cooldown,
                cooldown_key_fields=cooldown_key_fields,
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
            key = rule.cooldown_key(payload)
            if rule.cooldown_seconds > 0:
                rule.prune_cooldowns(now)
                last = rule.fired_at.get(key, 0.0)
                if last and now - last < rule.cooldown_seconds:
                    rule.suppressed[key] = rule.suppressed.get(key, 0) + 1
                    log.debug(
                        "rule.suppressed",
                        rule_id=rule.id,
                        subject=key or "*",
                        since_last_fire_s=int(now - last),
                        cooldown_s=rule.cooldown_seconds,
                        suppressed_total=rule.suppressed[key],
                    )
                    continue
            # Unterdrueckte Ereignisse gehen nicht verloren, sie werden mitgemeldet.
            rule.suppressed_at_last_fire = rule.suppressed.pop(key, 0)
            if rule.suppressed_at_last_fire:
                log.info(
                    "rule.cooldown_elapsed",
                    rule_id=rule.id,
                    subject=key or "*",
                    suppressed_since_last_fire=rule.suppressed_at_last_fire,
                )
            if rule.cooldown_seconds > 0:
                rule.fired_at[key] = now
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
                    "cooldown_seconds": r.cooldown_seconds,
                    "cooldown_key_fields": r.cooldown_key_fields,
                    "events_in_window": len(r.events),
                    "suppressed_now": sum(r.suppressed.values()),
                    "suggest_topic": r.suggest_topic,
                    "has_diagnose": bool(r.diagnose),
                    "has_action": bool(r.action),
                }
            )
        return out
