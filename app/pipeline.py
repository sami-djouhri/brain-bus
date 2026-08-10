"""
Pipeline für brain-bus.

Rule-Match → Suggestion auf MQTT (sofort) → Async Reasoning-Task → Reasoning auf MQTT.

Reasoning blockiert nichts; falls der Primärpfad (Qwen via memory-gateway) down ist,
wacht wake.sh auf node1 den Container auf, sonst Fallback zu Gemma-4B lokal.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from app import actions, decide, diagnose
from app.llm_client import LLMClient
from app.logging_config import get_logger
from app.mqtt import publisher
from app.notify import NotifyClient
from app.registry import resolve_services
from app.rules import Rule

log = get_logger(__name__)


def _safe_resolve_services(topic: str, payload: dict[str, Any]) -> list[Any]:
    try:
        return resolve_services(topic, payload)
    except Exception as exc:
        log.warning("registry.resolve_failed", topic=topic, error=str(exc))
        return []


def _priority_rank(value: str) -> int:
    normalized = str(value or "").strip().lower()
    if normalized in {"critical", "crit"}:
        return 4
    if normalized == "high":
        return 3
    if normalized in {"medium", "med", "normal"}:
        return 2
    if normalized == "low":
        return 1
    return 0


def _event_priority(rule: Rule) -> str | None:
    if not rule.events:
        return None
    latest = rule.events[-1]
    impacted = _safe_resolve_services(latest.topic, latest.payload or {})
    if any(service.criticality == "high" for service in impacted):
        return "critical"
    if latest.topic.endswith("/service/unhealthy"):
        return "high"
    if latest.topic.endswith("/service/degraded"):
        return "medium"
    return None


def _contextualize_payload(topic: str, payload: dict[str, Any]) -> dict[str, Any]:
    enriched = dict(payload or {})
    parts = topic.split("/")
    if len(parts) >= 2 and parts[0] == "homelab" and not enriched.get("service"):
        enriched["service"] = parts[1]
    enriched.setdefault("topic", topic)
    impacted = _safe_resolve_services(topic, enriched)
    if impacted and not enriched.get("affected_services"):
        enriched["affected_services"] = [service.id for service in impacted]
    return enriched


def _effective_ntfy(rule: Rule) -> dict[str, Any]:
    ntfy = dict(rule.ntfy or {})
    escalated_priority = _event_priority(rule)
    if escalated_priority and _priority_rank(escalated_priority) > _priority_rank(ntfy.get("priority", "")):
        ntfy["priority"] = escalated_priority
    return ntfy


def _build_suggestion(rule: Rule) -> dict[str, Any]:
    latest_topics = [e.topic for e in rule.events[-5:]]
    payloads = [e.payload for e in rule.events[-5:]]
    latest_event = rule.events[-1] if rule.events else None
    impacted = _safe_resolve_services(latest_event.topic, latest_event.payload or {}) if latest_event else []
    ntfy = _effective_ntfy(rule)
    return {
        "rule_id": rule.id,
        "hint": rule.triage.get("hint", ""),
        "memory_tags": rule.triage.get("memory_tags", []),
        "events_in_window": len(rule.events),
        "sample_topics": latest_topics,
        "sample_payloads": payloads,
        "fingerprint": rule.fingerprint(),
        "source": "rule-match",
        "confidence": "rule-only",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ntfy": ntfy,
        "impacted_services": [service.as_dict() for service in impacted],
    }


def _mqtt_publish_raw(topic: str, payload: dict[str, Any]) -> None:
    if publisher._client is None:  # noqa: SLF001
        publisher.connect()
    assert publisher._client is not None
    result = publisher._client.publish(topic, json.dumps(payload, default=str), qos=0, retain=False)
    log.debug("mqtt.publish.raw", topic=topic, rc=str(result.rc))


def publish_suggestion(rule: Rule) -> None:
    suggestion = _build_suggestion(rule)
    _mqtt_publish_raw(rule.suggest_topic, suggestion)
    log.info(
        "brain.suggestion.published",
        rule_id=rule.id,
        topic=rule.suggest_topic,
        events=len(rule.events),
    )


def _build_reasoning_prompt(rule: Rule) -> tuple[str, str]:
    system = "Antwort auf Deutsch mit genau 2 sehr kurzen Saetzen. Nur Ursache und naechster Check."
    event = rule.events[-1]
    payload = _contextualize_payload(event.topic, event.payload or {})
    impacted = _safe_resolve_services(event.topic, payload)
    user_parts = [
        f"regel {rule.id}",
    ]
    if payload.get("service"):
        user_parts.append(f"service {payload['service']}")
    if payload.get("host"):
        user_parts.append(f"host {payload['host']}")
    if payload.get("status"):
        user_parts.append(f"status {payload['status']}")
    if payload.get("summary"):
        summary = str(payload["summary"]).replace(".", " ").replace("\n", " ")[:48].strip()
        user_parts.append(f"summary {summary}")
    if impacted:
        names = ", ".join(f"{service.id}:{service.criticality}" for service in impacted[:3])
        user_parts.append(f"impact {names}")
    user = " ".join(user_parts)
    return system, user


async def run_reasoning(
    rule: Rule,
    fingerprint: str,
    llm: LLMClient,
    notify: NotifyClient | None = None,
) -> None:
    """Async-Enrichment: Diagnose → Reasoning → Decide → Action-Dispatch."""
    event = rule.events[-1] if rule.events else None
    last_event_payload = _contextualize_payload(event.topic, event.payload or {}) if event else {}

    # Stufe 8b: Diagnose-Kaskade (parallel risk:low Tools).
    diag_results = await diagnose.run_for_rule(
        rule.diagnose, last_event_payload
    )
    diag_block = diagnose.to_prompt_block(diag_results)

    system, user = _build_reasoning_prompt(rule)
    if diag_block:
        user = user + " " + diag_block.replace("\n", " ")
    result = await llm.reason(
        system,
        user,
        max_tokens=64,
        fallback_timeout=60.0,
        direct_timeout=60.0,
        primary_timeout=90.0,
    )
    reasoning_text = result.get("text") or ""
    payload = {
        "rule_id": rule.id,
        "fingerprint": fingerprint,
        "text": reasoning_text,
        "source": result.get("source"),
        "elapsed_ms": result.get("elapsed_ms"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    topic = f"homelab/brain/reasoning/{rule.id}"
    _mqtt_publish_raw(topic, payload)
    log.info(
        "brain.reasoning.published",
        rule_id=rule.id,
        source=result.get("source"),
        elapsed_ms=result.get("elapsed_ms"),
        text_len=len(reasoning_text),
    )

    # Discord-Notify bei hoher Priorität.
    priority = _effective_ntfy(rule).get("priority", "")
    if notify is not None and priority in {"high", "critical"}:
        hint = rule.triage.get("hint", "")
        title = f"Homelab: {rule.id}"
        body_parts = [hint] if hint else []
        if reasoning_text:
            body_parts.append("\n" + reasoning_text)
        body_parts.append(
            f"\n_Events: {len(rule.events)}, Quelle: {result.get('source')}_"
        )
        message = "\n".join(p for p in body_parts if p).strip()
        await notify.notify(title=title, message=message[:1900], urgent=True)

    # Stufe 8b: Decide-Gate nur wenn Action risk:med/high ODER Diagnose-Daten
    # vorliegen. Reine risk:low Auto-Actions ohne Diagnose laufen weiter
    # gate-frei (= 8a Verhalten — kein LLM-Aufwand für triviale Rules).
    # failure_class-Branch (Backup): transiente Fehler 1x automatisch retrien
    # (risk->low, kein Button), echte Fehler ueber den Confirm-Button mit
    # Diagnose. Attempt-Cap verhindert Auto-Retry-Endlosschleifen.
    effective_action = rule.action
    auto_transient = False
    if rule.action and rule.action.get("tool") == "backup.retry_service":
        fclass = str(last_event_payload.get("failure_class") or "").lower()
        service_key = str(
            last_event_payload.get("service_db_id")
            or last_event_payload.get("service_id")
            or ""
        )
        if fclass == "transient" and not actions.recent_auto_retry(
            tool="backup.retry_service", service_key=service_key, within_s=1800
        ):
            effective_action = {**rule.action, "risk": "low"}
            auto_transient = True
            log.info(
                "backup.transient_auto_retry",
                rule_id=rule.id,
                service=service_key,
            )

    decision: dict[str, Any] | None = None
    if effective_action and not auto_transient:
        action_risk = str(effective_action.get("risk", "")).lower()
        if action_risk in ("medium", "med", "high") or rule.diagnose:
            decision = await decide.judge(
                llm=llm,
                rule_id=rule.id,
                rule_hint=rule.triage.get("hint", ""),
                proposed_action=effective_action,
                event_payload=last_event_payload,
                diagnose_block=diag_block,
            )

    dispatch_result = await actions.dispatch(
        rule_id=rule.id,
        fingerprint=fingerprint,
        action_spec=effective_action,
        event_payload=last_event_payload,
        decision=decision,
    )
    log.info("action.dispatched", rule_id=rule.id, **dispatch_result)
