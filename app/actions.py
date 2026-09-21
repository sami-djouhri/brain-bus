"""
Action-Engine. Stufe 8a: nur risk:low auto-execute.
Stufe 8c erweitert um confirm-Flow für risk:medium.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from app import audit, confirmations, db, tool_runner
from app.logging_config import get_logger

log = get_logger(__name__)


def recent_auto_retry(*, tool: str, service_key: str, within_s: int = 1800) -> bool:
    """Attempt-Cap: True, wenn `tool` in den letzten within_s Sekunden bereits
    auto-getriggert (source=auto) fuer denselben service_key lief. Verhindert
    Auto-Retry-Endlosschleifen — nach dem ersten Auto-Versuch eskaliert der
    naechste Fehler zum Confirm-Button."""
    if not service_key:
        return False
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=within_s)
    for row in db.list_actions(limit=50):
        if row.get("source") != "auto" or row.get("tool_name") != tool:
            continue
        try:
            ts = datetime.fromisoformat(row["created_at"])
        except (TypeError, ValueError, KeyError):
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if ts < cutoff:
            continue
        try:
            args = json.loads(row.get("args_json") or "{}")
        except (TypeError, ValueError):
            args = {}
        if str(args.get("service_id")) == str(service_key):
            return True
    return False


def _decision_columns(decision: dict[str, Any] | None) -> dict[str, Any]:
    """V1 „Gläserne Autonomie": macht die Warum-Spur aus decide.judge() für die
    actions-Zeile persistierbar (Trigger→Regel→Reasoning→Ergebnis). Alle Felder
    None, wenn keine LLM-Entscheidung vorlag (z.B. risk:low ohne rule.diagnose)."""
    if not decision:
        return {
            "decision_confidence": None,
            "decision_reasoning": None,
            "decision_source": None,
        }
    reasoning = (
        (decision.get("summary") or "").strip()
        + "\n\n"
        + (decision.get("reason_for_decision") or "").strip()
    ).strip()
    conf = decision.get("confidence")
    return {
        "decision_confidence": conf if isinstance(conf, int) and not isinstance(conf, bool) else None,
        "decision_reasoning": reasoning or None,
        "decision_source": decision.get("llm_source"),
    }


_DECISION_RETENTION_DAYS = 90


def _persist_decision(
    *,
    rule_id: str,
    fingerprint: str,
    action_spec: dict[str, Any],
    tool_name: str,
    decision: dict[str, Any],
    outcome: str,
    threshold: int | None = None,
) -> None:
    """V1 „Gläserne Autonomie" (2. Schritt): persistiert eine bewusste Nicht-Aktion
    (das System hat eine Aktion erwogen und sich dagegen entschieden) in die separate
    decisions-Tabelle. Dieselbe Redaktion wie die actions-Warum-Spur. Fail-soft: ein
    Persist-Fehler darf den Dispatch niemals brechen (Robustheit vor Vollständigkeit)."""
    try:
        reasoning = audit._redact(  # noqa: SLF001 — bewusst geteilte Redaktion
            (
                (decision.get("summary") or "").strip()
                + "\n\n"
                + (decision.get("reason_for_decision") or "").strip()
            ).strip()
        ) or None
        conf = decision.get("confidence")
        db.insert_decision({
            "id": uuid.uuid4().hex,
            "created_at": audit.now_iso(),
            "rule_id": rule_id,
            "fingerprint": fingerprint,
            "tool_name": tool_name,
            "args_json": json.dumps(action_spec.get("args") or {}, default=str),
            "risk": str(action_spec.get("risk") or "").lower() or None,
            "outcome": outcome,
            "confidence": conf if isinstance(conf, int) and not isinstance(conf, bool) else None,
            "threshold": threshold,
            "reasoning": reasoning,
            "llm_source": decision.get("llm_source"),
        })
        cutoff = (datetime.now(timezone.utc) - timedelta(days=_DECISION_RETENTION_DAYS)).isoformat()
        db.prune_decisions(cutoff)
    except Exception as exc:  # pragma: no cover — Selbstheilungs-Pfad darf nicht brechen
        log.warning("decision.persist_failed", rule_id=rule_id, outcome=outcome, error=str(exc))


class DispatchResult:
    SKIPPED_NO_ACTION = "skipped_no_action"
    SKIPPED_CONDITION = "skipped_condition"
    SKIPPED_DUPLICATE = "skipped_duplicate"
    SKIPPED_HIGH_RISK = "skipped_high_risk"
    SKIPPED_NOT_RECOMMENDED = "skipped_not_recommended"
    SKIPPED_UNKNOWN_TOOL = "skipped_unknown_tool"
    EXECUTED_AUTO = "executed_auto"
    QUEUED_CONFIRM = "queued_confirm"  # 8c
    FAILED = "failed"


def _resolve_path(context: dict[str, Any], dotted: str) -> Any:
    cur: Any = context
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
            continue
        return None
    return cur


def _condition_matches(actual: Any, expected: Any) -> bool:
    if isinstance(expected, dict):
        if "exists" in expected:
            return (actual is not None) is bool(expected["exists"])
        if "equals" in expected:
            return str(actual) == str(expected["equals"])
        if "in" in expected:
            return str(actual) in {str(item) for item in expected["in"]}
        if "not_in" in expected:
            return str(actual) not in {str(item) for item in expected["not_in"]}
        return False
    return str(actual) == str(expected)


def _action_conditions_match(action_spec: dict[str, Any], event_payload: dict[str, Any]) -> tuple[bool, str | None]:
    conditions = action_spec.get("when") or {}
    if not conditions:
        return True, None

    context = {"event": {"payload": event_payload}}
    for path, expected in conditions.items():
        actual = _resolve_path(context, str(path))
        if not _condition_matches(actual, expected):
            return False, f"{path}={actual!r} does not match {expected!r}"
    return True, None


async def dispatch(
    *,
    rule_id: str,
    fingerprint: str,
    action_spec: dict[str, Any] | None,
    event_payload: dict[str, Any],
    decision: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    action_spec: {tool: str, args: dict, risk?: str (override), confidence_threshold?: int}
    decision: optional output of decide.judge() — {recommend_action, confidence, reason}
    """
    if not action_spec:
        return {"result": DispatchResult.SKIPPED_NO_ACTION}

    tool_name = action_spec.get("tool")
    if not tool_name:
        return {"result": DispatchResult.SKIPPED_NO_ACTION, "reason": "no tool"}

    condition_ok, condition_reason = _action_conditions_match(action_spec, event_payload)
    if not condition_ok:
        log.info(
            "action.condition_skipped",
            rule_id=rule_id,
            tool=tool_name,
            reason=condition_reason,
        )
        return {
            "result": DispatchResult.SKIPPED_CONDITION,
            "tool": tool_name,
            "reason": condition_reason,
        }

    spec = tool_runner.get(tool_name)
    if spec is None:
        log.warning("action.unknown_tool", tool=tool_name)
        return {"result": DispatchResult.SKIPPED_UNKNOWN_TOOL, "tool": tool_name}

    # decision-gate (8b): wenn decide() vorhanden, recommend_action+confidence prüfen
    if decision is not None:
        if not decision.get("recommend_action", False):
            log.info(
                "action.not_recommended",
                rule_id=rule_id,
                tool=tool_name,
                reason=decision.get("reason_for_decision", ""),
            )
            _persist_decision(
                rule_id=rule_id, fingerprint=fingerprint, action_spec=action_spec,
                tool_name=tool_name, decision=decision, outcome="not_recommended",
            )
            return {
                "result": DispatchResult.SKIPPED_NOT_RECOMMENDED,
                "decision": decision,
            }
        threshold = int(action_spec.get("confidence_threshold", 0))
        if threshold and int(decision.get("confidence", 0)) < threshold:
            log.info(
                "action.below_threshold",
                rule_id=rule_id,
                tool=tool_name,
                confidence=decision.get("confidence"),
                threshold=threshold,
            )
            _persist_decision(
                rule_id=rule_id, fingerprint=fingerprint, action_spec=action_spec,
                tool_name=tool_name, decision=decision, outcome="below_threshold",
                threshold=threshold,
            )
            return {
                "result": DispatchResult.SKIPPED_NOT_RECOMMENDED,
                "decision": decision,
            }

    # risk override (Tool default kann von action_spec überschrieben werden)
    risk = str(action_spec.get("risk") or spec.risk).lower()

    # Args rendern (Templating gegen event-Kontext)
    raw_args = action_spec.get("args") or {}
    rendered = tool_runner.render_args(raw_args, {"event": {"payload": event_payload}})
    try:
        validated = tool_runner.validate_and_coerce(spec, rendered)
    except tool_runner.ArgError as e:
        log.warning("action.arg_error", tool=tool_name, error=str(e))
        return {"result": DispatchResult.FAILED, "error": str(e)}

    if risk == "high":
        log.info("action.high_risk_skipped", rule_id=rule_id, tool=tool_name)
        return {"result": DispatchResult.SKIPPED_HIGH_RISK}

    if risk in ("medium", "med"):
        # Confirm-Flow (Stufe 8c): pending Confirmation in DB + Discord-Embed.
        reasoning_text = ""
        if decision:
            reasoning_text = (
                (decision.get("summary") or "").strip() + "\n\n"
                + (decision.get("reason_for_decision") or "").strip()
            ).strip()
        confirm_result = await confirmations.request(
            rule_id=rule_id,
            fingerprint=fingerprint,
            tool_name=tool_name,
            args=validated,
            risk=risk,
            reasoning_text=reasoning_text,
        )
        log.info(
            "action.confirm_requested",
            rule_id=rule_id,
            tool=tool_name,
            confirm_result=confirm_result.get("result"),
        )
        return {
            "result": DispatchResult.QUEUED_CONFIRM,
            "tool": tool_name,
            "risk": risk,
            **confirm_result,
        }

    # risk:low → auto-execute
    return await _execute(
        rule_id=rule_id,
        fingerprint=fingerprint,
        spec=spec,
        args=validated,
        source="auto",
        confirmation_id=None,
        decision=decision,
    )


async def _execute(
    *,
    rule_id: str | None,
    fingerprint: str | None,
    spec: tool_runner.ToolSpec,
    args: dict[str, Any],
    source: str,
    confirmation_id: str | None,
    decision: dict[str, Any] | None = None,
    decision_by: str | None = None,
) -> dict[str, Any]:
    """Common execution path (auto/confirm/manual). Idempotency via DB."""
    action_id = uuid.uuid4().hex
    args_json = json.dumps(args, default=str)
    row = {
        "id": action_id,
        "created_at": audit.now_iso(),
        "rule_id": rule_id,
        "fingerprint": fingerprint,
        "tool_name": spec.name,
        "args_json": args_json,
        "source": source,
        "confirmation_id": confirmation_id,
        "status": "running",
        "http_status": None,
        "response_excerpt": None,
        "elapsed_ms": None,
        **_decision_columns(decision),
    }
    inserted = db.insert_action(row)
    if not inserted:
        log.info(
            "action.duplicate_skipped",
            tool=spec.name,
            rule_id=rule_id,
            fingerprint=fingerprint,
        )
        return {"result": DispatchResult.SKIPPED_DUPLICATE}

    result = await tool_runner.run(spec, args)
    row.update(
        status=result["status"],
        http_status=result["http_status"],
        response_excerpt=result["response_excerpt"],
        elapsed_ms=result["elapsed_ms"],
    )
    db.update_action(action_id, {
        "status": row["status"],
        "http_status": row["http_status"],
        "response_excerpt": row["response_excerpt"],
        "elapsed_ms": row["elapsed_ms"],
    })

    audit_record = {**row, "decision_by": decision_by or source}
    audit.publish_mqtt(audit_record)
    # Memory async — non-blocking
    import asyncio
    asyncio.create_task(audit.write_memory(audit_record))

    log.info(
        "action.executed",
        action_id=action_id,
        tool=spec.name,
        status=row["status"],
        source=source,
        rule_id=rule_id,
    )

    final = DispatchResult.EXECUTED_AUTO if source == "auto" else "executed_" + source
    return {"result": final, "action_id": action_id, "tool": spec.name, "outcome": result["status"]}
