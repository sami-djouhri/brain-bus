"""
Audit-Layer: nach jeder Action MQTT-Publish + obsidian-memory-Writeback.

MQTT-Topic: homelab/brain/action/{tool}/{status}
Memory: POST /remember, folder=memory/actions, category=action.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

import httpx

from app import secrets_store
from app.config import settings
from app.logging_config import get_logger
from app.mqtt import publisher

log = get_logger(__name__)


_REDACT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"Bearer\s+[A-Za-z0-9._\-+/=]{8,}"), "Bearer ***"),
    (re.compile(r"eyJ[A-Za-z0-9._\-]{20,}"), "***JWT***"),
    (
        re.compile(
            r"(?i)\b(password|token|secret|api[_-]?key|access[_-]?key|auth)\b"
            r"\s*[:=]\s*[\"']?[^\s\"',}\]]+",
        ),
        r"\1=***",
    ),
]


def _redact(text: str | None) -> str:
    if not text:
        return ""
    s = str(text)
    for pat, repl in _REDACT_PATTERNS:
        s = pat.sub(repl, s)
    return s


def _redact_record(record: dict[str, Any]) -> dict[str, Any]:
    """Returns shallow copy of record with sensitive string fields redacted."""
    out = dict(record)
    if "args_json" in out:
        out["args_json"] = _redact(out.get("args_json"))
    if "response_excerpt" in out:
        out["response_excerpt"] = _redact(out.get("response_excerpt"))
    return out


def publish_mqtt(action_record: dict[str, Any]) -> None:
    tool = action_record.get("tool_name", "unknown").replace(".", "_")
    status = action_record.get("status", "unknown")
    topic = f"homelab/brain/action/{tool}/{status}"
    if publisher._client is None:  # noqa: SLF001
        publisher.connect()
    assert publisher._client is not None
    body = json.dumps(_redact_record(action_record), default=str)
    publisher._client.publish(topic, body, qos=0, retain=False)
    log.debug("audit.mqtt", topic=topic)


def _warum_spur(action_record: dict[str, Any]) -> tuple[str, list[str]]:
    """V1 „Gläserne Autonomie": baut die Warum-Spur einer Aktion für die
    Memory-Note — damit `memory.recall` je autonomer Aktion das WARUM liefert,
    nicht nur das WAS. Immer belegt:

    * mit LLM-Entscheidung (risk:medium/high oder rule.diagnose) → echtes
      Reasoning + Confidence + Modellquelle (aus decide.judge()/Confirm-Flow);
    * ohne (risk:low-Auto, manuell) → deterministische Begründung, denn bei einer
      deterministischen Regel IST Trigger→Regel→Ergebnis die vollständige Warum-Spur.

    Returns (block, extra_tags). block endet bereits mit Newline (oder ist leer).
    """
    source = str(action_record.get("source") or "?")
    rule_id = action_record.get("rule_id") or "—"
    conf = action_record.get("decision_confidence")
    reasoning = _redact(action_record.get("decision_reasoning") or "").strip()
    dsource = action_record.get("decision_source")

    lines: list[str] = []
    tags: list[str] = ["warum-spur"]
    if conf is not None:
        lines.append(f"Confidence: {conf}/100")
        if isinstance(conf, int) and not isinstance(conf, bool) and conf < 50:
            tags.append("low-confidence")
    if dsource:
        lines.append(f"Entschieden von: {dsource}")
    if reasoning:
        lines.append(f"Warum: {reasoning}")
    elif not lines:
        # Keine LLM-Entscheidung → deterministische Warum-Spur.
        if source == "auto":
            lines.append(
                f"Warum: automatisch ausgeführt — deterministische risk:low-Regel "
                f"`{rule_id}` feuerte, keine LLM-Prüfung nötig."
            )
        elif source == "manual":
            lines.append("Warum: manuell ausgelöst (kein autonomer Trigger).")
        else:
            lines.append(f"Warum: Regel `{rule_id}` (Quelle {source}).")
    return ("\n".join(lines) + "\n") if lines else "", tags


def _build_memory_note(action_record: dict[str, Any]) -> tuple[str, list[str]]:
    """Reine Note-Baufunktion (content, tags) — testbar ohne HTTP."""
    tool = action_record.get("tool_name", "")
    rule_id = action_record.get("rule_id") or "manual"
    status = action_record.get("status", "")
    decision_by = action_record.get("decision_by") or action_record.get("source", "?")
    args_json = _redact(action_record.get("args_json", "{}"))
    excerpt = _redact(action_record.get("response_excerpt", ""))[:300]
    warum_block, warum_tags = _warum_spur(action_record)
    content = (
        f"Action: {tool}\n"
        f"Args: {args_json}\n"
        f"Source: {action_record.get('source')}\n"
        f"Decided by: {decision_by}\n"
        f"Result: {status} (HTTP {action_record.get('http_status')})\n"
        f"Excerpt: {excerpt}\n"
        f"{warum_block}"
    )
    tags = [
        "action",
        tool,
        f"rule:{rule_id}",
        f"status:{status}",
        f"by:{decision_by}",
        *warum_tags,
    ]
    return content, tags


async def write_memory(action_record: dict[str, Any]) -> None:
    """Async, fail-silent. Schreibt action als Note für künftige memory.recall."""
    base_url = "http://192.0.2.10:8765"
    token = secrets_store.get("obsidian_token")
    if not token:
        log.debug("audit.memory_skip", reason="no obsidian_token")
        return
    tool = action_record.get("tool_name", "")
    rule_id = action_record.get("rule_id") or "manual"
    content, tags = _build_memory_note(action_record)
    payload = {
        "content": content,
        "source": "brain-bus",
        "folder": "memory/actions",
        "tags": tags,
    }
    headers = {"Authorization": f"Bearer {token}"}
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(4.0, connect=2.0)) as c:
            resp = await c.post(f"{base_url}/remember", json=payload, headers=headers)
            log.info(
                "audit.memory",
                status=resp.status_code,
                tool=tool,
                rule_id=rule_id,
            )
    except Exception as exc:
        log.warning("audit.memory_failed", error=str(exc))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
