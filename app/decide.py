"""
Decide-Layer: LLM bekommt Reasoning + Diagnose + soll strukturiert
entscheiden, ob die rule.action sinnvoll ist.

Returns dict:
    {
      "summary": "1-2 Sätze",
      "recommend_action": bool,
      "confidence": 0-100,
      "reason_for_decision": "..."
    }

Bei Parse-Fail → recommend_action=False, reason="parse-failed".
"""

from __future__ import annotations

import json
import re
from typing import Any

from app import audit
from app.llm_client import LLMClient
from app.logging_config import get_logger

log = get_logger(__name__)


_PAYLOAD_MAX_CHARS = 400


def _sanitize_for_prompt(payload: dict[str, Any]) -> str:
    """Reduces prompt-injection surface: redact secrets, strip control chars,
    cap length. The LLM-output is *re-validated* via _normalize anyway, but
    keeping the prompt clean reduces noise + injection vectors."""
    raw = json.dumps(payload, default=str, ensure_ascii=False)
    raw = audit._redact(raw)  # noqa: SLF001 — bewusst geteilt
    # Drop control chars + collapse whitespace.
    raw = re.sub(r"[\x00-\x1f\x7f]+", " ", raw)
    raw = re.sub(r"\s+", " ", raw).strip()
    if len(raw) > _PAYLOAD_MAX_CHARS:
        raw = raw[:_PAYLOAD_MAX_CHARS] + "…"
    return raw


_DECISION_INSTRUCTIONS = (
    "Du bekommst Diagnose-Daten und ein Action-Vorschlag. Entscheide, ob die "
    "Action sinnvoll wäre. Antworte AUSSCHLIESSLICH als kompaktes JSON, ohne "
    "Markdown, ohne Kommentar:\n"
    '{"summary":"1-2 Saetze","recommend_action":true,'
    '"confidence":75,"reason_for_decision":"1 Satz"}'
)

_JSON_RE = re.compile(r"\{.*?\}", re.DOTALL)


def _safe_parse(text: str) -> dict[str, Any] | None:
    text = (text or "").strip()
    if not text:
        return None
    # Versuche direkten Parse, dann Regex-Fallback (LLM packt manchmal Prefix dazu)
    try:
        d = json.loads(text)
        if isinstance(d, dict):
            return d
    except json.JSONDecodeError:
        pass
    m = _JSON_RE.search(text)
    if not m:
        return None
    try:
        d = json.loads(m.group(0))
        return d if isinstance(d, dict) else None
    except json.JSONDecodeError:
        return None


def _strict_bool(v: Any) -> bool:
    """Strikt: nur Python-bool oder explizit 'true'/'false'/'1'/'0' string,
    nicht jedes truthy Object — verhindert dass LLM mit zB '{recommend_action: 1}'
    durchkommt wo es eigentlich False sein sollte (oder umgekehrt)."""
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v == 1
    if isinstance(v, str):
        return v.strip().lower() in {"true", "1"}
    return False


def _strict_int(v: Any, default: int = 0) -> int:
    if isinstance(v, bool):
        return default
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        return int(v)
    if isinstance(v, str):
        try:
            return int(v.strip())
        except ValueError:
            return default
    return default


def _normalize(parsed: dict[str, Any] | None) -> dict[str, Any]:
    if parsed is None or not isinstance(parsed, dict):
        return {
            "summary": "",
            "recommend_action": False,
            "confidence": 0,
            "reason_for_decision": "parse-failed",
        }
    return {
        "summary": str(parsed.get("summary") or "").strip()[:400],
        "recommend_action": _strict_bool(parsed.get("recommend_action")),
        "confidence": max(0, min(100, _strict_int(parsed.get("confidence"), 0))),
        "reason_for_decision": str(parsed.get("reason_for_decision") or "")[:300],
    }


async def judge(
    *,
    llm: LLMClient,
    rule_id: str,
    rule_hint: str,
    proposed_action: dict[str, Any] | None,
    event_payload: dict[str, Any],
    diagnose_block: str,
    timeout_s: float = 60.0,
    max_tokens: int = 200,
) -> dict[str, Any]:
    """Ruft LLM mit kompakter Frage. Returns normalized decision dict."""
    if not proposed_action or not proposed_action.get("tool"):
        return _normalize({"recommend_action": False, "reason_for_decision": "no action proposed"})

    system = _DECISION_INSTRUCTIONS
    payload_summary = _sanitize_for_prompt(event_payload)
    args_summary = audit._redact(  # noqa: SLF001
        json.dumps(proposed_action.get("args") or {}, default=str, ensure_ascii=False)
    )[:200]
    user = (
        f"Regel: {rule_id}\n"
        f"Hinweis: {rule_hint}\n"
        f"Event: {payload_summary}\n"
        f"{diagnose_block}\n"
        f"Vorgeschlagene Action: {proposed_action['tool']} mit args {args_summary}\n"
    )
    result = await llm.reason(
        system,
        user,
        max_tokens=max_tokens,
        fallback_timeout=timeout_s,
        direct_timeout=timeout_s,
        primary_timeout=timeout_s,
    )
    text = result.get("text") or ""
    parsed = _safe_parse(text)
    decision = _normalize(parsed)
    decision["llm_source"] = result.get("source")
    decision["llm_elapsed_ms"] = result.get("elapsed_ms")
    decision["raw_text"] = text[:300]
    log.info(
        "decide.parsed",
        rule_id=rule_id,
        recommend=decision["recommend_action"],
        confidence=decision["confidence"],
        source=decision["llm_source"],
        elapsed_ms=decision["llm_elapsed_ms"],
        parsed_ok=parsed is not None,
    )
    return decision
