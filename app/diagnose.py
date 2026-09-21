"""
Diagnose-Kaskade: parallele Tool-Calls vor dem Reasoning.
Output wird ins Reasoning-Prompt eingespeist, damit LLM informiert
entscheidet, ob eine Action sinnvoll ist.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from app import tool_runner
from app.logging_config import get_logger

log = get_logger(__name__)


async def _run_one(
    spec_dict: dict[str, Any],
    event_payload: dict[str, Any],
    timeout: float = 5.0,
) -> tuple[str, dict[str, Any]]:
    """Ein einzelner Tool-Call. Returns (tool_name, result_or_error)."""
    tool_name = str(spec_dict.get("tool", ""))
    spec = tool_runner.get(tool_name)
    if spec is None:
        return tool_name, {"status": "skipped", "reason": "unknown tool"}
    if spec.risk != "low":
        return tool_name, {
            "status": "skipped",
            "reason": f"risk={spec.risk} not allowed in diagnose",
        }
    try:
        rendered = tool_runner.render_args(
            spec_dict.get("args") or {}, {"event": {"payload": event_payload}}
        )
        validated = tool_runner.validate_and_coerce(spec, rendered)
    except tool_runner.ArgError as e:
        return tool_name, {"status": "skipped", "reason": f"args: {e}"}

    result = await tool_runner.run(spec, validated, timeout=timeout)
    return tool_name, {
        "status": result["status"],
        "http_status": result["http_status"],
        "elapsed_ms": result["elapsed_ms"],
        "body": result["body"],
        "excerpt": result["response_excerpt"][:200] if result["status"] != "success" else None,
    }


async def run_for_rule(
    diagnose_specs: list[dict[str, Any]],
    event_payload: dict[str, Any],
    *,
    per_tool_timeout: float = 5.0,
    overall_timeout: float = 10.0,
) -> dict[str, dict[str, Any]]:
    """Führt alle diagnose tools parallel aus, fail-silent."""
    if not diagnose_specs:
        return {}
    tasks = [_run_one(s, event_payload, per_tool_timeout) for s in diagnose_specs]
    try:
        results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=overall_timeout)
    except asyncio.TimeoutError:
        log.warning("diagnose.overall_timeout", count=len(diagnose_specs))
        return {f"_timeout_{i}": {"status": "timeout"} for i, _ in enumerate(diagnose_specs)}
    out: dict[str, dict[str, Any]] = {}
    for tool_name, res in results:
        out[tool_name] = res
    log.info(
        "diagnose.completed",
        count=len(out),
        successes=sum(1 for r in out.values() if r.get("status") == "success"),
        tools=list(out.keys()),
    )
    return out


def to_prompt_block(diagnose_results: dict[str, dict[str, Any]]) -> str:
    """Diagnose-Ergebnisse für LLM-Prompt formatieren (knapp)."""
    if not diagnose_results:
        return ""
    lines = ["", "Diagnostik:"]
    for name, res in diagnose_results.items():
        if res.get("status") != "success":
            lines.append(f"- {name}: ({res.get('status')}) {res.get('reason') or res.get('excerpt') or ''}")
            continue
        body = res.get("body")
        if body is None:
            lines.append(f"- {name}: ok (kein body)")
            continue
        # Compact summary, list-len, dict-keys, stringify Rest
        if isinstance(body, list):
            lines.append(f"- {name}: {len(body)} Items")
            if body and isinstance(body[0], dict):
                lines.append(f"  bsp: {json.dumps(body[0], default=str, ensure_ascii=False)[:240]}")
        elif isinstance(body, dict):
            keys = list(body.keys())[:6]
            preview = {k: body.get(k) for k in keys}
            lines.append(f"- {name}: {json.dumps(preview, default=str, ensure_ascii=False)[:240]}")
        else:
            lines.append(f"- {name}: {str(body)[:200]}")
    return "\n".join(lines) + "\n"
