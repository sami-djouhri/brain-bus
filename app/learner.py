"""brain-bus Lernschleife.

Wertet Audit-Log (`actions`-Tabelle) der letzten 7 Tage aus, baut pro Rule
ein Profil, lässt LLM Tuning-Vorschläge generieren, schickt Notify an
host-junior /notify und legt einen Memory-Snapshot in obsidian ab.

Aufruf:
  - HTTP: POST /api/learner/run, GET /api/learner/last
  - CLI:  python -m app.cron_learner

Mindest-Schwelle: keine Suggestion wenn fired_count < 3 (zu spärliche Daten).
Auto-Apply: nein. Vorschlag wird nur gepusht.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("BRAIN_DB_PATH", "/data/brain.db")
RULES_PATH = os.environ.get("BRAIN_RULES_PATH", "/app/config/rules.yaml")
LOOKBACK_DAYS = int(os.environ.get("LEARNER_LOOKBACK_DAYS", "7"))
MIN_FIRED = int(os.environ.get("LEARNER_MIN_FIRED", "3"))
LAST_REPORT_PATH = Path("/data/learner_last.json")

JUNIOR_NOTIFY_URL = os.environ.get("JUNIOR_NOTIFY_URL", "http://host-junior:8765/notify")
OBSIDIAN_URL = os.environ.get("OBSIDIAN_URL", "http://obsidian-memory:8765")
OBSIDIAN_TOKEN_FILE = os.environ.get("OBSIDIAN_TOKEN_FILE", "/run/secrets/obsidian_token")
LLM_URL = os.environ.get("LLM_FALLBACK_URL", "http://192.0.2.10:8081/v1")
LLM_MODEL = os.environ.get("LLM_FALLBACK_MODEL", "gemma")


SYSTEM_PROMPT = """Du analysierst eine Homelab-Rule-Engine (brain-bus). Pro Rule bekommst du:
- fired_count (wie oft sie in N Tagen feuerte)
- action_success / action_failure
- typische fingerprint-Häufigkeiten (zeigt Idempotenz-Pattern)
- Sample-Payloads
- Aktuelle Rule-Definition aus config/rules.yaml

Schlage konkrete Tweaks vor:
- "threshold": Schwellenwert anpassen (z.B. window/min_count) bei Storm-Charakteristik oder fast immer fehlschlagenden Actions.
- "new_rule": neue Rule wenn ein Pattern wiederholt ohne Match auftrat (musst du im Kontext erkennen).
- "deprecate": Rule entfernen wenn 0x feuerte und logisch obsolet ist.

Antworte STRIKT als JSON, keine Prosa, kein Markdown:
{"suggestions": [{"rule_id": str, "change_type": "threshold|new_rule|deprecate",
  "yaml_diff": str (unified-diff oder neuer YAML-Block),
  "reason": str (1-2 Sätze warum),
  "confidence": float 0..1}]}

Wenn keine sinnvollen Vorschläge: {"suggestions": []}"""


def _read_token(path: str) -> str:
    try:
        return Path(path).read_text().strip()
    except Exception:
        return ""


def _read_rules() -> str:
    try:
        return Path(RULES_PATH).read_text()
    except Exception as e:
        logger.warning("rules.yaml read failed: %s", e)
        return ""


def _collect_profile() -> dict[str, Any]:
    """Liest brain.db actions-Tabelle und baut pro rule_id Profil."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)).isoformat()
    profile: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "fired_count": 0,
        "action_success": 0,
        "action_failure": 0,
        "fingerprints": Counter(),
        "samples": [],
        "tools": Counter(),
    })

    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT rule_id, fingerprint, tool_name, status, args_json, created_at "
            "FROM actions WHERE created_at >= ? ORDER BY created_at DESC",
            (cutoff,),
        ).fetchall()

    for r in rows:
        rid = r["rule_id"]
        p = profile[rid]
        p["fired_count"] += 1
        p["fingerprints"][r["fingerprint"]] += 1
        p["tools"][r["tool_name"] or "none"] += 1
        if (r["status"] or "").lower() in ("success", "ok"):
            p["action_success"] += 1
        elif (r["status"] or "").lower() in ("failure", "error", "failed"):
            p["action_failure"] += 1
        if len(p["samples"]) < 3 and r["args_json"]:
            try:
                p["samples"].append(json.loads(r["args_json"]))
            except Exception:
                p["samples"].append({"raw": r["args_json"][:200]})

    out = {}
    for rid, p in profile.items():
        if p["fired_count"] < MIN_FIRED:
            continue
        out[rid] = {
            "fired_count": p["fired_count"],
            "action_success": p["action_success"],
            "action_failure": p["action_failure"],
            "top_fingerprints": p["fingerprints"].most_common(5),
            "tools": dict(p["tools"]),
            "samples": p["samples"],
        }
    return out


def _ask_llm(profile: dict[str, Any], rules_yaml: str) -> dict[str, Any]:
    user = (
        f"Lookback: {LOOKBACK_DAYS} Tage\n\n"
        f"Aktuelle config/rules.yaml:\n```yaml\n{rules_yaml}\n```\n\n"
        f"Profil pro Rule:\n```json\n{json.dumps(profile, ensure_ascii=False, indent=2, default=str)}\n```"
    )
    try:
        with httpx.Client(timeout=60.0) as c:
            resp = c.post(
                f"{LLM_URL}/chat/completions",
                json={
                    "model": LLM_MODEL,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user},
                    ],
                    "max_tokens": 600,
                    "temperature": 0.2,
                    "stream": False,
                },
            )
            resp.raise_for_status()
            raw = resp.json()["choices"][0]["message"]["content"].strip()
    except Exception as e:
        logger.warning("LLM-Aufruf fehlgeschlagen: %s", e)
        return {"suggestions": [], "_error": str(e)}
    try:
        return json.loads(raw)
    except Exception:
        logger.warning("LLM-Response nicht parsebar: %s", raw[:300])
        return {"suggestions": [], "_raw": raw[:1000]}


def _notify_discord(report: dict[str, Any]) -> None:
    suggestions = report.get("suggestions", [])
    if not suggestions:
        title = "brain-bus Learner"
        message = (
            f"Lernschleife fertig: {report['rules_analyzed']} Rules analysiert, "
            "keine Tuning-Vorschlaege."
        )
        urgent = False
    else:
        lines = []
        for s in suggestions[:10]:
            conf = int((s.get("confidence", 0) or 0) * 100)
            lines.append(
                f"{s.get('rule_id', '?')} ({s.get('change_type', '?')}, conf {conf}%): "
                f"{s.get('reason', '')}\n"
                f"{(s.get('yaml_diff') or '')[:500]}"
            )
        title = f"brain-bus Learner - {len(suggestions)} Vorschlaege"
        message = "\n\n".join(lines)[:3800]
        urgent = False
    try:
        with httpx.Client(timeout=10.0) as c:
            c.post(
                JUNIOR_NOTIFY_URL,
                json={"title": title, "message": message, "urgent": urgent},
            ).raise_for_status()
    except Exception as e:
        logger.warning("junior notify failed: %s", e)


def _audit_to_memory(report: dict[str, Any]) -> None:
    token = _read_token(OBSIDIAN_TOKEN_FILE)
    if not token:
        return
    body = (
        f"# brain-bus Learner Report — {report['generated_at']}\n\n"
        f"Rules analysiert: {report['rules_analyzed']}\n"
        f"Vorschläge: {len(report.get('suggestions', []))}\n\n"
        f"```json\n{json.dumps(report, ensure_ascii=False, indent=2, default=str)[:6000]}\n```"
    )
    try:
        with httpx.Client(timeout=10.0, headers={"Authorization": f"Bearer {token}"}) as c:
            c.post(
                f"{OBSIDIAN_URL}/remember",
                json={
                    "folder": "memory/learner",
                    "title": f"learner-{report['generated_at'][:10]}",
                    "content": body,
                    "tags": ["learner", "brain-bus", "audit"],
                },
            ).raise_for_status()
    except Exception as e:
        logger.warning("obsidian remember failed: %s", e)


def run() -> dict[str, Any]:
    t0 = time.time()
    profile = _collect_profile()
    rules_yaml = _read_rules()

    if not profile:
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "lookback_days": LOOKBACK_DAYS,
            "rules_analyzed": 0,
            "suggestions": [],
            "note": f"Keine Rule >= {MIN_FIRED} Feuerungen — zu spärliche Daten.",
            "duration_s": round(time.time() - t0, 2),
        }
    else:
        llm_out = _ask_llm(profile, rules_yaml)
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "lookback_days": LOOKBACK_DAYS,
            "rules_analyzed": len(profile),
            "profile": profile,
            "suggestions": llm_out.get("suggestions", []),
            "duration_s": round(time.time() - t0, 2),
        }
        if "_raw" in llm_out:
            report["llm_raw_excerpt"] = llm_out["_raw"]

    LAST_REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    LAST_REPORT_PATH.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str))

    _notify_discord(report)
    _audit_to_memory(report)
    try:
        from app.mqtt import publisher
        import json as _json
        topic = "homelab/brain/learner/run"
        body = _json.dumps({
            "rules_analyzed": report["rules_analyzed"],
            "suggestions_count": len(report.get("suggestions", [])),
            "duration_s": report["duration_s"],
        })
        if publisher._client is None:
            publisher.connect()
        publisher._client.publish(topic, body, qos=0, retain=False)
    except Exception as e:
        logger.warning("audit publish failed: %s", e)

    return report


def get_last() -> dict[str, Any] | None:
    if not LAST_REPORT_PATH.exists():
        return None
    try:
        return json.loads(LAST_REPORT_PATH.read_text())
    except Exception:
        return None
