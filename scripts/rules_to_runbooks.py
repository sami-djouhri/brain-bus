#!/usr/bin/env python3
"""rules_to_runbooks.py, Generate the known-error-pattern runbook catalog from
the brain-bus rules.yaml.

The brain-bus rule engine is the deterministic source of truth for known failure
modes: each rule pairs a signal (MQTT topic) with triage context, diagnosis
tools, optional automated remediation (action + risk → Discord approval) and
memory recall of prior occurrences. This renders each rule as a human-readable
runbook note in the obsidian-memory homelab vault so the voice assistant can
answer "this happened before, what's the known fix?" and the catalog stays in
sync with what the engine actually does.

Hybrid design (the chosen approach): rules.yaml stays the machine-authoritative
config; these notes are the queryable knowledge layer. No parallel matching
logic is introduced into the live pipeline.

Output: <vault>/runbooks/patterns/<rule_id>.md  + runbooks/patterns/00-index.md
All notes carry generated: true so hand-authored runbooks are never touched.
"""
from __future__ import annotations

import argparse
import datetime
import os
import sys

import yaml

RISK_BEHAVIOUR = {
    "low": "Wird **automatisch** ausgeführt (geringes Risiko).",
    "medium": "Erfordert **manuelle Freigabe** per Discord-Button (host-Junior), dann automatische Ausführung.",
    "high": "**Nur Benachrichtigung**, keine automatische Aktion.",
}


def stamp() -> str:
    return datetime.date.today().isoformat()


def fm(fields: dict) -> str:
    lines = ["---"]
    for key, val in fields.items():
        if isinstance(val, list):
            lines.append(f"{key}:")
            for item in val:
                lines.append(f"  - {item}")
        else:
            lines.append(f"{key}: {val}")
    lines.append("---")
    return "\n".join(lines)


def runbook(rule: dict) -> str:
    rid = rule["id"]
    match = rule.get("match", {}) or {}
    triage = rule.get("triage", {}) or {}
    action = rule.get("action") or None
    diagnose = rule.get("diagnose") or []
    tags = ["homelab", "runbook", "error-pattern", "generated"] + list(triage.get("memory_tags", []) or [])

    out = [fm({
        "title": f"Fehlerbild: {rid}",
        "kind": "runbook",
        "rule_id": rid,
        "source_space": "homelab",
        "generated": "true",
        "generated_by": "brain-bus/rules_to_runbooks.py",
        "updated": stamp(),
        "tags": sorted(set(tags)),
    }), "", f"# Fehlerbild: `{rid}`", ""]

    out += ["## Auslöser (Signal)", "",
            f"- MQTT-Topic: `{match.get('topic','?')}`",
            f"- Schwelle: {match.get('min_events', 1)} Event(s) in {match.get('window_seconds', 60)} s", ""]

    if triage.get("hint"):
        out += ["## Bedeutung", "", triage["hint"], ""]

    if diagnose:
        out += ["## Automatische Diagnose", ""]
        for step in diagnose:
            out.append(f"- `{step.get('tool','?')}`")
        out.append("")

    out += ["## Reaktion", ""]
    if action:
        risk = str(action.get("risk", "")).lower()
        out += [
            f"- Empfohlene Aktion: `{action.get('tool','?')}`",
            f"- Risiko-Stufe: **{risk or 'unbestimmt'}**, {RISK_BEHAVIOUR.get(risk, 'Verhalten siehe Engine.')}",
        ]
        if action.get("confidence_threshold") is not None:
            out.append(f"- Confidence-Schwelle: {action['confidence_threshold']}")
        if action.get("when"):
            out.append(f"- Bedingungen: `{action['when']}`")
        out.append("")
    else:
        out += ["- **Nur Benachrichtigung**, diese Regel überwacht und meldet, führt aber keine Aktion aus.", ""]

    out += ["## Vorgeschichte (Wiederauftreten)", "",
            "Beim Auslösen ruft brain-bus `memory.recall` für ähnliche frühere "
            "Vorfälle ab; das Ergebnis jeder Aktion wird wieder ins Memory "
            "geschrieben (Audit-Trail). So erkennt das System wiederkehrende "
            "Fehlerbilder und zeigt die Historie bei der Freigabe.", ""]

    if triage.get("memory_tags"):
        out += ["## Memory-Tags", "", ", ".join(f"`{t}`" for t in triage["memory_tags"]), ""]

    return "\n".join(out)


def index_note(rules: list[dict]) -> str:
    auto = [r for r in rules if (r.get("action") or {}).get("risk", "").lower() in ("low",)]
    confirm = [r for r in rules if (r.get("action") or {}).get("risk", "").lower() in ("medium", "med")]
    notify = [r for r in rules if not r.get("action")]
    out = [fm({
        "title": "Fehlerbild-Katalog (Index)",
        "kind": "catalog-index",
        "source_space": "homelab",
        "generated": "true",
        "generated_by": "brain-bus/rules_to_runbooks.py",
        "updated": stamp(),
        "tags": ["homelab", "runbook", "error-pattern", "catalog", "generated"],
    }), "", "# Fehlerbild-Katalog", "",
        "_Generiert aus den brain-bus-Regeln (`rules.yaml`). Jede Regel ist ein "
        "bekanntes Fehlerbild mit Signal, Diagnose und Reaktion._", "",
        f"Stand: {stamp()}, {len(rules)} überwachte Fehlerbilder.", "",
        f"## Mit automatischer Freigabe-Aktion ({len(confirm)})", "",
        "_Bei Wiederauftreten: Benachrichtigung → Discord-Freigabe → Ausführung._", ""]
    for r in confirm:
        out.append(f"- [[{r['id']}]], `{(r.get('action') or {}).get('tool','')}`")
    out += ["", f"## Voll-automatisch ({len(auto)})", ""]
    for r in auto:
        out.append(f"- [[{r['id']}]], `{(r.get('action') or {}).get('tool','')}`")
    out += ["", f"## Nur Benachrichtigung ({len(notify)})", ""]
    for r in notify:
        out.append(f"- [[{r['id']}]], {(r.get('triage') or {}).get('hint','')[:80]}")
    out.append("")
    return "\n".join(out)


def write(path: str, content: str, dry: bool) -> str:
    if dry:
        return f"DRY  {path}"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            if "generated: true" not in fh.read(400):
                return f"SKIP (hand-authored)  {path}"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return f"WROTE  {path}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", default="/home/user/docker/brain-bus/config/rules.yaml")
    ap.add_argument("--vault", default="/vault/homelab")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    with open(args.rules, encoding="utf-8") as fh:
        rules = (yaml.safe_load(fh) or {}).get("rules", []) or []

    base = os.path.join(args.vault, "runbooks", "patterns")
    results = [write(os.path.join(base, "00-index.md"), index_note(rules), args.dry_run)]
    for rule in rules:
        results.append(write(os.path.join(base, f"{rule['id']}.md"), runbook(rule), args.dry_run))

    for line in results:
        print(line)
    print(f"\n{len(rules)} error-pattern runbooks from rules.yaml.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
