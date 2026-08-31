#!/usr/bin/env python3
"""Ordnet jeder brain-bus-Regel einen der drei Push-Kanaele und einen Cooldown zu.

Hintergrund (2026-08-23): alle Meldungen liefen auf ein Topic (`host-critical`),
gemessen ~84 Pushes/Tag, jeweils doppelt auf Discord und Handy. Gleichzeitig kamen
11 Regeln mit gesetztem Topic nie an, weil die Zustellung an `priority in
{high, critical}` haengt — darunter `ssh-login-notify` und saemtliche Entwarnungen.

Die drei Kanaele:
  host-critical  weckt (Ausfall, Sicherheit, drohender Datenverlust)
  host-warn      tagsueber, leise (Kapazitaet, Degradation, kommt-noch)
  host-info      stumm (Entwarnungen, Routine, Nachschlagen)

Der Cooldown wirkt je Subjekt (`cooldown_key_fields`), nicht regel-global — sonst
verschluckt die erste gemeldete Unit die zweite. Genau deshalb steht der globale
Vorgabewert in rules.py bewusst auf 0; hier wird er pro Regel gesetzt.

Das Skript arbeitet zeilenweise auf dem Rohtext, damit die Begruendungs-Kommentare
in rules.yaml erhalten bleiben (ein yaml-Roundtrip wuerde sie verwerfen).

Aufruf:  python3 scripts/kanaele-zuordnen.py [--pruefen]
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

RULES = Path(__file__).resolve().parent.parent / "config" / "rules.yaml"

# rule_id -> (kanal, prioritaet, cooldown_s, cooldown_key_fields)
# Kanal "critical" ist bewusst knapp gehalten: nur was ein Aufstehen um 3 Uhr
# rechtfertigt. Alles, dessen richtige Reaktion "morgen ansehen" ist, gehoert nach warn.
ZUORDNUNG: dict[str, tuple[str, str, int, list[str]]] = {
    # --- weckt: Ausfall, Sicherheit, drohender Datenverlust ---
    "service-unhealthy-core":            ("critical", "high",   1800,  ["host", "service"]),
    "backup-run-failed":                 ("critical", "high",   3600,  ["host"]),
    "dns-stack-degraded":                ("critical", "high",   1800,  ["host"]),
    "disk-warning":                      ("critical", "high",   7200,  ["host"]),
    # Temperatur weckt nur im kritischen Fall: ab dort drosselt die Hardware selbst
    # und die naechste Stufe ist Abschaltung. Der jetson steht hier, weil sein Luefter
    # seit 2026-08-30 abgeschaltet ist und nur der Kuehlkoerper traegt.
    "jetson-temp-critical":              ("critical", "high",   1800,  ["host"]),
    "cpu-temp-critical":                 ("critical", "high",   1800,  ["host"]),
    "service-flapping":                  ("critical", "high",   3600,  ["host", "service"]),
    "host-memory-critical":              ("critical", "high",   3600,  ["host"]),
    "authelia-brute-force":              ("critical", "high",   1800,  ["host"]),
    "target-down":                       ("critical", "high",   3600,  ["host", "service"]),
    "container-restart-loop":            ("critical", "high",   3600,  ["host", "service"]),
    "auth-email-bruteforce-spike":       ("critical", "high",   1800,  ["host"]),
    "crowdsec-security-alert":           ("critical", "high",   1800,  ["host"]),
    "edge-domain-unreachable":           ("critical", "high",   1800,  ["domain"]),
    "db-integrity-failed":               ("critical", "high",   3600,  ["host", "db"]),
    "service-unhealthy-timeout":         ("critical", "high",   3600,  ["host", "container"]),
    # Die DR-Luecke, die sich 2026-08-23 still selbst kleingerechnet hat.
    "backup-completeness-degraded":      ("critical", "high",   21600, ["host"]),
    "restore-drill-failed":              ("critical", "high",   21600, ["host"]),
    "loki-security-alert":               ("critical", "high",   1800,  ["host", "container", "kind"]),
    "ct-log-alert":                      ("critical", "high",   3600,  ["domain"]),
    "attack-surface-alert":              ("critical", "high",   3600,  ["target"]),
    "ddos-schutz-aktiv":                 ("critical", "high",   1800,  []),
    # War auf prioritaet "default" — kein gueltiger Wert, wurde deshalb NIE zugestellt.
    # Ausgerechnet die Regel, die meldet, dass der DDoS-Waechter nichts mehr sieht.
    "ddos-schutz-blind":                 ("critical", "high",   21600, ["hosts"]),
    "game-saves-kaputt":                 ("critical", "high",   21600, ["wirt"]),

    # --- tagsueber, leise: Kapazitaet, Degradation, kommt-noch ---
    "service-degraded-core":             ("warn",     "normal", 3600,  ["host", "service"]),
    "backup-job-failed":                 ("warn",     "normal", 3600,  ["service_id"]),
    # Der Sammelalarm selbst weckt nicht: die ihn ausloesenden Einzelalarme stehen
    # auf critical und tragen das Aufwachen. Sonst klingelt eine Stoerung zweimal.
    "alert-storm":                       ("warn",     "normal", 1800,  []),
    "host-high-cpu-recurring":           ("warn",     "normal", 7200,  ["host"]),
    # Vorwarnstufen: richtige Reaktion ist "heute ansehen", nicht aufstehen.
    "jetson-temp-high":                  ("warn",     "normal", 7200,  ["host"]),
    "cpu-temp-warning":                  ("warn",     "normal", 7200,  ["host"]),
    "wireguard-degraded":                ("warn",     "normal", 3600,  ["host"]),
    "capacity-pressure":                 ("warn",     "normal", 7200,  ["host"]),
    "cert-expiry-soon":                  ("warn",     "normal", 86400, ["domain"]),
    "swap-in-use":                       ("warn",     "normal", 21600, ["host"]),
    "disk-fill-predicted":               ("warn",     "normal", 21600, ["host", "service"]),
    "memory-leak-suspected":             ("warn",     "normal", 21600, ["host", "container"]),
    "container-oom-predicted":           ("warn",     "normal", 21600, ["host", "container"]),
    "herb-chat-upstream-down-sustained": ("warn",     "normal", 1800,  []),
    "ha-sync-failures-streak":           ("warn",     "normal", 7200,  ["host"]),
    # 136 Meldungen in 3,8 Tagen — der Cooldown von 2026-08-19 hat gewirkt, der
    # Kanal blieb aber "critical". Beides zusammen ergibt erst Ruhe.
    "docker-network-unauthorized-connect": ("warn",   "normal", 3600,  ["host", "container"]),
    "crowdsec-security-decision":        ("warn",     "normal", 3600,  ["host"]),
    "network-device-discovered-new":     ("warn",     "normal", 3600,  ["mac"]),
    "systemd-unit-failed":               ("warn",     "normal", 3600,  ["host", "unit"]),
    # Einzige gewollte Abweichung vom Muster "warn -> normal": leiser Kanal, aber hohe
    # Prioritaet und damit auch Discord. Begruendung steht an der Regel selbst — der
    # Waechter meldet je Unit genau EINMAL, eine leise Meldung ginge unter. Genau so
    # blieben meldeweg-probe und ddos-waechter tagelang unbemerkt.
    "systemd-unit-orphan":               ("warn",     "high",   3600,  ["host", "unit"]),
    "db-growth-alert":                   ("warn",     "normal", 86400, ["host", "db"]),
    "service-readiness-degraded":        ("warn",     "normal", 3600,  ["host", "container"]),
    "mem-highwater":                     ("warn",     "normal", 3600,  ["host", "container"]),
    "mem-restart":                       ("warn",     "normal", 3600,  ["host", "container"]),
    "image-cve-alert":                   ("warn",     "normal", 86400, ["host", "image"]),
    "node18-orchestrator-failed":        ("warn",     "normal", 3600,  []),
    # Spielserver auf gamehost. Bewusst NICHT critical: niemand muss um 3 Uhr aufstehen,
    # weil ein Spiel nicht erreichbar ist — die richtige Reaktion ist "morgen ansehen".
    # Cooldown je Spiel, sonst verschluckt das erste kaputte Spiel das zweite.
    "spiel-nicht-weckbar":               ("warn",     "normal", 21600, ["spiel"]),
    "game-arbiter-steht":                ("warn",     "normal", 7200,  []),
    # 12 h Cooldown je Spiel: der Zustand ist per Definition ein Dauerzustand,
    # eine haeufigere Erinnerung an dieselbe Sache waere nur Laerm.
    "spiel-dauerhaft-nicht-startbar":    ("warn",     "normal", 43200, ["spiel"]),
    # Blindheit des Spiel-Waechters: aergerlich, aber ohne Sicherheits- oder
    # Datenverlust-Folge -- anders als bei ddos-schutz-blind, das deshalb critical ist.
    "spiel-metriken-fehlen":             ("warn",     "normal", 21600, []),
    # Blindheit des Versions-Waechters. Warn statt info, weil sie sonst genau das
    # Schicksal teilt, das sie meldet: unbemerkt bleiben. Ein veralteter Server
    # weist Spieler ab, steht aber weiter "online" in der Liste.
    "game-version-unmessbar":            ("warn",     "normal", 86400, ["spiel"]),

    # --- stumm: Entwarnungen, Routine, Nachschlagen ---
    # ★ BEWUSST OHNE Cooldown. Diese Regel traegt die Ende-zu-Ende-Probe des
    # Meldewegs (homelab-work/meldeweg-probe). Ein Cooldown daempft dann nicht
    # Laerm, sondern verschluckt den Gesundheitstest — die Probe meldet einen
    # gestoerten Meldeweg, obwohl nur ihr eigener Poke unterdrueckt wurde.
    # Ein Test-Poke wird absichtlich abgesetzt und stuermt nie.
    "auto-test-poke":                    ("info",     "low",    0,     []),
    "briefing-skip-storm":               ("info",     "low",    21600, []),
    "briefing-tuner-proposal":           ("info",     "low",    86400, []),
    "briefing-feedback-not-relevant-storm": ("info",  "low",    21600, []),
    "registry-critical-gaps":            ("info",     "low",    86400, []),
    "dashboard-db-bloat":                ("info",     "low",    86400, []),
    "edge-domain-resolved":              ("info",     "low",    300,   ["domain"]),
    "systemd-unit-recovered":            ("info",     "low",    300,   ["host", "unit"]),
    # Bewusst OHNE Cooldown: jede Anmeldung zaehlt einzeln. Bei ~3/Tag traegt der
    # stumme Kanal das, und ein Cooldown wuerde die zweite Anmeldung verschlucken —
    # also genau die, die interessant waere.
    "ssh-login-notify":                  ("info",     "low",    0,     ["host", "user", "source"]),
    "game-server-outdated":              ("info",     "low",    86400, ["spiel"]),
    "game-version-wieder-messbar":       ("info",     "low",    300,   ["spiel"]),
    "game-server-uptodate":              ("info",     "low",    86400, ["spiel"]),
}

TOPIC = {"critical": "host-critical", "warn": "host-warn", "info": "host-info"}

RE_ID = re.compile(r"^- id: (\S+)\s*$")
RE_TOP_KEY = re.compile(r"^  (\w+):")
RE_COOLDOWN = re.compile(r"^  cooldown_(seconds|key_fields):")


def umschreiben(text: str) -> str:
    zeilen = text.splitlines()
    aus: list[str] = []
    i = 0
    while i < len(zeilen):
        z = zeilen[i]
        m = RE_ID.match(z)
        if not m:
            aus.append(z)
            i += 1
            continue

        rid = m.group(1)
        if rid not in ZUORDNUNG:
            raise SystemExit(f"Regel ohne Zuordnung: {rid} — Tabelle ergaenzen, nicht raten.")
        kanal, prio, cooldown, keys = ZUORDNUNG[rid]

        # Regelblock einsammeln (bis zum naechsten '- id:' oder Dateiende).
        j = i + 1
        while j < len(zeilen) and not RE_ID.match(zeilen[j]):
            j += 1
        block = zeilen[i + 1 : j]

        # Alte Cooldown-Zeilen entfernen; die erklaerenden Kommentare direkt
        # darueber gehen mit, sonst stehen sie verwaist ueber einem neuen Wert.
        gefiltert: list[str] = []
        for k, bz in enumerate(block):
            if RE_COOLDOWN.match(bz):
                while gefiltert and gefiltert[-1].strip().startswith("#"):
                    gefiltert.pop()
                continue
            gefiltert.append(bz)
        block = gefiltert

        # ntfy-Block neu setzen.
        neu: list[str] = []
        k = 0
        while k < len(block):
            bz = block[k]
            if bz.strip() == "ntfy:":
                neu.append("  ntfy:")
                neu.append(f"    priority: {prio}")
                neu.append(f"    topic: {TOPIC[kanal]}")
                k += 1
                # alte Unterzeilen des ntfy-Blocks ueberspringen
                while k < len(block) and block[k].startswith("    "):
                    k += 1
                continue
            neu.append(bz)
            k += 1
        block = neu

        # Cooldown vor 'triage:' einsetzen (dort standen die bisherigen auch).
        einfuegen = [f"  cooldown_seconds: {cooldown}"]
        if keys:
            einfuegen.append(f"  cooldown_key_fields: [{', '.join(keys)}]")
        pos = next(
            (n for n, bz in enumerate(block) if bz.strip() == "triage:"),
            len(block),
        )
        block = block[:pos] + einfuegen + block[pos:]

        aus.append(z)
        aus.extend(block)
        i = j
    return "\n".join(aus) + "\n"


def pruefen(pfad: Path) -> int:
    """Liest das Ergebnis zurueck und vergleicht es gegen die Tabelle.

    Ohne diesen Schritt bewiese ein fehlerfreier Lauf nur, dass das Skript
    durchlief — nicht, dass in der Datei steht, was gemeint war.
    """
    d = yaml.safe_load(pfad.read_text(encoding="utf-8"))
    fehler = 0
    ids = {r["id"] for r in d["rules"]}
    for rid in ZUORDNUNG:
        if rid not in ids:
            print(f"FEHLT in rules.yaml: {rid}")
            fehler += 1
    for r in d["rules"]:
        # Eine Regel ohne Tabelleneintrag ist ein Befund, kein Skriptfehler: sie bekommt
        # ihren Kanal dann nie zugewiesen. Frueher stieg der Pruefer hier mit KeyError aus
        # -- das sah nach kaputtem Werkzeug aus und verdeckte die anderen Abweichungen
        # gleich mit, weil der Lauf abbrach (seit 2026-08-26 genau dieser Zustand).
        if r["id"] not in ZUORDNUNG:
            print(f"OHNE ZUORDNUNG in der Tabelle: {r['id']} — ergaenzen, nicht raten.")
            fehler += 1
            continue
        kanal, prio, cooldown, keys = ZUORDNUNG[r["id"]]
        ist = (
            r.get("ntfy", {}).get("topic"),
            r.get("ntfy", {}).get("priority"),
            int(r.get("cooldown_seconds", 0)),
            list(r.get("cooldown_key_fields") or []),
        )
        soll = (TOPIC[kanal], prio, cooldown, keys)
        if ist != soll:
            print(f"ABWEICHUNG {r['id']}:\n  ist  {ist}\n  soll {soll}")
            fehler += 1
    verteilung: dict[str, int] = {}
    for r in d["rules"]:
        verteilung[r["ntfy"]["topic"]] = verteilung.get(r["ntfy"]["topic"], 0) + 1
    print(f"\n{len(d['rules'])} Regeln, Verteilung: {verteilung}")
    ohne = [r["id"] for r in d["rules"] if not r.get("cooldown_seconds")]
    print(f"ohne Cooldown (bewusst): {ohne}")
    return fehler


if __name__ == "__main__":
    if "--pruefen" in sys.argv:
        sys.exit(1 if pruefen(RULES) else 0)
    original = RULES.read_text(encoding="utf-8")
    RULES.write_text(umschreiben(original), encoding="utf-8")
    print(f"{RULES} umgeschrieben.")
    sys.exit(1 if pruefen(RULES) else 0)
