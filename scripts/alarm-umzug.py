#!/usr/bin/env python3
"""Reine Weiterleitungsregeln aus brain-bus in die Prometheus-Regel umziehen.

ZIELBILD 99 Stufe 3. Seit der Auffangregel `alarm-auffang` braucht ein
Prometheus-Alarm keine eigene brain-bus-Regel mehr: Kanal, Ruhezeit und Texte
stehen als Annotations in der Prometheus-Regel. Dieses Werkzeug zieht jede
brain-bus-Regel um, die nichts weiter tut als weiterreichen:

  * Topic `homelab/alerts/<Name>/fired` ohne Platzhalter
  * keine `diagnose`, keine `action`, `min_events` 1
  * `triage` nur mit hint, erster_schritt, memory_tags
  * Platzhalter nur `event.payload.labels.X` und `event.payload.summary`

Je Regel: `hint` wird Annotation `hinweis`, `erster_schritt` bleibt; Kanal und
Ruhezeit kommen nur dann als Annotation `kanal`/`ruhezeit` dazu, wenn sie von
der Vorgabe abweichen (Kanal aus severity, Ruhezeit 6h). Platzhalter werden
Prometheus-Vorlagen: `labels.X` zu `$labels.X`, `summary` zur Vorlage der
summary-Annotation selbst. Die Begruendungskommentare der brain-bus-Regel und
ihrer Zeile in kanaele-zuordnen.py ziehen NICHT mit: beim ersten Versuch hingen
Abschnittskoepfe danach ueber fremden Regeln. Sie bleiben in der Git-Historie
von brain-bus (Stand vor dem Umzug: 546d6b8). Die promtool-Tests bekommen die neuen
Annotations gerendert in ihre `exp_annotations`.

Prioritaet `high` auf host-warn (Discord plus ntfy 4) gibt es danach nicht
mehr: die Auffangregel kennt drei Kanaele mit fester Prioritaet. Gewollt, siehe
ZIELBILD 99 (6): Haus-Alarme raus aus Discord.

    python3 scripts/alarm-umzug.py --trocken     nur zaehlen und auflisten
    python3 scripts/alarm-umzug.py               umziehen (Dateien schreiben)

Danach: kanaele-zuordnen.py --pruefen, handlungstexte-pruefen.py,
monitoring/regeltests.sh, Unittests.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml

BB = Path(__file__).resolve().parent.parent
RULES = BB / "config" / "rules.yaml"
ZUORDNUNG = BB / "scripts" / "kanaele-zuordnen.py"
MON = Path("/home/user/docker/monitoring/prometheus")
PROM = MON / "alerts.rules.yml"

KANAL_TOPIC = {"host-critical": "critical", "host-warn": "warn", "host-info": "info"}
KANAL_AUS_SEVERITY = {"critical": "critical", "warning": "warn", "info": "info"}
RUHEZEIT_VORGABE = 21600
ERLAUBTE_TRIAGE = {"hint", "erster_schritt", "memory_tags"}
PLATZHALTER = re.compile(r"\{\{\s*([^}]*?)\s*\}\}")
RE_ID = re.compile(r"^- id:\s*(\S+)\s*$")


def dauer(sekunden: int) -> str:
    for einheit, faktor in (("d", 86400), ("h", 3600), ("m", 60)):
        if sekunden and sekunden % faktor == 0:
            return f"{sekunden // faktor}{einheit}"
    return str(sekunden)


def uebersetzbar(text: str) -> bool:
    return all(
        p == "event.payload.summary" or re.fullmatch(r"event\.payload\.labels\.\w+", p)
        for p in PLATZHALTER.findall(text)
    )


def nach_prometheus(text: str, summary_vorlage: str) -> str:
    def ersetze(m: re.Match[str]) -> str:
        p = m.group(1)
        if p == "event.payload.summary":
            return summary_vorlage
        return "{{ $labels.%s }}" % p.rsplit(".", 1)[1]
    return PLATZHALTER.sub(ersetze, text)


def fuer_test(text: str, labels: dict, summary: str) -> str:
    def ersetze(m: re.Match[str]) -> str:
        p = m.group(1)
        if p == "event.payload.summary":
            return summary
        return str(labels.get(p.rsplit(".", 1)[1], ""))
    return PLATZHALTER.sub(ersetze, text)


def yaml_wert(text: str) -> str:
    # JSON-Strings sind gueltige YAML-Strings in doppelten Anfuehrungszeichen.
    return json.dumps(text, ensure_ascii=False)


def kandidaten() -> tuple[dict[str, dict], list[tuple[str, str]]]:
    regeln = yaml.safe_load(RULES.read_text(encoding="utf-8"))["rules"]
    prom = yaml.safe_load(PROM.read_text(encoding="utf-8"))
    prom_regeln = {r["alert"]: r for g in prom["groups"] for r in g["rules"] if "alert" in r}
    umzug: dict[str, dict] = {}
    bleibt: list[tuple[str, str]] = []
    for r in regeln:
        topic = r["match"]["topic"]
        teile = topic.split("/")
        if len(teile) != 4 or teile[:2] != ["homelab", "alerts"] or "+" in topic or r.get("rueckfall"):
            continue
        name = teile[2]
        grund = []
        if r.get("diagnose"):
            grund.append("diagnose")
        if r.get("action"):
            grund.append("action")
        if int(r["match"].get("min_events", 1)) != 1:
            grund.append("min_events")
        triage = r.get("triage") or {}
        if set(triage) - ERLAUBTE_TRIAGE:
            grund.append("triage " + ",".join(sorted(set(triage) - ERLAUBTE_TRIAGE)))
        if name not in prom_regeln:
            grund.append("keine Prometheus-Regel")
        else:
            ann = prom_regeln[name].get("annotations") or {}
            if set(ann) & {"hinweis", "erster_schritt", "kanal", "ruhezeit", "meldeweg"}:
                grund.append("Annotation schon gesetzt")
        for feld in ("hint", "erster_schritt"):
            if not uebersetzbar(str(triage.get(feld) or "")):
                grund.append(f"{feld}: Platzhalter nicht uebersetzbar")
        if grund:
            bleibt.append((r["id"], "; ".join(grund)))
            continue
        prom_regel = prom_regeln[name]
        ann = prom_regel.get("annotations") or {}
        severity = (prom_regel.get("labels") or {}).get("severity", "")
        summary = str(ann.get("summary") or "")
        neu: dict[str, str] = {}
        hint = str(triage.get("hint") or "").strip()
        if hint:
            neu["hinweis"] = nach_prometheus(hint, summary)
        schritt = str(triage.get("erster_schritt") or "").strip()
        if schritt:
            neu["erster_schritt"] = nach_prometheus(schritt, summary)
        kanal = KANAL_TOPIC.get((r.get("ntfy") or {}).get("topic"), "")
        if kanal and kanal != KANAL_AUS_SEVERITY.get(severity):
            neu["kanal"] = kanal
        ruhe = int(r.get("cooldown_seconds", 0))
        if ruhe != RUHEZEIT_VORGABE:
            neu["ruhezeit"] = dauer(ruhe)
        umzug[name] = {
            "id": r["id"], "neu": neu, "triage": triage, "summary": summary,
            "prio_alt": (r.get("ntfy") or {}).get("priority"), "kanal_alt": kanal,
        }
    return umzug, bleibt


def brain_bus_bloecke(zeilen: list[str]) -> dict[str, tuple[int, int, list[str]]]:
    """rule_id -> (start, ende, kommentare). Start schliesst die direkt
    darueberstehenden Kommentarzeilen ein, Ende die eigenen Zeilen bis vor die
    Kommentare der naechsten Regel."""
    ids = [(i, RE_ID.match(z).group(1)) for i, z in enumerate(zeilen) if RE_ID.match(z)]

    def kopf(i: int) -> int:
        k = i
        while k > 0 and zeilen[k - 1].lstrip().startswith("#") and not zeilen[k - 1].startswith("# ---"):
            k -= 1
        return k

    bloecke = {}
    for n, (i, rid) in enumerate(ids):
        start = kopf(i)
        if n + 1 < len(ids):
            ende = kopf(ids[n + 1][0])
        else:
            ende = len(zeilen)
        # Leerzeilen am Ende bleiben stehen (Abstand zur naechsten Regel)
        while ende > i + 1 and not zeilen[ende - 1].strip():
            ende -= 1
        kommentare = [z.strip() for z in zeilen[start:ende] if z.lstrip().startswith("#")]
        bloecke[rid] = (start, ende, kommentare)
    return bloecke


def zuordnung_zeilen(zeilen: list[str], rid: str) -> tuple[int, int, list[str]] | None:
    muster = re.compile(r'^\s*"%s"\s*:' % re.escape(rid))
    for i, z in enumerate(zeilen):
        if muster.match(z):
            k = i
            while k > 0 and zeilen[k - 1].lstrip().startswith("#") and "---" not in zeilen[k - 1]:
                k -= 1
            return k, i + 1, [z.strip() for z in zeilen[k:i]]
    return None


def prom_einfuegen(zeilen: list[str], name: str, neu: dict[str, str], kommentare: list[str]) -> None:
    for i, z in enumerate(zeilen):
        m = re.match(r"^(\s*)- alert:\s*(\S+)\s*$", z)
        if not m or m.group(2) != name:
            continue
        einzug = len(m.group(1))
        j = i + 1
        while not re.match(r"^\s{%d}annotations:\s*$" % (einzug + 2), zeilen[j]):
            if re.match(r"^\s{0,%d}- " % einzug, zeilen[j]):
                raise SystemExit(f"{name}: kein annotations-Block")
            j += 1
        for k, (schluessel, wert) in enumerate(neu.items()):
            zeilen.insert(j + 1 + k, " " * (einzug + 4) + f"{schluessel}: {yaml_wert(wert)}")
        return
    raise SystemExit(f"{name}: Prometheus-Regel nicht gefunden")


def tests_nachziehen(umzug: dict[str, dict], schreiben: bool) -> int:
    geaendert = 0
    for datei in sorted(MON.glob("alerts.*.test.yml")):
        zeilen = datei.read_text(encoding="utf-8").split("\n")
        daten = yaml.safe_load("\n".join(zeilen))
        # Je exp_annotations-Block die Labels und die summary aus YAML lesen,
        # die Zeilen dann in Dateireihenfolge zuordnen.
        erwartet = []
        for test in daten.get("tests") or []:
            for at in test.get("alert_rule_test") or []:
                for alarm in at.get("exp_alerts") or []:
                    if "exp_annotations" in alarm:
                        erwartet.append((at["alertname"], alarm.get("exp_labels") or {},
                                         str((alarm["exp_annotations"] or {}).get("summary") or "")))
        n = 0
        aus = []
        for z in zeilen:
            aus.append(z)
            m = re.match(r"^(\s*)exp_annotations:\s*$", z)
            if not m:
                continue
            name, labels, summary = erwartet[n]
            n += 1
            if name not in umzug:
                continue
            for schluessel, wert in umzug[name]["neu"].items():
                if schluessel in ("hinweis", "erster_schritt"):
                    roh = str(umzug[name]["triage"].get("hint" if schluessel == "hinweis" else "erster_schritt")).strip()
                    wert = fuer_test(roh, labels, summary)
                aus.append(m.group(1) + "  " + f"{schluessel}: {yaml_wert(wert)}")
            geaendert += 1
        if n != len(erwartet):
            raise SystemExit(f"{datei.name}: {n} exp_annotations-Zeilen, {len(erwartet)} im YAML")
        if schreiben and aus != zeilen:
            datei.write_text("\n".join(aus), encoding="utf-8")
    return geaendert


def main() -> int:
    trocken = "--trocken" in sys.argv
    umzug, bleibt = kandidaten()
    print(f"Umzug: {len(umzug)} Regeln, bleiben: {len(bleibt)}")
    for rid, grund in bleibt:
        print(f"  bleibt {rid}: {grund}")
    discord_weg = [n for n, u in umzug.items() if u["kanal_alt"] == "warn" and u["prio_alt"] == "high"]
    print(f"warn mit Prioritaet high (verlieren Discord): {len(discord_weg)}")
    print(f"mit Annotation kanal: {sum('kanal' in u['neu'] for u in umzug.values())}, "
          f"mit ruhezeit: {sum('ruhezeit' in u['neu'] for u in umzug.values())}")

    rules_zeilen = RULES.read_text(encoding="utf-8").split("\n")
    zu_zeilen = ZUORDNUNG.read_text(encoding="utf-8").split("\n")
    prom_zeilen = PROM.read_text(encoding="utf-8").split("\n")
    bloecke = brain_bus_bloecke(rules_zeilen)

    weg_rules: list[tuple[int, int]] = []
    weg_zu: list[tuple[int, int]] = []
    for name, u in umzug.items():
        start, ende, kommentare = bloecke[u["id"]]
        weg_rules.append((start, ende))
        zu = zuordnung_zeilen(zu_zeilen, u["id"])
        if zu:
            weg_zu.append((zu[0], zu[1]))
            kommentare = kommentare + zu[2]
        prom_einfuegen(prom_zeilen, name, u["neu"], [])

    for start, ende in sorted(weg_rules, reverse=True):
        del rules_zeilen[start:ende]
    for start, ende in sorted(weg_zu, reverse=True):
        del zu_zeilen[start:ende]
    # doppelte Leerzeilen, die das Loeschen hinterlaesst, zusammenziehen
    rules_text = re.sub(r"\n{3,}", "\n\n", "\n".join(rules_zeilen))

    tests = tests_nachziehen(umzug, schreiben=not trocken)
    print(f"Test-Erwartungen nachgezogen: {tests}")
    if trocken:
        print("(trocken, nichts geschrieben)")
        return 0
    RULES.write_text(rules_text, encoding="utf-8")
    ZUORDNUNG.write_text("\n".join(zu_zeilen), encoding="utf-8")
    PROM.write_text("\n".join(prom_zeilen), encoding="utf-8")
    yaml.safe_load(RULES.read_text(encoding="utf-8"))
    yaml.safe_load(PROM.read_text(encoding="utf-8"))
    print("geschrieben.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
