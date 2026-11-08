"""Verlauf aus der Tageschronik fuer kritische Alarme (ZIELBILD 67 Stufe 4).

Entscheid 04.11.2026: jeder Alarm mit severity critical bekommt mit, wann
er zuletzt da war und was danach dazu gebaut wurde. Quelle ist die Chronik im
node1-Vault (`memory/chronik/JJJJ/MM/JJJJ-MM-TT.md`, interne Notiz).

Regelbasiert, ohne Sprachmodell (Regel): jede Tagesnotiz wird per Pfad
gelesen und Zeile fuer Zeile verglichen. Der Vektor-Recall verpasste dabei Tage
(gemessen 04.11. im host-router: zehn aehnlichste Notizen, nicht alle Tage).

Wortlaut: "danach dazu committet", nicht "geloest durch". Ob ein Commit den
Fehler behoben hat, steht in keiner Quelle; der Satz muss woertlich stimmen.
"""

from __future__ import annotations

import asyncio
import re
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import httpx

from app.logging_config import get_logger

log = get_logger(__name__)

OBSIDIAN_URL = "http://192.0.2.10:8765"
TOKEN_FILE = Path("/run/secrets/obsidian_token")
TAGE = 60
TZ = ZoneInfo("Europe/Berlin")

MONATE = ["Januar", "Februar", "März", "April", "Mai", "Juni", "Juli", "August",
          "September", "Oktober", "November", "Dezember"]

_ALARMZEILE = re.compile(
    r"^- (?P<spanne>.+?): (?P<name>[A-Za-z0-9]+)(?: \((?P<wo>[^)]*)\))?(?: \[(?P<schwere>\w+)\])?\s*$")
_COMMIT = re.compile(r"^- (?P<zeit>\d\d:\d\d) `(?P<sha>[0-9a-f]{7})` (?P<text>.+)$")


def chronik_pfad(tag: date) -> str:
    return f"memory/chronik/{tag:%Y}/{tag:%m}/{tag.isoformat()}.md"


def alarmname(topic: str, payload: dict[str, Any]) -> str:
    teile = topic.split("/")
    if len(teile) == 4 and teile[0] == "homelab" and teile[1] == "alerts":
        return teile[2]
    return str(payload.get("alertname") or "")


def ist_kritisch(payload: dict[str, Any]) -> bool:
    schwere = payload.get("severity") or (payload.get("labels") or {}).get("severity")
    return str(schwere or "").lower() == "critical"


def _abschnitt(inhalt: str, titel: str) -> list[str]:
    m = re.search(rf"^### {re.escape(titel)}.*?\n(.*?)(?=^##|\Z)", inhalt, re.M | re.S)
    return m.group(1).splitlines() if m else []


def _gebaut(inhalt: str) -> list[tuple[str, str, str, str]]:
    """(repo, zeit, sha, text) aus dem Abschnitt Gebaut."""
    teil = inhalt.split("## Gebaut", 1)[1].split("## Ereignisse", 1)[0] if "## Gebaut" in inhalt else ""
    repo = ""
    aus = []
    for z in teil.splitlines():
        m = re.match(r"^### ([\w./-]+) \(\d+\)$", z)
        if m:
            repo = m.group(1)
            continue
        m = _COMMIT.match(z)
        if m and repo:
            aus.append((repo, m.group("zeit"), m.group("sha"), m.group("text")))
    return aus


def _subjekt(labels: dict[str, Any]) -> list[str]:
    """Woran eine Chronikzeile denselben Fall erkennt: Host und Dienstname."""
    werte = []
    for k in ("host", "name", "container", "service", "unit", "geraet", "instanz"):
        v = str(labels.get(k) or "").strip()
        if v and v not in werte:
            werte.append(v)
    return werte


# Erste Namenshaelfte, die zu allgemein ist, um Commits zuzuordnen.
_ALLGEMEIN = {"host", "gast", "container", "service", "systemd", "alarm", "neustart", "probe",
              "target", "node", "disk", "config", "image", "waechter", "dienst"}


def _minuten(hhmm: str) -> int:
    return int(hhmm[:2]) * 60 + int(hhmm[3:5])


def _ende(name: str, tag: date, notizen: dict[date, str]) -> str:
    """Ende einer Phase "über Mitternacht hinaus" aus den Folgetagen."""
    for i in range(1, TAGE):
        t = tag + timedelta(days=i)
        if t not in notizen:
            return ""
        for z in _abschnitt(notizen[t], "Alarme"):
            m = _ALARMZEILE.match(z)
            if m and m.group("name") == name and m.group("spanne").startswith("seit dem Vortag"):
                b = re.search(r"bis (\d\d:\d\d)", m.group("spanne"))
                if b:
                    return f"bis {t.day}. {MONATE[t.month - 1]} {b.group(1)}"
                break  # lief auch diesen Tag durch, weiter zum naechsten
        else:
            return ""
    return ""


def verlauf_text(name: str, notizen: dict[date, str], heute: date, labels: dict[str, Any] | None = None) -> str:
    """Ein bis drei Saetze Verlauf, oder ein Satz, dass es der erste Fall ist.

    Heute zaehlt nur mit abgeschlossenen Phasen ("bis HH:MM"): die laufende ist
    der Alarm, der gerade gemeldet wird."""
    labels = labels or {}
    subjekt = _subjekt(labels)
    host = str(labels.get("host") or "")
    faelle: list[tuple[date, str, str]] = []  # (tag, spanne, wo)
    for tag in sorted(notizen, reverse=True):
        for z in _abschnitt(notizen[tag], "Alarme"):
            m = _ALARMZEILE.match(z)
            if not m or m.group("name") != name:
                continue
            spanne = m.group("spanne")
            if spanne.startswith("seit dem Vortag"):
                continue  # dieselbe Phase steht schon am Vortag
            if tag == heute and " bis " not in spanne:
                continue
            faelle.append((tag, spanne, m.group("wo") or ""))
    zeitraum = f"{len(notizen)} Tagen mit Chronik"
    if not faelle:
        return f"Verlauf (Chronik): kein früherer Fall von {name} in {zeitraum}."
    gleich = [f for f in faelle if host and f[2].split(",")[0].strip() == host]
    tag, spanne, wo = (gleich or faelle)[0]
    if "über Mitternacht hinaus" in spanne:
        bis = _ende(name, tag, notizen)
        spanne = spanne.replace(", über Mitternacht hinaus", f" {bis}" if bis else ", über Mitternacht hinaus")
    tage_n = len({f[0] for f in faelle})
    if wo:
        spanne = spanne[:-1] + f", {wo})" if spanne.endswith(")") else f"{spanne} ({wo})"
    satz = f"Verlauf (Chronik): zuletzt am {tag.day}. {MONATE[tag.month - 1]} {spanne}, an {tage_n} von {zeitraum}."
    if host and not gleich:
        satz += f" Auf {host} bisher nicht."
    # Regelmaessig: mindestens drei Faelle beginnen innerhalb von 15 Minuten.
    beginne = [_minuten(b.group(1)) for _, sp, _ in faelle if (b := re.match(r"(\d\d:\d\d)", sp))]
    if len(beginne) >= 3:
        mitte = sorted(beginne)[len(beginne) // 2]
        nah = [b for b in beginne if abs(b - mitte) <= 15]
        if len(nah) >= 3 and len(nah) >= len(beginne) * 0.6:
            satz += f" Kommt regelmäßig gegen {mitte // 60:02d}:{mitte % 60:02d} ({len(nah)} von {len(beginne)} Fällen)."
    # Danach committet: am Tag des Falls ab Beginn und am Folgetag, Text nennt
    # den Alarmnamen, sonst das Subjekt oder die erste Namenshaelfte.
    beginn = re.match(r"(\d\d:\d\d)", spanne)
    erster = re.match(r"[A-Z][a-z]+", name)
    kandidaten = [name] + [s for s in subjekt if s != host and len(s) >= 4]
    if erster and len(erster.group(0)) >= 5 and erster.group(0).lower() not in _ALLGEMEIN:
        kandidaten.append(erster.group(0))
    for wort in kandidaten:
        treffer = []
        for t in (tag, tag + timedelta(days=1)):
            for repo, zeit, sha, text in _gebaut(notizen.get(t, "")):
                if t == tag and beginn and zeit < beginn.group(1):
                    continue
                if wort.lower() in text.lower():
                    treffer.append(f"{repo.split('/')[-1]} {sha} „{text[:80]}“")
        if treffer:
            mehr = f" (+{len(treffer) - 2})" if len(treffer) > 2 else ""
            return satz + f" Danach committet, mit „{wort}“ im Text: " + "; ".join(treffer[:2]) + mehr + "."
    return satz + " Danach kein Commit, der ihn oder sein Subjekt nennt."


async def _lies(client: httpx.AsyncClient, sperre: asyncio.Semaphore, tag: date) -> tuple[date, str]:
    async with sperre:
        try:
            r = await client.get(f"{OBSIDIAN_URL}/notes", params={"path": chronik_pfad(tag)})
            if r.status_code == 200:
                return tag, str(r.json().get("content") or "")
        except Exception:
            pass
    return tag, ""


async def fuer_ereignis(topic: str, payload: dict[str, Any], *, timeout: float = 15.0) -> str:
    """Verlaufszeile fuer ein kritisches Alarm-Ereignis, sonst leer. Fail-silent."""
    if not ist_kritisch(payload):
        return ""
    name = alarmname(topic, payload)
    if not name:
        return ""
    try:
        token = TOKEN_FILE.read_text().strip()
    except OSError:
        return ""
    heute = datetime.now(TZ).date()
    sperre = asyncio.Semaphore(8)
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(8.0, connect=2.0),
                                     headers={"Authorization": f"Bearer {token}"}) as c:
            gelesen = await asyncio.wait_for(
                asyncio.gather(*(_lies(c, sperre, heute - timedelta(days=i)) for i in range(TAGE))), timeout)
    except asyncio.TimeoutError:
        log.warning("verlauf.timeout", alarm=name)
        return ""
    notizen = {t: inhalt for t, inhalt in gelesen if inhalt}
    if not notizen:
        log.warning("verlauf.keine_chronik", alarm=name)
        return ""
    return verlauf_text(name, notizen, heute, payload.get("labels") or {})
