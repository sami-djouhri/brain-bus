#!/usr/bin/env python3
"""Hausregeln als Pruefung: die still scheiternden Fallen aus der die Projektregeln.

hausregeln: datei-ausnehmen (diese Datei nennt die Muster, die sie sucht)

Warum eine Pruefung und keine Zeile im Text. Jede Regel hier steht seit einem
Vorfall in der die Projektregeln, und jede ist von der Art, die beim Lesen richtig
aussieht und im Betrieb nichts tut: eine DOCKER-USER-Regel mit `--dport` sieht nie
ein Paket, `rsync --exclude='.env'` schuetzt bei `--delete` nicht, eine Gatus-
Bedingung ohne `[CONNECTED]` ist gruen ohne Antwort. Ein Text, den man beim
Schreiben im Kopf haben muss, haelt das nicht auf.

Quelle ist `~/docker/scripts/hausregeln/`. Jedes Repo der CI-Liste traegt eine
Kopie unter `.gitea/hausregeln.py`, verteilt und auf Gleichstand geprueft von
interne Notiz (der Runner liest nur das
eigene Repo).

Grundlinie: was beim Einfuehren schon da war, steht je Repo in
`.gitea/hausregeln-grundlinie.json` und wird nur gemeldet. Rot wird ein Lauf erst
durch einen NEUEN Verstoss. Der Schluessel ist Regel, Datei und ein Hash der
Zeile, nicht die Zeilennummer: eine Aenderung weiter oben macht nichts rot.

    python3 hausregeln.py [WURZEL]                        # pruefen, 1 bei neuem Verstoss
    python3 hausregeln.py [WURZEL] --grundlinie-schreiben  # heutigen Stand festhalten
    python3 hausregeln.py [WURZEL] --alle                  # auch die Grundlinie zeigen
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - im CI installiert, auf host vorhanden
    yaml = None

GRUNDLINIE = Path(".gitea") / "hausregeln-grundlinie.json"
AUSNAHME_DATEI = "hausregeln: datei-ausnehmen"
AUSNAHME_ZEILE = "hausregeln: bewusst"

NIE_PRUEFEN = {".git", "node_modules", "dist", "build", ".cache", "__pycache__", ".pytest_cache",
               ".gradle", ".android", ".venv", "venv", "_retired", ".svelte-kit", ".gitea"}
TEXT = {".md", ".py", ".sh", ".bash", ".ts", ".js", ".svelte", ".yml", ".yaml", ".kt", ".kts",
        ".toml", ".json", ".service", ".timer", ".conf", ".txt", ".html", ".css", ".sql", ".rules"}
SKRIPT = {".sh", ".bash", ".py", ".yml", ".yaml", ".service", ".timer", ".conf", ".rules"}
NIE_TEXT = {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "uv.lock"}
OFFEN = {"0.0.0.0", "127.0.0.1", "::", "::1"}


@dataclass(frozen=True)
class Fund:
    regel: str
    datei: str
    zeile: int
    inhalt: str
    hinweis: str

    def schluessel(self) -> str:
        roh = re.sub(r"\s+", " ", self.inhalt.strip())
        return f"{self.regel}|{self.datei}|{hashlib.sha1(roh.encode()).hexdigest()[:12]}"


# ------------------------------------------------------------------ Dateien

def dateien(wurzel: Path) -> list[Path]:
    """Verfolgte Dateien, sonst alle (im CI liegt ein Archiv ohne .git).

    `git ls-files` statt Verzeichnislauf: so sieht der Prueflauf auf host
    dasselbe wie der Runner, und gitignorierte `.env`, Datenbanken und
    Laufzeitdaten werden nie geoeffnet.
    """
    try:
        aus = subprocess.run(["git", "-C", str(wurzel), "ls-files", "-z"], capture_output=True,
                             check=True).stdout.decode().split("\0")
        kandidaten = [wurzel / p for p in aus if p]
    except (subprocess.CalledProcessError, FileNotFoundError):
        kandidaten = [p for p in wurzel.rglob("*") if p.is_file()]
    heraus = []
    for p in kandidaten:
        teile = p.relative_to(wurzel).parts
        if any(t in NIE_PRUEFEN for t in teile[:-1]) or p.name in NIE_TEXT:
            continue
        if p.suffix in TEXT or p.name == "Makefile" or p.name.startswith(("Dockerfile", "docker-compose")):
            if p.is_file():
                heraus.append(p)
    return sorted(heraus)


def lies(p: Path) -> str | None:
    try:
        text = p.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None
    return None if AUSNAHME_DATEI in "\n".join(text.splitlines()[:8]) else text


def logische_zeilen(text: str) -> list[tuple[int, str]]:
    """Zeilen mit Backslash-Fortsetzung zusammengezogen, mit Nummer der ersten."""
    aus, puffer, start = [], "", 0
    for nr, zeile in enumerate(text.splitlines(), 1):
        if not puffer:
            start = nr
        if zeile.rstrip().endswith("\\"):
            puffer += zeile.rstrip()[:-1] + " "
            continue
        aus.append((start, puffer + zeile))
        puffer = ""
    if puffer:
        aus.append((start, puffer))
    return aus


def zeile_von(text: str, nadel: str) -> int:
    for nr, z in enumerate(text.splitlines(), 1):
        if nadel in z:
            return nr
    return 1


# ------------------------------------------------------------------ Regeln

EM_DASH = chr(0x2014)


def em_dash(rel: str, text: str) -> list[Fund]:
    return [Fund("em-dash", rel, nr, z, "Em-Dash: Regel, nirgendwo (Komma, Doppelpunkt oder Punkt)")
            for nr, z in enumerate(text.splitlines(), 1) if EM_DASH in z]


DPORT = re.compile(r"DOCKER-USER.*--dport\b|--dport\b.*DOCKER-USER")


def dport_docker_user(rel: str, text: str) -> list[Fund]:
    return [Fund("dport-docker-user", rel, nr, z,
                 "DOCKER-USER sieht Pakete nach dem DNAT: --ctorigdstport statt --dport")
            for nr, z in logische_zeilen(text)
            if DPORT.search(z) and not z.lstrip().startswith("#") and AUSNAHME_ZEILE not in z]


EXCLUDE_ENV = re.compile(r"--exclude[= ]+['\"]?\.env['\"]?(?=[\s'\"]|$)")
FILTER_ENV = re.compile(r"--filter[= ]+['\"]?P \.env")


def rsync_env(rel: str, text: str) -> list[Fund]:
    aus = []
    for nr, z in logische_zeilen(text):
        if "rsync" in z and "--delete" in z and EXCLUDE_ENV.search(z) and not FILTER_ENV.search(z):
            if not z.lstrip().startswith("#") and AUSNAHME_ZEILE not in z:
                aus.append(Fund("rsync-env", rel, nr, z,
                                "--exclude='.env' schuetzt bei --delete nicht: --filter='P .env' dazu"))
    return aus


def _yaml(text: str):
    if yaml is None:
        return None
    try:
        return yaml.safe_load(text)
    except Exception:
        return None


def compose(rel: str, text: str) -> list[Fund]:
    """Netze ohne Subnetz, Ports an einer Host-IP, host-mode-Healthcheck ohne Kennung."""
    d = _yaml(text)
    if not isinstance(d, dict) or not isinstance(d.get("services"), dict):
        return []
    zeilen = text.splitlines()
    aus = []
    for name, cfg in (d.get("networks") or {}).items():
        cfg = cfg if isinstance(cfg, dict) else {}
        if cfg.get("external"):
            continue
        if any("subnet" in (c or {}) for c in ((cfg.get("ipam") or {}).get("config") or [])):
            continue
        aus.append(Fund("compose-subnetz", rel, zeile_von(text, f"{name}:"), f"netz {name}",
                        "Compose-Netz ohne ipam.config.subnet: Auto-Vergabe kann das LAN ueberdecken"))
    for sname, s in d["services"].items():
        if not isinstance(s, dict):
            continue
        for port in s.get("ports") or []:
            ip = None
            if isinstance(port, str):
                m = re.match(r"^\[?([0-9a-fA-F:.]+?)\]?:\d", port)
                if m and port.count(":") >= 2:
                    ip = m.group(1)
            elif isinstance(port, dict):
                ip = port.get("host_ip")
            if ip and ip not in OFFEN:
                z = zeile_von(text, str(port) if isinstance(port, str) else ip)
                if zeilen and AUSNAHME_ZEILE in zeilen[z - 1]:
                    continue
                aus.append(Fund("port-host-ip", rel, z, f"{sname} {port}",
                                "Port an eine Host-IP gekoppelt: 0.0.0.0: oder 127.0.0.1:"
                                " (bewusste LAN-Bindings mit Kommentar 'hausregeln: bewusst')"))
        test = (s.get("healthcheck") or {}).get("test")
        test = " ".join(test) if isinstance(test, list) else str(test or "")
        if s.get("network_mode") == "host" and re.search(r"\b(curl|wget)\b", test) \
                and re.search(r"localhost|127\.0\.0\.1", test) and not re.search(r"grep|jq|\|", test):
            aus.append(Fund("hostmode-healthcheck", rel, zeile_von(text, "healthcheck"), f"{sname} {test}",
                            "host-mode teilt den Netzstapel: Kennung im Antworttext pruefen, sonst"
                            " meldet ein Nachbar die Gesundheit"))
    return aus


def gatus(rel: str, text: str) -> list[Fund]:
    d = _yaml(text)
    if not isinstance(d, dict) or not isinstance(d.get("endpoints"), list):
        return []
    aus = []
    for ep in d["endpoints"]:
        if not isinstance(ep, dict) or not ep.get("conditions"):
            continue
        erste = str(ep["conditions"][0]).replace(" ", "")
        if erste != "[CONNECTED]==true":
            name = str(ep.get("name") or ep.get("url"))
            aus.append(Fund("gatus-connected", rel, zeile_von(text, name), f"endpoint {name}",
                            "erste Bedingung muss [CONNECTED] == true sein, sonst gruen ohne Antwort"))
    return aus


def pruefe_datei(wurzel: Path, p: Path) -> list[Fund]:
    text = lies(p)
    if text is None:
        return []
    rel = p.relative_to(wurzel).as_posix()
    aus = em_dash(rel, text)
    if p.suffix in SKRIPT or p.name == "Makefile" or p.name.startswith("Dockerfile"):
        aus += dport_docker_user(rel, text) + rsync_env(rel, text)
    if p.suffix in {".yml", ".yaml"}:
        aus += compose(rel, text) + gatus(rel, text)
    return aus


def pruefe(wurzel: Path) -> list[Fund]:
    return [f for p in dateien(wurzel) for f in pruefe_datei(wurzel, p)]


# ------------------------------------------------------------------ Grundlinie

def lade_grundlinie(pfad: Path) -> Counter:
    if not pfad.is_file():
        return Counter()
    return Counter(json.loads(pfad.read_text(encoding="utf-8")).get("eintraege", {}))


def schreibe_grundlinie(pfad: Path, funde: list[Fund]) -> None:
    pfad.parent.mkdir(parents=True, exist_ok=True)
    zaehl = Counter(f.schluessel() for f in funde)
    pfad.write_text(json.dumps({"version": 1, "eintraege": dict(sorted(zaehl.items()))},
                               indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


def neue(funde: list[Fund], grundlinie: Counter) -> list[Fund]:
    """Was ueber die Grundlinie hinausgeht; je Schluessel zaehlt die Anzahl."""
    rest = Counter(grundlinie)
    aus = []
    for f in funde:
        k = f.schluessel()
        if rest[k] > 0:
            rest[k] -= 1
        else:
            aus.append(f)
    return aus


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Hausregeln pruefen")
    ap.add_argument("wurzel", nargs="?", default=".")
    ap.add_argument("--grundlinie-schreiben", action="store_true")
    ap.add_argument("--alle", action="store_true", help="auch die Funde der Grundlinie zeigen")
    args = ap.parse_args(argv)
    wurzel = Path(args.wurzel).resolve()
    funde = pruefe(wurzel)
    pfad = wurzel / GRUNDLINIE
    if args.grundlinie_schreiben:
        schreibe_grundlinie(pfad, funde)
        print(f"Grundlinie: {len(funde)} Funde in {pfad.relative_to(wurzel)}")
        return 0
    frisch = neue(funde, lade_grundlinie(pfad))
    zeigen = funde if args.alle else frisch
    for f in zeigen:
        print(f"{f.datei}:{f.zeile}: [{f.regel}] {f.hinweis}\n    {f.inhalt.strip()[:160]}")
    alt = len(funde) - len(frisch)
    print(f"hausregeln: {len(frisch)} neu, {alt} aus der Grundlinie")
    return 1 if frisch else 0


if __name__ == "__main__":
    sys.exit(main())
