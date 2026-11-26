#!/usr/bin/env python3
"""Ordnet jeder brain-bus-Regel einen der drei Push-Kanaele und einen Cooldown zu.

Hintergrund (2026-08-23): alle Meldungen liefen auf ein Topic (`host-critical`),
gemessen ~84 Pushes/Tag, jeweils doppelt auf Discord und Handy. Gleichzeitig kamen
11 Regeln mit gesetztem Topic nie an, weil die Zustellung an `priority in
{high, critical}` haengt: darunter `ssh-login-notify` und saemtliche Entwarnungen.

Die drei Kanaele:
  host-critical  weckt (Ausfall, Sicherheit, drohender Datenverlust)
  host-warn      tagsueber, leise (Kapazitaet, Degradation, kommt-noch)
  host-info      stumm (Entwarnungen, Routine, Nachschlagen)

Der Cooldown wirkt je Subjekt (`cooldown_key_fields`), nicht regel-global, sonst
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
    "service-flapping":                  ("critical", "high",   3600,  ["host", "service"]),
    "host-memory-critical":              ("critical", "high",   3600,  ["host"]),
    # Gitea-Anmeldewache (2026-10-06). Critical, weil Gitea keine Konto-Sperre
    # nach Fehlversuchen kennt, hier macht nichts von selbst zu. Ohne
    # Schluessel, es gibt eine Instanz und der Sturm-Ausdruck summiert.
    "gitea-anmeldung-sturm":             ("critical", "high",   1800,  []),
    "target-down":                       ("critical", "high",   3600,  ["host", "service"]),
    # CORE-Probe weckt, die allgemeine nicht. Der Unterschied ist derselbe wie
    # bei service-unhealthy-core gegen die breite Variante: fuer Home Assistant,
    # Gitea, Mosquitto und den Kalender ist Aufstehen die richtige Reaktion, fuer
    # eine fehlgeschlagene Probe an einem Wochenend-Dienst nicht.
    "core-probe-fehlgeschlagen":         ("critical", "high",   1800,  ["host", "service"]),
    "container-restart-loop":            ("critical", "high",   3600,  ["host", "service"]),
    "auth-email-bruteforce-spike":       ("critical", "high",   1800,  ["host"]),
    "crowdsec-security-alert":           ("critical", "high",   1800,  ["host"]),
    # Harte IOC-Befunde (Miner, ld.so.preload, Programm aus tmp). Der Waechter meldet
    # je Befund nur einmal, solange er besteht; die Abkuehlung faengt nur Doppellaeufe.
    "ioc-kritisch":                      ("critical", "high",   3600,  ["host"]),
    "edge-domain-unreachable":           ("critical", "high",   1800,  ["domain"]),
    "db-integrity-failed":               ("critical", "high",   3600,  ["host", "db"]),
    "service-unhealthy-timeout":         ("critical", "high",   3600,  ["host", "container"]),
    # Die breite Variante der beiden Zeilen darueber, und bewusst NICHT
    # critical: service-unhealthy-core deckt die CORE-Dienste ab, fuer die ein
    # Aufstehen richtig ist. Diese hier faengt jeden uebrigen Container auf
    # jedem Wirt. Am 2026-09-19 stand wake-gateway auf node1 acht Stunden
    # unhealthy, ohne dass jemand es erfuhr, und die Ursache war ein
    # Healthcheck auf einen abgeschalteten Port. Genau dafuer ist warn richtig.
    "container-unhealthy":               ("warn",     "normal", 21600, ["host", "name"]),
    # Auffangregel (ZIELBILD 99). Der Kanal hier ist nur der Rueckfall fuer einen
    # Alarm ohne severity; im Betrieb waehlt pipeline.py ihn je Alarm aus severity
    # oder Annotation `kanal`, die Ruhezeit aus Annotation `ruhezeit`.
    # Bibliothek-Einwurf auf node1 (2026-11-14): jede Meldung ist ein eigener
    # Einwurf, daher ohne Cooldown; eingelesen stumm, abgelehnt leise.
    "bibliothek-einwurf-eingelesen":     ("info",     "low",    0,     []),
    "bibliothek-einwurf-abgelehnt":      ("warn",     "normal", 0,     []),
    "alarm-auffang":                     ("warn",     "normal", 21600, ["fingerprint"]),
    # Die DR-Luecke, die sich 2026-08-23 still selbst kleingerechnet hat.
    "backup-completeness-degraded":      ("critical", "high",   21600, ["host"]),
    "restore-drill-failed":              ("critical", "high",   21600, ["host"]),
    # Kein Host-Feld: die Storage Box ist EINE geteilte Flaeche. Ein Cooldown je Wirt
    # haette denselben Befund siebenmal gemeldet, einmal pro sicherndem Host.
    # 12 h, weil der Fuellstand sich langsam bewegt und der Befund bis zur Entscheidung
    # (Aufbewahrung senken oder Box vergroessern) ohnehin bestehen bleibt.
    "offsite-kapazitaet":                ("critical", "high",   43200, []),
    # Dieselbe Sache eine Stufe frueher: platzbudget meldet ein ueberbuchtes
    # Repo, BEVOR die Box voll ist. Beide ohne host-Schluessel, weil die Box
    # eine geteilte Flaeche ist und ein Schluessel je Wirt denselben Befund
    # achtmal meldete.
    "platzbudget-ueberbucht":            ("critical", "high",   43200, []),
    "backup-exclude-unbekannt":          ("critical", "high",   86400, []),
    # --- Wiedervorlage (neu 2026-09-20) ---
    # Bewusst "warn", nicht "critical": das sind Befunde, die alle schon einmal
    # gemeldet wurden. Ein Wecken waere hier falsch, denn die richtige Reaktion
    # ist per Definition "heute ansehen", nicht "sofort aufstehen".
    # 20 h Cooldown statt 24: der Timer streut bis zu 5 min, genau 24 h wuerde
    # jeden zweiten Tag verschlucken. Keine key_fields, weil es EINE Liste fuer
    # den ganzen Bestand ist und kein Befund je Subjekt.
    "offene-befunde-wiedervorlage":      ("warn",     "normal", 72000, []),
    # --- Startseite (nachgezogen 2026-09-20) ---
    # --- finanzen (2026-09-26): die drei ausgewaehlten Meldungen ---
    # Keine davon weckt. Der Reisspunkt liegt per Vorgabe 60 Tage weg, ein
    # gerissenes Budget ist am naechsten Morgen genauso gerissen, und ein alter
    # Kurs macht die Anzeige veraltet und nicht falsch. Was hier nachts klingelte,
    # waere nach zwei Wochen stummgeschaltet.
    "finanzen-konto-reisst":             ("warn",     "normal", 86400,  []),
    "finanzen-budget-ueberschritten":    ("warn",     "normal", 86400,  []),
    # Der Kursabruf nach `info`: er aendert nichts am Geld, nur an der
    # Genauigkeit der Anzeige. Zwei Tage Ruhe, weil ein langes Wochenende ohne
    # neuen Boersenkurs der Normalfall ist.
    "finanzen-kursabruf":                ("info",     "low",    172800, []),
    # --- Fremdquellen der Tagesuebersicht (neu 2026-09-21) ---
    # --- Waechter-Herzschlag (neu 2026-09-20) ---
    # --- Audit-Quelle leer (neu 2026-10-15) ---
    # --- Hochgerechnete Restlebensdauer (neu 2026-10-13) ---
    # --- Gartikos Klimakette (neu 2026-10-16) ---
    # --- DNS-Redundanz (2026-10-24) ---
    # --- Soll-Ist-Abgleich der Dienste (2026-10-21) ---
    # Nach Dienst-KLASSE getrennt und nicht nach Namensliste. Fuer Home
    # Assistant, Gitea, Mosquitto oder das tardis ist Aufstehen die richtige
    # Reaktion, fuer einen fehlenden INTERNAL-Dienst nicht. Dieselbe Zweiteilung
    # wie bei `service-unhealthy-core` gegen die breite Variante. Eine
    # Namensliste in der Regel waere die Alternative, und die veraltet genau
    # dann, wenn ein neuer CORE-Dienst dazukommt.
    "dienst-soll-laeuft-nicht-kritisch":  ("critical", "high",   1800,  ["host", "dienst"]),
    # --- Sicherung je Position (2026-10-21) ---
    # Alle vier auf warn und nicht auf critical, obwohl es um die Sicherung
    # geht. Begruendung: `backup-run-failed` (critical, oben) deckt den Fall "der
    # Lauf scheitert". Diese vier sind die Feinsicht darunter -- eine einzelne
    # Position, die zurueckhaengt, ist ein Befund fuer den naechsten Vormittag.
    # Genau die Verwechslung dieser zwei Ebenen hat vom 17.10. bis 21.10. einen
    # critical getragen, der nichts Kritisches meinte.
    # --- Auslieferung der Welt-Archive (nachgetragen 2026-10-23) ---
    "chaos-drill-fehlschlag":             ("warn",     "normal", 86400, ["dienst"]),
    # --- lager (2026-10-24): die letzten vier Regeln ohne jeden Meldeweg ---
    # --- Selbstheilung (unit-heal-guard, neu 2026-09-20) ---
    # Meldet JEDEN Eingriff, auch den geglueckten: ein stiller Selbstheiler
    # verschiebt den blinden Fleck nur. "warn" statt "info", weil ein
    # geheilter Ausfall trotzdem eine Ursache hat, die beim chmod-Fall
    # regelmaessig im Deploy-Weg liegt und dort behoben gehoert, sonst
    # kommt sie beim naechsten Ausrollen wieder.
    "unit-geheilt":                      ("warn",     "normal", 3600,  ["host"]),
    "config-mount-geheilt":              ("warn",     "normal", 3600,  ["host"]),
    "container-nachgestartet":           ("warn",     "normal", 3600,  ["host"]),
    "loki-security-alert":               ("critical", "high",   1800,  ["host", "container", "kind"]),
    "ct-log-alert":                      ("critical", "high",   3600,  ["domain"]),
    "attack-surface-alert":              ("critical", "high",   3600,  ["target"]),
    "ddos-schutz-aktiv":                 ("critical", "high",   1800,  []),
    # War auf prioritaet "default", kein gueltiger Wert, wurde deshalb NIE zugestellt.
    # Ausgerechnet die Regel, die meldet, dass der DDoS-Waechter nichts mehr sieht.
    "ddos-schutz-blind":                 ("critical", "high",   21600, ["hosts"]),
    "game-saves-kaputt":                 ("critical", "high",   21600, ["wirt"]),

    # --- tagsueber, leise: Kapazitaet, Degradation, kommt-noch ---
    # Eine Zeile fuer ALLE blackbox-Proben ausser den CORE-Diensten, aus demselben
    # Grund wie beim Waechter-Herzschlag darueber: eine Tabelle, die je Probe
    # waechst, verliert genau die Zeile, auf die niemand sieht. Genau so standen
    # am 2026-09-27 19 von 68 Proben ohne jeden Meldeweg da.
    # Cooldown je Dienst, sonst verschluckt die erste ausgefallene Probe die
    # Meldung ueber die zweite.
    "probe-fehlgeschlagen":              ("warn",     "normal", 3600,  ["host", "service"]),
    # --- Die acht, die am 2026-09-27 ohne jeden Meldeweg dastanden ---
    # --- Jellyfin gegen den Media-Vault (neu 2026-10-03) ---
    # --- Navidrome gegen den Musik-Vault (Meldeweg nachgezogen 2026-11-02) ---
    "log-nachtdigest":                   ("info",     "low",    72000,  []),
    # Fitness-Anstoesse (2026-11-21 angeschlossen). Den Abstand haelt der Dienst
    # je Mandant, hier nur gegen Doppellaeufe; ein Rekord ist im Dienst einmalig.
    "fitness-rekord":                    ("info",     "low",    0,     []),
    # --- Backup-Abdeckung (neu 2026-10-04) ---
    "service-degraded-core":             ("warn",     "normal", 3600,  ["host", "service"]),
    "backup-job-failed":                 ("warn",     "normal", 3600,  ["service_id"]),
    # Der Sammelalarm selbst weckt nicht: die ihn ausloesenden Einzelalarme stehen
    # auf critical und tragen das Aufwachen. Sonst klingelt eine Stoerung zweimal.
    "alert-storm":                       ("warn",     "normal", 1800,  []),
    "wireguard-degraded":                ("warn",     "normal", 3600,  ["host"]),
    "capacity-pressure":                 ("warn",     "normal", 7200,  ["host"]),
    "cert-expiry-soon":                  ("warn",     "normal", 86400, ["domain"]),
    "swap-in-use":                       ("warn",     "normal", 21600, ["host"]),
    # Neu 2026-10-17: den Fall, den swap-in-use strukturell nicht sehen kann
    # (Freeze bei 90 % Swap und 23 bis 29 % freiem RAM, Watchdog-Reset).
    # high, weil hier noch etwa eine Stunde Zeit zum Handeln ist.
    "swap-thrashing":                    ("warn",     "high",   7200,  ["host"]),
    "load-saturated":                    ("warn",     "normal", 10800, ["host"]),
    "disk-fill-predicted":               ("warn",     "normal", 21600, ["host", "service"]),
    # Beide standen hier bis zum 2026-11-04 auf ["host", "container"], waehrend
    # rules.yaml seit 7f067f2/70c192b (03./04.11.) die korrigierten Felder trug.
    # Ein Lauf dieses Skripts haette die Korrektur still zurueckgedreht.
    # cAdvisor nennt den Container im Label `name`, nicht `container`: mit
    # [host, container] teilten sich alle Container eines Wirts einen
    # Schluessel, ai-llm und ai-llm-slow auf node2 feuerten am selben Tag, der
    # zweite verschwand in der Abkuehlzeit des ersten. memory-leak-suspected ist
    # ein Host-Befund (Container-Lecks meldet container-oom-predicted).
    "memory-leak-suspected":             ("warn",     "normal", 21600, ["labels.host"]),
    "container-oom-predicted":           ("warn",     "normal", 21600, ["labels.host", "labels.name"]),
    "herb-chat-upstream-down-sustained": ("warn",     "normal", 1800,  []),
    "ha-sync-failures-streak":           ("warn",     "normal", 7200,  ["host"]),
    # Schluessel ist die ZONE, nicht der Container, und das ist der ganze
    # Punkt dieser Regel. Hier stand bis zum 2026-10-24 ["host", "container"] mit
    # der Notiz, der Cooldown von 2026-08-19 habe gewirkt. Gemessen an dem Tag:
    # 644 Pushes, 249 in einer einzigen Stunde, jeder mit einem LLM-Aufruf von 75
    # bis 79 s auf der Slow-Lane, dazu ntfy und IRC. Der Cooldown hat fuer diese
    # Regel NIE gewirkt: ihr Subjekt ist ein UNGEPLANTER Container, und ein
    # `docker run --rm` traegt bei jedem Lauf einen neuen Zufallsnamen. Damit ist
    # der Abkuehlschluessel bei jedem Ereignis neu, und ein Schluessel, der sich je
    # Ereignis aendert, ist keine Abkuehlung. Dasselbe gilt eine Stufe tiefer fuer
    # die Entprellung im Watcher (`host:container:network`, 5 s) und fuer die
    # Whitelist, die aus genau diesen Tripeln besteht.
    # Stabil ist die Zone: "auf host ist etwas Ungeplantes cc-proxy beigetreten"
    # ist die Aussage, auf die man reagiert. Der Containername gehoert in den Text
    # der Meldung, nicht in den Schluessel.
    # ⚠️ Preis, bewusst bezahlt: ein echter Fremdcontainer in derselben Zone
    # innerhalb der Stunde wird mitgedaempft. Die Regel aggregiert dafuer
    # (min_events/window_seconds) und nennt die Zahl der Ereignisse.
    # Die uebrigen Regeln mit "container" im Schluessel sind davon NICHT
    # betroffen (am 24.10. alle 275 durchgesehen): sie meinen benannte
    # Compose-Container, deren Name stabil ist.
    "docker-network-unauthorized-connect": ("warn",   "normal", 3600,  ["host", "network"]),
    "crowdsec-security-decision":        ("warn",     "normal", 3600,  ["host"]),
    "network-device-discovered-new":     ("warn",     "normal", 3600,  ["mac"]),
    "systemd-unit-failed":               ("warn",     "normal", 3600,  ["host", "unit"]),
    # Laptop-Erinnerung (2026-11-19): kommt nur, wenn der Laptop im Haus ist und
    # seine Sicherung laut Gesamtbericht zu alt ist. Der Sender bremst selbst auf
    # 6 h; die Abkuehlung hier faengt einen Neustart des Senders ab.
    "laptop-sicherung-erinnerung":       ("warn",     "normal", 21600, ["host"]),
    # Einzige gewollte Abweichung vom Muster "warn -> normal": leiser Kanal, aber hohe
    # Prioritaet und damit auch Discord. Begruendung steht an der Regel selbst, der
    # Waechter meldet je Unit genau EINMAL, eine leise Meldung ginge unter. Genau so
    # blieben meldeweg-probe und ddos-waechter tagelang unbemerkt.
    "systemd-unit-orphan":               ("warn",     "high",   3600,  ["host", "unit"]),
    "db-growth-alert":                   ("warn",     "normal", 86400, ["host", "db"]),
    "db-engine-veraltet":                ("warn",     "normal", 604800, ["host", "container"]),
    "service-readiness-degraded":        ("warn",     "normal", 3600,  ["host", "container"]),
    "mem-highwater":                     ("warn",     "normal", 3600,  ["host", "container"]),
    "mem-restart":                       ("warn",     "normal", 3600,  ["host", "container"]),
    # Eine Meldung je Lauf und Art (2026-11-01). 1 h statt 24 h: scan.py meldet
    # ohnehin nur NEUE CVE-IDs und vermerkt sie nach Zustellung als gemeldet; eine
    # lange Abkuehlung wuerde einen zweiten Lauf am selben Tag (Neubau von Hand)
    # verschlucken, den der Scanner als zugestellt verbucht, der Befund waere weg.
    # [host, kind] statt [host, image]: scan.py schickt EINE Meldung je Lauf, nach
    # CVE gebuendelt (vorher ein Push je Image, elf in einer Minute fuer eine CVE).
    # Auf demselben Topic meldet sammeln.py die Fremdwirte mit kind
    # cve-critical-fremdwirt bzw. cve-scan-veraltet; beide Arten je Wirt duerfen
    # sich nicht gegenseitig wegkuehlen. (Bis 2026-11-04 stand das in rules.yaml
    # ueber cooldown_seconds, wo jeder Lauf dieses Skripts es loescht.)
    "image-cve-alert":                   ("warn",     "normal", 3600,  ["host", "kind"]),
    # ioc-waechter (2026-11-21). Neu = Abweichung von der Grundlinie, stumm und
    # ohne-root auf demselben Topic; [host, kind], damit sich die Arten je Wirt
    # nicht gegenseitig wegkuehlen. Die harte Stufe steht oben unter critical.
    "ioc-befund":                        ("warn",     "normal", 3600,  ["host", "kind"]),
    "node18-orchestrator-failed":        ("warn",     "normal", 3600,  []),
    # Blindheit des Versions-Waechters. Warn statt info, weil sie sonst genau das
    # Schicksal teilt, das sie meldet: unbemerkt bleiben. Ein veralteter Server
    # weist Spieler ab, steht aber weiter "online" in der Liste.
    "game-version-unmessbar":            ("warn",     "normal", 86400, ["spiel"]),
    "game-version-auto-offen":           ("warn",     "normal", 86400, ["spiel", "art", "status"]),
    # pin-wache: neue Version oder ungleiche Wirte, sieben Tage je Image; Blindheit taeglich.
    "pin-veraltet":                      ("warn",     "normal", 604800, ["name"]),
    "pin-abweichend":                    ("warn",     "normal", 604800, ["name"]),
    "pin-unmessbar":                     ("warn",     "normal", 86400, ["name"]),
    # Der Befund selbst gehoert in denselben Kanal wie die Blindheit darueber, und
    # stand bis zum 2026-09-19 eine Stufe leiser (info, also stumm und ohne Discord).
    # Die Begruendung der Zeile darueber galt damit fuer die Meldung "ich kann nicht
    # messen", nicht aber fuer "ich habe gemessen, und der Server ist veraltet".
    # Gemessen am Ergebnis: Valheim stand vier Protokollversionen zurueck (network
    # version 36 gegen 40, fuer jeden aktuellen Client unbetretbar) und Zomboid vier
    # Wochen, waehrend jeden Morgen eine stumme Meldung herausging. Ein Tagescooldown
    # je Spiel bleibt, der Zustand aendert sich nur durch das Einspielen.
    "game-server-outdated":              ("warn",     "normal", 86400, ["spiel"]),
    # Die Mod-Ebene desselben Befunds. Gleicher Kanal, gleicher Tagescooldown: ein
    # veralteter Mod-Stand ist ein Dauerzustand, der sich nur durch Mod-Pflege aendert.
    "game-mods-outdated":                ("warn",     "normal", 86400, ["spiel"]),
    # --- eMMC (jetsons Boot-Karte), ergaenzt 2026-10-15 -----------------------
    # Stand schon in rules.yaml, fehlte aber hier und bekam seinen Kanal damit
    # nie zugewiesen (der Pruefer meldete sie als "OHNE ZUORDNUNG").
    # Der Eintrag bestaetigt den vorgefundenen Ist-Zustand, er aendert ihn nicht.
    "vektorsuche-degradiert":            ("warn",     "normal", 21600, ["host", "container"]),


    # Die einzige Regel hier, die keinen Stoerfall meldet: die taegliche
    # Erinnerung an einen Pruefungstermin. Sie steht in `warn` und nicht in
    # `info`, obwohl sie keine Warnung ist, denn `info` ist stumm und eine
    # Erinnerung, die niemand bemerkt, erinnert nicht. Genau daran ist der in
    # den Apps eingebaute Weg gescheitert, nur stiller: dort war die ganze
    # Push-Kette gebaut und jedes Glied gerissen.
    # Der Cooldown von 12 h haelt sie bei einem doppelten Anstoss bei einer
    # Nachricht am Tag. Die Regel selbst traegt `ohne_deutung: true`, sonst
    # haengt die Kaskade eine erfundene Ursache an lauter Messwerte.
    "lernen-erinnerung":                 ("warn",     "normal", 43200, []),
    "ci-lauf-rot":                       ("warn",     "normal", 3600,  ["repo"]),

    # --- stumm: Entwarnungen, Routine, Nachschlagen ---
    # BEWUSST OHNE Cooldown. Diese Regel traegt die Ende-zu-Ende-Probe des
    # Meldewegs (interne Notiz). Ein Cooldown daempft dann nicht
    # Laerm, sondern verschluckt den Gesundheitstest, die Probe meldet einen
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
    # stumme Kanal das, und ein Cooldown wuerde die zweite Anmeldung verschlucken,
    # also genau die, die interessant waere.
    "ssh-login-notify":                  ("info",     "low",    0,     ["host", "user", "source"]),
    "game-version-wieder-messbar":       ("info",     "low",    300,   ["spiel"]),
    "game-version-auto-eingespielt":     ("info",     "low",    300,   ["spiel", "art"]),
    "game-server-uptodate":              ("info",     "low",    86400, ["spiel"]),
    # Eine Lampe rechtfertigt keine Unterbrechung. Stumm, aber nachschlagbar --
    # der Unterschied zur Steckdose ist, dass "aus" hier ein gueltiger Zustand ist.
    # Die drei stummen der Beobachtungsguete-Gruppe (2026-09-19). Merklisten,
    # keine Stoerungen: ein nie aktivierter Timer und eine Regel ohne Subjekt
    # sind meist die richtige Folge einer bewussten Entscheidung. Unsichtbar
    # bleiben sollen sie trotzdem nicht -- genau so stand
    # TapoLeuchtmittelLaengerWeg am 2026-09-12 ohne ein einziges Geraet da.
    # 7 Tage Cooldown, weil sich der Zustand nur durch eine Entscheidung aendert.
    "systemd-timer-verwaist-stehend":    ("info",     "low",    604800, ["beobachtet", "unit"]),






    # Neustartschleife (2026-10-15). `warn` und nicht `critical`: der Wirt
    # traegt es, und ein Dienst in der Schleife ist ein Zustand fuer den
    # naechsten Blick, kein Weckgrund. Schluessel `name`, weil bei einem
    # Port-Streit typisch zwei Container betroffen sind und ein gemeinsamer
    # Cooldown den zweiten verschluckte.
    "container-neustartschleife":        ("warn",     "normal", 21600,  ["name"]),

    # Der einzige auf dem stummen Kanal: severity info, und der Inhalt ist eine
    # Entwarnung mit einer Aufgabe dahinter, kein Vorfall.


    # --- sieben Zustellwege nachgezogen, 2026-10-11 ---
    # Die loeschgeschuetzte Zweitsicherung auf dem jetson (2026-10-15).
    # `warn` und nicht `critical`: faellt dieser Satz aus, ist kein Datum weg
    # und die Off-Site-Kopie nach Hetzner laeuft weiter. Weg ist der Schutz
    # GEGEN LOESCHEN, und das ist ein Zustand fuer den naechsten Tag, kein
    # Weckgrund mitten in der Nacht.
    # `high` als Prioritaet trotzdem, denn nur ab `high` stellt brain-bus auch
    # auf Discord zu, und eine ausgefallene Sicherung soll nicht allein im
    # stummen Kanal liegen.
    # Halbtags-Cooldown: der Lauf ist taeglich, eine Meldung je Lauf genuegt.
    # Beide Regeln sind der Grund, warum der Meldeweg-Abgleich existiert:
    # die Sonde `jetson_backup_*` stand drei Wochen auf erfolg=0 und hatte
    # ueberhaupt keine Alarmregel. Nach dem Bau der Regeln meldete
    # `abgleich.py` sie als "OHNE JEDEN MELDEWEG" -- eine scharfe Regel ohne
    # Zustellung ist dieselbe Stille, nur eine Ebene hoeher.
    "zweitziel-sicherung-fehlgeschlagen": ("warn",  "high",   43200, ["host"]),
    "finanzen-kuendigungsfrist":          ("warn",     "normal", 86400, []),
    "finanzen-kuendigung-unbekannt":      ("info",     "low",    604800, []),
    # Garantie-Alarm aus dem Lager (2026-11-14): sechs Tage, damit eine Sache im
    # 14-Tage-Fenster drei Mal kommt (14, 8, 2 Tage vorher), je Kennung.
    "lager-garantie-laeuft-ab":           ("warn",     "normal", 518400, ["kennung"]),
    # --- Meldewege nachgezogen 2026-10-24: Schwere der Alarmregel, nie lauter ---
    "nachtbericht":                      ("warn",     "normal", 43200, []),
    # Einmal je reparierter Version, der Waechter merkt sich das selbst.
    "patch-verfuegbar":                  ("warn",     "normal", 43200, []),
}

TOPIC = {"critical": "host-critical", "warn": "host-warn", "info": "host-info"}

RE_ID = re.compile(r"^- id: (\S+)\s*$")
RE_TOP_KEY = re.compile(r"^  (\w+):")
RE_COOLDOWN = re.compile(r"^  cooldown_(seconds|key_fields):")

# Kommentarzeilen, die beim Umschreiben verworfen wurden: (regel_id, zeile).
# Wird am Ende gemeldet, siehe Begruendung an der Entfernungsstelle.
VERWORFEN: list[tuple[str, str]] = []


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
            raise SystemExit(f"Regel ohne Zuordnung: {rid}, Tabelle ergaenzen, nicht raten.")
        kanal, prio, cooldown, keys = ZUORDNUNG[rid]

        # Regelblock einsammeln (bis zum naechsten '- id:' oder Dateiende).
        j = i + 1
        while j < len(zeilen) and not RE_ID.match(zeilen[j]):
            j += 1
        block = zeilen[i + 1 : j]

        # Alte Cooldown-Zeilen entfernen; die erklaerenden Kommentare direkt
        # darueber gehen mit, sonst stehen sie verwaist ueber einem neuen Wert.
        # Das ist Absicht und hat einen Preis: eine Begruendung, die jemand
        # hier in rules.yaml ueber `cooldown_seconds:` schreibt, ist beim naechsten
        # Lauf weg. Der Ort fuer die Begruendung ist die Tabelle oben. Bis zum
        # 2026-10-24 geschah das Loeschen STILL, und genau so sind an dem Tag drei
        # Begruendungen aus den Sitzungen vom 23./24.10. verschwunden (zwei davon
        # standen gekuerzt auch in der Tabelle, eine war danach nirgends mehr).
        # Gesehen wurde es nur, weil jemand den Diff gelesen hat. Deshalb wird
        # jetzt gemeldet, was entfernt wurde: ein Werkzeug, das Text verwirft,
        # sagt, welchen.
        gefiltert: list[str] = []
        for k, bz in enumerate(block):
            if RE_COOLDOWN.match(bz):
                while gefiltert and gefiltert[-1].strip().startswith("#"):
                    VERWORFEN.append((rid, gefiltert.pop().strip()))
                continue
            gefiltert.append(bz)
        block = gefiltert

        # ntfy-Block neu setzen.
        ntfy_block = [
            "  ntfy:",
            f"    priority: {prio}",
            f"    topic: {TOPIC[kanal]}",
        ]
        neu: list[str] = []
        k = 0
        vorhanden = False
        while k < len(block):
            bz = block[k]
            if bz.strip() == "ntfy:":
                vorhanden = True
                neu.extend(ntfy_block)
                k += 1
                # alte Unterzeilen des ntfy-Blocks ueberspringen
                while k < len(block) and block[k].startswith("    "):
                    k += 1
                continue
            neu.append(bz)
            k += 1
        block = neu

        # Fehlt der Block ganz, wird er angelegt statt uebergangen. Bis
        # 2026-09-20 aktualisierte diese Stelle nur einen vorhandenen Block --
        # eine NEU angelegte Regel behielt damit dauerhaft keinen Kanal, und
        # das Werkzeug, dessen einzige Aufgabe die Kanalzuordnung ist, meldete
        # dabei Erfolg. Sichtbar wurde es erst im Pruefer, und auch dort nur
        # als Absturz. Gegenprobe ist `--pruefen`: die Zeile "OHNE ntfy-Kanal"
        # muss leer bleiben.
        if not vorhanden:
            # Vor `suggest_topic:` einsetzen, wo der Block bei allen anderen
            # Regeln auch steht. Ohne Anker ans Ende der Regel, aber VOR den
            # abschliessenden Leerzeilen -- dahinter gehoerte er syntaktisch
            # schon zur naechsten Regel.
            pos = next(
                (n for n, bz in enumerate(block) if bz.startswith("  suggest_topic:")),
                None,
            )
            if pos is None:
                pos = len(block)
                while pos > 0 and not block[pos - 1].strip():
                    pos -= 1
            block = block[:pos] + ntfy_block + block[pos:]

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
    durchlief, und nicht, dass in der Datei steht, was gemeint war.
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
            print(f"OHNE ZUORDNUNG in der Tabelle: {r['id']}, ergaenzen, nicht raten.")
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
    # `r["ntfy"]` statt `r.get("ntfy")` liess den Pruefer mit KeyError
    # abstuerzen, sobald eine Regel noch gar keinen ntfy-Block hatte. Genau der
    # Fall tritt bei jeder NEU angelegten Regel ein (umschreiben() aktualisiert
    # einen vorhandenen Block, es legt keinen an), und dann bricht ausgerechnet
    # die Gegenprobe ab, statt den Mangel zu benennen. Gefunden am 2026-09-20
    # beim Anlegen der Wiedervorlage-Regeln.
    verteilung: dict[str, int] = {}
    ohne_kanal = []
    for r in d["rules"]:
        ziel = (r.get("ntfy") or {}).get("topic")
        if not ziel:
            ohne_kanal.append(r["id"])
            continue
        verteilung[ziel] = verteilung.get(ziel, 0) + 1
    print(f"\n{len(d['rules'])} Regeln, Verteilung: {verteilung}")
    if ohne_kanal:
        # Kein Absturz, aber auch kein Achselzucken: eine Regel ohne Kanal
        # feuert ins Leere und sieht dabei aus wie eine funktionierende Regel.
        print(f"OHNE ntfy-Kanal ({len(ohne_kanal)}), diese melden NIRGENDWO hin: "
              f"{ohne_kanal}")
        fehler += len(ohne_kanal)
    ohne = [r["id"] for r in d["rules"] if not r.get("cooldown_seconds")]
    print(f"ohne Cooldown (bewusst): {ohne}")
    return fehler


if __name__ == "__main__":
    if "--pruefen" in sys.argv:
        sys.exit(1 if pruefen(RULES) else 0)
    original = RULES.read_text(encoding="utf-8")
    RULES.write_text(umschreiben(original), encoding="utf-8")
    print(f"{RULES} umgeschrieben.")
    if VERWORFEN:
        print(f"\n⚠️  {len(VERWORFEN)} Kommentarzeile(n) ueber Cooldown-Zeilen "
              f"entfernt. Steht die Begruendung auch in der Tabelle dieses "
              f"Skripts? Wenn nicht, ist sie jetzt weg:")
        for rid, zeile in VERWORFEN:
            print(f"    {rid}: {zeile}")
    sys.exit(1 if pruefen(RULES) else 0)
