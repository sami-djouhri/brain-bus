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
    # ★ Die breite Variante der beiden Zeilen darueber, und bewusst NICHT
    # critical: service-unhealthy-core deckt die CORE-Dienste ab, fuer die ein
    # Aufstehen richtig ist. Diese hier faengt jeden uebrigen Container auf
    # jedem Wirt. Am 2026-09-19 stand wake-gateway auf node1 acht Stunden
    # unhealthy, ohne dass jemand es erfuhr, und die Ursache war ein
    # Healthcheck auf einen abgeschalteten Port. Genau dafuer ist warn richtig.
    "container-unhealthy":               ("warn",     "normal", 21600, ["host", "name"]),
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
    # Laengster Cooldown im Regelwerk (7 Tage): ein 30 Tage alter Befund
    # braucht keine Erinnerung, sondern eine Entscheidung. Taegliches
    # Nachhaken wuerde ihn nur zuverlaessig unsichtbar machen.
    "befund-zur-entscheidung":           ("warn",     "normal", 604800, []),
    # --- Startseite (nachgezogen 2026-09-20) ---
    # Beide Regeln lagen in alerts.rules.yml ohne Gegenstelle hier und meldeten
    # damit nirgendwohin. Cooldown je Kachel bzw. je Wirt, nicht regel-global.
    "launchpad-verweis-tot":             ("warn",     "normal", 86400,  ["titel"]),
    "launchpad-messung-steht":           ("warn",     "normal", 86400,  ["host"]),
    # --- Fremdquellen der Tagesuebersicht (neu 2026-09-21) ---
    # "warn" und nicht "critical" nach Owner-Entscheid: eine tote Datenquelle
    # ist aergerlich, aber nichts, wofuer man nachts aufsteht. Cooldown je
    # Quelle (`name`), sonst verschluckt die erste ausgefallene Quelle die
    # Meldung ueber die zweite. Genau dieser Fall lag am 2026-09-21 vor:
    # paperless und marktwatch waren gleichzeitig tot.
    "lifeops-quelle-antwortet-nicht":    ("warn",     "normal", 86400,  ["name"]),
    # --- Waechter-Herzschlag (neu 2026-09-20) ---
    # Fuenf Zeilen fuer ALLE Waechter. Vorher wuchs diese Tabelle mit jedem
    # neuen Waechter um ein bis drei Zeilen, und genau das Vergessen einer
    # solchen Zeile war der Mangel: `app-kette-pruefer` lag sieben Tage still.
    # Der Cooldown haengt am Label `waechter`, nicht regel-global -- sonst
    # verschluckt der erste stille Waechter die Meldung ueber den zweiten.
    "waechter-steht-still":              ("warn",     "normal", 86400,  ["waechter"]),
    "waechter-herzschlag-fehlt":         ("warn",     "normal", 86400,  ["waechter"]),
    # info und wochenweise: eine offene Eintragung ist kein Ausfall.
    "waechter-ohne-register-eintrag":    ("info",     "low",    604800, ["waechter"]),
    # Ohne key_fields: es gibt genau ein Register.
    "waechter-register-fehlt":           ("warn",     "normal", 86400,  []),
    # Wochenweise, weil die Behebung ein Owner-Handgriff ist (`systemctl --user`
    # ist fuer den Assistenten gesperrt). Taegliches Nachhaken an einer Sache,
    # die man heute nicht selbst erledigen kann, stumpft den Kanal ab.
    "waechter-einheit-nicht-aktiviert":  ("warn",     "normal", 604800, ["waechter"]),
    # --- Selbstheilung (unit-heal-guard, neu 2026-09-20) ---
    # Meldet JEDEN Eingriff, auch den geglueckten: ein stiller Selbstheiler
    # verschiebt den blinden Fleck nur. "warn" statt "info", weil ein
    # geheilter Ausfall trotzdem eine Ursache hat, die beim chmod-Fall
    # regelmaessig im Deploy-Weg liegt und dort behoben gehoert, sonst
    # kommt sie beim naechsten Ausrollen wieder.
    "unit-geheilt":                      ("warn",     "normal", 3600,  ["host"]),
    "config-mount-geheilt":              ("warn",     "normal", 3600,  ["host"]),
    "loki-security-alert":               ("critical", "high",   1800,  ["host", "container", "kind"]),
    "ct-log-alert":                      ("critical", "high",   3600,  ["domain"]),
    "attack-surface-alert":              ("critical", "high",   3600,  ["target"]),
    "ddos-schutz-aktiv":                 ("critical", "high",   1800,  []),
    # War auf prioritaet "default", kein gueltiger Wert, wurde deshalb NIE zugestellt.
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
    # 136 Meldungen in 3,8 Tagen, der Cooldown von 2026-08-19 hat gewirkt, der
    # Kanal blieb aber "critical". Beides zusammen ergibt erst Ruhe.
    "docker-network-unauthorized-connect": ("warn",   "normal", 3600,  ["host", "container"]),
    "crowdsec-security-decision":        ("warn",     "normal", 3600,  ["host"]),
    "network-device-discovered-new":     ("warn",     "normal", 3600,  ["mac"]),
    "systemd-unit-failed":               ("warn",     "normal", 3600,  ["host", "unit"]),
    # Einzige gewollte Abweichung vom Muster "warn -> normal": leiser Kanal, aber hohe
    # Prioritaet und damit auch Discord. Begruendung steht an der Regel selbst, der
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
    # weil ein Spiel nicht erreichbar ist, die richtige Reaktion ist "morgen ansehen".
    # Cooldown je Spiel, sonst verschluckt das erste kaputte Spiel das zweite.
    "spiel-nicht-weckbar":               ("warn",     "normal", 21600, ["spiel"]),
    "game-arbiter-steht":                ("warn",     "normal", 7200,  []),
    # 12 h Cooldown je Spiel: der Zustand ist per Definition ein Dauerzustand,
    # eine haeufigere Erinnerung an dieselbe Sache waere nur Laerm.
    "spiel-dauerhaft-nicht-startbar":    ("warn",     "normal", 43200, ["spiel"]),
    # ★ Der kaputte Server, der gruen aussieht: steht die Unit in 'failed', laeuft ihr
    # Platzhalter weiter -- spiel_weckbar meldet 1, spiel-nicht-weckbar schweigt also.
    # Das ist der Fall, den niemand sieht, bis ein Spieler sich beschwert. Trotzdem warn
    # und nicht critical: es geht nichts verloren, der Arbiter versucht es weiter, und
    # die richtige Reaktion ist "heute noch ansehen", nicht "sofort aufstehen".
    "spiel-dienst-gescheitert":          ("warn",     "normal", 21600, ["spiel"]),
    "spiel-start-laeuft-ins-leere":      ("warn",     "normal", 21600, ["spiel"]),
    # Kapazitaets-Befund, kein Ausfall: der hinterlegte Bedarf altert still, und ein zu
    # kleiner Wert laesst den Arbiter Starts zusagen, bei denen am Ende der OOM-Killer
    # entscheidet. 24 h Cooldown, weil die Antwort eine einmalige Korrektur ist.
    "spiel-speicher-ueber-bedarf":       ("warn",     "normal", 86400, ["spiel"]),
    # Blindheit des Spiel-Waechters: aergerlich, aber ohne Sicherheits- oder
    # Datenverlust-Folge -- anders als bei ddos-schutz-blind, das deshalb critical ist.
    "spiel-metriken-fehlen":             ("warn",     "normal", 21600, []),
    # Blindheit des Versions-Waechters. Warn statt info, weil sie sonst genau das
    # Schicksal teilt, das sie meldet: unbemerkt bleiben. Ein veralteter Server
    # weist Spieler ab, steht aber weiter "online" in der Liste.
    "game-version-unmessbar":            ("warn",     "normal", 86400, ["spiel"]),
    # ★ Der Befund selbst gehoert in denselben Kanal wie die Blindheit darueber, und
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
    # Ein wartender Neustart ist nach jedem Kernel-Update normal, erst das
    # Liegenbleiben ist der Befund: der Patch ist eingespielt und wirkt nicht.
    # Warn statt critical, die richtige Reaktion ist ein Wartungsfenster, kein
    # Aufstehen. Cooldown je Host und bewusst lang (7 Tage): der Zustand aendert
    # sich nur durch den Neustart selbst, haeufigeres Erinnern entwertet den Kanal.
    "neustart-offen":                    ("warn",     "normal", 604800, ["host"]),
    # Nachgezogen 2026-09-17. Beide Regeln feuerten in Prometheus und blieben
    # stumm, weil ein namentlicher Eintrag fehlte und homelab/alerts/+/fired die
    # Storm-Erkennung ist (min_events 5), kein Auffangnetz.
    # Cooldown je Konsument und nicht je Host: mehrere Konsumenten haengen am
    # selben Gateway, ein Schluessel je Wirt liesse den zweiten Befund
    # verschwinden. 6 h, weil die Prometheus-Regel schon 2 h `for` traegt.
    "llm-konsument-kommt-nicht-durch":   ("warn",     "normal", 21600, ["konsument"]),
    # ★★ Die Ueberwachung der Ueberwachung war selbst stumm: diese Regel ist der
    # einzige Alarm, der einen Ausfall von host noch melden koennte, und sie
    # hatte bis zum 2026-09-17 keinen Meldeweg.
    "beobachter2-meldeweg-tot":          ("critical", "high",   21600, ["host"]),
    # Grafana hat eine SMART-Regel, sie fragt aber smartmon_device_smart_healthy
    # ab und sieht damit nur die drei x86-Nodes. Die NVMe von node1 und node2
    # haengt an node_smart_healthy und war ohne diesen Eintrag ungedeckt.
    "datentraeger-smart-defekt":         ("critical", "high",   21600, ["host", "disk"]),
    "datentraeger-reserve-erschoepft":   ("critical", "high",   21600, ["host", "disk"]),
    # Bewusst warn trotz severity critical: bei 95 Prozent verbrauchter
    # Schreibmenge laeuft die Platte weiter, die richtige Reaktion ist "Ersatz
    # bestellen". 24 h Cooldown, der Wert bewegt sich nur langsam.
    "datentraeger-verschleiss-kritisch": ("warn",     "normal", 86400, ["host", "disk"]),
    # Die drei Vorstufen, ergaenzt 2026-09-19. Zu jeder gab es bereits eine
    # Endstufe oben, gedeckt war also der Moment, in dem es zu spaet ist, und
    # offen der, in dem man noch handeln kann. Alle drei auf warn: ihr Zweck ist
    # Vorlauf. Auf critical gelegt macht eine Bestellentscheidung einen
    # Nachtalarm, und danach wird der Kanal stummgeschaltet.
    "datentraeger-defektsektoren":       ("warn",     "normal", 86400, ["host", "disk"]),
    # Eine Woche Cooldown: der Wert steht bei 80 Prozent und bewegt sich ueber
    # Monate. Taeglich erinnern hiesse, eine Beschaffung zu Rauschen zu machen.
    "datentraeger-verschleiss-hoch":     ("warn",     "normal", 604800, ["host", "disk"]),
    "datentraeger-zu-warm":              ("warn",     "normal", 86400, ["host", "disk"]),
    # Nicht zu verwechseln mit restore-drill-failed: das faengt den eigenen
    # MQTT-Weg der service-restore-drill. Diese haengt an der Prometheus-Metrik
    # der restic-Rueckspielprobe auf proxmox und pbs.
    "rueckspielprobe-fehlgeschlagen":    ("critical", "high",   21600, ["host"]),
    # 6 h und damit kurz fuer einen Wochentermin: das Nachholfenster betraegt
    # 24 h, und innerhalb dieses Fensters soll mehr als einmal erinnert werden.
    "wochenbericht-montag-ohne-versand": ("warn",     "normal", 21600, ["host"]),
    # Stand schon in rules.yaml, fehlte aber hier und bekam seinen Kanal damit
    # nie zugewiesen (der Pruefer meldete sie als "OHNE ZUORDNUNG").
    # Der Eintrag bestaetigt den vorgefundenen Ist-Zustand, er aendert ihn nicht.
    "vektorsuche-degradiert":            ("warn",     "normal", 21600, ["host", "container"]),
    # 12 h Cooldown je Geraet, gleiche Begruendung wie bei den Spielen: ein Geraet, das
    # weg ist, bleibt weg, bis jemand hingeht. Haeufiger erinnern hiesse nur Laerm --
    # und Laerm ist genau das, was diesen Waechter am Ende wieder stummschalten wuerde.
    "tapo-steckdose-weg":                ("warn",     "normal", 43200, ["geraet"]),
    # Nachgezogen 2026-09-19: die Gruppe homelab-beobachtungsguete, also die
    # Ebene, die das Stummwerden anderer finden soll, war selbst vollstaendig
    # stumm. Alle neun Regeln feuerten in Prometheus ohne jeden Meldeweg.
    # Ausloeser war handfest: SystemdUnitLaengerAusgefallen trug an dem Tag
    # fuenf Befunde, darunter restic-backup.service auf zwei Wirten, waehrend
    # die letzte gelungene Off-Site-Sicherung 52 h zurueck lag.
    #
    # Cooldown je Wirt UND Unit: neun Befunde auf sieben Wirten standen
    # gleichzeitig offen, ein gemeinsamer Schluessel haette acht davon
    # verschluckt. 24 h, weil sich der Zustand nur aendert, wenn jemand hingeht.
    "systemd-unit-laenger-ausgefallen":  ("warn",     "normal", 86400, ["beobachtet", "unit"]),
    # ★ Die beiden Waechter-Regeln bewusst OHNE Schluessel, gegen das Hausmuster:
    # der Waechter arbeitet seine Ziele in EINER Schleife ab. Faellt er aus,
    # faellt er fuer alle -- am 2026-09-19 stand die Regel dadurch gleichzeitig
    # fuer alle 15 beobachteten Wirte an. Ein Schluessel je Wirt haette daraus
    # 15 Pushes fuer einen einzigen haengenden Prozess gemacht.
    "systemd-waechter-stumm":            ("warn",     "normal", 21600, []),
    "systemd-waechter-host-fehlt":       ("warn",     "normal", 21600, []),
    "alarmregel-metrik-unbekannt":       ("warn",     "normal", 86400, ["regel"]),
    # Ohne Schluessel, weil der Ausdruck im Feuerfall keine unterscheidenden
    # Labels traegt.
    "alarm-lebendtest-fehler":           ("warn",     "normal", 21600, []),

    # ★★★ Waechter-der-Waechter (2026-09-19). Alle auf warn, keiner auf critical:
    # eine stehengebliebene Messung ist kein Grund aufzustehen, sondern einer,
    # am naechsten Tag hinzusehen. Umgekehrt darf die Blindheit nicht LAUTER
    # sein als der Befund, den sie verdeckt.
    # Die Cooldowns sind lang (6 h bis 24 h), weil diese Zustaende stehen: ein
    # Waechter, der ausgefallen ist, bleibt bis zum Eingriff ausgefallen. Ein
    # kurzer Cooldown erzeugte hier taeglich dieselbe Zeile, und ein Befund, den
    # man jeden Morgen wegwischt, ist so gut wie keiner.
    # Beide ohne Schluessel: ein Pruefer, eine Instanz, die Ausdruecke tragen
    # im Feuerfall keine unterscheidenden Labels.
    "config-mount-pruefer-fehler":       ("warn",     "normal", 43200, []),
    "llm-konsumenten-wache-fehler":      ("warn",     "normal", 43200, []),
    "llm-konsumenten-wache-metrik-fehlt": ("warn",    "normal", 43200, []),
    # Rueckspielprobe je Wirt: hier ist ein Schluessel richtig, weil jeder Wirt
    # sein eigenes Repo hat und ein Ausfall auf proxmox nichts ueber node1 sagt.
    "rueckspielprobe-steht-still":       ("warn",     "normal", 86400, ["host"]),
    "rueckspielprobe-metrik-fehlt":      ("warn",     "normal", 86400, ["host"]),
    "rueckspielprobe-meldeweg-tot":      ("warn",     "normal", 43200, []),
    "service-rueckspielprobe-steht-still": ("warn",   "normal", 86400, ["host"]),
    "service-rueckspielprobe-metrik-fehlt": ("warn",  "normal", 86400, ["host"]),
    "wochenbericht-wache-steht-still":   ("warn",     "normal", 43200, ["host"]),
    "wochenbericht-zustand-unlesbar":    ("warn",     "normal", 43200, ["host"]),
    "wochenbericht-metrik-fehlt":        ("warn",     "normal", 86400, ["host"]),
    # Schluessel je Spiel: zwei gleichzeitig vergessene Wartungen sind zwei
    # getrennte Sachverhalte, und die zweite darf nicht von der ersten
    # verschluckt werden.
    "spiel-wartung-vergessen":           ("warn",     "normal", 43200, ["spiel"]),

    # --- stumm: Entwarnungen, Routine, Nachschlagen ---
    # ★ BEWUSST OHNE Cooldown. Diese Regel traegt die Ende-zu-Ende-Probe des
    # Meldewegs (homelab-work/meldeweg-probe). Ein Cooldown daempft dann nicht
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
    "game-server-uptodate":              ("info",     "low",    86400, ["spiel"]),
    # Eine Lampe rechtfertigt keine Unterbrechung. Stumm, aber nachschlagbar --
    # der Unterschied zur Steckdose ist, dass "aus" hier ein gueltiger Zustand ist.
    "tapo-leuchtmittel-weg":             ("info",     "low",    86400, ["geraet"]),
    # Die drei stummen der Beobachtungsguete-Gruppe (2026-09-19). Merklisten,
    # keine Stoerungen: ein nie aktivierter Timer und eine Regel ohne Subjekt
    # sind meist die richtige Folge einer bewussten Entscheidung. Unsichtbar
    # bleiben sollen sie trotzdem nicht -- genau so stand
    # TapoLeuchtmittelLaengerWeg am 2026-09-12 ohne ein einziges Geraet da.
    # 7 Tage Cooldown, weil sich der Zustand nur durch eine Entscheidung aendert.
    "systemd-timer-verwaist-stehend":    ("info",     "low",    604800, ["beobachtet", "unit"]),
    "alarmregel-ohne-subjekt":           ("info",     "low",    604800, ["regel"]),
    "alarmregel-ausnahme-ueberholt":     ("info",     "low",    604800, ["regel"]),

    # ── Geteilte Quellen von Herb und Gartiko (2026-09-20) ───────────────
    # Seit der Repo-Trennung sieht kein Werkzeug in einem der beiden Baeume
    # den anderen. Drift zwischen Doktor-Katalog, Sorten-Katalog und der
    # Klima-Rechnung erzeugt keinen Fehler, sondern zwei Antworten, die nicht
    # mehr zusammenpassen: im Discord ein anderer VPD als auf gartiko.de.
    #
    # Alle drei auf 'warn', keine auf 'critical': nichts davon faellt aus,
    # und nichts davon ist nachts reparierbar. Umgekehrt gehoert es auch
    # nicht auf 'info', denn der Zustand wird mit jedem Tag teurer, an dem
    # auf der veralteten Kopie weitergearbeitet wird.
    #
    # Cooldown 24 h, weil der Pruefer zweimal taeglich laeuft und der Zustand
    # steht, bis jemand nachzieht. Schluessel je Wirt: der Pruefer laeuft nur
    # auf host, ein feinerer Schluessel haette hier nichts zu trennen.
    "geteilte-quelle-driftet":           ("warn",     "normal", 86400, ["host"]),
    # ★ Bewusst dieselbe Lautstaerke wie der Befund selbst, nicht leiser:
    # "ich kann nicht messen" verdeckt genau den Fall, den die Regel darueber
    # finden soll, und eine leisere Einstufung machte die Blindheit zur
    # bequemeren von beiden.
    "geteilte-quelle-nicht-messbar":     ("warn",     "normal", 86400, ["host"]),
    # ★ Die dritte Regel dieser Familie, `geteilte-quellen-pruefer-stumm`, steht
    # seit 2026-09-20 nicht mehr hier: der Stillstand JEDES Waechters laeuft
    # jetzt ueber `waechter-steht-still` weiter oben.
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
            raise SystemExit(f"Regel ohne Zuordnung: {rid}, Tabelle ergaenzen, nicht raten.")
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

        # ★ Fehlt der Block ganz, wird er angelegt statt uebergangen. Bis
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
    # ★ `r["ntfy"]` statt `r.get("ntfy")` liess den Pruefer mit KeyError
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
    sys.exit(1 if pruefen(RULES) else 0)
