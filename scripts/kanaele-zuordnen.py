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
    # Gitea-Anmeldewache (2026-10-06). Gleiche Einstufung wie authelia-brute-force
    # eine Zeile hoeher, und aus demselben Grund: Gitea kennt keine Konto-Sperre
    # nach Fehlversuchen, hier macht nichts von selbst zu. Alle drei ohne
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
    # --- finanzen (2026-09-26): die drei vom Owner gewaehlten Meldungen ---
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
    "launchpad-messung-steht":           ("warn",     "normal", 86400,  ["host"]),
    # --- Fremdquellen der Tagesuebersicht (neu 2026-09-21) ---
    # "warn" und nicht "critical" nach Entscheid: eine tote Datenquelle
    # ist aergerlich, aber nichts, wofuer man nachts aufsteht. Cooldown je
    # Quelle (`name`), sonst verschluckt die erste ausgefallene Quelle die
    # Meldung ueber die zweite. Genau dieser Fall lag am 2026-09-21 vor:
    # paperless und marktwatch waren gleichzeitig tot.
    # Ein Tag Ruhe je Quelle: der Befund bleibt sichtbar, ohne mehrfach taeglich
    # zu klopfen, und die Wiedervorlage (offene-befunde) erinnert danach weiter.
    # Dieser Satz stand bis 2026-09-26 als Kommentar ueber der cooldown-Zeile
    # in rules.yaml und wurde dort beim naechsten Lauf dieses Skripts entfernt:
    # es raeumt die Kommentare direkt ueber einer Cooldown-Zeile mit ab. Hier
    # ueberlebt er.
    "lifeops-quelle-antwortet-nicht":    ("warn",     "normal", 86400,  ["name"]),
    # --- Waechter-Herzschlag (neu 2026-09-20) ---
    # Fuenf Zeilen fuer ALLE Waechter. Vorher wuchs diese Tabelle mit jedem
    # neuen Waechter um ein bis drei Zeilen, und genau das Vergessen einer
    # solchen Zeile war der Mangel: `app-kette-pruefer` lag sieben Tage still.
    # Der Cooldown haengt am Label `waechter`, nicht regel-global -- sonst
    # verschluckt der erste stille Waechter die Meldung ueber den zweiten.
    "waechter-steht-still":              ("warn",     "normal", 86400,  ["waechter"]),
    "waechter-herzschlag-fehlt":         ("warn",     "normal", 86400,  ["waechter"]),
    # Schluessel `waechter` UND `wirt`: ein Waechter kann auf mehreren Wirten
    # fehlen, und mit nur `waechter` verschluckte die erste Meldung alle
    # weiteren. Woechentlich, weil ein fehlender Sammler nicht von selbst
    # zurueckkommt und das Nachziehen ein Owner-Handgriff ist (Ausrollen mit
    # sudo). Taegliches Nachhaken daran stumpft den Kanal ab, siehe die
    # Begruendung bei `waechter-einheit-nicht-aktiviert` unten.
    "waechter-wirt-fehlt":               ("warn",     "normal", 604800, ["waechter", "wirt"]),
    # --- Audit-Quelle leer (neu 2026-10-15) ---
    # warn und nicht critical: die Luecke ist drei Monate alt und ihre Behebung
    # ist ein Vorhaben (promtail-Build oder ein journalctl-Umweg), kein
    # Handgriff. Wochenweise, damit die Erinnerung bleibt, ohne abzustumpfen.
    # Schluessel `quelle`, falls spaeter weitere Audit-Quellen dazukommen.
    "loki-audit-quelle-leer":            ("warn",     "normal", 604800, ["quelle"]),
    # --- Hochgerechnete Restlebensdauer (neu 2026-10-13) ---
    # Schluessel `wirt` und `geraet`: die Prognose rechnet je Platte, und mit nur
    # `wirt` verschluckte die erste Platte eines Wirts die zweite. NICHT `host`
    # nehmen: das ist bei allen Reihen host, weil host das Textfile fuer die
    # ganze Flotte schreibt. Ein Cooldown auf `host` waere einer fuer alles.
    # Wochenweise bei der Warnung (Ersatz beschaffen ist Planung, kein Handgriff),
    # taeglich bei der kritischen.
    "datentraeger-lebensdauer-endet-bald":      ("warn",     "normal", 604800, ["wirt", "geraet"]),
    "datentraeger-lebensdauer-endet-sehr-bald": ("critical", "high",   86400,  ["wirt", "geraet"]),
    # Der Waechter ueber die Schwelle der beiden Regeln darueber (2026-10-15).
    # Die Zahlen 730/365 stehen an drei Orten (haltbarkeit.yaml, Literal in der
    # Alarmregel, Anzeige auf :8102). Diese Meldung kommt, wenn die ersten zwei
    # auseinanderlaufen. Kein Betriebsbefund, sondern ein Pflegefehler, deshalb
    # warn und wochenweise: die Zahl aendert sich praktisch nie, und wenn, ist
    # das Angleichen eine Minute Arbeit. Schluessel `stufe`, weil Warn- und
    # kritische Schwelle unabhaengig voneinander driften koennen.
    "datentraeger-schwelle-abweichend":  ("warn",     "normal", 604800, ["stufe"]),
    # --- Gartikos Klimakette (neu 2026-10-16) ---
    # Anlass: die Erfassung stand sieben Tage, aus zwei Gruenden hintereinander
    # (Schalter aus am 09.10., Sensor per Zigbee weg am 13.10.), und keine
    # Pruefung meldete es. Jede Station war gesund, offen war nur die Kette.
    #
    # Zwei Regeln statt einer, und sie meinen Verschiedenes: `-steht-still`
    # ist das Symptom (die Reihe waechst nicht), `-quelle-liefert-nichts` die
    # Ursache. Letztere feuert auch dann, wenn die Reihe noch jung ist, also
    # BEVOR die Luecke entsteht. Darum eigener Cooldown-Schluessel: wer sie
    # zusammenlegt, verliert genau die Unterscheidung, die sagt, welcher
    # Handgriff faellig ist (Geraet gegen Kopplung).
    #
    # warn und nicht critical: es gehen keine Daten verloren, die Kurve bleibt
    # stehen, und der Handgriff ist beim Owner (Zigbee-Router bzw. Kopplung).
    # Taeglich, nicht stuendlich: beides sind Vorhaben von Minuten bis Tagen,
    # und ein stuendliches Nachhaken stumpft den Kanal ab.
    "gartiko-klima-steht-still":          ("warn",     "normal", 86400,  []),
    "gartiko-klima-quelle-liefert-nichts": ("warn",     "normal", 86400,  []),
    # Die Messung selbst. Haelt sie nicht, ist der Stillstand wieder unsichtbar.
    "gartiko-klima-wache-fehler":         ("warn",     "normal", 43200,  []),
    # --- DNS-Redundanz (2026-10-24) ---
    # Bis zum 24.10. gab es keine DNS-Regel, bei der Schicht, von der jeder
    # andere Dienst abhaengt. Die beiden critical stehen bewusst neben
    # `dns-stack-degraded`: ein namenloses LAN ist ein Grund aufzustehen.
    "dns-primaer-loest-nicht-auf":        ("critical", "high",   1800,  ["art"]),
    "dns-beide-resolver-weg":             ("critical", "high",   900,   []),
    # Der Sekundaer weckt NICHT: solange der Primaer traegt, faellt nichts aus,
    # es fehlt nur der Notausgang. Das ist ein Befund fuer den naechsten
    # Vormittag, kein Aufstehen.
    "sekundaer-dns-kennt-interne-namen-nicht": ("warn", "normal", 43200, []),
    "sekundaer-dns-antwortet-nicht":      ("warn",     "normal", 43200, []),
    "dns-redundanz-wache-steht":          ("warn",     "normal", 43200, []),
    # --- Soll-Ist-Abgleich der Dienste (2026-10-21) ---
    # Nach Dienst-KLASSE getrennt und nicht nach Namensliste. Fuer Home
    # Assistant, Gitea, Mosquitto oder das tardis ist Aufstehen die richtige
    # Reaktion, fuer einen fehlenden INTERNAL-Dienst nicht. Dieselbe Zweiteilung
    # wie bei `service-unhealthy-core` gegen die breite Variante. Eine
    # Namensliste in der Regel waere die Alternative, und die veraltet genau
    # dann, wenn ein neuer CORE-Dienst dazukommt.
    "dienst-soll-laeuft-nicht-kritisch":  ("critical", "high",   1800,  ["host", "dienst"]),
    # 6 h je Dienst: ein Dienst, der weg ist, bleibt weg, bis jemand hingeht.
    # Haeufiger erinnern waere Laerm, und Laerm ist genau das, was diesen
    # Waechter am Ende wieder stummschalten wuerde.
    "dienst-soll-laeuft-nicht":           ("warn",     "normal", 21600, ["host", "dienst"]),
    # Die Blindheit zu den beiden darueber, bewusst NICHT lauter als der
    # Befund, den sie verdeckt.
    # Ohne key_fields: es gibt genau einen Abgleich.
    "dienst-abgleich-unvollstaendig":     ("warn",     "normal", 21600, []),
    # info: ein nicht vollzogener Abschalt-Entschluss ist kein Ausfall.
    "dienst-laeuft-unerwartet":           ("info",     "low",    86400, ["host", "dienst"]),
    "dienst-live-unbekannt":              ("info",     "low",    86400, ["host", "name"]),
    # --- Sicherung je Position (2026-10-21) ---
    # Alle vier auf warn und nicht auf critical, obwohl es um die Sicherung
    # geht. Begruendung: `backup-run-failed` (critical, oben) deckt den Fall "der
    # Lauf scheitert". Diese vier sind die Feinsicht darunter -- eine einzelne
    # Position, die zurueckhaengt, ist ein Befund fuer den naechsten Vormittag.
    # Genau die Verwechslung dieser zwei Ebenen hat vom 17.10. bis 21.10. einen
    # critical getragen, der nichts Kritisches meinte.
    # --- Auslieferung der Welt-Archive (nachgetragen 2026-10-23) ---
    # Die einzige critical-Regel des Bestands OHNE Zustellweg war
    # `AuslieferungZugangsdatenGefunden`: ein Zugangsdatum in einem Archiv, das
    # jedes Clan-Mitglied laden kann, gemeldet an niemanden. Sie trug damit den
    # Daueralarm `AlarmOhneMeldewegCritical`. Hier gehoert sie zu
    # `authelia-brute-force` und `gitea-anmeldung-sturm`: ein offenes Leck ist
    # ein Grund aufzustehen.
    # 30 min: ein offenes Leck darf nicht halbtags unerwaehnt bleiben, aber auch
    # nicht im Minutentakt wiederholt werden, solange es offen ist.
    "auslieferung-zugangsdaten-gefunden": ("critical", "high",   1800,  []),
    "welt-auslieferung-zurueckgehalten":  ("warn",     "normal", 86400, []),
    "auslieferung-regel-greift-nicht":    ("warn",     "normal", 86400, ["spiel", "welt"]),
    # Die zwei Lebendigkeits-Regeln: nicht lauter als der Befund, den sie
    # verdecken.
    "auslieferung-pruefung-steht-still":  ("warn",     "normal", 43200, []),
    "auslieferung-metrik-fehlt":          ("warn",     "normal", 43200, []),
    "backup-position-veraltet":           ("warn",     "normal", 43200, ["position"]),
    # 7 Tage: der Grund ist ein Owner-Handgriff (Tresor-Kennwort), und taeglich
    # an etwas zu erinnern, das man selbst nicht erledigen kann, stumpft ab.
    "backup-position-lange-uebersprungen": ("warn",    "normal", 604800, ["position"]),
    "backup-position-nie-erfolgreich":    ("warn",     "normal", 86400, []),
    "backup-positions-messung-steht":     ("warn",     "normal", 43200, []),
    # Taeglich je Entitaet und nicht alle 6 h: die Behebung ist ein Griff am
    # Geraet oder am Funknetz, und an etwas zu erinnern, das niemand am Rechner
    # erledigen kann, stumpft den Kanal ab. Schluessel ist die Entitaet, weil
    # jede fuer sich einfriert.
    "temperaturwert-eingefroren":        ("warn",     "normal", 86400,  ["entity"]),
    # --- lager (2026-10-24): die letzten vier Regeln ohne jeden Meldeweg ---
    # Zwei Paare mit verschiedener Lautstaerke, und die Trennung ist der Punkt.
    # Die Messkette ist ein STILLER AUSFALL: der Dienst sieht gesund aus, seine
    # Fachzahlen sind weg, und solange das steht, sind die zwei Bestandsregeln
    # nicht still, sondern blind. Das gehoert auf warn, 6 h.
    # Der Bestand ist ein OFFENER BEFUND: alles funktioniert, es bucht nur
    # niemand. Das gehoert auf info und wochenweise. Taeglich an einen Vorrat zu
    # erinnern, der seit 237 Tagen unberuehrt ist, macht genau den Kanal taub,
    # auf dem die Messkette meldet.
    # Ohne key_fields: es gibt genau ein Lager auf genau einem Wirt.
    "lager-messkette-weg":               ("warn",     "normal", 21600,  []),
    "lager-messwerte-nicht-lesbar":      ("warn",     "normal", 21600,  []),
    "lager-seit-lange-ohne-buchung":     ("info",     "low",    604800, []),
    "lager-bestand-ueberwiegend-abgelaufen": ("info",  "low",    604800, []),
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
    # Eine Zeile fuer ALLE blackbox-Proben ausser den CORE-Diensten, aus demselben
    # Grund wie beim Waechter-Herzschlag darueber: eine Tabelle, die je Probe
    # waechst, verliert genau die Zeile, auf die niemand sieht. Genau so standen
    # am 2026-09-27 19 von 68 Proben ohne jeden Meldeweg da.
    # Cooldown je Dienst, sonst verschluckt die erste ausgefallene Probe die
    # Meldung ueber die zweite.
    "probe-fehlgeschlagen":              ("warn",     "normal", 3600,  ["host", "service"]),
    # --- Die acht, die am 2026-09-27 ohne jeden Meldeweg dastanden ---
    # Vier davon waren tags zuvor beim Bau von `finanzen` entstanden, drei bei
    # marktwatch. Das Muster ist immer dasselbe: die Alarmregel wird gebaut, der
    # Zustellweg ist ein zweiter Schritt an einem anderen Ort, und der faellt weg.
    # Alle acht sind `warning`, also leise, und mit Tagescooldown: keiner davon
    # rechtfertigt ein Aufstehen, alle sind "morgen ansehen".
    "finanzen-faellige-buchungen":       ("warn",     "normal", 86400, []),
    "finanzen-kurse-veraltet":           ("warn",     "normal", 86400, []),
    "finanzen-nie-ein-kurs":             ("warn",     "normal", 86400, []),
    "finanzen-nur-lesend":               ("warn",     "normal", 86400, []),
    "terraria-leitung-zusammengebrochen": ("warn",    "normal", 86400, []),
    # Cooldown je Quelle: sonst verschluckt die erste tote Quelle die Meldung
    # ueber die zweite, und genau das ist bei marktwatch der Normalfall.
    "marktwatch-quelle-nie-geliefert":   ("warn",     "normal", 86400, ["source"]),
    "marktwatch-quelle-liefert-nichts":  ("warn",     "normal", 86400, ["source"]),
    "marktwatch-quellen-messung-aus":    ("warn",     "normal", 86400, []),
    # Dasselbe Paar fuer die Nachrichten-Engine, und bewusst mit einer Woche
    # statt eines Tages beim toten Feed: dessen Alarm hat schon 14 Tage Vorlauf.
    # Wer dann meldet, meldet nichts Eiliges, sondern etwas Grundsaetzliches,
    # und dafuer ist eine taegliche Erinnerung das falsche Mittel (gleiche
    # Begruendung wie bei zigbee-geraet-stumm).
    # Cooldown je Feed, sonst verdeckt die erste tote Quelle die zweite, solange
    # der erste Befund nachhallt, und dann sieht ein Haus mit drei toten Quellen
    # aus wie eines mit einer.
    # Dieser Wortlaut stand bis zum 2026-10-06 als Kommentar ueber der
    # Cooldown-Zeile in rules.yaml und ist dort beim Lauf dieses Skripts
    # abgeraeumt worden, wie es die Stelle in `umschreiben()` vorsieht. Der
    # zweite Fall derselben Art nach dem 2026-09-26, deshalb hier gesichert:
    # Begruendungen zu Cooldowns gehoeren in DIESE Tabelle, nicht nach rules.yaml.
    "nachrichten-feed-liefert-nichts":   ("warn",     "normal", 604800, ["feed"]),
    "nachrichten-feed-messung-aus":      ("warn",     "normal", 86400, []),
    # --- Jellyfin gegen den Media-Vault (neu 2026-10-03) ---
    #
    # Vier der fuenf Regeln der Gruppe `jellyfin-vault` landen hier und nicht in
    # critical: der Medienserver ist kein CORE-Dienst, und die richtige Reaktion
    # auf einen stehenden Film ist "nachher ansehen". Der Cooldown laeuft je
    # Instanz, weil es zwei gibt (haupt und privat) und die eine die andere sonst
    # verdeckt.
    #
    # Die Ausnahme ist `jellyfin-portlock-fehlt`, und zwar nicht wegen des
    # Dienstes, sondern wegen der Mediathek dahinter: fehlt der Lock, liegt sie
    # LAN-weit offen. Das ist ein Sicherheitsbefund und weckt.
    "jellyfin-vault-offen-dienst-aus":   ("warn",     "normal", 21600, ["instanz"]),
    "jellyfin-medien-nicht-lesbar":      ("warn",     "normal", 21600, ["instanz"]),
    "jellyfin-portlock-fehlt":           ("critical", "high",   1800,  ["host"]),
    "jellyfin-portlock-ungeprueft":      ("info",     "low",    86400, ["host"]),
    "jellyfin-wache-befund-ohne-regel":  ("info",     "low",    604800, ["host"]),
    # --- Backup-Abdeckung (neu 2026-10-04) ---
    #
    # Die Luecke steht auf `warn`/`high` und nicht auf `critical`, obwohl es um
    # drohenden Datenverlust geht. Der Grund ist der Zeitbezug: ein Pfad ohne
    # Sicherung ist erst schlimm, wenn der Wirt ausfaellt, und bis dahin ist die
    # richtige Reaktion ein Entscheid am Schreibtisch. `high` sorgt dafuer, dass
    # es trotzdem nach Discord durchgeht (dort kommt nur high/critical an) --
    # genau der Weg, auf dem ein Entscheid gefaellt wird.
    "backup-abdeckung-luecke":           ("warn",     "high",   86400, ["host"]),
    "backup-pfadliste-zweigeteilt":      ("info",     "low",    604800, ["host"]),
    # restic-prune-Wache (2026-10-13). Dieselbe Einstufung und dieselbe
    # Begruendung wie `backup-abdeckung-luecke` zwei Zeilen hoeher: es geht um
    # drohenden Datenverlust, aber mit Zeitbezug -- ein Repo ohne prune sichert
    # weiter fehlerfrei, bis die Ablage volllaeuft. `high` statt `normal`, damit
    # es nach Discord durchgeht (dort kommt nur high/critical an), denn die
    # richtige Reaktion ist ein Handgriff oder ein Entscheid am Schreibtisch.
    # Schluessel `wirt`, nicht `host`: host schreibt das Textfile fuer alle
    # Wirte, `host` ist also immer host. Mit dem falschen Schluessel
    # verschluckt der erste gemeldete Wirt alle uebrigen fuer einen Tag.
    "restic-prune-ueberfaellig":         ("warn",     "high",   86400, ["wirt"]),
    "restic-prune-nicht-messbar":        ("warn",     "high",   604800, ["wirt"]),
    "restic-prune-falscher-wirt":        ("warn",     "high",   86400, ["wirt"]),
    # Ohne Schluessel: die Metrik ist eine Gesamtzahl und traegt kein `wirt`.
    "restic-prune-ausnahme-wirkungslos": ("info",     "low",    604800, []),
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
    # Neu 2026-10-17: den Fall, den swap-in-use strukturell nicht sehen kann
    # (Freeze bei 90 % Swap und 23 bis 29 % freiem RAM, Watchdog-Reset).
    # high, weil hier noch etwa eine Stunde Zeit zum Handeln ist.
    "swap-thrashing":                    ("warn",     "high",   7200,  ["host"]),
    "load-saturated":                    ("warn",     "normal", 10800, ["host"]),
    "disk-fill-predicted":               ("warn",     "normal", 21600, ["host", "service"]),
    "memory-leak-suspected":             ("warn",     "normal", 21600, ["host", "container"]),
    "container-oom-predicted":           ("warn",     "normal", 21600, ["host", "container"]),
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
    # Die beiden leisen der Gitea-Anmeldewache (2026-10-06), Gegenstueck zu
    # gitea-anmeldung-sturm im critical-Block. Beide `warning` in Prometheus und
    # hier bewusst `normal`: ein einzelner Fehlversuch ist meist der Besitzer mit
    # einem veralteten Tresor-Eintrag, und die richtige Reaktion ist nachsehen,
    # nicht aufstehen. 6 h Cooldown, nicht 24: bei rund drei Anmeldungen am Tag
    # wuerde ein Tagescooldown eine zweite, echte Serie verschlucken, und genau
    # die waere die interessante.
    "gitea-anmeldung-fehlgeschlagen":    ("warn",     "normal", 21600, []),
    "gitea-anmeldung-unbekanntes-konto": ("warn",     "normal", 21600, []),
    # Kein Angriff, sondern eine Automatik mit Benutzername in der Remote-URL,
    # die Gitea erst im zweiten Versuch annimmt. Leise wie die beiden darueber.
    "gitea-basic-pruefung-flut":         ("warn",     "normal", 21600, []),
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
    # Der kaputte Server, der gruen aussieht: steht die Unit in 'failed', laeuft ihr
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
    # Die Ueberwachung der Ueberwachung war selbst stumm: diese Regel ist der
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
    # --- eMMC (jetsons Boot-Karte), ergaenzt 2026-10-15 -----------------------
    # Die fuenf Regeln waren scharf in Prometheus und hatten keinen Ausgang,
    # zwei davon mit severity critical. Jede bekommt die Einstufung ihres
    # SMART-Geschwisters darueber, damit dasselbe Problem nicht je Bus anders
    # laut ist.
    #
    # Schluessel `geraet` statt `disk`: die eMMC-Metriken kommen aus dem
    # Sammler auf dem Geraet selbst und benennen das Medium so. `host` ist hier
    # ausnahmsweise der ECHTE Wirt (jetson), nicht der Bote, weil jetson in
    # seinen eigenen textfile-Collector schreibt. Gegengemessen 2026-10-15.
    "emmc-lebensdauer-fortgeschritten":  ("warn",     "normal", 604800, ["host", "geraet"]),
    # warn trotz severity critical, und das ist dieselbe Entscheidung wie bei
    # `datentraeger-verschleiss-kritisch` neun Zeilen hoeher: ab Stufe 10 laeuft
    # die Karte weiter, und die richtige Reaktion ist, den vorbereiteten
    # SSD-Boot zu aktivieren. Eine eMMC ist aufgeloetet, es gibt nichts zu
    # tauschen, was ein Nachtalarm beschleunigen wuerde. Taeglich erinnern, weil
    # ab hier ein Entscheid aussteht.
    "emmc-lebensdauer-fast-aufgebraucht": ("warn",    "normal", 86400,  ["host", "geraet"]),
    # Eine Woche: `pre_eol_info` ist ein Drei-Zustands-Register und bleibt auf
    # der 2 stehen, bis es auf die 3 springt. Taeglich dasselbe zu melden macht
    # aus einem Vorlauf Rauschen.
    "emmc-reserve-bloecke-knapp":        ("warn",     "normal", 604800, ["host", "geraet"]),
    # Einstufung wie `datentraeger-reserve-erschoepft` oben, und hier zu Recht
    # critical: 0x03 heisst "Urgent", der Vorrat an Ersatzblöcken ist weg, und
    # der naechste Defekt trifft Daten. Auf jetson zugleich das Boot-Medium.
    "emmc-reserve-bloecke-erschoepft":   ("critical", "high",   21600,  ["host", "geraet"]),
    # `warn` als Kanal, aber `high` als Lautstaerke, wie bei
    # `restic-prune-nicht-messbar`: "ich kann nicht messen" verdeckt genau die
    # vier Befunde darueber, darunter einen critical. Leiser einzustufen machte
    # die Blindheit zur bequemeren von beiden Lagen. Eine Woche Cooldown reicht,
    # weil die Regel selbst erst nach 25 h Blindheit anspringt.
    "emmc-telemetrie-nicht-lesbar":      ("warn",     "high",   604800, ["host", "geraet"]),
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
    # Die Summe (2026-10-15): nicht "ein Geraet fehlt", sondern "der Bestand
    # ist weg". Wochen-Cooldown statt der 43200 darueber, weil der Zustand sich
    # bis zur Entscheidung nicht aendert -- dieselbe Ueberlegung wie bei
    # `zigbee-ausnahme-wirkungslos` weiter unten. Ohne Schluessel, denn der
    # Ausdruck aggregiert ueber den ganzen Job und traegt kein geraet-Label.
    "tapo-geraeteklasse-komplett-weg":   ("warn",     "normal", 604800, []),
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
    # Die beiden Waechter-Regeln bewusst OHNE Schluessel, gegen das Hausmuster:
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

    # Waechter-der-Waechter (2026-09-19). Alle auf warn, keiner auf critical:
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
    # Drift der Systemdateien eines Wirts. Kein Ausfall, aber eine Aenderung, die nur im
    # Kopf dokumentiert ist; einmal am Tag reicht, der Abgleich laeuft taeglich.
    "host-dateien-weichen-ab":           ("warn",     "normal", 86400, ["wirt"]),
    # Selbstheilung der Spielserver: gehaeufte Heilungen = Defekt, haengend trotz Heilung =
    # Spieler stehen draussen. Beides leise, das zweite mit hoeherer Prioritaet.
    "spiel-heilt-sich-staendig":         ("warn",     "normal", 43200, ["spiel"]),
    "spiel-haengt-dauerhaft":            ("warn",     "high",   7200,  ["spiel"]),

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
    # Bewusst dieselbe Lautstaerke wie der Befund selbst, nicht leiser:
    # "ich kann nicht messen" verdeckt genau den Fall, den die Regel darueber
    # finden soll, und eine leisere Einstufung machte die Blindheit zur
    # bequemeren von beiden.
    "geteilte-quelle-nicht-messbar":     ("warn",     "normal", 86400, ["host"]),

    # ── Bibliothek: Dateibestand gegen den Katalog (2026-09-26) ──────────
    # Der Waechter misst seit dem 2026-09-26 taeglich, seine Befunde hatten
    # bis heute keine Alarmregel und damit auch keinen Meldeweg. Der Eintrag
    # im Waechter-Register deckte nur den Herzschlag, nicht das Ergebnis.
    #
    # Die beiden Schadensfaelle auf 'warn' und nicht 'critical': eine fehlende
    # Buchdatei ist Datenverlust, aber nachts nicht reparierbar, und der
    # Bestand ist bis zur Umstellung ohnehin noch aus Calibre ableitbar. Wird
    # die Bibliothek produktiv, gehoert `bibliothek-datei-fehlt` erneut
    # angesehen: dann ist sie die einzige Kopie neben restic.
    #
    # Keine cooldown_key_fields: eine Bibliothek, ein Wirt, die Metrik ist
    # eine Anzahl ohne unterscheidende Labels.
    "bibliothek-datei-fehlt":            ("warn",     "normal", 86400,  []),
    "bibliothek-datei-beschaedigt":      ("warn",     "normal", 86400,  []),
    # Aufraeumarbeit, kein Schaden: stumm und wochenweise. Die Alarmregel
    # wartet schon 25 h und meldet nur, was einen zweiten Tageslauf ueberlebt.
    "bibliothek-datei-verwaist":         ("info",     "low",    604800, []),
    # Die dritte Regel dieser Familie, `geteilte-quellen-pruefer-stumm`, steht
    # seit 2026-09-20 nicht mehr hier: der Stillstand JEDES Waechters laeuft
    # jetzt ueber `waechter-steht-still` weiter oben.
    #
    # Nachgezogen 2026-10-09, die Kennzahlen mit Stand `offen` im
    # Betriebsvertrag. Beide Bestandsregeln auf 'warn' aus demselben Grund wie
    # oben: der Verlust ist zum Meldezeitpunkt schon geschehen, nachts laesst
    # sich daran nichts reparieren. Eilig ist einzig, dass es VOR dem naechsten
    # pg_dump bemerkt wird -- der schreibt sonst den verlorenen Stand ueber den
    # guten. Das ist ein Tag Zeit, kein Aufstehen.
    "bibliothek-bestand-geschrumpft":    ("warn",     "normal", 86400,  []),
    # Im haeufigsten Fall war es ein gewollter Aussortierlauf. Derselbe
    # Cooldown wie oben, damit beide bei einem Vorfall, der beides ausloest,
    # im selben Takt melden statt sich abzuwechseln.
    "bibliothek-regal-eingebrochen":     ("warn",     "normal", 86400,  []),
    # Verloren ist nichts, die verdraengte Fassung steht in der Tabelle.
    # Gemeldet wird, dass niemand hineinsieht: stumm und wochenweise, wie die
    # verwaisten Dateien.
    "bibliothek-abgleichkonflikte-stauen": ("info",   "low",    604800, []),
    # Stand seit dem 2026-10-06 in rules.yaml und fehlte hier -- derselbe
    # Fall wie `vektorsuche-degradiert` weiter oben, und derselbe Grund, warum
    # er auffiel: der Pruefer meldete sie als "OHNE ZUORDNUNG". Die Werte
    # bestaetigen den vorgefundenen Ist-Zustand (info/low/eine Woche), sie
    # aendern ihn nicht. Ohne den Eintrag haette der naechste Schreiblauf des
    # Werkzeugs ueber eine Regel hinweggesehen, die es pflegen soll.
    "bibliothek-index-rueckstand":       ("info",     "low",    604800, []),

    # ── Nachgezogen 2026-10-09: die drei portal-handy-Regeln vom selben Tag ──
    # Sie hatten keinen Meldeweg, weder hier noch in Grafana. Bei einer
    # Regel mit `for: 25h`, die hoechstens einmal taeglich feuern kann, ist das
    # VOLLSTAENDIGE Stille: der Sammelzaehler `alert-storm` greift erst ab fuenf
    # Ereignissen und wird damit nie erreicht.
    #
    # Alle drei auf 'warn': es geht um die Bedienbarkeit auf dem Telefon, nicht
    # um einen Ausfall. Nachts ist daran nichts zu tun.
    #
    # Eine Woche fuer die Geometrie, weil das ein Rueckstand ist und kein
    # Vorfall -- die Zahl kann sich zwischen zwei Tageslaeufen gar nicht
    # aendern. Die Alarmregel traegt in ihrem eigenen Kommentar schon die
    # Sorge, dass eine staendig feuernde Regel abgeschaltet statt gelesen wird.
    "portal-handy-befunde":              ("warn",     "normal", 604800, []),
    # Taeglich: das ist ein Programmfehler, keine Unschoenheit. Die Flaeche
    # kann dabei fertig aussehen und ist es nicht.
    "portal-handy-skriptfehler":         ("warn",     "normal", 86400,  []),
    # Taeglich, und von den dreien die wichtigste: eine Flaeche, die gar nicht
    # laedt, laeuft nirgends ueber und hat keine zu kleinen Knoepfe. Ohne diese
    # Regel waere ein kaputtes Portal die ruhigste Messung von allen.
    "portal-handy-nicht-messbar":        ("warn",     "normal", 86400,  []),

    # ── Nachgezogen 2026-10-02: dreizehn Regeln ohne jeden Meldeweg ──────
    # Gefunden von interne Notiz. Das Muster dahinter
    # ist wichtiger als die Liste: die zuletzt gebauten Waechter sind die
    # stummen. Zigbee-Alarm und Tresor-Standby sind beide vom 2026-09-27, und
    # beide bekamen ihre Prometheus-Regel und diesen Eintrag nicht.
    #
    # 7 Tage je Geraet: ein seit 99 bis 169 Tagen verschwundenes Zigbee-Geraet
    # braucht keine taegliche Erinnerung, sondern eine Entscheidung. Auf der
    # Liste haelt es danach die Wiedervorlage.
    "zigbee-geraet-stumm":               ("warn",     "normal", 604800, ["geraet"]),

    # ── Tresor-Standby: der Notweg zum Passworttresor ────────────────────
    # Nur zwei der acht wecken, und der Grund ist die Umkehrbarkeit, nicht die
    # Wichtigkeit: ein ausgesetzter oder veralteter Spiegel laesst sich morgens
    # nachziehen, verlorene Eintraege und ein fehlgeschlagener Abgleich nicht.
    "tresor-spiegel-nicht-stimmig":      ("critical", "high",   21600,  []),
    "tresor-eintraege-geschrumpft":      ("critical", "high",   21600,  []),
    # Keine cooldown_key_fields in der ganzen Gruppe: es gibt einen Tresor und
    # einen Spiegel, die Metriken tragen kein unterscheidendes Label.
    "tresor-spiegel-veraltet":           ("warn",     "normal", 43200,  []),
    "tresor-spiegel-lange-ausgesetzt":   ("warn",     "normal", 86400,  []),
    "tresor-spiegel-misst-nicht":        ("warn",     "normal", 43200,  []),

    # ── Automations-Wirkungspruefung (interne Notiz) ──────
    # Die Klasse: Home Assistant wirft bei `switch.turn_on` auf eine
    # `unavailable`-Entitaet KEINEN Fehler. Eine Automation, deren Lampe fehlt,
    # laeuft durch und gilt dort als erfolgreich gelaufen. Gemessen beim Bau am
    # 2026-10-02: 13 von 34 Automationen in diesem Zustand, die aelteste seit
    # 111 Tagen, darunter die komplette Beleuchtungssteuerung der Wohnung und
    # vier Heizungs-Automationen.
    #
    # Nur die drei echten Befunde auf `warn`, die drei Buchhaltungs-Meldungen
    # auf `info`. Der Grund ist derselbe wie beim Zigbee-Block: wer eine
    # Entscheidungsvorlage weckt, stumpft den Kanal fuer die Ausfaelle ab.
    #
    # 7 Tage je Automation UND Entitaet: ein Geraet, das seit Wochen fehlt,
    # braucht keine taegliche Erinnerung. Auf der Liste haelt es danach die
    # Wiedervorlage.
    "automation-schaltet-ins-leere":     ("warn",     "normal", 604800, ["automation", "entitaet"]),
    "automation-waechter-misst-nicht":   ("warn",     "normal", 21600,  []),
    "automation-datei-unlesbar":         ("warn",     "normal", 21600,  []),
    # Die drei leisen. `ausnahme-ueberholt` ist oft eine gute Nachricht (ein
    # Geraet ist zurueck), `nie-ausgeloest` und `lange-entschuldigt` sind
    # Entscheidungsvorlagen ohne Dringlichkeit. 30 Tage beim mittleren, weil
    # die Frist dort ohnehin 180 Tage ist.
    "automation-ausnahme-ueberholt":     ("info",     "low",    86400,  []),
    "automation-ziel-lange-entschuldigt":("info",     "low",    2592000, ["entitaet"]),
    "automation-nie-ausgeloest":         ("info",     "low",    604800, []),
    "tresor-waechter-stumm":             ("warn",     "normal", 43200,  []),
    # Das Gegenstueck, das dem Waechter fehlte. `tresor-waechter-stumm`
    # rechnet `time() - <metrik>` und braucht dafuer einen aktuellen Messpunkt;
    # stirbt der Waechter, verschwindet die Metrik und die Regel hoert auf zu
    # rechnen, statt zu feuern. Gemessen am 2026-10-02: letzter Lauf 2026-09-27,
    # fuenf Tage unbemerkt. Der Spiegel hatte sein `absent()` schon.
    "tresor-waechter-misst-nicht":       ("warn",     "normal", 43200,  []),
    "tresor-uebernahme-offen":           ("warn",     "normal", 43200,  []),
    # Die Vault-Push-Kette (2026-10-15). Der Dienst lief zwei Wochen und tat
    # strukturell nichts (geratener Remote-Name `origin` gegen die Hausregel
    # `gitea`), meldete dabei `done` und endete mit rc=0. Gemessen: registry 45
    # und homelab-vault 18 Commits Rueckstand. Schluessel `vault` beim
    # Rueckstand, denn es haengen typisch mehrere Repos gleichzeitig und ein
    # gemeinsamer Cooldown verschluckte alle bis auf das erste.
    "vault-push-rueckstand":             ("warn",     "normal", 43200,  ["vault"]),
    "vault-push-fehler":                 ("warn",     "normal", 43200,  []),
    # Neustartschleife (2026-10-15). `warn` und nicht `critical`: der Wirt
    # traegt es, und ein Dienst in der Schleife ist ein Zustand fuer den
    # naechsten Blick, kein Weckgrund. Schluessel `name`, weil bei einem
    # Port-Streit typisch zwei Container betroffen sind und ein gemeinsamer
    # Cooldown den zweiten verschluckte.
    "container-neustartschleife":        ("warn",     "normal", 21600,  ["name"]),
    # Die dritte Luecke derselben Familie (2026-10-15): nicht "Waechter
    # stumm" und nicht "misst nicht", sondern er laeuft, misst richtig und
    # KANN SEIN ERGEBNIS NICHT MELDEN -- `waechter.env` fehlte auf node1 seit
    # dem 27.09., und `melden()` wird erst nach `uebernehmen.sh` gerufen.
    # Tages-Cooldown statt der 43200 der Nachbarn: die Abhilfe ist ein
    # Owner-Handgriff von einer Minute, und bis er passiert, aendert eine
    # zweite Meldung am selben Tag nichts als die Abstumpfung des Kanals.
    "tresor-waechter-ohne-meldeweg":     ("warn",     "normal", 86400,  []),

    # ── gamehost und der Tresor-Zertifikatspfad ───────────────────────────
    # Diese vier galten im Abgleich als von Grafana gedeckt, weil er ueber
    # Metriknamen vergleicht. Grafana hat Regeln auf `probe_success` und
    # `probe_ssl_earliest_cert_expiry`, aber nur fuer `blackbox-netcup-http`,
    # `blackbox-icmp`, `blackbox-service-http|blackbox-node1-local` und
    # `blackbox-core-tcp`. Gleiche Metrik, anderer Job, keine Deckung.
    "gamehost-site-down":                 ("warn",     "normal", 3600,   ["instance"]),
    "gamehost-cert-laeuft-ab":            ("warn",     "normal", 86400,  ["instance"]),
    "vaultwarden-cert-laeuft-ab":        ("warn",     "normal", 86400,  []),
    "vaultwarden-cert-probe-fehlt":      ("warn",     "normal", 43200,  []),
    # Der einzige auf dem stummen Kanal: severity info, und der Inhalt ist eine
    # Entwarnung mit einer Aufgabe dahinter, kein Vorfall.
    "tapo-geraet-zurueck":               ("info",     "low",    43200,  ["geraet"]),

    # ── Der Pruefer der Meldewege meldet jetzt selbst (2026-10-02) ────────
    # Die critical-Variante weckt, und zwar als einzige dieser Runde: sie
    # sagt, dass der lauteste Alarm des Hauses ins Leere geht. Die breite
    # Variante auf 'warn' mit 24 h Ruhe, weil der Abgleich alle 6 h laeuft und
    # derselbe Befund sonst viermal taeglich klopft, bis jemand eine Regel
    # anlegt. Keine key_fields: beide Metriken sind Anzahlen ueber den ganzen
    # Bestand und tragen kein unterscheidendes Label.
    "alarm-ohne-meldeweg-critical":      ("critical", "high",   21600,  []),
    "alarm-ohne-meldeweg":               ("warn",     "normal", 86400,  []),
    # Bewusst dieselbe Lautstaerke wie der Befund selbst, nicht leiser,
    # dieselbe Begruendung wie bei geteilte-quelle-nicht-messbar: "ich kann
    # nicht messen" verdeckt genau den Fall, den die Regel darueber finden
    # soll, und eine leisere Einstufung machte die Blindheit zur bequemeren
    # von beiden Antworten.
    "alarm-meldeweg-abgleich-misst-nicht": ("warn",   "normal", 86400,  []),

    # --- sieben Zustellwege nachgezogen, 2026-10-11 ---
    # Keine davon weckt: bei allen sieben ist die richtige Reaktion ein Entscheid
    # oder ein Handgriff am naechsten Tag. Die Begruendung je Regel steht im
    # Kommentarblock vor ihr in rules.yaml; hier stehen nur die Werte, mit denen
    # `--pruefen` sie gegenliest.
    # Vier der sieben waren am 11.10. noch nicht ausgerollt und deshalb selbst
    # fuer den Meldeweg-Pruefer unsichtbar, weil der Prometheus liest und nicht
    # die Datei. Dafuer gibt es seit demselben Tag `abgleich.py --aus-datei`.
    "backup-pfadliste-nicht-verglichen": ("warn",   "high",   86400,  ["host"]),
    "kiwix-sprachsuche-tot":             ("warn",   "high",   86400,  []),
    "kiwix-sprachsuche-messkette-aus":   ("info",   "low",    86400,  []),
    # Cooldown je Spiel: zwei Spiele mit lueckenhafter Sicherung sind zwei
    # Befunde, und ein regel-globaler Deckel verschluckte den zweiten.
    "welt-sicherung-lueckenhaft":        ("warn",   "high",   86400,  ["spiel"]),
    "welt-deckungspruefung-steht-still": ("warn",   "high",   86400,  []),
    # Terraria-Mod-Satz (2026-10-15). Die ersten zwei wecken, weil der Verlust
    # laeuft, waehrend der Alarm steht: eine Welt ohne ihren Mod verliert dessen
    # Bloecke und Items beim naechsten Autosave, und der kommt alle 10 min.
    # Nachts weckt es praktisch nie, ein Server ohne Spieler geht nach 20 min aus.
    # Cooldown je Spiel, sonst verschluckt die erste betroffene Instanz die zweite.
    "terraria-mod-still-deaktiviert":    ("critical", "high", 1800,   ["spiel"]),
    "terraria-mod-nicht-geladen":        ("critical", "high", 1800,   ["spiel"]),
    # Kein Schaden, aber der naechste Start bricht ab. Halbtages-Cooldown: die
    # Reaktion ist ein Mod nachladen, kein Aufstehen.
    "terraria-modsatz-unvollstaendig":   ("warn",   "high",   43200,  ["spiel"]),
    "terraria-modsatz-pruefung-steht-still": ("warn", "high", 86400,  []),
    "zigbee-bekannt-stumm-aber-da":      ("info",   "low",    86400,  ["geraet"]),
    # Wochen-Cooldown: ein Tippfehler in einer Ausnahmeliste bleibt bestehen,
    # bis jemand ihn korrigiert, und taeglich daran erinnert zu werden stumpft
    # den Kanal ab, ohne den Befund zu aendern.
    "zigbee-ausnahme-wirkungslos":       ("info",   "low",    604800, []),
    # Netzzustand statt Einzelgeraet (2026-10-15, Regeln aus einer parallelen
    # Sitzung, Meldeweg hier nachgezogen). `high` wie bei den uebrigen
    # Zigbee-Wegen, damit es auf Discord ankommt: an diesen Geraeten haengt die
    # Heizungssteuerung. Beide ohne Schluessel, denn beide Ausdruecke
    # aggregieren ueber das ganze Netz und tragen kein Geraete-Label.
    "zigbee-mehrere-geraete-stumm":      ("warn",   "high",   86400, []),
    "zigbee-ohne-router":                ("warn",   "high",   86400, []),
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
    # Schluessel `pfad` und nicht `host`: bei einer Rechteaenderung trifft es
    # mehrere Pfade gleichzeitig, und mit host-Schluessel verschluckte der
    # erste gemeldete jeden weiteren.
    "zweitziel-pfad-nicht-lesbar":       ("warn",   "high",   43200, ["pfad"]),
    "finanzen-kuendigungsfrist":          ("warn",     "normal", 86400, []),
    "finanzen-kuendigung-unbekannt":      ("info",     "low",    604800, []),
    # --- Meldewege nachgezogen 2026-10-24: Schwere der Alarmregel, nie lauter ---
    "farmwelt-reset-gescheitert": ("warn", "normal", 21600, []),
    "minecraft-direktweg-bricht-ab": ("warn", "normal", 21600, []),
    "minecraft-direktweg-ungenutzt": ("info", "low", 86400, []),
    "minecraft-job-bonus-gescheitert": ("warn", "normal", 21600, []),
    "minecraft-job-parkplatz-gescheitert": ("warn", "normal", 21600, []),
    "minecraft-job-stand-wartet-zu-lange": ("info", "low", 86400, []),
    "minecraft-raenge-pflege-gescheitert": ("warn", "normal", 21600, []),
    "minecraft-selbstpruefung-steht-still": ("warn", "normal", 21600, []),
    "minecraft-verweise-ins-leere": ("warn", "normal", 21600, []),
    "spiel-ohne-sicherung": ("warn", "normal", 21600, ["spiel", "welt"]),
    "spiel-sicherung-dauerhaft-abgelehnt": ("warn", "normal", 21600, ["spiel", "welt"]),
    "spiel-sicherung-veraltet": ("warn", "normal", 21600, ["spiel", "welt"]),
    "spiele-sicherung-metrik-fehlt": ("warn", "normal", 21600, []),
    "spiele-sicherung-steht-still": ("warn", "normal", 21600, []),
    "sync-arbeit-liegt-unveroeffentlicht": ("warn", "normal", 21600, ["repo"]),
    "sync-klon-haengt-zurueck": ("warn", "normal", 21600, ["repo"]),
    "sync-messung-gescheitert": ("warn", "normal", 21600, []),
    "karten-datei-fehlt": ("warn", "normal", 21600, []),
    "karten-datenstand-alt": ("warn", "normal", 21600, []),
    "karten-gattung-zeigt-ins-leere": ("warn", "normal", 21600, []),
    "karten-rohdaten-lauf-gescheitert": ("warn", "normal", 21600, []),
    "karten-rohdaten-nicht-erneuert": ("warn", "normal", 21600, []),
    "karten-rohdaten-verbraucher-abweichend": ("warn", "normal", 21600, []),
    "karten-satz-nicht-ausgeliefert": ("warn", "normal", 21600, []),
    "karten-wache-kann-nicht-messen": ("warn", "normal", 21600, []),
    "karten-spur-keine-neuen-fahrten": ("warn", "normal", 21600, []),
    "karten-spur-matching-quote-niedrig": ("warn", "normal", 21600, []),
    "karten-spur-matching-staut": ("warn", "normal", 21600, []),
    "karten-spur-matching-fehler": ("info", "low", 21600, []),
    "karten-spur-sicherung-fehlt": ("warn", "normal", 21600, []),
    "karten-spur-sicherung-hinkt": ("warn", "normal", 21600, []),
    "karten-spur-geraeteverwaltung-offen": ("info", "low", 21600, []),
    # Zweite Schicht hinter Authelia (Audit KARTEN-002), in Prometheus
    # `warning` mit `for: 24h`. Leise, anders als die drei Schranken darunter:
    # der Vhost bleibt dicht, offen ist nur der Weg an ihm vorbei aus dem Haus.
    "karten-spur-proxy-schranke-offen": ("warn", "normal", 21600, []),
    # Die drei Wege zur Bewegungshistorie wecken, ihre sechs Geschwister
    # darueber nicht. Der Unterschied ist die richtige Reaktion: ein gestautes
    # Matching sieht man sich morgen an und es wird nicht schlimmer, eine
    # offene Schranke laeuft mit jeder Stunde weiter. Cooldown deshalb 1 h
    # statt 6. Alle drei ohne Schluessel, es gibt genau einen Dienst.
    "karten-spur-schranke-offen": ("critical", "high", 3600, []),
    "karten-spur-direktport-offen": ("critical", "high", 3600, []),
    "karten-spur-sync-weg-offen": ("critical", "high", 3600, []),
    "medien-abgleich-veraltet": ("warn", "normal", 21600, []),
    "medien-vault-bericht-veraltet": ("warn", "normal", 21600, ["wirt"]),
    "medien-vault-kein-wirt": ("warn", "normal", 21600, []),
    "portal-sagt-etwas-falsches": ("warn", "normal", 21600, []),
    "portal-selbstpruefung-leer": ("warn", "normal", 21600, []),
    # Patchstand der selbst gebauten Images (Gruppe homelab-haertung, neu am
    # 2026-10-26). Alle fuenf auf `warn`, auch die mit severity critical, und das
    # ist dieselbe Entscheidung wie beim Speicherplatz weiter oben: die richtige
    # Reaktion auf einen zwei Monate alten Patchstand ist "morgen nachziehen",
    # nicht Aufstehen um 3 Uhr. Der Zustand besteht dann schon seit sechzig Tagen
    # und wird in einer Nacht nicht schlimmer.
    # `haertung-lange-veraltet` bekommt trotzdem `high`: es soll in der Liste
    # vor den anderen stehen, ohne zu wecken.
    # Cooldown 24 h und nicht 6 h: die Messung laeuft im Wochentakt, ein
    # Alarm je Tag und Dienst ist hier schon die obere Grenze des Sinnvollen.
    "haertung-veraltet": ("warn", "normal", 86400, ["wirt", "dienst"]),
    "haertung-lange-veraltet": ("warn", "high", 86400, ["wirt", "dienst"]),
    "haertung-wirt-nicht-erreicht": ("warn", "normal", 86400, ["wirt"]),
    "haertung-messung-leer": ("warn", "normal", 86400, []),
    "haertung-frist-abweichend": ("warn", "normal", 86400, []),
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
