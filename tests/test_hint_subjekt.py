"""Der Hint muss das AUSLOESENDE Subjekt nennen, nicht das zuletzt eingetroffene.

Hintergrund (2026-09-05): `_render_hint` las das Ereignis aus `rule.events[-1]`.
Solange nur ein Subjekt meldet, ist das dasselbe. Es faellt auseinander, sobald
mehrere Subjekte gleichzeitig melden: zwischen Ausloesen und Zustellen liegt der
LLM-Aufruf (gemessen 22 bis 33 s), und in dieser Zeit haengen die uebrigen Subjekte
ihre Ereignisse an. Gerendert wurde dann das letzte davon.

Belegt an den Tapo-Geraeten: drei Leuchtmittel meldeten je einzeln (der Cooldown je
Subjekt trennte korrekt), aber alle drei Meldungen nannten 'Strip L930'. Zwei
Steckdosen-Meldungen nannten beide 'Hub H100'. Die Meldung war also da und nannte
das falsche Geraet -- die unangenehmere Haelfte von "Meldung nennt nicht, WO",
weil sie nicht nach einer Luecke aussieht, sondern nach einer Antwort.

Betrifft jede Regel mit `cooldown_key_fields` und Platzhaltern im Hint.
"""
import time

from app import pipeline
from app.rules import Event, Rule

GERAETE = ("Fensterlampe L530", "Tapo L530 Wohnzimmer", "Strip L930")


def _regel() -> Rule:
    return Rule(
        id="tapo-test",
        topic_pattern="homelab/alerts/X/fired",
        min_events=1,
        window_seconds=300,
        cooldown_seconds=43200,
        cooldown_key_fields=["geraet"],
        triage={"hint": "Geraet '{{ event.payload.labels.geraet }}' ist weg."},
        suggest_topic="x",
        ntfy={"priority": "low", "topic": "host-info"},
    )


def _ereignis(geraet: str) -> Event:
    return Event(
        topic="homelab/alerts/X/fired",
        payload={"labels": {"geraet": geraet, "instance": "1.2.3.4"}},
        received_at=time.time(),
    )


def test_hint_nennt_das_ausloesende_geraet():
    """Drei Subjekte melden kurz hintereinander, zugestellt wird erst danach."""
    regel = _regel()
    ausloeser = []
    for geraet in GERAETE:
        ereignis = _ereignis(geraet)
        regel.events.append(ereignis)
        regel.trigger_event = ereignis  # das setzt rules.py beim Feuern
        ausloeser.append(ereignis)

    for ereignis in ausloeser:
        soll = ereignis.payload["labels"]["geraet"]
        assert soll in pipeline._render_hint(regel, ereignis), (
            f"Meldung nennt nicht {soll!r}"
        )


def test_ohne_ereignis_bleibt_der_alte_rueckfall():
    """Ohne mitgegebenes Ereignis gilt weiter events[-1] -- der Rueckfall soll
    keine Ausnahme werfen, sondern die Regel weiter zustellbar halten."""
    regel = _regel()
    for geraet in GERAETE:
        regel.events.append(_ereignis(geraet))
    assert GERAETE[-1] in pipeline._render_hint(regel)
