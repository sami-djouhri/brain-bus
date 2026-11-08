"""container-oom-predicted: Abkuehlzeit je Container und Meldung mit Namen.

Hintergrund (2026-11-03): cAdvisor nennt den Container im Label `name`. Die
Regel suchte `container`, fand nichts, und alle Container eines Wirts teilten
sich einen Abkuehl-Schluessel. ai-llm und ai-llm-slow auf node2 feuerten am
selben Tag, gemeldet wurde einer, ohne Namen; die KI-Einschaetzung riet daraus
"brain-bus". Geprueft wird gegen die echte rules.yaml mit den gemessenen Labels.
"""
import time
from pathlib import Path

from app import pipeline
from app.rules import Event, load_rules

RULES = Path(__file__).resolve().parent.parent / "config" / "rules.yaml"


def _regel():
    return next(r for r in load_rules(RULES) if r.id == "container-oom-predicted")


def _ereignis(name: str) -> Event:
    return Event(
        topic="homelab/alerts/ContainerMemoryGrowing/fired",
        payload={"labels": {
            "alertname": "ContainerMemoryGrowing", "host": "node2", "name": name,
            "instance": "192.0.2.10:9080", "job": "cadvisor-node2",
        }},
        received_at=time.time(),
    )


def test_zwei_container_eines_wirts_kuehlen_getrennt_ab():
    regel = _regel()
    a = regel.cooldown_key(_ereignis("ai-llm").payload)
    b = regel.cooldown_key(_ereignis("ai-llm-slow").payload)
    assert a != b
    assert a == "node2|ai-llm"


def test_meldung_nennt_container_und_wirt():
    regel = _regel()
    ereignis = _ereignis("ai-llm-slow")
    regel.events.append(ereignis)
    text = pipeline._render_hint(regel, ereignis)
    assert "'ai-llm-slow'" in text
    assert "node2" in text
