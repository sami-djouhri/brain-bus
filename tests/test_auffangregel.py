"""Auffangregel (ZIELBILD 99): ein Alarm ohne eigene Regel kommt trotzdem an.

Abgesichert wird beides:
  * die Auffangregel meldet nur, wo keine eigene Regel steht (keine
    Doppelmeldung), auch wenn die eigene gerade im Cooldown schweigt,
  * Kanal, Ruhezeit und Texte kommen aus dem Alarm selbst (severity und
    Annotations), nicht aus brain-bus.

Zu jeder Positiv-Regel steht eine Gegenprobe; sonst bestuende die Suite auch
eine Fassung, die gar nichts mehr meldet oder alles doppelt.
"""

import asyncio
import unittest
from unittest import mock

from app import pipeline, rules
from app.rules import Rule, RuleEngine

AUFFANG_TOPIC = "homelab/alerts/+/fired"


def _auffang() -> Rule:
    return Rule(
        id="alarm-auffang",
        topic_pattern=AUFFANG_TOPIC,
        min_events=1,
        window_seconds=300,
        triage={"memory_tags": ["alarm"]},
        ntfy={"priority": "normal", "topic": "host-warn"},
        suggest_topic="homelab/brain/suggestion/infra",
        cooldown_seconds=21600,
        cooldown_key_fields=["fingerprint"],
        rueckfall=True,
    )


def _eigene(name: str, cooldown: int = 0) -> Rule:
    return Rule(
        id=f"eigene-{name}",
        topic_pattern=f"homelab/alerts/{name}/fired",
        min_events=1,
        window_seconds=300,
        triage={"hint": "eigener Text"},
        ntfy={"priority": "high", "topic": "host-critical"},
        suggest_topic="homelab/brain/suggestion/infra",
        cooldown_seconds=cooldown,
    )


def _sturm() -> Rule:
    return Rule(
        id="alert-storm",
        topic_pattern=AUFFANG_TOPIC,
        min_events=5,
        window_seconds=300,
        triage={},
        ntfy={"priority": "normal", "topic": "host-warn"},
        suggest_topic="homelab/brain/suggestion/incident",
        cooldown_seconds=1800,
    )


def _alarm(name: str, *, fp: str = "fp1", severity: str = "warning", **annotations) -> tuple[str, dict]:
    return (
        f"homelab/alerts/{name}/fired",
        {
            "fingerprint": fp,
            "severity": severity,
            "labels": {"alertname": name, "severity": severity, "host": "host"},
            "summary": f"{name} kurz",
            "annotations": {"summary": f"{name} kurz", **annotations},
        },
    )


def _ids(engine: RuleEngine, topic: str, payload: dict) -> list[str]:
    return [r.id for r in engine.on_event(topic, payload, retained=False)]


class Vorrang(unittest.TestCase):
    def test_alarm_ohne_eigene_regel_geht_ueber_die_auffangregel(self):
        engine = RuleEngine([_eigene("Bekannt"), _auffang()])
        self.assertEqual(_ids(engine, *_alarm("Unbekannt")), ["alarm-auffang"])

    def test_gegenprobe_eigene_regel_verdraengt_die_auffangregel(self):
        engine = RuleEngine([_eigene("Bekannt"), _auffang()])
        self.assertEqual(_ids(engine, *_alarm("Bekannt")), ["eigene-Bekannt"])

    def test_eigene_regel_im_cooldown_laesst_die_auffangregel_nicht_einspringen(self):
        engine = RuleEngine([_eigene("Bekannt", cooldown=3600), _auffang()])
        self.assertEqual(_ids(engine, *_alarm("Bekannt")), ["eigene-Bekannt"])
        # zweites Ereignis: die eigene Regel schweigt mit Absicht
        self.assertEqual(_ids(engine, *_alarm("Bekannt", fp="fp2")), [])

    def test_platzhalter_regel_zaehlt_nicht_als_eigene(self):
        """alert-storm lauscht auf dasselbe Topic; wuerde es als eigene Regel
        gelten, kaeme ueber die Auffangregel nie etwas an."""
        engine = RuleEngine([_sturm(), _auffang()])
        self.assertEqual(_ids(engine, *_alarm("Unbekannt")), ["alarm-auffang"])

    def test_annotation_meldeweg_nimmt_den_alarm_heraus(self):
        engine = RuleEngine([_auffang()])
        self.assertEqual(_ids(engine, *_alarm("ViaGrafana", meldeweg="grafana")), [])

    def test_gegenprobe_leerer_meldeweg_meldet(self):
        engine = RuleEngine([_auffang()])
        self.assertEqual(_ids(engine, *_alarm("X", meldeweg="")), ["alarm-auffang"])


class Ruhezeit(unittest.TestCase):
    def test_cooldown_je_fingerabdruck(self):
        engine = RuleEngine([_auffang()])
        self.assertEqual(_ids(engine, *_alarm("A", fp="fp1")), ["alarm-auffang"])
        # gleicher Alarm, gleiches Subjekt: gedaempft
        self.assertEqual(_ids(engine, *_alarm("A", fp="fp1")), [])
        # anderes Subjekt (anderer Wirt): meldet sofort
        self.assertEqual(_ids(engine, *_alarm("A", fp="fp2")), ["alarm-auffang"])

    def test_annotation_ruhezeit_gilt_auch_nach_dem_regelwert(self):
        """7d aus der Annotation darf nicht nach den 6h des Regelwerts verfallen,
        weder beim Vergleich noch beim Aufraeumen der Cooldown-Tabelle."""
        engine = RuleEngine([_auffang()])
        start = 1_000_000.0
        with mock.patch.object(rules.time, "time", return_value=start):
            self.assertEqual(_ids(engine, *_alarm("A", ruhezeit="7d")), ["alarm-auffang"])
        with mock.patch.object(rules.time, "time", return_value=start + 2 * 86400):
            self.assertEqual(_ids(engine, *_alarm("A", ruhezeit="7d")), [])
        with mock.patch.object(rules.time, "time", return_value=start + 8 * 86400):
            self.assertEqual(_ids(engine, *_alarm("A", ruhezeit="7d")), ["alarm-auffang"])

    def test_gegenprobe_ohne_annotation_gilt_der_regelwert(self):
        engine = RuleEngine([_auffang()])
        start = 1_000_000.0
        with mock.patch.object(rules.time, "time", return_value=start):
            _ids(engine, *_alarm("A"))
        with mock.patch.object(rules.time, "time", return_value=start + 7 * 3600):
            self.assertEqual(_ids(engine, *_alarm("A")), ["alarm-auffang"])

    def test_dauer_lesen(self):
        self.assertEqual(rules.dauer_sekunden("6h"), 21600)
        self.assertEqual(rules.dauer_sekunden("90"), 90)
        self.assertEqual(rules.dauer_sekunden("7d"), 604800)
        self.assertIsNone(rules.dauer_sekunden("bald"))


class FakeNotify:
    def __init__(self) -> None:
        self.aufrufe: list[dict] = []

    async def notify(self, *, title: str, message: str, urgent: bool = False) -> None:
        self.aufrufe.append({"title": title, "message": message})


class FakeNtfy:
    def __init__(self) -> None:
        self.aufrufe: list[dict] = []

    async def publish(self, *, title: str, message: str, topic=None, priority: str = "") -> None:
        self.aufrufe.append({"title": title, "message": message, "topic": topic, "priority": priority})


class FakeLLM:
    def __init__(self) -> None:
        self.aufrufe = 0

    async def reason(self, *args, **kwargs) -> dict:
        self.aufrufe += 1
        return {"text": "", "source": "test", "elapsed_ms": 1}


async def _dispatch_stub(**kwargs) -> dict:
    return {"result": "skipped"}


async def _verlauf_stub(*args, **kwargs) -> str:
    return ""


def _zustellen(name: str, **kw) -> tuple[FakeNotify, FakeNtfy, FakeLLM]:
    engine = RuleEngine([_auffang()])
    topic, payload = _alarm(name, **kw)
    (regel,) = engine.on_event(topic, payload, retained=False)
    notify, ntfy, llm = FakeNotify(), FakeNtfy(), FakeLLM()
    with (
        mock.patch.object(pipeline, "_mqtt_publish_raw"),
        mock.patch.object(pipeline.actions, "dispatch", _dispatch_stub),
        mock.patch.object(pipeline.verlauf, "fuer_ereignis", _verlauf_stub),
    ):
        asyncio.run(
            pipeline.run_reasoning(
                regel, "fp", llm, notify=notify, ntfy=ntfy, trigger_event=regel.trigger_event
            )
        )
    return notify, ntfy, llm


class Zustellung(unittest.TestCase):
    def test_titel_traegt_den_alarmnamen_nicht_die_regel(self):
        _, ntfy, _ = _zustellen("PlatteVoll")
        self.assertEqual(ntfy.aufrufe[0]["title"], "Homelab: PlatteVoll")

    def test_kanal_aus_severity(self):
        for severity, topic, prio in (
            ("critical", "host-critical", "high"),
            ("warning", "host-warn", "normal"),
            ("info", "host-info", "low"),
        ):
            with self.subTest(severity=severity):
                _, ntfy, _ = _zustellen("A", severity=severity)
                self.assertEqual(ntfy.aufrufe[0]["topic"], topic)
                self.assertEqual(ntfy.aufrufe[0]["priority"], prio)

    def test_annotation_kanal_schlaegt_severity(self):
        _, ntfy, _ = _zustellen("A", severity="warning", kanal="critical")
        self.assertEqual(ntfy.aufrufe[0]["topic"], "host-critical")

    def test_discord_nur_fuer_critical(self):
        notify, _, _ = _zustellen("A", severity="critical")
        self.assertEqual(len(notify.aufrufe), 1)
        notify, _, _ = _zustellen("A", severity="warning")
        self.assertEqual(notify.aufrufe, [])

    def test_erster_schritt_und_hinweis_aus_den_annotations(self):
        _, ntfy, _ = _zustellen(
            "A", severity="critical", hinweis="Platte auf host voll.",
            erster_schritt="df -h /", description="lang",
        )
        text = ntfy.aufrufe[0]["message"]
        self.assertTrue(text.startswith("Erster Schritt: df -h /"))
        self.assertIn("Platte auf host voll.", text)
        self.assertNotIn("lang", text)

    def test_ohne_hinweis_kommt_die_description_an(self):
        """Der alte Mangel: die Prometheus-description erreichte das Handy nie."""
        _, ntfy, _ = _zustellen("A", description="Beschreibung aus Prometheus")
        self.assertIn("Beschreibung aus Prometheus", ntfy.aufrufe[0]["message"])

    def test_info_ohne_ki_deutung(self):
        _, _, llm = _zustellen("A", severity="info")
        self.assertEqual(llm.aufrufe, 0)


if __name__ == "__main__":
    unittest.main()
