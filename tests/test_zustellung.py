"""Zustellpfad: Platzhalter rendern, Kanal waehlen, Discord nur ab high.

Abgesichert wird, was am 2026-08-23 nachweislich still falsch war:
  * der Hint ging woertlich raus ('{{ event.payload.unit }}' statt der Unit),
  * 11 Regeln mit gesetztem Topic wurden nie zugestellt, weil die Zustellung
    an prioritaet >= high hing,
  * unterdrueckte Wiederholungen verschwanden spurlos.

Zu jeder Positiv-Regel steht eine Gegenprobe: sonst bestuende die Suite auch
eine Fassung, die grundsaetzlich nichts mehr zustellt.
"""

import asyncio
import unittest
from unittest import mock

from app import pipeline
from app.notify import NtfyClient
from app.rules import Event, Rule


def _regel(*, prioritaet: str, topic: str | None, hint: str = "", payload: dict | None = None) -> Rule:
    ntfy: dict = {"priority": prioritaet}
    if topic:
        ntfy["topic"] = topic
    r = Rule(
        id="test-regel",
        topic_pattern="homelab/system/test/x",
        min_events=1,
        window_seconds=60,
        triage={"hint": hint},
        ntfy=ntfy,
        suggest_topic="homelab/brain/suggestion/test",
    )
    r.events.append(
        Event(topic="homelab/system/test/x", payload=payload or {}, received_at=1.0)
    )
    return r


class FakeNotify:
    """Discord-Seite."""

    def __init__(self) -> None:
        self.aufrufe: list[dict] = []

    async def notify(self, *, title: str, message: str, urgent: bool = False) -> None:
        self.aufrufe.append({"title": title, "message": message, "urgent": urgent})


class FakeNtfy:
    """Handy-Seite."""

    def __init__(self) -> None:
        self.aufrufe: list[dict] = []

    async def publish(self, *, title: str, message: str, topic=None, priority: str = "") -> None:
        self.aufrufe.append({"title": title, "message": message, "topic": topic, "priority": priority})


class FakeLLM:
    def __init__(self, text: str = "") -> None:
        self._text = text
        self.aufrufe = 0

    async def reason(self, *args, **kwargs) -> dict:
        self.aufrufe += 1
        return {"text": self._text, "source": "test", "elapsed_ms": 1}


async def _dispatch_stub(**kwargs) -> dict:
    return {"result": "skipped"}


def _lauf(
    regel: Rule, *, llm_text: str = "", llm: FakeLLM | None = None
) -> tuple[FakeNotify, FakeNtfy]:
    """Faehrt den echten Zustellpfad, aber ohne MQTT-Broker und Aktions-Dispatch.

    Beides ist hier nicht der Pruefgegenstand und wuerde den Test an einen
    laufenden Broker binden, dann misst er die Umgebung statt den Code.
    """
    notify, ntfy = FakeNotify(), FakeNtfy()
    with (
        mock.patch.object(pipeline, "_mqtt_publish_raw"),
        mock.patch.object(pipeline.actions, "dispatch", _dispatch_stub),
    ):
        asyncio.run(
            pipeline.run_reasoning(
                regel, "fp-test", llm or FakeLLM(llm_text), notify=notify, ntfy=ntfy
            )
        )
    return notify, ntfy


class HintRendern(unittest.TestCase):
    def test_platzhalter_werden_durch_werte_ersetzt(self):
        regel = _regel(
            prioritaet="normal",
            topic="host-warn",
            hint="Unit '{{ event.payload.unit }}' auf {{ event.payload.host }} fehlgeschlagen.",
            payload={"unit": "restic-backup.service", "host": "node1"},
        )
        self.assertEqual(
            pipeline._render_hint(regel),
            "Unit 'restic-backup.service' auf node1 fehlgeschlagen.",
        )

    def test_gegenprobe_hint_ohne_platzhalter_bleibt_unveraendert(self):
        regel = _regel(prioritaet="high", topic="host-critical", hint="Kernservice ist down.")
        self.assertEqual(pipeline._render_hint(regel), "Kernservice ist down.")

    def test_fehlendes_feld_wird_leer_statt_woertlich(self):
        """Ein fehlender Wert darf keinen Platzhalter durchlassen, sonst steht
        die Vorlage wieder in der Meldung und sieht aus wie ein Messwert."""
        regel = _regel(
            prioritaet="normal",
            topic="host-warn",
            hint="Host {{ event.payload.host }} / Unit {{ event.payload.unit }}",
            payload={"host": "host"},
        )
        ergebnis = pipeline._render_hint(regel)
        self.assertNotIn("{{", ergebnis)
        self.assertIn("host", ergebnis)

    def test_gerenderter_hint_landet_wirklich_in_der_push_nachricht(self):
        """Der eigentliche Fehler war nicht der Renderer, sondern dass er im
        Zustellpfad nicht aufgerufen wurde. Genau das wird hier gemessen."""
        regel = _regel(
            prioritaet="high",
            topic="host-critical",
            hint="Container {{ event.payload.container }} bei {{ event.payload.pct }}%.",
            payload={"container": "gitea", "pct": 94},
        )
        _, ntfy = _lauf(regel)
        self.assertEqual(len(ntfy.aufrufe), 1)
        self.assertIn("Container gitea bei 94%.", ntfy.aufrufe[0]["message"])
        self.assertNotIn("{{", ntfy.aufrufe[0]["message"])


class KanalWahl(unittest.TestCase):
    def test_niedrige_prioritaet_mit_topic_geht_ans_handy(self):
        """Der Kern des alten Fehlers: ssh-login-notify & Entwarnungen."""
        regel = _regel(prioritaet="low", topic="host-info", hint="Anmeldung.")
        notify, ntfy = _lauf(regel)
        self.assertEqual(len(ntfy.aufrufe), 1, "info-Kanal muss zugestellt werden")
        self.assertEqual(ntfy.aufrufe[0]["topic"], "host-info")
        self.assertEqual(notify.aufrufe, [], "info darf Discord nicht belasten")

    def test_normale_prioritaet_geht_ans_handy_nicht_nach_discord(self):
        regel = _regel(prioritaet="normal", topic="host-warn", hint="Speicher knapp.")
        notify, ntfy = _lauf(regel)
        self.assertEqual(len(ntfy.aufrufe), 1)
        self.assertEqual(ntfy.aufrufe[0]["topic"], "host-warn")
        self.assertEqual(notify.aufrufe, [])

    def test_hohe_prioritaet_geht_auf_beide_wege(self):
        regel = _regel(prioritaet="high", topic="host-critical", hint="Dienst tot.")
        notify, ntfy = _lauf(regel)
        self.assertEqual(len(ntfy.aufrufe), 1)
        self.assertEqual(ntfy.aufrufe[0]["topic"], "host-critical")
        self.assertEqual(len(notify.aufrufe), 1)
        self.assertTrue(notify.aufrufe[0]["urgent"])

    def test_gegenprobe_ohne_topic_und_ohne_hohe_prioritaet_passiert_nichts(self):
        """Sonst wuerde die Suite auch eine Fassung bestehen, die alles zustellt."""
        regel = _regel(prioritaet="low", topic=None, hint="Belanglos.")
        notify, ntfy = _lauf(regel)
        self.assertEqual(ntfy.aufrufe, [])
        self.assertEqual(notify.aufrufe, [])

    def test_hohe_prioritaet_ohne_topic_erreicht_trotzdem_discord(self):
        """Rueckfallweg: eine Regel ohne Topic darf einen echten Ausfall nicht verlieren."""
        regel = _regel(prioritaet="critical", topic=None, hint="Alles aus.")
        notify, ntfy = _lauf(regel)
        self.assertEqual(len(notify.aufrufe), 1)
        self.assertEqual(ntfy.aufrufe, [])


class PrioritaetsAbbildung(unittest.TestCase):
    def test_jede_stufe_ist_abgebildet(self):
        """Fehlt eine Stufe, geht die Meldung ohne X-Priority raus und klingt
        am Handy wie jede andere, die Kanaltrennung waere dann kosmetisch."""
        for stufe, erwartet in [
            ("critical", "5"),
            ("high", "4"),
            ("normal", "3"),
            ("medium", "3"),
            ("low", "2"),
        ]:
            self.assertEqual(NtfyClient._PRIORITY_MAP.get(stufe), erwartet, stufe)

    def test_gegenprobe_unbekannte_stufe_setzt_keinen_header(self):
        self.assertIsNone(NtfyClient._PRIORITY_MAP.get("default"))


class UnterdrueckteMitzaehlen(unittest.TestCase):
    def test_unterdrueckte_wiederholungen_stehen_in_der_meldung(self):
        """Ohne diese Zeile sieht eine gedaempfte Dauerstoerung aus wie ein Einzelfall."""
        regel = _regel(prioritaet="high", topic="host-critical", hint="Dienst tot.")
        regel.suppressed_at_last_fire = 7
        _, ntfy = _lauf(regel)
        self.assertIn("+7 gleichartige unterdrueckt", ntfy.aufrufe[0]["message"])

    def test_gegenprobe_ohne_unterdrueckte_keine_zeile(self):
        regel = _regel(prioritaet="high", topic="host-critical", hint="Dienst tot.")
        _, ntfy = _lauf(regel)
        self.assertNotIn("unterdrueckt", ntfy.aufrufe[0]["message"])


class KiTextKennzeichnen(unittest.TestCase):
    def test_llm_text_ist_als_einschaetzung_markiert(self):
        """Das Modell erfindet Details (gemessen: 'Naechster Check um 19:15').
        Es muss unterscheidbar bleiben, was gemessen und was geraten ist."""
        regel = _regel(prioritaet="high", topic="host-critical", hint="Dienst tot.")
        _, ntfy = _lauf(regel, llm_text="Vermutlich das Netz.")
        nachricht = ntfy.aufrufe[0]["message"]
        self.assertIn("Einschaetzung (KI): Vermutlich das Netz.", nachricht)

    def test_gegenprobe_ohne_llm_text_keine_leere_ueberschrift(self):
        regel = _regel(prioritaet="high", topic="host-critical", hint="Dienst tot.")
        _, ntfy = _lauf(regel, llm_text="")
        self.assertNotIn("Einschaetzung (KI)", ntfy.aufrufe[0]["message"])


class LlmNurWoEsEtwasZuDeutenGibt(unittest.TestCase):
    def test_stummer_kanal_ruft_kein_llm(self):
        """Eine Entwarnung hat nichts zu deuten. Gemessen: allein
        systemd-unit-recovered lief 49x in 3,8 Tagen durch ein LLM (Median 28 s)
        und bekam eine erfundene Ursache an eine gute Nachricht gehaengt."""
        llm = FakeLLM("erfundene Ursache")
        regel = _regel(prioritaet="low", topic="host-info", hint="Unit laeuft wieder.")
        _, ntfy = _lauf(regel, llm=llm)
        self.assertEqual(llm.aufrufe, 0, "info-Kanal darf kein LLM kosten")
        self.assertNotIn("Einschaetzung (KI)", ntfy.aufrufe[0]["message"])
        self.assertIn("Unit laeuft wieder.", ntfy.aufrufe[0]["message"])

    def test_gegenprobe_warn_und_critical_deuten_weiterhin(self):
        """Sonst bestuende der Test auch eine Fassung, die das LLM ueberall abschaltet."""
        for prio, topic in [("normal", "host-warn"), ("high", "host-critical")]:
            llm = FakeLLM("Deutung")
            regel = _regel(prioritaet=prio, topic=topic, hint="Etwas ist auffaellig.")
            _, ntfy = _lauf(regel, llm=llm)
            self.assertEqual(llm.aufrufe, 1, f"{prio} muss deuten")
            self.assertIn("Einschaetzung (KI): Deutung", ntfy.aufrufe[0]["message"])

    def test_uebersprungen_ist_als_quelle_erkennbar(self):
        """Im Verlauf muss unterscheidbar bleiben, ob das Modell schwieg oder
        gar nicht gefragt wurde, sonst sieht Sparen aus wie ein Ausfall."""
        regel = _regel(prioritaet="low", topic="host-info", hint="Alles gut.")
        _, ntfy = _lauf(regel, llm=FakeLLM(""))
        self.assertIn("Quelle: uebersprungen", ntfy.aufrufe[0]["message"])


if __name__ == "__main__":
    unittest.main()
