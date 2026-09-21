"""Kanalzuordnung: der ntfy-Block wird auch dann gesetzt, wenn es keinen gibt.

Abgesichert wird, was am 2026-09-20 still falsch war: `umschreiben()`
aktualisierte einen vorhandenen ntfy-Block, legte aber keinen an. Eine NEU
angelegte Regel behielt damit dauerhaft keinen Kanal und meldete nirgendwohin,
waehrend das Werkzeug, dessen einzige Aufgabe die Kanalzuordnung ist, Erfolg
meldete. Sichtbar wurde es erst im Pruefer, und dort nur als Absturz.

Zu jeder Positiv-Regel eine Gegenprobe: eine Fassung, die stumpf einen zweiten
Block anhaengt, bestuende den ersten Test und faellt beim zweiten durch.
"""

import importlib.util
import unittest
from pathlib import Path

import yaml

_PFAD = Path(__file__).resolve().parent.parent / "scripts" / "kanaele-zuordnen.py"
_spec = importlib.util.spec_from_file_location("kanaele_zuordnen", _PFAD)
kz = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(kz)

# Eine ID, die in der echten Zuordnungstabelle steht: umschreiben() bricht bei
# unbekannten IDs bewusst ab, statt einen Kanal zu raten.
ID = "target-down"
KANAL, PRIO, COOLDOWN, KEYS = kz.ZUORDNUNG[ID]


def _regel(*, mit_ntfy: bool, mit_suggest: bool = True) -> str:
    zeilen = [
        f"- id: {ID}",
        "  match:",
        "    topic: homelab/alerts/TargetDown/fired",
        "    min_events: 1",
        "    window_seconds: 300",
        "  triage:",
        "    hint: Beispieltext.",
        "    memory_tags:",
        "    - infra",
    ]
    if mit_ntfy:
        zeilen += ["  ntfy:", "    priority: low", "    topic: host-info"]
    if mit_suggest:
        zeilen.append("  suggest_topic: homelab/brain/suggestion/infra")
    return "\n".join(zeilen) + "\n"


class NtfyBlockAnlegen(unittest.TestCase):
    def _eine_regel(self, text: str) -> dict:
        regeln = yaml.safe_load(kz.umschreiben(text))
        self.assertEqual(len(regeln), 1, "Umschreiben darf keine Regel verlieren oder doppeln")
        return regeln[0]

    def test_fehlender_block_wird_angelegt(self):
        r = self._eine_regel(_regel(mit_ntfy=False))
        self.assertEqual(r["ntfy"]["topic"], kz.TOPIC[KANAL])
        self.assertEqual(r["ntfy"]["priority"], PRIO)

    def test_vorhandener_block_wird_korrigiert_nicht_gedoppelt(self):
        ergebnis = kz.umschreiben(_regel(mit_ntfy=True))
        self.assertEqual(ergebnis.count("  ntfy:"), 1, "kein zweiter Block")
        r = yaml.safe_load(ergebnis)[0]
        self.assertEqual(r["ntfy"]["topic"], kz.TOPIC[KANAL])

    def test_ohne_suggest_topic_bleibt_der_block_in_der_regel(self):
        # Ohne Anker landete ein angehaengter Block hinter den Leerzeilen und
        # damit syntaktisch bei der naechsten Regel.
        r = self._eine_regel(_regel(mit_ntfy=False, mit_suggest=False) + "\n\n")
        self.assertEqual(r["ntfy"]["topic"], kz.TOPIC[KANAL])

    def test_zwei_regeln_bleiben_getrennt(self):
        zweite = _regel(mit_ntfy=False).replace(f"- id: {ID}", "- id: host-memory-critical")
        regeln = yaml.safe_load(kz.umschreiben(_regel(mit_ntfy=False) + "\n" + zweite))
        self.assertEqual([r["id"] for r in regeln], [ID, "host-memory-critical"])
        self.assertTrue(all(r.get("ntfy", {}).get("topic") for r in regeln))

    def test_cooldown_wird_gesetzt(self):
        r = self._eine_regel(_regel(mit_ntfy=False))
        self.assertEqual(r["cooldown_seconds"], COOLDOWN)
        if KEYS:
            self.assertEqual(r["cooldown_key_fields"], KEYS)


class PrueferMeldetStattAbzustuerzen(unittest.TestCase):
    """Die Gegenprobe darf den Mangel nicht mit sich selbst verdecken."""

    def test_regel_ohne_ntfy_ergibt_befund_keinen_keyerror(self):
        import io
        from contextlib import redirect_stdout
        from tempfile import NamedTemporaryFile

        with NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write("rules:\n" + "\n".join(
                "  " + z for z in _regel(mit_ntfy=False).splitlines()) + "\n")
            pfad = Path(f.name)
        puffer = io.StringIO()
        with redirect_stdout(puffer):
            fehler = kz.pruefen(pfad)
        pfad.unlink()
        self.assertGreater(fehler, 0)
        self.assertIn("OHNE ntfy-Kanal", puffer.getvalue())


if __name__ == "__main__":
    unittest.main()
