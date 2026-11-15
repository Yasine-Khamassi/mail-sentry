from __future__ import annotations

import json
import unittest
from pathlib import Path

from mail_sentry.analyzer import analyze
from mail_sentry.body_analysis import analyze_body
from mail_sentry.lure_language import CATEGORY_RULES, LURE_DIR, detect_language, load_dictionaries, scan_lures

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "lures"
# Language fixture -> categories that must fire.
EXPECTED = {
    "en": {"urgency", "invoice_payment", "package_delivery"},
    "fr": {"urgency", "credential_reset"},
    "es": {"invoice_payment", "package_delivery"},
    "de": {"urgency", "financial", "invoice_payment"},
    "pt": {"financial", "prize_lottery"},
    "ru": {"urgency", "credential_reset"},
    "zh": {"urgency", "credential_reset"},
    "ja": {"urgency", "credential_reset"},
    "ar": {"urgency", "financial", "credential_reset"},
}


def categories(language_report):
    return {match["category"] for match in language_report["lure_matches"]}


class DictionaryTests(unittest.TestCase):
    def test_every_language_has_every_category(self):
        dictionaries = load_dictionaries()
        self.assertTrue({"en", "ar", "fr", "es", "de", "pt", "ru", "zh", "ja"} <= set(dictionaries))
        for code, dictionary in dictionaries.items():
            with self.subTest(language=code):
                self.assertEqual(set(dictionary.categories), set(CATEGORY_RULES))
                self.assertTrue(all(terms for terms in dictionary.categories.values()))

    def test_files_carry_language_metadata_and_weights(self):
        for path in LURE_DIR.glob("*.json"):
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(path.stem, data["language"])
            for entries in data["categories"].values():
                for entry in entries:
                    self.assertIn(entry["weight"], range(1, 6))
                    self.assertTrue(("term" in entry) != ("pattern" in entry))


class FixtureTests(unittest.TestCase):
    def test_each_language_fixture_fires_its_categories(self):
        for code, expected in EXPECTED.items():
            with self.subTest(language=code):
                report = analyze(FIXTURES / f"{code}.eml")
                self.assertEqual(report["language"]["detected"], code)
                self.assertTrue(expected <= categories(report["language"]), categories(report["language"]))

    def test_benign_foreign_mail_stays_quiet(self):
        for name in ("fr_benign", "de_benign"):
            with self.subTest(name=name):
                report = analyze(FIXTURES / f"{name}.eml")
                self.assertEqual(report["language"]["lure_matches"], [])
                self.assertEqual(report["verdict"], "low_risk")

    def test_category_maps_to_rule_with_language_in_evidence(self):
        report = analyze(FIXTURES / "fr.eml")
        rules = {signal["rule"]: signal for signal in report["signals"]}
        self.assertIn("credential_lure", rules)
        self.assertTrue(rules["credential_lure"]["evidence"][0].startswith("French: "))


class BuiltinDetectionTests(unittest.TestCase):
    """The fallback detector must work without langdetect."""

    def test_scripts(self):
        samples = {
            "ar": "عزيزي العميل سيتم إيقاف حسابك قريبا",
            "ru": "Здравствуйте, ваш аккаунт будет заблокирован",
            "zh": "尊敬的用户您的账户已被冻结请尽快处理",
            "ja": "お客様のアカウントが停止されました。確認してください",
        }
        for code, text in samples.items():
            with self.subTest(language=code):
                self.assertEqual(detect_language(text, use_langdetect=False)["detected"], code)

    def test_latin_stopwords(self):
        samples = {
            "fr": "Bonjour, nous avons besoin de votre confirmation pour la commande dans les meilleurs délais.",
            "es": "Hola, necesitamos su confirmación para el pedido. Gracias por su paciencia con nuestro equipo.",
            "de": "Hallo, wir brauchen bitte Ihre Bestätigung für die Bestellung und den Termin mit dem Team.",
            "pt": "Olá, precisamos da sua confirmação para o pedido. Obrigado pela paciência com o nosso time.",
            "en": "Hello, we need your confirmation for the order and the meeting with our team this week.",
        }
        for code, text in samples.items():
            with self.subTest(language=code):
                result = detect_language(text, use_langdetect=False)
                self.assertEqual(result["detected"], code)
                self.assertEqual(result["method"], "builtin")

    def test_header_confirms_body(self):
        result = detect_language("Bonjour, merci pour votre message et pour les documents.", "fr-CA", use_langdetect=False)
        self.assertEqual((result["detected"], result["source"]), ("fr", "body+header"))
        self.assertGreaterEqual(result["confidence"], 0.9)


class ScanScopeTests(unittest.TestCase):
    def test_low_confidence_scans_every_dictionary(self):
        signals, report = scan_lures("ok 1234", use_langdetect=False)
        self.assertEqual(set(report["scanned"]), set(load_dictionaries()))
        self.assertEqual(signals, [])

    def test_header_alone_does_not_narrow_the_scan(self):
        _signals, report = scan_lures("ok", "de", use_langdetect=False)
        self.assertEqual(report["source"], "header")
        self.assertEqual(set(report["scanned"]), set(load_dictionaries()))

    def test_mixed_message_still_scans_english(self):
        text = "Bonjour, merci pour votre message et pour les documents de la semaine. Gift card needed, wire transfer today."
        signals, report = scan_lures(text, "fr", use_langdetect=False)
        self.assertIn("en", report["scanned"])
        self.assertIn("payment_lure", {s["rule"] for s in signals})

    def test_short_lure_scans_all_languages(self):
        signals, report = scan_lures("Срочно: сбросьте пароль", use_langdetect=False)
        self.assertIn("credential_lure", {s["rule"] for s in signals})

    def test_single_weak_word_does_not_fire(self):
        signals, _report = scan_lures("Veuillez trouver la facture du mois dans le portail habituel, merci.", use_langdetect=False)
        self.assertEqual(signals, [])

    def test_accent_free_spelling_still_matches(self):
        signals, _report = scan_lures("Votre compte sera suspendu. Reinitialisez votre mot de passe immediatement.", "fr", use_langdetect=False)
        self.assertIn("credential_lure", {s["rule"] for s in signals})

    def test_arabic_diacritics_and_alef_forms_are_folded(self):
        signals, _report = scan_lures("يُرجى إِعادة تَعيين كلمة المرور فوراً", use_langdetect=False)
        self.assertIn("credential_lure", {s["rule"] for s in signals})

    def test_hidden_text_is_still_ignored(self):
        html = '<div style="display:none">Votre compte sera suspendu immédiatement</div><p>Déjeuner vendredi ?</p>'
        signals, _links, _text = analyze_body("", html)
        self.assertNotIn("urgency_language", {s["rule"] for s in signals})


if __name__ == "__main__":
    unittest.main()
