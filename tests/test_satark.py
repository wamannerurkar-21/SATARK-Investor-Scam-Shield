from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from artifacts.satark.database.db import (
    get_recent_scans,
    get_summary,
    get_top_indicators,
    init_db,
    record_scan,
)
from artifacts.satark.satark_core import (
    analyze_text,
    detect_indicators,
    extract_text_from_image,
    extract_urls,
    risk_level,
    verification_status,
)
from artifacts.satark.translations import t


class AnalysisTests(unittest.TestCase):
    def test_demo_scam_message_triggers_multiple_signals(self) -> None:
        text = (
            "SEBI approved investment opportunity!\n"
            "Guaranteed 40% return in 15 days.\n"
            "Limited slots.\n"
            "Pay ₹10,000 today.\n"
            "Join our Telegram group."
        )
        result = analyze_text(text, use_optional_modules=False)
        self.assertEqual(result["risk_score"], 100)
        self.assertEqual(result["risk_level"], "VERY HIGH RISK")
        self.assertEqual(
            set(result["indicators"]),
            {
                "guaranteed_return",
                "urgency",
                "payment_request",
                "authority_claim",
                "off_platform_channel",
            },
        )
        self.assertEqual(result["analysis_source"], "Local transparent rules")

    def test_registration_claim_is_needs_verification(self) -> None:
        text = (
            "This adviser is registered with SEBI but the message has no "
            "registration number. Verify through an official source."
        )
        result = analyze_text(text, use_optional_modules=False)
        self.assertEqual(result["risk_score"], 25)
        self.assertEqual(result["risk_level"], "NEEDS VERIFICATION")

    def test_local_urls_are_extracted_but_not_verified(self) -> None:
        result = analyze_text(
            "Review this link https://example.org/check before replying.",
            use_optional_modules=False,
        )
        self.assertEqual(result["urls"], ["https://example.org/check"])
        self.assertEqual(result["url_results"][0]["status"], "not checked")

    def test_risk_thresholds_are_stable(self) -> None:
        self.assertEqual(risk_level(0), "LOW CONCERN")
        self.assertEqual(risk_level(25), "NEEDS VERIFICATION")
        self.assertEqual(risk_level(50), "HIGH RISK")
        self.assertEqual(risk_level(75), "VERY HIGH RISK")

    def test_marathi_signal_patterns_are_detected(self) -> None:
        indicators = detect_indicators("आजच पैसे पाठवा आणि हमीचा परतावा मिळवा.")
        self.assertIn("urgency", indicators)
        self.assertIn("payment_request", indicators)
        self.assertIn("guaranteed_return", indicators)

    def test_clean_verification_response_is_not_reported_as_a_match(self) -> None:
        clean = verification_status(
            [{"status": "No phishing detected"}],
            [{"status": "No match reported"}],
        )
        positive = verification_status(
            [{"status": "Phishing database match"}],
            [],
        )
        uncertain = verification_status(
            [],
            [{"status": "Not verified"}],
        )
        self.assertEqual(clean, "checked — no match reported")
        self.assertEqual(positive, "flagged")
        self.assertEqual(uncertain, "needs verification")

    def test_malformed_ai_output_falls_back_to_local_rules(self) -> None:
        def malformed_analyzer(text: str) -> str:
            return "{this is not JSON"

        with patch(
            "artifacts.satark.satark_core._load_callable",
            side_effect=lambda name: malformed_analyzer if name == "analyze_text" else None,
        ):
            result = analyze_text(
                "Guaranteed return. Pay ₹10,000 today.",
                use_optional_modules=True,
            )
        self.assertEqual(result["analysis_source"], "Local transparent rules")
        self.assertIn("unreadable result", result["analysis_status"])
        self.assertIn("guaranteed_return", result["indicators"])

    def test_local_only_mode_does_not_load_external_analysis_or_verification(self) -> None:
        loaded: list[str] = []

        def local_only_loader(name: str):
            loaded.append(name)
            return None

        with patch(
            "artifacts.satark.satark_core._load_callable",
            side_effect=local_only_loader,
        ):
            result = analyze_text(
                "SEBI approved. Guaranteed 30% return.",
                use_optional_modules=False,
            )
        self.assertTrue(result["indicators"])
        self.assertNotIn("analyze_text", loaded)
        self.assertNotIn("check_url", loaded)
        self.assertNotIn("verify_entity", loaded)

    def test_missing_gemini_key_reports_local_fallback(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            result = analyze_text(
                "SEBI approved offer. Guaranteed 40% return. Visit https://example.com",
                use_optional_modules=True,
            )
        self.assertEqual(result["analysis_source"], "Local transparent rules")
        self.assertEqual(result["analysis_status"], "local fallback")
        self.assertIn("guaranteed_return", result["indicators"])

    def test_invalid_image_is_rejected_without_crashing(self) -> None:
        with self.assertRaises(ValueError):
            extract_text_from_image(b"not an image")


class PrivacyDatabaseTests(unittest.TestCase):
    def test_metadata_and_aggregates_are_stored_without_message_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "satark-test.sqlite3"
            init_db(database)
            scan_id = record_scan(
                input_type="demo",
                risk_level="HIGH RISK",
                risk_score=62,
                indicator_count=2,
                verification_status="not checked",
                indicator_keys=["urgency", "payment_request"],
                db_path=database,
            )

            self.assertTrue(scan_id)
            summary = get_summary(database)
            self.assertEqual(summary["total_scans"], 1)
            self.assertEqual(summary["high_risk_scans"], 1)
            self.assertEqual(len(get_recent_scans(db_path=database)), 1)
            top = get_top_indicators(db_path=database)
            self.assertEqual({row["indicator_key"] for row in top}, {"urgency", "payment_request"})

            with sqlite3.connect(database) as connection:
                scan_columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(scans)")
                }
                stored_values = " ".join(
                    str(value)
                    for row in connection.execute("SELECT * FROM scans")
                    for value in row
                )
            self.assertEqual(
                scan_columns,
                {
                    "scan_id",
                    "timestamp",
                    "input_type",
                    "risk_level",
                    "risk_score",
                    "indicator_count",
                    "verification_status",
                },
            )
            self.assertNotIn("raw_message", scan_columns)
            self.assertNotIn("password", stored_values.lower())

    def test_database_rejects_invalid_input_types_and_scores(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "satark-test.sqlite3"
            with self.assertRaises(ValueError):
                record_scan(
                    input_type="email",
                    risk_level="LOW CONCERN",
                    risk_score=0,
                    indicator_count=0,
                    verification_status="not checked",
                    db_path=database,
                )
            with self.assertRaises(ValueError):
                record_scan(
                    input_type="text",
                    risk_level="LOW CONCERN",
                    risk_score=101,
                    indicator_count=0,
                    verification_status="not checked",
                    db_path=database,
                )


class TranslationTests(unittest.TestCase):
    def test_key_safety_copy_exists_in_all_languages(self) -> None:
        english_steps = t("verify_steps", "en")
        for language in ("hi", "mr"):
            self.assertNotEqual(t("verify_steps", language), english_steps)
            self.assertTrue(t("risk_disclaimer", language))
            self.assertTrue(t("privacy_points", language))


if __name__ == "__main__":
    unittest.main()