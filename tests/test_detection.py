from pathlib import Path
import sys
_APP_DIR = Path(__file__).resolve().parents[1] / "artifacts" / "satark"
if str(_APP_DIR) not in sys.path:
    sys.path.insert(0, str(_APP_DIR))

import importlib
import csv
import unittest
from pathlib import Path

from detection.rules import detect_risk_indicators
from detection.risk_engine import calculate_risk
from detection.url_extractor import extract_urls


class DetectionTests(unittest.TestCase):
    def names(self, text: str) -> set[str]:
        return {item["name"] for item in detect_risk_indicators(text)}

    def test_guaranteed_return_and_unrealistic_return(self) -> None:
        names = self.names("Guaranteed 40% return in 15 days.")
        self.assertIn("Guaranteed returns", names)
        self.assertIn("Unrealistic returns", names)

    def test_urgency_and_limited_time_pressure(self) -> None:
        names = self.names("Act now: this limited-time offer expires today.")
        self.assertIn("Urgency", names)
        self.assertIn("Limited-time pressure", names)

    def test_payment_request_and_advance_payment(self) -> None:
        names = self.names("Pay ₹10,000 today as an upfront processing fee.")
        self.assertIn("Payment request", names)
        self.assertIn("Advance payment", names)
        self.assertIn("Payment request", self.names("The sender asks for a ₹2,000 deposit."))

    def test_otp_request(self) -> None:
        self.assertIn("OTP request", self.names("Send your OTP now to verify the transfer."))

    def test_authority_claim_and_impersonation(self) -> None:
        names = self.names("A person pretending to be a SEBI officer says this is SEBI approved.")
        self.assertIn("Authority impersonation", names)
        self.assertIn("SEBI approval claim", names)

    def test_telegram_solicitation(self) -> None:
        self.assertIn(
            "Telegram investment solicitation",
            self.names("Join our Telegram group for daily trading signals and profit."),
        )

    def test_legitimate_financial_education_has_no_flags(self) -> None:
        names = self.names(
            "This lesson explains diversification, inflation, and how compound interest works."
        )
        self.assertEqual(names, set())

    def test_url_extraction_returns_url_and_domain_without_verifying(self) -> None:
        urls = extract_urls(
            "Visit https://example.com/login, www.example.org/learn, or example.in/info."
        )
        self.assertEqual(
            urls,
            [
                {"url": "https://example.com/login", "domain": "example.com"},
                {"url": "https://www.example.org/learn", "domain": "www.example.org"},
                {"url": "https://example.in/info", "domain": "example.in"},
            ],
        )

    def test_short_link_near_investment_solicitation_is_heuristically_flagged(self) -> None:
        names = self.names("Join this investment offer and earn returns: https://bit.ly/invest-now")
        self.assertIn("Suspicious investment URL pattern", names)

    def test_requested_red_flag_categories(self) -> None:
        cases = {
            "Double money promise": "Double their money this week.",
            "No-risk claim": "This investment has no possibility of loss.",
            "Limited-time pressure": "This limited-time offer expires today.",
            "Personal UPI or payment account": "Send money to my personal UPI account.",
            "PIN request": "The message asks for your UPI PIN.",
            "Password request": "The message asks for your password.",
            "Private key or seed phrase request": "The message asks for your seed phrase.",
            "Government impersonation": "A government officer asks for a money transfer.",
            "WhatsApp investment solicitation": "Join WhatsApp for trading signals and returns.",
            "Fake trading app": "Download the unofficial trading app.",
            "Guaranteed profit": "We guarantee daily profits.",
        }
        for expected_name, text in cases.items():
            with self.subTest(indicator=expected_name):
                self.assertIn(expected_name, self.names(text))

    def test_official_store_listing_is_not_labeled_a_fake_app(self) -> None:
        names = self.names(
            "Download the trading app from the official store listing shared by your broker."
        )
        self.assertNotIn("Fake trading app", names)

    def test_empty_text_has_no_indicators(self) -> None:
        self.assertEqual(detect_risk_indicators(""), [])

    def test_credentials_warning_is_not_detected_as_a_request(self) -> None:
        names = self.names("Never send your password or OTP to anyone.")
        self.assertNotIn("Password request", names)
        self.assertNotIn("OTP request", names)

    def test_dataset_has_required_prototype_categories_and_columns(self) -> None:
        with (Path(__file__).resolve().parents[1] / "artifacts" / "satark" / "data" / "scam_dataset.csv").open(encoding="utf-8", newline="") as file:
            reader = csv.DictReader(file)
            rows = list(reader)
        self.assertEqual(
            reader.fieldnames,
            ["id", "text", "category", "expected_risk", "expected_indicators"],
        )
        self.assertGreaterEqual(len(rows), 100)
        self.assertEqual(
            {row["category"] for row in rows},
            {
                "investment_scam",
                "guaranteed_return",
                "phishing",
                "impersonation",
                "fake_trading_app",
                "telegram_scam",
                "payment_scam",
                "otp_scam",
                "financial_misinformation",
                "legitimate_education",
                "legitimate_information",
            },
        )
        for row in rows:
            with self.subTest(dataset_id=row["id"]):
                indicators = detect_risk_indicators(row["text"])
                self.assertEqual(
                    row["expected_indicators"].split(";") if row["expected_indicators"] else [],
                    [indicator["name"] for indicator in indicators],
                )
                self.assertEqual(
                    row["expected_risk"],
                    calculate_risk(indicators)["risk_level"],
                )

    def test_modules_import_independently(self) -> None:
        for module_name in (
            "ai.schemas",
            "ai.prompts",
            "ai.analyzer",
            "detection.rules",
            "detection.risk_engine",
            "detection.url_extractor",
        ):
            with self.subTest(module=module_name):
                self.assertIsNotNone(importlib.import_module(module_name))


if __name__ == "__main__":
    unittest.main()