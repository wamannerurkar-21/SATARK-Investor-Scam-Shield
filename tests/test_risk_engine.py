from pathlib import Path
import sys
_APP_DIR = Path(__file__).resolve().parents[1] / "artifacts" / "satark"
if str(_APP_DIR) not in sys.path:
    sys.path.insert(0, str(_APP_DIR))

import unittest

from ai.analyzer import analyze_text
from detection.risk_engine import calculate_risk


class RiskEngineTests(unittest.TestCase):
    def test_weighted_score_and_threshold(self) -> None:
        result = calculate_risk(
            [
                {"name": "Guaranteed returns"},
                {"name": "Urgency"},
                {"name": "Payment request"},
            ]
        )
        self.assertEqual(result["risk_score"], 50)
        self.assertEqual(result["risk_level"], "HIGH RISK")
        self.assertEqual(result["risk_name"], "SATARK Risk Indicator")

    def test_credential_indicators_share_one_weight(self) -> None:
        result = calculate_risk(
            [{"name": "OTP request"}, {"name": "PIN request"}]
        )
        self.assertEqual(result["risk_score"], 30)
        self.assertEqual(result["risk_level"], "NEEDS VERIFICATION")

    def test_score_is_capped_at_one_hundred(self) -> None:
        result = calculate_risk(
            [
                {"name": "Guaranteed returns"},
                {"name": "Unrealistic returns"},
                {"name": "Urgency"},
                {"name": "Payment request"},
                {"name": "OTP request"},
                {"name": "Authority impersonation"},
                {"name": "Suspicious investment URL pattern"},
                {"name": "Telegram investment solicitation"},
                {"name": "Fake trading app"},
                {"name": "No-risk claim"},
            ]
        )
        self.assertEqual(result["risk_score"], 100)
        self.assertEqual(result["risk_level"], "VERY HIGH RISK")

    def test_configurable_thresholds_and_weights(self) -> None:
        config = {
            "risk_weights": {"custom": 7},
            "indicator_risk_keys": {"Custom indicator": ["custom"]},
            "risk_thresholds": [
                {"min": 0, "max": 6, "label": "LOW CONCERN"},
                {"min": 7, "max": 100, "label": "NEEDS VERIFICATION"},
            ],
        }
        result = calculate_risk([{"name": "Custom indicator"}], config=config)
        self.assertEqual(result["risk_score"], 7)
        self.assertEqual(result["risk_level"], "NEEDS VERIFICATION")

    def test_empty_analysis_matches_stable_contract(self) -> None:
        result = analyze_text("")
        self.assertEqual(
            set(result),
            {
                "claims",
                "risk_indicators",
                "risk_score",
                "risk_level",
                "summary",
                "verification_steps",
                "urls",
            },
        )
        self.assertEqual(result["claims"], [])
        self.assertEqual(result["risk_indicators"], [])
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "LOW CONCERN")
        self.assertEqual(result["urls"], [])

    def test_sample_claims_and_safety_language(self) -> None:
        result = analyze_text(
            "SEBI approved investment opportunity. "
            "Guaranteed 40% return in 15 days. Pay ₹10,000 today."
        )
        self.assertGreaterEqual(len(result["claims"]), 3)
        self.assertIn("SEBI approval claim", {item["name"] for item in result["risk_indicators"]})
        self.assertNotIn("100% scam", result["summary"])
        self.assertIn("not an official SEBI score", result["summary"])
        self.assertIn("Pause and verify before sending money.", result["verification_steps"])


if __name__ == "__main__":
    unittest.main()