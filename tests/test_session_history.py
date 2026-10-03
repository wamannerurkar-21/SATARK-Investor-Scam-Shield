from __future__ import annotations

import unittest

from artifacts.satark.session_history import (
    normalize_session_history,
    recent_session_scans,
    session_summary,
    top_session_indicators,
)


def scan(scan_id: str, risk_level: str, indicators: list[str] | None = None):
    return {
        "scan_id": scan_id,
        "timestamp": f"2026-10-03T10:00:{scan_id[-1]}+00:00",
        "input_type": "text",
        "risk_level": risk_level,
        "risk_score": 60,
        "indicator_count": len(indicators or []),
        "verification_status": "not checked",
        "indicator_keys": indicators or [],
    }


class SessionHistoryTests(unittest.TestCase):
    def test_fresh_session_has_zero_counters_and_no_scans(self) -> None:
        self.assertEqual(
            session_summary([]),
            {
                "total_scans": 0,
                "high_risk_scans": 0,
                "needs_verification": 0,
                "low_concern": 0,
            },
        )
        self.assertEqual(recent_session_scans([]), [])
        self.assertEqual(top_session_indicators([]), [])

    def test_counters_and_recent_history_use_only_the_supplied_session(self) -> None:
        history = [
            scan("scan-1", "VERY HIGH RISK", ["urgency", "payment_request"]),
            scan("scan-2", "NEEDS VERIFICATION", ["urgency"]),
            scan("scan-3", "LOW CONCERN"),
            scan("scan-4", "HIGH RISK", ["payment_request"]),
        ]

        self.assertEqual(
            session_summary(history),
            {
                "total_scans": 4,
                "high_risk_scans": 2,
                "needs_verification": 1,
                "low_concern": 1,
            },
        )
        self.assertEqual(
            [row["scan_id"] for row in recent_session_scans(history, limit=2)],
            ["scan-4", "scan-3"],
        )
        self.assertEqual(
            top_session_indicators(history),
            [
                {"indicator_key": "payment_request", "total_count": 2},
                {"indicator_key": "urgency", "total_count": 2},
            ],
        )

    def test_normalization_rejects_invalid_records_and_duplicate_ids(self) -> None:
        valid = scan("scan-1", "LOW CONCERN")
        invalid = {**scan("scan-2", "LOW CONCERN"), "risk_score": 101}
        normalized = normalize_session_history(
            {"scans": [valid, valid, invalid, {"scan_id": "raw message text"}]}
        )
        self.assertEqual([row["scan_id"] for row in normalized], ["scan-1"])


if __name__ == "__main__":
    unittest.main()