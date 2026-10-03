
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from verification.entities import extract_entities
from verification.openphish import _post_lookup_request, check_url
from verification.sebi import verify_entity
from verification.urls import extract_urls


class UrlExtractionTests(unittest.TestCase):
    def test_extracts_and_normalizes_urls(self) -> None:
        text = (
            "Open https://bad.example.in/login?id=4, visit bad-domain[.]com, "
            "or see hxxps://phish.example.co.uk/path."
        )
        self.assertEqual(
            extract_urls(text),
            [
                "https://bad.example.in/login?id=4",
                "https://bad-domain.com",
                "https://phish.example.co.uk/path",
            ],
        )

    def test_ignores_email_domains_and_deduplicates_case_insensitively(self) -> None:
        self.assertEqual(
            extract_urls("mail me at help@example.com; visit https://EXAMPLE.com and https://example.com"),
            ["https://EXAMPLE.com"],
        )

    def test_non_string_or_empty_input_returns_no_urls(self) -> None:
        self.assertEqual(extract_urls(""), [])
        self.assertEqual(extract_urls(None), [])


class OpenPhishTests(unittest.TestCase):
    def test_gateway_request_uses_post_json_and_bearer_auth(self) -> None:
        class FakeResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def read(self, _limit):
                return b'{"status":"NO_MATCH_FOUND"}'

        class FakeOpener:
            request = None

            def open(self, request, timeout):
                self.request = request
                self.timeout = timeout
                return FakeResponse()

        opener = FakeOpener()
        with patch("verification.openphish.build_opener", return_value=opener):
            payload = _post_lookup_request(
                "https://gateway.example/check",
                "unit-test-key",
                "https://suspicious.example/path",
            )

        self.assertEqual(payload, {"status": "NO_MATCH_FOUND"})
        self.assertEqual(opener.request.get_method(), "POST")
        self.assertEqual(opener.request.get_header("Authorization"), "Bearer unit-test-key")
        self.assertEqual(
            json.loads(opener.request.data.decode("utf-8")),
            {"url": "https://suspicious.example/path"},
        )

    def test_missing_api_key_returns_configured_unavailable_shape(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            result = check_url("https://example.com")

        self.assertEqual(result["status"], "VERIFICATION_UNAVAILABLE")
        self.assertEqual(result["message"], "External phishing verification is not configured.")

    def test_phishing_match(self) -> None:
        with patch(
            "verification.openphish._post_lookup_request",
            return_value={"status": "PHISHING_DATABASE_MATCH"},
        ) as request:
            result = check_url(
                "https://bad.example/login",
                api_key="unit-test-key",
                api_url="https://gateway.example/check",
            )

        self.assertEqual(result["status"], "PHISHING_DATABASE_MATCH")
        request.assert_called_once_with(
            "https://gateway.example/check",
            "unit-test-key",
            "https://bad.example/login",
        )

    def test_no_match_does_not_claim_url_is_safe(self) -> None:
        with patch(
            "verification.openphish._post_lookup_request",
            return_value={"status": "NO_MATCH_FOUND"},
        ):
            result = check_url(
                "https://unknown.example",
                api_key="unit-test-key",
                api_url="https://gateway.example/check",
            )

        self.assertEqual(result["status"], "NO_MATCH_FOUND")
        self.assertIn("does not mean the URL is safe", result["message"])

    def test_malformed_url_is_not_sent_to_the_service(self) -> None:
        with patch("verification.openphish._post_lookup_request") as request:
            result = check_url(
                "javascript:alert(1)",
                api_key="unit-test-key",
                api_url="https://gateway.example/check",
            )

        self.assertEqual(result["status"], "VERIFICATION_UNAVAILABLE")
        self.assertIn("malformed", result["message"])
        request.assert_not_called()

    def test_upstream_failure_is_a_clean_unavailable_result(self) -> None:
        with patch(
            "verification.openphish._post_lookup_request",
            side_effect=TimeoutError("private network detail"),
        ):
            result = check_url(
                "https://example.com",
                api_key="unit-test-key",
                api_url="https://gateway.example/check",
            )

        self.assertEqual(result["status"], "VERIFICATION_UNAVAILABLE")
        self.assertNotIn("private network detail", result["message"])


class SebiVerificationTests(unittest.TestCase):
    def test_missing_registry_is_unavailable_with_manual_verification_message(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            result = verify_entity("Example Securities Ltd")

        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertIn("We could not independently verify", result["message"])

    def test_exact_match_uses_only_recorded_registration_details(self) -> None:
        result = verify_entity(
            "Example Securities Ltd.",
            records=[
                {
                    "name": "Example Securities Ltd",
                    "registration_number": "INZ000000000",
                    "category": "Stock Broker",
                }
            ],
            source_url="https://www.sebi.gov.in/intermediaries.html",
        )

        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["registration_number"], "INZ000000000")
        self.assertIn("does not verify a specific investment offer", result["message"])

    def test_missing_name_is_not_labeled_fraudulent(self) -> None:
        result = verify_entity(
            "Unknown Entity",
            records=[{"name": "Known Broker Limited"}],
            source_url="https://www.sebi.gov.in/intermediaries.html",
        )

        self.assertEqual(result["status"], "NOT VERIFIED")
        self.assertIn("does not mean the entity is fraudulent", result["message"])

    def test_rejects_unofficial_registry_source(self) -> None:
        result = verify_entity(
            "Example Securities Ltd",
            records=[{"name": "Example Securities Ltd"}],
            source_url="https://fake-sebi-blog.example/registrations",
        )
        self.assertEqual(result["status"], "UNAVAILABLE")

    def test_duplicate_exact_names_are_ambiguous(self) -> None:
        result = verify_entity(
            "Example Securities Ltd",
            records=[
                {"name": "Example Securities Ltd", "registration_number": "first"},
                {"name": "Example Securities Ltd", "registration_number": "second"},
            ],
            source_url="https://www.sebi.gov.in/intermediaries.html",
        )
        self.assertEqual(result["status"], "AMBIGUOUS")
        self.assertNotIn("registration_number", result)

    def test_reads_official_registry_snapshot_from_configured_file(self) -> None:
        document = {
            "source_url": "https://www.sebi.gov.in/intermediaries.html",
            "records": [{"name": "Example Securities Ltd", "category": "Stock Broker"}],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            with patch.dict(os.environ, {"SEBI_REGISTRY_FILE": str(path)}, clear=True):
                result = verify_entity("Example Securities Ltd")

        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["source_url"], document["source_url"])


class EntityExtractionTests(unittest.TestCase):
    def test_extracts_entity_types_and_contact_indicators(self) -> None:
        result = extract_entities(
            "Company: Acme Capital Ltd\n"
            "Broker: Example Securities Pvt Ltd\n"
            "Investment platform: QuickTrade App\n"
            "Call +91 98765 43210 or Telegram @quicktradehelp / t.me/acmealerts\n"
            "Visit https://acme.example/login"
        )

        self.assertIn("Acme Capital Ltd", result["organization_names"])
        self.assertIn("Example Securities Pvt Ltd", result["broker_names"])
        self.assertIn("QuickTrade App", result["investment_platform_names"])
        self.assertIn("+91 98765 43210", result["phone_numbers"])
        self.assertEqual(result["telegram_handles"], ["@quicktradehelp", "@acmealerts"])
        self.assertEqual(
            result["urls"],
            ["https://t.me/acmealerts", "https://acme.example/login"],
        )


if __name__ == "__main__":
    unittest.main()
