import json
import unittest
from unittest import mock

import cti_checker


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def read(self):
        return json.dumps(self.payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class CTICheckerTests(unittest.TestCase):
    def test_extract_verdict_from_explicit_boolean(self):
        self.assertEqual(cti_checker.extract_verdict({"malicious": True}), "malicious")
        self.assertEqual(cti_checker.extract_verdict({"malicious": False}), "benign")

    def test_extract_verdict_avoids_guessing_for_unknown_values(self):
        self.assertEqual(
            cti_checker.extract_verdict({"classification": "unknown"}),
            "unknown",
        )
        self.assertEqual(cti_checker.extract_verdict({"confidence_score": 95}), "unknown")

    def test_query_ais_posts_expected_payload_and_headers(self):
        captured = {}

        def fake_urlopen(req, timeout):
            captured["url"] = req.full_url
            captured["timeout"] = timeout
            captured["headers"] = dict(req.header_items())
            captured["body"] = req.data.decode("utf-8")
            return FakeResponse({"verdict": "malicious"})

        config = cti_checker.AISConfig(
            base_url="https://ais.example.test",
            path="/lookup",
            api_key="secret-token",
        )

        with mock.patch("cti_checker.request.urlopen", side_effect=fake_urlopen):
            result = cti_checker.query_ais(config, "1.2.3.4", "ioc")

        self.assertEqual(captured["url"], "https://ais.example.test/lookup")
        self.assertEqual(captured["timeout"], 15)
        self.assertEqual(json.loads(captured["body"]), {"query": "1.2.3.4", "query_type": "ioc"})
        self.assertEqual(
            captured["headers"]["Authorization"],
            f"{config.auth_scheme} {config.api_key}",
        )
        self.assertEqual(result["verdict"], "malicious")


if __name__ == "__main__":
    unittest.main()
