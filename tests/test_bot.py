"""Smoke + correctness tests. Run: python -m unittest discover tests"""
from __future__ import annotations

import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from edr_parser import _detect_vendor, parse_alert, parse_alert_file  # noqa: E402
from ioc_enricher import IOCEnricher, classify_ioc  # noqa: E402
from triage_bot import decide, triage  # noqa: E402


class TestClassifier(unittest.TestCase):
    def test_classify(self):
        cases = {
            "1.2.3.4": "ipv4",
            "::1": "ipv6",
            "evil.com": "domain",
            "5d41402abc4b2a76b9719d911017c592": "md5",
            "0123456789abcdef0123456789abcdef01234567": "sha1",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef": "sha256",
            "https://evil.com/x": "url",
            "garbage": "unknown",
        }
        for value, expected in cases.items():
            self.assertEqual(classify_ioc(value), expected, value)


class TestEnricher(unittest.TestCase):
    def setUp(self):
        self.enricher = IOCEnricher(intel_path=os.path.join(ROOT, "samples", "threat_intel.json"))

    def test_known_bad_ip(self):
        e = self.enricher.enrich("45.155.205.233")
        self.assertEqual(e.kind, "ipv4")
        self.assertGreaterEqual(e.score, 90)
        self.assertIn("c2", e.tags)

    def test_benign_dns(self):
        e = self.enricher.enrich("8.8.8.8")
        self.assertEqual(e.score, 0)

    def test_unknown_ioc(self):
        e = self.enricher.enrich("not.in.intel.example")
        self.assertEqual(e.score, 0)
        self.assertEqual(e.kind, "domain")


class TestEdrParser(unittest.TestCase):
    def test_detect_vendor(self):
        cs = {"behaviors": [{}], "device": {"hostname": "x"}}
        s1 = {"device": {}, "agent": {}, "threatInfo": {}}
        defender = {"DeviceName": "x", "Severity": "High"}
        self.assertEqual(_detect_vendor(cs), "crowdstrike")
        self.assertEqual(_detect_vendor(s1), "sentinelone")
        self.assertEqual(_detect_vendor(defender), "defender")

    def test_parse_sample(self):
        alerts = parse_alert_file(os.path.join(ROOT, "samples", "edr_alerts.json"))
        self.assertEqual(len(alerts), 5)
        # First alert is the CrowdStrike one; should map severity 80 -> critical.
        self.assertEqual(alerts[0]["vendor"], "crowdstrike")
        self.assertEqual(alerts[0]["severity"], "critical")


class TestDecisioning(unittest.TestCase):
    def test_block_when_critical_and_high_score(self):
        action, _ = decide({"severity": "critical"}, [{"score": 95}])
        self.assertEqual(action, "block")

    def test_escalate_for_high_with_70(self):
        action, _ = decide({"severity": "high"}, [{"score": 75}])
        self.assertEqual(action, "escalate")

    def test_investigate_for_medium_with_iocs(self):
        action, _ = decide({"severity": "medium"}, [{"score": 50}])
        self.assertEqual(action, "investigate")

    def test_auto_close_low_no_iocs(self):
        action, _ = decide({"severity": "low"}, [{"score": 0}])
        self.assertEqual(action, "auto_close")


class TestEndToEnd(unittest.TestCase):
    def test_e2e(self):
        decisions = triage(
            os.path.join(ROOT, "samples", "edr_alerts.json"),
            os.path.join(ROOT, "samples", "threat_intel.json"),
        )
        self.assertEqual(len(decisions), 5)
        actions = [d["action"] for d in decisions]
        self.assertIn("block", actions)
        self.assertIn("auto_close", actions)


if __name__ == "__main__":
    unittest.main()
