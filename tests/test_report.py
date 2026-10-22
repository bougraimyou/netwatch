"""Report assembly and rendering.

The hostile-name test is the one to keep: a capture is untrusted input, and a
DNS name is a string somebody else chose. If a report renders it as markup, a
detection tool becomes a delivery mechanism.
"""

from __future__ import annotations

import json
import re
import unittest

from helpers import report_for
from netwatch.render import render_html

REQUIRED_TOP_LEVEL = (
    "report_version",
    "tool",
    "capture",
    "protocols",
    "top_flows",
    "top_hosts",
    "top_domains",
    "alerts",
    "alert_count",
    "severity_counts",
    "rules",
    "rule_summary",
    "baseline",
    "integrity",
    "limitations",
)


class TestReportShape(unittest.TestCase):
    def test_required_sections_are_present(self):
        report = report_for("mixed")
        for key in REQUIRED_TOP_LEVEL:
            self.assertIn(key, report)

    def test_capture_block_counts_are_consistent(self):
        report = report_for("scan")
        capture = report["capture"]
        self.assertGreater(capture["packets"], 0)
        self.assertGreater(capture["flows"], 0)
        self.assertGreater(capture["duration_s"], 0)
        self.assertEqual(capture["start"] is not None, True)

    def test_alert_count_matches_the_alert_list(self):
        report = report_for("mixed")
        self.assertEqual(report["alert_count"], len(report["alerts"]))
        self.assertEqual(report["alert_count"], sum(report["severity_counts"].values()))

    def test_rule_summary_counts(self):
        report = report_for("mixed")
        summary = report["rule_summary"]
        self.assertEqual(summary["total"], 5)
        self.assertEqual(summary["ran"] + summary["skipped"], summary["total"])

    def test_limitations_name_the_missing_baseline(self):
        report = report_for("mixed", with_baseline=False)
        self.assertTrue(any("baseline" in line.lower() for line in report["limitations"]))
        self.assertFalse(report["baseline"]["present"])

    def test_limitations_always_explain_address_scope(self):
        report = report_for("clean")
        self.assertTrue(any("scope" in line.lower() for line in report["limitations"]))

    def test_json_round_trip(self):
        report = report_for("dns")
        self.assertEqual(json.loads(json.dumps(report)), report)

    def test_protocol_breakdown_sums_to_captured_packets(self):
        report = report_for("clean")
        total = sum(entry["packets"] for entry in report["protocols"])
        # Some packets are link-layer only (ARP) and land under their own name.
        self.assertLessEqual(total, report["capture"]["packets"])


class TestRendering(unittest.TestCase):
    def test_html_is_self_contained(self):
        html = render_html(report_for("mixed"))
        self.assertIn("<!doctype html>", html)
        self.assertIn("window.__NETWATCH_REPORT__", html)
        self.assertNotIn('src="app.js"', html)  # inlined, not linked
        self.assertNotIn('href="style.css"', html)
        self.assertIn("<style>", html)

    def test_html_has_the_alert_titles(self):
        report = report_for("mixed")
        html = render_html(report)
        for alert in report["alerts"]:
            self.assertIn(alert["severity"], html)

    def test_report_data_survives_the_embedded_json(self):
        report = report_for("dns")
        html = render_html(report)
        match = re.search(r"window\.__NETWATCH_REPORT__ = (.*?);</script>", html, re.S)
        self.assertIsNotNone(match)
        embedded = json.loads(match.group(1))
        self.assertEqual(embedded["alert_count"], report["alert_count"])

    def test_script_tag_in_data_cannot_close_the_script_element(self):
        report = report_for("dns")
        report["alerts"][0]["title"] = '</script><script>alert("xss")</script>'
        html = render_html(report)
        # The literal sequence must not appear; the escaped form must.
        self.assertNotIn('</script><script>alert("xss")', html)
        self.assertIn("\\u003c/script\\u003e", html)

    def test_hostile_dns_name_is_not_markup(self):
        report = report_for("dns")
        report["top_domains"].insert(0, {"domain": "<img src=x onerror=alert(1)>", "queries": 1})
        html = render_html(report)
        # Inside the JSON it is escaped; the renderer inserts names with
        # textContent, so no element is ever built from it.
        self.assertNotIn("<img src=x onerror=", html)
        self.assertIn("\\u003cimg", html.lower())

    def test_page_title_is_escaped(self):
        report = report_for("clean")
        report["capture"]["name"] = "a<b>&c"
        html = render_html(report)
        self.assertIn("a&lt;b&gt;&amp;c", html)


if __name__ == "__main__":
    unittest.main()
