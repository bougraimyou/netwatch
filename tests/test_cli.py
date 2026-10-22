"""The command line, exercised through the real entry point.

These run ``python -m netwatch`` in a subprocess rather than calling ``main()``
so the packaging, the parser and the exit codes are all tested the way a user
or a CI job would hit them.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from helpers import FIXTURES, run_cli


class TestBasicCommands(unittest.TestCase):
    def test_version(self):
        result = run_cli("--version")
        self.assertEqual(result.returncode, 0)
        self.assertIn("netwatch", result.stdout)

    def test_rules_lists_every_rule(self):
        result = run_cli("rules")
        self.assertEqual(result.returncode, 0)
        for rule in ("port_scan", "dns_anomaly", "beaconing", "cleartext_credentials", "new_external_peer"):
            self.assertIn(rule, result.stdout)

    def test_help_mentions_exit_codes(self):
        result = run_cli("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Exit codes", result.stdout)


class TestAnalyze(unittest.TestCase):
    def test_demo_capture_analyzes_clean(self):
        directory = Path(tempfile.mkdtemp())
        generated = run_cli("demo", "--out", str(directory), "--scenario", "scan")
        self.assertEqual(generated.returncode, 0, generated.stderr)

        capture = directory / "scan.pcap"
        self.assertTrue(capture.exists())
        result = run_cli("analyze", str(capture))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("scanned 200 ports", result.stdout)

    def test_json_and_html_are_written(self):
        directory = Path(tempfile.mkdtemp())
        result = run_cli(
            "analyze",
            str(FIXTURES / "mixed.pcap"),
            "--baseline",
            str(FIXTURES / "baseline.json"),
            "--json",
            str(directory / "report.json"),
            "--html",
            str(directory / "report.html"),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads((directory / "report.json").read_text())
        self.assertGreater(report["alert_count"], 0)
        html = (directory / "report.html").read_text()
        self.assertIn("<!doctype html>", html)

    def test_fail_on_alerts_exits_one(self):
        result = run_cli("analyze", str(FIXTURES / "scan.pcap"), "--fail-on-alerts", "-q")
        self.assertEqual(result.returncode, 1)

    def test_fail_on_alerts_stays_zero_on_clean_traffic(self):
        result = run_cli("analyze", str(FIXTURES / "clean.pcap"), "--fail-on-alerts", "-q")
        self.assertEqual(result.returncode, 0)

    def test_missing_capture_is_a_clean_error(self):
        result = run_cli("analyze", "/nonexistent/capture.pcap")
        self.assertEqual(result.returncode, 2)
        self.assertIn("no such file", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_quiet_suppresses_the_summary(self):
        result = run_cli("analyze", str(FIXTURES / "clean.pcap"), "-q")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "")


class TestConfigErrors(unittest.TestCase):
    def test_unknown_rule_is_rejected(self):
        directory = Path(tempfile.mkdtemp())
        config = directory / "rules.json"
        config.write_text(json.dumps({"port_scna": {"distinct_ports": 10}}))
        result = run_cli("analyze", str(FIXTURES / "clean.pcap"), "--config", str(config))
        self.assertEqual(result.returncode, 2)
        self.assertIn("unknown rule", result.stderr)

    def test_unknown_setting_is_rejected(self):
        directory = Path(tempfile.mkdtemp())
        config = directory / "rules.json"
        config.write_text(json.dumps({"port_scan": {"distinct_port": 10}}))
        result = run_cli("analyze", str(FIXTURES / "clean.pcap"), "--config", str(config))
        self.assertEqual(result.returncode, 2)
        self.assertIn("unknown setting", result.stderr)

    def test_invalid_json_is_rejected(self):
        directory = Path(tempfile.mkdtemp())
        config = directory / "rules.json"
        config.write_text("{not json")
        result = run_cli("analyze", str(FIXTURES / "clean.pcap"), "--config", str(config))
        self.assertEqual(result.returncode, 2)
        self.assertIn("not valid JSON", result.stderr)


class TestOtherCommands(unittest.TestCase):
    def test_baseline_then_analyze(self):
        directory = Path(tempfile.mkdtemp())
        baseline = directory / "baseline.json"
        built = run_cli("baseline", str(FIXTURES / "clean.pcap"), "--out", str(baseline), "--note", "test")
        self.assertEqual(built.returncode, 0, built.stderr)
        document = json.loads(baseline.read_text())
        self.assertEqual(document["note"], "test")
        self.assertTrue(document["hosts"])

        result = run_cli("analyze", str(FIXTURES / "cleartext.pcap"), "--baseline", str(baseline))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("FTP credentials", result.stdout)

    def test_report_renders_an_existing_json(self):
        directory = Path(tempfile.mkdtemp())
        report_json = directory / "report.json"
        run_cli(
            "analyze",
            str(FIXTURES / "scan.pcap"),
            "--json",
            str(report_json),
            "-q",
        )
        out = directory / "standalone.html"
        result = run_cli("report", str(report_json), "--out", str(out))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("<!doctype html>", out.read_text())

    def test_report_missing_file(self):
        result = run_cli("report", "/nope/report.json", "--out", "/tmp/x.html")
        self.assertEqual(result.returncode, 2)

    def test_demo_bundle_writes_everything(self):
        directory = Path(tempfile.mkdtemp()) / "demo"
        result = run_cli("demo", "--out", str(directory))
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ("report.json", "report.html", "index.html", "app.js", "style.css", "baseline.json"):
            self.assertTrue((directory / name).exists(), name)
        for scenario in ("clean", "scan", "dns", "beacon", "cleartext", "mixed"):
            self.assertTrue((directory / "captures" / f"{scenario}.pcap").exists(), scenario)

    def test_unknown_scenario_is_rejected(self):
        result = run_cli("demo", "--out", tempfile.mkdtemp(), "--scenario", "nope")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unknown scenario", result.stderr)

    def test_serve_without_input_fails_cleanly(self):
        result = run_cli("serve")
        self.assertEqual(result.returncode, 2)
        self.assertIn("captures", result.stderr)


class TestReportShapeErrors(unittest.TestCase):
    """A report file is trusted input for the renderer and the server, so a
    file that is valid JSON but not a netwatch report must be refused with
    exit 2 and the file named - not an AttributeError from mid-render."""

    def _write(self, content: str) -> str:
        path = Path(tempfile.mkdtemp()) / "report.json"
        path.write_text(content, encoding="utf-8")
        return str(path)

    def test_report_rejects_documents_that_are_not_reports(self):
        for content in ("123", "[]", '"x"', "{}"):
            with self.subTest(content=content):
                out = Path(tempfile.mkdtemp()) / "standalone.html"
                result = run_cli("report", self._write(content), "--out", str(out))
                self.assertEqual(result.returncode, 2)
                self.assertIn("not a netwatch report", result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertFalse(out.exists())

    def test_serve_rejects_a_bad_report_before_binding_a_socket(self):
        # If the validation happened after the bind, the server would hold the
        # process open and this run_cli call would hit its timeout instead of
        # returning exit 2.
        result = run_cli("serve", "--report", self._write('"x"'), timeout=15)
        self.assertEqual(result.returncode, 2)
        self.assertIn("not a netwatch report", result.stderr)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
