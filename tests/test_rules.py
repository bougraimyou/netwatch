"""The rule set.

Two kinds of test live here and both matter:

* the scenario matrix - every committed fixture, the rules that must fire on it,
  and the rules that must stay silent;
* the unit cases - a threshold slightly out of reach, a jittered beacon, a
  disabled rule - which prove the rule is measuring what it claims rather than
  matching a fixture it was written against.
"""

from __future__ import annotations

import json
import unittest

from helpers import index_from_frames, report_for, report_from_frames, rules_for
from netwatch.demo import SCENARIOS, CaptureBuilder, GATEWAY, SERVER, tcp
from netwatch.rules import DEFAULT_CONFIG, SEVERITY_ORDER

SCANNER = "10.20.0.23"


def builder() -> CaptureBuilder:
    return CaptureBuilder(seed=11, start_ns=1_760_000_000_000_000_000)


class TestScenarioMatrix(unittest.TestCase):
    """Every scenario: what must fire, what must not, and how much."""

    def test_each_scenario_matches_its_declared_expectations(self):
        for name, scenario in sorted(SCENARIOS.items()):
            with self.subTest(scenario=name):
                report = report_for(name)
                fired = {alert["rule"] for alert in report["alerts"]}
                for rule in scenario.expect.get("rules", []):
                    self.assertIn(
                        rule, fired, f"{name}: expected {rule} to fire, fired {sorted(fired)}"
                    )
                for rule in scenario.expect.get("absent", []):
                    self.assertNotIn(rule, fired, f"{name}: {rule} must stay silent")
                if "alerts" in scenario.expect:
                    self.assertEqual(report["alert_count"], scenario.expect["alerts"])
                if "min_alerts" in scenario.expect:
                    self.assertGreaterEqual(report["alert_count"], scenario.expect["min_alerts"])

    def test_clean_traffic_produces_no_alerts_without_a_baseline(self):
        report = report_for("clean", with_baseline=False)
        self.assertEqual(report["alert_count"], 0)

    def test_clean_traffic_against_its_own_baseline_produces_no_alerts(self):
        # The strongest false-positive test available: the same traffic that
        # built the baseline must not look new to it.
        report = report_for("clean", with_baseline=True)
        self.assertEqual(report["alert_count"], 0)
        self.assertEqual(report["baseline"]["present"], True)


class TestPortScan(unittest.TestCase):
    def test_vertical_scan_fires(self):
        b = builder()
        for index in range(40):
            b.emit(index * 0.2, b.lan(SCANNER, SERVER, tcp(SCANNER, SERVER, 40000 + index, 1 + index, flags=0x02)))
        alerts, _ = rules_for(index_from_frames(b.frames))
        scans = [alert for alert in alerts if alert.rule == "port_scan"]
        self.assertEqual(len(scans), 1)
        self.assertIn("scanned 40 ports", scans[0].title)
        self.assertEqual(scans[0].evidence["distinct_ports"], 40)
        self.assertEqual(scans[0].evidence["syn_only_ratio"], 1.0)

    def test_horizontal_sweep_fires_on_a_single_port(self):
        b = builder()
        for index in range(15):
            target = f"10.20.0.{100 + index}"
            b.emit(index * 0.4, b.lan(SCANNER, target, tcp(SCANNER, target, 40000 + index, 445, flags=0x02)))
        alerts, _ = rules_for(index_from_frames(b.frames))
        scans = [alert for alert in alerts if alert.rule == "port_scan"]
        self.assertTrue(scans)
        self.assertIn("445", scans[0].title)
        self.assertEqual(scans[0].evidence["distinct_hosts"], 15)

    def test_threshold_is_configurable(self):
        b = builder()
        for index in range(40):
            b.emit(index * 0.2, b.lan(SCANNER, SERVER, tcp(SCANNER, SERVER, 40000 + index, 1 + index, flags=0x02)))
        alerts, _ = rules_for(
            index_from_frames(b.frames), config={"port_scan": {"distinct_ports": 500}}
        )
        self.assertEqual([a for a in alerts if a.rule == "port_scan"], [])

    def test_slow_scan_outside_the_window_does_not_fire(self):
        b = builder()
        # 40 ports, but spread over 40 minutes: one port every minute is not a
        # sweep, it is a program doing its job.
        for index in range(40):
            b.emit(index * 60.0, b.lan(SCANNER, SERVER, tcp(SCANNER, SERVER, 40000 + index, 1 + index, flags=0x02)))
        alerts, _ = rules_for(index_from_frames(b.frames))
        self.assertEqual([a for a in alerts if a.rule == "port_scan"], [])

    def test_established_connections_are_not_a_scan(self):
        b = builder()
        # Many ports, but every connection completes its handshake.
        for index in range(40):
            b.emit(index * 0.2, b.lan(SCANNER, SERVER, tcp(SCANNER, SERVER, 40000 + index, 8000 + index, flags=0x12)))
        alerts, _ = rules_for(index_from_frames(b.frames))
        self.assertEqual([a for a in alerts if a.rule == "port_scan"], [])


class TestDnsAnomaly(unittest.TestCase):
    def test_tunnel_pattern_fires(self):
        b = builder()
        b.dns_tunnel(10.0, client="10.20.0.22", queries=60)
        alerts, _ = rules_for(index_from_frames(b.frames))
        dns_alerts = [alert for alert in alerts if alert.rule == "dns_anomaly"]
        self.assertEqual(len(dns_alerts), 1)
        self.assertEqual(dns_alerts[0].host, "10.20.0.22")
        self.assertEqual(dns_alerts[0].evidence["domain"], "example.net")
        self.assertGreaterEqual(dns_alerts[0].evidence["mean_label_length"], 20)

    def test_normal_lookups_do_not_fire(self):
        b = builder()
        for index, name in enumerate(
            ["www.example.com", "mail.example.com", "cdn.example.org", "api.example.net"] * 15
        ):
            b.dns_lookup(index * 0.5, "10.20.0.21", name, "93.184.216.34")
        alerts, _ = rules_for(index_from_frames(b.frames))
        self.assertEqual([a for a in alerts if a.rule == "dns_anomaly"], [])

    def test_nxdomain_flood_fires_even_when_every_domain_differs(self):
        b = builder()
        b.dga_walk(10.0, client="10.20.0.22", queries=40)
        alerts, _ = rules_for(index_from_frames(b.frames))
        dns_alerts = [alert for alert in alerts if alert.rule == "dns_anomaly"]
        self.assertEqual(len(dns_alerts), 1)
        self.assertIn("NXDOMAIN", dns_alerts[0].title)

    def test_a_few_missing_names_are_not_a_flood(self):
        b = builder()
        for index in range(5):
            b.dns_miss(index * 2.0, "10.20.0.21", f"typo{index}.example.com")
        alerts, _ = rules_for(index_from_frames(b.frames))
        self.assertEqual([a for a in alerts if a.rule == "dns_anomaly"], [])


class TestBeaconing(unittest.TestCase):
    def _beacon_frames(self, intervals, *, jitter):
        b = builder()
        clock = 10.0
        for index in range(len(intervals) + 1):
            if index:
                clock += intervals[index - 1] + jitter * (1 if index % 2 else -1)
            b.emit(clock, b.lan("10.20.0.21", GATEWAY, tcp("10.20.0.21", "203.0.113.45", 50000 + index, 8443, flags=0x02)))
        return b.frames

    def test_regular_check_ins_fire(self):
        frames = self._beacon_frames([60.0] * 19, jitter=0.5)
        alerts, _ = rules_for(index_from_frames(frames))
        beacons = [alert for alert in alerts if alert.rule == "beaconing"]
        self.assertEqual(len(beacons), 1)
        self.assertEqual(beacons[0].evidence["connections"], 20)
        self.assertLess(beacons[0].evidence["coefficient_of_variation"], 0.02)

    def test_jittered_traffic_does_not_fire(self):
        frames = self._beacon_frames([60.0] * 19, jitter=20.0)
        alerts, _ = rules_for(index_from_frames(frames))
        self.assertEqual([a for a in alerts if a.rule == "beaconing"], [])

    def test_too_few_connections_do_not_fire(self):
        frames = self._beacon_frames([60.0] * 4, jitter=0.2)
        alerts, _ = rules_for(index_from_frames(frames))
        self.assertEqual([a for a in alerts if a.rule == "beaconing"], [])

    def test_internal_destination_is_not_a_beacon(self):
        b = builder()
        for index in range(20):
            b.emit(10 + index * 60, b.lan("10.20.0.21", SERVER, tcp("10.20.0.21", SERVER, 50000 + index, 8443, flags=0x02)))
        alerts, _ = rules_for(index_from_frames(b.frames))
        self.assertEqual([a for a in alerts if a.rule == "beaconing"], [])


class TestCleartextCredentials(unittest.TestCase):
    def test_ftp_and_http_basic_are_both_reported(self):
        b = builder()
        b.cleartext_login(10.0)
        alerts, _ = rules_for(index_from_frames(b.frames))
        findings = [
            finding
            for alert in alerts
            if alert.rule == "cleartext_credentials"
            for finding in alert.evidence["findings"]
        ]
        protocols = {finding["protocol"] for finding in findings}
        self.assertEqual(protocols, {"FTP", "HTTP"})

    def test_secrets_are_never_written_to_the_report(self):
        b = builder()
        b.cleartext_login(10.0)
        report = report_from_frames(b.frames)
        serialized = json.dumps(report)
        self.assertNotIn("Atias2026", serialized)
        self.assertNotIn("atias-demo-password", serialized)
        # The username survives only in masked form.
        self.assertNotIn('"youcef"', serialized)
        self.assertIn("[redacted]", serialized)

    def test_encrypted_traffic_does_not_fire(self):
        b = builder()
        for index in range(6):
            b.https_session(10 + index * 5, "10.20.0.21", "93.184.216.34")
        alerts, _ = rules_for(index_from_frames(b.frames))
        self.assertEqual([a for a in alerts if a.rule == "cleartext_credentials"], [])


class TestNewExternalPeer(unittest.TestCase):
    def test_rule_is_skipped_without_a_baseline_and_says_so(self):
        alerts, statuses = rules_for(index_from_frames(builder().frames))
        status = next(s for s in statuses if s.rule == "new_external_peer")
        self.assertFalse(status.ran)
        self.assertIn("baseline", status.skipped_reason)
        self.assertEqual([a for a in alerts if a.rule == "new_external_peer"], [])

    def test_known_peers_do_not_fire(self):
        baseline = {
            "version": 1,
            "created": "2026-01-01T00:00:00Z",
            "hosts": {
                "10.20.0.21": {"external_peers": ["93.184.216.34"]},
            },
        }
        b = builder()
        b.https_session(10.0, "10.20.0.21", "93.184.216.34")
        alerts, _ = rules_for(index_from_frames(b.frames), baseline=baseline)
        self.assertEqual([a for a in alerts if a.rule == "new_external_peer"], [])

    def test_new_peer_fires_once_with_volume(self):
        baseline = {"version": 1, "created": "2026-01-01T00:00:00Z", "hosts": {"10.20.0.21": {"external_peers": []}}}
        b = builder()
        b.new_external_peer(10.0, "10.20.0.21")
        alerts, _ = rules_for(index_from_frames(b.frames), baseline=baseline)
        peers = [alert for alert in alerts if alert.rule == "new_external_peer"]
        self.assertEqual(len(peers), 1)
        self.assertEqual(peers[0].evidence["new_peer_count"], 1)


class TestRuleFramework(unittest.TestCase):
    def test_disabled_rule_is_skipped_and_explained(self):
        alerts, statuses = rules_for(
            index_from_frames(builder().frames), config={"port_scan": {"enabled": False}}
        )
        status = next(s for s in statuses if s.rule == "port_scan")
        self.assertFalse(status.ran)
        self.assertEqual(status.skipped_reason, "disabled in config")
        self.assertEqual([a for a in alerts if a.rule == "port_scan"], [])

    def test_every_alert_has_the_fields_the_report_needs(self):
        report = report_for("mixed")
        self.assertGreater(report["alert_count"], 0)
        for alert in report["alerts"]:
            for field in ("rule", "rule_name", "severity", "title", "summary", "host", "description", "evidence", "packets"):
                self.assertIn(field, alert, alert.get("title"))
            self.assertIn(alert["severity"], SEVERITY_ORDER)

    def test_alerts_are_sorted_worst_first(self):
        report = report_for("mixed")
        ranks = [SEVERITY_ORDER[alert["severity"]] for alert in report["alerts"]]
        self.assertEqual(ranks, sorted(ranks))

    def test_scan_alert_carries_a_real_hexdump(self):
        report = report_for("scan")
        scan = next(alert for alert in report["alerts"] if alert["rule"] == "port_scan")
        hexdumps = [packet["hex"] for packet in scan["packets"] if packet.get("hex")]
        self.assertTrue(hexdumps, "a scan alert should carry the triggering bytes")
        # Bytes 12-13 of an Ethernet frame are the ethertype; a real frame
        # dump has IPv4 there, and the sample is long enough to include it.
        self.assertEqual(hexdumps[0][24:28], "0800")
        self.assertGreater(len(hexdumps[0]), 40)

    def test_statuses_cover_every_rule_every_time(self):
        _, statuses = rules_for(index_from_frames(builder().frames))
        self.assertEqual({status.rule for status in statuses}, set(DEFAULT_CONFIG))


if __name__ == "__main__":
    unittest.main()
