"""The synthetic captures themselves.

Two claims are being tested here, and both are load-bearing for the README:

* the committed fixtures are byte-for-byte what the generator produces, so
  ``netwatch demo`` really does reproduce the demo people can see;
* the frames are well-formed IP packets with correct checksums, not byte soup
  that only this decoder happens to accept.
"""

from __future__ import annotations

import json
import struct
import unittest

from helpers import FIXTURES, SEED, START_NS, index_from_frames
from netwatch.baseline import build as build_baseline
from netwatch.demo import SCENARIOS, build, serialise


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


class TestReproducibility(unittest.TestCase):
    def test_committed_fixtures_match_the_generator(self):
        for name in sorted(SCENARIOS):
            with self.subTest(scenario=name):
                generated, _ = build(name, seed=SEED, start_ns=START_NS)
                committed = (FIXTURES / f"{name}.pcap").read_bytes()
                self.assertEqual(
                    len(generated),
                    len(committed),
                    f"{name}: committed fixture has a different size than the generator produces",
                )
                self.assertEqual(generated, committed, f"{name}: committed fixture has drifted")

    def test_baseline_fixture_matches_a_fresh_build(self):
        committed = json.loads((FIXTURES / "baseline.json").read_text())
        capture, _ = build("clean", seed=SEED, start_ns=START_NS)
        frames = _frames_from_pcap(capture)
        rebuilt = build_baseline(index_from_frames(frames))
        self.assertEqual(rebuilt["hosts"], committed["hosts"])
        self.assertEqual(rebuilt["window"], committed["window"])

    def test_serialise_round_trips_through_the_reader(self):
        from netwatch.pcap import PcapReader
        import io

        payload, _ = build("scan", seed=SEED, start_ns=START_NS)
        packets = list(PcapReader(io.BytesIO(payload)))
        self.assertGreater(len(packets), 0)
        self.assertEqual(packets[0].linktype, 1)


class TestFrameValidity(unittest.TestCase):
    def test_every_ipv4_header_checksum_is_correct(self):
        for name in sorted(SCENARIOS):
            capture, _ = build(name, seed=SEED, start_ns=START_NS)
            checked = 0
            for ts_ns, frame in _frames_from_pcap(capture):
                if len(frame) < 34 or frame[12:14] != b"\x08\x00":
                    continue
                ihl = (frame[14] & 0x0F) * 4
                header = frame[14 : 14 + ihl]
                self.assertEqual(checksum(header), 0xFFFF, f"{name}: bad IPv4 checksum")
                checked += 1
            self.assertGreater(checked, 0, f"{name}: no IPv4 packets to check")

    def test_transport_checksums_are_correct(self):
        capture, _ = build("clean", seed=SEED, start_ns=START_NS)
        checked_tcp = 0
        checked_udp = 0
        for _ts_ns, frame in _frames_from_pcap(capture):
            if len(frame) < 34 or frame[12:14] != b"\x08\x00":
                continue
            ihl = (frame[14] & 0x0F) * 4
            protocol = frame[23]
            total_len = struct.unpack_from("!H", frame, 16)[0]
            segment = frame[14 + ihl : 14 + total_len]
            pseudo = frame[26:34] + struct.pack("!BBH", 0, protocol, len(segment))
            if protocol == 6 and len(segment) >= 20:
                self.assertEqual(checksum(pseudo + segment), 0xFFFF, "bad TCP checksum")
                checked_tcp += 1
            elif protocol == 17 and len(segment) >= 8:
                stored = struct.unpack_from("!H", segment, 6)[0]
                if stored:
                    self.assertEqual(checksum(pseudo + segment), 0xFFFF, "bad UDP checksum")
                    checked_udp += 1
        self.assertGreater(checked_tcp, 0)
        self.assertGreater(checked_udp, 0)

    def test_no_duplicate_timestamps_within_a_flow(self):
        # Two packets at the same instant in the same direction would make
        # interval statistics lie; the generator spaces everything.
        capture, _ = build("beacon", seed=SEED, start_ns=START_NS)
        seen = set()
        for ts_ns, frame in _frames_from_pcap(capture):
            if frame[12:14] != b"\x08\x00":
                continue
            key = (frame[26:34], frame[34:38], ts_ns)
            self.assertNotIn(key, seen, "duplicate timestamp for one direction and 4-tuple")
            seen.add(key)


class TestScenarioDefinitions(unittest.TestCase):
    def test_every_scenario_declares_what_must_and_must_not_fire(self):
        for name, scenario in SCENARIOS.items():
            self.assertIn("rules", scenario.expect, name)
            self.assertIn("absent", scenario.expect, name)

    def test_unknown_scenario_is_rejected(self):
        with self.assertRaises(KeyError):
            build("not-a-scenario")

    def test_frames_are_time_ordered_after_serialisation(self):
        capture, _ = build("mixed", seed=SEED, start_ns=START_NS)
        timestamps = [ts for ts, _frame in _frames_from_pcap(capture)]
        self.assertEqual(timestamps, sorted(timestamps))

    def test_serialise_is_deterministic(self):
        a = serialise([(1_760_000_000_000_000_000, b"\x00" * 20)])
        b = serialise([(1_760_000_000_000_000_000, b"\x00" * 20)])
        self.assertEqual(a, b)


def _frames_from_pcap(payload: bytes):
    """Split a pcap byte string into (ts_ns, frame) pairs."""
    frames = []
    offset = 24
    while offset + 16 <= len(payload):
        ts_sec, ts_usec, incl_len, _orig = struct.unpack_from("<IIII", payload, offset)
        offset += 16
        frames.append((ts_sec * 1_000_000_000 + ts_usec * 1_000, payload[offset : offset + incl_len]))
        offset += incl_len
    return frames


if __name__ == "__main__":
    unittest.main()
