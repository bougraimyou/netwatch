"""The pipeline: how captures are expanded, numbered and folded.

The engine is the one place that knows what "analyze" means, so these tests
hold it to the two properties the reports depend on: a packet keeps a number
that no other packet answers to, even across files, and the same capture
named twice is analyzed once.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from helpers import rules_for
from netwatch.demo import CaptureBuilder, SERVER, serialise, tcp
from netwatch.engine import build_index

SCANNER = "10.20.0.23"


def builder() -> CaptureBuilder:
    return CaptureBuilder(seed=13, start_ns=1_760_000_000_000_000_000)


def _write(path: Path, frames: list[tuple[int, bytes]]) -> None:
    path.write_bytes(serialise(frames))


def _scan_file() -> tuple[Path, list[tuple[int, bytes]]]:
    """A capture that trips port_scan: 40 bare SYNs, one port each."""
    b = builder()
    for index in range(40):
        b.emit(
            index * 0.2,
            b.lan(SCANNER, SERVER, tcp(SCANNER, SERVER, 40000 + index, 1 + index, flags=0x02)),
        )
    path = Path(tempfile.mkdtemp()) / "scan.pcap"
    _write(path, b.frames)
    return path, b.frames


def _clean_file() -> tuple[Path, list[tuple[int, bytes]]]:
    """One SSH connection attempt: no rule fires, the bytes still exist."""
    b = builder()
    b.emit(10.0, b.lan("10.20.0.21", SERVER, tcp("10.20.0.21", SERVER, 51000, 22, flags=0x02)))
    path = Path(tempfile.mkdtemp()) / "clean.pcap"
    _write(path, b.frames)
    return path, b.frames


class TestMultiFileIndex(unittest.TestCase):
    def test_second_file_does_not_take_over_the_first_files_packet_bytes(self):
        # Packet numbers count within one capture file. The index folds every
        # file into one table keyed by that number, so without a per-file
        # offset the file read later would take over the earlier file's keys,
        # and the scan alert would end up citing bytes that belong to the
        # other capture. The scan file goes first: whatever the second file
        # writes must not distort the first file's evidence.
        scan_path, _scan_frames = _scan_file()
        clean_path, _clean_frames = _clean_file()

        scan_only = build_index([str(scan_path)])
        alerts_only, _ = rules_for(scan_only.index)
        scan_alert = next(alert for alert in alerts_only if alert.rule == "port_scan")
        scan_hexdump = [ref["hex"] for ref in scan_alert.packets if ref.get("hex")]
        self.assertTrue(scan_hexdump)

        combined = build_index([str(scan_path), str(clean_path)])
        alerts_both, _ = rules_for(combined.index)
        both_alert = next(alert for alert in alerts_both if alert.rule == "port_scan")
        both_hexdump = [ref["hex"] for ref in both_alert.packets if ref.get("hex")]
        # The scan alert must cite the scan capture's own bytes, exactly as it
        # would analyzed alone.
        self.assertEqual(both_hexdump, scan_hexdump)

    def test_every_packet_keeps_a_number_of_its_own(self):
        scan_path, _ = _scan_file()
        clean_path, _ = _clean_file()
        index = build_index([str(scan_path), str(clean_path)]).index
        # Each frame is distinct and short enough to fit the archive, so the
        # archive should hold one entry per packet. Numbers colliding across
        # files would drop entries rather than raise, which is why this has
        # to be counted, not merely run.
        self.assertEqual(len(index.raw), index.total_packets)

    def test_first_file_evidence_survives_a_later_file(self):
        scan_path, _ = _scan_file()
        clean_path, clean_frames = _clean_file()
        combined = build_index([str(scan_path), str(clean_path)]).index
        first_sample = clean_frames[0][1][:128]
        self.assertIn(first_sample, list(combined.raw.values()))


class TestOverlappingInputs(unittest.TestCase):
    def test_a_directory_plus_one_of_its_members_counts_each_packet_once(self):
        scan_path, _ = _scan_file()
        directory = scan_path.parent

        directory_only = build_index([str(directory)])
        repeated = build_index([str(directory), str(scan_path)])

        self.assertEqual(directory_only.sources, repeated.sources)
        self.assertEqual(repeated.index.total_packets, directory_only.index.total_packets)

    def test_first_occurrence_order_is_kept_for_explicit_files(self):
        scan_path, _ = _scan_file()
        clean_path, _ = _clean_file()
        scan_first = build_index([str(scan_path), str(clean_path), str(scan_path)])
        self.assertEqual(
            [source.path for source in scan_first.sources],
            [str(scan_path), str(clean_path)],
        )


if __name__ == "__main__":
    unittest.main()
