"""Capture format readers and writer.

These tests build pcap and pcapng byte strings by hand rather than round-tripping
only through the writer, because a reader tested exclusively against its own
writer proves nothing about the format, only about the pair.
"""

from __future__ import annotations

import gzip
import io
import struct
import tempfile
import unittest
from pathlib import Path

from helpers import pcap_bytes, pcapng_block, pcapng_epb, pcapng_interface, pcapng_section
from netwatch.pcap import (
    PcapError,
    PcapReader,
    PcapWriter,
    is_pcapng,
    read_capture,
)

FRAME = b"\x00" * 20


class TestPcapReader(unittest.TestCase):
    def _read(self, blob: bytes) -> list:
        return list(PcapReader(io.BytesIO(blob), source="test.pcap"))

    def test_little_endian_microseconds(self):
        blob = pcap_bytes([(1_600_000_000_123_456_000, FRAME)], endian="<")
        packets = self._read(blob)
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0].ts_ns, 1_600_000_000_123_456_000)
        self.assertEqual(packets[0].data, FRAME)
        self.assertEqual(packets[0].linktype, 1)

    def test_big_endian_microseconds(self):
        blob = pcap_bytes([(1_600_000_000_999_000_000, FRAME)], endian=">")
        packets = self._read(blob)
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0].ts_ns, 1_600_000_000_999_000_000)

    def test_nanosecond_resolution(self):
        # A nanosecond pcap stores 123456789 ns; a microsecond reader would
        # report 123456000. This is the mistake the magic check exists to stop.
        blob = pcap_bytes([(1_600_000_000_123_456_789, FRAME)], endian="<", nsec=True)
        packets = self._read(blob)
        self.assertEqual(packets[0].ts_ns, 1_600_000_000_123_456_789)

    def test_multiple_records_keep_order_and_indices(self):
        records = [(1_600_000_000_000_000_000 + i * 1_000_000_000, FRAME) for i in range(5)]
        packets = self._read(pcap_bytes(records))
        self.assertEqual([p.index for p in packets], [0, 1, 2, 3, 4])
        self.assertEqual([p.ts_ns for p in packets], [ts for ts, _ in records])

    def test_truncated_final_record_keeps_earlier_packets(self):
        blob = pcap_bytes([(1_600_000_000_000_000_000, FRAME)])
        # Append a record header that promises more bytes than follow.
        blob += struct.pack("<IIII", 1_600_000_001, 0, 100, 100) + b"short"
        packets = self._read(blob)
        self.assertEqual(len(packets), 1)

    def test_short_file_is_rejected(self):
        with self.assertRaises(PcapError):
            self._read(b"\xd4\xc3\xb2\xa1" + b"\x00" * 4)

    def test_bad_magic_is_rejected_with_the_bytes_in_the_message(self):
        with self.assertRaises(PcapError) as caught:
            self._read(b"NOTPCAP!" + b"\x00" * 64)
        self.assertIn("not a pcap", str(caught.exception))

    def test_wrong_version_is_rejected(self):
        blob = bytearray(pcap_bytes([(1, FRAME)]))
        struct.pack_into("<H", blob, 4, 3)
        with self.assertRaises(PcapError) as caught:
            self._read(bytes(blob))
        self.assertIn("unsupported pcap version", str(caught.exception))

    def test_fcs_bits_are_masked_off_the_link_type(self):
        blob = pcap_bytes([(1, FRAME)], linktype=1 | 0x10000000)
        packets = self._read(blob)
        self.assertEqual(packets[0].linktype, 1)


class TestPcapWriter(unittest.TestCase):
    def test_round_trip(self):
        buffer = io.BytesIO()
        writer = PcapWriter(buffer)
        timestamps = [1_600_000_000_000_000_000, 1_600_000_000_500_000_000]
        for ts in timestamps:
            writer.write(ts, FRAME)
        writer.close()

        packets = list(PcapReader(io.BytesIO(buffer.getvalue())))
        self.assertEqual([p.ts_ns for p in packets], timestamps)
        self.assertEqual([p.data for p in packets], [FRAME, FRAME])

    def test_writer_truncates_sub_microsecond_precision_predictably(self):
        buffer = io.BytesIO()
        writer = PcapWriter(buffer)
        writer.write(1_600_000_000_123_456_789, FRAME)
        writer.close()
        packet = next(iter(PcapReader(io.BytesIO(buffer.getvalue()))))
        self.assertEqual(packet.ts_ns, 1_600_000_000_123_456_000)


class TestPcapNgReader(unittest.TestCase):
    def test_section_interface_and_enhanced_packet(self):
        blob = (
            pcapng_section()
            + pcapng_interface()
            + pcapng_epb(FRAME, 1_600_000_000_123_456_000)
        )
        packets = list(read_capture(_write_temp(blob, ".pcapng")))
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0].ts_ns, 1_600_000_000_123_456_000)
        self.assertEqual(packets[0].data, FRAME)
        self.assertEqual(packets[0].linktype, 1)

    def test_nanosecond_timestamp_resolution_option(self):
        blob = (
            pcapng_section()
            + pcapng_interface(tsresol=9)
            + pcapng_epb(FRAME, 1_600_000_000_123_456_789, tsresol=9)
        )
        packets = list(read_capture(_write_temp(blob, ".pcapng")))
        self.assertEqual(packets[0].ts_ns, 1_600_000_000_123_456_789)

    def test_big_endian_section(self):
        blob = (
            pcapng_section(endian=">")
            + pcapng_interface(endian=">")
            + pcapng_epb(FRAME, 1_600_000_000_000_000_000, endian=">")
        )
        packets = list(read_capture(_write_temp(blob, ".pcapng")))
        self.assertEqual(packets[0].ts_ns, 1_600_000_000_000_000_000)

    def test_simple_packet_block_has_no_timestamp(self):
        body = struct.pack("<I", len(FRAME)) + FRAME
        blob = pcapng_section() + pcapng_interface() + pcapng_block(3, body)
        packets = list(read_capture(_write_temp(blob, ".pcapng")))
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0].ts_ns, 0)

    def test_unknown_block_is_skipped_by_its_length(self):
        blob = (
            pcapng_section()
            + pcapng_block(0x0BAD, b"ignore me please")
            + pcapng_interface()
            + pcapng_epb(FRAME, 1_600_000_000_000_000_000)
        )
        packets = list(read_capture(_write_temp(blob, ".pcapng")))
        self.assertEqual(len(packets), 1)

    def test_bad_byte_order_magic_is_rejected(self):
        header = struct.pack("<II", 0x0A0D0D0A, 28)
        body = b"\xde\xad\xbe\xef" + b"\x00" * 16
        blob = header + body + struct.pack("<I", 28)
        with self.assertRaises(PcapError):
            list(read_capture(_write_temp(blob, ".pcapng")))


class TestDetection(unittest.TestCase):
    def test_is_pcapng(self):
        self.assertTrue(is_pcapng(b"\x0a\x0d\x0d\x0a\x1c\x00\x00\x00"))
        self.assertFalse(is_pcapng(b"\xd4\xc3\xb2\xa1"))

    def test_gzip_is_transparent(self):
        blob = pcap_bytes([(1_600_000_000_000_000_000, FRAME)])
        path = Path(tempfile.mkdtemp()) / "capture.pcap.gz"
        path.write_bytes(gzip.compress(blob))
        packets = list(read_capture(path))
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0].ts_ns, 1_600_000_000_000_000_000)

    def test_directory_is_rejected(self):
        with self.assertRaises(IsADirectoryError):
            list(read_capture(tempfile.mkdtemp()))

    def test_extension_does_not_decide_the_format(self):
        # Captures are routinely saved with the wrong suffix; the magic bytes
        # are the only reliable signal.
        blob = (
            pcapng_section()
            + pcapng_interface()
            + pcapng_epb(FRAME, 1_600_000_000_000_000_000)
        )
        packets = list(read_capture(_write_temp(blob, ".pcap")))
        self.assertEqual(len(packets), 1)


def _write_temp(blob: bytes, suffix: str) -> Path:
    directory = Path(tempfile.mkdtemp())
    path = directory / f"capture{suffix}"
    path.write_bytes(blob)
    return path


if __name__ == "__main__":
    unittest.main()
