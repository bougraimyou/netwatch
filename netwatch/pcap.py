"""Readers and writers for libpcap and pcapng capture files.

This is written directly against the published file formats rather than on top
of a wrapper library. Two reasons, both deliberate:

* the tool runs anywhere Python runs, with nothing to install;
* the parser is itself part of the evidence. A tool that claims to work at the
  packet level should be able to say what a pcap header looks like without
  shelling out to tcpdump.

Every reader here yields packets lazily and refuses to die on a truncated or
malformed record: a capture that was cut off mid-write is common in the wild,
and losing the last packet is not a reason to lose the other 40 000.
"""

from __future__ import annotations

import contextlib
import gzip
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator

__all__ = [
    "PcapError",
    "CapturePacket",
    "LINKTYPE_ETHERNET",
    "LINKTYPE_NULL",
    "LINKTYPE_RAW",
    "LINKTYPE_LINUX_SLL",
    "LINKTYPE_LINUX_SLL2",
    "LINKTYPE_IPV4",
    "LINKTYPE_IPV6",
    "PcapReader",
    "PcapNgReader",
    "PcapWriter",
    "read_capture",
    "is_pcapng",
]

# Link-layer types we understand. Values come from the tcpdump link-type
# registry; anything else is passed through and reported as unsupported rather
# than guessed at.
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

_NS = 1_000_000_000


class PcapError(ValueError):
    """A capture file could not be read.

    The message always names the byte offset or the packet index where the
    reader gave up, because "invalid pcap" on its own is useless when you are
    staring at a 200 MB file.
    """


@dataclass(slots=True)
class CapturePacket:
    """One record from a capture file, still undecoded."""

    index: int
    ts_ns: int
    data: bytes
    orig_len: int
    linktype: int


# ---------------------------------------------------------------------------
# libpcap
# ---------------------------------------------------------------------------

# magic bytes -> (endianness, nanoseconds per fractional unit)
_PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000),           # little endian, microseconds
    b"\xa1\xb2\xc3\xd4": (">", 1_000),           # big endian, microseconds
    b"\x4d\x3c\xb2\xa1": ("<", 1),               # little endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": (">", 1),               # big endian, nanoseconds
}

_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


class PcapReader:
    """Read a classic libpcap file.

    Handles both byte orders and both timestamp resolutions. The global header
    is validated once; after that every record is read with a bounds check, so
    a corrupt length field cannot make the reader allocate wildly.
    """

    __slots__ = ("_fh", "_endian", "_frac_to_ns", "_linktype", "_snaplen", "_index", "_offset")

    def __init__(self, fh: BinaryIO, *, source: str = "<stream>") -> None:
        self._fh = fh
        self._index = 0
        self._offset = 0
        header = fh.read(24)
        if len(header) < 24:
            raise PcapError(f"{source}: file is shorter than the 24 byte pcap header")
        magic = header[:4]
        try:
            self._endian, self._frac_to_ns = _PCAP_MAGIC[magic]
        except KeyError:
            raise PcapError(
                f"{source}: not a pcap file (magic {magic.hex()}); "
                "expected one of d4c3b2a1, a1b2c3d4, 4d3cb2a1, a1b23c4d"
            ) from None
        major, minor = struct.unpack_from(self._endian + "HH", header, 4)
        if major != 2:
            raise PcapError(f"{source}: unsupported pcap version {major}.{minor}")
        (self._snaplen,) = struct.unpack_from(self._endian + "I", header, 16)
        (self._linktype,) = struct.unpack_from(self._endian + "I", header, 20)
        self._linktype &= 0x0FFFFFFF  # upper bits carry FCS metadata
        self._offset = 24

    @property
    def linktype(self) -> int:
        return self._linktype

    @property
    def snaplen(self) -> int:
        return self._snaplen

    def __iter__(self) -> Iterator[CapturePacket]:
        return self

    def __next__(self) -> CapturePacket:
        header = self._fh.read(16)
        if len(header) < 16:
            raise StopIteration
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(self._endian + "IIII", header)
        # A record that claims more bytes than exist means the writer was killed
        # mid-flush. Yield what is there and stop.
        data = self._fh.read(incl_len)
        self._offset += 16 + incl_len
        if len(data) < incl_len:
            if not data:
                raise StopIteration
            raise StopIteration
        packet = CapturePacket(
            index=self._index,
            ts_ns=ts_sec * _NS + ts_frac * self._frac_to_ns,
            data=data,
            orig_len=orig_len,
            linktype=self._linktype,
        )
        self._index += 1
        return packet


# ---------------------------------------------------------------------------
# pcapng
# ---------------------------------------------------------------------------

_BT_SHB = 0x0A0D0D0A
_BT_IDB = 0x00000001
_BT_PB = 0x00000002
_BT_SPB = 0x00000003
_BT_EPB = 0x00000006

# pcapng option codes we care about
_OPT_IF_TSRESOL = 9


def is_pcapng(head: bytes) -> bool:
    return head[:4] == _PCAPNG_MAGIC


def _read_options(blob: bytes, endian: str) -> dict[int, bytes]:
    options: dict[int, bytes] = {}
    offset = 0
    while offset + 4 <= len(blob):
        code, length = struct.unpack_from(endian + "HH", blob, offset)
        offset += 4
        if code == 0:  # opt_endofopt
            break
        value = blob[offset : offset + length]
        options.setdefault(code, value)
        offset += length + (-length % 4)
    return options


class PcapNgReader:
    """Read a pcapng file.

    Supports the blocks that actually carry packets (Enhanced Packet Block and
    Simple Packet Block) plus the section and interface descriptions needed to
    interpret them. Unknown block types are skipped by their declared length,
    which is the whole point of the format.
    """

    __slots__ = ("_fh", "_endian", "_ifaces", "_packets", "_index", "_source")

    def __init__(self, fh: BinaryIO, *, source: str = "<stream>") -> None:
        self._fh = fh
        self._endian = "<"
        self._ifaces: list[tuple[int, int]] = []  # (linktype, ns per fractional unit)
        self._index = 0
        self._source = source
        self._packets = self._parse()

    @property
    def linktype(self) -> int:
        if not self._ifaces:
            return 0
        return self._ifaces[0][0]

    def _parse(self) -> list[CapturePacket]:
        packets: list[CapturePacket] = []
        fh = self._fh
        first = True
        while True:
            head = fh.read(8)
            if len(head) < 8:
                break
            if first:
                if head[:4] != _PCAPNG_MAGIC:
                    raise PcapError(f"{self._source}: not a pcapng file")
                first = False
            block_type = struct.unpack(self._endian + "I", head[:4])[0]
            (total_len,) = struct.unpack(self._endian + "I", head[4:8])
            if block_type == _BT_SHB:
                # Section Header Block re-declares the byte order.
                bom = fh.read(4)
                if bom == b"\x4d\x3c\x2b\x1a":
                    self._endian = "<"
                elif bom == b"\x1a\x2b\x3c\x4d":
                    self._endian = ">"
                else:
                    raise PcapError(f"{self._source}: bad pcapng byte-order magic {bom.hex()}")
                (total_len,) = struct.unpack(self._endian + "I", head[4:8])
                rest = fh.read(total_len - 12)
                if len(rest) < total_len - 12:
                    raise PcapError(f"{self._source}: truncated section header block")
                self._ifaces = []
                continue
            if total_len < 12:
                raise PcapError(f"{self._source}: pcapng block length {total_len} is impossible")
            body = fh.read(total_len - 12)
            trailer = fh.read(4)
            if len(body) < total_len - 12 or len(trailer) < 4:
                break  # capture cut short mid-block; keep what we already have
            if block_type == _BT_IDB:
                linktype, _reserved, _snaplen = struct.unpack_from(self._endian + "HHI", body, 0)
                opts = _read_options(body[8:], self._endian)
                frac = 1_000  # default: microseconds -> ns
                raw = opts.get(_OPT_IF_TSRESOL)
                if raw:
                    (resolution,) = struct.unpack("B", raw[:1])
                    if resolution & 0x80:
                        exponent = resolution & 0x7F
                        frac = max(1, _NS // (2**exponent))
                    else:
                        frac = max(1, _NS // (10**resolution))
                self._ifaces.append((linktype, frac))
            elif block_type == _BT_EPB:
                iface_id, ts_high, ts_low, caplen, origlen = struct.unpack_from(
                    self._endian + "IIIII", body, 0
                )
                data = body[20 : 20 + caplen]
                frac = self._ifaces[iface_id][1] if iface_id < len(self._ifaces) else 1_000
                linktype = self._ifaces[iface_id][0] if iface_id < len(self._ifaces) else 0
                ts_ns = (ts_high << 32 | ts_low) * frac
                packets.append(
                    CapturePacket(
                        index=len(packets),
                        ts_ns=ts_ns,
                        data=data,
                        orig_len=origlen,
                        linktype=linktype,
                    )
                )
            elif block_type == _BT_SPB:
                if not self._ifaces:
                    raise PcapError(f"{self._source}: packet block before any interface description")
                (origlen,) = struct.unpack_from(self._endian + "I", body, 0)
                linktype, frac = self._ifaces[0]
                snaplen = origlen if origlen else len(body) - 4
                data = body[4 : 4 + min(snaplen, len(body) - 4)]
                packets.append(
                    CapturePacket(
                        index=len(packets),
                        ts_ns=0,  # SPB carries no timestamp by design
                        data=data,
                        orig_len=origlen,
                        linktype=linktype,
                    )
                )
            elif block_type == _BT_PB:
                iface_id, _drops, ts_high, ts_low, caplen, origlen = struct.unpack_from(
                    self._endian + "HHIIII", body, 0
                )
                frac = self._ifaces[iface_id][1] if iface_id < len(self._ifaces) else 1_000
                linktype = self._ifaces[iface_id][0] if iface_id < len(self._ifaces) else 0
                packets.append(
                    CapturePacket(
                        index=len(packets),
                        ts_ns=(ts_high << 32 | ts_low) * frac,
                        data=body[20 : 20 + caplen],
                        orig_len=origlen,
                        linktype=linktype,
                    )
                )
            # every other block type is skipped by its length, per the spec
        return packets

    def __iter__(self) -> Iterator[CapturePacket]:
        return iter(self._packets)

    def __next__(self) -> CapturePacket:
        if self._index >= len(self._packets):
            raise StopIteration
        packet = self._packets[self._index]
        self._index += 1
        return packet


# ---------------------------------------------------------------------------
# writer
# ---------------------------------------------------------------------------


class PcapWriter:
    """Write a classic libpcap file.

    Used by ``netwatch collect`` for live capture and by the test suite to
    build capture fixtures byte by byte. Round-tripping through the reader is
    itself a test.
    """

    def __init__(self, fh: BinaryIO, *, linktype: int = LINKTYPE_ETHERNET, snaplen: int = 262144) -> None:
        self._fh = fh
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype))

    def write(self, ts_ns: int, data: bytes, orig_len: int | None = None) -> None:
        ts_sec, rem = divmod(ts_ns, _NS)
        ts_usec = rem // 1_000
        self._fh.write(
            struct.pack("<IIII", ts_sec, ts_usec, len(data), orig_len if orig_len is not None else len(data))
        )
        self._fh.write(data)

    def close(self) -> None:
        self._fh.flush()


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _open_capture(path: Path):
    """Open a capture, transparently decompressing .gz, and always close it."""
    raw = path.open("rb")
    try:
        if path.suffix == ".gz":
            with gzip.GzipFile(fileobj=raw, mode="rb") as decompressed:
                yield decompressed
        else:
            yield raw
    finally:
        raw.close()


def read_capture(path: str | Path) -> Iterator[CapturePacket]:
    """Yield packets from a pcap or pcapng file, gzip accepted.

    The format is detected from the magic bytes, not the extension, because
    captures are routinely saved with the wrong one. The file handle is closed
    when the iterator is exhausted or abandoned, so a caller that stops early
    does not leak a descriptor.
    """
    path = Path(path)
    if path.is_dir():
        raise IsADirectoryError(f"{path} is a directory, not a capture file")
    with _open_capture(path) as fh:
        try:
            head = fh.read(4)
            fh.seek(0)
        except (OSError, ValueError):
            raise PcapError(f"{path}: capture is not seekable") from None
        if head == _PCAPNG_MAGIC:
            yield from PcapNgReader(fh, source=str(path))
        else:
            yield from PcapReader(fh, source=str(path))
