"""Protocol decoding: link layer up to transport, plus a scope classifier.

Everything here is written against the RFC field layouts. The decoder is
defensive by design: a capture is untrusted input, and a malformed header must
produce a packet marked ``truncated`` rather than an exception that kills the
analysis of the other 40 000 packets around it.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field

from .pcap import (
    LINKTYPE_ETHERNET,
    LINKTYPE_IPV4,
    LINKTYPE_IPV6,
    LINKTYPE_LINUX_SLL,
    LINKTYPE_LINUX_SLL2,
    LINKTYPE_NULL,
    LINKTYPE_RAW,
    CapturePacket,
)

__all__ = [
    "Packet",
    "AddressScope",
    "decode",
    "address_scope",
    "tcp_flags_to_str",
]

# Payload is kept only as far as the cleartext-credential rule needs to look.
# Keeping whole payloads would turn a 200 MB capture into gigabytes of heap and
# would mean writing third-party traffic to disk, which nothing here needs.
MAX_PAYLOAD = 512

# The first bytes of the frame itself are kept so an alert can show a real
# hexdump. A bare SYN has no payload, and "here is the packet" is exactly the
# case where the header bytes are the whole story.
RAW_FRAME_BYTES = 128

PROTO_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6",
    132: "SCTP",
}


class AddressScope:
    """Coarse classification of an address, used by the "new external peer" rule.

    This is deliberately a *bogon* classifier, not a subnet calculation. The
    tool does not know your LAN layout, so it treats the reserved and private
    ranges as inside and everything else as outside. That is the honest version
    of the question "is this destination external". It is documented as a
    limitation rather than hidden.
    """

    INTERNAL = "internal"
    EXTERNAL = "external"
    SPECIAL = "special"  # multicast, broadcast, unspecified, link-local


_PRIVATE_V4 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),  # carrier grade NAT
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

_SPECIAL_V4 = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
]

_PRIVATE_V6_NETWORKS = (
    ipaddress.ip_network("fc00::/7"),   # unique local
    ipaddress.ip_network("fec0::/10"),  # deprecated site local, still seen
)


def address_scope(address: str | None) -> str:
    """Return ``internal``, ``external`` or ``special`` for an IP address."""
    if not address:
        return AddressScope.SPECIAL
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return AddressScope.SPECIAL
    if ip.version == 6:
        # Not ``ip.is_private``: Python classifies the documentation prefix
        # 2001:db8::/32 as private, and a test-network address is exactly the
        # kind of stand-in for "somewhere out there" that this must call external.
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            return AddressScope.SPECIAL
        for net in _PRIVATE_V6_NETWORKS:
            if ip in net:
                return AddressScope.INTERNAL
        if ip.ipv4_mapped is not None:
            return address_scope(str(ip.ipv4_mapped))
        return AddressScope.EXTERNAL
    for net in _SPECIAL_V4:
        if ip in net:
            return AddressScope.SPECIAL
    for net in _PRIVATE_V4:
        if ip in net:
            return AddressScope.INTERNAL
    return AddressScope.EXTERNAL


def tcp_flags_to_str(flags: int) -> str:
    """Render a TCP flag byte the way tcpdump does, for log and UI readability."""
    names = (
        (0x01, "F"),
        (0x02, "S"),
        (0x04, "R"),
        (0x08, "P"),
        (0x10, "A"),
        (0x20, "U"),
        (0x40, "E"),
        (0x80, "C"),
    )
    text = "".join(letter for bit, letter in names if flags & bit)
    return text or "."


@dataclass(slots=True)
class Packet:
    """A decoded packet, flattened to the fields the analysis actually uses."""

    index: int
    ts_ns: int
    orig_len: int
    src: str | None = None
    dst: str | None = None
    sport: int | None = None
    dport: int | None = None
    proto: str = "OTHER"
    ip_proto: int | None = None
    ttl: int | None = None
    tcp_flags: int | None = None
    vlan: tuple[int, ...] = ()
    payload: bytes = b""
    payload_len: int = 0
    truncated: bool = False
    parse_error: str | None = None
    extra: dict[str, object] = field(default_factory=dict)
    frame: bytes = b""

    @property
    def src_scope(self) -> str:
        return address_scope(self.src)

    @property
    def dst_scope(self) -> str:
        return address_scope(self.dst)

    @property
    def is_syn_only(self) -> bool:
        return self.tcp_flags is not None and self.tcp_flags & 0x02 and not self.tcp_flags & 0x10

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Packet #{self.index} {self.src}:{self.sport} -> {self.dst}:{self.dport} {self.proto}>"


# ---------------------------------------------------------------------------
# link layer
# ---------------------------------------------------------------------------


def _strip_ethernet(data: bytes) -> tuple[int, bytes, tuple[int, ...]] | None:
    """Return (ethertype, payload, vlan ids) or None when the frame is too short."""
    if len(data) < 14:
        return None
    ethertype = struct.unpack_from("!H", data, 12)[0]
    offset = 14
    vlans: list[int] = []
    # 802.1Q, 802.1ad and the older QinQ tag variants can nest.
    while ethertype in (0x8100, 0x88A8, 0x9100, 0x9200):
        if len(data) < offset + 4:
            break
        tci = struct.unpack_from("!H", data, offset)[0]
        vlans.append(tci & 0x0FFF)
        ethertype = struct.unpack_from("!H", data, offset + 2)[0]
        offset += 4
    return ethertype, data[offset:], tuple(vlans)


def _strip_sll(data: bytes) -> tuple[int, bytes] | None:
    if len(data) < 16:
        return None
    proto = struct.unpack_from("!H", data, 14)[0]
    return proto, data[16:]


def _strip_sll2(data: bytes) -> tuple[int, bytes] | None:
    if len(data) < 20:
        return None
    proto = struct.unpack_from("!H", data, 0)[0]
    return proto, data[20:]


def _strip_null(data: bytes) -> tuple[int, bytes] | None:
    if len(data) < 4:
        return None
    family = struct.unpack_from("=I", data, 0)[0]
    proto = 0x0800 if family == 2 else 0x86DD if family in (10, 24, 28, 30) else 0
    return proto, data[4:]


# ---------------------------------------------------------------------------
# network layer
# ---------------------------------------------------------------------------

_IPV6_EXT_HEADERS = {0, 43, 44, 51, 60, 135}


def _decode_ipv4(data: bytes, packet: Packet) -> int:
    """Fill IP fields.

    Returns the offset where the transport header starts, or ``-1`` when there
    is no transport header to decode (malformed, or a non-first fragment). The
    distinction matters: offset 0 on a fragment would otherwise hand the middle
    of a datagram to the TCP decoder and invent a source port.
    """
    if len(data) < 20:
        packet.truncated = True
        packet.parse_error = "ipv4 header truncated"
        return -1
    version_ihl = data[0]
    if version_ihl >> 4 != 4:
        packet.truncated = True
        packet.parse_error = f"ipv4 version {version_ihl >> 4}"
        return -1
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        packet.truncated = True
        packet.parse_error = "ipv4 header length invalid"
        return -1
    total_len, _ident, frag_flags, ttl, proto = struct.unpack_from("!HHHBB", data, 2)
    packet.src = str(ipaddress.IPv4Address(data[12:16]))
    packet.dst = str(ipaddress.IPv4Address(data[16:20]))
    packet.ttl = ttl
    packet.ip_proto = proto
    packet.proto = PROTO_NAMES.get(proto, f"IP/{proto}")
    available = min(total_len, len(data)) if total_len else len(data)
    frag_offset = frag_flags & 0x1FFF
    packet.extra["ip_id"] = _ident
    packet.extra["fragment"] = frag_offset > 0
    # A non-first fragment has no transport header. Saying so is better than
    # decoding random bytes from the middle of a datagram as a TCP port.
    if frag_offset > 0:
        packet.extra["fragment_offset"] = frag_offset
        return -1
    return ihl if ihl <= available else -1


def _decode_ipv6(data: bytes, packet: Packet) -> int:
    if len(data) < 40:
        packet.truncated = True
        packet.parse_error = "ipv6 header truncated"
        return -1
    if data[0] >> 4 != 6:
        packet.truncated = True
        packet.parse_error = "ipv6 version mismatch"
        return -1
    payload_len = struct.unpack_from("!H", data, 4)[0]
    next_header = data[6]
    packet.src = str(ipaddress.IPv6Address(data[8:24]))
    packet.dst = str(ipaddress.IPv6Address(data[24:40]))
    packet.ttl = data[7]  # hop limit
    packet.ip_proto = next_header
    offset = 40
    # Walk extension headers. The cap stops a crafted chain from looping.
    for _ in range(8):
        if next_header not in _IPV6_EXT_HEADERS:
            break
        if next_header == 44:  # fragment header is fixed at 8 bytes
            if len(data) < offset + 8:
                packet.truncated = True
                return -1
            next_header = data[offset]
            offset += 8
            continue
        if len(data) < offset + 2:
            packet.truncated = True
            return -1
        next_header, ext_len = data[offset], data[offset + 1]
        offset += (ext_len + 1) * 8
    packet.ip_proto = next_header
    packet.proto = PROTO_NAMES.get(next_header, f"IP/{next_header}")
    end = min(40 + payload_len, len(data)) if payload_len else len(data)
    return offset if offset <= end else -1


# ---------------------------------------------------------------------------
# transport layer
# ---------------------------------------------------------------------------


def _decode_tcp(data: bytes, packet: Packet) -> None:
    if len(data) < 20:
        packet.truncated = True
        return
    packet.sport, packet.dport, _seq, _ack, offset_flags = struct.unpack_from("!HHIIH", data, 0)
    header_len = (offset_flags >> 12) * 4
    packet.tcp_flags = offset_flags & 0x01FF
    if header_len < 20 or header_len > len(data):
        packet.truncated = True
        return
    packet.payload_len = len(data) - header_len
    packet.payload = data[header_len : header_len + MAX_PAYLOAD]


def _decode_udp(data: bytes, packet: Packet) -> None:
    if len(data) < 8:
        packet.truncated = True
        return
    packet.sport, packet.dport, udp_len, _checksum = struct.unpack_from("!HHHH", data, 0)
    if udp_len and udp_len >= 8:
        packet.payload_len = min(udp_len - 8, len(data) - 8)
    else:
        packet.payload_len = max(0, len(data) - 8)
    packet.payload = data[8 : 8 + MAX_PAYLOAD]


def _decode_icmp(data: bytes, packet: Packet) -> None:
    if len(data) < 4:
        packet.truncated = True
        return
    packet.extra["icmp_type"] = data[0]
    packet.extra["icmp_code"] = data[1]
    packet.payload_len = max(0, len(data) - 4)


def _decode_arp(data: bytes, packet: Packet) -> None:
    if len(data) < 28:
        packet.truncated = True
        return
    op = struct.unpack_from("!H", data, 6)[0]
    packet.src = str(ipaddress.IPv4Address(data[14:18]))
    packet.dst = str(ipaddress.IPv4Address(data[24:28]))
    packet.extra["arp_op"] = op
    packet.extra["arp_sender_mac"] = ":".join(f"{b:02x}" for b in data[8:14])
    packet.extra["arp_target_mac"] = ":".join(f"{b:02x}" for b in data[18:24])
    packet.payload_len = 0
    packet.proto = "ARP"


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


def decode(capture_packet: CapturePacket) -> Packet:
    """Decode one raw capture record into a :class:`Packet`.

    Never raises for malformed content: the returned packet carries
    ``truncated`` and ``parse_error`` instead.
    """
    packet = Packet(
        index=capture_packet.index,
        ts_ns=capture_packet.ts_ns,
        orig_len=capture_packet.orig_len,
        frame=capture_packet.data[:RAW_FRAME_BYTES],
    )
    data = capture_packet.data
    linktype = capture_packet.linktype

    if linktype == LINKTYPE_ETHERNET:
        stripped = _strip_ethernet(data)
        if stripped is None:
            packet.truncated = True
            packet.parse_error = "ethernet frame too short"
            return packet
        ethertype, payload, vlans = stripped
        packet.vlan = vlans
        if ethertype == 0x0806:
            _decode_arp(payload, packet)
            return packet
        if ethertype not in (0x0800, 0x86DD):
            packet.proto = f"ETH/{ethertype:#06x}"
            packet.payload_len = len(payload)
            return packet
        offset = _decode_ipv4(payload, packet) if ethertype == 0x0800 else _decode_ipv6(payload, packet)
        if offset < 0:
            return packet
        l4 = payload[offset:]
    elif linktype in (LINKTYPE_RAW,):
        if not data:
            packet.truncated = True
            return packet
        if data[0] >> 4 == 4:
            offset = _decode_ipv4(data, packet)
        else:
            offset = _decode_ipv6(data, packet)
        if offset < 0:
            return packet
        l4 = data[offset:]
    elif linktype == LINKTYPE_IPV4:
        offset = _decode_ipv4(data, packet)
        if offset < 0:
            return packet
        l4 = data[offset:]
    elif linktype == LINKTYPE_IPV6:
        offset = _decode_ipv6(data, packet)
        if offset < 0:
            return packet
        l4 = data[offset:]
    elif linktype == LINKTYPE_LINUX_SLL:
        stripped = _strip_sll(data)
        if stripped is None:
            packet.truncated = True
            return packet
        ethertype, payload = stripped
        if ethertype == 0x0806:
            _decode_arp(payload, packet)
            return packet
        if ethertype not in (0x0800, 0x86DD):
            packet.proto = f"SLL/{ethertype:#06x}"
            return packet
        offset = _decode_ipv4(payload, packet) if ethertype == 0x0800 else _decode_ipv6(payload, packet)
        if offset < 0:
            return packet
        l4 = payload[offset:]
    elif linktype == LINKTYPE_LINUX_SLL2:
        stripped = _strip_sll2(data)
        if stripped is None:
            packet.truncated = True
            return packet
        ethertype, payload = stripped
        if ethertype == 0x0806:
            _decode_arp(payload, packet)
            return packet
        if ethertype not in (0x0800, 0x86DD):
            packet.proto = f"SLL2/{ethertype:#06x}"
            return packet
        offset = _decode_ipv4(payload, packet) if ethertype == 0x0800 else _decode_ipv6(payload, packet)
        if offset < 0:
            return packet
        l4 = payload[offset:]
    elif linktype == LINKTYPE_NULL:
        stripped = _strip_null(data)
        if stripped is None:
            packet.truncated = True
            return packet
        ethertype, payload = stripped
        if ethertype not in (0x0800, 0x86DD):
            packet.proto = f"NULL/{ethertype:#06x}"
            return packet
        offset = _decode_ipv4(payload, packet) if ethertype == 0x0800 else _decode_ipv6(payload, packet)
        if offset < 0:
            return packet
        l4 = payload[offset:]
    else:
        packet.proto = f"LINKTYPE/{linktype}"
        packet.parse_error = f"unsupported link type {linktype}"
        packet.payload_len = len(data)
        return packet

    if packet.truncated:
        return packet

    if packet.proto == "TCP":
        _decode_tcp(l4, packet)
    elif packet.proto == "UDP":
        _decode_udp(l4, packet)
    elif packet.proto in ("ICMP", "ICMPv6"):
        _decode_icmp(l4, packet)
    else:
        packet.payload_len = len(l4)
        packet.payload = l4[:MAX_PAYLOAD]
    return packet
