"""Protocol decoding, from the link layer up."""

from __future__ import annotations

import socket
import struct
import unittest

from netwatch.demo import dns_query, ethernet, icmp_echo, ipv4, tcp, udp
from netwatch.packets import (
    LINKTYPE_ETHERNET,
    LINKTYPE_IPV4,
    LINKTYPE_IPV6,
    LINKTYPE_LINUX_SLL,
    LINKTYPE_LINUX_SLL2,
    LINKTYPE_NULL,
    LINKTYPE_RAW,
    Packet,
    address_scope,
    decode,
    tcp_flags_to_str,
)
from netwatch.pcap import CapturePacket

CLIENT_MAC = "02:00:00:00:00:21"
GATEWAY_MAC = "02:00:00:00:00:01"
CLIENT = "10.20.0.21"
SERVER = "10.20.0.10"


def capture(frame: bytes, *, linktype: int = LINKTYPE_ETHERNET, ts_ns: int = 1_600_000_000_000_000_000) -> Packet:
    return decode(
        CapturePacket(index=0, ts_ns=ts_ns, data=frame, orig_len=len(frame), linktype=linktype)
    )


class TestEthernetAndIpv4(unittest.TestCase):
    def test_tcp_over_ethernet(self):
        frame = ethernet(
            CLIENT_MAC, GATEWAY_MAC, 0x0800, tcp(CLIENT, SERVER, 51000, 22, flags=0x18, payload=b"hello")
        )
        packet = capture(frame)
        self.assertEqual(packet.src, CLIENT)
        self.assertEqual(packet.dst, SERVER)
        self.assertEqual(packet.sport, 51000)
        self.assertEqual(packet.dport, 22)
        self.assertEqual(packet.proto, "TCP")
        self.assertEqual(packet.payload, b"hello")
        self.assertEqual(packet.payload_len, 5)
        self.assertFalse(packet.truncated)

    def test_flags_are_decoded(self):
        frame = ethernet(CLIENT_MAC, GATEWAY_MAC, 0x0800, tcp(CLIENT, SERVER, 1, 2, flags=0x12))
        packet = capture(frame)
        self.assertTrue(packet.is_syn_only is False)  # SYN+ACK is not a bare SYN
        self.assertEqual(tcp_flags_to_str(packet.tcp_flags), "SA")
        bare = capture(ethernet(CLIENT_MAC, GATEWAY_MAC, 0x0800, tcp(CLIENT, SERVER, 1, 2, flags=0x02)))
        self.assertTrue(bare.is_syn_only)

    def test_vlan_tags_are_recorded(self):
        inner = tcp(CLIENT, SERVER, 1234, 80)
        vlan = struct.pack("!HH", 0x0064, 0x0800)
        frame = ethernet(CLIENT_MAC, GATEWAY_MAC, 0x8100, vlan + inner)
        packet = capture(frame)
        self.assertEqual(packet.vlan, (100,))
        self.assertEqual(packet.dport, 80)

    def test_double_tagged_frame(self):
        inner = tcp(CLIENT, SERVER, 1234, 443)
        tag = struct.pack("!HH", 0x000A, 0x8100)
        tag2 = struct.pack("!HH", 0x0014, 0x0800)
        frame = ethernet(CLIENT_MAC, GATEWAY_MAC, 0x88A8, tag + tag2 + inner)
        packet = capture(frame)
        self.assertEqual(packet.vlan, (10, 20))
        self.assertEqual(packet.dport, 443)

    def test_udp_payload_and_length(self):
        payload = dns_query(1, "example.com")
        frame = ethernet(CLIENT_MAC, GATEWAY_MAC, 0x0800, udp(CLIENT, "10.20.0.1", 53000, 53, payload))
        packet = capture(frame)
        self.assertEqual(packet.proto, "UDP")
        self.assertEqual(packet.payload_len, len(payload))
        self.assertEqual(packet.payload, payload)

    def test_icmp(self):
        frame = ethernet(CLIENT_MAC, GATEWAY_MAC, 0x0800, icmp_echo(CLIENT, "10.20.0.1"))
        packet = capture(frame)
        self.assertEqual(packet.proto, "ICMP")
        self.assertEqual(packet.extra["icmp_type"], 8)

    def test_non_first_fragment_has_no_transport_header(self):
        # A fragment offset of 100 with the transport header missing must not
        # be decoded as if byte 0 were a source port.
        header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, 40, 1, 0x2000 | 100, 64, 6, 0,
            bytes([10, 20, 0, 21]), bytes([10, 20, 0, 10]),
        )
        frame = ethernet(CLIENT_MAC, GATEWAY_MAC, 0x0800, header + b"\xde\xad" * 10)
        packet = capture(frame)
        self.assertIsNone(packet.sport)
        self.assertTrue(packet.extra["fragment"])
        self.assertFalse(packet.truncated)

    def test_truncated_ethernet_frame(self):
        packet = capture(b"\x00" * 8)
        self.assertTrue(packet.truncated)
        self.assertIn("ethernet", packet.parse_error)

    def test_truncated_ipv4_header(self):
        frame = ethernet(CLIENT_MAC, GATEWAY_MAC, 0x0800, b"\x45\x00\x00")
        packet = capture(frame)
        self.assertTrue(packet.truncated)


class TestIpv6(unittest.TestCase):
    def _frame(self, next_header: int, l4: bytes, extension: bytes = b"") -> bytes:
        src = socket.inet_pton(socket.AF_INET6, "fd00::21")
        dst = socket.inet_pton(socket.AF_INET6, "2001:db8::10")
        payload = extension + l4
        ipv6 = struct.pack("!IHBB", 0x60000000, len(payload), next_header, 64) + src + dst + payload
        return ethernet(CLIENT_MAC, GATEWAY_MAC, 0x86DD, ipv6)

    def test_tcp_over_ipv6(self):
        segment = struct.pack("!HHIIBBHHH", 40000, 443, 1, 0, 5 << 4, 0x02, 8192, 0, 0)
        packet = capture(self._frame(6, segment))
        self.assertEqual(packet.src, "fd00::21")
        self.assertEqual(packet.dst, "2001:db8::10")
        self.assertEqual(packet.proto, "TCP")
        self.assertEqual(packet.dport, 443)

    def test_hop_by_hop_extension_header_is_walked(self):
        segment = struct.pack("!HHIIBBHHH", 40000, 80, 1, 0, 5 << 4, 0x02, 8192, 0, 0)
        extension = bytes([6, 0]) + b"\x00" * 6  # next header = TCP, length 8
        packet = capture(self._frame(0, segment, extension))
        self.assertEqual(packet.proto, "TCP")
        self.assertEqual(packet.dport, 80)


class TestLinkTypes(unittest.TestCase):
    def test_raw_ip(self):
        frame = tcp(CLIENT, SERVER, 1234, 22, payload=b"x")
        packet = capture(frame, linktype=LINKTYPE_RAW)
        self.assertEqual(packet.src, CLIENT)
        self.assertEqual(packet.dport, 22)

    def test_linux_cooked_capture(self):
        inner = tcp(CLIENT, SERVER, 1234, 22)
        header = struct.pack("!HHH", 0, 1, 6) + b"\x00" * 8 + struct.pack("!H", 0x0800)
        packet = capture(header + inner, linktype=LINKTYPE_LINUX_SLL)
        self.assertEqual(packet.dport, 22)

    def test_linux_cooked_capture_v2(self):
        inner = tcp(CLIENT, SERVER, 1234, 22, payload=b"x")
        # SLL2 header, 20 bytes: protocol, reserved, interface index, ARPHRD,
        # packet type, link address length, then the link address itself. The
        # protocol sits at the front, the payload after the fixed fields.
        header = struct.pack("!HHIHBB", 0x0800, 0, 2, 1, 0, 6) + b"\x00" * 8
        packet = capture(header + inner, linktype=LINKTYPE_LINUX_SLL2)
        self.assertEqual(packet.src, CLIENT)
        self.assertEqual(packet.dst, SERVER)
        self.assertEqual(packet.sport, 1234)
        self.assertEqual(packet.dport, 22)
        self.assertEqual(packet.proto, "TCP")
        self.assertEqual(packet.payload, b"x")

    def test_sll2_unknown_protocol_is_labelled_not_guessed(self):
        inner = tcp(CLIENT, SERVER, 1234, 22)
        header = struct.pack("!HHIHBB", 0x1234, 0, 2, 1, 0, 6) + b"\x00" * 8
        packet = capture(header + inner, linktype=LINKTYPE_LINUX_SLL2)
        self.assertEqual(packet.proto, "SLL2/0x1234")
        self.assertIsNone(packet.sport)

    def test_null_loopback_family_is_host_byte_order(self):
        inner = tcp(CLIENT, SERVER, 1234, 22)
        # DLT_NULL stores a 4 byte address-family value in host byte order;
        # 2 is AF_INET on the systems this link type is captured on.
        packet = capture(struct.pack("=I", 2) + inner, linktype=LINKTYPE_NULL)
        self.assertEqual(packet.src, CLIENT)
        self.assertEqual(packet.dst, SERVER)
        self.assertEqual(packet.proto, "TCP")
        self.assertEqual(packet.dport, 22)

    def test_null_ipv6_family_is_recognised(self):
        segment = struct.pack("!HHIIBBHHH", 40000, 22, 1, 0, 5 << 4, 0x02, 8192, 0, 0)
        src = socket.inet_pton(socket.AF_INET6, "fd00::21")
        dst = socket.inet_pton(socket.AF_INET6, "2001:db8::10")
        datagram = struct.pack("!IHBB", 0x60000000, len(segment), 6, 64) + src + dst + segment
        # AF_INET6 is 10 on Linux, 24 and 28 and 30 on the BSDs.
        for family in (10, 24, 28, 30):
            packet = capture(struct.pack("=I", family) + datagram, linktype=LINKTYPE_NULL)
            with self.subTest(family=family):
                self.assertEqual(packet.proto, "TCP")
                self.assertEqual(packet.dport, 22)

    def test_null_unknown_family_is_labelled_not_guessed(self):
        packet = capture(struct.pack("=I", 1) + tcp(CLIENT, SERVER, 1234, 22), linktype=LINKTYPE_NULL)
        self.assertEqual(packet.proto, "NULL/0x0000")
        self.assertIsNone(packet.sport)

    def test_ipv4_linktype_starts_at_the_ip_header(self):
        packet = capture(tcp(CLIENT, SERVER, 1234, 22, payload=b"y"), linktype=LINKTYPE_IPV4)
        self.assertEqual(packet.src, CLIENT)
        self.assertEqual(packet.proto, "TCP")
        self.assertEqual(packet.dport, 22)
        self.assertEqual(packet.payload, b"y")

    def test_ipv6_linktype_starts_at_the_ip_header(self):
        segment = struct.pack("!HHIIBBHHH", 40000, 22, 1, 0, 5 << 4, 0x02, 8192, 0, 0)
        src = socket.inet_pton(socket.AF_INET6, "fd00::21")
        dst = socket.inet_pton(socket.AF_INET6, "2001:db8::10")
        datagram = struct.pack("!IHBB", 0x60000000, len(segment), 6, 64) + src + dst + segment
        packet = capture(datagram, linktype=LINKTYPE_IPV6)
        self.assertEqual(packet.src, "fd00::21")
        self.assertEqual(packet.dst, "2001:db8::10")
        self.assertEqual(packet.proto, "TCP")
        self.assertEqual(packet.dport, 22)
        self.assertTrue(packet.is_syn_only)

    def test_unsupported_link_type_is_reported_not_guessed(self):
        packet = capture(b"\x00" * 32, linktype=999)
        self.assertEqual(packet.proto, "LINKTYPE/999")
        self.assertIn("unsupported link type", packet.parse_error)

    def test_arp(self):
        arp = struct.pack(
            "!HHBBH",
            1,
            0x0800,
            6,
            4,
            1,
        ) + bytes.fromhex("020000000021") + bytes([10, 20, 0, 21]) + b"\x00" * 6 + bytes([10, 20, 0, 1])
        frame = ethernet("ff:ff:ff:ff:ff:ff", CLIENT_MAC, 0x0806, arp)
        packet = capture(frame)
        self.assertEqual(packet.proto, "ARP")
        self.assertEqual(packet.src, "10.20.0.21")
        self.assertEqual(packet.dst, "10.20.0.1")
        self.assertEqual(packet.extra["arp_op"], 1)


class TestAddressScope(unittest.TestCase):
    def test_private_ranges_are_internal(self):
        for address in ("10.0.0.5", "172.16.4.2", "192.168.1.1", "127.0.0.1", "100.64.0.9"):
            self.assertEqual(address_scope(address), "internal", address)

    def test_public_addresses_are_external(self):
        for address in ("93.184.216.34", "203.0.113.45", "198.51.100.7", "8.8.8.8"):
            self.assertEqual(address_scope(address), "external", address)

    def test_multicast_and_unspecified_are_special(self):
        for address in ("224.0.0.1", "255.255.255.255", "0.0.0.0", "ff02::1", "::1"):
            self.assertEqual(address_scope(address), "special", address)

    def test_ipv6_unique_local_is_internal(self):
        self.assertEqual(address_scope("fd00::1"), "internal")
        self.assertEqual(address_scope("2001:db8::1"), "external")

    def test_garbage_is_special(self):
        self.assertEqual(address_scope("not-an-address"), "special")
        self.assertEqual(address_scope(None), "special")


if __name__ == "__main__":
    unittest.main()
