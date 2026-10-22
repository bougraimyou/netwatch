"""Flow and host aggregation.

The rules trust this layer completely, so the aggregation has to be right about
the things rules quietly depend on: which side is the client, when a connection
starts, and who talked to whom.
"""

from __future__ import annotations

import unittest

from netwatch.demo import dns_query, dns_response, ethernet, ipv4, tcp, udp
from netwatch.flows import TrafficIndex
from netwatch.packets import decode
from netwatch.pcap import CapturePacket

CLIENT = "10.20.0.21"
SERVER = "10.20.0.10"
RESOLVER = "10.20.0.1"
CLIENT_MAC = "02:00:00:00:00:21"
SERVER_MAC = "02:00:00:00:00:10"


def feed(index: TrafficIndex, payload: bytes, *, ts_ns: int = 1_600_000_000_000_000_000, ethertype: int = 0x0800, index_no: int = 0) -> None:
    frame = ethernet(CLIENT_MAC, SERVER_MAC, ethertype, payload)
    index.add(
        decode(CapturePacket(index=index_no, ts_ns=ts_ns, data=frame, orig_len=len(frame), linktype=1))
    )


class TestFlowAggregation(unittest.TestCase):
    def test_packets_roll_up_into_one_flow(self):
        index = TrafficIndex()
        for i in range(4):
            feed(index, tcp(CLIENT, SERVER, 51000, 22, flags=0x18, payload=b"x" * 10), ts_ns=1_000_000_000 * (1 + i))

        flow = next(iter(index.flows.values()))
        self.assertEqual(flow.packets, 4)
        self.assertEqual(flow.bytes, 40)
        self.assertEqual(flow.duration_s, 3.0)
        self.assertEqual(index.total_packets, 4)

    def test_connection_starts_on_bare_syn_not_on_every_packet(self):
        index = TrafficIndex()
        base = 1_600_000_000_000_000_000
        # One handshake plus one data packet: still one connection.
        feed(index, tcp(CLIENT, SERVER, 51000, 22, flags=0x02), ts_ns=base)
        feed(index, tcp(CLIENT, SERVER, 51000, 22, flags=0x10, ack=1), ts_ns=base + 1_000_000)
        feed(index, tcp(CLIENT, SERVER, 51000, 22, flags=0x18, ack=1, payload=b"data"), ts_ns=base + 2_000_000)
        flow = next(iter(index.flows.values()))
        self.assertEqual(len(flow.connections), 1)
        self.assertEqual(len(index.events), 1)

    def test_two_sessions_on_the_same_tuple_are_two_connections(self):
        index = TrafficIndex()
        base = 1_600_000_000_000_000_000
        feed(index, tcp(CLIENT, SERVER, 51000, 22, flags=0x02), ts_ns=base)
        feed(index, tcp(CLIENT, SERVER, 51000, 22, flags=0x02), ts_ns=base + 60_000_000_000)
        flow = next(iter(index.flows.values()))
        self.assertEqual(len(flow.connections), 2)
        self.assertEqual(flow.intervals_s(), [60.0])

    def test_directions_are_separate_flows(self):
        index = TrafficIndex()
        base = 1_600_000_000_000_000_000
        feed(index, tcp(CLIENT, SERVER, 51000, 22, flags=0x02), ts_ns=base)
        frame = ethernet(SERVER_MAC, CLIENT_MAC, 0x0800, tcp(SERVER, CLIENT, 22, 51000, flags=0x12, ack=1))
        index.add(decode(CapturePacket(index=1, ts_ns=base, data=frame, orig_len=len(frame), linktype=1)))
        self.assertEqual(len(index.flows), 2)
        client_host = index.hosts[CLIENT]
        self.assertEqual(client_host.peers_out, {SERVER})
        self.assertGreaterEqual(client_host.packets_out, 1)
        self.assertGreaterEqual(client_host.packets_in, 1)


class TestDnsAttribution(unittest.TestCase):
    def test_query_attributes_the_client_to_the_sender(self):
        index = TrafficIndex()
        payload = dns_query(1, "example.com")
        feed(index, udp(CLIENT, RESOLVER, 53000, 53, payload))
        observation = index.dns_observations[0]
        self.assertEqual(observation.client, CLIENT)
        self.assertEqual(observation.server, RESOLVER)
        self.assertFalse(observation.is_response)
        self.assertEqual(index.hosts[CLIENT].dns_queries, 1)

    def test_response_attributes_the_client_to_the_receiver(self):
        index = TrafficIndex()
        payload = dns_response(1, "example.com", address="93.184.216.34")
        feed(index, udp(RESOLVER, CLIENT, 53, 53000, payload))
        observation = index.dns_observations[0]
        self.assertEqual(observation.client, CLIENT)
        self.assertEqual(observation.server, RESOLVER)
        self.assertTrue(observation.is_response)

    def test_malformed_dns_is_counted_not_raised(self):
        index = TrafficIndex()
        feed(index, udp(CLIENT, RESOLVER, 53000, 53, b"\x00\x01\x02"))
        self.assertEqual(index.dns_observations, [])
        self.assertEqual(index.dns_parse_errors, 1)

    def test_top_domains_groups_by_registrable_domain(self):
        index = TrafficIndex()
        for i, name in enumerate(["a.example.com", "b.example.com", "other.example.net"]):
            feed(index, udp(CLIENT, RESOLVER, 53000, 53, dns_query(i, name)), ts_ns=1_600_000_000_000_000_000 + i)
        self.assertEqual(index.top_domains(3)[0], ("example.com", 2))


class TestHostsAndBudget(unittest.TestCase):
    def test_host_bytes_and_peers(self):
        index = TrafficIndex()
        feed(index, tcp(CLIENT, "93.184.216.34", 50000, 443, flags=0x18, payload=b"x" * 100))
        host = index.hosts[CLIENT]
        self.assertEqual(host.bytes_out, 100)
        self.assertEqual(host.external_peers, {"93.184.216.34"})
        self.assertEqual(host.ports_contacted, {443})

    def test_raw_archive_is_bounded(self):
        index = TrafficIndex()
        index.raw_bytes = 32 * 1024 * 1024  # pretend the budget is spent
        feed(index, tcp(CLIENT, SERVER, 51000, 22, flags=0x18, payload=b"secret"))
        self.assertTrue(index.raw_truncated)
        self.assertEqual(index.raw, {})

    def test_cleartext_port_payloads_are_sampled(self):
        index = TrafficIndex()
        feed(index, tcp(CLIENT, SERVER, 51000, 21, flags=0x18, payload=b"USER bob\r\n"), index_no=9)
        flow = next(iter(index.flows.values()))
        self.assertEqual(flow.samples, [b"USER bob\r\n"])
        self.assertEqual(flow.sample_packets, [9])

    def test_payload_on_an_uninteresting_port_is_not_retained(self):
        index = TrafficIndex()
        staged = tcp(CLIENT, SERVER, 51000, 9000, flags=0x18, payload=b"not retained")
        feed(index, staged)
        flow = next(iter(index.flows.values()))
        self.assertEqual(flow.samples, [])
        # But the packet itself is still archived, on its own budget.
        self.assertTrue(index.raw)

    def test_packet_without_transport_ports_is_counted_but_not_a_flow(self):
        index = TrafficIndex()
        frame = ethernet(CLIENT_MAC, SERVER_MAC, 0x0800, ipv4(CLIENT, SERVER, 253, b"\x00" * 8))
        index.add(decode(CapturePacket(index=0, ts_ns=1, data=frame, orig_len=len(frame), linktype=1)))
        self.assertEqual(index.total_packets, 1)
        self.assertEqual(index.flows, {})


if __name__ == "__main__":
    unittest.main()
