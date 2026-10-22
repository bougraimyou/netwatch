"""Traffic aggregation: flows, hosts, DNS observations and connection events.

The rules never look at raw packets. They look at this index, which is the one
place that knows how to fold packets into something with a question attached
("who talked to whom, how often, and how regularly").
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from . import dns
from .packets import Packet, address_scope

__all__ = [
    "Flow",
    "Host",
    "ConnectionEvent",
    "TrafficIndex",
    "CLEARTEXT_PORTS",
]

# Ports whose payload is worth keeping a sample of: the cleartext-credential
# rule reads these, and nothing else needs packet bodies.
CLEARTEXT_PORTS = frozenset({21, 23, 25, 80, 110, 143, 587, 8000, 8080, 8888})

# Bounds. A capture is untrusted input and a 2 GB pcap must not become a 20 GB
# process. When a bound is hit the index records that it truncated, so a rule
# can decline to make a claim it cannot support.
MAX_CONNECTION_TIMESTAMPS = 4096
MAX_PAYLOAD_SAMPLES = 12
MAX_EVENTS_PER_HOST = 50_000

# Alerts are supposed to be auditable: "here is the packet that made me say
# this". Keeping the raw bytes of every packet would defeat the point of
# streaming a capture, so the archive holds the first 128 bytes of each packet
# until a fixed memory budget runs out. Past that, alerts still carry the
# decoded fields and say plainly that the bytes were not retained.
RAW_SAMPLE_BYTES = 128
RAW_BUDGET_BYTES = 32 * 1024 * 1024


@dataclass(slots=True)
class Flow:
    """One directional 5-tuple."""

    src: str
    sport: int
    dst: str
    dport: int
    proto: str
    packets: int = 0
    bytes: int = 0
    wire_bytes: int = 0
    first_ns: int = 0
    last_ns: int = 0
    connections: list[int] = field(default_factory=list)
    syn: int = 0
    ack: int = 0
    rst: int = 0
    fin: int = 0
    samples: list[bytes] = field(default_factory=list)
    sample_packets: list[int] = field(default_factory=list)
    truncated: bool = False

    @property
    def key(self) -> tuple[str, int, str, int, str]:
        return (self.src, self.sport, self.dst, self.dport, self.proto)

    @property
    def duration_s(self) -> float:
        return (self.last_ns - self.first_ns) / 1e9

    def intervals_s(self) -> list[float]:
        """Seconds between consecutive connection attempts."""
        if len(self.connections) < 2:
            return []
        return [(b - a) / 1e9 for a, b in zip(self.connections, self.connections[1:])]


@dataclass(slots=True)
class Host:
    """Per-address behaviour."""

    address: str
    packets_out: int = 0
    packets_in: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    first_ns: int | None = None
    last_ns: int | None = None
    peers_out: set[str] = field(default_factory=set)
    ports_contacted: set[int] = field(default_factory=set)
    protocols: Counter = field(default_factory=Counter)
    dns_queries: int = 0

    @property
    def scope(self) -> str:
        return address_scope(self.address)

    @property
    def external_peers(self) -> set[str]:
        return {peer for peer in self.peers_out if address_scope(peer) == "external"}

    def observe(self, packet: Packet, outbound: bool) -> None:
        timestamp = packet.ts_ns
        if self.first_ns is None or timestamp < self.first_ns:
            self.first_ns = timestamp
        if self.last_ns is None or timestamp > self.last_ns:
            self.last_ns = timestamp
        if outbound:
            self.packets_out += 1
            self.bytes_out += packet.payload_len
            self.protocols[packet.proto] += 1
            if packet.dst:
                self.peers_out.add(packet.dst)
            if packet.dport is not None:
                self.ports_contacted.add(packet.dport)
        else:
            self.packets_in += 1
            self.bytes_in += packet.payload_len
            self.protocols[packet.proto] += 1


@dataclass(slots=True)
class ConnectionEvent:
    """A connection attempt, kept in time order for the scanning rules."""

    ts_ns: int
    src: str
    dst: str
    dport: int
    proto: str
    syn_only: bool
    packet_index: int = -1
    answered: bool = False


@dataclass(slots=True)
class DnsObservation:
    ts_ns: int
    client: str
    server: str
    name: str
    qtype: int
    is_response: bool
    rcode: int
    answer_count: int


class TrafficIndex:
    """Fold decoded packets into flows, hosts and observations."""

    __slots__ = (
        "flows",
        "hosts",
        "events",
        "dns_observations",
        "protocol_counts",
        "total_packets",
        "total_wire_bytes",
        "total_payload_bytes",
        "start_ns",
        "end_ns",
        "truncated_packets",
        "parse_errors",
        "vlans",
        "events_truncated",
        "dns_parse_errors",
        "raw",
        "raw_bytes",
        "raw_truncated",
    )

    def __init__(self) -> None:
        self.flows: dict[tuple[str, int, str, int, str], Flow] = {}
        self.hosts: dict[str, Host] = {}
        self.events: list[ConnectionEvent] = []
        self.dns_observations: list[DnsObservation] = []
        self.protocol_counts: Counter = Counter()
        self.total_packets = 0
        self.total_wire_bytes = 0
        self.total_payload_bytes = 0
        self.start_ns: int | None = None
        self.end_ns: int | None = None
        self.truncated_packets = 0
        self.parse_errors = 0
        self.vlans: set[int] = set()
        self.events_truncated = False
        self.dns_parse_errors = 0
        self.raw: dict[int, bytes] = {}
        self.raw_bytes = 0
        self.raw_truncated = False

    # -- ingestion ---------------------------------------------------------

    def add(self, packet: Packet) -> None:
        self.total_packets += 1
        self.total_wire_bytes += packet.orig_len
        self.total_payload_bytes += packet.payload_len
        if packet.truncated:
            self.truncated_packets += 1
        if packet.parse_error:
            self.parse_errors += 1
        if self.raw_bytes < RAW_BUDGET_BYTES:
            sample = packet.frame[:RAW_SAMPLE_BYTES] if packet.frame else b""
            if sample:
                self.raw[packet.index] = sample
                self.raw_bytes += len(sample)
        elif not self.raw_truncated:
            self.raw_truncated = True
        if packet.ts_ns:
            if self.start_ns is None or packet.ts_ns < self.start_ns:
                self.start_ns = packet.ts_ns
            if self.end_ns is None or packet.ts_ns > self.end_ns:
                self.end_ns = packet.ts_ns
        if packet.vlan:
            self.vlans.update(packet.vlan)
        if not packet.src or not packet.dst:
            return

        self.protocol_counts[packet.proto] += 1

        src_host = self.hosts.get(packet.src)
        if src_host is None:
            src_host = self.hosts[packet.src] = Host(packet.src)
        src_host.observe(packet, outbound=True)

        dst_host = self.hosts.get(packet.dst)
        if dst_host is None:
            dst_host = self.hosts[packet.dst] = Host(packet.dst)
        dst_host.observe(packet, outbound=False)

        if packet.sport is None or packet.dport is None:
            return

        key = (packet.src, packet.sport, packet.dst, packet.dport, packet.proto)
        flow = self.flows.get(key)
        if flow is None:
            flow = self.flows[key] = Flow(
                src=packet.src,
                sport=packet.sport,
                dst=packet.dst,
                dport=packet.dport,
                proto=packet.proto,
                first_ns=packet.ts_ns,
            )
        flow.packets += 1
        flow.bytes += packet.payload_len
        flow.wire_bytes += packet.orig_len
        flow.last_ns = packet.ts_ns
        if packet.tcp_flags is not None:
            if packet.tcp_flags & 0x02:
                flow.syn += 1
            if packet.tcp_flags & 0x10:
                flow.ack += 1
            if packet.tcp_flags & 0x04:
                flow.rst += 1
            if packet.tcp_flags & 0x01:
                flow.fin += 1
        if packet.payload and packet.dport in CLEARTEXT_PORTS:
            if len(flow.samples) < MAX_PAYLOAD_SAMPLES:
                flow.samples.append(packet.payload)
                flow.sample_packets.append(packet.index)
            else:
                flow.truncated = True

        # A connection starts on a SYN without ACK, or on the first packet of a
        # UDP exchange. Keeping these separate from packet counts is what makes
        # beacon detection possible: a beacon is 40 connections, not 40 packets.
        starts_connection = False
        if packet.proto == "TCP":
            if packet.is_syn_only:
                starts_connection = True
        else:
            starts_connection = flow.packets == 1
        if starts_connection:
            if len(flow.connections) < MAX_CONNECTION_TIMESTAMPS:
                flow.connections.append(packet.ts_ns)
            else:
                flow.truncated = True
            if len(self.events) < MAX_EVENTS_PER_HOST * 4:
                self.events.append(
                    ConnectionEvent(
                        ts_ns=packet.ts_ns,
                        src=packet.src,
                        dst=packet.dst,
                        dport=packet.dport,
                        proto=packet.proto,
                        syn_only=packet.is_syn_only,
                        packet_index=packet.index,
                    )
                )
            else:
                self.events_truncated = True

        if packet.dport == 53 or packet.sport == 53:
            self._observe_dns(packet)

    def _observe_dns(self, packet: Packet) -> None:
        payload = packet.payload
        if not payload:
            return
        try:
            message = dns.parse_tcp(payload) if packet.proto == "TCP" else dns.parse(payload)
        except dns.DnsError:
            self.dns_parse_errors += 1
            return
        if not message.questions:
            return
        # The client is whoever asked; on a response the roles are reversed.
        client, server = (packet.src, packet.dst) if not message.is_response else (packet.dst, packet.src)
        observation = DnsObservation(
            ts_ns=packet.ts_ns,
            client=client,
            server=server,
            name=message.qname,
            qtype=message.qtype,
            is_response=message.is_response,
            rcode=message.rcode,
            answer_count=message.answer_count,
        )
        self.dns_observations.append(observation)
        if not message.is_response:
            host = self.hosts.get(client)
            if host is not None:
                host.dns_queries += 1

    # -- summaries ---------------------------------------------------------

    @property
    def duration_s(self) -> float:
        if self.start_ns is None or self.end_ns is None:
            return 0.0
        return (self.end_ns - self.start_ns) / 1e9

    def top_flows(self, limit: int = 10) -> list[Flow]:
        return sorted(self.flows.values(), key=lambda f: f.bytes, reverse=True)[:limit]

    def top_hosts(self, limit: int = 10) -> list[Host]:
        return sorted(
            self.hosts.values(),
            key=lambda h: h.bytes_out + h.bytes_in,
            reverse=True,
        )[:limit]

    def top_domains(self, limit: int = 10) -> list[tuple[str, int]]:
        counter: Counter = Counter()
        for observation in self.dns_observations:
            if not observation.is_response and observation.name:
                counter[dns.base_domain(observation.name)] += 1
        return counter.most_common(limit)

    def internal_hosts(self) -> list[Host]:
        return [host for host in self.hosts.values() if host.scope == "internal"]
