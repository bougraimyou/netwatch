"""Synthetic capture generator.

This module exists because of a rule about the test suite: a detection tool is
only credible if you can show the rule firing on traffic that is known to
contain the thing, and staying silent on traffic that is known not to. Handing
around "a real capture from a customer" would be neither reproducible nor
publishable, so the captures are built here, packet by packet, with correct
checksums, and committed as fixtures.

Every scenario is deterministic for a given seed. ``netwatch demo`` regenerates
exactly the bytes the test suite asserts against.
"""

from __future__ import annotations

import random
import struct
from dataclasses import dataclass, field

__all__ = [
    "SCENARIOS",
    "Scenario",
    "CaptureBuilder",
    "build",
    "write",
]

# ---------------------------------------------------------------------------
# packet construction
# ---------------------------------------------------------------------------


def _mac(text: str) -> bytes:
    return bytes(int(part, 16) for part in text.split(":"))


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ethernet(src: str, dst: str, ethertype: int, payload: bytes) -> bytes:
    return _mac(dst) + _mac(src) + struct.pack("!H", ethertype) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes, *, ttl: int = 64, ident: int = 0) -> bytes:
    src_bytes = bytes(int(part) for part in src.split("."))
    dst_bytes = bytes(int(part) for part in dst.split("."))
    total_len = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        ident & 0xFFFF,
        0x4000,  # don't fragment
        ttl,
        proto,
        0,
        src_bytes,
        dst_bytes,
    )
    checksum = _checksum(header)
    header = header[:10] + struct.pack("!H", checksum) + header[12:]
    return header + payload


def _pseudo_header(src: str, dst: str, proto: int, length: int) -> bytes:
    return (
        bytes(int(part) for part in src.split("."))
        + bytes(int(part) for part in dst.split("."))
        + struct.pack("!BBH", 0, proto, length)
    )


def tcp(
    src: str,
    dst: str,
    sport: int,
    dport: int,
    *,
    flags: int = 0x02,
    seq: int = 1000,
    ack: int = 0,
    payload: bytes = b"",
    window: int = 64240,
) -> bytes:
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, window, 0, 0)
    segment = header + payload
    checksum = _checksum(_pseudo_header(src, dst, 6, len(segment)) + segment)
    segment = segment[:16] + struct.pack("!H", checksum) + segment[18:]
    return ipv4(src, dst, 6, segment)


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    header = struct.pack("!HHHH", sport, dport, length, 0)
    datagram = header + payload
    checksum = _checksum(_pseudo_header(src, dst, 17, len(datagram)) + datagram)
    datagram = datagram[:6] + struct.pack("!H", checksum) + datagram[8:]
    return ipv4(src, dst, 17, datagram)


def icmp_echo(src: str, dst: str, *, request: bool = True) -> bytes:
    body = b"netwatch-demo-payload"
    header = struct.pack("!BBHHH", 8 if request else 0, 0, 0, 1, 1)
    packet = header + body
    checksum = _checksum(packet)
    return ipv4(src, dst, 1, packet[:2] + struct.pack("!H", checksum) + packet[4:])


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        encoded = label.encode("ascii")
        out += bytes([len(encoded)]) + encoded
    return out + b"\x00"


def dns_query(txid: int, name: str, qtype: int = 1) -> bytes:
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    return header + _encode_name(name) + struct.pack("!HH", qtype, 1)


def dns_response(txid: int, name: str, *, rcode: int = 0, address: str | None = None, qtype: int = 1) -> bytes:
    flags = 0x8180 | (rcode & 0xF)
    answers = 1 if address and rcode == 0 else 0
    header = struct.pack("!HHHHHH", txid, flags, 1, answers, 0, 0)
    question = _encode_name(name) + struct.pack("!HH", qtype, 1)
    answer = b""
    if answers:
        answer = (
            b"\xc0\x0c"  # compression pointer back to the question name
            + struct.pack("!HHIH", 1, 1, 60, 4)
            + bytes(int(part) for part in address.split("."))
        )
    return header + question + answer


# ---------------------------------------------------------------------------
# scenario definitions
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Scenario:
    name: str
    description: str
    duration_s: float
    expect: dict[str, object] = field(default_factory=dict)


SCENARIOS: dict[str, Scenario] = {
    "clean": Scenario(
        name="clean",
        description="A quiet office: DNS, web, time sync and internal administration. Nothing planted.",
        duration_s=300,
        expect={"rules": [], "absent": ["port_scan", "dns_anomaly", "beaconing", "cleartext_credentials"], "alerts": 0},
    ),
    "scan": Scenario(
        name="scan",
        description="One workstation sweeps 200 ports on the file server with bare SYNs.",
        duration_s=120,
        expect={"rules": ["port_scan"], "absent": ["beaconing", "cleartext_credentials"], "min_alerts": 1},
    ),
    "dns": Scenario(
        name="dns",
        description="A workstation sends data through generated subdomains, then walks a DGA of dead names.",
        duration_s=180,
        expect={"rules": ["dns_anomaly"], "absent": ["port_scan", "beaconing", "cleartext_credentials"], "min_alerts": 2},
    ),
    "beacon": Scenario(
        name="beacon",
        description="A workstation checks in with one external address every 60 seconds.",
        duration_s=1500,
        expect={"rules": ["beaconing"], "absent": ["port_scan", "cleartext_credentials"], "min_alerts": 1},
    ),
    "cleartext": Scenario(
        name="cleartext",
        description="An FTP login and an HTTP basic-auth request, both in the clear.",
        duration_s=120,
        expect={"rules": ["cleartext_credentials"], "absent": ["port_scan", "beaconing"], "min_alerts": 2},
    ),
    "mixed": Scenario(
        name="mixed",
        description="The clean office, plus a scan, a DNS tunnel, a beacon, a cleartext login and a new external peer.",
        duration_s=1800,
        expect={
            "rules": ["port_scan", "dns_anomaly", "beaconing", "cleartext_credentials", "new_external_peer"],
            "absent": [],
            "min_alerts": 5,
        },
    ),
}


# ---------------------------------------------------------------------------
# builder
# ---------------------------------------------------------------------------

GATEWAY = "10.20.0.1"
GATEWAY_MAC = "02:00:00:00:00:01"
SERVER = "10.20.0.10"
SERVER_MAC = "02:00:00:00:00:10"
WORKSTATIONS = {
    "10.20.0.21": "02:00:00:00:00:21",
    "10.20.0.22": "02:00:00:00:00:22",
    "10.20.0.23": "02:00:00:00:00:23",
}

WEB_SERVER = "93.184.216.34"
BEACON_HOST = "203.0.113.45"
NEW_PEER = "198.51.100.7"


class CaptureBuilder:
    """Collects framed bytes with timestamps, then serialises a pcap."""

    def __init__(self, *, seed: int = 7, start_ns: int | None = None) -> None:
        self.random = random.Random(seed)
        self.frames: list[tuple[int, bytes]] = []
        self.start_ns = start_ns if start_ns is not None else 1_760_000_000_000_000_000
        self._txid = 0x1000

    # -- helpers -------------------------------------------------------

    def at(self, offset_s: float) -> int:
        return self.start_ns + int(offset_s * 1e9)

    def emit(self, offset_s: float, frame: bytes) -> None:
        self.frames.append((self.at(offset_s), frame))

    def _next_txid(self) -> int:
        self._txid = (self._txid + 1) & 0xFFFF
        return self._txid

    def lan(self, src: str, dst: str, l4: bytes, ethertype: int = 0x0800) -> bytes:
        src_mac = WORKSTATIONS.get(src) or (SERVER_MAC if src == SERVER else GATEWAY_MAC)
        dst_mac = WORKSTATIONS.get(dst) or (SERVER_MAC if dst == SERVER else GATEWAY_MAC)
        return ethernet(src_mac, dst_mac, ethertype, l4)

    # -- traffic shapes ------------------------------------------------

    def dns_lookup(self, offset_s: float, client: str, name: str, address: str | None) -> None:
        txid = self._next_txid()
        self.emit(offset_s, self.lan(client, GATEWAY, udp(client, GATEWAY, 51234, 53, dns_query(txid, name))))
        self.emit(
            offset_s + 0.01,
            self.lan(GATEWAY, client, udp(GATEWAY, client, 53, 51234, dns_response(txid, name, address=address))),
        )

    def dns_miss(self, offset_s: float, client: str, name: str) -> None:
        txid = self._next_txid()
        self.emit(offset_s, self.lan(client, GATEWAY, udp(client, GATEWAY, 51234, 53, dns_query(txid, name))))
        self.emit(
            offset_s + 0.01,
            self.lan(
                GATEWAY,
                client,
                udp(GATEWAY, client, 53, 51234, dns_response(txid, name, rcode=3)),
            ),
        )

    def http_get(self, offset_s: float, client: str, host: str, *, path: str = "/", extra_headers: bytes = b"") -> None:
        request = (
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n".encode("ascii")
            + extra_headers
            + b"Accept: */*\r\nConnection: close\r\n\r\n"
        )
        self.emit(offset_s, self.lan(client, GATEWAY, tcp(client, WEB_SERVER, 49812, 80, payload=request)))
        self.emit(
            offset_s + 0.2,
            self.lan(
                GATEWAY,
                client,
                tcp(WEB_SERVER, client, 80, 49812, flags=0x18, ack=1, payload=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
            ),
        )

    def https_session(self, offset_s: float, client: str, host: str) -> None:
        self.emit(offset_s, self.lan(client, GATEWAY, tcp(client, host, 50120, 443, flags=0x02)))
        self.emit(offset_s + 0.02, self.lan(GATEWAY, client, tcp(host, client, 443, 50120, flags=0x12, ack=1)))
        self.emit(offset_s + 0.04, self.lan(client, GATEWAY, tcp(client, host, 50120, 443, flags=0x10, ack=1)))
        self.emit(
            offset_s + 0.06,
            self.lan(client, GATEWAY, tcp(client, host, 50120, 443, flags=0x18, ack=1, payload=b"\x16\x03\x01\x02\x00" + b"\x00" * 64)),
        )

    def ssh_session(self, offset_s: float, client: str) -> None:
        self.emit(offset_s, self.lan(client, SERVER, tcp(client, SERVER, 51000, 22, flags=0x02)))
        self.emit(offset_s + 0.03, self.lan(SERVER, client, tcp(SERVER, client, 22, 51000, flags=0x12, ack=1)))
        self.emit(offset_s + 0.06, self.lan(client, SERVER, tcp(client, SERVER, 51000, 22, flags=0x18, ack=1, payload=b"SSH-2.0-OpenSSH_9.6\r\n")))
        self.emit(offset_s + 0.4, self.lan(client, SERVER, tcp(client, SERVER, 51000, 22, flags=0x18, ack=1, payload=b"\x00" * 96)))

    def ntp_sync(self, offset_s: float, client: str) -> None:
        payload = b"\x1b" + b"\x00" * 47
        self.emit(offset_s, self.lan(client, GATEWAY, udp(client, GATEWAY, 123, 123, payload)))
        self.emit(offset_s + 0.005, self.lan(GATEWAY, client, udp(GATEWAY, client, 123, 123, b"\x1c" + b"\x00" * 47)))

    # -- the clean office ---------------------------------------------

    def baseline_traffic(self, duration_s: float) -> None:
        clients = list(WORKSTATIONS)
        sites = [
            ("www.example.com", WEB_SERVER),
            ("mail.example.com", "93.184.216.35"),
            ("updates.example.org", "198.51.100.20"),
        ]
        # DNS: short names, spread out, no single domain dominating.
        offset = 1.0
        while offset < duration_s - 10:
            client = clients[int(offset) % len(clients)]
            name, address = sites[int(offset) % len(sites)]
            self.dns_lookup(offset, client, name, address)
            offset += self.random.uniform(14, 34)
        # Web, irregular enough that no beacon test can mistake it for a rhythm.
        offset = 5.0
        for _ in range(6):
            client = clients[int(offset) % len(clients)]
            self.http_get(offset, client, "www.example.com")
            offset += self.random.uniform(30, 70)
        offset = 20.0
        for _ in range(4):
            client = clients[int(offset) % len(clients)]
            self.https_session(offset, client, WEB_SERVER)
            offset += self.random.uniform(45, 90)
        # Internal administration and time sync.
        offset = 8.0
        while offset < duration_s - 5:
            client = clients[int(offset) % len(clients)]
            self.ssh_session(offset, client)
            offset += self.random.uniform(35, 75)
        offset = 3.0
        while offset < duration_s - 5:
            self.ntp_sync(offset, GATEWAY)
            offset += 64.0
        # A little ICMP, so the protocol mix is not suspiciously narrow.
        for k in range(4):
            self.emit(30 + k * 40, self.lan(clients[k % len(clients)], GATEWAY, icmp_echo(clients[k % len(clients)], GATEWAY)))

    # -- planted behaviour --------------------------------------------

    def port_scan(self, start_s: float, scanner: str = "10.20.0.23", target: str = SERVER, ports: int = 200) -> None:
        span = 40.0
        for index in range(ports):
            offset = start_s + (span * index / ports)
            self.emit(
                offset,
                self.lan(scanner, target, tcp(scanner, target, 40000 + index, 1 + index, flags=0x02)),
            )

    def dns_tunnel(self, start_s: float, client: str = "10.20.0.22", queries: int = 120) -> None:
        alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
        for index in range(queries):
            label = "".join(self.random.choice(alphabet) for _ in range(30))
            name = f"{label}.data.example.net"
            self.dns_lookup(start_s + index * 0.5, client, name, None)

    def dga_walk(self, start_s: float, client: str = "10.20.0.22", queries: int = 40) -> None:
        # A real DGA does not put random labels under one domain: it invents
        # second-level domains. Each lookup is a different registrable name, so
        # only the NXDOMAIN-flood branch can catch this, not domain grouping.
        alphabet = "abcdefghijklmnopqrstuvwxyz"
        tlds = ("com", "net", "org", "info", "biz")
        for index in range(queries):
            label = "".join(self.random.choice(alphabet) for _ in range(22))
            tld = tlds[index % len(tlds)]
            self.dns_miss(start_s + index * 0.8, client, f"{label}.{tld}")

    def beacon(self, start_s: float, client: str = "10.20.0.21", count: int = 20, interval_s: float = 60.0) -> None:
        for index in range(count):
            jitter = self.random.uniform(-0.4, 0.4)
            offset = start_s + index * interval_s + jitter
            self.emit(offset, self.lan(client, GATEWAY, tcp(client, BEACON_HOST, 52000 + index % 3, 8443, flags=0x02)))
            self.emit(offset + 0.05, self.lan(GATEWAY, client, tcp(BEACON_HOST, client, 8443, 52000 + index % 3, flags=0x18, ack=1, payload=b"\x17\x03\x03\x00\x20" + b"\xaa" * 32)))

    def cleartext_login(self, start_s: float, client: str = "10.20.0.21") -> None:
        ftp_server = "198.51.100.7"
        self.emit(start_s, self.lan(client, GATEWAY, tcp(client, ftp_server, 49700, 21, flags=0x02)))
        self.emit(start_s + 0.05, self.lan(GATEWAY, client, tcp(ftp_server, client, 21, 49700, flags=0x18, ack=1, payload=b"220 FTP server ready\r\n")))
        self.emit(start_s + 0.1, self.lan(client, GATEWAY, tcp(client, ftp_server, 49700, 21, flags=0x18, ack=1, payload=b"USER youcef\r\n")))
        self.emit(start_s + 0.15, self.lan(GATEWAY, client, tcp(ftp_server, client, 21, 49700, flags=0x18, ack=1, payload=b"331 Password required\r\n")))
        self.emit(start_s + 0.2, self.lan(client, GATEWAY, tcp(client, ftp_server, 49700, 21, flags=0x18, ack=1, payload=b"PASS Atias2026!\r\n")))
        self.emit(start_s + 0.25, self.lan(GATEWAY, client, tcp(ftp_server, client, 21, 49700, flags=0x18, ack=1, payload=b"230 Logged in\r\n")))
        # A basic-auth request from the same workstation, different protocol.
        credentials = __import__("base64").b64encode(b"youcef:atias-demo-password")
        self.http_get(
            start_s + 2.0,
            client,
            "intranet.example.net",
            path="/admin",
            extra_headers=b"Authorization: Basic " + credentials + b"\r\n",
        )

    def new_external_peer(self, start_s: float, client: str = "10.20.0.22") -> None:
        for index in range(3):
            offset = start_s + index * 6.0
            self.emit(offset, self.lan(client, GATEWAY, tcp(client, NEW_PEER, 53000 + index, 443, flags=0x02)))
            self.emit(
                offset + 0.05,
                self.lan(
                    GATEWAY,
                    client,
                    tcp(NEW_PEER, client, 443, 53000 + index, flags=0x18, ack=1, payload=b"\x16\x03\x01\x01" + b"\x00" * 256),
                ),
            )


def build(scenario: str, *, seed: int = 7, start_ns: int | None = None) -> tuple[bytes, Scenario]:
    """Return (pcap bytes, scenario) for a named scenario."""
    if scenario not in SCENARIOS:
        raise KeyError(f"unknown scenario {scenario!r}; choose from {', '.join(sorted(SCENARIOS))}")
    definition = SCENARIOS[scenario]
    builder = CaptureBuilder(seed=seed, start_ns=start_ns)

    if scenario in ("clean", "mixed"):
        builder.baseline_traffic(definition.duration_s)

    if scenario == "scan":
        builder.baseline_traffic(definition.duration_s)
        builder.port_scan(20.0)
    elif scenario == "dns":
        builder.baseline_traffic(definition.duration_s)
        builder.dns_tunnel(30.0)
        builder.dga_walk(100.0)
    elif scenario == "beacon":
        builder.baseline_traffic(definition.duration_s)
        builder.beacon(60.0)
    elif scenario == "cleartext":
        builder.baseline_traffic(definition.duration_s)
        builder.cleartext_login(20.0)
    elif scenario == "mixed":
        builder.port_scan(120.0)
        builder.dns_tunnel(300.0)
        builder.dga_walk(400.0)
        builder.beacon(500.0)
        builder.cleartext_login(1000.0)
        builder.new_external_peer(1200.0)

    frames = sorted(builder.frames, key=lambda item: item[0])
    return serialise(frames), definition


def serialise(frames: list[tuple[int, bytes]]) -> bytes:
    """Write frames as a little-endian microsecond pcap."""
    out = bytearray()
    out += struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)  # LINKTYPE_ETHERNET
    for ts_ns, frame in frames:
        seconds, remainder = divmod(ts_ns, 1_000_000_000)
        out += struct.pack("<IIII", seconds, remainder // 1_000, len(frame), len(frame))
        out += frame
    return bytes(out)


def write(path, scenario: str, *, seed: int = 7, start_ns: int | None = None) -> Scenario:
    """Generate a scenario and write it to ``path``."""
    payload, definition = build(scenario, seed=seed, start_ns=start_ns)
    with open(path, "wb") as handle:
        handle.write(payload)
    return definition
