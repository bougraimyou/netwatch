"""A minimal DNS decoder.

Enough of RFC 1035 to answer the questions the analysis asks: who looked up
what, did the answer exist, and does the name look generated rather than typed.
Answers are followed through compression pointers, because a decoder that
ignores them reports garbage on the second record of every real response.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field

__all__ = [
    "DnsError",
    "DnsQuestion",
    "DnsMessage",
    "parse",
    "parse_tcp",
    "shannon_entropy",
    "base_domain",
    "is_ip_literal",
    "QTYPE_NAMES",
]

QTYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
    43: "DS",
    46: "RRSIG",
    48: "DNSKEY",
    65: "HTTPS",
    255: "ANY",
}

RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

# Registrable-domain approximation. A full public suffix list is several
# thousand entries and a network fetch; this covers the suffixes that actually
# appear in the captures this tool targets, and falls back to "last two labels"
# otherwise. The limitation is stated in the README rather than hidden.
_TWO_LEVEL = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au",
    "co.jp", "or.jp", "ne.jp", "ac.jp",
    "co.nz", "co.za", "co.in", "co.il", "co.kr", "co.id",
    "com.br", "com.mx", "com.ar", "com.tr", "com.sa", "com.eg", "com.qa",
    "com.dz", "net.dz", "org.dz", "edu.dz", "gov.dz", "asso.dz", "art.dz",
    "press.dz", "tm.dz", "pol.dz", "mil.dz",
    "com.tn", "com.ma", "com.jo", "com.lb", "com.kw", "com.om", "com.bh",
    "co.ma", "net.ma", "org.ma", "ac.ma", "gov.ma",
    "com.sg", "com.hk", "com.tw", "com.cn", "com.my", "com.ph", "com.vn",
    "co.th", "in.th", "or.th", "ac.th", "go.th",
    "com.pk", "com.bd", "com.np", "com.lk",
    "com.ua", "com.ru", "com.pl", "com.pt", "com.es", "com.gr", "com.cy",
    "co.at", "or.at", "ac.at", "gv.at",
}


class DnsError(ValueError):
    """The payload is not a DNS message this decoder can read."""


@dataclass(slots=True)
class DnsQuestion:
    name: str
    qtype: int
    qclass: int = 1

    @property
    def type_name(self) -> str:
        return QTYPE_NAMES.get(self.qtype, str(self.qtype))


@dataclass(slots=True)
class DnsMessage:
    txid: int
    flags: int
    questions: list[DnsQuestion] = field(default_factory=list)
    answer_count: int = 0
    authority_count: int = 0
    additional_count: int = 0

    @property
    def is_response(self) -> bool:
        return bool(self.flags & 0x8000)

    @property
    def rcode(self) -> int:
        return self.flags & 0x000F

    @property
    def rcode_name(self) -> str:
        return RCODE_NAMES.get(self.rcode, str(self.rcode))

    @property
    def is_nxdomain(self) -> bool:
        return self.rcode == 3

    @property
    def qname(self) -> str:
        return self.questions[0].name if self.questions else ""

    @property
    def qtype(self) -> int:
        return self.questions[0].qtype if self.questions else 0


def _read_name(data: bytes, offset: int, *, depth: int = 0) -> tuple[str, int]:
    """Read a (possibly compressed) domain name.

    Returns the name in lower case with the trailing dot removed, plus the
    offset just past the name in the *current* position.
    """
    if depth > 8:
        raise DnsError("compression pointer loop")
    labels: list[str] = []
    jumped = False
    end = offset
    while True:
        if offset >= len(data):
            raise DnsError("name runs past end of message")
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise DnsError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
            jumped = True
            offset = pointer
            depth += 1
            if depth > 8:
                raise DnsError("compression pointer loop")
            continue
        if length & 0xC0:
            raise DnsError(f"unsupported label type {length:#04x}")
        offset += 1
        label = data[offset : offset + length]
        if len(label) < length:
            raise DnsError("label runs past end of message")
        labels.append(label.decode("ascii", errors="replace"))
        offset += length
        if not jumped:
            end = offset
    return ".".join(labels).lower(), end


def parse(data: bytes) -> DnsMessage:
    """Parse a DNS message from a UDP payload (or a TCP segment body)."""
    if len(data) < 12:
        raise DnsError("message shorter than the 12 byte header")
    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack_from("!HHHHHH", data, 0)
    message = DnsMessage(
        txid=txid,
        flags=flags,
        answer_count=ancount,
        authority_count=nscount,
        additional_count=arcount,
    )
    offset = 12
    for _ in range(qdcount):
        name, offset = _read_name(data, offset)
        if offset + 4 > len(data):
            raise DnsError("question runs past end of message")
        qtype, qclass = struct.unpack_from("!HH", data, offset)
        offset += 4
        message.questions.append(DnsQuestion(name=name, qtype=qtype, qclass=qclass))
    return message


def parse_tcp(data: bytes) -> DnsMessage:
    """Parse a DNS message carried over TCP, which prefixes a 2 byte length."""
    if len(data) < 2:
        raise DnsError("tcp dns payload shorter than the length prefix")
    (length,) = struct.unpack_from("!H", data, 0)
    body = data[2 : 2 + length]
    if len(body) < length:
        raise DnsError("tcp dns length prefix exceeds payload")
    return parse(body)


def is_ip_literal(name: str) -> bool:
    """True for reverse lookup names and any name that is really an address."""
    if name.endswith(".in-addr.arpa") or name.endswith(".ip6.arpa"):
        return True
    stripped = name.strip(".")
    if stripped.replace(".", "").isdigit():
        return True
    return False


def base_domain(name: str) -> str:
    """Approximate the registrable domain of a name.

    ``a.b.example.com`` -> ``example.com``; ``x.example.com.dz`` ->
    ``example.com.dz``. Used to group lookups that belong to one campaign
    rather than counting one domain per random subdomain.
    """
    name = name.strip(".").lower()
    if not name:
        return ""
    labels = name.split(".")
    if len(labels) <= 2:
        return name
    candidate = ".".join(labels[-2:])
    if candidate in _TWO_LEVEL and len(labels) >= 3:
        return ".".join(labels[-3:])
    return candidate


def shannon_entropy(text: str) -> float:
    """Bits per character. Random-looking text scores high, words score low."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())
