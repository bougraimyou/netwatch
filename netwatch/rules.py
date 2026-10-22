"""Detection rules.

Five rules, each a pure function over the traffic index. The design rule is
stricter than the feature list: a rule that cannot be shown to stay silent on
clean traffic does not ship, and no rule is allowed to be vague about the
evidence that made it fire.

Every alert carries the decoded facts that produced it and, where the packet
bytes were retained, the exact bytes. That is the difference between "suspicious
DNS" and a finding somebody can check.
"""

from __future__ import annotations

import base64
import binascii
import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from . import dns
from .flows import DnsObservation, Flow, TrafficIndex
from .packets import address_scope

__all__ = [
    "Alert",
    "RuleStatus",
    "DEFAULT_CONFIG",
    "SEVERITY_ORDER",
    "run_rules",
    "rules_summary",
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

DEFAULT_CONFIG: dict[str, dict[str, object]] = {
    "port_scan": {
        "enabled": True,
        "distinct_ports": 20,
        "window_s": 60,
        "min_syn_ratio": 0.5,
        "horizontal_distinct_hosts": 10,
    },
    "dns_anomaly": {
        "enabled": True,
        "window_s": 300,
        "min_queries": 40,
        "max_label_length": 20,
        "min_entropy": 3.6,
        "min_unique_subdomains": 25,
        "nxdomain_threshold": 20,
    },
    "beaconing": {
        "enabled": True,
        "min_connections": 12,
        "max_coefficient_of_variation": 0.20,
        "min_interval_s": 5,
        "max_interval_s": 3600,
    },
    "cleartext_credentials": {
        "enabled": True,
    },
    "new_external_peer": {
        "enabled": True,
        "max_alerts": 5,
    },
}


@dataclass(slots=True)
class Alert:
    rule: str
    rule_name: str
    severity: str
    title: str
    summary: str
    host: str
    evidence: dict[str, object] = field(default_factory=dict)
    description: str = ""
    packets: list[dict[str, object]] = field(default_factory=list)

    @property
    def sort_key(self) -> tuple[int, str]:
        return (SEVERITY_ORDER.get(self.severity, 9), self.title)


@dataclass(slots=True)
class RuleStatus:
    rule: str
    name: str
    ran: bool
    alerts: int = 0
    skipped_reason: str | None = None


@dataclass(slots=True)
class RuleContext:
    index: TrafficIndex
    config: dict[str, dict[str, object]]
    baseline: dict[str, object] | None = None

    def cfg(self, rule: str) -> dict[str, object]:
        merged = dict(DEFAULT_CONFIG[rule])
        merged.update(self.config.get(rule, {}))
        return merged


def _iso(ts_ns: int) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _packet_refs(
    index: TrafficIndex,
    packet_indices: list[int],
    limit: int = 3,
    *,
    withhold_payload: bool = False,
) -> list[dict[str, object]]:
    """Build the auditable packet references for an alert.

    A rule that found a secret inside the payload must pass
    ``withhold_payload``. The reference then keeps the packet number and, when
    the bytes were retained, their length - both harmless - but the bytes
    themselves never leave the process. Hex encoding is a change of format,
    not a redaction: a report that masks ``PASS ****`` in one field while
    carrying the same password in a hexdump beside it has not redacted
    anything.
    """
    refs: list[dict[str, object]] = []
    for packet_index in packet_indices[:limit]:
        sample = index.raw.get(packet_index)
        ref: dict[str, object] = {"packet": packet_index}
        if withhold_payload:
            ref["note"] = "packet bytes withheld: this frame carries the credential in the clear"
            if sample:
                ref["bytes"] = len(sample)
        elif sample:
            ref["hex"] = binascii.hexlify(sample).decode("ascii")
            ref["bytes"] = len(sample)
        else:
            ref["hex"] = None
            ref["note"] = "payload not retained (byte budget exhausted or empty payload)"
        refs.append(ref)
    return refs


# ---------------------------------------------------------------------------
# 1. port scan
# ---------------------------------------------------------------------------


def rule_port_scan(ctx: RuleContext) -> list[Alert]:
    cfg = ctx.cfg("port_scan")
    if not cfg["enabled"]:
        return []
    window_ns = int(float(cfg["window_s"]) * 1e9)
    threshold = int(cfg["distinct_ports"])
    horizontal_threshold = int(cfg["horizontal_distinct_hosts"])
    alerts: list[Alert] = []

    by_target: dict[tuple[str, str], list] = defaultdict(list)
    for event in ctx.index.events:
        by_target[(event.src, event.dst)].append(event)

    reported: set[str] = set()
    for (src, dst), events in by_target.items():
        events.sort(key=lambda e: e.ts_ns)
        best = _best_window(events, window_ns, threshold, key=lambda e: e.dport)
        if best is None:
            continue
        start, end, ports, selected = best
        syn_ratio = sum(1 for e in selected if e.syn_only) / len(selected) if selected else 0.0
        if syn_ratio < float(cfg["min_syn_ratio"]):
            continue
        reported.add(src)
        alerts.append(
            Alert(
                rule="port_scan",
                rule_name="Port scan",
                severity="high",
                title=f"{src} scanned {len(ports)} ports on {dst}",
                summary=(
                    f"{len(selected)} connection attempts to {len(ports)} distinct ports "
                    f"on {dst} within {float(cfg['window_s']):g}s"
                ),
                host=src,
                description=(
                    "One source touched many destination ports in a short window, and "
                    f"{syn_ratio:.0%} of those attempts were a bare SYN with no handshake. "
                    "That is the shape of a port scan, not of a program using a service."
                ),
                evidence={
                    "dst": dst,
                    "distinct_ports": len(ports),
                    "attempts": len(selected),
                    "syn_only_ratio": round(syn_ratio, 3),
                    "window_s": float(cfg["window_s"]),
                    "first_seen": _iso(start),
                    "last_seen": _iso(end),
                    "ports": sorted(ports)[:60],
                    "ports_total": len(ports),
                },
                packets=_packet_refs(ctx.index, [e.packet_index for e in selected]),
            )
        )

    # Horizontal sweep: one port, many hosts. A different question from the
    # vertical scan above, so it gets its own alert rather than being folded in.
    by_port: dict[tuple[str, int], list] = defaultdict(list)
    for event in ctx.index.events:
        by_port[(event.src, event.dport)].append(event)
    for (src, dport), events in by_port.items():
        if src in reported:
            continue
        events.sort(key=lambda e: e.ts_ns)
        best = _best_window(events, window_ns, horizontal_threshold, key=lambda e: e.dst)
        if best is None:
            continue
        start, end, hosts_hit, selected = best
        alerts.append(
            Alert(
                rule="port_scan",
                rule_name="Port scan",
                severity="high",
                title=f"{src} probed port {dport} across {len(hosts_hit)} hosts",
                summary=(
                    f"{len(selected)} attempts to port {dport} across {len(hosts_hit)} "
                    f"distinct hosts within {float(cfg['window_s']):g}s"
                ),
                host=src,
                description=(
                    "One source asked the same port on many hosts in a short window. "
                    "That is a horizontal sweep looking for a specific service."
                ),
                evidence={
                    "dport": dport,
                    "distinct_hosts": len(hosts_hit),
                    "attempts": len(selected),
                    "window_s": float(cfg["window_s"]),
                    "first_seen": _iso(start),
                    "last_seen": _iso(end),
                    "hosts": sorted(hosts_hit)[:40],
                },
                packets=_packet_refs(ctx.index, [e.packet_index for e in selected]),
            )
        )
    return alerts


def _best_window(events: list, window_ns: int, threshold: int, key) -> tuple[int, int, set, list] | None:
    """Sliding window over time-sorted events, maximising distinct key values.

    Returns the best (start, end, distinct_values, events_in_window) or None if
    no window reaches the threshold. Two pointers, so this stays linear.
    """
    best: tuple[int, int, set, list] | None = None
    left = 0
    counts: Counter = Counter()
    for right, event in enumerate(events):
        counts[key(event)] += 1
        while event.ts_ns - events[left].ts_ns > window_ns:
            leave = events[left]
            counts[key(leave)] -= 1
            if counts[key(leave)] <= 0:
                del counts[key(leave)]
            left += 1
        if len(counts) > threshold and (best is None or len(counts) > len(best[2])):
            best = (
                events[left].ts_ns,
                event.ts_ns,
                set(counts),
                events[left : right + 1],
            )
    return best


# ---------------------------------------------------------------------------
# 2. DNS anomaly (tunnelling and generated names)
# ---------------------------------------------------------------------------


def rule_dns_anomaly(ctx: RuleContext) -> list[Alert]:
    cfg = ctx.cfg("dns_anomaly")
    if not cfg["enabled"]:
        return []
    window_ns = int(float(cfg["window_s"]) * 1e9)
    alerts: list[Alert] = []

    queries = [o for o in ctx.index.dns_observations if not o.is_response and o.name]
    by_domain: dict[tuple[str, str], list[DnsObservation]] = defaultdict(list)
    for observation in queries:
        by_domain[(observation.client, dns.base_domain(observation.name))].append(observation)

    for (client, domain), observations in by_domain.items():
        observations.sort(key=lambda o: o.ts_ns)
        window = _dns_window(observations, window_ns)
        if len(window) < int(cfg["min_queries"]):
            continue
        names = [o.name for o in window]
        labels = [name.split(".")[0] for name in names if name]
        unique_names = len(set(names))
        mean_label = statistics.fmean(len(label) for label in labels) if labels else 0.0
        entropy = statistics.fmean(dns.shannon_entropy(label) for label in labels) if labels else 0.0
        generated = (
            mean_label >= float(cfg["max_label_length"])
            or entropy >= float(cfg["min_entropy"])
            or unique_names >= int(cfg["min_unique_subdomains"])
        )
        if not generated:
            continue
        duration_s = max((window[-1].ts_ns - window[0].ts_ns) / 1e9, 0.001)
        alerts.append(
            Alert(
                rule="dns_anomaly",
                rule_name="DNS anomaly",
                severity="high",
                title=f"{client} queried {domain} {len(window)} times with generated names",
                summary=(
                    f"{len(window)} lookups, {unique_names} unique names, mean label "
                    f"{mean_label:.1f} chars, entropy {entropy:.2f} bits/char"
                ),
                host=client,
                description=(
                    "A client asked one domain many times with names that look generated "
                    "rather than typed: long labels, high per-character entropy, almost "
                    "no repetition. Bulk random subdomains are how DNS tunnelling carries "
                    "data out, and how some malware finds its controller."
                ),
                evidence={
                    "domain": domain,
                    "queries": len(window),
                    "unique_names": unique_names,
                    "mean_label_length": round(mean_label, 2),
                    "mean_entropy": round(entropy, 3),
                    "queries_per_second": round(len(window) / duration_s, 3),
                    "first_seen": _iso(window[0].ts_ns),
                    "last_seen": _iso(window[-1].ts_ns),
                    "sample_names": [w.name for w in window[:12]],
                },
                packets=[],
            )
        )

    # NXDOMAIN floods: a client asking for names that do not exist, at volume.
    # This is the DGA pattern and it is deliberately a separate alert, because
    # "the name is random" and "the name does not exist" are different facts.
    responses = [o for o in ctx.index.dns_observations if o.is_response]
    by_client: dict[str, list[DnsObservation]] = defaultdict(list)
    for observation in responses:
        if observation.rcode == 3:
            by_client[observation.client].append(observation)
    for client, observations in by_client.items():
        observations.sort(key=lambda o: o.ts_ns)
        window = _dns_window(observations, window_ns)
        if len(window) < int(cfg["nxdomain_threshold"]):
            continue
        labels = [o.name.split(".")[0] for o in window if o.name]
        entropy = statistics.fmean(dns.shannon_entropy(label) for label in labels) if labels else 0.0
        unique = len({o.name for o in window})
        if unique < int(cfg["nxdomain_threshold"]) or entropy < 3.0:
            continue
        alerts.append(
            Alert(
                rule="dns_anomaly",
                rule_name="DNS anomaly",
                severity="high",
                title=f"{client} got {len(window)} NXDOMAIN answers for generated names",
                summary=(
                    f"{len(window)} unanswered lookups, {unique} unique names, "
                    f"entropy {entropy:.2f} bits/char"
                ),
                host=client,
                description=(
                    "Many lookups for names that do not exist, with generated-looking "
                    "labels. A domain generation algorithm walks through candidate "
                    "controller names like this, and each miss returns NXDOMAIN."
                ),
                evidence={
                    "nxdomain_responses": len(window),
                    "unique_names": unique,
                    "mean_entropy": round(entropy, 3),
                    "first_seen": _iso(window[0].ts_ns),
                    "last_seen": _iso(window[-1].ts_ns),
                    "sample_names": [o.name for o in window[:12]],
                },
                packets=[],
            )
        )
    return alerts


def _dns_window(observations: list[DnsObservation], window_ns: int) -> list[DnsObservation]:
    """Return the densest window of observations, as a list."""
    best: list[DnsObservation] = []
    left = 0
    for right, observation in enumerate(observations):
        while observation.ts_ns - observations[left].ts_ns > window_ns:
            left += 1
        if right - left + 1 > len(best):
            best = observations[left : right + 1]
    return best


# ---------------------------------------------------------------------------
# 3. beaconing
# ---------------------------------------------------------------------------


def rule_beaconing(ctx: RuleContext) -> list[Alert]:
    cfg = ctx.cfg("beaconing")
    if not cfg["enabled"]:
        return []
    alerts: list[Alert] = []
    min_connections = int(cfg["min_connections"])
    max_cv = float(cfg["max_coefficient_of_variation"])
    min_interval = float(cfg["min_interval_s"])
    max_interval = float(cfg["max_interval_s"])

    # A beacon rotates its source port; that is what makes it look like ordinary
    # web traffic to a 5-tuple view. So the rhythm is measured per destination
    # service, not per connection.
    grouped: dict[tuple[str, str, int, str], dict[str, object]] = {}
    for flow in ctx.index.flows.values():
        if not flow.connections:
            continue
        key = (flow.src, flow.dst, flow.dport, flow.proto)
        entry = grouped.setdefault(key, {"timestamps": [], "bytes": 0, "packets": 0, "sports": set()})
        entry["timestamps"].extend(flow.connections)  # type: ignore[union-attr]
        entry["bytes"] = int(entry["bytes"]) + flow.wire_bytes
        entry["packets"] = int(entry["packets"]) + flow.packets
        entry["sports"].add(flow.sport)  # type: ignore[union-attr]

    for (src, dst, dport, proto), entry in grouped.items():
        timestamps: list[int] = sorted(entry["timestamps"])  # type: ignore[arg-type]
        # Retransmitted SYNs are one connection attempt, not two. Without this
        # the spacing looks erratic and a real beacon reads as noise.
        deduped: list[int] = []
        for timestamp in timestamps:
            if not deduped or timestamp - deduped[-1] > 1_000_000_000:
                deduped.append(timestamp)
        if len(deduped) < 2:
            # One connection has no intervals yet, and statistics over an
            # empty list raises StatisticsError instead of measuring
            # anything. A short flow is a non-finding, not a crash.
            continue
        if len(deduped) < min_connections:
            continue
        if address_scope(src) != "internal" or address_scope(dst) != "external":
            continue
        intervals = [(b - a) / 1e9 for a, b in zip(deduped, deduped[1:])]
        mean = statistics.fmean(intervals)
        if not (min_interval <= mean <= max_interval):
            continue
        stdev = statistics.pstdev(intervals)
        cv = stdev / mean if mean else 99.0
        if cv > max_cv:
            continue
        severity = "high" if cv <= 0.05 and len(deduped) >= 30 else "medium"
        alerts.append(
            Alert(
                rule="beaconing",
                rule_name="Beaconing",
                severity=severity,
                title=f"{src} contacted {dst}:{dport} {len(deduped)} times at a fixed rhythm",
                summary=(
                    f"interval {mean:.1f}s +/- {stdev:.1f}s (CV {cv:.3f}) over "
                    f"{len(deduped)} connections"
                ),
                host=src,
                description=(
                    "A host opened the same destination port over and over with almost "
                    "identical spacing. People and browsers do not do that; scheduled "
                    "malware and some legitimate agents do. Low variance is the signal, "
                    "not the volume."
                ),
                evidence={
                    "dst": dst,
                    "dport": dport,
                    "proto": proto,
                    "connections": len(deduped),
                    "source_ports": len(entry["sports"]),  # type: ignore[arg-type]
                    "mean_interval_s": round(mean, 3),
                    "stdev_interval_s": round(stdev, 3),
                    "coefficient_of_variation": round(cv, 4),
                    "wire_bytes": entry["bytes"],
                    "packets": entry["packets"],
                    "intervals_sample_s": [round(i, 2) for i in intervals[:8]],
                    "first_seen": _iso(deduped[0]),
                    "last_seen": _iso(deduped[-1]),
                    "duration_s": round((deduped[-1] - deduped[0]) / 1e9, 1),
                },
                packets=[],
            )
        )
    return alerts


# ---------------------------------------------------------------------------
# 4. cleartext credentials
# ---------------------------------------------------------------------------

_FTP_USER = re.compile(rb"(?:^|\r?\n)USER\s+(\S{1,64})", re.IGNORECASE)
_FTP_PASS = re.compile(rb"(?:^|\r?\n)PASS\s+(\S{1,128})", re.IGNORECASE)
_HTTP_BASIC = re.compile(rb"Authorization:\s*Basic\s+([A-Za-z0-9+/=]{4,256})", re.IGNORECASE)
_HTTP_PASSWORD = re.compile(rb"(?:password|passwd|pwd)=([^&\s\r\n]{1,128})", re.IGNORECASE)
_SMTP_AUTH_PLAIN = re.compile(rb"AUTH\s+PLAIN\s+([A-Za-z0-9+/=]{4,512})", re.IGNORECASE)
_TELNET_PASSWORD = re.compile(rb"Password:\s*", re.IGNORECASE)


def rule_cleartext_credentials(ctx: RuleContext) -> list[Alert]:
    cfg = ctx.cfg("cleartext_credentials")
    if not cfg["enabled"]:
        return []
    alerts: list[Alert] = []

    for flow in ctx.index.flows.values():
        if not flow.samples:
            continue
        findings = _inspect_samples(flow)
        if not findings:
            continue
        # One alert per flow, with every credential method found in it.
        protocols = sorted({finding["protocol"] for finding in findings})
        alerts.append(
            Alert(
                rule="cleartext_credentials",
                rule_name="Cleartext credentials",
                severity="medium",
                title=f"{flow.src} sent {', '.join(protocols)} credentials without encryption to {flow.dst}:{flow.dport}",
                summary=(
                    f"{len(findings)} credential exchange{'s' if len(findings) != 1 else ''} "
                    f"over {flow.proto} on port {flow.dport}; secrets are redacted in this report"
                ),
                host=flow.src,
                description=(
                    "A password or authorisation header crossed the network in a protocol "
                    "with no encryption. Anyone on the path can read it. The value itself "
                    "is deliberately not reproduced here."
                ),
                evidence={
                    "dst": flow.dst,
                    "dport": flow.dport,
                    "proto": flow.proto,
                    "findings": findings,
                    "secret_redacted": True,
                },
                # The frames these packet numbers point at carry the credential
                # in the clear, so their bytes are withheld here even though
                # the archive still holds them. Redaction that stops at the
                # value in "findings" is not redaction.
                packets=_packet_refs(ctx.index, flow.sample_packets, withhold_payload=True),
            )
        )
    return alerts


def _mask(value: str) -> str:
    """Keep the length visible, keep the value secret."""
    if not value:
        return ""
    if len(value) <= 2:
        return "*" * len(value)
    return value[0] + "*" * (len(value) - 2) + value[-1]


def _inspect_samples(flow: Flow) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()

    def add(protocol: str, method: str, username: str, secret_length: int) -> None:
        key = (protocol, method)
        if key in seen:
            return
        seen.add(key)
        findings.append(
            {
                "protocol": protocol,
                "method": method,
                "username": _mask(username) if username else None,
                "secret": "[redacted]",
                "secret_length": secret_length,
            }
        )

    for sample in flow.samples:
        match = _FTP_USER.search(sample)
        if match:
            user = match.group(1).decode("ascii", errors="replace")
            # USER and PASS arrive in separate segments, so the password length
            # has to be looked up across the whole flow, not this one packet.
            password_match = next(
                (found for other in flow.samples if (found := _FTP_PASS.search(other))), None
            )
            add("FTP", "USER/PASS", user, len(password_match.group(1)) if password_match else 0)
        for match in _HTTP_BASIC.finditer(sample):
            try:
                decoded = base64.b64decode(match.group(1), validate=True).decode("latin-1")
            except (binascii.Error, UnicodeDecodeError):
                continue
            username, _, password = decoded.partition(":")
            add("HTTP", "Basic authorization header", username, len(password))
        for match in _HTTP_PASSWORD.finditer(sample):
            add("HTTP", "form password field", "", len(match.group(1)))
        for match in _SMTP_AUTH_PLAIN.finditer(sample):
            try:
                decoded = base64.b64decode(match.group(1), validate=True)
            except binascii.Error:
                continue
            parts = decoded.split(b"\x00")
            username = parts[-2].decode("utf-8", errors="replace") if len(parts) >= 2 else ""
            password = parts[-1].decode("utf-8", errors="replace") if len(parts) >= 2 else ""
            add("SMTP", "AUTH PLAIN", username, len(password))
        if _TELNET_PASSWORD.search(sample):
            add("Telnet", "password prompt answered", "", 0)
    return findings


# ---------------------------------------------------------------------------
# 5. new external peer
# ---------------------------------------------------------------------------


def rule_new_external_peer(ctx: RuleContext) -> list[Alert]:
    cfg = ctx.cfg("new_external_peer")
    if not cfg["enabled"]:
        return []
    if not ctx.baseline:
        return []
    known_hosts = ctx.baseline.get("hosts", {})
    if not isinstance(known_hosts, dict):
        return []
    candidates: list[tuple[float, str, list[str], int]] = []
    for host in ctx.index.hosts.values():
        if host.scope != "internal":
            continue
        observed = host.external_peers
        if not observed:
            continue
        entry = known_hosts.get(host.address)
        known = set(entry.get("external_peers", [])) if isinstance(entry, dict) else set()
        new_peers = sorted(observed - known)
        if not new_peers:
            continue
        # Only worth an alert when the new peer actually carried traffic. Both
        # directions count: a download has almost no outbound payload, and an
        # exfiltration has almost no inbound, so either alone would miss half
        # the cases.
        volume = 0
        for flow in ctx.index.flows.values():
            if (flow.src == host.address and flow.dst in new_peers) or (
                flow.dst == host.address and flow.src in new_peers
            ):
                volume += flow.wire_bytes
        if volume <= 0:
            continue
        candidates.append((volume, host.address, new_peers, host.dns_queries))

    candidates.sort(reverse=True)
    alerts: list[Alert] = []
    for volume, address, new_peers, _dns_queries in candidates[: int(cfg["max_alerts"])]:
        alerts.append(
            Alert(
                rule="new_external_peer",
                rule_name="New external peer",
                severity="medium",
                title=f"{address} talked to {len(new_peers)} external address{'es' if len(new_peers) != 1 else ''} not present in the baseline",
                summary=f"{volume} bytes exchanged with {', '.join(new_peers[:4])}",
                host=address,
                description=(
                    "The baseline was built from traffic that was considered normal. "
                    "This host exchanged traffic with external addresses that never appeared in it. "
                    "A new peer is not automatically bad, which is why this is medium and "
                    "not high: it is the question to ask, not the answer."
                ),
                evidence={
                    "new_peers": new_peers[:30],
                    "new_peer_count": len(new_peers),
                    "wire_bytes": volume,
                    "baseline_known_peers": len(known_hosts.get(address, {}).get("external_peers", []))
                    if isinstance(known_hosts.get(address), dict)
                    else 0,
                },
                packets=[],
            )
        )
    return alerts


# ---------------------------------------------------------------------------
# driver
# ---------------------------------------------------------------------------

_RULES = [
    ("port_scan", "Port scan", rule_port_scan),
    ("dns_anomaly", "DNS anomaly", rule_dns_anomaly),
    ("beaconing", "Beaconing", rule_beaconing),
    ("cleartext_credentials", "Cleartext credentials", rule_cleartext_credentials),
    ("new_external_peer", "New external peer", rule_new_external_peer),
]

RULE_DESCRIPTIONS = {
    "port_scan": "One source, many ports or many hosts, in a short window.",
    "dns_anomaly": "Generated-looking names at volume, or a flood of NXDOMAIN answers.",
    "beaconing": "Repeated connections to one destination at a near-constant interval.",
    "cleartext_credentials": "A password crossed the wire unencrypted. Values are redacted.",
    "new_external_peer": "An external destination that the baseline never saw. Needs a baseline.",
}


def run_rules(
    index: TrafficIndex,
    config: dict[str, dict[str, object]] | None = None,
    baseline: dict[str, object] | None = None,
) -> tuple[list[Alert], list[RuleStatus]]:
    """Run every enabled rule and return alerts plus a per-rule status."""
    context = RuleContext(index=index, config=config or {}, baseline=baseline)
    alerts: list[Alert] = []
    statuses: list[RuleStatus] = []
    for rule_id, name, function in _RULES:
        cfg = context.cfg(rule_id)
        if not cfg.get("enabled", True):
            statuses.append(RuleStatus(rule_id, name, ran=False, skipped_reason="disabled in config"))
            continue
        if rule_id == "new_external_peer" and not baseline:
            statuses.append(
                RuleStatus(
                    rule_id,
                    name,
                    ran=False,
                    skipped_reason="no baseline supplied; build one with `netwatch baseline`",
                )
            )
            continue
        produced = function(context)
        alerts.extend(produced)
        statuses.append(RuleStatus(rule_id, name, ran=True, alerts=len(produced)))
    return alerts, statuses


def rules_summary(statuses: list[RuleStatus]) -> dict[str, object]:
    return {
        "total": len(statuses),
        "ran": sum(1 for status in statuses if status.ran),
        "skipped": sum(1 for status in statuses if not status.ran),
        "alerts": sum(status.alerts for status in statuses),
    }
