"""Report assembly.

The report is a plain dictionary with a published shape. Everything downstream
(the HTML renderer, the JSON file, the HTTP API, the tests) reads that one
structure, so there is exactly one definition of what a finding is.
"""

from __future__ import annotations

from datetime import datetime, timezone

from . import __version__
from .baseline import describe as describe_baseline
from .flows import TrafficIndex
from .rules import Alert, RuleStatus, rules_summary

__all__ = ["build_report", "to_json"]

REPORT_VERSION = 1


def _iso(ts_ns: int | None) -> str | None:
    if not ts_ns:
        return None
    return datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _human_bytes(value: int | float) -> str:
    value = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def _alert_to_dict(alert: Alert) -> dict[str, object]:
    return {
        "rule": alert.rule,
        "rule_name": alert.rule_name,
        "severity": alert.severity,
        "title": alert.title,
        "summary": alert.summary,
        "host": alert.host,
        "description": alert.description,
        "evidence": alert.evidence,
        "packets": alert.packets,
    }


def build_report(
    index: TrafficIndex,
    alerts: list[Alert],
    statuses: list[RuleStatus],
    *,
    capture_name: str = "capture",
    baseline: dict[str, object] | None = None,
    generated_at: datetime | None = None,
) -> dict[str, object]:
    """Assemble the report document."""
    generated = generated_at or datetime.now(timezone.utc)

    protocols = [
        {"name": name, "packets": count}
        for name, count in index.protocol_counts.most_common()
        if count
    ]
    top_flows = [
        {
            "src": flow.src,
            "sport": flow.sport,
            "dst": flow.dst,
            "dport": flow.dport,
            "proto": flow.proto,
            "packets": flow.packets,
            "bytes": flow.bytes,
            "bytes_human": _human_bytes(flow.bytes),
            "duration_s": round(flow.duration_s, 3),
        }
        for flow in index.top_flows(12)
    ]
    top_hosts = [
        {
            "address": host.address,
            "scope": host.scope,
            "packets_out": host.packets_out,
            "packets_in": host.packets_in,
            "bytes_out": host.bytes_out,
            "bytes_in": host.bytes_in,
            "bytes_human": _human_bytes(host.bytes_out + host.bytes_in),
            "peers": len(host.peers_out),
            "ports": len(host.ports_contacted),
            "dns_queries": host.dns_queries,
        }
        for host in index.top_hosts(12)
    ]
    domains = [
        {"domain": domain, "queries": count} for domain, count in index.top_domains(10)
    ]

    severity_counts: dict[str, int] = {}
    for alert in alerts:
        severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1

    integrity = {
        "truncated_packets": index.truncated_packets,
        "parse_errors": index.parse_errors,
        "dns_parse_errors": index.dns_parse_errors,
        "connection_events_truncated": index.events_truncated,
        "raw_samples_truncated": index.raw_truncated,
        "raw_samples_retained": len(index.raw),
        "vlans": sorted(index.vlans),
    }
    limitations: list[str] = []
    if index.truncated_packets or index.parse_errors:
        limitations.append(
            f"{index.truncated_packets} packet(s) were truncated and {index.parse_errors} had a header "
            "this decoder does not support. Findings only cover what was decoded."
        )
    if index.events_truncated:
        limitations.append(
            "The connection event log hit its size cap, so scan detection covers the captured "
            "portion only."
        )
    if index.raw_truncated:
        limitations.append(
            "The packet byte archive hit its memory budget. Some alerts cite decoded fields "
            "without the raw bytes."
        )
    if not baseline:
        limitations.append(
            "No baseline was supplied, so the 'new external peer' rule did not run. That rule "
            "compares against remembered traffic and cannot work without one."
        )
    limitations.append(
        "Address scope treats reserved and private ranges as internal. A destination outside "
        "them is called external without knowing your actual LAN layout."
    )

    return {
        "report_version": REPORT_VERSION,
        "tool": {
            "name": "NetWatch",
            "version": __version__,
            "generated_at": generated.strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "capture": {
            "name": capture_name,
            "packets": index.total_packets,
            "wire_bytes": index.total_wire_bytes,
            "wire_bytes_human": _human_bytes(index.total_wire_bytes),
            "payload_bytes": index.total_payload_bytes,
            "payload_bytes_human": _human_bytes(index.total_payload_bytes),
            "duration_s": round(index.duration_s, 3),
            "start": _iso(index.start_ns),
            "end": _iso(index.end_ns),
            "flows": len(index.flows),
            "hosts": len(index.hosts),
            "dns_observations": len(index.dns_observations),
            "dns_queries": sum(1 for o in index.dns_observations if not o.is_response),
        },
        "protocols": protocols,
        "top_flows": top_flows,
        "top_hosts": top_hosts,
        "top_domains": domains,
        "alerts": [_alert_to_dict(alert) for alert in sorted(alerts, key=lambda a: a.sort_key)],
        "alert_count": len(alerts),
        "severity_counts": severity_counts,
        "rules": [
            {
                "rule": status.rule,
                "name": status.name,
                "ran": status.ran,
                "alerts": status.alerts,
                "skipped_reason": status.skipped_reason,
            }
            for status in statuses
        ],
        "rule_summary": rules_summary(statuses),
        "baseline": {
            "present": bool(baseline),
            "description": describe_baseline(baseline) if baseline else None,
            "created": (baseline or {}).get("created"),
        },
        "integrity": integrity,
        "limitations": limitations,
    }


def to_json(report: dict[str, object], *, indent: int = 2) -> str:
    import json

    return json.dumps(report, indent=indent, sort_keys=False)
