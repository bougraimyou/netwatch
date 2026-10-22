"""Behavioural baselines.

A baseline answers one question: what did this network normally do? It is built
from a capture the operator considers clean, stored as JSON, and compared
against later traffic. Without one, "new external peer" cannot exist, and the
report says so instead of pretending the rule ran.

A baseline is data, not a promise. It is only as good as the window it was built
from, and the file records that window so nobody has to guess.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .flows import TrafficIndex

__all__ = ["BASELINE_VERSION", "build", "save", "load", "describe"]

BASELINE_VERSION = 1


def _iso(ts_ns: int | None) -> str | None:
    if not ts_ns:
        return None
    return datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(slots=True)
class BaselineSource:
    path: str
    packets: int
    duration_s: float


def build(index: TrafficIndex, *, sources: list[BaselineSource] | None = None, note: str = "") -> dict[str, object]:
    """Turn a traffic index into a baseline document."""
    hosts: dict[str, dict[str, object]] = {}
    for host in index.hosts.values():
        if host.scope != "internal":
            continue
        hosts[host.address] = {
            "external_peers": sorted(host.external_peers),
            "ports_contacted": sorted(host.ports_contacted)[:500],
            "protocols": dict(host.protocols.most_common(12)),
            "bytes_out": host.bytes_out,
            "bytes_in": host.bytes_in,
            "dns_queries": host.dns_queries,
        }
    return {
        "version": BASELINE_VERSION,
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "note": note,
        "window": {
            "start": _iso(index.start_ns),
            "end": _iso(index.end_ns),
            "duration_s": round(index.duration_s, 3),
            "packets": index.total_packets,
        },
        "sources": [
            {"path": source.path, "packets": source.packets, "duration_s": round(source.duration_s, 3)}
            for source in (sources or [])
        ],
        "hosts": hosts,
    }


def save(path: str | Path, baseline: dict[str, object]) -> None:
    Path(path).write_text(json.dumps(baseline, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def load(path: str | Path) -> dict[str, object]:
    """Load and validate a baseline file.

    A baseline that is the wrong shape produces a clear error rather than a
    rule that silently matches nothing.
    """
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: not valid JSON ({exc})") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{path}: baseline must be a JSON object")
    if data.get("version") != BASELINE_VERSION:
        raise ValueError(
            f"{path}: baseline version {data.get('version')!r} is not supported (expected {BASELINE_VERSION})"
        )
    if not isinstance(data.get("hosts"), dict):
        raise ValueError(f"{path}: baseline has no 'hosts' object")
    return data


def describe(baseline: dict[str, object]) -> str:
    """One line for a CLI or a report header."""
    hosts = baseline.get("hosts") or {}
    window = baseline.get("window") or {}
    return (
        f"{len(hosts)} hosts, {window.get('packets', 0)} packets, "
        f"built {baseline.get('created', 'unknown')}"
    )
