"""Analysis pipeline: captures in, index and alerts out.

The one place that knows how to go from files on disk to a report. The CLI and
the tests both call this rather than re-implementing the loop, so there is no
second definition of what "analyze" means.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .flows import TrafficIndex
from .packets import decode
from .pcap import PcapError, read_capture
from .rules import Alert, RuleStatus, run_rules

__all__ = ["SourceStats", "IndexResult", "expand_paths", "build_index", "load_config"]

CAPTURE_SUFFIXES = {".pcap", ".pcapng", ".cap", ".dmp"}


@dataclass(slots=True)
class SourceStats:
    path: str
    packets: int
    wire_bytes: int
    linktype: int


@dataclass(slots=True)
class IndexResult:
    index: TrafficIndex
    sources: list[SourceStats]


class CaptureError(RuntimeError):
    """A capture could not be read; the message names the file."""


def expand_paths(paths: list[str]) -> list[Path]:
    """Expand directories into capture files, keeping explicit files as given.

    A directory is walked in sorted order so two runs over the same folder
    produce the same report.
    """
    resolved: list[Path] = []
    for raw in paths:
        path = Path(raw).expanduser()
        if not path.exists():
            raise CaptureError(f"{path}: no such file or directory")
        if path.is_dir():
            found = sorted(
                child
                for child in path.rglob("*")
                if child.is_file()
                and (
                    child.suffix.lower() in CAPTURE_SUFFIXES
                    or (
                        child.suffix.lower() == ".gz"
                        and child.with_suffix("").suffix.lower() in CAPTURE_SUFFIXES
                    )
                )
            )
            if not found:
                raise CaptureError(f"{path}: no .pcap, .pcapng or .cap files in this directory")
            resolved.extend(found)
        else:
            resolved.append(path)
    if not resolved:
        raise CaptureError("no captures to analyze")
    return resolved


def build_index(paths: list[str]) -> IndexResult:
    """Read every capture and fold it into one traffic index."""
    index = TrafficIndex()
    sources: list[SourceStats] = []
    files = expand_paths(paths)
    for path in files:
        packets = 0
        wire = 0
        linktype = -1
        try:
            for raw in read_capture(path):
                packets += 1
                wire += raw.orig_len
                linktype = raw.linktype
                index.add(decode(raw))
        except PcapError as exc:
            raise CaptureError(f"{path}: {exc}") from exc
        except OSError as exc:
            raise CaptureError(f"{path}: {exc}") from exc
        sources.append(
            SourceStats(path=str(path), packets=packets, wire_bytes=wire, linktype=linktype)
        )
    return IndexResult(index=index, sources=sources)


def load_config(path: str | Path | None) -> dict[str, dict[str, object]]:
    """Load a rule threshold file.

    Unknown top-level keys are rejected: a typo in a threshold name would
    otherwise silently leave the default in place, which is exactly the kind of
    quiet misconfiguration a detection tool must not have.
    """
    if path is None:
        return {}
    from .rules import DEFAULT_CONFIG

    path = Path(path).expanduser()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise CaptureError(f"{path}: config file not found") from None
    except json.JSONDecodeError as exc:
        raise CaptureError(f"{path}: not valid JSON ({exc})") from exc
    if not isinstance(data, dict):
        raise CaptureError(f"{path}: config must be a JSON object mapping rule ids to settings")
    unknown = set(data) - set(DEFAULT_CONFIG)
    if unknown:
        raise CaptureError(
            f"{path}: unknown rule(s) {', '.join(sorted(unknown))}; "
            f"known rules are {', '.join(sorted(DEFAULT_CONFIG))}"
        )
    for rule, settings in data.items():
        if not isinstance(settings, dict):
            raise CaptureError(f"{path}: settings for {rule} must be an object")
        unknown_settings = set(settings) - set(DEFAULT_CONFIG[rule])
        if unknown_settings:
            raise CaptureError(
                f"{path}: unknown setting(s) for {rule}: {', '.join(sorted(unknown_settings))}"
            )
    return data


def analyze(
    paths: list[str],
    *,
    baseline: dict[str, object] | None = None,
    config: dict[str, dict[str, object]] | None = None,
) -> tuple[IndexResult, list[Alert], list[RuleStatus]]:
    """Full pipeline for a set of captures."""
    result = build_index(paths)
    alerts, statuses = run_rules(result.index, config=config, baseline=baseline)
    return result, alerts, statuses
