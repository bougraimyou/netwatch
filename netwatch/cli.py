"""Command line interface.

Four verbs, because that is what the workflow actually needs: look at traffic,
remember what normal looks like, produce something shareable, and watch a
dashboard. Everything else is a flag on one of those.

Exit codes are part of the contract: 0 success, 1 alerts found *when asked to
fail on them*, 2 error. That is what makes ``netwatch analyze ... --fail-on-alerts``
usable as a check in a pipeline.
"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .baseline import build as build_baseline
from .baseline import load as load_baseline
from .baseline import save as save_baseline
from .collect import CaptureNotPermitted, collect
from .engine import CaptureError, analyze, build_index, load_config
from .report import build_report, to_json
from .rules import DEFAULT_CONFIG, RULE_DESCRIPTIONS
from .render import read_asset, render_html
from .serve import serve

__all__ = ["main", "build_parser"]

_COLOR = sys.stdout.isatty()


def _c(text: str, code: str) -> str:
    if not _COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def _bold(text: str) -> str:
    return _c(text, "1")


def _dim(text: str) -> str:
    return _c(text, "2")


_SEVERITY_COLOR = {
    "critical": "91",
    "high": "91",
    "medium": "93",
    "low": "94",
    "info": "90",
}


def _severity(text: str) -> str:
    return _c(text.upper().ljust(7), _SEVERITY_COLOR.get(text, "0"))


def _human_bytes(value: float) -> str:
    value = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def _parse_start(value: str | None) -> int | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"--start must be ISO 8601, e.g. 2026-10-21T08:00:00Z (got {value!r})"
        ) from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp() * 1e9)


def _capture_name(paths: list[str], sources) -> str:
    if len(sources) == 1:
        return Path(sources[0].path).name
    if len(paths) == 1:
        return Path(paths[0]).name or "captures"
    return f"{len(sources)} captures"


def _load_report(path: str | Path) -> dict[str, object]:
    """Read a report JSON and require the published shape.

    Everything downstream of a report file - the HTML renderer, the HTTP
    handler - indexes the document as the structure ``netwatch analyze``
    writes. A file that is valid JSON but not a report is refused here, with
    the file named, instead of surfacing as an AttributeError after the work
    has started. A baseline load does the same for its own shape.
    """
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise CaptureError(f"{path}: no such file") from None
    except json.JSONDecodeError as exc:
        raise CaptureError(f"{path}: not valid JSON ({exc})") from exc
    if not isinstance(data, dict):
        raise CaptureError(f"{path}: not a netwatch report file (top level must be a JSON object)")
    missing = [
        key
        for key, expected in (("capture", dict), ("alerts", list), ("rules", list), ("rule_summary", dict))
        if not isinstance(data.get(key), expected)
    ]
    if missing:
        raise CaptureError(
            f"{path}: not a netwatch report file (missing the "
            f"{', '.join(repr(key) for key in missing)} section(s))"
        )
    return data


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


def cmd_analyze(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    baseline = load_baseline(args.baseline) if args.baseline else None
    result, alerts, statuses = analyze(args.captures, baseline=baseline, config=config)
    report = build_report(
        result.index,
        alerts,
        statuses,
        capture_name=_capture_name(args.captures, result.sources),
        baseline=baseline,
    )

    if not args.quiet:
        _print_summary(report)
    if args.json:
        Path(args.json).write_text(to_json(report) + "\n", encoding="utf-8")
        if not args.quiet:
            print(f"  json    {args.json}")
    if args.html:
        Path(args.html).write_text(render_html(report), encoding="utf-8")
        if not args.quiet:
            print(f"  html    {args.html}")
    if not args.quiet:
        print()
    if args.fail_on_alerts and alerts:
        return 1
    return 0


def _print_summary(report: dict) -> None:
    capture = report["capture"]
    tool = report["tool"]
    print()
    print(f"  {_bold('NetWatch')} {_dim(tool['version'])}   {capture['name']}")
    print()
    print(
        f"  packets  {capture['packets']:>10,}     flows  {capture['flows']:>7,}     "
        f"hosts  {capture['hosts']:>5,}"
    )
    print(
        f"  traffic  {capture['wire_bytes_human']:>10}     window {_format_duration(capture['duration_s']):>7}     "
        f"alerts {len(report['alerts']):>5,}"
    )
    rules = report["rule_summary"]
    print(f"  rules    {rules['ran']} ran, {rules['skipped']} skipped")
    if report["alerts"]:
        print()
        for alert in report["alerts"]:
            print(f"  {_severity(alert['severity'])} {_bold(alert['title'])}")
            print(f"          {alert['summary']}")
    else:
        print()
        print(f"  {_c('No rule fired.', '32')}")
    skipped = [rule for rule in report["rules"] if not rule["ran"]]
    if skipped:
        print()
        for rule in skipped:
            print(f"  {_dim('skipped')}  {rule['name']}: {rule['skipped_reason']}")
    if report["limitations"]:
        print()
        for line in report["limitations"]:
            for wrapped in textwrap.wrap(line, width=96):
                print(f"  {_dim(wrapped)}")


def _format_duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m{seconds:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m"


def cmd_baseline(args: argparse.Namespace) -> int:
    result = build_index(args.captures)
    from .baseline import BaselineSource

    document = build_baseline(
        result.index,
        sources=[
            BaselineSource(path=source.path, packets=source.packets, duration_s=result.index.duration_s)
            for source in result.sources
        ],
        note=args.note or "",
    )
    save_baseline(args.out, document)
    print(
        f"  baseline written to {args.out}  "
        f"({len(document['hosts'])} internal hosts, {result.index.total_packets} packets)"
    )
    if not document["hosts"]:
        print(
            "  warning: no internal hosts found. Address scope treats private and reserved "
            "ranges as internal, so a capture of only public addresses produces an empty baseline.",
            file=sys.stderr,
        )
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    report = _load_report(args.report)
    Path(args.out).write_text(render_html(report), encoding="utf-8")
    print(f"  report written to {args.out}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    if args.report:
        # Read and validate before anything is bound: a bad report file must
        # end the process with exit 2, not leave a half-started dashboard
        # behind.
        report = _load_report(args.report)
    else:
        config = load_config(args.config)
        baseline = load_baseline(args.baseline) if args.baseline else None
        result, alerts, statuses = analyze(args.captures, baseline=baseline, config=config)
        report = build_report(
            result.index,
            alerts,
            statuses,
            capture_name=_capture_name(args.captures, result.sources),
            baseline=baseline,
        )

    try:
        server = serve(report, host=args.host, port=args.port)
    except OSError as exc:
        raise CaptureError(f"could not bind {args.host}:{args.port}: {exc}") from exc
    host, port = server.server_address[:2]
    url = f"http://{host}:{port}/"
    print(f"  NetWatch {__version__} serving {len(report.get('alerts', []))} alerts at {url}")
    print("  Ctrl-C to stop")
    if args.open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        server.server_close()
    return 0


def cmd_collect(args: argparse.Namespace) -> int:
    result = collect(
        args.iface,
        args.out,
        duration=args.duration,
        count=args.count,
        snaplen=args.snaplen,
        promiscuous=not args.no_promisc,
    )
    print(
        f"  captured {result.packets:,} packets ({_human_bytes(result.bytes)}) from {args.iface} "
        f"over {result.duration_s:.1f}s into {result.path} ({result.stopped_by})"
    )
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    from .demo import SCENARIOS
    from .demo import write as write_demo

    out = Path(args.out).expanduser()
    out.mkdir(parents=True, exist_ok=True)
    start_ns = _parse_start(args.start)

    if args.scenario:
        if args.scenario not in SCENARIOS:
            raise CaptureError(
                f"unknown scenario {args.scenario!r}; choose from {', '.join(sorted(SCENARIOS))}"
            )
        path = out / f"{args.scenario}.pcap"
        write_demo(path, args.scenario, seed=args.seed, start_ns=start_ns)
        print(f"  {args.scenario:<10} {path}  ({SCENARIOS[args.scenario].description})")
        return 0

    captures = out / "captures"
    captures.mkdir(exist_ok=True)
    for name in sorted(SCENARIOS):
        write_demo(captures / f"{name}.pcap", name, seed=args.seed, start_ns=start_ns)
        print(f"  generated {name:<10} {captures / (name + '.pcap')}")

    clean_result = build_index([str(captures / "clean.pcap")])
    document = build_baseline(clean_result.index, note="generated demo baseline")
    baseline_path = out / "baseline.json"
    save_baseline(baseline_path, document)

    result, alerts, statuses = analyze(
        [str(captures / "mixed.pcap")], baseline=document, config={}
    )
    report = build_report(
        result.index,
        alerts,
        statuses,
        capture_name="mixed.pcap",
        baseline=document,
    )
    (out / "report.json").write_text(to_json(report) + "\n", encoding="utf-8")
    (out / "report.html").write_text(render_html(report), encoding="utf-8")
    (out / "index.html").write_text(read_asset("index.html"), encoding="utf-8")
    (out / "app.js").write_text(read_asset("app.js"), encoding="utf-8")
    (out / "style.css").write_text(read_asset("style.css"), encoding="utf-8")
    print(f"  baseline   {baseline_path}")
    print(f"  report     {out / 'report.json'}  ({len(alerts)} alerts)")
    print(f"  dashboard  {out / 'index.html'}")
    print(f"  standalone {out / 'report.html'}")
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    print()
    print(f"  {_bold('NetWatch')} {_dim(__version__)} rules")
    print()
    for rule_id, description in RULE_DESCRIPTIONS.items():
        defaults = DEFAULT_CONFIG[rule_id]
        print(f"  {_bold(rule_id)}")
        for line in textwrap.wrap(description, width=88):
            print(f"    {line}")
        settings = ", ".join(
            f"{key}={value}" for key, value in defaults.items() if key != "enabled"
        )
        if settings:
            print(f"    {_dim(settings)}")
        print()
    return 0


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netwatch",
        description=(
            "Read packet captures, build a behavioural baseline, and report traffic "
            "that does not fit it. No runtime dependencies."
        ),
        epilog=(
            "Exit codes: 0 success, 1 alerts found with --fail-on-alerts, 2 error. "
            "Example: netwatch demo --out demo && open demo/report.html"
        ),
    )
    parser.add_argument("--version", action="version", version=f"netwatch {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True, metavar="command")

    analyze_parser = subparsers.add_parser(
        "analyze", help="analyze one or more captures"
    )
    analyze_parser.add_argument(
        "captures", nargs="+", help="pcap/pcapng files, .gz accepted, or a directory to search"
    )
    analyze_parser.add_argument("--baseline", help="baseline JSON from `netwatch baseline`")
    analyze_parser.add_argument("--config", help="rule thresholds as JSON")
    analyze_parser.add_argument("--json", help="write the report document here")
    analyze_parser.add_argument("--html", help="write a self-contained HTML report here")
    analyze_parser.add_argument(
        "--fail-on-alerts", action="store_true", help="exit 1 when any rule fires (for CI)"
    )
    analyze_parser.add_argument("-q", "--quiet", action="store_true", help="suppress the summary")
    analyze_parser.set_defaults(func=cmd_analyze)

    baseline_parser = subparsers.add_parser(
        "baseline", help="build a behavioural baseline from a capture you consider clean"
    )
    baseline_parser.add_argument("captures", nargs="+")
    baseline_parser.add_argument("--out", required=True, help="baseline JSON to write")
    baseline_parser.add_argument("--note", help="free text stored with the baseline")
    baseline_parser.set_defaults(func=cmd_baseline)

    report_parser = subparsers.add_parser(
        "report", help="render an existing report.json as standalone HTML"
    )
    report_parser.add_argument("report", help="report JSON produced by `netwatch analyze --json`")
    report_parser.add_argument("--out", required=True, help="HTML file to write")
    report_parser.set_defaults(func=cmd_report)

    serve_parser = subparsers.add_parser("serve", help="serve a dashboard over HTTP")
    serve_parser.add_argument("captures", nargs="*", help="captures to analyze on startup")
    serve_parser.add_argument("--report", help="serve an existing report JSON instead")
    serve_parser.add_argument("--baseline")
    serve_parser.add_argument("--config")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8080)
    serve_parser.add_argument("--open", action="store_true", help="open a browser")
    serve_parser.set_defaults(func=cmd_serve)

    collect_parser = subparsers.add_parser(
        "collect", help="capture live traffic to a pcap file (Linux, root)"
    )
    collect_parser.add_argument("--iface", required=True, help="interface name, e.g. eth0")
    collect_parser.add_argument("--out", required=True, help="pcap file to write")
    collect_parser.add_argument("--duration", type=float, help="stop after this many seconds")
    collect_parser.add_argument("--count", type=int, help="stop after this many packets")
    collect_parser.add_argument("--snaplen", type=int, default=262144)
    collect_parser.add_argument(
        "--no-promisc", action="store_true", help="stay in non-promiscuous mode"
    )
    collect_parser.set_defaults(func=cmd_collect)

    demo_parser = subparsers.add_parser(
        "demo", help="generate synthetic captures, a baseline and a demo report"
    )
    demo_parser.add_argument("--out", default="demo", help="directory to write into")
    demo_parser.add_argument("--scenario", help="generate just this capture")
    demo_parser.add_argument("--seed", type=int, default=7, help="PRNG seed for reproducibility")
    demo_parser.add_argument("--start", help="capture start time, ISO 8601")
    demo_parser.set_defaults(func=cmd_demo)

    rules_parser = subparsers.add_parser("rules", help="list the rules and their defaults")
    rules_parser.set_defaults(func=cmd_rules)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "serve" and not args.report and not args.captures:
        parser.error("serve needs either captures to analyze or --report FILE")
    try:
        return args.func(args)
    except (CaptureError, CaptureNotPermitted, ValueError, OSError) as exc:
        print(f"netwatch: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
