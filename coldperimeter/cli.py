"""Command line entry point: ``coldperimeter scan | report | capture``."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, exposure
from .consent import ConsentError, collect_consent
from .discovery.hosts import ScopeError
from .discovery.ports import DEFAULT_PORTS, parse_port_specs
from .exposure import checklist
from .findings.rules import evaluate
from .models import ScanResult
from .report.plan import available_languages, load_locale, render_html, render_markdown
from .scanner import ScanOptions, scan_local


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _progress(message: str) -> None:
    print(message, file=sys.stderr)


def _add_scope_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--site", help="name of the store being audited")
    parser.add_argument("--authorized-by", help="who authorized this audit")
    parser.add_argument("--operator", help="technician running the scan")
    parser.add_argument("--network", help="network to scan, e.g. 192.168.1.0/24 (default: local /24)")
    parser.add_argument("--targets", nargs="+", default=[], help="scan only these private addresses")
    parser.add_argument("--allow-large", action="store_true", help="allow networks above 1024 addresses")
    parser.add_argument("--ports", help="ports to check, e.g. 80,443 or http:8081,modbus:1502")
    parser.add_argument("--port-delay", type=float, default=0.2, help="seconds between ports on one host")
    parser.add_argument("--request-gap", type=float, default=5.0, help="seconds between requests to one host")
    parser.add_argument("--no-xml-probe", action="store_true", help="skip the read_units identity request")


def _scan_options(args: argparse.Namespace, capture_dir: Path | None) -> ScanOptions:
    return ScanOptions(
        network=ipaddress.ip_network(args.network, strict=False) if args.network else None,
        targets=args.targets,
        allow_large=args.allow_large,
        port_specs=parse_port_specs(args.ports) if args.ports else DEFAULT_PORTS,
        port_delay=args.port_delay,
        request_gap=args.request_gap,
        xml_probe=not args.no_xml_probe,
        capture_dir=capture_dir,
    )


def _write_reports(result: ScanResult, out_dir: Path, lang: str) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "scan.json").write_text(
        json.dumps(result.to_dict(), indent=2), encoding="utf-8"
    )
    (out_dir / "report.html").write_text(render_html(result, lang), encoding="utf-8")
    (out_dir / "report.md").write_text(render_markdown(result, lang), encoding="utf-8")
    print(f"Report written to {out_dir / 'report.html'}")


def cmd_scan(args: argparse.Namespace) -> int:
    locale = load_locale(args.lang)
    consent = collect_consent(args.site, args.authorized_by, args.operator)
    options = _scan_options(args, Path(args.capture_dir) if args.capture_dir else None)

    started = _now()
    scope, hosts = asyncio.run(scan_local(options, _progress))

    _progress("Checking exposure to the internet ...")
    exposure_result = exposure.assess(
        igd_url=args.igd_url,
        probe_url=args.probe_url,
        offline=args.offline,
        use_upnp=not args.no_upnp,
    )
    for error in exposure_result.errors:
        _progress(f"  note: {error}")

    if args.checklist_file:
        answers = checklist.load_answers(Path(args.checklist_file))
    elif args.no_checklist:
        answers = checklist.unanswered()
    else:
        answers = checklist.ask_interactively(locale["checklist"])

    result = ScanResult(
        tool_version=__version__,
        started_at=started,
        finished_at=_now(),
        consent=consent,
        scope=scope,
        hosts=hosts,
        exposure=exposure_result,
        checklist=answers,
        findings=evaluate(hosts, exposure_result, answers),
    )
    _write_reports(result, Path(args.out), args.lang)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    data = json.loads(Path(args.scan_file).read_text(encoding="utf-8"))
    result = ScanResult.from_dict(data)
    if args.reevaluate:
        result.findings = evaluate(result.hosts, result.exposure, result.checklist)
    _write_reports(result, Path(args.out), args.lang)
    return 0


def cmd_capture(args: argparse.Namespace) -> int:
    collect_consent(args.site, args.authorized_by, args.operator)
    if not args.targets:
        raise ScopeError("capture needs --targets with the device address(es).")
    out_dir = Path(args.out)
    _, hosts = asyncio.run(scan_local(_scan_options(args, out_dir), _progress))
    saved = sum(1 for h in hosts if h.open_ports)
    print(f"{saved} capture file(s) written to {out_dir}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="coldperimeter",
        description="Read-only exposure audit for refrigeration controllers.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    languages = available_languages()

    scan = commands.add_parser("scan", help="audit the local network and write a report")
    _add_scope_arguments(scan)
    scan.add_argument("--probe-url", help="URL of a ColdPerimeter probe server for the outside-in test")
    scan.add_argument("--igd-url", help="router UPnP description URL (skips discovery)")
    scan.add_argument("--no-upnp", action="store_true", help="do not query the router over UPnP")
    scan.add_argument("--offline", action="store_true", help="make no request to the internet")
    scan.add_argument("--checklist-file", help="YAML file with on-site checklist answers")
    scan.add_argument("--no-checklist", action="store_true", help="skip the on-site questions")
    scan.add_argument("--capture-dir", help="also save raw device observations here")
    scan.add_argument("--lang", default="en", choices=languages, help="report language")
    scan.add_argument("--out", default="out", help="output directory")
    scan.set_defaults(func=cmd_scan)

    report = commands.add_parser("report", help="rebuild the report from a saved scan.json")
    report.add_argument("scan_file")
    report.add_argument("--reevaluate", action="store_true", help="re-apply the rules to the saved data")
    report.add_argument("--lang", default="en", choices=languages, help="report language")
    report.add_argument("--out", default="out", help="output directory")
    report.set_defaults(func=cmd_report)

    capture = commands.add_parser(
        "capture", help="save raw observations of given devices to refine signatures"
    )
    _add_scope_arguments(capture)
    capture.add_argument("--out", default="captures", help="output directory")
    capture.set_defaults(func=cmd_capture)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ConsentError, ScopeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
