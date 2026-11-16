"""Command line entry point: ``coldperimeter scan | report | capture | vpn | ui``."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import sys
from pathlib import Path

from . import __version__
from .consent import ConsentError, collect_consent
from .discovery.hosts import ScopeError
from .discovery.ports import DEFAULT_PORTS, parse_port_specs
from .exposure import checklist
from .findings.rules import evaluate
from .fingerprint.capture import save_capture
from .models import ScanResult
from .report.plan import available_languages, load_locale
from .scanner import ScanOptions, scan_local
from .service import ScanCancelled, ScanRequest, apply_checklist, run_scan, write_reports


def _progress(stage: str, message: str, done: int | None, total: int | None) -> None:
    if message:
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


def _scan_options(args: argparse.Namespace, capture_dir: Path | None = None) -> ScanOptions:
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


def _write(result: ScanResult, out_dir: Path, lang: str) -> None:
    print(f"Report written to {write_reports(result, out_dir, lang)}")


def cmd_scan(args: argparse.Namespace) -> int:
    locale = load_locale(args.lang)
    answers = None
    if args.checklist_file:
        answers = checklist.load_answers(Path(args.checklist_file))
    request = ScanRequest(
        site_name=args.site,
        authorized_by=args.authorized_by,
        operator=args.operator,
        options=_scan_options(args, Path(args.capture_dir) if args.capture_dir else None),
        igd_url=args.igd_url,
        probe_url=args.probe_url,
        offline=args.offline,
        use_upnp=not args.no_upnp,
        checklist=answers,
    )
    result = run_scan(request, _progress)
    if answers is None and not args.no_checklist:
        apply_checklist(result, checklist.ask_interactively(locale["checklist"]))
    _write(result, Path(args.out), args.lang)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    data = json.loads(Path(args.scan_file).read_text(encoding="utf-8"))
    result = ScanResult.from_dict(data)
    if args.reevaluate:
        result.findings = evaluate(result.hosts, result.exposure, result.checklist)
    _write(result, Path(args.out), args.lang)
    return 0


def cmd_capture(args: argparse.Namespace) -> int:
    collect_consent(args.site, args.authorized_by, args.operator)
    if not args.targets:
        raise ScopeError("capture needs --targets with the device address(es).")
    out_dir = Path(args.out)
    _, hosts = asyncio.run(scan_local(_scan_options(args), _progress))
    saved = [
        path
        for index, host in enumerate(hosts)
        if (path := save_capture(host, out_dir, args.sanitize, index))
    ]
    print(f"{len(saved)} capture file(s) written to {out_dir}")
    if args.sanitize:
        print("Sanitized: review the files before sharing them all the same.")
    return 0


def cmd_vpn_init(args: argparse.Namespace) -> int:
    from .vpn.output import save_plan
    from .vpn.wireguard import VpnRequest, build_plan

    plan = build_plan(
        VpnRequest(
            topology=args.topology,
            endpoint_host=args.endpoint,
            endpoint_port=args.endpoint_port,
            controller_ips=args.controller,
            controller_ports=[int(p) for p in args.ports.split(",")],
            store_device=args.store_device,
            store_number=args.store_number,
            technician_number=args.technician_number,
            server_public_key=args.server_public_key,
        )
    )
    paths = save_plan(plan, Path(args.out), load_locale(args.lang)["vpn"])
    for path in paths:
        print(path)
    print("These files contain private keys. Nothing was changed on any device.")
    return 0


def cmd_vpn_verify(args: argparse.Namespace) -> int:
    from .vpn.verify import verify_access

    result = verify_access(args.address, args.port)
    if result.reachable:
        title = f" (page title: {result.title})" if result.title else ""
        print(f"Reachable: {result.address}:{result.port}{title}")
        return 0
    print(f"NOT reachable: {result.address}:{result.port}")
    return 1


def cmd_ui(args: argparse.Namespace) -> int:
    from .gui.app import run

    return run(browser=args.browser, port=args.port)


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
    capture.add_argument("--sanitize", action="store_true",
                         help="remove store names, IP addresses and device MACs")
    capture.add_argument("--out", default="captures", help="output directory")
    capture.set_defaults(func=cmd_capture)

    vpn = commands.add_parser("vpn", help="guided WireGuard setup (generates files only)")
    vpn_commands = vpn.add_subparsers(dest="vpn_command", required=True)

    init = vpn_commands.add_parser("init", help="generate WireGuard configuration files")
    init.add_argument("--topology", choices=("direct", "hub"), default="direct",
                      help="direct: store dials the maintenance center; hub: both dial a relay server")
    init.add_argument("--endpoint", required=True, help="public host name or address of the server")
    init.add_argument("--endpoint-port", type=int, default=51820)
    init.add_argument("--controller", nargs="+", required=True, help="controller address(es) in the store")
    init.add_argument("--ports", default="80,443", help="controller TCP ports to make reachable")
    init.add_argument("--store-device", choices=("gateway", "router"), default="gateway")
    init.add_argument("--store-number", type=int, default=1)
    init.add_argument("--technician-number", type=int, default=1)
    init.add_argument("--server-public-key", help="public key of an existing server (adds this store to it)")
    init.add_argument("--lang", default="en", choices=languages, help="language of the instructions")
    init.add_argument("--out", default="vpn", help="output directory")
    init.set_defaults(func=cmd_vpn_init)

    verify = vpn_commands.add_parser("verify", help="check a controller answers through the tunnel")
    verify.add_argument("--address", required=True)
    verify.add_argument("--port", type=int, default=80)
    verify.set_defaults(func=cmd_vpn_verify)

    ui = commands.add_parser("ui", help="open the graphical interface")
    ui.add_argument("--browser", action="store_true", help="use the web browser instead of a native window")
    ui.add_argument("--port", type=int, default=0, help="local port (default: random)")
    ui.set_defaults(func=cmd_ui)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ConsentError, ScopeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ScanCancelled:
        print("Scan stopped.", file=sys.stderr)
        return 130
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
