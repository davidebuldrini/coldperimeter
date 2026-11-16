"""Local-network part of a scan: hosts, ports, probes, identification."""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .discovery import hosts as host_discovery
from .discovery.ports import DEFAULT_PORTS, PortSpec, scan_hosts
from .fingerprint import probe
from .fingerprint.capture import save_capture
from .fingerprint.engine import identify, load_signatures, vendor_for_mac
from .models import Host

WEB_ROLES = ("http", "https")
MAX_WEB_PORTS_PER_HOST = 2

# Progress callback: (stage, message, done, total). ``done``/``total`` are
# ``None`` for plain messages and numbers for per-host counters.
Progress = Callable[[str, str, int | None, int | None], None]

STAGE_HOSTS = "hosts"
STAGE_PORTS = "ports"
STAGE_IDENTITY = "identity"


@dataclass
class ScanOptions:
    network: ipaddress.IPv4Network | None = None
    targets: list[str] = field(default_factory=list)
    allow_large: bool = False
    port_specs: tuple[PortSpec, ...] = DEFAULT_PORTS
    port_delay: float = 0.2
    connect_timeout: float = 1.5
    # Vendor guidance: older system managers need about 5 s between requests.
    request_gap: float = 5.0
    xml_probe: bool = True
    capture_dir: Path | None = None


def _emit(
    progress: Progress | None,
    stage: str,
    message: str,
    done: int | None = None,
    total: int | None = None,
) -> None:
    if progress:
        progress(stage, message, done, total)


async def _probe_host(host: Host, options: ScanOptions) -> None:
    """Send the read-only web probes to one host, one request at a time."""
    web_ports = [p for p in host.open_ports if p.role in WEB_ROLES]
    web_ports = web_ports[:MAX_WEB_PORTS_PER_HOST]
    first = True
    for port in web_ports:
        if not first:
            await asyncio.sleep(options.request_gap)
        first = False
        observation = await asyncio.to_thread(
            probe.http_get, host.ip, port.port, port.role == "https"
        )
        host.http.append(observation)

    if not options.xml_probe:
        return
    answered = [o for o in host.http if o.error is None]
    if not answered:
        return
    target = answered[0]
    await asyncio.sleep(options.request_gap)
    host.xml = await asyncio.to_thread(
        probe.xml_read_units, host.ip, target.port, target.tls
    )


async def scan_local(
    options: ScanOptions, progress: Progress | None = None
) -> tuple[str, list[Host]]:
    """Discover, probe and identify hosts. Returns ``(scope, hosts)``."""
    if options.targets:
        addresses = host_discovery.validate_targets(options.targets)
        scope = ", ".join(addresses)
    else:
        network = options.network or host_discovery.default_network()
        host_discovery.validate_network(network, options.allow_large)
        scope = str(network)
        _emit(progress, STAGE_HOSTS, f"Looking for live hosts in {network} ...")
        addresses = await host_discovery.discover_hosts(network)
    total = len(addresses)
    _emit(progress, STAGE_HOSTS, f"{total} host(s) to check.", total, total)

    _emit(progress, STAGE_PORTS, "Checking ports (slow on purpose) ...", 0, total)
    checked = 0

    def port_scan_done() -> None:
        nonlocal checked
        checked += 1
        _emit(progress, STAGE_PORTS, "", checked, total)

    open_ports = await scan_hosts(
        addresses,
        options.port_specs,
        delay=options.port_delay,
        timeout=options.connect_timeout,
        on_host_done=port_scan_done,
    )

    arp = host_discovery.read_arp_table()
    databases = load_signatures()
    hosts = [
        Host(
            ip=ip,
            mac=arp.get(ip),
            vendor=vendor_for_mac(arp.get(ip), databases),
            open_ports=open_ports.get(ip, []),
        )
        for ip in addresses
    ]

    to_probe = [h for h in hosts if h.open_ports]
    _emit(
        progress, STAGE_IDENTITY, "Reading device identity (read-only) ...", 0, len(to_probe)
    )
    limiter = asyncio.Semaphore(4)
    probed = 0

    async def guarded(host: Host) -> None:
        nonlocal probed
        async with limiter:
            await _probe_host(host, options)
        probed += 1
        _emit(progress, STAGE_IDENTITY, "", probed, len(to_probe))

    await asyncio.gather(*(guarded(h) for h in to_probe))

    for host in hosts:
        host.device = identify(host, databases)
        if options.capture_dir:
            save_capture(host, options.capture_dir)

    found = sum(1 for h in hosts if h.device)
    _emit(
        progress,
        STAGE_IDENTITY,
        f"{found} controller candidate(s) identified.",
        len(to_probe),
        len(to_probe),
    )
    return scope, hosts
