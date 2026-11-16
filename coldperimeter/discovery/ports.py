"""Gentle TCP connect scan.

Old controllers have tiny network stacks, so each host is probed one port at a
time with a pause in between, and only a short fixed list of ports is tried.
No payload is sent: the connection is opened and closed.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from ..models import OpenPort


@dataclass(frozen=True)
class PortSpec:
    port: int
    role: str


DEFAULT_PORTS: tuple[PortSpec, ...] = (
    PortSpec(21, "ftp"),
    PortSpec(22, "ssh"),
    PortSpec(23, "telnet"),
    PortSpec(80, "http"),
    PortSpec(443, "https"),
    PortSpec(502, "modbus"),
    PortSpec(3001, "xml-legacy"),
    PortSpec(5900, "vnc"),
    PortSpec(8080, "http"),
)

_ROLE_BY_PORT = {spec.port: spec.role for spec in DEFAULT_PORTS}
KNOWN_ROLES = {spec.role for spec in DEFAULT_PORTS} | {"unknown"}


def parse_port_specs(text: str) -> tuple[PortSpec, ...]:
    """Parse ``80,443`` or ``http:18080,modbus:15020`` into port specs."""
    specs = []
    for item in text.split(","):
        item = item.strip()
        if not item:
            continue
        role, _, number = item.rpartition(":")
        port = int(number)
        if not 1 <= port <= 65535:
            raise ValueError(f"Port out of range: {port}")
        role = role or _ROLE_BY_PORT.get(port, "unknown")
        if role not in KNOWN_ROLES:
            raise ValueError(f"Unknown port role: {role}")
        specs.append(PortSpec(port, role))
    if not specs:
        raise ValueError("No ports given.")
    return tuple(specs)


async def is_open(ip: str, port: int, timeout: float = 1.5) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return True


async def scan_host(
    ip: str,
    specs: tuple[PortSpec, ...] = DEFAULT_PORTS,
    delay: float = 0.2,
    timeout: float = 1.5,
) -> list[OpenPort]:
    """Probe one host sequentially, pausing ``delay`` seconds between ports."""
    found = []
    for index, spec in enumerate(specs):
        if index:
            await asyncio.sleep(delay)
        if await is_open(ip, spec.port, timeout):
            found.append(OpenPort(spec.port, spec.role))
    return found


async def scan_hosts(
    ips: list[str],
    specs: tuple[PortSpec, ...] = DEFAULT_PORTS,
    delay: float = 0.2,
    timeout: float = 1.5,
    concurrency: int = 8,
) -> dict[str, list[OpenPort]]:
    """Scan several hosts; at most ``concurrency`` hosts at the same time."""
    limiter = asyncio.Semaphore(concurrency)

    async def one(ip: str) -> tuple[str, list[OpenPort]]:
        async with limiter:
            return ip, await scan_host(ip, specs, delay, timeout)

    return dict(await asyncio.gather(*(one(ip) for ip in ips)))
