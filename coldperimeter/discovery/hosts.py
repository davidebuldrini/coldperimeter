"""Find live hosts without raw sockets or administrator rights.

Uses the operating system's own ``ping`` and ARP table. The scope is
restricted to private (RFC 1918) or loopback addresses: this tool is meant for
the network the technician is standing in, never for the internet.
"""

from __future__ import annotations

import asyncio
import ipaddress
import platform
import re
import socket
import subprocess

MAX_DEFAULT_ADDRESSES = 1024

_ARP_LINE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})\D+?"
    r"((?:[0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2})"
)


class ScopeError(Exception):
    """Raised when the requested targets are outside the allowed scope."""


def local_ipv4() -> str | None:
    """Return the address of the interface used for the default route.

    Connecting a UDP socket sends no packet; it only asks the OS which source
    address it would use.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 9))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def default_network() -> ipaddress.IPv4Network:
    """Guess the local network as the /24 around the local address."""
    ip = local_ipv4()
    if ip is None:
        raise ScopeError("Cannot determine the local address; pass --network.")
    return ipaddress.ip_network(f"{ip}/24", strict=False)


def validate_network(
    network: ipaddress.IPv4Network, allow_large: bool = False
) -> None:
    if not (network.is_private or network.is_loopback):
        raise ScopeError(
            f"{network} is not a private network. ColdPerimeter only scans "
            "local networks."
        )
    if network.num_addresses > MAX_DEFAULT_ADDRESSES and not allow_large:
        raise ScopeError(
            f"{network} has {network.num_addresses} addresses. "
            "Narrow the range or pass --allow-large."
        )


def validate_targets(targets: list[str]) -> list[str]:
    """Check that every explicit target is a private or loopback IPv4 address."""
    checked = []
    for raw in targets:
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise ScopeError(f"{raw!r} is not an IP address.") from exc
        if ip.version != 4 or not (ip.is_private or ip.is_loopback):
            raise ScopeError(
                f"{raw} is not a private IPv4 address. ColdPerimeter only "
                "scans local networks."
            )
        checked.append(str(ip))
    return checked


def _ping_command(ip: str) -> list[str]:
    system = platform.system()
    if system == "Windows":
        return ["ping", "-n", "1", "-w", "1000", ip]
    if system == "Darwin":
        return ["ping", "-c", "1", "-W", "1000", ip]
    return ["ping", "-c", "1", "-W", "1", ip]


async def _ping(ip: str, limiter: asyncio.Semaphore) -> bool:
    async with limiter:
        try:
            proc = await asyncio.create_subprocess_exec(
                *_ping_command(ip),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            return await asyncio.wait_for(proc.wait(), timeout=3) == 0
        except (OSError, asyncio.TimeoutError):
            return False


async def ping_sweep(
    network: ipaddress.IPv4Network, concurrency: int = 16
) -> set[str]:
    """Send one echo request to every host address; return those answering."""
    limiter = asyncio.Semaphore(concurrency)
    ips = [str(ip) for ip in network.hosts()]
    results = await asyncio.gather(*(_ping(ip, limiter) for ip in ips))
    return {ip for ip, alive in zip(ips, results) if alive}


def normalize_mac(mac: str) -> str:
    parts = re.split(r"[:-]", mac)
    return ":".join(p.zfill(2).upper() for p in parts)


def parse_arp_table(text: str) -> dict[str, str]:
    """Parse ``arp -a`` output from macOS, Linux or Windows."""
    table: dict[str, str] = {}
    for line in text.splitlines():
        match = _ARP_LINE.search(line)
        if not match:
            continue
        mac = normalize_mac(match.group(2))
        if mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
            continue
        if mac.startswith("01:00:5E"):  # IPv4 multicast
            continue
        table[match.group(1)] = mac
    return table


def read_arp_table() -> dict[str, str]:
    try:
        out = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=15, check=False
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return {}
    return parse_arp_table(out)


async def discover_hosts(network: ipaddress.IPv4Network) -> list[str]:
    """Return live addresses in ``network``: ping responders plus ARP entries.

    Devices that drop ICMP still appear in the ARP table after the sweep, so
    both sources are merged.
    """
    alive = await ping_sweep(network)
    for ip in read_arp_table():
        if ipaddress.ip_address(ip) in network:
            alive.add(ip)
    alive.discard(str(network.network_address))
    alive.discard(str(network.broadcast_address))
    own = local_ipv4()
    if own:
        alive.discard(own)
    return sorted(alive, key=lambda a: int(ipaddress.ip_address(a)))
