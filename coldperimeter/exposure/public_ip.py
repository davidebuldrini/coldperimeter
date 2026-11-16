"""Public address lookup and carrier-grade NAT detection."""

from __future__ import annotations

import ipaddress
import urllib.error
import urllib.request

from .. import USER_AGENT

ECHO_SERVICE = "https://api.ipify.org"
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def is_public(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global and addr not in _CGNAT


def fetch_public_ip(timeout: float = 5.0) -> str | None:
    """Ask a public echo service which address our traffic comes from."""
    request = urllib.request.Request(ECHO_SERVICE, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            ip = response.read(64).decode().strip()
    except (OSError, urllib.error.URLError):
        return None
    return ip if is_public(ip) else None


def behind_cgnat(wan_ip: str | None, public_ip: str | None) -> bool | None:
    """Tell whether the router's WAN address differs from the public one.

    ``True`` means the router sits behind another NAT (carrier-grade NAT or a
    second router): its own port forwards are then not directly reachable from
    the internet. ``None`` means there is not enough information.
    """
    if not wan_ip:
        return None
    if not is_public(wan_ip):
        return True
    if public_ip:
        return wan_ip != public_ip
    return False
