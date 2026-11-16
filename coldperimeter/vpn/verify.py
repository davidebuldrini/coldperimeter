"""Read-only check that a controller answers through the tunnel.

Run it from a machine connected to the VPN, before any direct access is
removed (plan step 3).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from ..discovery.hosts import validate_targets
from ..discovery.ports import is_open
from ..fingerprint import probe

TLS_PORTS = {443, 8443}


@dataclass
class VerifyResult:
    address: str
    port: int
    reachable: bool
    title: str | None = None


def verify_access(address: str, port: int, timeout: float = 5.0) -> VerifyResult:
    """Open one TCP connection and, if it answers HTTP, read the page title."""
    address = validate_targets([address])[0]
    if not 1 <= port <= 65535:
        raise ValueError(f"Port out of range: {port}")
    reachable = asyncio.run(is_open(address, port, timeout))
    result = VerifyResult(address=address, port=port, reachable=reachable)
    if reachable:
        # Shifted ports (gateway mode) keep the last digits of the real port.
        tls = (port % 10000) in TLS_PORTS
        observation = probe.http_get(address, port, tls, timeout)
        result.title = observation.title
    return result
