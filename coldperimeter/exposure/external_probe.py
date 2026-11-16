"""Client for the ColdPerimeter probe server.

The probe server checks ports on the address the request comes from, so the
only way to test a site is to call it from inside that site's network. The
client never sends a target address.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from .. import USER_AGENT

TOKEN_ENV = "COLDPERIMETER_PROBE_TOKEN"
MAX_PORTS = 32


class ProbeError(Exception):
    pass


def run_probe(probe_url: str, ports: list[int], timeout: float = 60.0) -> dict[str, Any]:
    """Ask the probe server to test ``ports`` on our own public address.

    Returns ``{"ip": str, "ports": {"80": {"open": bool, "title": str|None}}}``.
    """
    headers = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}
    token = os.environ.get(TOKEN_ENV)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    payload = json.dumps({"ports": sorted(set(ports))[:MAX_PORTS]}).encode()
    request = urllib.request.Request(
        probe_url.rstrip("/") + "/v1/probe", data=payload, headers=headers
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            data = json.loads(response.read(262144))
    except (OSError, urllib.error.URLError, ValueError) as exc:
        raise ProbeError(f"Probe server request failed: {exc}") from exc
    if not isinstance(data, dict) or "ip" not in data or "ports" not in data:
        raise ProbeError("Probe server returned an unexpected answer.")
    return data
