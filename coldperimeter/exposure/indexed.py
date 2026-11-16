"""Check whether the site's public address is already in a public index.

Uses Shodan InternetDB, a free keyless lookup. If the address is listed there,
attackers browsing the same index can already see the open ports.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from .. import USER_AGENT
from .public_ip import is_public

INDEX_URL = "https://internetdb.shodan.io/"


def lookup_index(public_ip: str, timeout: float = 8.0) -> dict[str, Any] | None:
    """Return ``{"ports": [...], "vulns": [...]}`` or ``None`` if not checked.

    An address that is absent from the index yields empty lists.
    """
    if not is_public(public_ip):
        return None
    request = urllib.request.Request(
        INDEX_URL + public_ip, headers={"User-Agent": USER_AGENT}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            data = json.loads(response.read(262144))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"ports": [], "vulns": []}
        return None
    except (OSError, urllib.error.URLError, ValueError):
        return None
    return {
        "ports": [int(p) for p in data.get("ports", [])],
        "vulns": [str(v) for v in data.get("vulns", [])],
    }
