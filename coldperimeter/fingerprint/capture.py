"""Save raw observations so signatures can be refined from field data.

Capture files contain page titles, headers, body samples and unit names of the
customer's devices. They stay on the technician's laptop; nothing is uploaded.
Use ``sanitize`` before sharing a capture, for example in a pull request.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ..models import Host

REDACTED = "REDACTED"

_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_MAC = re.compile(r"\b((?:[0-9A-Fa-f]{2}[:-]){2}[0-9A-Fa-f]{2})((?:[:-][0-9A-Fa-f]{2}){3})\b")
_STORE_TAGS = re.compile(
    r"<(store_name|storeId1|storeId2)(\s*)>.*?</\1\s*>", re.IGNORECASE | re.DOTALL
)
_PRIVATE_FIELDS = {"store_name"}


def _scrub_text(text: str) -> str:
    text = _STORE_TAGS.sub(lambda m: f"<{m.group(1)}>{REDACTED}</{m.group(1)}>", text)
    text = _IPV4.sub("x.x.x.x", text)
    # Keep the manufacturer prefix: it is what the signatures match on.
    return _MAC.sub(lambda m: m.group(1) + re.sub(r"[0-9A-Fa-f]{2}", "00", m.group(2)), text)


def sanitize(value: Any, key: str | None = None) -> Any:
    """Return a copy with store names, IP addresses and device MACs removed."""
    if isinstance(value, dict):
        return {k: sanitize(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize(item, key) for item in value]
    if isinstance(value, str):
        return REDACTED if key in _PRIVATE_FIELDS else _scrub_text(value)
    return value


def save_capture(
    host: Host, directory: Path, sanitized: bool = False, index: int = 0
) -> Path | None:
    """Write one JSON file per host that has at least one open port."""
    if not host.open_ports:
        return None
    directory.mkdir(parents=True, exist_ok=True)
    data = asdict(host)
    if sanitized:
        data = sanitize(data)
        name = f"device-{index + 1}.json"
    else:
        name = f"{host.ip.replace('.', '_')}.json"
    path = directory / name
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path
