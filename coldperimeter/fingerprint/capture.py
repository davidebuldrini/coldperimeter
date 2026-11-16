"""Save raw observations so signatures can be refined from field data.

Capture files contain page titles, headers, body samples and unit names of the
customer's devices. They stay on the technician's laptop; nothing is uploaded.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from ..models import Host


def save_capture(host: Host, directory: Path) -> Path | None:
    """Write one JSON file per host that exposes a web or industrial port."""
    if not host.open_ports:
        return None
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{host.ip.replace('.', '_')}.json"
    path.write_text(json.dumps(asdict(host), indent=2), encoding="utf-8")
    return path
