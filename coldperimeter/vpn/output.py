"""Write a VPN plan to disk: configuration files plus plain-language steps."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .wireguard import VpnPlan

INSTRUCTIONS_FILE = "INSTRUCTIONS.md"


def render_instructions(plan: VpnPlan, texts: dict[str, Any]) -> str:
    """Build the step list in the operator's language (``locale['vpn']``)."""
    request = plan.request
    server = texts["hub_name"] if request.topology == "hub" else texts["center_name"]
    endpoint = f"{request.endpoint_host}:{request.endpoint_port}"
    by_role = {f.role: f.name for f in plan.files}
    targets = ", ".join(
        f"{a.controller_ip}:{a.controller_port}" for a in plan.access
    )

    steps = []
    if "server" in by_role:
        steps.append(
            texts["server_new"].format(
                server=server, endpoint=endpoint, file=by_role["server"],
                port=request.endpoint_port,
            )
        )
    else:
        steps.append(
            texts["server_existing"].format(server=server, file=by_role["server-peer"])
        )
    store_key = "store_gateway" if request.store_device == "gateway" else "store_router"
    steps.append(texts[store_key].format(file=by_role["store"], targets=targets))
    if "technician" in by_role:
        steps.append(texts["technician"].format(file=by_role["technician"]))
    steps.append(texts["verify"])

    lines = [f"# {texts['instructions_title']}", "", texts["intro"], ""]
    lines += [f"{number}. {step}" for number, step in enumerate(steps, 1)]
    lines += ["", f"## {texts['access_title']}", ""]
    lines += [
        "- "
        + texts["access_line"].format(
            controller=a.controller_ip, controller_port=a.controller_port,
            address=a.address, port=a.port,
        )
        for a in plan.access
    ]
    notes = [texts["keys_warning"]]
    if request.topology == "direct" and "server" in by_role:
        notes.append(texts["direct_note"].format(file=by_role["server"]))
    if request.store_device == "router":
        notes.append(texts["router_note"])
    lines += ["", f"## {texts['notes_title']}", ""] + [f"- {note}" for note in notes]
    return "\n".join(lines) + "\n"


def save_plan(plan: VpnPlan, directory: Path, texts: dict[str, Any]) -> list[Path]:
    """Write every file with owner-only permissions; return the paths."""
    directory.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass  # not meaningful on every file system
    written = []
    for config in plan.files:
        path = directory / config.name
        # Create with restrictive permissions before any key is written.
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(config.content)
        written.append(path)
    instructions = directory / INSTRUCTIONS_FILE
    instructions.write_text(render_instructions(plan, texts), encoding="utf-8")
    written.append(instructions)
    return written
