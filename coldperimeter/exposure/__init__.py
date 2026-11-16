"""Work out whether, and how, the site is reachable from the internet."""

from __future__ import annotations

from ..models import Exposure
from . import external_probe, indexed, public_ip, upnp

# Ports always tested from outside, in addition to the router's mappings.
BASE_EXTERNAL_PORTS = (21, 22, 23, 80, 443, 502, 3001, 5900, 8080)


def assess(
    *,
    igd_url: str | None = None,
    probe_url: str | None = None,
    offline: bool = False,
    use_upnp: bool = True,
) -> Exposure:
    """Run every exposure check that is enabled and collect the results.

    ``offline`` disables the three checks that talk to the internet (public
    address lookup, external probe, public index). The router query stays on
    because it never leaves the local network.
    """
    result = Exposure()

    if use_upnp:
        locations = [igd_url] if igd_url else upnp.discover_igd()
        for location in locations:
            try:
                wan_ip, mappings = upnp.query_igd(location)
            except upnp.UpnpError as exc:
                result.errors.append(str(exc))
                continue
            result.upnp_found = True
            result.igd_url = location
            result.wan_ip = wan_ip
            result.mappings = mappings
            break

    if offline:
        result.behind_cgnat = public_ip.behind_cgnat(result.wan_ip, None)
        return result

    if probe_url:
        ports = set(BASE_EXTERNAL_PORTS)
        ports.update(m.external_port for m in result.mappings if m.protocol == "TCP")
        try:
            answer = external_probe.run_probe(probe_url, sorted(ports))
        except external_probe.ProbeError as exc:
            result.errors.append(str(exc))
        else:
            result.external_checked = True
            result.public_ip = answer["ip"]
            result.external_ports = {
                str(port): {"open": bool(info.get("open")), "title": info.get("title")}
                for port, info in answer["ports"].items()
            }

    if not result.public_ip:
        result.public_ip = public_ip.fetch_public_ip()

    result.behind_cgnat = public_ip.behind_cgnat(result.wan_ip, result.public_ip)

    if result.public_ip:
        listing = indexed.lookup_index(result.public_ip)
        if listing is not None:
            result.index_checked = True
            result.indexed_ports = listing["ports"]
            result.indexed_vulns = listing["vulns"]

    return result
