"""Read the router's port mappings through UPnP IGD.

Only query actions are used (``GetExternalIPAddress`` and
``GetGenericPortMappingEntry``). Nothing is added, changed or deleted.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlparse

from .. import USER_AGENT
from ..models import PortMapping

SSDP_ADDR = ("239.255.255.250", 1900)
SEARCH_TARGETS = (
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
)
MAX_MAPPINGS = 256

_SERVICE = re.compile(r"<service>(.*?)</service>", re.IGNORECASE | re.DOTALL)
_WAN_SERVICE = re.compile(r"urn:schemas-upnp-org:service:WAN(?:IP|PPP)Connection:[12]")


class UpnpError(Exception):
    pass


def _tag(text: str, name: str) -> str | None:
    match = re.search(rf"<{name}[^>]*>\s*(.*?)\s*</{name}>", text, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else None


def _is_local_url(url: str) -> bool:
    """Accept only gateways on a private or loopback address."""
    host = urlparse(url).hostname or ""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback


def discover_igd(timeout: float = 3.0) -> list[str]:
    """Send SSDP searches and return the description URLs of local gateways."""
    locations: list[str] = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(timeout)
    try:
        for target in SEARCH_TARGETS:
            message = (
                "M-SEARCH * HTTP/1.1\r\n"
                f"HOST: {SSDP_ADDR[0]}:{SSDP_ADDR[1]}\r\n"
                'MAN: "ssdp:discover"\r\n'
                "MX: 2\r\n"
                f"ST: {target}\r\n\r\n"
            )
            sock.sendto(message.encode(), SSDP_ADDR)
        while True:
            try:
                data, _ = sock.recvfrom(4096)
            except (socket.timeout, OSError):
                break
            match = re.search(rb"(?im)^location:\s*(\S+)", data)
            if match:
                url = match.group(1).decode(errors="replace")
                if _is_local_url(url) and url not in locations:
                    locations.append(url)
    except OSError:
        pass
    finally:
        sock.close()
    return locations


def _http(url: str, data: bytes | None = None, headers: dict | None = None) -> str:
    request = urllib.request.Request(
        url, data=data, headers={"User-Agent": USER_AGENT, **(headers or {})}
    )
    with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310
        return response.read(262144).decode("utf-8", errors="replace")


def _soap(control_url: str, service: str, action: str, arguments: str = "") -> str:
    body = (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        f'<s:Body><u:{action} xmlns:u="{service}">{arguments}</u:{action}></s:Body>'
        "</s:Envelope>"
    )
    return _http(
        control_url,
        data=body.encode(),
        headers={
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": f'"{service}#{action}"',
        },
    )


def find_wan_service(location: str) -> tuple[str, str]:
    """Return ``(service_type, control_url)`` of the gateway's WAN service."""
    if not _is_local_url(location):
        raise UpnpError(f"{location} is not a local address.")
    try:
        description = _http(location)
    except (OSError, urllib.error.URLError) as exc:
        raise UpnpError(f"Cannot read gateway description: {exc}") from exc
    base = _tag(description, "URLBase") or location
    for block in _SERVICE.findall(description):
        service_type = _tag(block, "serviceType") or ""
        control = _tag(block, "controlURL")
        if control and _WAN_SERVICE.fullmatch(service_type):
            return service_type, urljoin(base, control)
    raise UpnpError("Gateway exposes no WAN connection service.")


def query_igd(location: str) -> tuple[str | None, list[PortMapping]]:
    """Return the gateway's WAN address and its list of port mappings."""
    service, control = find_wan_service(location)

    wan_ip = None
    try:
        wan_ip = _tag(
            _soap(control, service, "GetExternalIPAddress"), "NewExternalIPAddress"
        )
    except (OSError, urllib.error.URLError):
        pass

    mappings: list[PortMapping] = []
    for index in range(MAX_MAPPINGS):
        try:
            reply = _soap(
                control,
                service,
                "GetGenericPortMappingEntry",
                f"<NewPortMappingIndex>{index}</NewPortMappingIndex>",
            )
        except (OSError, urllib.error.URLError):
            break  # the gateway answers with an error past the last entry
        internal_ip = _tag(reply, "NewInternalClient")
        external_port = _tag(reply, "NewExternalPort")
        if not internal_ip or not external_port:
            break
        mappings.append(
            PortMapping(
                external_port=int(external_port),
                protocol=(_tag(reply, "NewProtocol") or "TCP").upper(),
                internal_ip=internal_ip,
                internal_port=int(_tag(reply, "NewInternalPort") or external_port),
                description=_tag(reply, "NewPortMappingDescription") or "",
                enabled=(_tag(reply, "NewEnabled") or "1") == "1",
            )
        )
    return wan_ip, mappings
