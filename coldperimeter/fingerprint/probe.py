"""Read-only application probes.

Two requests at most are sent to a host's web port:

* ``GET /`` to read the page title and the ``Server`` header;
* the ``read_units`` command of the Danfoss XML interface, which is documented
  by the vendor as a read command and returns the unit identity.

No credentials are ever sent and no write command exists in this module.
Every request uses its own connection and ``Connection: close`` because the
vendor documentation states the system managers accept one request per
connection and need several seconds between requests.
"""

from __future__ import annotations

import http.client
import re
import ssl

from .. import USER_AGENT
from ..models import HttpObservation, XmlIdentity

MAX_BODY = 65536
BODY_SAMPLE = 2000
XML_PATH = "/xml.cgi"
XML_READ_UNITS = '<cmd action="read_units"/>'

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_RESP = re.compile(r"<resp\b[^>]*>", re.IGNORECASE)
_ERROR_ATTR = re.compile(r'\berror\s*=\s*"([^"]*)"', re.IGNORECASE)
_INTERNET_UNIT = re.compile(
    r"<unit_internet\s*>(.*?)</unit_internet\s*>", re.IGNORECASE | re.DOTALL
)


def _connection(
    ip: str, port: int, tls: bool, timeout: float
) -> http.client.HTTPConnection:
    if not tls:
        return http.client.HTTPConnection(ip, port, timeout=timeout)
    # Controllers ship self-signed certificates; we only read public pages.
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return http.client.HTTPSConnection(ip, port, timeout=timeout, context=context)


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _tag(text: str, name: str) -> str | None:
    match = re.search(
        rf"<{name}\s*>\s*(.*?)\s*</{name}\s*>", text, re.IGNORECASE | re.DOTALL
    )
    return match.group(1).strip() if match else None


def http_get(ip: str, port: int, tls: bool, timeout: float = 5.0) -> HttpObservation:
    obs = HttpObservation(port=port, tls=tls)
    conn = _connection(ip, port, tls, timeout)
    try:
        conn.request(
            "GET", "/", headers={"User-Agent": USER_AGENT, "Connection": "close"}
        )
        resp = conn.getresponse()
        body = _decode(resp.read(MAX_BODY))
        obs.status = resp.status
        obs.server = resp.getheader("Server")
        title = _TITLE.search(body)
        if title:
            obs.title = " ".join(title.group(1).split())[:200]
        obs.body_sample = body[:BODY_SAMPLE]
    except (OSError, http.client.HTTPException) as exc:
        obs.error = f"{type(exc).__name__}: {exc}"
    finally:
        conn.close()
    return obs


def parse_read_units(text: str, port: int, tls: bool) -> XmlIdentity:
    """Extract the identity fields from a ``read_units`` response."""
    ident = XmlIdentity(port=port, tls=tls, raw=text[:BODY_SAMPLE])
    resp = _RESP.search(text)
    if not resp:
        return ident
    ident.responded = True
    error = _ERROR_ATTR.search(resp.group(0))
    ident.error_code = error.group(1) if error else None
    ident.store_name = _tag(text, "store_name")
    ident.unit_name = _tag(text, "unit_name")
    ident.software = _tag(text, "software")
    ident.mac = _tag(text, "macaddr")
    for block in _INTERNET_UNIT.findall(text):
        ip = _tag(block, "ip")
        if ip:
            ident.internet_addrs.append({"ip": ip, "port": _tag(block, "port") or ""})
    return ident


def xml_read_units(
    ip: str, port: int, tls: bool, timeout: float = 5.0
) -> XmlIdentity:
    conn = _connection(ip, port, tls, timeout)
    try:
        conn.request(
            "POST",
            XML_PATH,
            body=XML_READ_UNITS,
            headers={
                "User-Agent": USER_AGENT,
                "Connection": "close",
                "Content-Type": "text/xml",
                "Accept": "text/xml",
            },
        )
        resp = conn.getresponse()
        return parse_read_units(_decode(resp.read(MAX_BODY)), port, tls)
    except (OSError, http.client.HTTPException) as exc:
        ident = XmlIdentity(port=port, tls=tls)
        ident.raw = f"{type(exc).__name__}: {exc}"
        return ident
    finally:
        conn.close()
