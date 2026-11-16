"""Probe server: tests TCP ports on the caller's own address, nothing else.

Abuse resistance is structural, not policy:

* the request has no target field (unknown fields are rejected), so the only
  address ever probed is the one the HTTP request came from;
* the number of ports per request is capped and requests are rate limited;
* callers on private or loopback addresses are refused unless the server is
  started in test mode.

Deploy it directly on a public address. Behind a reverse proxy the caller's
address would be the proxy's: forwarded headers are deliberately NOT trusted.

Run with:  uvicorn probe_server.app:app --host 0.0.0.0 --port 8443
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import ssl
import time

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

MAX_PORTS = 32
CONNECT_TIMEOUT = 3.0
TLS_PORTS = {443, 8443}
_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


class ProbeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ports: list[int] = Field(min_length=1, max_length=MAX_PORTS)


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global and addr not in _CGNAT


async def _read_title(ip: str, port: int) -> str | None:
    """Fetch ``/`` and return the page title, if the port speaks HTTP."""
    context = None
    if port in TLS_PORTS:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=context), CONNECT_TIMEOUT
        )
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return None
    try:
        writer.write(
            f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: ColdPerimeter-probe\r\n\r\n".encode()
        )
        await writer.drain()
        data = await asyncio.wait_for(reader.read(32768), CONNECT_TIMEOUT)
    except (OSError, asyncio.TimeoutError):
        return None
    finally:
        writer.close()
    match = _TITLE.search(data)
    if not match:
        return None
    return " ".join(match.group(1).decode("utf-8", errors="replace").split())[:200]


async def _probe_port(ip: str, port: int) -> dict:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), CONNECT_TIMEOUT
        )
    except (OSError, asyncio.TimeoutError):
        return {"open": False, "title": None}
    writer.close()
    return {"open": True, "title": await _read_title(ip, port)}


def create_app(
    *,
    token: str | None = None,
    allow_private: bool = False,
    min_interval: float = 30.0,
) -> FastAPI:
    app = FastAPI(title="ColdPerimeter probe", docs_url=None, redoc_url=None)
    last_seen: dict[str, float] = {}

    @app.get("/v1/health")
    async def health() -> dict:
        return {"status": "ok"}

    @app.post("/v1/probe")
    async def probe(body: ProbeRequest, request: Request) -> dict:
        if token and request.headers.get("authorization") != f"Bearer {token}":
            raise HTTPException(status_code=401, detail="Invalid token.")
        if request.client is None:
            raise HTTPException(status_code=400, detail="Caller address unknown.")
        caller = request.client.host
        if not _is_public(caller) and not allow_private:
            raise HTTPException(
                status_code=400, detail="Caller is not on a public address."
            )
        for port in body.ports:
            if not 1 <= port <= 65535:
                raise HTTPException(status_code=422, detail=f"Invalid port: {port}")

        now = time.monotonic()
        if now - last_seen.get(caller, -min_interval) < min_interval:
            raise HTTPException(status_code=429, detail="Too many requests.")
        last_seen[caller] = now

        ports = sorted(set(body.ports))
        results = await asyncio.gather(*(_probe_port(caller, p) for p in ports))
        return {"ip": caller, "ports": {str(p): r for p, r in zip(ports, results)}}

    return app


app = create_app(
    token=os.environ.get("COLDPERIMETER_PROBE_TOKEN") or None,
    allow_private=os.environ.get("COLDPERIMETER_PROBE_ALLOW_PRIVATE") == "1",
)
