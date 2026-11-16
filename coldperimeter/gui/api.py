"""Local HTTP API for the graphical interface.

The server is reachable only from this computer, and still treats every
request as untrusted: a web page open in the user's browser could try to call
it. Three guards apply to every ``/api/`` request:

* a random per-session token in the ``X-ColdPerimeter-Token`` header;
* a ``Host`` header check, which defeats DNS rebinding;
* no CORS headers, so other origins cannot read responses.
"""

from __future__ import annotations

import ipaddress
import os
import platform
import secrets
import subprocess
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from .. import __version__
from ..consent import ConsentError
from ..discovery import hosts as host_discovery
from ..discovery.ports import DEFAULT_PORTS, parse_port_specs
from ..exposure.checklist import QUESTIONS
from ..models import ScanResult
from ..report.plan import available_languages, load_locale, result_view
from ..scanner import ScanOptions
from ..service import ScanRequest, slugify, write_reports
from ..vpn.output import render_instructions, save_plan
from ..vpn.verify import verify_access
from ..vpn.wireguard import VpnConfigError, VpnRequest, build_plan
from .jobs import Job, JobManager

STATIC_DIR = Path(__file__).parent / "static"
TOKEN_HEADER = "x-coldperimeter-token"
CSP = "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ScanStart(_Strict):
    site_name: str = ""
    authorized_by: str = ""
    operator: str = ""
    confirmed: bool = False
    network: str | None = None
    targets: list[str] = Field(default_factory=list, max_length=64)
    offline: bool = False
    probe_url: str | None = None
    xml_probe: bool = True
    use_upnp: bool = True
    # Mainly for trials against the bundled simulators.
    igd_url: str | None = None
    ports: str | None = None
    port_delay: float = Field(default=0.2, ge=0, le=10)
    request_gap: float = Field(default=5.0, ge=0, le=60)


class ChecklistBody(_Strict):
    answers: dict[str, str]


class LangBody(_Strict):
    lang: str = "en"


class OpenBody(_Strict):
    lang: str = "en"
    what: str = "report"


class VpnBody(_Strict):
    site_name: str = "site"
    lang: str = "en"
    topology: str = "direct"
    endpoint_host: str
    endpoint_port: int = 51820
    controller_ips: list[str] = Field(max_length=8)
    controller_ports: list[int] = Field(default_factory=lambda: [80, 443], max_length=8)
    store_device: str = "gateway"
    store_number: int = 1
    technician_number: int = 1
    server_public_key: str | None = None


class VerifyBody(_Strict):
    address: str
    port: int = 80


def open_path(path: Path) -> None:
    """Open a file or folder with the operating system's default handler."""
    system = platform.system()
    if system == "Windows":
        os.startfile(path)  # type: ignore[attr-defined]  # noqa: S606
    elif system == "Darwin":
        subprocess.Popen(["open", str(path)])  # noqa: S603, S607
    else:
        subprocess.Popen(["xdg-open", str(path)])  # noqa: S603, S607


def default_export_root() -> Path:
    return Path.home() / "Documents" / "ColdPerimeter"


def _lang(lang: str) -> str:
    if lang not in available_languages():
        raise HTTPException(status_code=400, detail=f"Unknown language: {lang}")
    return lang


def create_api(
    token: str | None = None,
    allowed_hosts: set[str] | None = None,
    export_root: Path | None = None,
    opener: Callable[[Path], None] = open_path,
) -> FastAPI:
    token = token or secrets.token_urlsafe(32)
    export_root = export_root or default_export_root()
    app = FastAPI(title="ColdPerimeter", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.token = token
    jobs = JobManager()

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if allowed_hosts is not None and request.headers.get("host") not in allowed_hosts:
            return JSONResponse({"detail": "Unexpected host."}, status_code=403)
        if request.url.path.startswith("/api/"):
            supplied = request.headers.get(TOKEN_HEADER, "")
            if not secrets.compare_digest(supplied, token):
                return JSONResponse({"detail": "Missing or invalid token."}, status_code=401)
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    def job_or_404(job_id: str) -> Job:
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Unknown scan.")
        return job

    def result_or_409(job_id: str) -> ScanResult:
        job = job_or_404(job_id)
        if job.result is None:
            raise HTTPException(status_code=409, detail="Scan has no result yet.")
        return job.result

    def export_dir(result: ScanResult) -> Path:
        stamp = result.finished_at[:19].replace(":", "").replace("T", "-")
        return export_root / f"{slugify(result.consent.site_name)}-{stamp}"

    # -- general -----------------------------------------------------------

    @app.get("/api/meta")
    def meta() -> dict[str, Any]:
        try:
            network = str(host_discovery.default_network())
        except host_discovery.ScopeError:
            network = None
        return {
            "version": __version__,
            "languages": available_languages(),
            "network": network,
            "questions": list(QUESTIONS),
            "default_ports": [p.port for p in DEFAULT_PORTS],
            "export_root": str(export_root),
        }

    @app.get("/api/locale/{lang}")
    def locale(lang: str) -> dict[str, Any]:
        return load_locale(_lang(lang))

    # -- scans -------------------------------------------------------------

    @app.post("/api/scans")
    def start_scan(body: ScanStart) -> dict[str, str]:
        if not body.confirmed:
            raise HTTPException(status_code=400, detail="Authorization was not confirmed.")
        if not (body.site_name.strip() and body.authorized_by.strip() and body.operator.strip()):
            raise HTTPException(status_code=400, detail="Authorization record incomplete.")
        if jobs.running() is not None:
            raise HTTPException(status_code=409, detail="A scan is already running.")
        if body.probe_url and not body.probe_url.startswith(("http://", "https://")):
            raise HTTPException(status_code=400, detail="Probe address must start with http:// or https://")
        try:
            network = None
            if body.targets:
                host_discovery.validate_targets(body.targets)
            elif body.network:
                network = ipaddress.ip_network(body.network.strip(), strict=False)
                if network.version != 4:
                    raise ValueError("Only IPv4 networks are supported.")
                host_discovery.validate_network(network)
            else:
                host_discovery.validate_network(host_discovery.default_network())
            options = ScanOptions(
                network=network,
                targets=body.targets,
                port_specs=parse_port_specs(body.ports) if body.ports else DEFAULT_PORTS,
                port_delay=body.port_delay,
                request_gap=body.request_gap,
                xml_probe=body.xml_probe,
            )
        except (host_discovery.ScopeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        job = jobs.start(
            ScanRequest(
                site_name=body.site_name,
                authorized_by=body.authorized_by,
                operator=body.operator,
                options=options,
                igd_url=body.igd_url,
                probe_url=body.probe_url or None,
                offline=body.offline,
                use_upnp=body.use_upnp,
            )
        )
        return {"id": job.id}

    @app.post("/api/scans/import")
    def import_scan(data: dict[str, Any]) -> dict[str, str]:
        try:
            result = ScanResult.from_dict(data)
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail="Not a ColdPerimeter scan file.") from exc
        return {"id": jobs.add_finished(result).id}

    @app.get("/api/scans/{job_id}")
    def scan_status(job_id: str) -> dict[str, Any]:
        return job_or_404(job_id).snapshot()

    @app.post("/api/scans/{job_id}/cancel")
    def cancel_scan(job_id: str) -> dict[str, str]:
        job_or_404(job_id).cancel()
        return {"status": "cancelling"}

    @app.post("/api/scans/{job_id}/checklist")
    def set_checklist(job_id: str, body: ChecklistBody) -> dict[str, str]:
        try:
            job_or_404(job_id).set_checklist(body.answers)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"status": "saved"}

    @app.get("/api/scans/{job_id}/result")
    def scan_result(job_id: str, lang: str = "en") -> dict[str, Any]:
        return result_view(result_or_409(job_id), _lang(lang))

    @app.post("/api/scans/{job_id}/export")
    def export_scan(job_id: str, body: LangBody) -> dict[str, str]:
        result = result_or_409(job_id)
        directory = export_dir(result)
        report = write_reports(result, directory, _lang(body.lang))
        return {"dir": str(directory), "report": str(report)}

    @app.post("/api/scans/{job_id}/open")
    def open_export(job_id: str, body: OpenBody) -> dict[str, str]:
        if body.what not in ("report", "folder"):
            raise HTTPException(status_code=400, detail="Unknown item.")
        result = result_or_409(job_id)
        directory = export_dir(result)
        report = write_reports(result, directory, _lang(body.lang))
        # Only paths this server has just written are ever opened.
        opener(report if body.what == "report" else directory)
        return {"dir": str(directory)}

    # -- VPN assistant -----------------------------------------------------

    @app.post("/api/vpn/generate")
    def vpn_generate(body: VpnBody) -> dict[str, Any]:
        texts = load_locale(_lang(body.lang))["vpn"]
        try:
            plan = build_plan(
                VpnRequest(
                    topology=body.topology,
                    endpoint_host=body.endpoint_host,
                    endpoint_port=body.endpoint_port,
                    controller_ips=body.controller_ips,
                    controller_ports=body.controller_ports,
                    store_device=body.store_device,
                    store_number=body.store_number,
                    technician_number=body.technician_number,
                    server_public_key=body.server_public_key or None,
                )
            )
        except VpnConfigError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        directory = export_root / f"{slugify(body.site_name)}-vpn-{stamp}"
        save_plan(plan, directory, texts)
        # Private keys stay in the files: the response carries none.
        return {
            "dir": str(directory),
            "files": [{"name": f.name, "role": f.role} for f in plan.files],
            "access": [vars(a) for a in plan.access],
            "public_keys": plan.public_keys,
            "instructions": render_instructions(plan, texts),
        }

    @app.post("/api/vpn/open")
    def vpn_open(body: dict[str, str]) -> dict[str, str]:
        directory = Path(body.get("dir", "")).resolve()
        if export_root.resolve() not in directory.parents or not directory.is_dir():
            raise HTTPException(status_code=400, detail="Not a ColdPerimeter folder.")
        opener(directory)
        return {"dir": str(directory)}

    @app.post("/api/vpn/verify")
    def vpn_verify(body: VerifyBody) -> dict[str, Any]:
        try:
            return vars(verify_access(body.address.strip(), body.port))
        except (host_discovery.ScopeError, ValueError, ConsentError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
    return app
