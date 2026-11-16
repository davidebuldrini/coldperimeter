"""Run a complete audit as one job.

Both front ends use this module: the command line calls ``run_scan`` directly
and the graphical interface runs it in a background thread.
"""

from __future__ import annotations

import asyncio
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, exposure
from .consent import collect_consent
from .exposure import checklist as checklist_module
from .findings.rules import evaluate
from .models import ScanResult
from .report.plan import render_html, render_markdown
from .scanner import Progress, ScanOptions, scan_local

STAGE_EXPOSURE = "exposure"
STAGES = ("hosts", "ports", "identity", STAGE_EXPOSURE)


class ScanCancelled(Exception):
    """Raised when the operator stops a running scan."""


@dataclass
class ScanRequest:
    site_name: str | None
    authorized_by: str | None
    operator: str | None
    options: ScanOptions = field(default_factory=ScanOptions)
    igd_url: str | None = None
    probe_url: str | None = None
    offline: bool = False
    use_upnp: bool = True
    checklist: dict[str, str] | None = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


async def _cancellable(coroutine, cancel: threading.Event | None):
    """Await ``coroutine``, cancelling it soon after ``cancel`` is set."""
    task = asyncio.ensure_future(coroutine)
    while not task.done():
        if cancel is not None and cancel.is_set():
            task.cancel()
        await asyncio.wait([task], timeout=0.2)
    return task.result()


def run_scan(
    request: ScanRequest,
    progress: Progress | None = None,
    cancel: threading.Event | None = None,
) -> ScanResult:
    """Run every stage and return the result. Raises ``ScanCancelled``."""
    consent = collect_consent(request.site_name, request.authorized_by, request.operator)
    started = _now()

    try:
        scope, hosts = asyncio.run(
            _cancellable(scan_local(request.options, progress), cancel)
        )
    except asyncio.CancelledError as exc:
        raise ScanCancelled() from exc
    if cancel is not None and cancel.is_set():
        raise ScanCancelled()

    if progress:
        progress(STAGE_EXPOSURE, "Checking exposure to the internet ...", 0, 1)
    exposure_result = exposure.assess(
        igd_url=request.igd_url,
        probe_url=request.probe_url,
        offline=request.offline,
        use_upnp=request.use_upnp,
    )
    if progress:
        for error in exposure_result.errors:
            progress(STAGE_EXPOSURE, f"note: {error}", None, None)
        progress(STAGE_EXPOSURE, "", 1, 1)
    if cancel is not None and cancel.is_set():
        raise ScanCancelled()

    answers = request.checklist or checklist_module.unanswered()
    return ScanResult(
        tool_version=__version__,
        started_at=started,
        finished_at=_now(),
        consent=consent,
        scope=scope,
        hosts=hosts,
        exposure=exposure_result,
        checklist=answers,
        findings=evaluate(hosts, exposure_result, answers),
    )


def apply_checklist(result: ScanResult, answers: dict[str, str]) -> None:
    """Store new checklist answers and re-apply the rules."""
    merged = checklist_module.unanswered()
    for question, value in answers.items():
        if question not in merged:
            raise ValueError(f"Unknown checklist question: {question}")
        if value not in checklist_module.ANSWERS:
            raise ValueError(f"{question}: answer must be yes, no or unknown")
        merged[question] = value
    result.checklist = merged
    result.findings = evaluate(result.hosts, result.exposure, merged)


def slugify(text: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-").lower()
    return slug[:60] or "site"


def write_reports(result: ScanResult, out_dir: Path, lang: str) -> Path:
    """Write ``scan.json``, ``report.html`` and ``report.md``; return the HTML path."""
    import json

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "scan.json").write_text(
        json.dumps(result.to_dict(), indent=2), encoding="utf-8"
    )
    html_path = out_dir / "report.html"
    html_path.write_text(render_html(result, lang), encoding="utf-8")
    (out_dir / "report.md").write_text(render_markdown(result, lang), encoding="utf-8")
    return html_path
