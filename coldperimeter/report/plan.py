"""Build the ordered intervention plan and render the report.

The step order is fixed and deliberate: the VPN is brought up and alarms are
verified (steps 2-3) before any direct access is removed (step 4), so that
temperature alarms are never silenced by the hardening work.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..exposure.checklist import QUESTIONS
from ..models import SEVERITIES, Finding, ScanResult

LOCALE_DIR = Path(__file__).parent / "locales"
TEMPLATE_DIR = Path(__file__).parent / "templates"
STEP_COUNT = 7


class _Missing(dict):
    """Leave unknown ``{placeholders}`` visible instead of raising."""

    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def available_languages() -> list[str]:
    return sorted(p.stem for p in LOCALE_DIR.glob("*.yaml"))


def load_locale(lang: str) -> dict[str, Any]:
    path = LOCALE_DIR / f"{lang}.yaml"
    if not path.is_file():
        raise ValueError(
            f"Unknown language {lang!r}. Available: {', '.join(available_languages())}"
        )
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@dataclass
class RenderedFinding:
    rule_id: str
    severity: str
    severity_label: str
    host: str | None
    title: str
    detail: str
    action: str
    step: int
    evidence: list[str] = field(default_factory=list)


@dataclass
class PlanStep:
    number: int
    title: str
    intro: str
    always: list[str]
    items: list[RenderedFinding]


def _params(finding: Finding, locale: dict[str, Any]) -> _Missing:
    params = _Missing(finding.params)
    questions = params.get("questions")
    if isinstance(questions, list):
        params["questions"] = " ".join(locale["checklist"][q] for q in questions)
    return params


def render_finding(finding: Finding, locale: dict[str, Any]) -> RenderedFinding:
    texts = locale["findings"][finding.rule_id]
    params = _params(finding, locale)
    return RenderedFinding(
        rule_id=finding.rule_id,
        severity=finding.severity,
        severity_label=locale["severity"][finding.severity],
        host=finding.host,
        title=texts["title"].format_map(params),
        detail=texts["detail"].format_map(params),
        action=texts["action"].format_map(params),
        step=finding.step,
        evidence=list(finding.evidence),
    )


def build_plan(findings: list[Finding], locale: dict[str, Any]) -> list[PlanStep]:
    """Group the findings' actions under the seven fixed steps."""
    rendered = [render_finding(f, locale) for f in findings]
    steps = []
    for number in range(1, STEP_COUNT + 1):
        texts = locale["steps"][number]
        items = [r for r in rendered if r.step == number]
        items.sort(key=lambda r: SEVERITIES.index(r.severity))
        steps.append(
            PlanStep(
                number=number,
                title=texts["title"],
                intro=texts["intro"],
                always=list(texts.get("always", [])),
                items=items,
            )
        )
    return steps


def _context(result: ScanResult, lang: str) -> dict[str, Any]:
    locale = load_locale(lang)
    findings = [render_finding(f, locale) for f in result.findings]
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
    return {
        "lang": lang,
        "t": locale["labels"],
        "locale": locale,
        "result": result,
        "controllers": [h for h in result.hosts if h.device],
        "findings": findings,
        "counts": counts,
        "plan": build_plan(result.findings, locale),
        "questions": [
            (locale["checklist"][q], result.checklist.get(q, "unknown")) for q in QUESTIONS
        ],
    }


def render_html(result: ScanResult, lang: str = "en") -> str:
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    return env.get_template("report.html.j2").render(**_context(result, lang))


def render_markdown(result: ScanResult, lang: str = "en") -> str:
    ctx = _context(result, lang)
    t = ctx["t"]
    exposure = result.exposure
    lines = [
        f"# {t['title']}",
        "",
        f"- **{t['site']}:** {result.consent.site_name}",
        f"- **{t['authorized_by']}:** {result.consent.authorized_by}",
        f"- **{t['operator']}:** {result.consent.operator}",
        f"- **{t['scope']}:** {result.scope}",
        f"- **{t['scanned']}:** {result.finished_at}",
        f"- **{t['controllers_found']}:** {len(ctx['controllers'])}",
        f"- **{t['public_ip']}:** {exposure.public_ip or t['unknown']}",
        f"- **{t['external_check']}:** {t['yes'] if exposure.external_checked else t['no']}",
        "",
        f"## {t['devices']}",
        "",
    ]
    if not ctx["controllers"]:
        lines.append(t["none"])
    for host in ctx["controllers"]:
        device = host.device
        ports = ", ".join(f"{p.port} ({p.role})" for p in host.open_ports)
        lines.append(
            f"- **{host.ip}** — {device.vendor} {device.model or device.family}; "
            f"{t['firmware']}: {device.firmware or t['unknown']}; "
            f"{t['confidence']}: {ctx['locale']['confidence'][device.confidence]}; "
            f"{t['open_ports']}: {ports}"
        )
    lines += ["", f"## {t['findings']}", ""]
    for f in ctx["findings"]:
        where = f" — {f.host}" if f.host else ""
        lines.append(f"### [{f.severity_label}] {f.title}{where}")
        lines.append("")
        lines.append(f.detail)
        for item in f.evidence:
            lines.append(f"- {item}")
        lines.append("")
    lines += [f"## {t['plan']}", ""]
    for step in ctx["plan"]:
        lines.append(f"### {t['step']} {step.number}. {step.title}")
        lines.append("")
        lines.append(step.intro)
        lines.append("")
        for text in step.always:
            lines.append(f"- [ ] {text}")
        for item in step.items:
            where = f" ({item.host})" if item.host else ""
            lines.append(f"- [ ] **[{item.severity_label}]** {item.action}{where}")
        lines.append("")
    lines += [f"## {t['checklist']}", ""]
    for question, answer in ctx["questions"]:
        lines.append(f"- {question} **{t[answer]}**")
    lines += ["", f"## {t['limits']}", ""]
    lines += [f"- {text}" for text in ctx["locale"]["limits"]]
    return "\n".join(lines) + "\n"
