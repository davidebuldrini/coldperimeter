"""Deterministic rules: observed situation -> finding -> plan step.

Each rule emits ``Finding`` objects. The wording lives in the locale files
under ``findings.<rule_id>``; ``step`` says where the corrective action goes
in the intervention plan (see ``report/plan.py``).
"""

from __future__ import annotations

import re

from ..exposure.public_ip import is_public
from ..models import SEVERITIES, Exposure, Finding, Host

# Plan steps.
STEP_INVENTORY = 1
STEP_REMOVE_ACCESS = 4
STEP_SEGMENT = 5
STEP_HARDEN = 7

_CONTROLLER_TITLE = re.compile(r"(?i)danfoss|storeview|ak[- ]?s[cm][- ]?\d{3}|adap[- ]?kool")
_LEGACY_ROLES = ("telnet", "ftp", "vnc")
_INDUSTRIAL_ROLES = ("modbus", "xml-legacy")


def _exposure_findings(exposure: Exposure, controller_ips: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    tcp_mappings = {m.external_port: m for m in exposure.mappings if m.protocol == "TCP"}

    for port_text, info in sorted(exposure.external_ports.items(), key=lambda kv: int(kv[0])):
        if not info.get("open"):
            continue
        port = int(port_text)
        mapping = tcp_mappings.get(port)
        title = info.get("title") or ""
        to_controller = bool(
            (mapping and mapping.internal_ip in controller_ips)
            or _CONTROLLER_TITLE.search(title)
        )
        evidence = [f"TCP {port} answered on {exposure.public_ip} from the internet"]
        if title:
            evidence.append(f"Page title seen from outside: {title}")
        if mapping:
            evidence.append(
                f"Router forwards it to {mapping.internal_ip}:{mapping.internal_port}"
            )
        findings.append(
            Finding(
                rule_id="EXT-OPEN-CONTROLLER" if to_controller else "EXT-OPEN-OTHER",
                severity="critical" if to_controller else "high",
                step=STEP_REMOVE_ACCESS,
                host=mapping.internal_ip if mapping else None,
                params={"port": port, "public_ip": exposure.public_ip},
                evidence=evidence,
            )
        )

    for mapping in exposure.mappings:
        if mapping.internal_ip not in controller_ips:
            continue
        seen = exposure.external_ports.get(str(mapping.external_port))
        if seen and seen.get("open"):
            continue  # already reported as EXT-OPEN-CONTROLLER
        if seen is not None or exposure.behind_cgnat:
            severity = "medium"  # rule exists but is not reachable right now
        else:
            severity = "critical"
        findings.append(
            Finding(
                rule_id="UPNP-MAP-CONTROLLER",
                severity=severity,
                step=STEP_REMOVE_ACCESS,
                host=mapping.internal_ip,
                params={
                    "external_port": mapping.external_port,
                    "internal_port": mapping.internal_port,
                    "protocol": mapping.protocol,
                },
                evidence=[
                    f"Router mapping: {mapping.protocol} {mapping.external_port} -> "
                    f"{mapping.internal_ip}:{mapping.internal_port}"
                    + (f" ({mapping.description})" if mapping.description else "")
                ],
            )
        )

    if exposure.upnp_found:
        findings.append(
            Finding(
                rule_id="UPNP-ENABLED",
                severity="medium",
                step=STEP_REMOVE_ACCESS,
                params={"count": len(exposure.mappings)},
                evidence=[f"Gateway answered UPnP queries at {exposure.igd_url}"],
            )
        )

    if exposure.index_checked and exposure.indexed_ports:
        findings.append(
            Finding(
                rule_id="INDEXED",
                severity="high",
                step=STEP_REMOVE_ACCESS,
                params={
                    "public_ip": exposure.public_ip,
                    "ports": ", ".join(str(p) for p in exposure.indexed_ports),
                },
                evidence=[
                    "Public index lists ports: "
                    + ", ".join(str(p) for p in exposure.indexed_ports)
                ]
                + (
                    ["Index also lists: " + ", ".join(exposure.indexed_vulns[:10])]
                    if exposure.indexed_vulns
                    else []
                ),
            )
        )

    if not exposure.external_checked:
        findings.append(
            Finding(rule_id="EXT-NOT-TESTED", severity="info", step=STEP_INVENTORY)
        )

    if exposure.behind_cgnat:
        findings.append(
            Finding(
                rule_id="CGNAT",
                severity="info",
                step=STEP_INVENTORY,
                params={"wan_ip": exposure.wan_ip, "public_ip": exposure.public_ip or "?"},
            )
        )
    return findings


def _controller_findings(host: Host) -> list[Finding]:
    assert host.device is not None
    findings: list[Finding] = []
    device = host.device

    def add(rule_id: str, severity: str, step: int, params=None, evidence=None) -> None:
        findings.append(
            Finding(
                rule_id=rule_id,
                severity=severity,
                step=step,
                host=host.ip,
                params=params or {},
                evidence=evidence or [],
            )
        )

    add(
        "FLAT-NET",
        "medium",
        STEP_SEGMENT,
        evidence=[
            "Reached from the scanning laptop on ports: "
            + ", ".join(str(p) for p in host.port_numbers())
        ],
    )

    if host.xml and host.xml.responded and host.xml.error_code == "0":
        add(
            "XML-NOAUTH",
            "high",
            STEP_HARDEN,
            evidence=[
                f"read_units answered without credentials on port {host.xml.port}"
            ],
        )

    if host.xml:
        public = [a for a in host.xml.internet_addrs if is_public(a.get("ip"))]
        if public:
            add(
                "XML-PUBLIC-ADDR",
                "medium",
                STEP_REMOVE_ACCESS,
                params={"address": ", ".join(f"{a['ip']}:{a['port']}" for a in public)},
                evidence=["Controller reports this internet address in read_units"],
            )

    plain = [p.port for p in host.open_ports if p.role == "http"]
    if plain:
        add(
            "HTTP-PLAIN",
            "medium",
            STEP_SEGMENT,
            params={"ports": ", ".join(str(p) for p in plain)},
        )

    legacy = [f"{p.role} ({p.port})" for p in host.open_ports if p.role in _LEGACY_ROLES]
    if legacy:
        add("LEGACY-SVC", "medium", STEP_SEGMENT, params={"services": ", ".join(legacy)})

    if host.has_role("modbus"):
        add("MODBUS-OPEN", "medium", STEP_SEGMENT)

    if device.advisories:
        add(
            "ADVISORY",
            "high" if device.model_id == "ak-sm-800a" else "medium",
            STEP_HARDEN,
            params={
                "model": device.model or device.family,
                "firmware": device.firmware or "unknown",
                "advisories": "; ".join(
                    f"{a['id']} (fixed in {a.get('fixed_in', '?')})"
                    for a in device.advisories
                ),
            },
            evidence=[f"{a['id']}: {a.get('url', '')}" for a in device.advisories],
        )

    if device.confidence == "low":
        add("LOW-CONFIDENCE", "info", STEP_INVENTORY, evidence=list(device.evidence))

    return findings


def _checklist_findings(answers: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []

    def answer(question: str) -> str:
        return answers.get(question, "unknown")

    hidden_paths = (
        ("cellular_router", "CHK-CELLULAR", "high"),
        ("remote_desktop", "CHK-REMOTE-DESKTOP", "high"),
        ("dialup_modem", "CHK-DIALUP", "medium"),
    )
    for question, rule_id, severity in hidden_paths:
        if answer(question) == "yes":
            findings.append(Finding(rule_id=rule_id, severity=severity, step=STEP_REMOVE_ACCESS))

    if answer("second_wan") == "yes":
        findings.append(Finding(rule_id="CHK-SECOND-WAN", severity="medium", step=STEP_INVENTORY))
    if answer("vendor_cloud") == "yes":
        findings.append(Finding(rule_id="CHK-VENDOR-CLOUD", severity="info", step=STEP_INVENTORY))
    if answer("passwords_changed") != "yes":
        findings.append(
            Finding(
                rule_id="CHK-PASSWORDS",
                severity="high" if answer("passwords_changed") == "no" else "medium",
                step=STEP_HARDEN,
            )
        )
    if answer("alarm_path_known") != "yes":
        findings.append(Finding(rule_id="CHK-ALARM-PATH", severity="medium", step=STEP_INVENTORY))

    unknown = [
        q
        for q in ("cellular_router", "remote_desktop", "dialup_modem", "second_wan", "vendor_cloud")
        if answer(q) == "unknown"
    ]
    if unknown:
        findings.append(
            Finding(
                rule_id="CHK-UNKNOWN",
                severity="low",
                step=STEP_INVENTORY,
                params={"questions": unknown},
            )
        )
    return findings


def evaluate(hosts: list[Host], exposure: Exposure, checklist: dict[str, str]) -> list[Finding]:
    """Apply every rule and return findings sorted by severity."""
    controllers = [h for h in hosts if h.device]
    controller_ips = {h.ip for h in controllers}

    findings = _exposure_findings(exposure, controller_ips)
    for host in controllers:
        findings.extend(_controller_findings(host))

    for host in hosts:
        if host.device is None and any(host.has_role(r) for r in _INDUSTRIAL_ROLES):
            findings.append(
                Finding(
                    rule_id="UNIDENTIFIED",
                    severity="info",
                    step=STEP_INVENTORY,
                    host=host.ip,
                    params={"ports": ", ".join(str(p) for p in host.port_numbers())},
                )
            )

    if not controllers:
        findings.append(Finding(rule_id="NO-CONTROLLER", severity="info", step=STEP_INVENTORY))

    findings.extend(_checklist_findings(checklist))
    findings.sort(key=lambda f: (SEVERITIES.index(f.severity), f.rule_id, f.host or ""))
    return findings
