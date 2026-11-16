"""Plain data containers shared by every stage of a scan.

Everything here must stay JSON-serialisable through ``dataclasses.asdict`` so a
scan can be saved and a report regenerated later without touching the network.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass
class OpenPort:
    port: int
    role: str


@dataclass
class HttpObservation:
    """What a single ``GET /`` returned."""

    port: int
    tls: bool
    status: int | None = None
    server: str | None = None
    title: str | None = None
    body_sample: str = ""
    error: str | None = None


@dataclass
class XmlIdentity:
    """Answer to the documented, read-only ``read_units`` XML command."""

    port: int
    tls: bool
    responded: bool = False
    error_code: str | None = None
    store_name: str | None = None
    unit_name: str | None = None
    software: str | None = None
    mac: str | None = None
    internet_addrs: list[dict[str, str]] = field(default_factory=list)
    raw: str = ""


@dataclass
class DeviceMatch:
    vendor: str
    family: str
    model_id: str | None
    model: str | None
    firmware: str | None
    confidence: str  # "high" | "medium" | "low"
    score: int
    evidence: list[str] = field(default_factory=list)
    advisories: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Host:
    ip: str
    mac: str | None = None
    vendor: str | None = None
    open_ports: list[OpenPort] = field(default_factory=list)
    http: list[HttpObservation] = field(default_factory=list)
    xml: XmlIdentity | None = None
    device: DeviceMatch | None = None

    def port_numbers(self) -> list[int]:
        return [p.port for p in self.open_ports]

    def has_role(self, role: str) -> bool:
        return any(p.role == role for p in self.open_ports)


@dataclass
class PortMapping:
    external_port: int
    protocol: str
    internal_ip: str
    internal_port: int
    description: str = ""
    enabled: bool = True


@dataclass
class Exposure:
    upnp_found: bool = False
    igd_url: str | None = None
    wan_ip: str | None = None
    mappings: list[PortMapping] = field(default_factory=list)
    public_ip: str | None = None
    behind_cgnat: bool | None = None
    external_checked: bool = False
    # port (as string, JSON-friendly) -> {"open": bool, "title": str | None}
    external_ports: dict[str, dict[str, Any]] = field(default_factory=dict)
    index_checked: bool = False
    indexed_ports: list[int] = field(default_factory=list)
    indexed_vulns: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class Consent:
    site_name: str
    authorized_by: str
    operator: str
    recorded_at: str


@dataclass
class Finding:
    rule_id: str
    severity: str
    step: int
    host: str | None = None
    params: dict[str, Any] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    tool_version: str
    started_at: str
    finished_at: str
    consent: Consent
    scope: str
    hosts: list[Host] = field(default_factory=list)
    exposure: Exposure = field(default_factory=Exposure)
    checklist: dict[str, str] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanResult":
        hosts = []
        for h in data.get("hosts", []):
            hosts.append(
                Host(
                    ip=h["ip"],
                    mac=h.get("mac"),
                    vendor=h.get("vendor"),
                    open_ports=[OpenPort(**p) for p in h.get("open_ports", [])],
                    http=[HttpObservation(**o) for o in h.get("http", [])],
                    xml=XmlIdentity(**h["xml"]) if h.get("xml") else None,
                    device=DeviceMatch(**h["device"]) if h.get("device") else None,
                )
            )
        exp = dict(data.get("exposure", {}))
        exp["mappings"] = [PortMapping(**m) for m in exp.get("mappings", [])]
        return cls(
            tool_version=data["tool_version"],
            started_at=data["started_at"],
            finished_at=data["finished_at"],
            consent=Consent(**data["consent"]),
            scope=data["scope"],
            hosts=hosts,
            exposure=Exposure(**exp),
            checklist=dict(data.get("checklist", {})),
            findings=[Finding(**f) for f in data.get("findings", [])],
        )
