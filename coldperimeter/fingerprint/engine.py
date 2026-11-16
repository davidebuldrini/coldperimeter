"""Match a host's observations against the declarative signature files."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..models import DeviceMatch, Host

SIGNATURE_DIR = Path(__file__).parent / "signatures"

CANDIDATE_SCORE = 20
MEDIUM_SCORE = 40
HIGH_SCORE = 60


@dataclass
class SignatureDB:
    vendor: str
    family: str
    ouis: dict[str, str] = field(default_factory=dict)
    signatures: list[dict[str, Any]] = field(default_factory=list)
    models: list[dict[str, Any]] = field(default_factory=list)
    advisories: dict[str, dict[str, Any]] = field(default_factory=dict)

    def oui_owner(self, mac: str | None) -> str | None:
        if not mac:
            return None
        return self.ouis.get(mac.upper()[:8])


def load_signatures(directory: Path = SIGNATURE_DIR) -> list[SignatureDB]:
    databases = []
    for path in sorted(directory.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        databases.append(
            SignatureDB(
                vendor=data["vendor"],
                family=data.get("family", data["vendor"]),
                ouis={o["prefix"].upper(): o["owner"] for o in data.get("oui", [])},
                signatures=data.get("signatures", []),
                models=data.get("models", []),
                advisories=data.get("advisories", {}),
            )
        )
    return databases


def vendor_for_mac(mac: str | None, databases: list[SignatureDB]) -> str | None:
    for db in databases:
        owner = db.oui_owner(mac)
        if owner:
            return owner
    return None


def _signature_matches(host: Host, db: SignatureDB, match: dict[str, Any]) -> bool:
    """All conditions listed in ``match`` must hold."""
    if match.get("xml_read_units") and not (host.xml and host.xml.responded):
        return False
    if match.get("mac_oui"):
        macs = [host.mac, host.xml.mac.replace("-", ":") if host.xml and host.xml.mac else None]
        if not any(db.oui_owner(mac) for mac in macs):
            return False
    if "http_title" in match:
        pattern = re.compile(match["http_title"])
        if not any(o.title and pattern.search(o.title) for o in host.http):
            return False
    if "http_body" in match:
        pattern = re.compile(match["http_body"])
        if not any(pattern.search(o.body_sample) for o in host.http):
            return False
    if "http_server" in match:
        pattern = re.compile(match["http_server"])
        if not any(o.server and pattern.search(o.server) for o in host.http):
            return False
    return True


def _identity_text(host: Host) -> str:
    parts = [o.title or "" for o in host.http]
    if host.xml and host.xml.unit_name:
        parts.append(host.xml.unit_name)
    parts.extend(o.body_sample for o in host.http)
    return "\n".join(parts)


def _match_db(host: Host, db: SignatureDB) -> DeviceMatch | None:
    score = 0
    evidence = []
    for sig in db.signatures:
        if _signature_matches(host, db, sig.get("match", {})):
            score += int(sig.get("weight", 0))
            evidence.append(f"{sig['description']} [{sig.get('status', 'unverified')}]")
    if score < CANDIDATE_SCORE:
        return None

    text = _identity_text(host)
    model = next((m for m in db.models if re.search(m["pattern"], text)), None)
    if model:
        advisory_ids = model.get("advisories", [])
    else:
        # Unknown model: list every advisory so the technician can rule it out.
        advisory_ids = list(db.advisories)
    advisories = [
        {"id": aid, **db.advisories[aid]} for aid in advisory_ids if aid in db.advisories
    ]
    confidence = (
        "high" if score >= HIGH_SCORE else "medium" if score >= MEDIUM_SCORE else "low"
    )
    return DeviceMatch(
        vendor=db.vendor,
        family=db.family,
        model_id=model["id"] if model else None,
        model=model["name"] if model else None,
        firmware=host.xml.software if host.xml else None,
        confidence=confidence,
        score=score,
        evidence=evidence,
        advisories=advisories,
    )


def identify(host: Host, databases: list[SignatureDB]) -> DeviceMatch | None:
    """Return the best match across all signature files, or ``None``."""
    matches = [m for m in (_match_db(host, db) for db in databases) if m]
    return max(matches, key=lambda m: m.score, default=None)
