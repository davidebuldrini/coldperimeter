"""Mandatory authorization record.

A scan never starts without the name of the site, the person who authorized the
audit and the operator running it. The record is printed in the report.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone

from .models import Consent


class ConsentError(Exception):
    """Raised when the authorization record is missing or incomplete."""


def _ask(label: str) -> str:
    if not sys.stdin.isatty():
        return ""
    return input(f"{label}: ").strip()


def collect_consent(
    site_name: str | None,
    authorized_by: str | None,
    operator: str | None,
) -> Consent:
    """Build the consent record from CLI flags, prompting for missing fields."""
    site_name = (site_name or "").strip() or _ask("Site name (store being audited)")
    authorized_by = (authorized_by or "").strip() or _ask(
        "Authorized by (network owner or their delegate)"
    )
    operator = (operator or "").strip() or _ask("Operator (technician running the scan)")

    missing = [
        name
        for name, value in (
            ("--site", site_name),
            ("--authorized-by", authorized_by),
            ("--operator", operator),
        )
        if not value
    ]
    if missing:
        raise ConsentError(
            "Authorization record incomplete. Provide: " + ", ".join(missing)
        )
    return Consent(
        site_name=site_name,
        authorized_by=authorized_by,
        operator=operator,
        recorded_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
