"""Guided on-site questions for access paths a network scan cannot see.

A cellular router bolted inside the refrigeration cabinet, a dial-up modem or
a remote-desktop tool on the back-office PC never show up in a LAN scan.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

ANSWERS = ("yes", "no", "unknown")

# Question ids; the wording lives in the locale files under ``checklist.<id>``.
QUESTIONS = (
    "cellular_router",
    "remote_desktop",
    "dialup_modem",
    "second_wan",
    "vendor_cloud",
    "passwords_changed",
    "alarm_path_known",
)


def unanswered() -> dict[str, str]:
    return {question: "unknown" for question in QUESTIONS}


def load_answers(path: Path) -> dict[str, str]:
    """Read answers from a YAML mapping of question id to yes/no/unknown."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    answers = unanswered()
    for question, value in data.items():
        if question not in answers:
            raise ValueError(f"Unknown checklist question: {question}")
        # YAML reads bare yes/no as booleans.
        if isinstance(value, bool):
            value = "yes" if value else "no"
        value = str(value).strip().lower()
        if value not in ANSWERS:
            raise ValueError(f"{question}: answer must be yes, no or unknown")
        answers[question] = value
    return answers


def ask_interactively(texts: dict[str, str]) -> dict[str, str]:
    """Ask each question on the terminal; Enter means "unknown"."""
    answers = unanswered()
    if not sys.stdin.isatty():
        return answers
    shortcuts = {"y": "yes", "n": "no", "": "unknown", "u": "unknown"}
    for question in QUESTIONS:
        while True:
            reply = input(f"{texts[question]} [y/n/Enter=unknown] ").strip().lower()
            reply = shortcuts.get(reply, reply)
            if reply in ANSWERS:
                answers[question] = reply
                break
    return answers
