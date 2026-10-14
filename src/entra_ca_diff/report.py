"""Render findings as plain text, Markdown, or JSON."""

from __future__ import annotations

import json
from dataclasses import asdict

from .rules import Finding


def _counts(findings: list[Finding]) -> str:
    parts = []
    for sev in ("high", "medium", "low"):
        n = sum(1 for f in findings if f.severity == sev)
        if n:
            parts.append(f"{n} {sev}")
    return ", ".join(parts)


def to_text(findings: list[Finding], compared: int) -> str:
    if not findings:
        return f"No coverage or enforcement regressions found across {compared} policies."
    lines = [f"{len(findings)} findings ({_counts(findings)}) across {compared} policies.", ""]
    for f in findings:
        lines.append(f"[{f.severity.upper()}] {f.policy}")
        lines.append(f"  {f.rule}: {f.message}")
        for d in f.details:
            lines.append(f"    - {d}")
    return "\n".join(lines)


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")


def to_markdown(findings: list[Finding], compared: int) -> str:
    lines = ["## Conditional Access change review", ""]
    if not findings:
        lines.append(f"No coverage or enforcement regressions found across {compared} policies.")
        return "\n".join(lines) + "\n"
    lines.append(f"{len(findings)} findings ({_counts(findings)}) across {compared} policies.")
    lines += ["", "| Severity | Policy | Rule | Finding |", "|---|---|---|---|"]
    for f in findings:
        detail = _md_escape(f.message)
        if f.details:
            detail += "<br>" + "<br>".join(f"`{_md_escape(d)}`" for d in f.details)
        lines.append(f"| {f.severity} | {_md_escape(f.policy)} | `{f.rule}` | {detail} |")
    return "\n".join(lines) + "\n"


def to_json(findings: list[Finding], compared: int) -> str:
    return json.dumps(
        {"policiesCompared": compared, "findings": [asdict(f) for f in findings]},
        indent=2,
    )


RENDERERS = {"text": to_text, "markdown": to_markdown, "json": to_json}
