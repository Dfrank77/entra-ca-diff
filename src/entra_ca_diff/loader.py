"""Load Conditional Access policies from a JSON file or a folder of JSON files."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


class PolicyLoadError(Exception):
    """Raised when an input path can't be read as Conditional Access policy JSON."""


@dataclass
class PolicySet:
    """Policies keyed by id (or display name when an export has no id)."""

    policies: dict[str, dict] = field(default_factory=dict)
    skipped: list[str] = field(default_factory=list)


def _is_policy(obj: object) -> bool:
    return isinstance(obj, dict) and "conditions" in obj and "state" in obj


def _policy_key(policy: dict) -> str:
    return policy.get("id") or policy.get("displayName") or ""


def _extract(obj: object) -> list[dict]:
    """Accept a single policy, a list of policies, or a Graph list response ({"value": [...]})."""
    if _is_policy(obj):
        return [obj]
    if isinstance(obj, dict) and isinstance(obj.get("value"), list):
        return [p for p in obj["value"] if _is_policy(p)]
    if isinstance(obj, list):
        return [p for p in obj if _is_policy(p)]
    return []


def _read_text(file: Path) -> str:
    """Windows PowerShell 5.1's Out-File writes UTF-16 by default, so exports
    from EntraExporter on Windows may not be UTF-8."""
    raw = file.read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16")
    return raw.decode("utf-8-sig")


def load_policies(path: str | Path) -> PolicySet:
    path = Path(path)
    if not path.exists():
        raise PolicyLoadError(f"Path not found: {path}")

    files = sorted(path.rglob("*.json")) if path.is_dir() else [path]
    result = PolicySet()

    for file in files:
        try:
            data = json.loads(_read_text(file))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise PolicyLoadError(f"Invalid JSON in {file}: {exc}") from exc

        found = _extract(data)
        if not found:
            result.skipped.append(str(file))
            continue

        for policy in found:
            key = _policy_key(policy)
            if not key:
                raise PolicyLoadError(f"Policy in {file} has no id or displayName")
            if key in result.policies:
                raise PolicyLoadError(f"Duplicate policy key '{key}' in {file}")
            result.policies[key] = policy

    return result
