"""Rules that compare a baseline Conditional Access policy to a proposed one.

Property names and allowed values follow the Microsoft Graph v1.0
conditionalAccessPolicy schema. Every rule looks for a change that reduces
coverage or enforcement. A finding means "a human should look at this",
not "this change is wrong". Plenty of these are intentional.
"""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}

ENABLED = "enabled"
REPORT_ONLY = "enabledForReportingButNotEnforced"
DISABLED = "disabled"

# Lists where an added entry removes someone or something from the policy.
EXCLUDE_FIELDS = [
    ("users", "excludeUsers", "excluded users"),
    ("users", "excludeGroups", "excluded groups"),
    ("users", "excludeRoles", "excluded roles"),
    ("applications", "excludeApplications", "excluded applications"),
    ("clientApplications", "excludeServicePrincipals", "excluded service principals"),
    ("locations", "excludeLocations", "excluded locations"),
    ("platforms", "excludePlatforms", "excluded platforms"),
]

# Lists where a removed entry takes someone or something out of the policy.
INCLUDE_FIELDS = [
    ("users", "includeUsers", "included users"),
    ("users", "includeGroups", "included groups"),
    ("users", "includeRoles", "included roles"),
    ("applications", "includeApplications", "included applications"),
    ("applications", "includeUserActions", "included user actions"),
    ("applications", "includeAuthenticationContextClassReferences", "included authentication contexts"),
    ("clientApplications", "includeServicePrincipals", "included service principals"),
    ("locations", "includeLocations", "included locations"),
    ("platforms", "includePlatforms", "included platforms"),
]

# Conditions where an empty list means "not configured, applies to everything".
RISK_FIELDS = [
    ("signInRiskLevels", "sign-in risk levels"),
    ("userRiskLevels", "user risk levels"),
    ("servicePrincipalRiskLevels", "service principal risk levels"),
]

HIGH_IMPACT_CONTROLS = {"block", "mfa"}


@dataclass
class Finding:
    severity: str
    rule: str
    policy: str
    message: str
    details: list[str] = field(default_factory=list)

    def at_least(self, threshold: str) -> bool:
        return SEVERITY_ORDER[self.severity] >= SEVERITY_ORDER[threshold]


# ---------- helpers ----------

def _conditions(policy: dict) -> dict:
    return policy.get("conditions") or {}


def _list(policy: dict, section: str | None, key: str) -> list:
    source = _conditions(policy)
    if section is not None:
        source = source.get(section) or {}
    value = source.get(key)
    return list(value) if isinstance(value, list) else []


def _grant(policy: dict) -> dict:
    return policy.get("grantControls") or {}


def _controls(policy: dict) -> list[str]:
    return list(_grant(policy).get("builtInControls") or [])


def _auth_strength_id(policy: dict) -> str | None:
    strength = _grant(policy).get("authenticationStrength")
    if isinstance(strength, dict):
        return strength.get("id") or strength.get("displayName")
    return None


def _requirements(policy: dict) -> set[str]:
    """Everything a sign-in could satisfy to pass the grant controls."""
    grant = _grant(policy)
    reqs = {f"control:{c}" for c in grant.get("builtInControls") or []}
    reqs |= {f"customFactor:{c}" for c in grant.get("customAuthenticationFactors") or []}
    reqs |= {f"termsOfUse:{t}" for t in grant.get("termsOfUse") or []}
    strength = _auth_strength_id(policy)
    if strength:
        reqs.add(f"authenticationStrength:{strength}")
    return reqs


def _operator(policy: dict) -> str:
    return (_grant(policy).get("operator") or "OR").upper()


def _name(policy: dict) -> str:
    return policy.get("displayName") or policy.get("id") or "(unnamed policy)"


def _lockout_risk(policy: dict) -> str | None:
    """Return 'block' or 'grant' if an enabled policy covers all users and all
    apps with no user, group or role exclusion (no break-glass path)."""
    if policy.get("state") != ENABLED:
        return None
    if "All" not in _list(policy, "users", "includeUsers"):
        return None
    if "All" not in _list(policy, "applications", "includeApplications"):
        return None
    if any(_list(policy, "users", k) for k in ("excludeUsers", "excludeGroups", "excludeRoles")):
        return None
    # Any other condition means the policy doesn't hit every sign-in.
    cond = _conditions(policy)
    if cond.get("locations") or cond.get("platforms") or cond.get("devices"):
        return None
    if any(_list(policy, None, k) for k, _ in RISK_FIELDS):
        return None
    app_types = _list(policy, None, "clientAppTypes")
    if app_types and "all" not in app_types:
        return None
    if "block" in _controls(policy):
        return "block"
    if _requirements(policy):
        return "grant"
    return None


# ---------- rules ----------

def check_state(old: dict, new: dict) -> list[Finding]:
    before, after = old.get("state"), new.get("state")
    if before == after:
        return []
    if before == ENABLED and after == REPORT_ONLY:
        return [Finding("high", "state-weakened", _name(new),
                        "Policy moved from enabled to report-only. It is no longer enforced.")]
    if before == ENABLED and after == DISABLED:
        return [Finding("high", "state-weakened", _name(new),
                        "Policy moved from enabled to disabled.")]
    if before == REPORT_ONLY and after == DISABLED:
        return [Finding("low", "state-weakened", _name(new),
                        "Policy moved from report-only to disabled.")]
    return []


def check_grant_controls(old: dict, new: dict) -> list[Finding]:
    findings: list[Finding] = []
    name = _name(new)

    removed = [c for c in _controls(old) if c not in _controls(new)]
    for control in removed:
        severity = "high" if control in HIGH_IMPACT_CONTROLS else "medium"
        findings.append(Finding(severity, "control-removed", name,
                                f"Grant control '{control}' was removed."))

    old_strength, new_strength = _auth_strength_id(old), _auth_strength_id(new)
    if old_strength and not new_strength:
        findings.append(Finding("high", "control-removed", name,
                                "Authentication strength requirement was removed.",
                                [f"was: {old_strength}"]))
    elif old_strength and new_strength and old_strength != new_strength:
        findings.append(Finding("medium", "auth-strength-changed", name,
                                "Authentication strength changed. Confirm the new one is not weaker.",
                                [f"was: {old_strength}", f"now: {new_strength}"]))

    for key, label in (("termsOfUse", "Terms of use"),
                       ("customAuthenticationFactors", "Custom control")):
        gone = [v for v in _grant(old).get(key) or [] if v not in (_grant(new).get(key) or [])]
        if gone:
            findings.append(Finding("low", "control-removed", name,
                                    f"{label} requirement removed.", gone))

    old_reqs, new_reqs = _requirements(old), _requirements(new)
    if _operator(old) == "AND" and _operator(new) == "OR" and len(new_reqs) > 1:
        findings.append(Finding("high", "operator-weakened", name,
                                "Grant operator changed from AND to OR. "
                                "Any one control now satisfies the policy.",
                                sorted(new_reqs)))
    elif _operator(new) == "OR" and old_reqs and len(new_reqs) > 1:
        added = sorted(new_reqs - old_reqs)
        if added:
            findings.append(Finding("medium", "alternative-added", name,
                                    "New OR alternative added. Users can now pass the policy "
                                    "with this instead of the existing requirement.",
                                    added))
    return findings


def check_exclusions(old: dict, new: dict) -> list[Finding]:
    findings: list[Finding] = []
    for section, key, label in EXCLUDE_FIELDS:
        before = set(_list(old, section, key))
        added = [v for v in _list(new, section, key) if v not in before]
        if added:
            findings.append(Finding("medium", "exclusion-added", _name(new),
                                    f"New {label}.", added))

    old_guests = (_conditions(old).get("users") or {}).get("excludeGuestsOrExternalUsers")
    new_guests = (_conditions(new).get("users") or {}).get("excludeGuestsOrExternalUsers")
    if new_guests and new_guests != old_guests:
        findings.append(Finding("medium", "exclusion-added", _name(new),
                                "Guest or external user exclusion added or changed."))
    return findings


def check_scope(old: dict, new: dict) -> list[Finding]:
    findings: list[Finding] = []
    name = _name(new)

    for section, key, label in INCLUDE_FIELDS:
        before, after = _list(old, section, key), _list(new, section, key)
        removed = [v for v in before if v not in after]
        if not removed:
            # A condition that was not configured and now is narrows the policy.
            if section in ("locations", "platforms") and not before and after and "All" not in after:
                findings.append(Finding("medium", "scope-narrowed", name,
                                        f"New {section} condition limits where the policy applies.",
                                        after))
            continue
        tenant_wide = "All" in removed and key in ("includeUsers", "includeApplications")
        findings.append(Finding(
            "high" if tenant_wide else "medium", "scope-narrowed", name,
            f"'All' removed from {label}. Policy is no longer tenant-wide."
            if tenant_wide else f"Removed from {label}.",
            removed))

    before_types = _list(old, None, "clientAppTypes")
    after_types = _list(new, None, "clientAppTypes")
    if before_types and after_types and "all" in before_types and "all" not in after_types:
        findings.append(Finding("medium", "scope-narrowed", name,
                                "Client app types narrowed from 'all'.", after_types))
    elif before_types and "all" not in before_types:
        dropped = [t for t in before_types if t not in after_types and "all" not in after_types]
        if dropped:
            findings.append(Finding("medium", "scope-narrowed", name,
                                    "Client app types removed.", dropped))

    for key, label in RISK_FIELDS:
        before, after = _list(old, None, key), _list(new, None, key)
        if not before and after:
            findings.append(Finding("medium", "scope-narrowed", name,
                                    f"Policy now only applies at specific {label}.", after))
        elif before:
            dropped = [v for v in before if v not in after]
            if dropped:
                findings.append(Finding("medium", "scope-narrowed", name,
                                        f"Removed {label}.", dropped))
    return findings


def check_lockout(old: dict | None, new: dict) -> list[Finding]:
    risk = _lockout_risk(new)
    if risk is None or (old is not None and _lockout_risk(old) == risk):
        return []
    if risk == "block":
        return [Finding("high", "no-break-glass", _name(new),
                        "Enabled block policy covers all users and all apps with no excluded "
                        "users, groups or roles. This can lock everyone out of the tenant.")]
    return [Finding("medium", "no-break-glass", _name(new),
                    "Enabled policy covers all users and all apps with no excluded users, groups "
                    "or roles. Microsoft recommends excluding emergency access accounts.")]


def compare_policy(old: dict | None, new: dict | None) -> list[Finding]:
    if old is not None and new is None:
        severity = "high" if old.get("state") == ENABLED else "low"
        return [Finding(severity, "policy-removed", _name(old),
                        f"Policy was deleted (it was {old.get('state')}).")]
    if new is None:
        return []
    if old is None:
        return check_lockout(None, new)

    findings: list[Finding] = []
    for rule in (check_state, check_grant_controls, check_exclusions, check_scope):
        findings.extend(rule(old, new))
    findings.extend(check_lockout(old, new))
    return findings


def compare_sets(old: dict[str, dict], new: dict[str, dict]) -> list[Finding]:
    findings: list[Finding] = []
    for key in sorted(set(old) | set(new)):
        findings.extend(compare_policy(old.get(key), new.get(key)))
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.policy, f.rule))
    return findings
