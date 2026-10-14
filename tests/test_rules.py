import copy

import pytest

from entra_ca_diff.rules import compare_policy, compare_sets

BREAKGLASS = "00000000-0000-0000-0000-00000000b001"


def policy(**overrides):
    base = {
        "id": "p1",
        "displayName": "Require MFA",
        "state": "enabled",
        "conditions": {
            "users": {"includeUsers": ["All"], "excludeUsers": [BREAKGLASS]},
            "applications": {"includeApplications": ["All"]},
            "clientAppTypes": ["all"],
        },
        "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
    }
    base.update(overrides)
    return base


def changed(old, mutate):
    new = copy.deepcopy(old)
    mutate(new)
    return new


def rules(findings):
    return [(f.rule, f.severity) for f in findings]


def test_identical_policy_has_no_findings():
    p = policy()
    assert compare_policy(p, copy.deepcopy(p)) == []


@pytest.mark.parametrize("after,severity", [
    ("enabledForReportingButNotEnforced", "high"),
    ("disabled", "high"),
])
def test_enabled_policy_weakened(after, severity):
    old = policy()
    new = changed(old, lambda p: p.update(state=after))
    assert rules(compare_policy(old, new)) == [("state-weakened", severity)]


def test_report_only_to_disabled_is_low():
    old = policy(state="enabledForReportingButNotEnforced")
    new = changed(old, lambda p: p.update(state="disabled"))
    assert rules(compare_policy(old, new)) == [("state-weakened", "low")]


def test_enabling_a_policy_is_not_flagged():
    old = policy(state="enabledForReportingButNotEnforced")
    new = changed(old, lambda p: p.update(state="enabled"))
    assert compare_policy(old, new) == []


def test_mfa_removed_is_high():
    old = policy()
    new = changed(old, lambda p: p["grantControls"].update(builtInControls=[]))
    assert ("control-removed", "high") in rules(compare_policy(old, new))


def test_block_removed_is_high():
    old = policy(grantControls={"operator": "OR", "builtInControls": ["block"]})
    new = changed(old, lambda p: p["grantControls"].update(builtInControls=["mfa"]))
    assert ("control-removed", "high") in rules(compare_policy(old, new))


def test_auth_strength_removed_and_changed():
    old = policy(grantControls={"operator": "OR", "builtInControls": [],
                                "authenticationStrength": {"id": "phishing-resistant"}})
    removed = changed(old, lambda p: p["grantControls"].pop("authenticationStrength"))
    swapped = changed(old, lambda p: p["grantControls"].update(
        authenticationStrength={"id": "mfa-any"}))
    assert ("control-removed", "high") in rules(compare_policy(old, removed))
    assert ("auth-strength-changed", "medium") in rules(compare_policy(old, swapped))


def test_and_to_or_is_high():
    old = policy(grantControls={"operator": "AND", "builtInControls": ["mfa", "compliantDevice"]})
    new = changed(old, lambda p: p["grantControls"].update(operator="OR"))
    assert rules(compare_policy(old, new)) == [("operator-weakened", "high")]


def test_new_or_alternative_is_medium():
    old = policy()
    new = changed(old, lambda p: p["grantControls"].update(builtInControls=["mfa", "compliantDevice"]))
    assert rules(compare_policy(old, new)) == [("alternative-added", "medium")]


def test_adding_control_under_and_is_not_flagged():
    old = policy(grantControls={"operator": "AND", "builtInControls": ["mfa"]})
    new = changed(old, lambda p: p["grantControls"].update(builtInControls=["mfa", "compliantDevice"]))
    assert compare_policy(old, new) == []


@pytest.mark.parametrize("section,key,value", [
    ("users", "excludeUsers", "u2"),
    ("users", "excludeGroups", "g1"),
    ("users", "excludeRoles", "r1"),
    ("applications", "excludeApplications", "app1"),
])
def test_new_exclusion_flagged(section, key, value):
    old = policy()
    new = changed(old, lambda p: p["conditions"][section].setdefault(key, []).append(value))
    findings = compare_policy(old, new)
    assert rules(findings) == [("exclusion-added", "medium")]
    assert findings[0].details == [value]


def test_guests_exclusion_flagged():
    old = policy()
    new = changed(old, lambda p: p["conditions"]["users"]["excludeUsers"].append("GuestsOrExternalUsers"))
    assert ("exclusion-added", "medium") in rules(compare_policy(old, new))


def test_removing_exclusion_is_not_flagged():
    old = policy()
    new = changed(old, lambda p: p["conditions"]["users"].update(excludeUsers=[]))
    # Removing the only exclusion trips the break-glass check, nothing else.
    assert [r for r, _ in rules(compare_policy(old, new))] == ["no-break-glass"]


def test_all_users_removed_is_high():
    old = policy()
    new = changed(old, lambda p: p["conditions"]["users"].update(includeUsers=[], includeGroups=["g1"]))
    assert rules(compare_policy(old, new)) == [("scope-narrowed", "high")]


def test_included_group_removed_is_medium():
    old = policy()
    old["conditions"]["users"] = {"includeGroups": ["g1", "g2"]}
    new = changed(old, lambda p: p["conditions"]["users"].update(includeGroups=["g1"]))
    assert rules(compare_policy(old, new)) == [("scope-narrowed", "medium")]


def test_risk_condition_added_narrows():
    old = policy()
    new = changed(old, lambda p: p["conditions"].update(signInRiskLevels=["high"]))
    assert rules(compare_policy(old, new)) == [("scope-narrowed", "medium")]


def test_client_app_types_narrowed():
    old = policy()
    new = changed(old, lambda p: p["conditions"].update(clientAppTypes=["browser"]))
    assert rules(compare_policy(old, new)) == [("scope-narrowed", "medium")]


def test_location_condition_added_narrows():
    old = policy()
    new = changed(old, lambda p: p["conditions"].update(locations={"includeLocations": ["loc1"]}))
    assert rules(compare_policy(old, new)) == [("scope-narrowed", "medium")]


def test_new_block_all_policy_without_breakglass_is_high():
    new = policy(conditions={"users": {"includeUsers": ["All"]},
                             "applications": {"includeApplications": ["All"]},
                             "clientAppTypes": ["all"]},
                 grantControls={"operator": "OR", "builtInControls": ["block"]})
    assert rules(compare_policy(None, new)) == [("no-break-glass", "high")]


def test_block_all_with_location_condition_is_not_lockout():
    new = policy(conditions={"users": {"includeUsers": ["All"]},
                             "applications": {"includeApplications": ["All"]},
                             "locations": {"includeLocations": ["All"], "excludeLocations": ["trusted"]},
                             "clientAppTypes": ["all"]},
                 grantControls={"operator": "OR", "builtInControls": ["block"]})
    assert compare_policy(None, new) == []


def test_new_report_only_policy_not_flagged():
    new = policy(state="enabledForReportingButNotEnforced",
                 conditions={"users": {"includeUsers": ["All"]},
                             "applications": {"includeApplications": ["All"]}},
                 grantControls={"operator": "OR", "builtInControls": ["block"]})
    assert compare_policy(None, new) == []


def test_deleted_policy():
    assert rules(compare_policy(policy(), None)) == [("policy-removed", "high")]
    assert rules(compare_policy(policy(state="disabled"), None)) == [("policy-removed", "low")]


def test_compare_sets_matches_by_key_and_sorts_by_severity():
    old = {"a": policy(id="a"), "b": policy(id="b", displayName="B")}
    new = {"a": changed(old["a"], lambda p: p["conditions"]["users"].update(excludeGroups=["g9"])),
           "b": changed(old["b"], lambda p: p.update(state="disabled"))}
    findings = compare_sets(old, new)
    assert [f.severity for f in findings] == ["high", "medium"]
