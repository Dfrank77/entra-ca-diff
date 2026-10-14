# entra-ca-diff

If you keep Conditional Access policies in git, a pull request that weakens one looks like any other JSON change. One new group in `excludeGroups` or `AND` flipped to `OR` is a single line in the diff, and it's easy to approve without seeing what it does.

entra-ca-diff compares two sets of CA policies and tells you which changes reduce coverage or enforcement. It works on the JSON Microsoft Graph returns, so it reads EntraExporter output or anything else that saves the raw policy objects.

A finding doesn't mean the change is wrong. Plenty of exclusions are on purpose. It means someone should look before it merges.

## Install

Python 3.10 or newer. No other dependencies.

```
pip install git+https://github.com/Dfrank77/entra-ca-diff.git
```

## Usage

```
entra-ca-diff <baseline> <proposed>
```

Both arguments can be a single JSON file or a folder. Folders are read recursively. A file can hold one policy, a list of policies, or a Graph list response (`{"value": [...]}`). Policies are matched by `id`, or by `displayName` if there's no id. JSON files that aren't CA policies (named locations, for example) are skipped.

Try it on the included examples:

```
entra-ca-diff examples/baseline examples/proposed
```

```
4 findings (2 high, 2 medium) across 4 policies.

[HIGH] CA003 - Require MFA for all users
  state-weakened: Policy moved from enabled to report-only. It is no longer enforced.
[HIGH] CA004 - Block all access (testing)
  no-break-glass: Enabled block policy covers all users and all apps with no excluded users, groups or roles. This can lock everyone out of the tenant.
[MEDIUM] CA001 - Require MFA for Global Admins
  alternative-added: New OR alternative added. Users can now pass the policy with this instead of the existing requirement.
    - control:compliantDevice
[MEDIUM] CA002 - Block legacy authentication
  exclusion-added: New excluded groups.
    - 00000000-0000-0000-0000-00000000c001
```

Options:

| Option | What it does |
|---|---|
| `--format text\|markdown\|json` | Output format. Default is text. |
| `--output FILE` | Write the report to a file instead of the terminal. |
| `--fail-on high\|medium\|low\|never` | Exit 1 if any finding is at or above this severity. Default is high. |

Exit codes: 0 means nothing at or above `--fail-on`, 1 means findings, 2 means bad input.

## What it checks

| Rule | Severity | Triggers when |
|---|---|---|
| `state-weakened` | high / low | An enabled policy moves to report-only or disabled (high). Report-only to disabled is low. |
| `policy-removed` | high / low | A policy is deleted. High if it was enabled. |
| `control-removed` | high / medium / low | A grant control is removed. `block`, `mfa` and authentication strength are high. Terms of use and custom controls are low. |
| `auth-strength-changed` | medium | The authentication strength is swapped for a different one. |
| `operator-weakened` | high | Grant operator goes from `AND` to `OR` with more than one control. |
| `alternative-added` | medium | A new control is added under `OR`, which gives users another way to pass. |
| `exclusion-added` | medium | New excluded users, groups, roles, apps, service principals, locations, platforms or guests. |
| `scope-narrowed` | high / medium | Something removed from an include list. Losing `All` from included users or apps is high. Also flags new risk level, location or platform conditions and narrower client app types, since those make the policy apply to fewer sign-ins. |
| `no-break-glass` | high / medium | An enabled policy covers all users and all apps with no user, group or role exclusion. High for block policies, since that is how tenants get locked out. |

Every check is about the policy getting weaker. Changes that make a policy stricter aren't reported.

## Running it on pull requests

`examples/workflows/ca-review.yml` is a GitHub Actions workflow for the repo where you keep your policies. On each pull request it checks out the base branch, runs entra-ca-diff against the PR's version, and writes a findings table to the job summary. It fails the check on high findings.

It defaults to EntraExporter's folder layout (`Identity/Conditional/AccessPolicies`). Change `POLICY_PATH` if yours is different.

## Limits

- It compares JSON. It doesn't call Graph, so it can't tell you who is in a group or what an ID resolves to. Findings show raw IDs.
- Session controls (sign-in frequency, persistent browser) aren't checked yet.
- `no-break-glass` only looks for any user, group or role exclusion. It doesn't know whether that exclusion is actually your emergency access account.
- Authentication strength is compared by ID. If you change what's inside a strength policy, this won't see it.

## Development

```
pip install -e ".[dev]"
pytest
```

## License

MIT
