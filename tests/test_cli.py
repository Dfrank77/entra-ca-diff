import json
from pathlib import Path

import pytest

from entra_ca_diff.cli import main
from entra_ca_diff.html_report import render_html
from entra_ca_diff.loader import load_policies
from entra_ca_diff.rules import Finding

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


@pytest.fixture(autouse=True)
def _run_in_tmp(tmp_path, monkeypatch):
    # The CLI writes ca-diff-report.html to the working directory by default.
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)


def test_examples_flag_expected_findings(capsys):
    code = main([str(EXAMPLES / "baseline"), str(EXAMPLES / "proposed"), "--format", "json"])
    out = json.loads(capsys.readouterr().out)
    found = {(f["policy"].split(" - ")[0], f["rule"]) for f in out["findings"]}
    assert code == 1
    assert found == {
        ("CA001", "alternative-added"),
        ("CA002", "exclusion-added"),
        ("CA003", "state-weakened"),
        ("CA004", "no-break-glass"),
    }


def test_same_folder_passes(capsys):
    assert main([str(EXAMPLES / "baseline"), str(EXAMPLES / "baseline")]) == 0
    assert "No coverage or enforcement regressions" in capsys.readouterr().out


def test_fail_on_never_returns_zero(capsys):
    assert main([str(EXAMPLES / "baseline"), str(EXAMPLES / "proposed"), "--fail-on", "never"]) == 0


def test_fail_on_threshold(tmp_path, capsys):
    base, prop = tmp_path / "b.json", tmp_path / "p.json"
    policy = {"id": "x", "displayName": "X", "state": "enabled",
              "conditions": {"users": {"includeUsers": ["All"], "excludeUsers": ["bg"]},
                             "applications": {"includeApplications": ["All"]}},
              "grantControls": {"operator": "OR", "builtInControls": ["mfa"]}}
    base.write_text(json.dumps(policy))
    policy["conditions"]["users"]["excludeGroups"] = ["g1"]  # medium finding only
    prop.write_text(json.dumps(policy))
    assert main([str(base), str(prop)]) == 0
    assert main([str(base), str(prop), "--fail-on", "medium"]) == 1


def test_missing_path_is_error(capsys):
    assert main(["does-not-exist", str(EXAMPLES / "baseline")]) == 2
    assert "Path not found" in capsys.readouterr().err


def test_bad_json_is_error(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert main([str(bad), str(bad)]) == 2


def test_writes_github_step_summary(tmp_path, monkeypatch, capsys):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    main([str(EXAMPLES / "baseline"), str(EXAMPLES / "proposed")])
    assert "| high |" in summary.read_text()


def test_loader_accepts_graph_list_response(tmp_path):
    f = tmp_path / "all.json"
    f.write_text(json.dumps({"value": [
        {"id": "a", "displayName": "A", "state": "enabled", "conditions": {}},
        {"id": "b", "displayName": "B", "state": "disabled", "conditions": {}},
    ]}))
    assert set(load_policies(f).policies) == {"a", "b"}


def test_loader_reads_utf16_powershell_export(tmp_path):
    f = tmp_path / "p.json"
    f.write_bytes(json.dumps({"id": "a", "displayName": "A", "state": "enabled",
                              "conditions": {}}).encode("utf-16"))
    assert set(load_policies(f).policies) == {"a"}


def test_loader_skips_non_policy_json(tmp_path):
    (tmp_path / "policy.json").write_text(json.dumps(
        {"id": "a", "displayName": "A", "state": "enabled", "conditions": {}}))
    (tmp_path / "namedLocation.json").write_text(json.dumps({"id": "loc", "displayName": "HQ"}))
    result = load_policies(tmp_path)
    assert set(result.policies) == {"a"}
    assert len(result.skipped) == 1


def test_html_report_written_by_default(tmp_path):
    main([str(EXAMPLES / "baseline"), str(EXAMPLES / "proposed")])
    html = (tmp_path / "ca-diff-report.html").read_text()
    assert "CA004 - Block all access (testing)" in html
    assert 'class="policy sev-high"' in html


def test_html_custom_path_and_no_html(tmp_path):
    main([str(EXAMPLES / "baseline"), str(EXAMPLES / "baseline"), "--html", str(tmp_path / "r.html")])
    assert "No coverage or enforcement regressions" in (tmp_path / "r.html").read_text()
    (tmp_path / "ca-diff-report.html").unlink(missing_ok=True)
    main([str(EXAMPLES / "baseline"), str(EXAMPLES / "proposed"), "--no-html"])
    assert not (tmp_path / "ca-diff-report.html").exists()


def test_html_escapes_policy_names():
    html = render_html([Finding("high", "r", "<script>alert(1)</script>", "m")], 1, "a", "b")
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html
