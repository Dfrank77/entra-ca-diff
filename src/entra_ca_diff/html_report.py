"""Render findings as a self-contained HTML report."""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape

from .rules import SEVERITY_ORDER, Finding

SEVERITIES = ["high", "medium", "low"]


def render_html(findings: list[Finding], compared: int, baseline: str, proposed: str) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}

    by_policy: dict[str, list[Finding]] = {}
    for f in findings:
        by_policy.setdefault(f.policy, []).append(f)
    ordered = sorted(
        by_policy.items(),
        key=lambda kv: (-max(SEVERITY_ORDER[f.severity] for f in kv[1]), kv[0].lower()),
    )

    parts = [_HEAD.format(now=escape(now)), _summary(counts, len(findings), compared, baseline, proposed)]
    if not findings:
        parts.append('<p class="empty">No coverage or enforcement regressions found.</p>')
    else:
        parts.append('<div class="findings">')
        parts.extend(_policy_card(name, fs) for name, fs in ordered)
        parts.append("</div>")
    parts.append(_FOOT)
    return "".join(parts)


def _summary(counts: dict[str, int], total: int, compared: int, baseline: str, proposed: str) -> str:
    stats = "".join(
        f'<div class="stat sev-{s}"><span class="n">{counts[s]}</span><span class="l">{s}</span></div>'
        for s in SEVERITIES if counts[s]
    )
    return f"""
      <section class="summary">
        <div class="meta">
          <div><span class="n">{compared}</span><span class="l">policies compared</span></div>
          <div class="paths">
            <span class="l">baseline</span><code>{escape(baseline)}</code>
            <span class="l">proposed</span><code>{escape(proposed)}</code>
          </div>
        </div>
        <div class="tally">
          <div class="total"><span class="n">{total}</span><span class="l">findings</span></div>
          {stats}
        </div>
      </section>
    """


def _policy_card(name: str, findings: list[Finding]) -> str:
    top = max(findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity
    rows = []
    for f in sorted(findings, key=lambda f: -SEVERITY_ORDER[f.severity]):
        details = ""
        if f.details:
            details = '<div class="ids">' + "".join(
                f"<code>{escape(d)}</code>" for d in f.details) + "</div>"
        rows.append(
            f'<li class="sev-{f.severity}"><span class="pill">{f.severity}</span>'
            f'<div class="row"><span class="rule">{escape(f.rule)}</span>'
            f'<span class="detail">{escape(f.message)}</span>{details}</div></li>'
        )
    return f"""
      <article class="policy sev-{top}">
        <header><h2>{escape(name)}</h2></header>
        <ul>{"".join(rows)}</ul>
      </article>
    """


_HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Entra CA Diff</title>
<style>
  :root {{
    --bg: #f8fafc; --card: #fff; --border: #e2e8f0;
    --text: #0f172a; --muted: #64748b;
    --sev-high: #ea580c; --sev-medium: #eab308; --sev-low: #2563eb;
    --bg-high: #fed7aa; --bg-medium: #fef9c3; --bg-low: #bfdbfe;
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.5; }}
  main {{ max-width: 1100px; margin: 0 auto; padding: 2rem 1.5rem 4rem; }}
  h1 {{ margin: 0 0 0.25rem; font-size: 1.5rem; }}
  .ts {{ color: var(--muted); font-size: 0.875rem; margin: 0 0 2rem; }}
  .summary {{ display: grid; gap: 1rem; grid-template-columns: 1fr; margin-bottom: 2rem; }}
  @media (min-width: 720px) {{ .summary {{ grid-template-columns: 1fr 1fr; }} }}
  .meta, .tally {{ display: flex; flex-wrap: wrap; gap: 0.5rem;
    background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 1rem; }}
  .meta > div, .tally > div {{ flex: 1 1 auto; min-width: 6rem; padding: 0.5rem 0.75rem; }}
  .paths code {{ display: block; font-size: 0.8rem; margin-bottom: 0.4rem; word-break: break-all; }}
  .n {{ display: block; font-size: 1.5rem; font-weight: 600; }}
  .l {{ display: block; font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }}
  .stat.sev-high .n {{ color: var(--sev-high); }}
  .stat.sev-medium .n {{ color: var(--sev-medium); }}
  .stat.sev-low .n {{ color: var(--sev-low); }}
  .findings {{ display: flex; flex-direction: column; gap: 1rem; }}
  .policy {{ background: var(--card); border: 1px solid var(--border); border-left: 4px solid;
    border-radius: 12px; padding: 1.25rem 1.5rem; }}
  .policy.sev-high {{ border-left-color: var(--sev-high); }}
  .policy.sev-medium {{ border-left-color: var(--sev-medium); }}
  .policy.sev-low {{ border-left-color: var(--sev-low); }}
  .policy h2 {{ margin: 0 0 0.75rem; font-size: 1.1rem; }}
  .policy ul {{ margin: 0; padding: 0; list-style: none; display: flex; flex-direction: column; gap: 0.5rem; }}
  .policy li {{ display: flex; gap: 0.75rem; align-items: flex-start; padding: 0.625rem 0.875rem; border-radius: 8px; }}
  li.sev-high {{ background: var(--bg-high); }}
  li.sev-medium {{ background: var(--bg-medium); }}
  li.sev-low {{ background: var(--bg-low); }}
  .pill {{ display: inline-block; font-size: 0.7rem; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.05em; padding: 0.125rem 0.5rem; border-radius: 999px; white-space: nowrap; color: white; }}
  .sev-high .pill {{ background: var(--sev-high); }}
  .sev-medium .pill {{ background: var(--sev-medium); }}
  .sev-low .pill {{ background: var(--sev-low); }}
  .row {{ display: flex; flex-direction: column; gap: 0.125rem; flex: 1; min-width: 0; }}
  .rule {{ font-family: ui-monospace, monospace; font-size: 0.8rem; color: var(--muted); }}
  .detail {{ font-size: 0.9375rem; }}
  .ids {{ display: flex; flex-wrap: wrap; gap: 0.35rem; margin-top: 0.35rem; }}
  .ids code {{ font-family: ui-monospace, monospace; font-size: 0.75rem; background: rgba(0,0,0,0.07);
    padding: 0.1rem 0.4rem; border-radius: 5px; word-break: break-all; }}
  .empty {{ text-align: center; padding: 3rem; color: var(--muted); }}
</style>
</head>
<body>
<main>
  <h1>Entra CA Diff</h1>
  <p class="ts">{now}</p>
"""

_FOOT = """
</main>
</body>
</html>
"""
