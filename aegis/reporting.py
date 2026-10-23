"""Report generation.

Two layers:
- `build_report` deterministically assembles a professional Markdown report
  from the structured findings, scope, and command transcript. This always
  works, with no extra model call.
- `narrative_sections` optionally asks Claude to write the executive summary
  and overall-risk prose from the structured data, for a more polished report.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass

import anthropic

from .agent import AssessmentResult, Finding
from .executor import Executor
from .scope import Scope

MODEL = "claude-opus-4-8"

_SEV_BADGE = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}


@dataclass
class ReportContext:
    scope: Scope
    executor: Executor
    result: AssessmentResult
    narrative: dict | None = None


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {k: 0 for k in _SEV_BADGE}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def build_report(ctx: ReportContext) -> str:
    scope = ctx.scope
    result = ctx.result
    auth = scope.authorization
    counts = severity_counts(result.findings)
    now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M")

    lines: list[str] = []
    a = lines.append

    a(f"# Penetration Test Report — {auth.engagement}")
    a("")
    a(f"**Client:** {auth.client}  ")
    a(f"**Authorized by:** {auth.authorized_by}  ")
    a(f"**Engagement window:** {auth.start_date} to {auth.end_date}  ")
    a(f"**Report generated:** {now}  ")
    a(f"**Tooling:** AEGIS (AI-assisted authorized assessment)  ")
    a("")
    a("> This assessment was performed under written authorization against the "
      "scope defined below. All testing was limited to reconnaissance, "
      "enumeration, and non-destructive vulnerability identification.")
    a("")

    # Executive summary
    a("## 1. Executive Summary")
    a("")
    if ctx.narrative and ctx.narrative.get("executive_summary"):
        a(ctx.narrative["executive_summary"])
    else:
        total = len(result.findings)
        a(f"AEGIS assessed the in-scope systems and recorded **{total} finding(s)**: "
          + ", ".join(f"{counts[s]} {s}" for s in _SEV_BADGE if counts[s]) + "."
          if total else "No issues were identified within the tested scope.")
        if result.summary:
            a("")
            a(result.summary)
    a("")

    # Risk overview table
    a("## 2. Findings Overview")
    a("")
    a("| # | Severity | Finding | Target |")
    a("|---|----------|---------|--------|")
    for i, f in enumerate(result.findings, 1):
        a(f"| {i} | {_SEV_BADGE.get(f.severity, f.severity.upper())} | {f.title} | {f.target} |")
    if not result.findings:
        a("| – | – | No findings recorded | – |")
    a("")

    # Scope
    a("## 3. Scope")
    a("")
    if scope.hosts:
        a(f"- **Hosts:** {', '.join(scope.hosts)}")
    if scope.cidrs:
        a(f"- **Networks:** {', '.join(scope.cidrs)}")
    if scope.domains:
        a(f"- **Domains:** {', '.join(scope.domains)}")
    if scope.excluded:
        a(f"- **Excluded:** {', '.join(scope.excluded)}")
    a("")

    # Methodology
    a("## 4. Methodology")
    a("")
    a("The automated phase followed a reconnaissance → enumeration → "
      "vulnerability-identification workflow. An AI agent (Claude) planned each "
      "step from prior results; every command was validated against the "
      "authorized scope and an allowlist of non-destructive tools before "
      "execution. The agent performed **{n}** tool action(s)."
      .format(n=result.steps_taken))
    a("")

    # Detailed findings
    a("## 5. Detailed Findings")
    a("")
    if not result.findings:
        a("_No findings were recorded within the tested scope._")
        a("")
    for i, f in enumerate(result.findings, 1):
        a(f"### 5.{i} {f.title}")
        a("")
        a(f"- **Severity:** {_SEV_BADGE.get(f.severity, f.severity.upper())}")
        a(f"- **Affected target:** {f.target}")
        if f.cvss:
            a(f"- **CVSS:** {f.cvss}")
        a("")
        a("**Description**")
        a("")
        a(f.description)
        a("")
        a("**Evidence**")
        a("")
        a("```")
        a(f.evidence.strip())
        a("```")
        a("")
        a("**Remediation**")
        a("")
        a(f.remediation)
        a("")

    # Appendix: command log
    a("## 6. Appendix — Command Log")
    a("")
    a("Full transcript of commands the agent ran (and any it was refused).")
    a("")
    for r in ctx.executor.transcript:
        cmd = " ".join(r.command)
        if not r.allowed:
            a(f"- ❌ `{cmd}` — refused: {r.refusal_reason}")
        else:
            a(f"- ✅ `{cmd}` — exit={r.exit_code}, {r.duration_s:.1f}s, "
              f"targets: {', '.join(r.checked_targets) or 'n/a'}")
    if not ctx.executor.transcript:
        a("- _(no commands executed)_")
    a("")

    a("---")
    a("")
    a("_Generated by AEGIS. Findings should be validated by a qualified human "
      "before remediation decisions are made._")
    a("")
    return "\n".join(lines)


def narrative_sections(
    ctx_scope: Scope,
    result: AssessmentResult,
    client: anthropic.Anthropic | None = None,
) -> dict:
    """Ask Claude to write an executive summary from the structured findings."""
    client = client or anthropic.Anthropic()
    findings_blob = "\n".join(
        f"- [{f.severity}] {f.title} on {f.target}: {f.description}"
        for f in result.findings
    ) or "No findings were recorded."

    prompt = (
        "Write a concise executive summary (2-4 short paragraphs) for a "
        "penetration test report aimed at a non-technical business audience. "
        "Describe the overall security posture, the most important risks, and "
        "the recommended priorities. Do not invent findings beyond those listed.\n\n"
        f"Engagement: {ctx_scope.authorization.engagement}\n"
        f"Findings:\n{findings_blob}\n\n"
        f"Agent summary: {result.summary}"
    )
    response = client.messages.create(
        model=MODEL,
        max_tokens=4000,
        thinking={"type": "adaptive"},
        messages=[{"role": "user", "content": prompt}],
    )
    text = next((b.text for b in response.content if b.type == "text"), "")
    return {"executive_summary": text.strip()}
