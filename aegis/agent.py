"""The Claude-driven pentest agent.

AEGIS runs a manual tool-use loop so that every command the model proposes
passes through the Executor's allowlist + scope gate before it runs. The model
plans the assessment, calls tools to gather evidence, records structured
findings, and signals when it is done. A separate pass then writes the report.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

import anthropic

from .executor import ALLOWED_TOOLS, Executor
from .scope import Scope

MODEL = "claude-opus-4-8"

SYSTEM_PROMPT = """\
You are AEGIS, an autonomous penetration-testing assistant operating under a \
signed, scope-limited engagement. You behave like a professional consultant \
running the automated phase of an authorized assessment.

Operating rules (non-negotiable):
- You may only interact with targets inside the authorized scope. The harness \
enforces this and will REFUSE out-of-scope commands; do not try to work around \
a refusal.
- Your goal is to DISCOVER and DOCUMENT weaknesses: open services, \
misconfigurations, outdated software, weak TLS, exposed content, and known \
CVEs. You identify and evidence issues. You do not launch destructive actions, \
denial-of-service, online password attacks, or exploitation payloads.
- Work methodically: reconnaissance -> service/host enumeration -> \
web/app enumeration -> vulnerability identification. Let earlier results guide \
later commands.
- Prefer safe, non-intrusive scan options. Keep scans narrow and purposeful.

Available command-line tools (allowlist): {tools}

How to work:
- Use `run_command` to execute one allowlisted tool invocation at a time. Each \
command must name an in-scope host, IP, or URL.
- When you identify a real issue, call `record_finding` with a precise title, \
severity, affected target, the evidence, and concrete remediation.
- Think about what a result tells you before the next step. Do not repeat \
scans that add nothing.
- When you have covered the scope and recorded all findings, call `finish` \
with a short summary of what you tested.
"""

TOOLS = [
    {
        "name": "run_command",
        "description": (
            "Run a single allowlisted recon/enumeration/vuln-scan command. "
            "The command string is parsed as argv (no shell). It must include "
            "at least one in-scope target. Out-of-scope targets and non-allowlisted "
            "tools are refused."
        ),
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Full command line, e.g. 'nmap -sV -T3 scanme.example.com'.",
                },
                "rationale": {
                    "type": "string",
                    "description": "One sentence: why this command, given results so far.",
                },
            },
            "required": ["command", "rationale"],
        },
    },
    {
        "name": "record_finding",
        "description": "Record a confirmed or suspected security finding with evidence.",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "title": {"type": "string"},
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                },
                "target": {"type": "string", "description": "Affected host/service/URL."},
                "description": {"type": "string", "description": "What the issue is and why it matters."},
                "evidence": {"type": "string", "description": "Command output or observation that proves it."},
                "remediation": {"type": "string", "description": "How to fix it."},
                "cvss": {"type": "string", "description": "CVSS 3.1 vector or base score if known. Optional."},
            },
            "required": ["title", "severity", "target", "description", "evidence", "remediation"],
        },
    },
    {
        "name": "finish",
        "description": "Signal that the assessment is complete.",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "summary": {"type": "string", "description": "What was tested and the overall posture."},
            },
            "required": ["summary"],
        },
    },
]


@dataclass
class Finding:
    title: str
    severity: str
    target: str
    description: str
    evidence: str
    remediation: str
    cvss: str | None = None


@dataclass
class AssessmentResult:
    findings: list[Finding] = field(default_factory=list)
    summary: str = ""
    steps_taken: int = 0


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class AegisAgent:
    def __init__(
        self,
        scope: Scope,
        executor: Executor,
        client: anthropic.Anthropic | None = None,
        max_steps: int = 40,
        on_event=None,
    ) -> None:
        self.scope = scope
        self.executor = executor
        self.client = client or anthropic.Anthropic()
        self.max_steps = max_steps
        self.on_event = on_event or (lambda *_: None)
        self.findings: list[Finding] = []

    def _emit(self, kind: str, detail: str) -> None:
        self.on_event(kind, detail)

    def run(self) -> AssessmentResult:
        system = SYSTEM_PROMPT.format(
            tools=", ".join(f"{name} ({desc})" for name, desc in ALLOWED_TOOLS.items())
        )
        kickoff = (
            f"Engagement: {self.scope.authorization.engagement} for "
            f"{self.scope.authorization.client}.\n"
            f"In-scope hosts: {self.scope.hosts or '(none listed)'}\n"
            f"In-scope CIDRs: {self.scope.cidrs or '(none listed)'}\n"
            f"In-scope domains: {self.scope.domains or '(none listed)'}\n"
            f"Excluded: {self.scope.excluded or '(none)'}\n\n"
            "Begin the authorized assessment. Start with reconnaissance, then "
            "enumerate and identify vulnerabilities. Record findings as you go."
        )
        messages: list[dict] = [{"role": "user", "content": kickoff}]

        summary = ""
        steps = 0
        done = False
        while not done and steps < self.max_steps:
            response = self.client.messages.create(
                model=MODEL,
                max_tokens=16000,
                thinking={"type": "adaptive"},
                system=system,
                tools=TOOLS,
                messages=messages,
            )

            if response.stop_reason == "refusal":
                detail = getattr(response.stop_details, "explanation", "") or "model declined"
                self._emit("refusal", detail)
                break

            messages.append({"role": "assistant", "content": response.content})

            tool_uses = [b for b in response.content if b.type == "tool_use"]
            for block in response.content:
                if block.type == "text" and block.text.strip():
                    self._emit("thought", block.text.strip())

            if not tool_uses:
                if response.stop_reason == "end_turn":
                    break
                continue

            tool_results = []
            for tu in tool_uses:
                steps += 1
                feedback, finished, maybe_summary = self._handle_tool(tu.name, tu.input)
                tool_results.append(
                    {"type": "tool_result", "tool_use_id": tu.id, "content": feedback}
                )
                if finished:
                    done = True
                    summary = maybe_summary

            messages.append({"role": "user", "content": tool_results})

        return AssessmentResult(
            findings=sorted(self.findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 9)),
            summary=summary,
            steps_taken=steps,
        )

    def _handle_tool(self, name: str, tool_input: dict):
        if name == "run_command":
            command = tool_input.get("command", "")
            rationale = tool_input.get("rationale", "")
            self._emit("command", f"{command}  # {rationale}")
            result = self.executor.run(command)
            self._emit(
                "result",
                result.refusal_reason or f"exit={result.exit_code} ({result.duration_s:.1f}s)",
            )
            return result.as_model_feedback(), False, ""

        if name == "record_finding":
            finding = Finding(
                title=tool_input["title"],
                severity=tool_input["severity"],
                target=tool_input["target"],
                description=tool_input["description"],
                evidence=tool_input["evidence"],
                remediation=tool_input["remediation"],
                cvss=tool_input.get("cvss"),
            )
            self.findings.append(finding)
            self._emit("finding", f"[{finding.severity.upper()}] {finding.title} ({finding.target})")
            return "Finding recorded.", False, ""

        if name == "finish":
            summary = tool_input.get("summary", "")
            self._emit("finish", summary)
            return "Assessment closed.", True, summary

        return f"Unknown tool {name!r}.", False, ""
