# AEGIS — AI-assisted authorized penetration testing

AEGIS drives standard reconnaissance and vulnerability-identification tools with
an AI agent (Claude), under a **signed, enforced engagement scope**, and writes a
professional Markdown report at the end.

The agent plans the assessment, runs tools, reasons about what each result
means, decides the next step, records structured findings, and then produces an
executive summary, a findings table, detailed findings with evidence and
remediation, a methodology section, and a full command log.

> ⚠️ **Authorized use only.** AEGIS is for systems you own or have **written
> permission** to test, and for deliberately vulnerable labs. It will not run
> until you declare authorization, and it refuses any target outside the scope
> you define. Testing systems without authorization is illegal.

---

## What makes this safe (and portfolio-worthy)

Most "AI hacking tool" demos skip the parts that make a tool usable on a real
engagement. AEGIS is built around them:

| Guardrail | How it works |
|---|---|
| **Authorization gate** | Won't start until `authorization.confirmed: true` in the scope file *and* you type a confirmation at launch. Also checks the engagement date window. |
| **Scope enforcement** | Every host/IP/URL an AI command touches is validated against your allowlist. Names are resolved and the resulting IPs are re-checked against authorized CIDRs, so an in-scope name that resolves out-of-scope is still refused. |
| **Tool allowlist** | Only non-destructive recon / enumeration / vuln-identification tools can run (`nmap`, `whatweb`, `nikto`, `nuclei`, `gobuster`, `ffuf`, `sslscan`, …). Exploitation frameworks and online password crackers are blocked. |
| **No shell** | Commands run via `argv`, never a shell string, so metacharacters can't chain a second process. Shell-control tokens in arguments are rejected outright. |
| **Bounded** | Per-command timeout and a cap on total agent actions. |
| **Auditable** | Every command — run or refused — is logged in the report's appendix. |

The design mirrors how the automated phase of a real scoped assessment actually
works: **identify and document, then hand off to a human.** Findings are marked
as requiring human validation.

---

## Install

```bash
pip install -r requirements.txt          # or: pip install -e .
export ANTHROPIC_API_KEY=sk-ant-...       # or run `ant auth login`
```

The scanning tools themselves (`nmap`, etc.) must be installed and on your
`PATH`. Missing tools are reported per-command rather than crashing the run.

## Use

1. Copy the scope template and fill it in for **your** authorized engagement:

   ```bash
   cp scope.example.yaml my-engagement.yaml
   # edit targets, set authorization.confirmed: true (only with permission)
   ```

2. Run it:

   ```bash
   python -m aegis --scope my-engagement.yaml -o report.md
   ```

   Useful flags:
   - `--dry-run` — validate and approve every command the agent proposes, but
     don't execute (great for seeing its plan safely, and for CI).
   - `--max-steps N` — cap how many tool actions the agent takes.
   - `--no-narrative` — skip the AI-written executive summary.
   - `--yes` — skip the interactive confirmation (for automation you control).

### A safe first run

`scanme.nmap.org` is a host the Nmap project operates **specifically** for scan
practice. The shipped `scope.example.yaml` targets it — set `confirmed: true`
and try:

```bash
python -m aegis --scope scope.example.yaml -o report.md
```

## Scope file

```yaml
authorization:
  client: "Acme Corp (lab)"
  engagement: "Q4 external web assessment"
  authorized_by: "Jane Doe, CISO — RoE signed 2026-10-20"
  start_date: "2026-10-20"
  end_date: "2026-11-20"
  confirmed: true          # only with written authorization

hosts:   [scanme.nmap.org] # explicit hosts/IPs
cidrs:   []                # authorized ranges; names must resolve into these
domains: []                # subdomains of these are in scope
excluded: []               # never touched, even if inside a range above
max_runtime_seconds: 300
```

## How it fits together

```
scope.py      Authorization + scope enforcement (the gate everything passes through)
executor.py   Allowlist + argv execution + per-command validation and logging
agent.py      Claude tool-use loop: plan -> run_command -> record_finding -> finish
reporting.py  Deterministic Markdown report + optional AI executive summary
cli.py        Entrypoint, authorization prompt, event stream
```

## Tests

```bash
python -m pytest -q
```

The safety-critical pieces (scope membership, exclusions, allowlist, injection
resistance, report assembly) are covered and run **without** an API key.

## Extending it

- Add tools to `ALLOWED_TOOLS` in `aegis/executor.py` (keep it non-destructive).
- Add tools for the agent (e.g. a passive-OSINT lookup) in `aegis/agent.py`.
- Swap the model via `MODEL` in `agent.py` / `reporting.py`.

## License

MIT. You are responsible for using AEGIS only where you are authorized.
