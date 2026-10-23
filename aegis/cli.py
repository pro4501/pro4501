"""Command-line entrypoint for AEGIS."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .scope import Scope, ScopeError

_EVENT_PREFIX = {
    "thought": "\033[90m  …\033[0m",
    "command": "\033[36m  $\033[0m",
    "result": "\033[90m   ↳\033[0m",
    "finding": "\033[33m  ⚑\033[0m",
    "refusal": "\033[31m  ⚠\033[0m",
    "finish": "\033[32m  ✓\033[0m",
}


def _print_event(kind: str, detail: str) -> None:
    prefix = _EVENT_PREFIX.get(kind, "   ")
    if kind == "thought" and len(detail) > 280:
        detail = detail[:277] + "..."
    print(f"{prefix} {detail}", flush=True)


def _confirm_authorization(scope: Scope, assume_yes: bool) -> bool:
    auth = scope.authorization
    print("\n=== AUTHORIZATION CHECK ===")
    print(f"Client:        {auth.client}")
    print(f"Engagement:    {auth.engagement}")
    print(f"Authorized by: {auth.authorized_by}")
    print(f"Window:        {auth.start_date} → {auth.end_date}")
    print(f"Targets:       hosts={scope.hosts} cidrs={scope.cidrs} domains={scope.domains}")
    print("===========================")
    print(
        "\nBy continuing you confirm you have WRITTEN PERMISSION to test the "
        "targets above. Testing systems without authorization is illegal."
    )
    if assume_yes:
        print("(--yes supplied; proceeding)")
        return True
    try:
        answer = input("Type 'I AM AUTHORIZED' to proceed: ").strip()
    except EOFError:
        return False
    return answer == "I AM AUTHORIZED"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="AEGIS — AI-assisted, scope-gated authorized penetration testing.",
    )
    parser.add_argument("--scope", required=True, help="Path to the scope/authorization YAML file.")
    parser.add_argument("--output", "-o", default="aegis-report.md", help="Report output path.")
    parser.add_argument("--max-steps", type=int, default=40, help="Max agent tool actions.")
    parser.add_argument("--dry-run", action="store_true", help="Validate + approve commands but do not execute them.")
    parser.add_argument("--yes", action="store_true", help="Skip the interactive authorization prompt (use only in automation you control).")
    parser.add_argument("--no-narrative", action="store_true", help="Skip the AI-written executive summary.")
    args = parser.parse_args(argv)

    try:
        scope = Scope.from_file(args.scope)
    except (ScopeError, FileNotFoundError, ValueError) as exc:
        print(f"Scope error: {exc}", file=sys.stderr)
        return 2

    if not _confirm_authorization(scope, args.yes):
        print("Authorization not confirmed. Aborting.", file=sys.stderr)
        return 3

    # Import here so `--help` and scope validation work without the SDK/key.
    import anthropic

    from .agent import AegisAgent
    from .executor import Executor
    from .reporting import ReportContext, build_report, narrative_sections

    try:
        client = anthropic.Anthropic()
    except Exception as exc:  # noqa: BLE001
        print(f"Could not initialize Anthropic client: {exc}", file=sys.stderr)
        print("Set ANTHROPIC_API_KEY or run `ant auth login`.", file=sys.stderr)
        return 4

    executor = Executor(scope=scope, dry_run=args.dry_run)
    agent = AegisAgent(
        scope=scope,
        executor=executor,
        client=client,
        max_steps=args.max_steps,
        on_event=_print_event,
    )

    print("\n=== STARTING ASSESSMENT ===\n")
    result = agent.run()
    print(f"\n=== ASSESSMENT COMPLETE: {len(result.findings)} finding(s), "
          f"{result.steps_taken} action(s) ===\n")

    narrative = None
    if not args.no_narrative:
        try:
            narrative = narrative_sections(scope, result, client=client)
        except Exception as exc:  # noqa: BLE001
            print(f"(narrative generation skipped: {exc})", file=sys.stderr)

    report = build_report(
        ReportContext(scope=scope, executor=executor, result=result, narrative=narrative)
    )
    out = Path(args.output)
    out.write_text(report, encoding="utf-8")
    print(f"Report written to {out.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
