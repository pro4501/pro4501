"""Safe command execution.

The AI proposes commands; this module decides whether they are allowed to run.
Two hard rules:

1. Only binaries on ALLOWED_TOOLS may run. These are reconnaissance,
   enumeration, and vulnerability-identification tools -- not exploitation
   frameworks. The agent's job is to find and report, not to weaponize.
2. Every host/URL argument must pass the Scope gate.

Commands run through argv (never a shell string), so shell metacharacters
cannot inject extra commands. A timeout bounds every run.
"""

from __future__ import annotations

import shlex
import subprocess
import time
from dataclasses import dataclass, field

from .scope import Scope, ScopeError

# Reconnaissance / enumeration / vuln-identification tooling only.
# Each entry maps a binary to a one-line description shown to the model.
ALLOWED_TOOLS: dict[str, str] = {
    "nmap": "Port/service scanning and NSE enumeration scripts.",
    "masscan": "Fast port discovery across a range.",
    "whatweb": "Web technology fingerprinting.",
    "nikto": "Web server misconfiguration and known-issue scanner.",
    "nuclei": "Template-based vulnerability scanner.",
    "gobuster": "Content/DNS/vhost brute-force discovery.",
    "ffuf": "Web fuzzing for content and parameters.",
    "dig": "DNS lookups.",
    "host": "DNS lookups.",
    "whois": "Domain/IP registration lookups.",
    "curl": "Fetch HTTP responses and headers.",
    "wget": "Fetch resources over HTTP(S).",
    "openssl": "Inspect TLS certificates and configuration (s_client).",
    "sslscan": "Enumerate TLS versions and ciphers.",
    "dnsrecon": "DNS reconnaissance.",
    "sublist3r": "Passive subdomain enumeration.",
    "wpscan": "WordPress enumeration and known-vulnerability checks.",
    "enum4linux": "SMB/NetBIOS enumeration.",
    "smbclient": "SMB share inspection.",
}

# Flags that turn a recon tool into an attack tool, or that would let a scan
# run away. Refused regardless of the binary.
BANNED_TOKENS: tuple[str, ...] = (
    "--script=exploit",
    "--script-args",
    "vuln,exploit",
    "-oG-",  # noise; keep output on stdout
)

# Shell control tokens. Commands run via argv (no shell), so these cannot
# chain a second process -- but a legitimate recon command never needs one as a
# standalone argument, so their presence signals an injection attempt. Refused.
SHELL_CONTROL_TOKENS: frozenset[str] = frozenset({";", "|", "||", "&", "&&", ">", ">>", "<", "`"})

# Binaries that should never appear even as an argument value.
BANNED_SUBSTRINGS: tuple[str, ...] = (
    "msfconsole",
    "msfvenom",
    "meterpreter",
    "sqlmap --os-shell",
    "hydra",  # online password attacks are out of scope for this tool
    "medusa",
)


@dataclass
class CommandResult:
    command: list[str]
    checked_targets: list[str]
    exit_code: int | None
    stdout: str
    stderr: str
    duration_s: float
    allowed: bool
    refusal_reason: str | None = None

    def as_model_feedback(self) -> str:
        if not self.allowed:
            return f"REFUSED: {self.refusal_reason}"
        head = (
            f"exit={self.exit_code} duration={self.duration_s:.1f}s "
            f"targets_verified={','.join(self.checked_targets) or 'n/a'}\n"
        )
        out = self.stdout.strip()
        err = self.stderr.strip()
        body = out
        if err:
            body += f"\n[stderr]\n{err}"
        return head + _truncate(body, 12000)


@dataclass
class Executor:
    scope: Scope
    dry_run: bool = False
    transcript: list[CommandResult] = field(default_factory=list)

    def run(self, command: str) -> CommandResult:
        try:
            argv = shlex.split(command)
        except ValueError as exc:
            return self._refuse(command, [], f"Could not parse command: {exc}")

        if not argv:
            return self._refuse(command, [], "Empty command.")

        binary = argv[0].rsplit("/", 1)[-1]
        if binary not in ALLOWED_TOOLS:
            return self._refuse(
                command,
                [],
                f"Tool {binary!r} is not on the allowlist. Allowed: "
                f"{', '.join(sorted(ALLOWED_TOOLS))}.",
            )

        for tok in argv[1:]:
            if tok in SHELL_CONTROL_TOKENS or "`" in tok or "$(" in tok:
                return self._refuse(
                    command, [], f"Refused shell-control token {tok!r} in arguments."
                )

        lowered = command.lower()
        for token in BANNED_TOKENS:
            if token in lowered:
                return self._refuse(command, [], f"Refused flag/token: {token!r}.")
        for sub in BANNED_SUBSTRINGS:
            if sub in lowered:
                return self._refuse(command, [], f"Refused reference to {sub!r}.")

        # Validate every argument that looks like a target.
        checked: list[str] = []
        try:
            for arg in argv[1:]:
                if _looks_like_target(arg):
                    host = self.scope.assert_target_allowed(arg)
                    checked.append(host)
        except ScopeError as exc:
            return self._refuse(command, checked, str(exc))

        if not checked:
            return self._refuse(
                command,
                [],
                "No in-scope target found in the command. Every scan must name "
                "an authorized host, IP, or URL as an argument.",
            )

        if self.dry_run:
            result = CommandResult(
                command=argv,
                checked_targets=checked,
                exit_code=None,
                stdout="[dry-run] command approved but not executed.",
                stderr="",
                duration_s=0.0,
                allowed=True,
            )
            self.transcript.append(result)
            return result

        return self._execute(argv, checked)

    def _execute(self, argv: list[str], checked: list[str]) -> CommandResult:
        start = time.monotonic()
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=self.scope.max_runtime_seconds,
                check=False,
            )
            result = CommandResult(
                command=argv,
                checked_targets=checked,
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                duration_s=time.monotonic() - start,
                allowed=True,
            )
        except FileNotFoundError:
            result = CommandResult(
                command=argv,
                checked_targets=checked,
                exit_code=None,
                stdout="",
                stderr=f"{argv[0]} is not installed on this system.",
                duration_s=time.monotonic() - start,
                allowed=True,
            )
        except subprocess.TimeoutExpired:
            result = CommandResult(
                command=argv,
                checked_targets=checked,
                exit_code=None,
                stdout="",
                stderr=f"Command timed out after {self.scope.max_runtime_seconds}s.",
                duration_s=time.monotonic() - start,
                allowed=True,
            )
        self.transcript.append(result)
        return result

    def _refuse(self, command: str, checked: list[str], reason: str) -> CommandResult:
        result = CommandResult(
            command=shlex.split(command) if command.strip() else [command],
            checked_targets=checked,
            exit_code=None,
            stdout="",
            stderr="",
            duration_s=0.0,
            allowed=False,
            refusal_reason=reason,
        )
        self.transcript.append(result)
        return result


def _looks_like_target(arg: str) -> bool:
    if arg.startswith("-"):
        return False
    if "://" in arg:
        return True
    # bare domain, host, ip, or host:port -- contains a dot or a colon and no slash-only path
    if "/" in arg and "://" not in arg and "." not in arg.split("/")[0]:
        return False  # looks like a local path / wordlist
    return ("." in arg) or (":" in arg)


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[truncated {len(text) - limit} chars]"
