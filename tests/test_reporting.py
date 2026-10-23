from datetime import date, timedelta

from aegis.agent import AssessmentResult, Finding
from aegis.executor import Executor
from aegis.reporting import ReportContext, build_report, severity_counts
from aegis.scope import Authorization, Scope


def _scope():
    auth = Authorization(
        client="Acme Lab", authorized_by="CISO", engagement="Test Engagement",
        start_date=date.today() - timedelta(days=1),
        end_date=date.today() + timedelta(days=1), confirmed=True,
    )
    return Scope(authorization=auth, hosts=["scanme.example.com"])


def test_severity_counts():
    findings = [
        Finding("a", "high", "t", "d", "e", "r"),
        Finding("b", "high", "t", "d", "e", "r"),
        Finding("c", "low", "t", "d", "e", "r"),
    ]
    counts = severity_counts(findings)
    assert counts["high"] == 2
    assert counts["low"] == 1


def test_report_contains_findings_and_scope():
    scope = _scope()
    executor = Executor(scope=scope, dry_run=True)
    executor.run("nmap -sV scanme.example.com")  # populates transcript (refused: not resolvable, but logged)
    result = AssessmentResult(
        findings=[
            Finding(
                title="Outdated OpenSSH",
                severity="medium",
                target="scanme.example.com:22",
                description="Running an old OpenSSH version.",
                evidence="OpenSSH 6.6.1",
                remediation="Upgrade OpenSSH.",
                cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            )
        ],
        summary="One medium issue found.",
        steps_taken=3,
    )
    report = build_report(ReportContext(scope=scope, executor=executor, result=result))
    assert "Penetration Test Report" in report
    assert "Outdated OpenSSH" in report
    assert "Test Engagement" in report
    assert "Executive Summary" in report
    assert "Command Log" in report
    assert "CVSS" in report


def test_report_handles_no_findings():
    scope = _scope()
    executor = Executor(scope=scope, dry_run=True)
    result = AssessmentResult(findings=[], summary="Clean.", steps_taken=1)
    report = build_report(ReportContext(scope=scope, executor=executor, result=result))
    assert "No findings" in report or "No issues" in report
