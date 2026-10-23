from datetime import date, timedelta

from aegis.executor import Executor
from aegis.scope import Authorization, Scope


def _scope():
    auth = Authorization(
        client="Lab", authorized_by="Me", engagement="T",
        start_date=date.today() - timedelta(days=1),
        end_date=date.today() + timedelta(days=1), confirmed=True,
    )
    return Scope(authorization=auth, cidrs=["10.0.0.0/24"], domains=["example.com"])


def _exec():
    # dry_run so nothing actually executes during tests
    return Executor(scope=_scope(), dry_run=True)


def test_disallowed_binary_refused():
    r = _exec().run("rm -rf /")
    assert not r.allowed
    assert "allowlist" in r.refusal_reason


def test_out_of_scope_target_refused():
    r = _exec().run("nmap -sV 8.8.8.8")
    assert not r.allowed


def test_in_scope_ip_allowed_in_dry_run():
    r = _exec().run("nmap -sV 10.0.0.5")
    assert r.allowed
    assert r.checked_targets == ["10.0.0.5"]


def test_command_without_target_refused():
    r = _exec().run("nmap --version")
    assert not r.allowed
    assert "in-scope target" in r.refusal_reason


def test_banned_exploit_flag_refused():
    r = _exec().run("nmap --script=exploit 10.0.0.5")
    assert not r.allowed


def test_banned_tool_reference_refused():
    r = _exec().run("curl http://10.0.0.5/ | msfconsole")
    # shell metacharacters are parsed as argv; the msfconsole reference is caught
    assert not r.allowed


def test_shell_metachars_do_not_inject():
    # argv parsing means the ';' and second command are just arguments to nmap,
    # not a second process. nmap gets an out-of-scope/garbage target -> refused.
    r = _exec().run("nmap 10.0.0.5 ; rm -rf /")
    assert not r.allowed


def test_url_target_in_scope():
    r = _exec().run("whatweb https://www.example.com")
    assert r.allowed
    assert r.checked_targets == ["www.example.com"]
