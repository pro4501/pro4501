from datetime import date, timedelta

import pytest

from aegis.scope import Authorization, Scope, ScopeError


def _auth(confirmed=True):
    return Authorization(
        client="Lab",
        authorized_by="Me",
        engagement="Test",
        start_date=date.today() - timedelta(days=1),
        end_date=date.today() + timedelta(days=1),
        confirmed=confirmed,
    )


def test_unconfirmed_authorization_rejected():
    with pytest.raises(ScopeError):
        _auth(confirmed=False).validate()


def test_expired_window_rejected():
    auth = Authorization(
        client="Lab", authorized_by="Me", engagement="T",
        start_date=date(2000, 1, 1), end_date=date(2000, 1, 2), confirmed=True,
    )
    with pytest.raises(ScopeError):
        auth.validate()


def test_literal_ip_must_be_in_cidr():
    scope = Scope(authorization=_auth(), cidrs=["10.0.0.0/24"])
    assert scope.assert_target_allowed("10.0.0.5") == "10.0.0.5"
    with pytest.raises(ScopeError):
        scope.assert_target_allowed("10.0.1.5")


def test_exclusion_blocks_in_range_ip():
    scope = Scope(authorization=_auth(), cidrs=["10.0.0.0/24"], excluded=["10.0.0.9"])
    with pytest.raises(ScopeError):
        scope.assert_target_allowed("10.0.0.9")


def test_domain_scoping_allows_subdomains():
    scope = Scope(authorization=_auth(), domains=["example.com"])
    # No CIDR list -> name-based scoping only; a resolvable public name is fine.
    assert scope.assert_target_allowed("example.com") == "example.com"


def test_out_of_scope_name_rejected():
    scope = Scope(authorization=_auth(), domains=["example.com"])
    with pytest.raises(ScopeError):
        scope.assert_target_allowed("https://evil.test/")


def test_url_target_parsed():
    scope = Scope(authorization=_auth(), domains=["example.com"])
    assert scope.assert_target_allowed("https://www.example.com/path") == "www.example.com"


def test_no_targets_rejected(tmp_path):
    f = tmp_path / "scope.yaml"
    f.write_text(
        "authorization:\n"
        "  client: L\n  authorized_by: M\n  engagement: E\n"
        f"  start_date: '{date.today()}'\n  end_date: '{date.today()}'\n"
        "  confirmed: true\n"
    )
    with pytest.raises(ScopeError):
        Scope.from_file(str(f))
