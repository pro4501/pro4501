"""Authorization and scope enforcement.

Nothing in AEGIS runs against a host until that host has been proven to sit
inside an explicitly authorized engagement scope. This module is the single
gate that proves it. Every target an AI-proposed command touches is checked
here first; if the check fails, the command never runs.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from datetime import date
from urllib.parse import urlparse

import yaml


class ScopeError(Exception):
    """Raised when a target is out of scope or authorization is missing."""


@dataclass
class Authorization:
    """Proof that the operator is allowed to test the listed targets.

    These fields map to what a real rules-of-engagement document records.
    `confirmed` must be explicitly set True by the human operator -- it is the
    "I have written permission to test these systems" switch.
    """

    client: str
    authorized_by: str
    engagement: str
    start_date: date
    end_date: date
    confirmed: bool = False

    def validate(self) -> None:
        if not self.confirmed:
            raise ScopeError(
                "Authorization not confirmed. Set `authorization.confirmed: true` in "
                "the scope file only if you have written permission to test these "
                "targets. Testing systems without authorization is illegal."
            )
        for field_name in ("client", "authorized_by", "engagement"):
            if not getattr(self, field_name):
                raise ScopeError(f"authorization.{field_name} is required.")
        today = date.today()
        if today < self.start_date:
            raise ScopeError(f"Engagement has not started yet (starts {self.start_date}).")
        if today > self.end_date:
            raise ScopeError(f"Engagement window has ended (ended {self.end_date}).")


@dataclass
class Scope:
    """The set of in-scope targets plus the authorization that permits them."""

    authorization: Authorization
    hosts: list[str] = field(default_factory=list)
    cidrs: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)
    max_runtime_seconds: int = 300

    _networks: list[ipaddress._BaseNetwork] = field(default_factory=list, repr=False)
    _excluded_networks: list[ipaddress._BaseNetwork] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        self._networks = [ipaddress.ip_network(c, strict=False) for c in self.cidrs]
        self._excluded_networks = []
        for item in self.excluded:
            try:
                self._excluded_networks.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                pass  # plain hostnames handled by name match below

    @classmethod
    def from_file(cls, path: str) -> "Scope":
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
        if not isinstance(raw, dict):
            raise ScopeError("Scope file must be a YAML mapping.")

        auth_raw = raw.get("authorization")
        if not isinstance(auth_raw, dict):
            raise ScopeError("Scope file must contain an `authorization` block.")

        authorization = Authorization(
            client=auth_raw.get("client", ""),
            authorized_by=auth_raw.get("authorized_by", ""),
            engagement=auth_raw.get("engagement", ""),
            start_date=_as_date(auth_raw.get("start_date")),
            end_date=_as_date(auth_raw.get("end_date")),
            confirmed=bool(auth_raw.get("confirmed", False)),
        )

        scope = cls(
            authorization=authorization,
            hosts=[str(h).strip().lower() for h in raw.get("hosts", [])],
            cidrs=[str(c).strip() for c in raw.get("cidrs", [])],
            domains=[str(d).strip().lower() for d in raw.get("domains", [])],
            excluded=[str(e).strip().lower() for e in raw.get("excluded", [])],
            max_runtime_seconds=int(raw.get("max_runtime_seconds", 300)),
        )
        scope.authorization.validate()
        if not (scope.hosts or scope.cidrs or scope.domains):
            raise ScopeError("Scope defines no targets (need at least one host, cidr, or domain).")
        return scope

    # -- membership checks -------------------------------------------------

    def _domain_in_scope(self, name: str) -> bool:
        name = name.lower().rstrip(".")
        if name in self.hosts:
            return True
        for domain in self.domains:
            if name == domain or name.endswith("." + domain):
                return True
        return False

    def _ip_in_scope(self, ip: ipaddress._BaseAddress) -> bool:
        return any(ip in net for net in self._networks)

    def _is_excluded(self, name: str, ip: ipaddress._BaseAddress | None) -> bool:
        name = name.lower().rstrip(".")
        if name in self.excluded:
            return True
        if ip is not None:
            if any(ip in net for net in self._excluded_networks):
                return True
        return False

    def assert_target_allowed(self, target: str) -> str:
        """Raise ScopeError unless `target` (host, IP, or URL) is in scope.

        Returns the normalized hostname/IP that was checked, for logging.
        """
        host = _extract_host(target)
        if not host:
            raise ScopeError(f"Could not parse a target host from {target!r}.")

        # Resolve the host so we can check both the name and every IP it maps
        # to -- this blocks a name that is technically "in scope" by string but
        # resolves to an address you were never authorized to touch.
        resolved_ips = _resolve(host)

        if self._is_excluded(host, None) or any(self._is_excluded(host, ip) for ip in resolved_ips):
            raise ScopeError(f"Target {host!r} is on the exclusion list.")

        # A literal IP target: must fall inside an authorized CIDR.
        literal_ip = _as_ip(host)
        if literal_ip is not None:
            if self._ip_in_scope(literal_ip):
                return host
            raise ScopeError(f"IP {host} is not inside any authorized CIDR range.")

        # A name target: the name must be in scope AND every IP it resolves to
        # must be in an authorized CIDR (or there must be no CIDR list at all,
        # meaning name-based scoping only).
        if not self._domain_in_scope(host):
            raise ScopeError(
                f"Host {host!r} is not in the authorized domain/host list."
            )
        if self._networks:
            for ip in resolved_ips:
                if not self._ip_in_scope(ip):
                    raise ScopeError(
                        f"Host {host!r} resolves to {ip}, which is outside the "
                        f"authorized CIDR ranges. Refusing to proceed."
                    )
        return host


def _as_date(value) -> date:
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        return date.fromisoformat(value)
    raise ScopeError(f"Invalid date value: {value!r} (use YYYY-MM-DD).")


def _extract_host(target: str) -> str:
    target = target.strip()
    if "://" in target:
        return (urlparse(target).hostname or "").lower()
    # strip a :port suffix for bare host:port, but keep IPv6 brackets sane
    if target.startswith("[") and "]" in target:  # [::1]:80
        return target[1 : target.index("]")].lower()
    if target.count(":") == 1:
        return target.split(":", 1)[0].lower()
    return target.lower()


def _as_ip(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _resolve(host: str) -> list[ipaddress._BaseAddress]:
    literal = _as_ip(host)
    if literal is not None:
        return [literal]
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    ips = set()
    for info in infos:
        addr = info[4][0]
        ip = _as_ip(addr)
        if ip is not None:
            ips.add(ip)
    return list(ips)
