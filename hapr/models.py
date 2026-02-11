"""Data models for HAProxy configuration elements and audit results."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Status(enum.Enum):
    """Result status for a single check."""
    PASS = "pass"
    FAIL = "fail"
    PARTIAL = "partial"
    NOT_APPLICABLE = "n/a"
    ERROR = "error"


class Severity(enum.Enum):
    """Check severity levels with associated scoring weights."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {
            Severity.CRITICAL: 10,
            Severity.HIGH: 7,
            Severity.MEDIUM: 4,
            Severity.LOW: 2,
            Severity.INFO: 0,
        }[self]


# ---------------------------------------------------------------------------
# HAProxy config models
# ---------------------------------------------------------------------------

@dataclass
class Directive:
    """Generic HAProxy directive (keyword + arguments)."""
    keyword: str
    args: str = ""
    line_number: int = 0

    @property
    def value(self) -> str:
        return self.args


@dataclass
class BindLine:
    """Parsed 'bind' directive."""
    address: str = ""
    port: int | None = None
    ssl: bool = False
    options: dict[str, str] = field(default_factory=dict)
    raw: str = ""
    line_number: int = 0


@dataclass
class ServerLine:
    """Parsed 'server' directive."""
    name: str = ""
    address: str = ""
    port: int | None = None
    ssl: bool = False
    options: dict[str, str] = field(default_factory=dict)
    raw: str = ""
    line_number: int = 0


@dataclass
class GlobalSection:
    """HAProxy 'global' section."""
    directives: list[Directive] = field(default_factory=list)

    def get(self, keyword: str) -> list[Directive]:
        return [d for d in self.directives if d.keyword == keyword]

    def has(self, keyword: str) -> bool:
        return any(d.keyword == keyword for d in self.directives)

    def get_value(self, keyword: str) -> str | None:
        matches = self.get(keyword)
        return matches[0].args if matches else None


@dataclass
class DefaultsSection:
    """HAProxy 'defaults' section."""
    name: str = ""
    directives: list[Directive] = field(default_factory=list)

    def get(self, keyword: str) -> list[Directive]:
        return [d for d in self.directives if d.keyword == keyword]

    def has(self, keyword: str) -> bool:
        return any(d.keyword == keyword for d in self.directives)

    def get_value(self, keyword: str) -> str | None:
        matches = self.get(keyword)
        return matches[0].args if matches else None


@dataclass
class Frontend:
    """HAProxy 'frontend' section."""
    name: str = ""
    binds: list[BindLine] = field(default_factory=list)
    directives: list[Directive] = field(default_factory=list)

    def get(self, keyword: str) -> list[Directive]:
        return [d for d in self.directives if d.keyword == keyword]

    def has(self, keyword: str) -> bool:
        return any(d.keyword == keyword for d in self.directives)

    def get_value(self, keyword: str) -> str | None:
        matches = self.get(keyword)
        return matches[0].args if matches else None

    @property
    def use_backends(self) -> list[Directive]:
        return self.get("use_backend") + self.get("default_backend")

    @property
    def acls(self) -> list[Directive]:
        return self.get("acl")


@dataclass
class Backend:
    """HAProxy 'backend' section."""
    name: str = ""
    servers: list[ServerLine] = field(default_factory=list)
    directives: list[Directive] = field(default_factory=list)

    def get(self, keyword: str) -> list[Directive]:
        return [d for d in self.directives if d.keyword == keyword]

    def has(self, keyword: str) -> bool:
        return any(d.keyword == keyword for d in self.directives)

    def get_value(self, keyword: str) -> str | None:
        matches = self.get(keyword)
        return matches[0].args if matches else None


@dataclass
class ListenSection:
    """HAProxy 'listen' section (combined frontend+backend)."""
    name: str = ""
    binds: list[BindLine] = field(default_factory=list)
    servers: list[ServerLine] = field(default_factory=list)
    directives: list[Directive] = field(default_factory=list)

    def get(self, keyword: str) -> list[Directive]:
        return [d for d in self.directives if d.keyword == keyword]

    def has(self, keyword: str) -> bool:
        return any(d.keyword == keyword for d in self.directives)

    def get_value(self, keyword: str) -> str | None:
        matches = self.get(keyword)
        return matches[0].args if matches else None

    @property
    def acls(self) -> list[Directive]:
        return self.get("acl")


@dataclass
class HAProxyConfig:
    """Root container for a parsed HAProxy configuration."""
    file_path: str = ""
    global_section: GlobalSection = field(default_factory=GlobalSection)
    defaults: list[DefaultsSection] = field(default_factory=list)
    frontends: list[Frontend] = field(default_factory=list)
    backends: list[Backend] = field(default_factory=list)
    listens: list[ListenSection] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def all_binds(self) -> list[BindLine]:
        binds = []
        for fe in self.frontends:
            binds.extend(fe.binds)
        for ls in self.listens:
            binds.extend(ls.binds)
        return binds

    @property
    def all_servers(self) -> list[ServerLine]:
        servers = []
        for be in self.backends:
            servers.extend(be.servers)
        for ls in self.listens:
            servers.extend(ls.servers)
        return servers

    @property
    def all_frontends_and_listens(self) -> list[Frontend | ListenSection]:
        return self.frontends + self.listens  # type: ignore[operator]

    @property
    def all_backends_and_listens(self) -> list[Backend | ListenSection]:
        return self.backends + self.listens  # type: ignore[operator]

    @property
    def all_sections(self) -> list[GlobalSection | DefaultsSection | Frontend | Backend | ListenSection]:
        sections: list = [self.global_section]
        sections.extend(self.defaults)
        sections.extend(self.frontends)
        sections.extend(self.backends)
        sections.extend(self.listens)
        return sections

    def get_defaults(self) -> DefaultsSection:
        """Return the first (or merged) defaults section."""
        if self.defaults:
            return self.defaults[0]
        return DefaultsSection()


# ---------------------------------------------------------------------------
# Audit / Finding models
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """Result of a single check execution."""
    check_id: str
    status: Status
    message: str
    evidence: str = ""
    severity: Severity = Severity.INFO
    title: str = ""
    category: str = ""
    remediation: str = ""
    weight: int = 0


@dataclass
class CategoryScore:
    """Score for a single check category."""
    category_id: str
    category_name: str
    score: float = 0.0
    max_score: float = 0.0
    percentage: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    check_count: int = 0
    pass_count: int = 0
    fail_count: int = 0
    partial_count: int = 0
    na_count: int = 0


@dataclass
class AuditResult:
    """Complete audit result with all findings and scores."""
    config_path: str = ""
    scan_date: str = field(default_factory=lambda: datetime.now().isoformat())
    haproxy_version: str | None = None
    overall_score: float = 0.0
    letter_grade: str = "F"
    category_scores: dict[str, CategoryScore] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    scan_results: list[ScanResult] = field(default_factory=list)
    cve_results: list[CVEResult] = field(default_factory=list)
    scan_performed: bool = False
    cve_check_performed: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# TLS Scan models
# ---------------------------------------------------------------------------

@dataclass
class CertInfo:
    """Certificate information from TLS scan."""
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    key_size: int = 0
    signature_algorithm: str = ""
    is_self_signed: bool = False
    is_expired: bool = False
    san_entries: list[str] = field(default_factory=list)
    chain_valid: bool = True


@dataclass
class ScanResult:
    """TLS scan result for a single target."""
    target: str = ""
    port: int = 443
    accepted_protocols: list[str] = field(default_factory=list)
    rejected_protocols: list[str] = field(default_factory=list)
    accepted_ciphers: dict[str, list[str]] = field(default_factory=dict)
    cert_info: CertInfo | None = None
    vulnerabilities: dict[str, bool] = field(default_factory=dict)
    hsts_header: str | None = None
    supports_fallback_scsv: bool = False
    supported_curves: list[str] = field(default_factory=list)
    secure_renegotiation: bool = True
    error: str | None = None


# ---------------------------------------------------------------------------
# CVE models
# ---------------------------------------------------------------------------

@dataclass
class CVEResult:
    """A single CVE entry for a HAProxy version."""
    cve_id: str = ""
    description: str = ""
    cvss_score: float = 0.0
    severity: str = ""
    published_date: str = ""
    url: str = ""


@dataclass
class CVECheckResult:
    """CVE check summary for a HAProxy version."""
    version: str = ""
    cves: list[CVEResult] = field(default_factory=list)
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    error: str | None = None
