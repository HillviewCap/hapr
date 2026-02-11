"""Check execution engine and scoring."""

from __future__ import annotations

import importlib
from typing import Any

from ..models import (
    AuditResult,
    CategoryScore,
    CVECheckResult,
    Finding,
    HAProxyConfig,
    ScanResult,
    Severity,
    Status,
)
from .baseline import get_checks, load_baseline

# Category display names
CATEGORY_NAMES: dict[str, str] = {
    "process": "Process Security",
    "tls": "TLS/SSL Configuration",
    "access": "Access Control",
    "headers": "HTTP Security Headers",
    "request": "Request Handling",
    "logging": "Logging & Monitoring",
    "disclosure": "Information Disclosure",
    "timeouts": "Timeout Configuration",
    "backend": "Backend Security",
    "frontend": "Frontend Security",
    "global_defaults": "Global & Defaults",
    "tls_live": "Live TLS Scan",
    "cve": "Known Vulnerabilities",
}


def run_audit(
    config: HAProxyConfig,
    baseline_path: str | None = None,
    scan_results: list[ScanResult] | None = None,
    cve_results: CVECheckResult | None = None,
) -> AuditResult:
    """Execute all baseline checks and compute scores.

    Parameters
    ----------
    config:
        Parsed HAProxy configuration.
    baseline_path:
        Optional custom baseline YAML path.
    scan_results:
        TLS scan results (None if scanning was not performed).
    cve_results:
        CVE check results (None if version detection was not performed).
    """
    baseline = load_baseline(baseline_path)
    checks = get_checks(baseline)

    scanner_available = scan_results is not None and len(scan_results) > 0
    version_available = cve_results is not None and cve_results.version != ""

    findings: list[Finding] = []
    has_http = _config_has_http_mode(config)

    for check_def in checks:
        requires = check_def.get("requires")

        # Skip checks whose dependencies are not met
        if requires == "scanner" and not scanner_available:
            continue
        if requires == "version" and not version_available:
            continue

        # Skip HTTP-only checks when config is TCP-only
        requires_mode = check_def.get("requires_mode")
        if requires_mode == "http" and not has_http:
            findings.append(Finding(
                check_id=check_def["id"],
                status=Status.NOT_APPLICABLE,
                message="Check requires HTTP mode but config is TCP-only.",
                severity=Severity(check_def.get("severity", "info")),
                title=check_def.get("title", ""),
                category=check_def.get("category", ""),
                remediation=check_def.get("remediation", ""),
                weight=check_def.get("weight", 0),
            ))
            continue

        finding = _execute_check(
            check_def, config, scan_results or [], cve_results
        )
        findings.append(finding)

    # Compute scores
    category_scores = _compute_category_scores(findings)
    overall_score, letter_grade = _compute_overall_score(category_scores)

    return AuditResult(
        config_path=config.file_path,
        haproxy_version=cve_results.version if cve_results else None,
        overall_score=overall_score,
        letter_grade=letter_grade,
        category_scores=category_scores,
        findings=findings,
        scan_results=scan_results or [],
        cve_results=cve_results.cves if cve_results else [],
        scan_performed=scanner_available,
        cve_check_performed=version_available,
    )


def _config_has_http_mode(config: HAProxyConfig) -> bool:
    """Return True if any section uses ``mode http`` (explicitly or inherited).

    HAProxy defaults to HTTP mode when no ``mode`` directive is present.
    Frontends/listens inherit mode from the defaults section, so we first
    determine the effective default mode, then check each frontend/listen.
    """
    # Determine the effective default mode
    default_mode: str | None = None
    for d in config.defaults:
        val = d.get_value("mode")
        if val is not None:
            default_mode = val.strip().lower()

    # Check frontends and listens for their effective mode
    proxy_sections = list(config.frontends) + list(config.listens)

    if not proxy_sections and not config.defaults:
        # No sections at all — treat as HTTP (HAProxy default)
        return True

    for section in proxy_sections:
        mode_value = section.get_value("mode") if hasattr(section, "get_value") else None
        if mode_value is not None:
            if mode_value.strip().lower() == "http":
                return True
        else:
            # Inherits from defaults; if defaults is tcp, this is tcp
            effective = default_mode or "http"  # HAProxy defaults to http
            if effective == "http":
                return True

    # If no proxy sections exist, check defaults alone
    if not proxy_sections:
        effective = default_mode or "http"
        return effective == "http"

    return False


def _execute_check(
    check_def: dict[str, Any],
    config: HAProxyConfig,
    scan_results: list[ScanResult],
    cve_results: CVECheckResult | None,
) -> Finding:
    """Resolve and execute a single check function."""
    check_id = check_def["id"]
    check_func_path = check_def["check_function"]
    severity = Severity(check_def.get("severity", "info"))
    weight = check_def.get("weight", severity.weight)

    try:
        func = _resolve_check_function(check_func_path)
    except Exception as exc:
        return Finding(
            check_id=check_id,
            status=Status.ERROR,
            message=f"Failed to resolve check function: {exc}",
            severity=severity,
            title=check_def.get("title", ""),
            category=check_def.get("category", ""),
            remediation=check_def.get("remediation", ""),
            weight=weight,
        )

    try:
        category = check_def.get("category", "")
        if category == "tls_live":
            finding = func(config, scan_results)
        elif category == "cve":
            finding = func(config, cve_results)
        else:
            finding = func(config)
    except Exception as exc:
        return Finding(
            check_id=check_id,
            status=Status.ERROR,
            message=f"Check execution error: {exc}",
            severity=severity,
            title=check_def.get("title", ""),
            category=check_def.get("category", ""),
            remediation=check_def.get("remediation", ""),
            weight=weight,
        )

    # Enrich the finding with baseline metadata
    finding.check_id = check_id
    finding.severity = severity
    finding.weight = weight
    finding.title = check_def.get("title", finding.title)
    finding.category = check_def.get("category", finding.category)
    finding.remediation = check_def.get("remediation", finding.remediation)

    return finding


def _resolve_check_function(dotted_path: str):
    """Resolve 'module.function_name' to an actual callable.

    The dotted_path is relative to ``hapr.framework.checks``.
    For example ``tls.check_min_tls_version`` resolves to
    ``hapr.framework.checks.tls:check_min_tls_version``.
    """
    parts = dotted_path.rsplit(".", 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid check_function path: {dotted_path}")

    module_name, func_name = parts
    full_module = f"hapr.framework.checks.{module_name}"
    mod = importlib.import_module(full_module)
    func = getattr(mod, func_name, None)
    if func is None:
        raise AttributeError(f"{func_name} not found in {full_module}")
    return func


def _compute_category_scores(findings: list[Finding]) -> dict[str, CategoryScore]:
    """Compute per-category scores from findings."""
    by_cat: dict[str, list[Finding]] = {}
    for f in findings:
        by_cat.setdefault(f.category, []).append(f)

    scores: dict[str, CategoryScore] = {}
    for cat, cat_findings in by_cat.items():
        cs = CategoryScore(
            category_id=cat,
            category_name=CATEGORY_NAMES.get(cat, cat),
            findings=cat_findings,
        )

        weighted_score = 0.0
        max_weighted = 0.0

        for f in cat_findings:
            cs.check_count += 1

            if f.status == Status.NOT_APPLICABLE:
                cs.na_count += 1
                continue

            w = f.weight
            max_weighted += w

            if f.status == Status.PASS:
                weighted_score += w
                cs.pass_count += 1
            elif f.status == Status.PARTIAL:
                weighted_score += w * 0.5
                cs.partial_count += 1
            elif f.status == Status.FAIL:
                cs.fail_count += 1
            # ERROR counts as fail (0 points)

        cs.max_score = max_weighted
        cs.score = weighted_score
        cs.percentage = (weighted_score / max_weighted * 100) if max_weighted > 0 else 100.0
        scores[cat] = cs

    return scores


def _compute_overall_score(
    category_scores: dict[str, CategoryScore],
) -> tuple[float, str]:
    """Compute overall weighted score and letter grade."""
    total_score = 0.0
    total_max = 0.0

    for cs in category_scores.values():
        total_score += cs.score
        total_max += cs.max_score

    if total_max == 0:
        pct = 100.0
    else:
        pct = total_score / total_max * 100

    grade = _letter_grade(pct)
    return round(pct, 1), grade


def _letter_grade(score: float) -> str:
    if score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    else:
        return "F"
