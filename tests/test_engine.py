"""Tests for the check execution engine and scoring."""

import pytest
from hapr.parser import parse_string
from hapr.framework.engine import run_audit, _compute_category_scores, _compute_overall_score, _letter_grade
from hapr.models import (
    AuditResult,
    CategoryScore,
    CVECheckResult,
    Finding,
    HAProxyConfig,
    ScanResult,
    Severity,
    Status,
)


class TestScoring:
    """Test scoring logic."""

    def test_letter_grade_a(self):
        assert _letter_grade(95) == "A"
        assert _letter_grade(90) == "A"

    def test_letter_grade_b(self):
        assert _letter_grade(85) == "B"
        assert _letter_grade(80) == "B"

    def test_letter_grade_c(self):
        assert _letter_grade(75) == "C"
        assert _letter_grade(70) == "C"

    def test_letter_grade_d(self):
        assert _letter_grade(65) == "D"
        assert _letter_grade(60) == "D"

    def test_letter_grade_f(self):
        assert _letter_grade(59) == "F"
        assert _letter_grade(0) == "F"

    def test_category_score_all_pass(self):
        findings = [
            Finding(check_id="T-001", status=Status.PASS, message="ok", weight=10, category="test"),
            Finding(check_id="T-002", status=Status.PASS, message="ok", weight=7, category="test"),
        ]
        scores = _compute_category_scores(findings)
        assert "test" in scores
        assert scores["test"].percentage == 100.0
        assert scores["test"].pass_count == 2
        assert scores["test"].fail_count == 0

    def test_category_score_all_fail(self):
        findings = [
            Finding(check_id="T-001", status=Status.FAIL, message="bad", weight=10, category="test"),
            Finding(check_id="T-002", status=Status.FAIL, message="bad", weight=7, category="test"),
        ]
        scores = _compute_category_scores(findings)
        assert scores["test"].percentage == 0.0
        assert scores["test"].fail_count == 2

    def test_category_score_mixed(self):
        findings = [
            Finding(check_id="T-001", status=Status.PASS, message="ok", weight=10, category="test"),
            Finding(check_id="T-002", status=Status.FAIL, message="bad", weight=10, category="test"),
        ]
        scores = _compute_category_scores(findings)
        assert scores["test"].percentage == 50.0

    def test_category_score_partial(self):
        findings = [
            Finding(check_id="T-001", status=Status.PARTIAL, message="partial", weight=10, category="test"),
        ]
        scores = _compute_category_scores(findings)
        assert scores["test"].percentage == 50.0
        assert scores["test"].partial_count == 1

    def test_na_excluded_from_scoring(self):
        findings = [
            Finding(check_id="T-001", status=Status.PASS, message="ok", weight=10, category="test"),
            Finding(check_id="T-002", status=Status.NOT_APPLICABLE, message="n/a", weight=10, category="test"),
        ]
        scores = _compute_category_scores(findings)
        assert scores["test"].percentage == 100.0
        assert scores["test"].na_count == 1

    def test_overall_score_calculation(self):
        findings = [
            Finding(check_id="A-001", status=Status.PASS, message="ok", weight=10, category="cat_a"),
            Finding(check_id="B-001", status=Status.FAIL, message="bad", weight=10, category="cat_b"),
        ]
        cat_scores = _compute_category_scores(findings)
        overall, grade = _compute_overall_score(cat_scores)
        assert overall == 50.0
        assert grade == "F"

    def test_overall_score_empty(self):
        scores = _compute_category_scores([])
        overall, grade = _compute_overall_score(scores)
        assert overall == 100.0
        assert grade == "A"


class TestRunAudit:
    """Test the full audit pipeline."""

    def test_audit_insecure_config(self):
        config = parse_string("""
global
    log /dev/log local0

defaults
    mode http

frontend ft_web
    bind :80
    default_backend bk_app

backend bk_app
    server app1 10.0.0.1:8080
""")
        result = run_audit(config)
        assert isinstance(result, AuditResult)
        assert result.overall_score < 50  # Should score low
        assert result.letter_grade in ("D", "F")
        assert len(result.findings) > 0

    def test_audit_no_scan_checks_when_not_scanning(self):
        """Scan/CVE checks should be excluded when not scanning."""
        config = parse_string("""
global
    log /dev/log local0

defaults
    mode http
""")
        result = run_audit(config)
        scan_findings = [f for f in result.findings if f.category in ("tls_live", "cve")]
        assert len(scan_findings) == 0

    def test_audit_with_scan_results(self):
        """When scan results are provided, tls_live checks should run."""
        config = parse_string("""
global
    log /dev/log local0

defaults
    mode http
""")
        scan_results = [ScanResult(
            target="example.com",
            port=443,
            accepted_protocols=["TLS 1.2", "TLS 1.3"],
            rejected_protocols=["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"],
        )]
        result = run_audit(config, scan_results=scan_results)
        scan_findings = [f for f in result.findings if f.category == "tls_live"]
        assert len(scan_findings) > 0

    def test_audit_with_cve_results(self):
        """When CVE results are provided, cve checks should run."""
        config = parse_string("""
global
    log /dev/log local0

defaults
    mode http
""")
        cve_results = CVECheckResult(version="2.8.1", cves=[])
        result = run_audit(config, cve_results=cve_results)
        cve_findings = [f for f in result.findings if f.category == "cve"]
        assert len(cve_findings) > 0

    def test_secure_config_scores_higher(self):
        """Secure config should score significantly higher than insecure."""
        from hapr.parser import parse_file
        secure = run_audit(parse_file("examples/secure.cfg"))
        insecure = run_audit(parse_file("examples/insecure.cfg"))
        assert secure.overall_score > insecure.overall_score
        assert secure.overall_score > 70
        assert insecure.overall_score < 30

    def test_findings_have_metadata(self):
        """Findings should have check metadata from baseline."""
        config = parse_string("""
global
    log /dev/log local0

defaults
    mode http
""")
        result = run_audit(config)
        for finding in result.findings:
            assert finding.check_id != ""
            assert finding.category != ""
            assert finding.severity is not None
            assert finding.weight >= 0

    def test_severity_weights(self):
        """Verify severity weight values."""
        assert Severity.CRITICAL.weight == 10
        assert Severity.HIGH.weight == 7
        assert Severity.MEDIUM.weight == 4
        assert Severity.LOW.weight == 2
        assert Severity.INFO.weight == 0

    def test_custom_baseline_not_found(self):
        """Should raise error with invalid baseline path."""
        config = parse_string("global\n    log /dev/log local0\n")
        with pytest.raises(FileNotFoundError):
            run_audit(config, baseline_path="/nonexistent/baseline.yaml")
