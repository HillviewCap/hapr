"""Jinja2 HTML report generator."""

from __future__ import annotations

import importlib.resources
from pathlib import Path

import plotly.graph_objects as go
from jinja2 import Environment, FileSystemLoader

from .models import AuditResult, HAProxyConfig, Status
from .visualizer import topology_to_html_div

# Tier definitions — order matters (cumulative hierarchy).
TIER_ORDER: list[str] = ["baseline", "level1", "level2", "level3"]
TIER_LABELS: dict[str, str] = {
    "baseline": "Baseline",
    "level1": "Level 1",
    "level2": "Level 2",
    "level3": "Level 3",
}
TIER_DESCRIPTIONS: dict[str, str] = {
    "baseline": "Minimum viable security \u2014 every deployment must pass",
    "level1": "Standard production security",
    "level2": "Enhanced security for sensitive environments",
    "level3": "Maximum hardening for high-security environments",
}

# Maturity levels \u2014 ordered from highest to lowest threshold.
MATURITY_LEVELS: list[dict[str, str | float]] = [
    {"id": "exemplary",   "label": "Exemplary",   "threshold": 100.0, "css": "exemplary"},
    {"id": "achieved",    "label": "Achieved",     "threshold": 90.0,  "css": "achieved"},
    {"id": "progressing", "label": "Progressing",  "threshold": 75.0,  "css": "progressing"},
    {"id": "developing",  "label": "Developing",   "threshold": 50.0,  "css": "developing"},
    {"id": "not_met",     "label": "Not Met",      "threshold": 0.0,   "css": "not-met"},
]


def _maturity_for_percentage(percentage: float) -> dict[str, str | float]:
    """Return the maturity level dict for a given score percentage."""
    for level in MATURITY_LEVELS:
        if percentage >= level["threshold"]:
            return level
    return MATURITY_LEVELS[-1]


def generate_report(
    config: HAProxyConfig,
    audit_result: AuditResult,
    output_path: str,
) -> None:
    """Render the HTML audit report to *output_path*.

    Parameters
    ----------
    config:
        Parsed HAProxy configuration (used for topology graph).
    audit_result:
        Complete audit results with findings and scores.
    output_path:
        File path to write the HTML report.
    """
    ref = importlib.resources.files("hapr.templates").joinpath("report.html.j2")
    with importlib.resources.as_file(ref) as template_path:
        env = Environment(
            loader=FileSystemLoader(str(template_path.parent)),
            autoescape=True,
        )
        template = env.get_template("report.html.j2")

        # Build the topology graph HTML div
        topology_html = topology_to_html_div(config, audit_result)

        # Build the score breakdown chart
        score_chart_html = _build_score_chart(audit_result)

        # Topology section stats
        topology_stats = {
            "frontends": len(config.frontends),
            "backends": len(config.backends),
            "listens": len(config.listens),
            "servers": len(config.all_servers),
        }

        # Tier assessment metrics
        tier_metrics = _compute_tier_metrics(audit_result)

        html = template.render(
            result=audit_result,
            topology_html=topology_html,
            score_chart_html=score_chart_html,
            topology_stats=topology_stats,
            tier_metrics=tier_metrics,
        )

        Path(output_path).write_text(html, encoding="utf-8")


def _build_score_chart(audit_result: AuditResult) -> str:
    """Build a horizontal bar chart of category scores."""
    categories = []
    scores = []
    colors = []

    # Sort by score ascending so worst is at bottom
    sorted_cats = sorted(
        audit_result.category_scores.values(),
        key=lambda c: c.percentage,
        reverse=True,
    )

    for cs in sorted_cats:
        categories.append(cs.category_name)
        scores.append(round(cs.percentage, 1))
        colors.append(_score_color(cs.percentage))

    fig = go.Figure(go.Bar(
        x=scores,
        y=categories,
        orientation="h",
        marker_color=colors,
        text=[f"{s}%" for s in scores],
        textposition="auto",
    ))

    fig.update_layout(
        title="Score by Category",
        xaxis=dict(title="Score (%)", range=[0, 100]),
        yaxis=dict(autorange="reversed"),
        height=max(300, len(categories) * 40 + 100),
        margin=dict(l=200, r=40, t=50, b=40),
        plot_bgcolor="white",
    )

    return fig.to_html(include_plotlyjs=False, full_html=False)


def _score_color(score: float) -> str:
    """Return a color based on the score percentage."""
    if score >= 90:
        return "#4CAF50"  # green
    elif score >= 80:
        return "#8BC34A"  # light green
    elif score >= 70:
        return "#FFC107"  # yellow
    elif score >= 60:
        return "#FF9800"  # orange
    else:
        return "#F44336"  # red


def _compute_tier_metrics(audit_result: AuditResult) -> list[dict]:
    """Compute per-tier metrics from audit findings.

    Each tier dict contains counts, weighted score percentage, and
    a maturity level (Exemplary / Achieved / Progressing / Developing /
    Not Met) derived from the weighted score.
    """
    findings = audit_result.findings
    tiers: list[dict] = []

    for tier_id in TIER_ORDER:
        tier_findings = [f for f in findings if f.tier == tier_id]
        if not tier_findings:
            continue

        total = len(tier_findings)
        pass_count = sum(1 for f in tier_findings if f.status == Status.PASS)
        fail_count = sum(1 for f in tier_findings if f.status == Status.FAIL)
        partial_count = sum(
            1 for f in tier_findings if f.status == Status.PARTIAL
        )
        na_count = sum(
            1 for f in tier_findings if f.status == Status.NOT_APPLICABLE
        )
        error_count = sum(
            1 for f in tier_findings if f.status == Status.ERROR
        )

        # Weighted score
        weighted_score = 0.0
        max_weighted = 0.0
        for f in tier_findings:
            if f.status == Status.NOT_APPLICABLE:
                continue
            max_weighted += f.weight
            if f.status == Status.PASS:
                weighted_score += f.weight
            elif f.status == Status.PARTIAL:
                weighted_score += f.weight * 0.5

        percentage = (
            (weighted_score / max_weighted * 100) if max_weighted > 0 else 100.0
        )

        pct_rounded = round(percentage, 1)
        maturity = _maturity_for_percentage(pct_rounded)

        tiers.append({
            "id": tier_id,
            "label": TIER_LABELS[tier_id],
            "description": TIER_DESCRIPTIONS[tier_id],
            "total": total,
            "pass_count": pass_count,
            "fail_count": fail_count,
            "partial_count": partial_count,
            "na_count": na_count,
            "error_count": error_count,
            "percentage": pct_rounded,
            "maturity_label": maturity["label"],
            "maturity_css": maturity["css"],
        })

    return tiers
