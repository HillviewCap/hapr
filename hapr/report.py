"""Jinja2 HTML report generator."""

from __future__ import annotations

import importlib.resources
from pathlib import Path

import plotly.graph_objects as go
from jinja2 import Environment, FileSystemLoader

from .models import AuditResult, HAProxyConfig
from .visualizer import topology_to_html_div


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

        html = template.render(
            result=audit_result,
            topology_html=topology_html,
            score_chart_html=score_chart_html,
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
