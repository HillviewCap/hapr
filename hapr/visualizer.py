"""Plotly-based network topology graph for HAProxy configurations.

Builds a directed graph: Frontends -> Backends -> Servers,
colored by security finding severity.
"""

from __future__ import annotations

import math
from typing import Any

import plotly.graph_objects as go

from .models import AuditResult, HAProxyConfig, Status


def build_topology(
    config: HAProxyConfig,
    audit_result: AuditResult | None = None,
) -> go.Figure:
    """Build an interactive Plotly network topology figure.

    Parameters
    ----------
    config:
        Parsed HAProxy configuration.
    audit_result:
        Optional audit results for severity-based coloring.
    """
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    node_index: dict[str, int] = {}

    severity_colors = _build_severity_map(audit_result) if audit_result else {}

    # --- Build nodes ---

    # Frontends
    for fe in config.frontends:
        idx = len(nodes)
        node_index[f"fe:{fe.name}"] = idx
        bind_info = ", ".join(
            f"{b.address or '*'}:{b.port or '?'}{' (SSL)' if b.ssl else ''}"
            for b in fe.binds
        ) or "no binds"
        color = severity_colors.get(f"fe:{fe.name}", "#4CAF50")
        nodes.append({
            "label": fe.name,
            "type": "frontend",
            "detail": f"Frontend: {fe.name}\nBinds: {bind_info}",
            "color": color,
        })

    # Listen sections (act as both frontend and backend)
    for ls in config.listens:
        idx = len(nodes)
        node_index[f"ls:{ls.name}"] = idx
        bind_info = ", ".join(
            f"{b.address or '*'}:{b.port or '?'}{' (SSL)' if b.ssl else ''}"
            for b in ls.binds
        ) or "no binds"
        color = severity_colors.get(f"ls:{ls.name}", "#2196F3")
        nodes.append({
            "label": ls.name,
            "type": "listen",
            "detail": f"Listen: {ls.name}\nBinds: {bind_info}",
            "color": color,
        })

    # Backends
    for be in config.backends:
        idx = len(nodes)
        node_index[f"be:{be.name}"] = idx
        server_count = len(be.servers)
        color = severity_colors.get(f"be:{be.name}", "#FF9800")
        nodes.append({
            "label": be.name,
            "type": "backend",
            "detail": f"Backend: {be.name}\nServers: {server_count}",
            "color": color,
        })

    # Servers
    for be in config.backends:
        for srv in be.servers:
            key = f"srv:{be.name}/{srv.name}"
            if key not in node_index:
                idx = len(nodes)
                node_index[key] = idx
                addr = f"{srv.address}:{srv.port or '?'}"
                ssl_tag = " (SSL)" if srv.ssl else ""
                check_tag = " [check]" if "check" in srv.options else ""
                color = "#9C27B0" if srv.ssl else "#E0E0E0"
                nodes.append({
                    "label": srv.name,
                    "type": "server",
                    "detail": f"Server: {srv.name}\nAddr: {addr}{ssl_tag}{check_tag}",
                    "color": color,
                })

    for ls in config.listens:
        for srv in ls.servers:
            key = f"srv:{ls.name}/{srv.name}"
            if key not in node_index:
                idx = len(nodes)
                node_index[key] = idx
                addr = f"{srv.address}:{srv.port or '?'}"
                ssl_tag = " (SSL)" if srv.ssl else ""
                color = "#9C27B0" if srv.ssl else "#E0E0E0"
                nodes.append({
                    "label": srv.name,
                    "type": "server",
                    "detail": f"Server: {srv.name}\nAddr: {addr}{ssl_tag}",
                    "color": color,
                })

    # --- Build edges ---

    # Frontend -> Backend edges
    for fe in config.frontends:
        fe_key = f"fe:{fe.name}"
        for d in fe.use_backends:
            backend_name = d.args.split()[0] if d.args else ""
            be_key = f"be:{backend_name}"
            if be_key in node_index:
                condition = ""
                if d.keyword == "use_backend" and " if " in d.args:
                    condition = d.args.split(" if ", 1)[1].strip()
                elif d.keyword == "use_backend" and " unless " in d.args:
                    condition = "unless " + d.args.split(" unless ", 1)[1].strip()
                edges.append({
                    "from": node_index[fe_key],
                    "to": node_index[be_key],
                    "label": condition or "default",
                })

    # Backend -> Server edges
    for be in config.backends:
        be_key = f"be:{be.name}"
        if be_key not in node_index:
            continue
        for srv in be.servers:
            srv_key = f"srv:{be.name}/{srv.name}"
            if srv_key in node_index:
                edges.append({
                    "from": node_index[be_key],
                    "to": node_index[srv_key],
                    "label": "",
                })

    # Listen -> Server edges
    for ls in config.listens:
        ls_key = f"ls:{ls.name}"
        if ls_key not in node_index:
            continue
        for srv in ls.servers:
            srv_key = f"srv:{ls.name}/{srv.name}"
            if srv_key in node_index:
                edges.append({
                    "from": node_index[ls_key],
                    "to": node_index[srv_key],
                    "label": "",
                })

    # --- Layout ---
    positions = _compute_layout(nodes, edges)

    # --- Build Plotly figure ---
    fig = go.Figure()

    # Edge traces
    for edge in edges:
        x0, y0 = positions[edge["from"]]
        x1, y1 = positions[edge["to"]]
        fig.add_trace(go.Scatter(
            x=[x0, x1, None],
            y=[y0, y1, None],
            mode="lines",
            line=dict(width=1.5, color="#888"),
            hoverinfo="text",
            text=edge.get("label", ""),
            showlegend=False,
        ))

    # Node traces by type
    type_shapes = {
        "frontend": "diamond",
        "listen": "hexagon",
        "backend": "square",
        "server": "circle",
    }

    for node_type, marker_symbol in type_shapes.items():
        type_nodes = [(i, n) for i, n in enumerate(nodes) if n["type"] == node_type]
        if not type_nodes:
            continue

        fig.add_trace(go.Scatter(
            x=[positions[i][0] for i, _ in type_nodes],
            y=[positions[i][1] for i, _ in type_nodes],
            mode="markers+text",
            marker=dict(
                size=20 if node_type != "server" else 14,
                color=[n["color"] for _, n in type_nodes],
                symbol=marker_symbol,
                line=dict(width=2, color="#333"),
            ),
            text=[n["label"] for _, n in type_nodes],
            textposition="top center",
            hovertext=[n["detail"] for _, n in type_nodes],
            hoverinfo="text",
            name=node_type.capitalize(),
        ))

    fig.update_layout(
        title="HAProxy Network Topology",
        showlegend=True,
        hovermode="closest",
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        plot_bgcolor="white",
        margin=dict(l=20, r=20, t=50, b=20),
        height=600,
    )

    return fig


def export_topology_html(
    config: HAProxyConfig,
    output_path: str,
    audit_result: AuditResult | None = None,
) -> None:
    """Export topology graph as a standalone HTML file."""
    fig = build_topology(config, audit_result)
    fig.write_html(output_path, include_plotlyjs="cdn", full_html=True)


def topology_to_html_div(
    config: HAProxyConfig,
    audit_result: AuditResult | None = None,
) -> str:
    """Return topology graph as an embeddable HTML div."""
    fig = build_topology(config, audit_result)
    return fig.to_html(include_plotlyjs=False, full_html=False)


def _compute_layout(
    nodes: list[dict], edges: list[dict]
) -> list[tuple[float, float]]:
    """Compute a layered left-to-right layout for the graph.

    Layer 0: frontends/listens
    Layer 1: backends
    Layer 2: servers
    """
    layers: dict[str, int] = {
        "frontend": 0,
        "listen": 0,
        "backend": 1,
        "server": 2,
    }

    by_layer: dict[int, list[int]] = {0: [], 1: [], 2: []}
    for i, node in enumerate(nodes):
        layer = layers.get(node["type"], 0)
        by_layer[layer].append(i)

    positions: list[tuple[float, float]] = [(0.0, 0.0)] * len(nodes)
    x_spacing = 3.0

    for layer, indices in by_layer.items():
        n = len(indices)
        if n == 0:
            continue
        x = layer * x_spacing
        y_start = -(n - 1) / 2.0
        for rank, idx in enumerate(indices):
            positions[idx] = (x, y_start + rank)

    return positions


def _build_severity_map(audit_result: AuditResult) -> dict[str, str]:
    """Map section names to colors based on worst finding severity."""
    color_map: dict[str, str] = {}

    # Build a mapping of section names to worst severity
    section_severity: dict[str, int] = {}
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    for finding in audit_result.findings:
        if finding.status in (Status.FAIL, Status.PARTIAL):
            rank = severity_rank.get(finding.severity.value, 0)
            # Try to associate with sections based on category
            if finding.category == "frontend":
                for key in color_map:
                    if key.startswith("fe:"):
                        section_severity[key] = max(section_severity.get(key, 0), rank)
            elif finding.category == "backend":
                for key in color_map:
                    if key.startswith("be:"):
                        section_severity[key] = max(section_severity.get(key, 0), rank)

    rank_to_color = {
        4: "#F44336",  # red - critical
        3: "#FF9800",  # orange - high
        2: "#FFC107",  # yellow - medium
        1: "#8BC34A",  # light green - low
        0: "#4CAF50",  # green - info/pass
    }

    for key, rank in section_severity.items():
        color_map[key] = rank_to_color.get(rank, "#4CAF50")

    return color_map
