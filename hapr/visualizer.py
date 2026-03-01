"""Plotly-based network topology graph for HAProxy configurations.

Builds a directed graph: Frontends -> Backends -> Servers,
colored by security finding severity.  Supports a two-tier
collapsible view (overview collapses backends into aggregate
summary nodes, detail expands the full graph) and a
frontend-scoped dropdown filter for large environments.
"""

from __future__ import annotations

import json
from typing import Any

import plotly.graph_objects as go

from .models import AuditResult, HAProxyConfig, Status


# ---------------------------------------------------------------------------
# CSS for the topology controls (inlined by the report template and by
# export_topology_html)
# ---------------------------------------------------------------------------

_CONTROLS_CSS = """\
.topology-controls {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin-bottom: 0.75rem;
    flex-wrap: wrap;
}
.topology-controls .topo-btn {
    padding: 0.3rem 0.75rem;
    border: 1px solid #d5d8dc;
    border-radius: 4px;
    background: #fff;
    font-size: 0.78rem;
    font-weight: 600;
    cursor: pointer;
    color: #5a6a7a;
    transition: background 0.15s, border-color 0.15s;
}
.topology-controls .topo-btn:hover { background: #f0f2f5; }
.topology-controls .topo-btn.active {
    background: #2c3e50;
    color: #fff;
    border-color: #2c3e50;
}
.topology-controls select {
    padding: 0.3rem 0.5rem;
    border: 1px solid #d5d8dc;
    border-radius: 4px;
    font-size: 0.78rem;
    font-weight: 600;
    color: #5a6a7a;
    background: #fff;
    cursor: pointer;
}
"""


# ---------------------------------------------------------------------------
# Marker shapes and sizes per node type
# ---------------------------------------------------------------------------

_TYPE_SHAPES: dict[str, str] = {
    "frontend": "diamond",
    "listen": "hexagon",
    "backend": "square",
    "server": "circle",
    "summary": "star",
}

_TYPE_SIZES: dict[str, int] = {
    "frontend": 20,
    "listen": 20,
    "backend": 20,
    "server": 14,
    "summary": 26,
}


# ---------------------------------------------------------------------------
# Connectivity map
# ---------------------------------------------------------------------------

def _build_connectivity_map(
    config: HAProxyConfig,
) -> dict[str, dict[str, Any]]:
    """Build a frontend/listen -> backend -> server connectivity map.

    Returns a dict keyed by scope identifier (``"fe:<name>"`` or
    ``"ls:<name>"``) whose values contain:

    - ``name``: display name
    - ``type``: ``"frontend"`` or ``"listen"``
    - ``backend_keys``: list of ``"be:<name>"`` keys this scope routes to
    - ``server_keys``: list of ``"srv:<addr>:<port>"`` keys reachable
      (keyed by physical address so shared servers are counted once)
    """
    backend_lookup: dict[str, list[str]] = {}
    for be in config.backends:
        backend_lookup[be.name] = [
            f"srv:{srv.address}:{srv.port or '?'}" for srv in be.servers
        ]

    connectivity: dict[str, dict[str, Any]] = {}

    for fe in config.frontends:
        be_keys: list[str] = []
        srv_keys: list[str] = []
        for d in fe.use_backends:
            backend_name = d.args.split()[0] if d.args else ""
            be_key = f"be:{backend_name}"
            if backend_name in backend_lookup:
                be_keys.append(be_key)
                srv_keys.extend(backend_lookup[backend_name])
        connectivity[f"fe:{fe.name}"] = {
            "name": fe.name,
            "type": "frontend",
            "backend_keys": be_keys,
            "server_keys": srv_keys,
        }

    for ls in config.listens:
        srv_keys = [
            f"srv:{srv.address}:{srv.port or '?'}" for srv in ls.servers
        ]
        connectivity[f"ls:{ls.name}"] = {
            "name": f"{ls.name} (listen)",
            "type": "listen",
            "backend_keys": [],
            "server_keys": srv_keys,
        }

    return connectivity


# ---------------------------------------------------------------------------
# Node / edge building
# ---------------------------------------------------------------------------

def _build_nodes_and_edges(
    config: HAProxyConfig,
    audit_result: AuditResult | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    """Return (nodes, edges, node_index) for *config*."""
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    node_index: dict[str, int] = {}

    severity_colors = _build_severity_map(audit_result) if audit_result else {}

    # -- Frontends --
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

    # -- Listens --
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

    # -- Backends --
    for be in config.backends:
        idx = len(nodes)
        node_index[f"be:{be.name}"] = idx
        server_count = len(be.servers)
        color = severity_colors.get(f"be:{be.name}", "#FF9800")
        nodes.append({
            "label": f"{be.name} ({server_count} srv)",
            "type": "backend",
            "detail": f"Backend: {be.name}\nServers: {server_count}",
            "color": color,
        })

    # -- Servers (deduplicated by physical address) --
    # First pass: collect metadata per unique address across all sections.
    server_info: dict[str, dict[str, Any]] = {}

    for be in config.backends:
        for srv in be.servers:
            addr = f"{srv.address}:{srv.port or '?'}"
            key = f"srv:{addr}"
            if key not in server_info:
                server_info[key] = {
                    "names": [],
                    "parents": [],
                    "ssl": False,
                    "has_check": False,
                    "addr": addr,
                }
            info = server_info[key]
            if srv.name not in info["names"]:
                info["names"].append(srv.name)
            info["parents"].append(be.name)
            info["ssl"] = info["ssl"] or srv.ssl
            info["has_check"] = info["has_check"] or ("check" in srv.options)

    for ls in config.listens:
        for srv in ls.servers:
            addr = f"{srv.address}:{srv.port or '?'}"
            key = f"srv:{addr}"
            if key not in server_info:
                server_info[key] = {
                    "names": [],
                    "parents": [],
                    "ssl": False,
                    "has_check": False,
                    "addr": addr,
                }
            info = server_info[key]
            if srv.name not in info["names"]:
                info["names"].append(srv.name)
            info["parents"].append(f"{ls.name} (listen)")
            info["ssl"] = info["ssl"] or srv.ssl
            info["has_check"] = info["has_check"] or ("check" in srv.options)

    # Second pass: create one node per unique physical server.
    for key, info in server_info.items():
        idx = len(nodes)
        node_index[key] = idx
        names = info["names"]
        # Use the name if all config entries share it, otherwise the address
        label = names[0] if len(set(names)) == 1 else info["addr"]
        ssl_tag = " (SSL)" if info["ssl"] else ""
        check_tag = " [check]" if info["has_check"] else ""
        detail_lines = [
            f"Server: {', '.join(names)}",
            f"Addr: {info['addr']}{ssl_tag}{check_tag}",
        ]
        if len(info["parents"]) > 1:
            detail_lines.append(f"Referenced by: {', '.join(info['parents'])}")
        color = "#9C27B0" if info["ssl"] else "#E0E0E0"
        nodes.append({
            "label": label,
            "type": "server",
            "detail": "\n".join(detail_lines),
            "color": color,
        })

    # -- FE -> BE edges --
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
                    "from": fe_key,
                    "to": be_key,
                    "label": condition or "default",
                    "edge_type": "fe_be",
                })

    # -- BE -> Server edges (one edge per unique physical server per backend) --
    for be in config.backends:
        be_key = f"be:{be.name}"
        if be_key not in node_index:
            continue
        seen_srv: set[str] = set()
        for srv in be.servers:
            srv_key = f"srv:{srv.address}:{srv.port or '?'}"
            if srv_key in node_index and srv_key not in seen_srv:
                seen_srv.add(srv_key)
                edges.append({
                    "from": be_key,
                    "to": srv_key,
                    "label": "",
                    "edge_type": "be_srv",
                })

    # -- Listen -> Server edges --
    for ls in config.listens:
        ls_key = f"ls:{ls.name}"
        if ls_key not in node_index:
            continue
        seen_srv: set[str] = set()
        for srv in ls.servers:
            srv_key = f"srv:{srv.address}:{srv.port or '?'}"
            if srv_key in node_index and srv_key not in seen_srv:
                seen_srv.add(srv_key)
                edges.append({
                    "from": ls_key,
                    "to": srv_key,
                    "label": "",
                    "edge_type": "be_srv",
                })

    return nodes, edges, node_index


# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------

def _compute_layout(
    nodes: list[dict], edges: list[dict],
) -> tuple[dict[str, tuple[float, float]], dict[int, list[str]]]:
    """Compute a layered left-to-right layout.

    Returns ``(positions, by_layer)`` where *positions* maps node keys
    to ``(x, y)`` and *by_layer* maps layer index to a list of node keys.
    """
    layer_assignment: dict[str, int] = {
        "frontend": 0,
        "listen": 0,
        "backend": 1,
        "server": 2,
    }

    by_layer: dict[int, list[str]] = {0: [], 1: [], 2: []}
    for node in nodes:
        layer = layer_assignment.get(node["type"], 0)
        by_layer[layer].append(node["_key"])

    positions: dict[str, tuple[float, float]] = {}
    x_spacing = 3.0

    for layer, keys in by_layer.items():
        n = len(keys)
        if n == 0:
            continue
        x = layer * x_spacing
        y_start = -(n - 1) / 2.0
        for rank, key in enumerate(keys):
            positions[key] = (x, y_start + rank)

    return positions, by_layer


# ---------------------------------------------------------------------------
# Trace helpers
# ---------------------------------------------------------------------------

def _make_edge_trace(
    edge_group: list[dict[str, Any]],
    positions: dict[str, tuple[float, float]],
    visible: bool = True,
) -> go.Scatter:
    """Create a single consolidated edge trace from *edge_group*."""
    xs: list[float | None] = []
    ys: list[float | None] = []
    for edge in edge_group:
        x0, y0 = positions[edge["from"]]
        x1, y1 = positions[edge["to"]]
        xs.extend([x0, x1, None])
        ys.extend([y0, y1, None])
    return go.Scatter(
        x=xs, y=ys,
        mode="lines",
        line=dict(width=1.5, color="#888"),
        hoverinfo="skip",
        showlegend=False,
        visible=visible,
    )


def _make_node_trace(
    node_type: str,
    keys: list[str],
    nodes_by_key: dict[str, dict[str, Any]],
    positions: dict[str, tuple[float, float]],
    visible: bool = True,
    show_legend: bool = True,
) -> go.Scatter:
    """Create a single node trace for all nodes of *node_type* in *keys*."""
    marker_symbol = _TYPE_SHAPES.get(node_type, "circle")
    marker_size = _TYPE_SIZES.get(node_type, 20)
    text_pos = "middle right" if node_type == "summary" else "top center"
    filtered = [k for k in keys if k in positions]
    return go.Scatter(
        x=[positions[k][0] for k in filtered],
        y=[positions[k][1] for k in filtered],
        mode="markers+text",
        marker=dict(
            size=marker_size,
            color=[nodes_by_key[k]["color"] for k in filtered],
            symbol=marker_symbol,
            line=dict(width=2, color="#333"),
        ),
        text=[nodes_by_key[k]["label"] for k in filtered],
        textposition=text_pos,
        hovertext=[nodes_by_key[k]["detail"] for k in filtered],
        hoverinfo="text",
        name=node_type.capitalize(),
        showlegend=show_legend,
        visible=visible,
    )


# ---------------------------------------------------------------------------
# Core builder
# ---------------------------------------------------------------------------

def _build_topology_with_controls(
    config: HAProxyConfig,
    audit_result: AuditResult | None = None,
) -> tuple[go.Figure, dict[str, Any]]:
    """Build topology figure with two-tier controls metadata.

    Returns ``(fig, meta)`` where *meta* drives the JavaScript controls.

    Trace layout
    ------------
    **Set A** — "All Frontends" view (8 traces, indices 0-7):

    ======  ============================================  ===========
    Index   Content                                       Visible in
    ======  ============================================  ===========
    0       FE/Listen → Aggregate edges                   overview
    1       FE → BE edges                                 detail
    2       BE → Server edges                             detail
    3       Frontend nodes                                both
    4       Listen nodes                                  both
    5       Summary/aggregate nodes                       overview
    6       Backend nodes                                 detail
    7       Server nodes                                  detail
    ======  ============================================  ===========

    **Set B** — per-scope filtered views (7 traces per scope):

    ======  ============================================  ===========
    Offset  Content                                       Visible in
    ======  ============================================  ===========
    +0      FE/Listen node                                both
    +1      Summary/aggregate node                        overview
    +2      Backend nodes                                 detail
    +3      Server nodes                                  detail
    +4      FE/Listen → Aggregate edge                    overview
    +5      FE → BE edges                                 detail
    +6      BE → Server edges                             detail
    ======  ============================================  ===========
    """
    nodes, edges, node_index = _build_nodes_and_edges(config, audit_result)

    if not nodes:
        fig = go.Figure()
        fig.update_layout(
            title="HAProxy Network Topology",
            annotations=[dict(
                text="No topology data", showarrow=False,
                xref="paper", yref="paper", x=0.5, y=0.5,
            )],
            height=300,
        )
        return fig, {}

    # Attach _key to each node so _compute_layout can use it
    key_by_idx = {v: k for k, v in node_index.items()}
    for i, node in enumerate(nodes):
        node["_key"] = key_by_idx[i]

    nodes_by_key: dict[str, dict[str, Any]] = {n["_key"]: n for n in nodes}

    positions, by_layer = _compute_layout(nodes, edges)

    connectivity = _build_connectivity_map(config)

    # Classify edges
    fe_be_edges = [e for e in edges if e["edge_type"] == "fe_be"]
    be_srv_edges = [e for e in edges if e["edge_type"] == "be_srv"]

    # Classify node keys by type
    fe_keys = [n["_key"] for n in nodes if n["type"] == "frontend"]
    ls_keys = [n["_key"] for n in nodes if n["type"] == "listen"]
    be_keys = [n["_key"] for n in nodes if n["type"] == "backend"]
    srv_keys = [n["_key"] for n in nodes if n["type"] == "server"]

    # ── Build aggregate/summary nodes and FE→Aggregate edges ──
    agg_keys: list[str] = []
    fe_agg_edges: list[dict[str, Any]] = []

    for scope_key, scope in connectivity.items():
        n_be = len(set(scope["backend_keys"]))
        n_srv = len(set(scope["server_keys"]))

        parts: list[str] = []
        if n_be > 0:
            parts.append(f"{n_be} backend{'s' if n_be != 1 else ''}")
        if n_srv > 0:
            parts.append(f"{n_srv} server{'s' if n_srv != 1 else ''}")
        label = " \u00b7 ".join(parts) if parts else "no connections"

        # Build hover detail listing individual backends with server counts
        be_srv_counts: dict[str, int] = {}
        for be in config.backends:
            be_srv_counts[be.name] = len(be.servers)
        detail_lines = [f"Scope: {scope['name']}"]
        for bk in dict.fromkeys(scope["backend_keys"]):
            be_name = bk.split(":", 1)[1]
            count = be_srv_counts.get(be_name, 0)
            detail_lines.append(f"  {be_name} ({count} srv)")
        if scope["type"] == "listen" and n_srv > 0:
            detail_lines.append(
                f"  {n_srv} direct server{'s' if n_srv != 1 else ''}"
            )

        agg_key = f"agg:{scope_key}"
        nodes_by_key[agg_key] = {
            "label": label,
            "type": "summary",
            "detail": "\n".join(detail_lines),
            "color": "#78909C",
            "_key": agg_key,
        }
        agg_keys.append(agg_key)

        # Position aggregate at layer-1 x, same y as its parent scope
        if scope_key in positions:
            _, parent_y = positions[scope_key]
            positions[agg_key] = (3.0, parent_y)

        fe_agg_edges.append({
            "from": scope_key,
            "to": agg_key,
            "edge_type": "fe_agg",
        })

    # ── Dynamic height computation ──
    layer_0_count = len(by_layer.get(0, []))
    layer_1_count = len(by_layer.get(1, []))
    layer_2_count = len(by_layer.get(2, []))

    overview_height = max(400, min(2000, layer_0_count * 30 + 150))
    detail_height = max(
        400,
        min(2000, max(layer_0_count, layer_1_count, layer_2_count) * 30 + 150),
    )

    # Y-axis ranges
    def _yrange(keys: list[str], pad: float = 1.0) -> list[float]:
        if not keys:
            return [-2.0, 2.0]
        ys = [positions[k][1] for k in keys if k in positions]
        if not ys:
            return [-2.0, 2.0]
        return [min(ys) - pad, max(ys) + pad]

    overview_yrange = _yrange(by_layer.get(0, []) + agg_keys)
    detail_yrange = _yrange(
        by_layer.get(0, []) + by_layer.get(1, []) + by_layer.get(2, []),
    )

    # ── Build figure ──
    fig = go.Figure()

    # ── Set A: "All Frontends" traces (8 traces, indices 0-7) ──
    # [0] FE/Listen → Aggregate edges (overview)
    fig.add_trace(_make_edge_trace(fe_agg_edges, positions, visible=True))
    # [1] FE → BE edges (detail)
    fig.add_trace(_make_edge_trace(fe_be_edges, positions, visible=False))
    # [2] BE → Server edges (detail)
    fig.add_trace(_make_edge_trace(be_srv_edges, positions, visible=False))
    # [3] Frontend nodes (always)
    fig.add_trace(_make_node_trace(
        "frontend", fe_keys, nodes_by_key, positions, visible=True,
    ))
    # [4] Listen nodes (always)
    fig.add_trace(_make_node_trace(
        "listen", ls_keys, nodes_by_key, positions, visible=True,
    ))
    # [5] Summary/aggregate nodes (overview)
    fig.add_trace(_make_node_trace(
        "summary", agg_keys, nodes_by_key, positions, visible=True,
    ))
    # [6] Backend nodes (detail)
    fig.add_trace(_make_node_trace(
        "backend", be_keys, nodes_by_key, positions, visible=False,
    ))
    # [7] Server nodes (detail)
    fig.add_trace(_make_node_trace(
        "server", srv_keys, nodes_by_key, positions,
        visible=False, show_legend=True,
    ))

    SET_A_COUNT = 8
    TRACES_PER_SCOPE = 7

    # ── Set B: Per-scope traces (7 traces per scope) ──
    scope_meta: list[dict[str, Any]] = []
    scope_keys = list(connectivity.keys())

    for scope_key in scope_keys:
        scope = connectivity[scope_key]
        base_idx = SET_A_COUNT + len(scope_meta) * TRACES_PER_SCOPE

        scope_node_key = scope_key
        scope_be_keys = list(dict.fromkeys(scope["backend_keys"]))
        scope_srv_keys = list(dict.fromkeys(scope["server_keys"]))
        agg_key = f"agg:{scope_key}"

        # Edges for this scope
        scope_fe_be = [e for e in fe_be_edges if e["from"] == scope_key]
        scope_be_srv = [
            e for e in be_srv_edges
            if e["from"] in scope_be_keys or e["from"] == scope_key
        ]
        scope_fe_agg = [e for e in fe_agg_edges if e["from"] == scope_key]

        node_type = nodes_by_key[scope_node_key]["type"]

        # [+0] FE/Listen node
        fig.add_trace(_make_node_trace(
            node_type, [scope_node_key], nodes_by_key, positions,
            visible=False, show_legend=False,
        ))
        # [+1] Summary/aggregate node (overview)
        fig.add_trace(_make_node_trace(
            "summary", [agg_key], nodes_by_key, positions,
            visible=False, show_legend=False,
        ))
        # [+2] Backend nodes (detail)
        fig.add_trace(_make_node_trace(
            "backend", scope_be_keys, nodes_by_key, positions,
            visible=False, show_legend=False,
        ))
        # [+3] Server nodes (detail)
        fig.add_trace(_make_node_trace(
            "server", scope_srv_keys, nodes_by_key, positions,
            visible=False, show_legend=False,
        ))
        # [+4] FE/Listen → Aggregate edge (overview)
        fig.add_trace(_make_edge_trace(scope_fe_agg, positions, visible=False))
        # [+5] FE → BE edges (detail)
        fig.add_trace(_make_edge_trace(scope_fe_be, positions, visible=False))
        # [+6] BE → Server edges (detail)
        fig.add_trace(_make_edge_trace(scope_be_srv, positions, visible=False))

        # Compute y-ranges
        scope_overview_keys = [scope_node_key, agg_key]
        scope_detail_keys = [scope_node_key] + scope_be_keys + scope_srv_keys
        scope_overview_yrange = _yrange(scope_overview_keys)
        scope_detail_yrange = _yrange(scope_detail_keys)
        scope_overview_h = max(
            400,
            min(2000, max(1, len(scope_overview_keys)) * 30 + 150),
        )
        scope_detail_h = max(
            400,
            min(2000, max(1, len(scope_detail_keys)) * 30 + 150),
        )

        scope_meta.append({
            "key": scope_key,
            "name": scope["name"],
            "base_idx": base_idx,
            "overview_yrange": scope_overview_yrange,
            "detail_yrange": scope_detail_yrange,
            "overview_height": scope_overview_h,
            "detail_height": scope_detail_h,
        })

    total_traces = SET_A_COUNT + len(scope_keys) * TRACES_PER_SCOPE

    fig.update_layout(
        title="HAProxy Network Topology",
        showlegend=True,
        hovermode="closest",
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(
            showgrid=False, zeroline=False, showticklabels=False,
            range=overview_yrange,
        ),
        plot_bgcolor="white",
        margin=dict(l=20, r=20, t=50, b=20),
        height=overview_height,
    )

    meta: dict[str, Any] = {
        "set_a_count": SET_A_COUNT,
        "traces_per_scope": TRACES_PER_SCOPE,
        "total_traces": total_traces,
        "scopes": scope_meta,
        "overview_height": overview_height,
        "detail_height": detail_height,
        "overview_yrange": overview_yrange,
        "detail_yrange": detail_yrange,
    }

    return fig, meta


# ---------------------------------------------------------------------------
# Controls HTML + JS
# ---------------------------------------------------------------------------

def _build_controls_html(meta: dict[str, Any]) -> str:
    """Generate the HTML controls + JS for the topology figure."""
    if not meta:
        return ""

    scopes = meta.get("scopes", [])

    options_html = '<option value="__all__">All Frontends</option>\n'
    for s in scopes:
        options_html += (
            f'<option value="{s["key"]}">{s["name"]}</option>\n'
        )

    meta_json = json.dumps(meta)

    return f"""\
<div class="topology-controls">
    <button class="topo-btn active" id="topo-overview-btn">Overview</button>
    <button class="topo-btn" id="topo-detail-btn">Detail</button>
    <select id="topo-scope-select">
        {options_html}
    </select>
</div>
<script>
(function() {{
    "use strict";
    var meta = {meta_json};
    var mode = "overview";
    var scope = "__all__";

    function update() {{
        var vis = [];
        var n = meta.total_traces;
        for (var i = 0; i < n; i++) vis.push(false);

        var height, yrange;

        if (scope === "__all__") {{
            if (mode === "overview") {{
                // [0] FE->Agg edges, [3] FE, [4] Listen, [5] Summary
                vis[0] = true; vis[3] = true; vis[4] = true; vis[5] = true;
            }} else {{
                // [1] FE->BE, [2] BE->Srv, [3] FE, [4] Listen, [6] BE, [7] Srv
                vis[1] = true; vis[2] = true; vis[3] = true;
                vis[4] = true; vis[6] = true; vis[7] = true;
            }}
            height = (mode === "overview") ? meta.overview_height : meta.detail_height;
            yrange = (mode === "overview") ? meta.overview_yrange : meta.detail_yrange;
        }} else {{
            var sm = null;
            for (var j = 0; j < meta.scopes.length; j++) {{
                if (meta.scopes[j].key === scope) {{ sm = meta.scopes[j]; break; }}
            }}
            if (!sm) return;
            var b = sm.base_idx;
            if (mode === "overview") {{
                // [+0] FE node, [+1] Summary, [+4] FE->Agg edge
                vis[b] = true; vis[b + 1] = true; vis[b + 4] = true;
            }} else {{
                // [+0] FE node, [+2] BE, [+3] Srv, [+5] FE->BE, [+6] BE->Srv
                vis[b] = true; vis[b + 2] = true; vis[b + 3] = true;
                vis[b + 5] = true; vis[b + 6] = true;
            }}
            height = (mode === "overview") ? sm.overview_height : sm.detail_height;
            yrange = (mode === "overview") ? sm.overview_yrange : sm.detail_yrange;
        }}

        var plotDiv = document.getElementById("hapr-topology");
        if (!plotDiv) return;
        Plotly.update(plotDiv,
            {{ visible: vis }},
            {{ height: height, "yaxis.range": yrange }}
        );
    }}

    document.addEventListener("DOMContentLoaded", function() {{
        var overviewBtn = document.getElementById("topo-overview-btn");
        var detailBtn = document.getElementById("topo-detail-btn");
        var selectEl = document.getElementById("topo-scope-select");

        if (overviewBtn) overviewBtn.addEventListener("click", function() {{
            mode = "overview";
            overviewBtn.classList.add("active");
            detailBtn.classList.remove("active");
            update();
        }});
        if (detailBtn) detailBtn.addEventListener("click", function() {{
            mode = "detail";
            detailBtn.classList.add("active");
            overviewBtn.classList.remove("active");
            update();
        }});
        if (selectEl) selectEl.addEventListener("change", function() {{
            scope = selectEl.value;
            update();
        }});
    }});
}})();
</script>
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

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
    fig, _meta = _build_topology_with_controls(config, audit_result)
    return fig


def topology_to_html_div(
    config: HAProxyConfig,
    audit_result: AuditResult | None = None,
) -> str:
    """Return topology graph as an embeddable HTML div with controls."""
    fig, meta = _build_topology_with_controls(config, audit_result)
    plotly_div = fig.to_html(
        include_plotlyjs=False, full_html=False, div_id="hapr-topology",
    )
    controls = _build_controls_html(meta)
    return controls + plotly_div


def export_topology_html(
    config: HAProxyConfig,
    output_path: str,
    audit_result: AuditResult | None = None,
) -> None:
    """Export topology graph as a standalone HTML file."""
    fig, meta = _build_topology_with_controls(config, audit_result)
    plotly_div = fig.to_html(
        include_plotlyjs=False, full_html=False, div_id="hapr-topology",
    )
    controls = _build_controls_html(meta)

    html = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>HAProxy Network Topology</title>
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
<style>{_CONTROLS_CSS}</style>
</head>
<body>
{controls}
{plotly_div}
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)


# ---------------------------------------------------------------------------
# Severity color mapping
# ---------------------------------------------------------------------------

def _build_severity_map(audit_result: AuditResult) -> dict[str, str]:
    """Map section names to colors based on worst finding severity."""
    color_map: dict[str, str] = {}

    section_severity: dict[str, int] = {}
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    for finding in audit_result.findings:
        if finding.status in (Status.FAIL, Status.PARTIAL):
            rank = severity_rank.get(finding.severity.value, 0)
            if finding.category == "frontend":
                for key in color_map:
                    if key.startswith("fe:"):
                        section_severity[key] = max(
                            section_severity.get(key, 0), rank,
                        )
            elif finding.category == "backend":
                for key in color_map:
                    if key.startswith("be:"):
                        section_severity[key] = max(
                            section_severity.get(key, 0), rank,
                        )

    rank_to_color = {
        4: "#F44336",
        3: "#FF9800",
        2: "#FFC107",
        1: "#8BC34A",
        0: "#4CAF50",
    }

    for key, rank in section_severity.items():
        color_map[key] = rank_to_color.get(rank, "#4CAF50")

    return color_map
