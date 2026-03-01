"""Tests for the topology visualizer."""

from __future__ import annotations

import os
import tempfile

import plotly.graph_objects as go
import pytest

from hapr.parser import parse_string
from hapr.visualizer import (
    _build_connectivity_map,
    _build_nodes_and_edges,
    _build_topology_with_controls,
    build_topology,
    export_topology_html,
    topology_to_html_div,
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

MULTI_FRONTEND_CFG = """\
frontend ft_https
    bind *:443 ssl crt /etc/ssl/cert.pem
    use_backend bk_api if { path_beg /api/ }
    use_backend bk_static if { path_beg /static/ }
    default_backend bk_webapp

frontend ft_http
    bind *:80
    default_backend bk_webapp

backend bk_webapp
    server webapp1 10.0.1.1:8080 check
    server webapp2 10.0.1.2:8080 check

backend bk_api
    server api1 10.0.2.1:8080 check
    server api2 10.0.2.2:8080 check
    server api3 10.0.2.3:8080 check

backend bk_static
    server static1 10.0.3.1:80

backend bk_orphan
    server orphan1 10.0.4.1:9090
"""

LISTEN_CFG = """\
listen stats
    bind *:8404
    stats enable
    server stats_srv 127.0.0.1:8080

frontend ft_main
    bind *:443 ssl crt /etc/ssl/cert.pem
    default_backend bk_app

backend bk_app
    server app1 10.0.1.1:8080 check
"""

EMPTY_CFG = """\
global
    daemon
defaults
    mode http
"""

SINGLE_FE_CFG = """\
frontend ft_only
    bind *:443 ssl crt /etc/ssl/cert.pem
    default_backend bk_one

backend bk_one
    server s1 10.0.0.1:80 check
    server s2 10.0.0.2:80 check
"""

NO_BACKEND_FE_CFG = """\
frontend ft_redirect
    bind *:80
"""

# Two backends sharing the same physical servers
SHARED_SERVERS_CFG = """\
frontend ft_main
    bind *:443 ssl crt /etc/ssl/cert.pem
    use_backend bk_api if { path_beg /api/ }
    default_backend bk_webapp

backend bk_webapp
    server web1 10.0.1.1:8080 check
    server web2 10.0.1.2:8080 check

backend bk_api
    server web1 10.0.1.1:8080 check
    server api1 10.0.2.1:8080 check
"""

# Same physical server, different config names
SHARED_SERVERS_DIFF_NAMES_CFG = """\
frontend ft_main
    bind *:443 ssl crt /etc/ssl/cert.pem
    use_backend bk_api if { path_beg /api/ }
    default_backend bk_webapp

backend bk_webapp
    server webapp-primary 10.0.1.1:8080 check

backend bk_api
    server api-primary 10.0.1.1:8080 check
"""


# ---------------------------------------------------------------------------
# TestConnectivityMap
# ---------------------------------------------------------------------------

class TestConnectivityMap:
    """Test _build_connectivity_map returns correct scope mappings."""

    def test_multiple_frontends_sharing_backends(self):
        config = parse_string(MULTI_FRONTEND_CFG)
        cmap = _build_connectivity_map(config)

        assert "fe:ft_https" in cmap
        assert "fe:ft_http" in cmap
        https_scope = cmap["fe:ft_https"]
        assert set(https_scope["backend_keys"]) == {
            "be:bk_api", "be:bk_static", "be:bk_webapp",
        }
        http_scope = cmap["fe:ft_http"]
        assert http_scope["backend_keys"] == ["be:bk_webapp"]

    def test_server_keys_populated(self):
        config = parse_string(MULTI_FRONTEND_CFG)
        cmap = _build_connectivity_map(config)

        https_scope = cmap["fe:ft_https"]
        # bk_api has 3 servers, bk_static has 1, bk_webapp has 2 => 6 total
        assert len(https_scope["server_keys"]) == 6

    def test_server_keys_use_address_format(self):
        """Server keys should be keyed by physical address, not parent/name."""
        config = parse_string(MULTI_FRONTEND_CFG)
        cmap = _build_connectivity_map(config)

        https_scope = cmap["fe:ft_https"]
        for sk in https_scope["server_keys"]:
            assert sk.startswith("srv:")
            # Should NOT contain backend name as prefix
            assert "/" not in sk

    def test_orphan_backend_not_in_any_scope(self):
        config = parse_string(MULTI_FRONTEND_CFG)
        cmap = _build_connectivity_map(config)

        all_be_keys: set[str] = set()
        for scope in cmap.values():
            all_be_keys.update(scope["backend_keys"])
        assert "be:bk_orphan" not in all_be_keys

    def test_listen_section_as_scope(self):
        config = parse_string(LISTEN_CFG)
        cmap = _build_connectivity_map(config)

        assert "ls:stats" in cmap
        stats = cmap["ls:stats"]
        assert stats["type"] == "listen"
        assert "stats (listen)" in stats["name"]
        assert len(stats["server_keys"]) == 1
        assert stats["backend_keys"] == []

    def test_frontend_with_no_backends(self):
        config = parse_string(NO_BACKEND_FE_CFG)
        cmap = _build_connectivity_map(config)

        assert "fe:ft_redirect" in cmap
        scope = cmap["fe:ft_redirect"]
        assert scope["backend_keys"] == []
        assert scope["server_keys"] == []

    def test_empty_config(self):
        config = parse_string(EMPTY_CFG)
        cmap = _build_connectivity_map(config)
        assert cmap == {}

    def test_shared_servers_deduped_in_scope(self):
        """When two backends share a server, unique count should reflect dedup."""
        config = parse_string(SHARED_SERVERS_CFG)
        cmap = _build_connectivity_map(config)

        scope = cmap["fe:ft_main"]
        # bk_webapp: web1(10.0.1.1), web2(10.0.1.2)
        # bk_api:    web1(10.0.1.1), api1(10.0.2.1)
        # Raw list has 4 entries but 3 unique addresses
        assert len(scope["server_keys"]) == 4  # raw list
        assert len(set(scope["server_keys"])) == 3  # unique physical


# ---------------------------------------------------------------------------
# TestServerDeduplication
# ---------------------------------------------------------------------------

class TestServerDeduplication:
    """Test that servers are deduplicated by physical address."""

    def test_shared_server_creates_one_node(self):
        """Same address across backends should produce one server node."""
        config = parse_string(SHARED_SERVERS_CFG)
        nodes, edges, node_index = _build_nodes_and_edges(config)

        server_nodes = [n for n in nodes if n["type"] == "server"]
        # 3 unique addresses: 10.0.1.1:8080, 10.0.1.2:8080, 10.0.2.1:8080
        assert len(server_nodes) == 3

    def test_shared_server_has_edges_from_both_backends(self):
        """The shared server should have edges from both referencing backends."""
        config = parse_string(SHARED_SERVERS_CFG)
        nodes, edges, node_index = _build_nodes_and_edges(config)

        shared_key = "srv:10.0.1.1:8080"
        assert shared_key in node_index

        edges_to_shared = [
            e for e in edges
            if e["to"] == shared_key and e["edge_type"] == "be_srv"
        ]
        sources = {e["from"] for e in edges_to_shared}
        assert sources == {"be:bk_webapp", "be:bk_api"}

    def test_shared_server_hover_shows_backends(self):
        """Hover detail for shared server should list all referencing backends."""
        config = parse_string(SHARED_SERVERS_CFG)
        nodes, edges, node_index = _build_nodes_and_edges(config)

        shared_idx = node_index["srv:10.0.1.1:8080"]
        detail = nodes[shared_idx]["detail"]
        assert "bk_webapp" in detail
        assert "bk_api" in detail
        assert "Referenced by:" in detail

    def test_unique_server_no_referenced_by(self):
        """A server referenced by only one backend should not show 'Referenced by'."""
        config = parse_string(SHARED_SERVERS_CFG)
        nodes, edges, node_index = _build_nodes_and_edges(config)

        unique_key = "srv:10.0.2.1:8080"  # only in bk_api
        unique_idx = node_index[unique_key]
        detail = nodes[unique_idx]["detail"]
        assert "Referenced by:" not in detail

    def test_different_names_same_address_uses_address_label(self):
        """When config names differ but address matches, label should be the address."""
        config = parse_string(SHARED_SERVERS_DIFF_NAMES_CFG)
        nodes, edges, node_index = _build_nodes_and_edges(config)

        shared_key = "srv:10.0.1.1:8080"
        shared_idx = node_index[shared_key]
        node = nodes[shared_idx]
        # Names differ (webapp-primary vs api-primary), so label should be addr
        assert node["label"] == "10.0.1.1:8080"

    def test_same_name_same_address_uses_name_label(self):
        """When all config entries share the same name, label should be that name."""
        config = parse_string(SHARED_SERVERS_CFG)
        nodes, edges, node_index = _build_nodes_and_edges(config)

        shared_key = "srv:10.0.1.1:8080"
        shared_idx = node_index[shared_key]
        node = nodes[shared_idx]
        # Both backends call it "web1"
        assert node["label"] == "web1"

    def test_aggregate_reflects_unique_server_count(self):
        """Aggregate summary label should count unique physical servers."""
        config = parse_string(SHARED_SERVERS_CFG)
        fig, _meta = _build_topology_with_controls(config)

        summary_trace = fig.data[5]
        labels = list(summary_trace.text)
        # ft_main: 2 backends, 3 unique servers (not 4)
        assert any("3 servers" in l for l in labels)

    def test_all_unique_servers_unchanged(self):
        """Configs with all unique addresses should behave the same as before."""
        config = parse_string(MULTI_FRONTEND_CFG)
        nodes, edges, node_index = _build_nodes_and_edges(config)

        server_nodes = [n for n in nodes if n["type"] == "server"]
        # 7 unique addresses across all backends
        assert len(server_nodes) == 7


# ---------------------------------------------------------------------------
# TestBuildTopology
# ---------------------------------------------------------------------------

class TestBuildTopology:
    """Test build_topology returns a valid Plotly figure."""

    def test_returns_figure(self):
        config = parse_string(MULTI_FRONTEND_CFG)
        fig = build_topology(config)
        assert isinstance(fig, go.Figure)

    def test_trace_count_multi_frontend(self):
        """Set A = 8 traces, Set B = 2 scopes * 7 = 14.  Total = 22."""
        config = parse_string(MULTI_FRONTEND_CFG)
        fig, meta = _build_topology_with_controls(config)

        num_scopes = len(meta["scopes"])
        assert num_scopes == 2  # ft_https, ft_http
        expected_total = 8 + num_scopes * 7
        assert meta["total_traces"] == expected_total
        assert len(fig.data) == expected_total

    def test_trace_count_with_listen(self):
        """2 scopes (ft_main + stats listen) => 8 + 2*7 = 22."""
        config = parse_string(LISTEN_CFG)
        fig, meta = _build_topology_with_controls(config)

        num_scopes = len(meta["scopes"])
        assert num_scopes == 2
        expected_total = 8 + num_scopes * 7
        assert len(fig.data) == expected_total

    def test_empty_config_no_crash(self):
        config = parse_string(EMPTY_CFG)
        fig = build_topology(config)
        assert isinstance(fig, go.Figure)

    def test_single_frontend(self):
        config = parse_string(SINGLE_FE_CFG)
        fig, meta = _build_topology_with_controls(config)

        assert len(meta["scopes"]) == 1
        assert meta["scopes"][0]["name"] == "ft_only"

    def test_dynamic_height_in_meta(self):
        config = parse_string(MULTI_FRONTEND_CFG)
        _fig, meta = _build_topology_with_controls(config)

        assert "overview_height" in meta
        assert "detail_height" in meta
        assert meta["overview_height"] >= 400
        assert meta["detail_height"] >= 400

    def test_overview_shows_aggregates_hides_backends(self):
        """In overview (default), aggregate nodes visible, BE/Srv nodes hidden."""
        config = parse_string(MULTI_FRONTEND_CFG)
        fig, _meta = _build_topology_with_controls(config)

        assert fig.data[0].visible is True   # FE->Agg edges
        assert fig.data[1].visible is False  # FE->BE edges
        assert fig.data[2].visible is False  # BE->Srv edges
        assert fig.data[3].visible is True   # FE nodes
        assert fig.data[5].visible is True   # Summary nodes
        assert fig.data[6].visible is False  # BE nodes
        assert fig.data[7].visible is False  # Server nodes

    def test_aggregate_node_labels(self):
        """Aggregate nodes should contain backend/server counts."""
        config = parse_string(MULTI_FRONTEND_CFG)
        fig, _meta = _build_topology_with_controls(config)

        summary_trace = fig.data[5]
        labels = list(summary_trace.text)
        # ft_https: 3 backends, 6 servers; ft_http: 1 backend, 2 servers
        assert any("3 backends" in l for l in labels)
        assert any("6 servers" in l for l in labels)
        assert any("1 backend" in l for l in labels)

    def test_aggregate_positioned_at_layer_1(self):
        """Aggregate nodes should be at x=3.0 (layer 1 position)."""
        config = parse_string(SINGLE_FE_CFG)
        fig, _meta = _build_topology_with_controls(config)

        summary_trace = fig.data[5]
        assert all(x == 3.0 for x in summary_trace.x)


# ---------------------------------------------------------------------------
# TestTopologyHtmlDiv
# ---------------------------------------------------------------------------

class TestTopologyHtmlDiv:
    """Test topology_to_html_div output structure."""

    def test_contains_controls_div(self):
        config = parse_string(MULTI_FRONTEND_CFG)
        html = topology_to_html_div(config)
        assert 'class="topology-controls"' in html

    def test_contains_plotly_div(self):
        config = parse_string(MULTI_FRONTEND_CFG)
        html = topology_to_html_div(config)
        assert 'id="hapr-topology"' in html

    def test_contains_overview_detail_buttons(self):
        config = parse_string(MULTI_FRONTEND_CFG)
        html = topology_to_html_div(config)
        assert "topo-overview-btn" in html
        assert "topo-detail-btn" in html

    def test_contains_scope_dropdown(self):
        config = parse_string(MULTI_FRONTEND_CFG)
        html = topology_to_html_div(config)
        assert "topo-scope-select" in html
        assert "All Frontends" in html
        assert "ft_https" in html
        assert "ft_http" in html

    def test_empty_config_no_controls(self):
        config = parse_string(EMPTY_CFG)
        html = topology_to_html_div(config)
        assert 'class="topology-controls"' not in html


# ---------------------------------------------------------------------------
# TestExportTopologyHtml
# ---------------------------------------------------------------------------

class TestExportTopologyHtml:
    """Test export_topology_html writes a valid HTML file."""

    def test_writes_html_file(self):
        config = parse_string(MULTI_FRONTEND_CFG)
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            export_topology_html(config, path)
            content = open(path, encoding="utf-8").read()
            assert "<!DOCTYPE html>" in content
            assert "plotly-latest.min.js" in content
            assert 'id="hapr-topology"' in content
            assert "topology-controls" in content
        finally:
            os.unlink(path)

    def test_export_empty_config(self):
        config = parse_string(EMPTY_CFG)
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            export_topology_html(config, path)
            content = open(path, encoding="utf-8").read()
            assert "<!DOCTYPE html>" in content
        finally:
            os.unlink(path)
