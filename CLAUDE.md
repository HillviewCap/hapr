# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

HAPR (HAProxy Audit & Reporting Tool) — a Python CLI that audits HAProxy configurations against a 65-check security baseline across 13 categories. It parses configs, scores them, optionally performs live TLS scanning (sslyze) and CVE lookups (NVD), generates Plotly topology graphs, and produces self-contained HTML reports via Jinja2.

## Commands

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run all tests
pytest tests/ -v

# Run a single test file
pytest tests/test_parser.py -v

# Quick audit (terminal output)
hapr audit examples/secure.cfg

# Full audit with HTML report (config + TLS + CVE)
hapr audit examples/secure.cfg --full -o report.html
```

CI runs on GitHub Actions (`.github/workflows/ci.yml`) across Python 3.10–3.12. The only dev dependency is pytest.

## Architecture

**CLI** (`hapr/cli.py`): Click command group with commands: `audit`, `scan`, `graph`, `score`, `list-checks`, `version-check`. Uses Rich for terminal output.

**Parser** (`hapr/parser.py`): Line-by-line state machine that parses HAProxy configs into dataclasses. Entry points: `parse_file(path)` and `parse_string(text)`.

**Models** (`hapr/models.py`): All dataclasses — config models (`HAProxyConfig`, `Frontend`, `Backend`, etc.), audit models (`AuditResult`, `Finding`, `CategoryScore`), scan/CVE models, and enums (`Status`, `Severity`).

**Engine** (`hapr/framework/engine.py`): Core audit pipeline. Loads baseline YAML, dynamically resolves check functions via `importlib.import_module`, executes checks, computes weighted scores per category and overall with letter grade (A-F).

**Checks** (`hapr/framework/checks/`): 13 modules, each containing pure functions that take `HAProxyConfig` and return `Finding`. Check IDs follow `HAPR-{CATEGORY}-{NNN}` pattern. The `__init__.py` imports all modules for registry.

**Baseline** (`framework/hapr-baseline.yaml`): Single source of truth for all 65 check definitions — id, title, severity, weight, category, check_function path, remediation, and references.

**Report** (`hapr/report.py`): Renders `templates/report.html.j2` with audit results and Plotly charts into self-contained HTML.

**Visualizer** (`hapr/visualizer.py`): Builds directed topology graph (Frontends → Backends → Servers) using Plotly with severity-colored nodes.

## Key Conventions

- All modules use `from __future__ import annotations` with Python 3.10+ type syntax (`X | Y`, `list[X]`)
- Check functions are pure: `HAProxyConfig` in, `Finding` out — baseline YAML provides all metadata
- Check function paths in baseline YAML use dotted format relative to `hapr.framework.checks` (e.g., `tls.check_minimum_tls_version`)
- Scoring: PASS=100%, PARTIAL=50%, FAIL=0%, N/A=excluded; severity weights: Critical=10, High=7, Medium=4, Low=2, Info=0
- Tests use class-based grouping and inline HAProxy config strings via `parse_string()`
- Logging via standard `logging.getLogger(__name__)`
