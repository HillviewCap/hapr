# HAPR User Guide

HAPR (HAProxy Audit & Reporting Tool) is a Python CLI that audits HAProxy configurations against a 103-check security baseline. It parses configs, scores them, optionally performs live TLS scanning and CVE lookups, generates topology graphs, and produces self-contained HTML reports.

No CIS benchmark or automated security audit tool exists for HAProxy -- HAPR fills that gap.

---

## Installation

Requires **Python 3.10+**.

```bash
# From PyPI
pip install hapr

# From source (editable install with dev dependencies)
pip install -e ".[dev]"

# From source with pinned dependencies
pip install -r requirements.txt
pip install -e .
```

### Optional Dependencies

- **sslyze** -- Required for live TLS scanning (`--scan` and `--full` flags). Install separately if not included.
- **NVD API key** -- Provides higher rate limits for CVE lookups. Set via `--nvd-api-key` flag or the `NVD_API_KEY` environment variable.

---

## Commands

### `hapr audit` -- Run a Security Audit

The primary command. Parses an HAProxy configuration file, runs security checks against the baseline, and reports results.

```bash
# Basic audit (terminal output, all tiers)
hapr audit haproxy.cfg

# Tiered assessments
hapr audit haproxy.cfg --tier baseline     # Minimum viable security (17 checks)
hapr audit haproxy.cfg --tier level1       # Standard production (58 cumulative checks)
hapr audit haproxy.cfg --tier level2       # Advanced protection (86 cumulative checks)
hapr audit haproxy.cfg                     # Full assessment (103 checks)

# Generate an HTML report
hapr audit haproxy.cfg -o report.html

# Full audit: config + live TLS scan + CVE check
hapr audit haproxy.cfg --full -o report.html
```

**Options:**

| Flag | Description |
|------|-------------|
| `-o, --output PATH` | Generate an HTML report at the given path |
| `--tier TIER` | Run checks up to this tier: `baseline`, `level1`, `level2`, or `level3` (default: all) |
| `--scan / --no-scan` | Enable live TLS scanning (auto-discovers targets from bind lines) |
| `--scan-targets HOST:PORT` | Explicit TLS scan targets (repeatable) |
| `--version-detect / --no-version-detect` | Enable HAProxy version detection and CVE checking |
| `--full` | Shorthand for `--scan --version-detect` |

### `hapr scan` -- Standalone TLS Scan

Scan one or more TLS endpoints without running the full audit. Reports accepted protocols, cipher suites, certificate details, and known TLS vulnerabilities.

```bash
hapr scan example.com:443
hapr scan lb1.internal:443 lb2.internal:443
```

### `hapr graph` -- Topology Graph

Generate an interactive HTML network diagram showing how frontends route traffic to backends and servers.

```bash
hapr graph haproxy.cfg -o topology.html
```

### `hapr score` -- Quick Score

Print the overall score and grade to the terminal without detailed findings.

```bash
hapr score haproxy.cfg
```

### `hapr list-checks` -- List All Checks

Display every check in the baseline with its ID, title, category, severity, and requirements.

```bash
hapr list-checks
```

### `hapr version-check` -- CVE Lookup

Look up known CVEs for a specific HAProxy version without needing a configuration file.

```bash
hapr version-check 2.6.0
```

---

## Global Options

These options apply to all commands:

| Option | Description |
|--------|-------------|
| `--baseline PATH` | Use a custom baseline YAML file instead of the built-in one |
| `--nvd-api-key KEY` | NVD API key for CVE lookups (or set `NVD_API_KEY` env var) |
| `--socket PATH` | HAProxy runtime API Unix socket path for version detection |
| `--haproxy-bin PATH` | Path to the `haproxy` binary for version detection |
| `--stats-url URL` | HAProxy stats page URL for version detection |
| `--log-level LEVEL` | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` (default: `WARNING`) |
| `--log-file PATH` | Write log output to a file |

---

## Running Assessments

### Standalone Assessment (Config File Only)

The simplest use case: audit a configuration file sitting on your local machine. No network access required.

```bash
# Baseline tier -- minimum viable security (17 checks)
hapr audit /etc/haproxy/haproxy.cfg --tier baseline

# Full tier sweep with an HTML report
hapr audit /etc/haproxy/haproxy.cfg -o audit-report.html
```

This mode analyzes the config text for security issues: missing TLS settings, weak timeouts, absent headers, process hardening gaps, and more. It works entirely offline.

### Network Assessment (Config + Live Scanning + CVE)

For a comprehensive assessment, enable live TLS scanning and CVE checking. This requires network access to the HAProxy endpoints and the NVD API.

```bash
# Full audit: parse config, scan TLS endpoints, check CVEs
hapr audit /etc/haproxy/haproxy.cfg --full -o full-report.html
```

**How targets are discovered:**
- With `--scan`, HAPR reads `bind` lines from the config and attempts to connect to each TLS-enabled endpoint.
- With `--scan-targets`, you specify endpoints explicitly (useful when the config uses internal hostnames or when scanning from a different network).

```bash
# Explicit scan targets
hapr audit haproxy.cfg --scan-targets lb.example.com:443 --scan-targets api.example.com:8443 -o report.html
```

**Version detection** uses three methods (tried in order):
1. **Unix socket** -- Query the HAProxy runtime API via `--socket /var/run/haproxy.sock`
2. **Binary** -- Run `haproxy -v` via `--haproxy-bin /usr/sbin/haproxy`
3. **Stats page** -- Scrape the version from the stats URL via `--stats-url http://localhost:9000/stats`

```bash
# Full network assessment with explicit version detection
hapr audit haproxy.cfg \
  --full \
  --socket /var/run/haproxy/admin.sock \
  --nvd-api-key $NVD_API_KEY \
  -o report.html
```

### Using a Custom Baseline

Override the built-in baseline with your own YAML file to tailor checks to your organization's requirements:

```bash
hapr audit haproxy.cfg --baseline my-custom-baseline.yaml -o report.html
```

See the [HAPR Framework](HAPR-Framework) page for details on the baseline format and how to create custom checks.

---

## Example Configurations

Three example configs are included in the `examples/` directory for testing:

| Config | Description | Expected Scores |
|--------|-------------|-----------------|
| `examples/secure.cfg` | Well-hardened configuration | Baseline: A 100%, Level 1: B 84%, Full: C 71% |
| `examples/insecure.cfg` | Deliberately weak configuration | Low scores across all tiers |
| `examples/mixed.cfg` | Realistic production config with gaps | Mixed results |

```bash
# Try it out
hapr audit examples/secure.cfg --tier baseline
hapr audit examples/insecure.cfg -o insecure-report.html
```
