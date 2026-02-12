# Understanding the Report

When you run `hapr audit` with the `-o` flag, HAPR generates a self-contained HTML report that you can open in any browser and share with stakeholders. This page walks through each section of the report.

```bash
hapr audit haproxy.cfg -o report.html
```

---

## Report Layout

The report is a single HTML file with no external dependencies (except the Plotly CDN for interactive charts). It contains these sections, accessible via a sticky navigation bar at the top:

1. **Executive Summary**
2. **Score Breakdown**
3. **Network Topology**
4. **TLS Scan Results** (only when `--scan` or `--full` is used)
5. **CVE Summary** (only when `--version-detect` or `--full` is used)
6. **Findings Detail**
7. **Remediation Summary**

---

## 1. Executive Summary

The first thing you see is the overall assessment at a glance:

- **Grade Badge** -- A large circular badge showing the letter grade (A through F) with color coding:
  - **A** (90-100%): Green -- strong security posture
  - **B** (80-89%): Blue -- good with minor gaps
  - **C** (70-79%): Yellow -- moderate issues need attention
  - **D** (60-69%): Orange -- significant security gaps
  - **F** (below 60%): Red -- critical issues present

- **Overall Score** -- The weighted percentage score displayed below the grade.

- **Audit Metadata** -- Configuration file path, scan date, detected HAProxy version, and whether TLS scanning and CVE checking were performed.

- **Finding Counts** -- Quick summary boxes showing the total number of checks and how many passed, failed, were partial, or not applicable.

---

## 2. Score Breakdown

This section provides per-category visibility into the assessment results.

- **Bar Chart** -- An interactive Plotly chart showing each category's score as a horizontal bar. Hover over bars for exact percentages.

- **Category Details Table** -- Every category listed with:
  - Category name
  - Score percentage
  - Color-coded progress bar (green/yellow/red)
  - Pass, fail, partial, and N/A counts
  - Total checks in the category

Categories are scored using weighted averages based on each check's severity weight. A category with only low-severity failures will score higher than one with critical-severity failures. See the [HAPR Framework](HAPR-Framework) page for details on the scoring model.

---

## 3. Network Topology

An interactive Plotly graph showing the traffic flow through your HAProxy configuration:

- **Frontends** (left) -- Entry points where clients connect
- **Backends** (center) -- Server groups that receive routed traffic
- **Servers** (right) -- Individual backend servers

Nodes are connected by directed edges showing `use_backend` and `default_backend` routing. You can zoom, pan, and hover over nodes for details.

---

## 4. TLS Scan Results

This section appears when the audit includes live TLS scanning (`--scan`, `--scan-targets`, or `--full`). Each scanned endpoint gets its own card showing:

- **Protocols** -- Color-coded tags for each TLS protocol version. Green tags indicate accepted protocols; red tags indicate rejected (good -- you want old protocols rejected).

- **Accepted Cipher Suites** -- Listed per protocol version. Review these for weak ciphers that should be disabled.

- **Certificate Information** -- A grid showing:
  - Subject and issuer
  - Validity period (not before / not after)
  - Key size and signature algorithm
  - Whether the certificate is self-signed or expired
  - Whether the chain is valid
  - Subject Alternative Name (SAN) entries

- **Vulnerability Checks** -- A table of known TLS vulnerabilities (Heartbleed, ROBOT, etc.) with a clear VULNERABLE or Safe status for each.

- **Additional Details** -- HSTS header presence, Fallback SCSV support, secure renegotiation status, and supported elliptic curves.

---

## 5. CVE Summary

This section appears when version detection and CVE checking are enabled (`--version-detect` or `--full`). It shows:

- The detected HAProxy version
- Total CVEs found
- A table listing each CVE with:
  - **CVE ID** (linked to the NVD entry)
  - **Description** of the vulnerability
  - **CVSS score** (numerical severity rating)
  - **Severity badge** (critical/high/medium/low)
  - **Published date**

If no CVEs are found for your version, a green success message is displayed instead.

---

## 6. Findings Detail

The most detailed section of the report. Every check that was executed is listed in a sortable, filterable table:

### Filtering

Three filter groups at the top let you narrow the view:

- **Severity**: All, Critical, High, Medium, Low, Info
- **Status**: All, Pass, Fail, Partial, N/A
- **Category**: All, or any specific category (Process, TLS, Access, etc.)

Filters combine -- selecting "High" severity and "Fail" status shows only high-severity failures.

### Table Columns

| Column | Description |
|--------|-------------|
| **ID** | The check identifier (e.g., `HAPR-TLS-001`) |
| **Title** | Human-readable name of the check |
| **Category** | Which security category it belongs to |
| **Severity** | Color-coded badge: critical (red), high (orange-red), medium (yellow), low (green), info (blue) |
| **Status** | The check result: pass (green), fail (red), partial (yellow), n/a (gray) |
| **Message** | Explanation of what was found |
| **Evidence** | The specific config lines or data that triggered the result |

Click any column header to sort the table by that column.

### Understanding Status Values

- **Pass** -- The check's security requirement is fully met.
- **Fail** -- The check's requirement is not met. Review the message and remediation guidance.
- **Partial** -- The requirement is partially met. Some but not all instances comply (e.g., HSTS is set on some frontends but not all).
- **N/A** -- The check does not apply to this configuration (e.g., mTLS checks when no client certificates are configured).

---

## 7. Remediation Summary

Failed findings are grouped by severity level (critical first, then high, medium, low) with actionable remediation guidance for each:

- **Check ID and title** -- Identifies which check failed
- **Remediation text** -- Specific instructions on how to fix the issue, typically including HAProxy directive examples

This section is designed to be handed directly to the team responsible for updating the HAProxy configuration. If all checks pass, a green success message confirms no remediation is needed.

---

## Sharing Reports

The HTML report is self-contained and can be:

- Opened directly in any browser
- Attached to emails or tickets
- Stored as audit artifacts for compliance
- Compared across time by saving reports from successive audits

The only external dependency is the Plotly CDN for the interactive charts. If you need fully offline reports, the charts will still render if the CDN was cached by your browser.
