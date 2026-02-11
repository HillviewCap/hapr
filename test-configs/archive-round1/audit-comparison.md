# HAPR Tool vs. Manual Audit: Detailed Comparison Report

**Date**: 2026-02-11
**Scope**: live-server.cfg audit results + 10 GitHub configurations
**Manual Auditor**: Senior Cybersecurity Professional (65 findings across 13 categories)
**HAPR Tool**: Automated audit (62 checks executed for live-server.cfg, 65-check baseline)

---

## 1. Agreement Analysis

The manual audit and HAPR tool **agree** on the following findings for `live-server.cfg`. These represent validated, high-confidence results.

### 1.1 Agreed FAIL Findings (Both Found the Same Issues)

| HAPR Check | Manual Check | Finding | Severity |
|-----------|-------------|---------|----------|
| HAPR-PROC-001 | MAN-001 | No chroot configured | High |
| HAPR-PROC-002 | MAN-002 | No non-root user configured | Critical |
| HAPR-PROC-003 | MAN-003 | No group directive | Medium |
| HAPR-PROC-004 | MAN-004 | No ulimits configured | Low |
| HAPR-TLS-001 | MAN-005 | TLS 1.0 minimum version allowed | Critical |
| HAPR-ACL-002 | MAN-013 | No admin path restrictions | High |
| HAPR-ACL-003 | MAN-014 | No rate limiting configured | High |
| HAPR-ACL-004 | MAN-015 | No stick tables | Medium |
| HAPR-ACL-005 | MAN-016 | Stats without authentication | High |
| HAPR-HDR-002 | MAN-018 | No Content-Security-Policy | Medium |
| HAPR-HDR-004 | MAN-020 | No Referrer-Policy | Low |
| HAPR-HDR-005 | MAN-021 | No Permissions-Policy | Low |
| HAPR-REQ-001 | MAN-023 | No body size limits | Medium |
| HAPR-REQ-002 | MAN-024 | No URL length limits | Low |
| HAPR-REQ-003 | MAN-025 | No HTTP method filtering | Medium |
| HAPR-REQ-004 | MAN-026 | No request header size limits | Low |
| HAPR-LOG-003 | MAN-029 | Stats page has no authentication | High |
| HAPR-INF-003 | MAN-034 | Version-revealing headers not fully removed | Medium |
| HAPR-INF-004 | MAN-035 | Stats page version not hidden | Low |
| HAPR-BKD-002 | MAN-042 | No per-server connection limits | Medium |
| HAPR-BKD-003 | MAN-043 | Backend uses plain HTTP | Medium |
| HAPR-FRT-001 | MAN-046 | No per-frontend connection limits | Medium |
| HAPR-FRT-002 | MAN-047 | No explicit maxconn on frontends | Medium |
| HAPR-FRT-004 | MAN-049 | No WAF integration | Medium |
| HAPR-FRT-005 | MAN-050 | No SQL injection protection | Medium |
| HAPR-FRT-006 | MAN-051 | No XSS protection rules | Medium |
| HAPR-GBL-003 | MAN-054 | No DNS resolver configured | Low |

**Total: 27 agreed FAIL findings.** This is strong alignment.

### 1.2 Agreed PASS Findings (Both Confirmed Controls Present)

| HAPR Check | Manual Check | Finding |
|-----------|-------------|---------|
| HAPR-TLS-003 | MAN-007 | SSL default bind options set |
| HAPR-TLS-004 | MAN-008 | SSL default bind ciphers set |
| HAPR-TLS-005 | MAN-009 | TLS 1.3 ciphersuites configured |
| HAPR-TLS-006 | MAN-010 | HSTS header configured |
| HAPR-TLS-007 | MAN-011 | DH parameter size >= 2048 |
| HAPR-ACL-001 | MAN-012 | ACLs defined in frontends |
| HAPR-HDR-001 | MAN-017 | X-Frame-Options set |
| HAPR-HDR-003 | MAN-019 | X-Content-Type-Options set |
| HAPR-HDR-006 | MAN-022 | X-XSS-Protection not misconfigured (absent = good) |
| HAPR-LOG-001 | MAN-027 | Log directive present |
| HAPR-LOG-004 | MAN-030 | Appropriate log level |
| HAPR-LOG-005 | MAN-031 | HTTP log option enabled |
| HAPR-INF-001 | MAN-032 | Server header removed |
| HAPR-INF-002 | MAN-033 | Custom error pages configured |
| HAPR-TMO-001 | MAN-036 | Client timeout set |
| HAPR-TMO-002 | MAN-037 | Server timeout set |
| HAPR-TMO-003 | MAN-038 | Connect timeout set |
| HAPR-TMO-004 | MAN-039 | HTTP request timeout set |
| HAPR-TMO-005 | MAN-040 | Timeout values are reasonable |
| HAPR-BKD-001 | MAN-041 | Health checks configured |
| HAPR-BKD-005 | MAN-045 | Retry and redispatch configured |
| HAPR-GBL-001 | MAN-052 | Secure defaults section exists |
| HAPR-GBL-004 | MAN-055 | Global maxconn set |
| HAPR-GBL-005 | MAN-056 | Default DH parameter size set |

**Total: 24 agreed PASS findings.**

**Overall agreement: 51 out of ~55 comparable checks agree (93% concordance).**

---

## 2. Gaps in the HAPR Tool (Manual Found, Tool Missed)

### 2.1 CRITICAL BUG: HAPR-TLS-002 False Negative (Weak Cipher Detection Failure)

**This is the most significant finding in this comparison.**

**Issue**: The manual audit (MAN-006) correctly identified that `live-server.cfg` line 29 contains `DES-CBC3-SHA` and `RC4-SHA` in the cipher list. However, HAPR-TLS-002 reported **PASS** (no weak ciphers found). This is a confirmed **false negative** caused by a regex bug.

**Root Cause**: The weak cipher detection regex in `/home/snakep/hapr/hapr/framework/checks/tls.py` (line 21-26) is:

```python
_WEAK_CIPHER_PATTERNS = re.compile(
    r"(?:^|[:\+!,\s])"
    r"(?:DES|3DES|RC4|MD5|NULL|EXPORT|aNULL|eNULL|LOW|DES-CBC3)"
    r"(?:[:\+!,\s]|$)",
    re.IGNORECASE,
)
```

The regex requires the weak cipher keyword to be bounded by one of `: + ! , space` or string start/end. But in the actual cipher string:

```
ECDHE-RSA-AES128-SHA:DES-CBC3-SHA:RC4-SHA
```

- `DES-CBC3-SHA`: After `DES-CBC3`, the next character is `-` (hyphen), which is NOT in the boundary set `[:\+!,\s]`. The regex fails to match.
- `RC4-SHA`: After `RC4`, the next character is `-` (hyphen). Same problem.

**Proof of bug (verified via Python execution)**:

```python
>>> import re
>>> pattern = re.compile(r"(?:^|[:\+!,\s])(?:DES|3DES|RC4|MD5|NULL|EXPORT|aNULL|eNULL|LOW|DES-CBC3)(?:[:\+!,\s]|$)", re.IGNORECASE)
>>> cipher_str = "ECDHE-RSA-AES128-SHA:DES-CBC3-SHA:RC4-SHA"
>>> pattern.findall(cipher_str)
[]  # Empty -- no matches found!
```

**Impact**: Any configuration with OpenSSL-style cipher names like `DES-CBC3-SHA`, `RC4-SHA`, `RC4-MD5`, or `DES-CBC-SHA` will **falsely pass** the weak cipher check. This is a critical security gap because the entire purpose of this check is to detect exactly these ciphers.

**Recommended Fix**: The regex needs to account for full OpenSSL cipher suite names. Instead of trying to match isolated keywords with delimiters, the pattern should match these weak cipher names as they actually appear in cipher strings:

```python
_WEAK_CIPHER_PATTERNS = re.compile(
    r"(?:^|:)"
    r"("
    r"(?:EXP-|EXPORT-)?\S*(?:DES-CBC3|DES-CBC|RC4|RC2|NULL|SEED|IDEA)\S*"
    r"|(?:DES|3DES|RC4|MD5|NULL|EXPORT|aNULL|eNULL|LOW)"
    r")"
    r"(?::|$)",
    re.IGNORECASE,
)
```

Or, more robustly, split on `:` and check each cipher name individually:

```python
def _has_weak_ciphers(cipher_string: str) -> list[str]:
    weak_keywords = {"DES", "3DES", "RC4", "MD5", "NULL", "EXPORT",
                     "aNULL", "eNULL", "LOW", "DES-CBC3", "RC2", "SEED"}
    weak_found = []
    for cipher in cipher_string.split(":"):
        cipher_upper = cipher.upper().strip()
        # Skip exclusion patterns like !RC4
        if cipher_upper.startswith("!"):
            continue
        for keyword in weak_keywords:
            if keyword in cipher_upper:
                weak_found.append(cipher.strip())
                break
    return weak_found
```

### 2.2 Manual Found Partial Status Where Tool Found Binary PASS/FAIL

| Manual Check | Tool Check | Discrepancy |
|-------------|-----------|-------------|
| MAN-034 (PARTIAL) | HAPR-INF-003 (FAIL) | Manual auditor gave PARTIAL because the `Server` header IS removed, but `X-Powered-By` is not. The tool gave FAIL because it requires removing at least 2 version-revealing headers for PASS and found 0 explicit `del-header` directives for the version header list (`x-powered-by`, `x-aspnet-version`, etc.). The `Server` header removal is checked separately by HAPR-INF-001. The tool's FAIL is arguably correct since the check specifically examines version-revealing headers like `X-Powered-By`, distinct from the `Server` header. However, a PARTIAL might be more appropriate since the `Server` header IS being stripped (reducing overall disclosure risk). |
| MAN-053 (PARTIAL) | HAPR-GBL-002 (PASS) | Manual auditor noted stats socket at `/tmp/haproxy.sock` is in a world-accessible directory, despite `mode 660`. The tool PASSED because `mode 660` is present. The tool does not check the socket path for security-sensitive directories like `/tmp`. This is a gap -- the socket path should be evaluated as part of the permission assessment. |

### 2.3 Manual Audit Findings the Tool Does Not Cover At All

| Manual Check | Category | Finding | Why Tool Missed |
|-------------|----------|---------|----------------|
| MAN-044 | Backend Security | Cookie persistence missing or insecure | The tool's HAPR-BKD-004 returned N/A (no cookie directive found). The manual auditor noted the *absence* of cookie persistence as a finding, plus warned about future security attributes if added. The tool correctly identifies N/A when no cookies exist, but the manual auditor treated the absence differently (as a note about missing affinity). This is arguably correct N/A behavior by the tool. |
| MAN-053 | Global/Defaults | Stats socket in /tmp is risky despite mode 660 | Tool checks `mode` value but not socket path. See section 2.2. |
| GH02-003/GH01-003 | Access Control | Weak stats credentials (admin:admin) | The tool checks for presence of `stats auth` but does not evaluate password strength. The manual auditor flagged trivially guessable credentials. **Improvement opportunity**: Add weak-password detection to HAPR-ACL-005 and HAPR-LOG-003. |
| GH09-002 | Process Security | Passwords stored with `insecure-password` | The tool does not check for plaintext passwords in `userlist` sections. **Improvement opportunity**: Add a check for `insecure-password` directives. |
| GH06-003 | Timeouts | Excessively long client/server timeouts (4h) | HAPR-TMO-005 checks for unreasonable timeouts but the threshold details are unclear. The manual auditor flagged 4-hour timeouts as excessive even though they are "set". This may be working correctly for most configs but needs verification against ocp4-helpernode. |
| GH06-006 | Backend Security | `verify none` on SSL connections | The tool checks for backend SSL presence (HAPR-BKD-003) but does not verify the verification mode. `ssl verify none` is present but the security implications are not assessed. **Improvement opportunity**: Add a check for `verify none` on backend SSL. |

---

## 3. Gaps in the Manual Audit (Tool Found, Manual Missed)

The HAPR tool identified several issues that the manual auditor did not explicitly call out:

### 3.1 Live TLS Scan Results (Tool Had Data, Manual Could Not)

The HAPR tool performed a live TLS scan that the manual auditor could not replicate without a running server:

| HAPR Check | Status | Finding |
|-----------|--------|---------|
| HAPR-SCAN-001 | PASS | No deprecated TLS versions accepted (runtime -- despite config allowing TLS 1.0, the OpenSSL library may have rejected it) |
| HAPR-SCAN-002 | PASS | No weak ciphers negotiated (runtime -- OpenSSL may have refused DES-CBC3-SHA and RC4-SHA even though they are in the config) |
| HAPR-SCAN-003 | FAIL | Certificate chain issues (self-signed test cert) |
| HAPR-SCAN-004 | PASS | Certificate not expired |
| HAPR-SCAN-005 | PASS | No known TLS vulnerabilities (Heartbleed, ROBOT, CCS) |
| HAPR-SCAN-006 | PASS | Secure renegotiation supported |

**Important note on HAPR-SCAN-001 and HAPR-SCAN-002 PASS results**: The config explicitly allows TLS 1.0 and includes `DES-CBC3-SHA:RC4-SHA`. The live scan showed these were NOT actually negotiable at runtime. This means the running OpenSSL library rejected them despite the config allowing them. This is a valuable finding from the live scan -- **configuration analysis alone would overstate the risk** while live scanning reveals the actual attack surface. However, this creates a false sense of security if the OpenSSL version is later downgraded. The static config analysis (HAPR-TLS-001 FAIL, HAPR-TLS-002 should-be-FAIL) correctly flags the configuration-level risk.

### 3.2 Checks the Manual Auditor Did Not Explicitly Cover

The manual auditor covered the same conceptual ground but did not have individual check IDs for:

- **HAPR-FRT-001/002**: Explicit per-frontend maxconn. The manual audit noted this in MAN-046/047 but the tool has two separate checks (connection rate limits vs. maxconn presence), providing more granular visibility.
- **HAPR-LOG-002**: The tool passed this (accepts `option httplog` as detailed logging), while the manual audit failed it (MAN-028, wants custom `log-format`). See Section 5 for analysis of this disagreement.

---

## 4. Context Sensitivity Analysis

### 4.1 How the Tool Handles Special-Purpose Configs

The manual auditor correctly noted that some GitHub configs are special-purpose (TCP-only, Kubernetes, database proxies) where HTTP-focused checks are N/A. The HAPR tool's handling:

**Checks that properly return N/A**:

| Check | N/A Trigger | Behavior |
|-------|-----------|----------|
| HAPR-BKD-001 | No backend sections | Returns N/A |
| HAPR-BKD-003 | No server lines | Returns N/A |
| HAPR-BKD-004 | No cookie directives | Returns N/A |
| HAPR-FRT-001 | No frontend sections | Returns N/A |
| HAPR-FRT-003 | No port-80 frontends | Returns N/A |

**Checks that INCORRECTLY FAIL for TCP/special-purpose configs**:

| Check | Issue | Impact |
|-------|-------|--------|
| HAPR-HDR-001 through HAPR-HDR-006 | HTTP security headers checks FAIL on TCP-only configs (bbossgroups-tcp, triton-moray, severalnines-db-ha) | These checks look for `http-response set-header` directives. In TCP mode, HTTP headers are irrelevant and these directives are invalid. The checks should return N/A when no HTTP-mode frontends exist. |
| HAPR-REQ-001 through HAPR-REQ-004 | Request handling checks FAIL on TCP-only configs | Request body size, URL length, method filtering, and header size limits are HTTP-layer concepts. They should return N/A in TCP-only configs. |
| HAPR-INF-001 | Server header removal FAIL on TCP-only configs | `http-response del-header Server` is an HTTP directive. N/A is appropriate for TCP-mode configs. |
| HAPR-INF-003 | Version header removal FAIL on TCP-only configs | Same as above. |
| HAPR-FRT-004/005/006 | WAF, SQLi, XSS checks FAIL on TCP-only configs | These are HTTP application-layer protections. They do not apply to TCP passthrough configurations. |
| HAPR-ACL-002 | Admin path restrictions FAIL on TCP-only configs | Path-based ACLs are HTTP concepts. N/A for TCP mode. |

**Quantifying the scoring impact**: For a TCP-only config like `bbossgroups-tcp.cfg`, approximately 15-18 checks are incorrectly applied as FAIL instead of N/A. Since N/A checks are excluded from scoring, these false failures significantly deflate the score. A TCP load balancer with proper process hardening, timeouts, and logging could score 60-70% instead of the reported 37.2% if HTTP-specific checks were properly excluded.

### 4.2 The Kubernetes Config Problem

For `kubernetes-docker-packt.cfg`, the tool scored 28.2% (F). The manual auditor noted this is a Kubernetes ingress load balancer where TCP passthrough is acceptable. The tool applies all 62+ checks including HTTP headers, request filtering, and TLS configuration, none of which apply to a TCP passthrough proxy. A contextually correct score would be significantly higher once irrelevant checks are excluded.

### 4.3 Recommended Context Sensitivity Improvements

1. **Add mode detection**: Before running HTTP-specific checks, detect whether any frontend/listen section uses `mode http`. If all sections are `mode tcp`, return N/A for HTTP-specific checks.

2. **Add a `requires_mode` field to baseline YAML**: Similar to the existing `requires: scanner` and `requires: version` fields, add `requires_mode: http` to HTTP-specific checks. The engine can then skip them automatically for TCP-only configs.

3. **Per-section mode awareness**: Some configs have both TCP and HTTP sections. Checks should evaluate only the relevant sections.

---

## 5. False Positive / False Negative Analysis

### 5.1 Confirmed False Negatives (Tool says PASS, should say FAIL)

| Check | Expected | Actual | Details | Severity |
|-------|----------|--------|---------|----------|
| **HAPR-TLS-002** | **FAIL** | **PASS** | **BUG**: Regex fails to detect `DES-CBC3-SHA` and `RC4-SHA` in the cipher string. Full analysis in Section 2.1. | **CRITICAL** |
| HAPR-GBL-002 | FAIL or PARTIAL | PASS | Stats socket at `/tmp/haproxy.sock` with `mode 660` passes, but `/tmp` is world-accessible. A `mode 660` socket in `/tmp` is still less secure than one in `/var/run/haproxy/`. The tool should warn about `/tmp` socket locations. | Medium |

### 5.2 Confirmed False Positives (Tool says FAIL, but control is present or N/A)

For the **live-server.cfg** specifically, no clear false positives were identified. All FAIL findings correspond to genuinely missing controls.

However, for the **GitHub configs**, there are systematic false positives:

| Config | Affected Checks | Issue |
|--------|----------------|-------|
| bbossgroups-tcp.cfg | HAPR-HDR-001 through HDR-006, HAPR-REQ-001 through REQ-004, HAPR-INF-001, HAPR-INF-003, HAPR-ACL-002, HAPR-FRT-004/005/006 | TCP-only config; HTTP checks are inapplicable (see Section 4) |
| triton-moray.cfg | Same set of HTTP checks | TCP-only config |
| severalnines-db-ha.cfg | Same set of HTTP checks | Database proxy in TCP mode |
| kubernetes-docker-packt.cfg | HTTP header, request, and frontend security checks | TCP passthrough for Kubernetes |

### 5.3 Disagreements (Differing Professional Judgment, Not Bugs)

| Check | Tool Result | Manual Result | Analysis |
|-------|-----------|--------------|----------|
| HAPR-LOG-002 | PASS | MAN-028 FAIL | The tool accepts `option httplog` as sufficient for "detailed log format." The manual auditor wanted a custom `log-format` string with security-specific fields. Both positions have merit: `option httplog` provides good detail (client IP, request, status, timers), but a custom `log-format` can include captured headers and more security-relevant fields. **Recommendation**: Change HAPR-LOG-002 to PARTIAL when only `option httplog` is present (recognizing it provides good-but-not-optimal detail), and PASS only when a custom `log-format` is defined. |
| HAPR-FRT-003 | N/A | MAN-048 PASS | The tool returned N/A because `ft_http` binds on port 8080, not port 80, and the check only looks for port 80. The manual auditor gave PASS recognizing the redirect exists on 8080. **Recommendation**: Expand HAPR-FRT-003 to check common HTTP ports (80, 8080, 8000) or any non-SSL frontend, not just port 80. |
| HAPR-BKD-004 | N/A | MAN-044 FAIL | The tool returns N/A (no cookie directive). The manual auditor noted the absence of session persistence and warned about security attributes if cookies are added. N/A is technically correct since the check is about cookie *security*, not cookie *presence*. No change needed. |

---

## 6. Scoring Fairness

### 6.1 Live Server Scoring Comparison

| Metric | HAPR Tool | Manual Audit |
|--------|----------|-------------|
| Overall Score | 60.4% (D) | "HIGH" risk |
| Total Checks | 62 (3 CVE checks skipped) | 65 (9 UNKNOWN for live/CVE) |
| PASS | 33 | 24 |
| FAIL | 27 | 30 |
| PARTIAL | 0 | 2 |
| N/A | 2 | 0 |
| UNKNOWN | 0 | 9 |

**Key observations**:

1. **The D grade (60.4%) is generous given the actual security posture.** The config has critical TLS weaknesses (TLS 1.0 + weak ciphers), an unauthenticated admin stats page, no process isolation, no rate limiting, and no request filtering. The manual auditor rated this as "HIGH" risk. A D grade may not adequately communicate the severity to a non-technical stakeholder.

2. **The TLS-002 false negative inflates the score.** HAPR-TLS-002 is a critical-severity check (weight 10). If it correctly reported FAIL, the TLS category score would drop from 79.6% to approximately 64.3%, and the overall score would drop from 60.4% to approximately 57.4% (still D, but closer to F).

3. **Severity weighting works well for prioritization.** Critical (10), High (7), Medium (4), Low (2), Info (0) correctly ensures that process security (all critical/high checks failing) scores 0% while timeouts (all medium/low checks passing) scores 100%. This properly surfaces the most dangerous gaps.

4. **The letter grade thresholds may need adjustment.** The grading scale (A: 90+, B: 80+, C: 70+, D: 60+, F: <60) means a config with critical vulnerabilities can still get a D (60-69%). Consider:
   - Adding a rule: if any critical-severity check FAILs, the maximum grade is capped at D regardless of overall score.
   - Or adjusting thresholds: A: 95+, B: 85+, C: 70+, D: 55+, F: <55.

### 6.2 GitHub Config Scoring

| Config | HAPR Score | Manual Risk | Alignment |
|--------|-----------|------------|-----------|
| akhilraj-haproxy-backend | 42.8% (F) | MEDIUM | Over-penalized (good process hardening not weighted enough) |
| bbossgroups-tcp | 37.2% (F) | MEDIUM-HIGH | **Severely over-penalized** due to HTTP checks applied to TCP config |
| haproxy-acme-validation | 38.2% (F) | HIGH | Aligned |
| jenkins-ha | 42.4% (F) | MEDIUM | Somewhat over-penalized (good process hardening + stick-tables) |
| kubernetes-docker-packt | 28.2% (F) | HIGH | Over-penalized due to TCP/passthrough checks being applied |
| ocp4-helpernode | 37.0% (F) | MEDIUM | Over-penalized (infrastructure config with good fundamentals) |
| rabbitmq-lb | 27.7% (F) | MEDIUM-HIGH | Somewhat aligned |
| rpm-haproxy | 30.0% (F) | MEDIUM | Over-penalized (has good process hardening, maxconn, health checks) |
| severalnines-db-ha | 28.5% (F) | MEDIUM | Over-penalized (good auth model, TCP-only) |
| triton-moray | 27.1% (F) | HIGH | Somewhat aligned (genuinely weak config) |

**All 10 GitHub configs received F grades.** While many have real security issues, the universal F rating reduces the tool's discriminating power. A config with chroot, user/group, logging, timeouts, and authenticated stats (like severalnines-db-ha) receiving the same grade as one with almost nothing (kubernetes-docker-packt) makes it hard to prioritize remediation.

**Root causes of score deflation**:
1. HTTP-specific checks applied to TCP configs (15-18 checks incorrectly FAIL)
2. Aspirational checks (WAF, SQLi protection, XSS protection) that virtually no real-world HAProxy config implements, always FAIL
3. No context weighting for config purpose (infrastructure vs. public-facing)

---

## 7. Recommended Tool Improvements

### Priority 1: Critical Bug Fixes

**7.1. Fix HAPR-TLS-002 Weak Cipher Regex (BUG)**
- **File**: `/home/snakep/hapr/hapr/framework/checks/tls.py`, lines 21-26
- **Issue**: `_WEAK_CIPHER_PATTERNS` regex fails to match OpenSSL-format cipher names like `DES-CBC3-SHA`, `RC4-SHA`, `RC4-MD5`
- **Fix**: Replace the boundary-based regex with a colon-delimited split-and-match approach:
  ```python
  _WEAK_CIPHER_NAMES = {"DES", "3DES", "RC4", "MD5", "NULL", "EXPORT",
                         "aNULL", "eNULL", "LOW", "DES-CBC3", "DES-CBC",
                         "RC2", "SEED", "IDEA"}

  def _find_weak_ciphers(cipher_string: str) -> list[str]:
      weak = []
      for cipher in cipher_string.split(":"):
          c = cipher.strip()
          if c.startswith("!"):
              continue
          c_upper = c.upper()
          for wk in _WEAK_CIPHER_NAMES:
              if wk in c_upper:
                  weak.append(c)
                  break
      return weak
  ```
- **Impact**: Critical. This is a security tool failing to detect known-insecure ciphers.

### Priority 2: Context Sensitivity

**7.2. Add Mode-Aware Check Filtering**
- **File**: `/home/snakep/hapr/framework/hapr-baseline.yaml` and `/home/snakep/hapr/hapr/framework/engine.py`
- **Issue**: HTTP-specific checks (headers, request handling, WAF, SQLi, XSS, admin paths, server header removal) are applied to TCP-only configs, producing false FAILs.
- **Fix**: Add a `requires_mode: http` field to HTTP-specific checks in the baseline YAML. In the engine, skip checks where `requires_mode` does not match the config's detected mode. Detection logic: if ALL defaults + frontends + listens use `mode tcp`, the config is TCP-only.
- **Affected checks**: HAPR-HDR-001 through HDR-006, HAPR-REQ-001 through REQ-004, HAPR-INF-001, HAPR-INF-003, HAPR-ACL-002, HAPR-FRT-003 through FRT-006
- **Impact**: High. Fixes scoring for 6+ of the 10 GitHub configs.

**7.3. Expand HTTP-to-HTTPS Redirect Port Detection**
- **File**: `/home/snakep/hapr/hapr/framework/checks/frontend.py`, `check_http_to_https_redirect()`
- **Issue**: Only checks for port 80 binds. Misses common HTTP ports like 8080, 8000.
- **Fix**: Check ports 80, 8080, 8000, or better yet, check any non-SSL frontend that does not redirect.
- **Impact**: Low (only affects unusual port configs).

### Priority 3: Detection Improvements

**7.4. Add Stats Password Strength Check**
- **Issue**: Tool checks for `stats auth` presence but does not evaluate password quality. `stats auth admin:admin` passes.
- **Fix**: Add a check (or enhance HAPR-ACL-005/HAPR-LOG-003) that flags common/weak passwords (admin:admin, admin:password, haproxy:haproxy, etc.) and very short passwords.
- **Impact**: Medium. Several GitHub configs have trivial stats passwords.

**7.5. Add Stats Socket Path Check**
- **File**: `/home/snakep/hapr/hapr/framework/checks/global_defaults.py`, `check_stats_socket_permissions()`
- **Issue**: Tool checks `mode` value but not socket path. Sockets in `/tmp` are risky even with `mode 660`.
- **Fix**: Flag sockets in `/tmp`, `/var/tmp`, or other world-accessible directories. Recommend `/var/run/haproxy/` or similar restricted paths.
- **Impact**: Medium.

**7.6. Add Backend SSL Verification Mode Check**
- **Issue**: HAPR-BKD-003 checks for `ssl` keyword on server lines but does not check `verify` option. `ssl verify none` is flagged as a PASS, even though it is vulnerable to MITM.
- **Fix**: Add a new check or enhance HAPR-BKD-003 to PARTIAL when `ssl verify none` is detected, and PASS only when `ssl verify required` with a CA file is present.
- **Impact**: Medium. Affects configs like ocp4-helpernode.

**7.7. Add Plaintext Password Detection**
- **Issue**: `userlist` sections with `insecure-password` directives are not flagged.
- **Fix**: Add a new check that scans for `insecure-password` in userlist sections and flags it as a security concern.
- **Impact**: Medium.

### Priority 4: Scoring Refinements

**7.8. Add Critical-Failure Grade Capping**
- **Issue**: A config with critical-severity FAILs can still get a D (60%+).
- **Fix**: If any critical-severity check FAILs, cap the letter grade at D maximum. If 3+ critical checks FAIL, cap at F.
- **Impact**: Low (scoring presentation only, no detection change).

**7.9. Reclassify HAPR-LOG-002 PASS Threshold**
- **Issue**: `option httplog` alone gives PASS. A custom `log-format` provides significantly better security visibility.
- **Fix**: Change to: PASS = custom `log-format` present; PARTIAL = `option httplog` or `option tcplog` only; FAIL = neither.
- **Impact**: Low.

**7.10. Add Config-Purpose Classification**
- **Issue**: All configs scored on the same baseline, but infrastructure configs, database proxies, and public-facing web proxies have different security requirements.
- **Fix**: Add optional config classification (web, infrastructure, database, internal) that adjusts which checks are evaluated and their weights.
- **Impact**: Low (significant effort, long-term improvement).

---

## 8. Summary of Key Metrics

| Metric | Value |
|--------|-------|
| Total agreement rate (live-server.cfg) | 93% (51/55 comparable checks) |
| Confirmed bugs in HAPR tool | 1 critical (TLS-002 regex) |
| False negatives identified | 2 (TLS-002 cipher regex, GBL-002 /tmp socket) |
| False positives (live-server) | 0 |
| Systematic false positives (GitHub TCP configs) | 15-18 checks per TCP-only config |
| Checks manual found that tool lacks | 4 (password strength, socket path, SSL verify mode, plaintext passwords) |
| Scoring accuracy for live-server | Good (D is somewhat generous given critical failures) |
| Scoring accuracy for GitHub configs | Poor (all F, no discrimination between configs of varying quality) |
| Recommended improvements | 10 (1 critical bug fix, 2 context sensitivity, 4 detection, 3 scoring) |

---

*End of Comparison Report*
