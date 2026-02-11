# HAPR Baseline Gap Assessment & Tiered Level Framework

## Executive Summary

This report assesses the HAPR security baseline (`framework/hapr-baseline.yaml`) against HAProxy's
official configuration tutorials, industry security frameworks (DISA STIG, NIST, OWASP, PCI DSS),
and HAProxy advanced security features. It defines a four-tier assessment model and identifies
specific gaps, duplications, and reclassification needs.

**Key Findings:**
- The current baseline has **66 checks** (not 65 as documented) across 13 categories
- **3 check duplications** inflate scoring unfairly (DH param, stats security, maxconn)
- **3-4 checks are mistiered** — WAF/SQLi/XSS and DNS resolver penalize standard deployments
- **1 miscategorization** — LOG-003 (stats secured) belongs in access control
- **18 missing baseline/L1 checks** identified from HAProxy docs and industry standards
- **No CIS Benchmark exists for HAProxy** — HAPR fills a genuine gap in the ecosystem
- The DISA Web Server SRG is the closest authoritative framework with 17+ mappable controls

---

## 1. Tier Definitions

### Baseline — Configuration Hardening
**Purpose:** Minimum viable security. Every HAProxy deployment MUST pass these checks.
**Audience:** All deployments, regardless of environment.
**Standard:** DISA STIG CAT I + essential CAT II, PCI DSS mandatory requirements.
**Scope:** Static config analysis only. No external dependencies.

### Level 1 — Standard Production Security
**Purpose:** Standard production hardening addressing most compliance requirements.
**Audience:** Production environments with security requirements, SOC 2, general PCI scope.
**Standard:** DISA STIG CAT II/III, PCI DSS Req 2/4/6/10, SOC 2 CC6/CC7, OWASP recommendations.
**Scope:** Config analysis + header/policy validation + integration detection.

### Level 2 — Advanced Threat Protection
**Purpose:** Enhanced security for environments handling sensitive data (PII, financial, healthcare).
**Audience:** Organizations with dedicated security teams, PCI DSS cardholder environments.
**Standard:** PCI DSS 4.0 full compliance, NIST SP 800-52 Rev. 2, OWASP full header set.
**Scope:** Config analysis + live TLS scanning + external integration validation.

### Level 3 — Zero Trust / Maximum Hardening
**Purpose:** Maximum security for government, military, financial core, and zero-trust architectures.
**Audience:** DISA STIG full compliance, FIPS 140-2 environments, zero-trust architectures.
**Standard:** Full DISA STIG, FIPS 140-2 cipher suites, architectural-level controls.
**Scope:** Full stack including mTLS, supply chain, HTTP smuggling defenses, service mesh patterns.

---

## 2. Current Baseline Issues

### 2.1 Check Duplications

| Duplicated Control | Checks Involved | Combined Weight | Should Be |
|---|---|---|---|
| DH Parameter Size >= 2048 | HAPR-TLS-007 + HAPR-GBL-005 | 4+4 = 8 | Single check, weight 4 |
| Stats Page Security | HAPR-ACL-005 + HAPR-LOG-003 + HAPR-INF-004 | 7+7+2 = 16 | Consolidate to 1-2 checks |
| Global/Frontend maxconn | HAPR-FRT-001 + HAPR-FRT-002 + HAPR-GBL-004 | 4+4+4 = 12 | Differentiate scope clearly |

**Impact:** A single `tune.ssl.default-dh-param 2048` directive improves score by 8 points instead
of the intended 4. A single `stats auth` line affects scoring in 3 categories (16 points total).

**Recommendation:**
- Remove HAPR-GBL-005 (duplicate of TLS-007)
- Consolidate stats checks: ACL-005 covers auth/password strength, move LOG-003's unique aspects
  (hide-version, admin ACL) into ACL-005, remove LOG-003 from logging category
- Differentiate maxconn checks: GBL-004 = global maxconn exists, FRT-001 = per-frontend maxconn
  exists, remove FRT-002 (redundant with FRT-001 + GBL-004)

### 2.2 Miscategorized Checks

| Check | Current Category | Should Be | Reason |
|---|---|---|---|
| HAPR-LOG-003 | logging | access | Stats page security is access control, not logging |
| HAPR-TLS-006 | tls | headers (or keep in TLS) | HSTS is an HTTP header, but TLS placement is defensible |

### 2.3 Mistiered Checks (Too Advanced for Baseline)

| Check | Current Tier | Recommended Tier | Reason |
|---|---|---|---|
| HAPR-FRT-004 (WAF Integration) | Baseline (medium/4) | Level 2 | Most deployments don't have WAF; penalizes standard configs |
| HAPR-FRT-005 (SQL Injection Rules) | Baseline (medium/4) | Level 2 | Proxy-level SQLi patterns are defense-in-depth, not baseline |
| HAPR-FRT-006 (XSS Protection Rules) | Baseline (medium/4) | Level 2 | Same as above; trivially bypassable at proxy level |
| HAPR-GBL-003 (DNS Resolver) | Baseline (low/2) | Level 1 | Many configs use static IPs; should return N/A not FAIL |

### 2.4 Severity Weight Adjustments

| Check | Current | Recommended | Reason |
|---|---|---|---|
| HAPR-TMO-004 (HTTP Request Timeout) | medium/4 | high/7 | Primary slowloris defense; critical for DoS protection |
| HAPR-HDR-002 (CSP) | medium/4 | medium/4 (keep) | CSP is important but primarily an application concern at proxy level |

### 2.5 Implementation Gaps in Existing Checks

These checks exist but their implementations are too shallow:

| Check | Gap | Recommended Fix |
|---|---|---|
| HAPR-TLS-006 (HSTS) | Does not validate max-age value (max-age=0 passes) | Validate max-age >= 31536000 |
| HAPR-HDR-001 to HDR-005 | Presence-only; no value validation | Add value validation (e.g., nosniff for X-Content-Type-Options) |
| HAPR-ACL-001 | Single ACL anywhere = PASS | Check per-frontend ACL coverage |
| HAPR-INF-003 | Requires removing 2+ of 6 headers; penalizes clean configs | Return PASS if at least X-Powered-By or Server is handled |
| HAPR-LOG-004 | Accepts `emerg` as good log level | Only accept info/notice/warning as PASS |
| HAPR-REQ-002 | Uses tune.maxrewrite as URL length indicator (misleading) | Only count actual URL length ACLs |
| HAPR-REQ-004 | tune.bufsize satisfies check (overly broad) | Only count tune.http.maxhdr specifically |

---

## 3. Gap Analysis: Missing Checks

### 3.1 Missing from Baseline (Should Be Added Now)

These are fundamental security practices missing from the current baseline that every deployment needs:

| Proposed ID | Title | Category | Severity | Source |
|---|---|---|---|---|
| HAPR-PROC-005 | Daemon Mode Configured | process | low/2 | SOCFortress Guide, HAProxy docs |
| HAPR-TMO-006 | HTTP Keep-Alive Timeout Set | timeouts | medium/4 | HAProxy docs, connection reuse security |
| HAPR-LOG-006 | Dontlognull Option Enabled | logging | low/2 | HAProxy best practices, log noise reduction |

### 3.2 Missing from Level 1 (New Checks)

Standard production hardening checks not currently covered:

| Proposed ID | Title | Category | Severity | Source |
|---|---|---|---|---|
| HAPR-TLS-008 | TLS Session Tickets Disabled | tls | medium/4 | BetterCrypto, Mozilla, DISA STIG |
| HAPR-TLS-009 | SSL Default Server Options Set | tls | medium/4 | Mozilla SSL Generator |
| HAPR-ACL-007 | Source IP Restrictions on Admin Interfaces | access | high/7 | DISA STIG, PCI DSS |
| HAPR-HDR-007 | Cross-Origin-Opener-Policy Set | headers | low/2 | OWASP Secure Headers |
| HAPR-HDR-008 | Cross-Origin-Embedder-Policy Set | headers | low/2 | OWASP Secure Headers |
| HAPR-REQ-005 | HTTP Request Smuggling Prevention | request | high/7 | CVE-2021-40346, HAProxy HTX |
| HAPR-FRT-007 | X-Forwarded-For Configuration | frontend | medium/4 | HAProxy docs, Airship Guide |
| HAPR-FRT-008 | Bind Address Restrictions | frontend | medium/4 | NIST 800-123, DISA STIG |
| HAPR-GBL-006 | Hard-Stop-After Configured | global_defaults | low/2 | HAProxy docs, graceful shutdown |
| HAPR-GBL-007 | Nbproc Not Used (Deprecated) | global_defaults | medium/4 | HAProxy 2.5+ deprecation |
| HAPR-BKD-006 | Backend SSL Certificate Verification | backend | high/7 | PCI DSS, NIST 800-52 |
| HAPR-LOG-007 | Remote Syslog Configured | logging | medium/4 | PCI DSS Req 10, SOC 2 CC7.2 |
| HAPR-INF-005 | X-Forwarded-For Spoofing Prevention | disclosure | medium/4 | Airship Guide |
| HAPR-PROC-006 | Config File Permissions Restricted | process | high/7 | NIST 800-123, DISA STIG |

### 3.3 Missing from Level 2 (New Checks)

Advanced checks for sensitive environments:

| Proposed ID | Title | Category | Severity | Source |
|---|---|---|---|---|
| HAPR-TLS-010 | OCSP Stapling Configured | tls | medium/4 | NIST 800-52, PCI DSS 4.0.1 |
| HAPR-TLS-011 | FIPS-Approved Cipher Suites Only | tls | high/7 | DISA STIG, FIPS 140-2 |
| HAPR-HDR-009 | Cross-Origin-Resource-Policy Set | headers | low/2 | OWASP Secure Headers |
| HAPR-SCAN-007 | Certificate Key Size Adequate | tls_live | medium/4 | NIST 800-52 (RSA >= 2048, ECDSA >= 256) |
| HAPR-SCAN-008 | Certificate Expiry Warning (30 days) | tls_live | medium/4 | PCI DSS 4.0.1, operational best practice |
| HAPR-SCAN-009 | Certificate Hostname Match | tls_live | high/7 | NIST 800-52, browser trust |
| HAPR-SPOE-001 | SPOE WAF Filter Declared | frontend | medium/4 | PCI DSS 4.0 Req 6.4.2 |
| HAPR-SPOE-002 | SPOE Agent Timeout Configuration | frontend | low/2 | HAProxy SPOE best practices |
| HAPR-LUA-001 | Lua Memory Limit Set | global_defaults | medium/4 | HAProxy docs (tune.lua.maxmem) |
| HAPR-LUA-002 | Lua Forced Yield Configured | global_defaults | low/2 | HAProxy docs (tune.lua.forced-yield) |
| HAPR-PEER-001 | Peer Communication Encrypted | global_defaults | medium/4 | HAProxy Peers TLS |
| HAPR-CACHE-001 | Cache Security Controls | backend | medium/4 | Cache poisoning prevention |
| HAPR-COMP-001 | Compression BREACH Risk | frontend | medium/4 | CVE-2013-3587 |
| HAPR-PROXY-001 | PROXY Protocol Source Restricted | frontend | high/7 | IP spoofing prevention |

### 3.4 Missing from Level 3 (New Checks)

Maximum hardening for high-security environments:

| Proposed ID | Title | Category | Severity | Source |
|---|---|---|---|---|
| HAPR-MTLS-001 | Mutual TLS Client Verification | tls | high/7 | Zero-trust, DISA STIG |
| HAPR-MTLS-002 | Client Certificate CRL Configured | tls | medium/4 | Certificate lifecycle |
| HAPR-JWT-001 | JWT Signature Verification Enforced | access | high/7 | API gateway security |
| HAPR-JWT-002 | JWT Algorithm Restriction (No alg:none) | access | critical/10 | OWASP JWT security |
| HAPR-H2-001 | HTTP/2 Stream Limits Configured | request | medium/4 | DoS prevention |
| HAPR-H2-002 | H2C Smuggling Prevention | request | high/7 | BishopFox h2csmuggler |
| HAPR-BOT-001 | Bot Detection Patterns Configured | access | medium/4 | Bot management |
| HAPR-IPREP-001 | IP Reputation Integration Detected | access | medium/4 | CrowdSec/threat intel |
| HAPR-API-001 | API Authentication Enforcement | access | high/7 | API gateway patterns |
| HAPR-API-002 | Per-API Rate Limiting | access | medium/4 | API abuse prevention |

---

## 4. Reclassification of Existing Checks into Tiers

### Baseline (14 checks) — Every deployment must pass

| Check ID | Title | Current Severity |
|---|---|---|
| HAPR-PROC-001 | Chroot Enabled | high/7 |
| HAPR-PROC-002 | Runs as Non-Root User | critical/10 |
| HAPR-TLS-001 | Minimum TLS Version 1.2 | critical/10 |
| HAPR-TLS-002 | No Weak Cipher Strings | critical/10 |
| HAPR-TLS-003 | SSL Default Bind Options Set | high/7 |
| HAPR-TMO-001 | Client Timeout Set | high/7 |
| HAPR-TMO-002 | Server Timeout Set | high/7 |
| HAPR-TMO-003 | Connect Timeout Set | high/7 |
| HAPR-TMO-004 | HTTP Request Timeout Set | **high/7** (upgraded) |
| HAPR-LOG-001 | Log Directive Present | high/7 |
| HAPR-INF-001 | Server Header Removed | high/7 |
| HAPR-GBL-001 | Secure Defaults Section Exists | high/7 |
| HAPR-GBL-004 | Global Maxconn Set | medium/4 |
| HAPR-CVE-001 | No Critical CVEs | critical/10 |

### Level 1 (28 checks) — Standard production security

| Check ID | Title | Current Severity |
|---|---|---|
| HAPR-PROC-003 | Group Directive Set | medium/4 |
| HAPR-TLS-004 | SSL Default Bind Ciphers Set | high/7 |
| HAPR-TLS-005 | TLS 1.3 Ciphersuites Configured | medium/4 |
| HAPR-TLS-006 | HSTS Header Configured | high/7 |
| HAPR-TLS-007 | DH Parameter Size >= 2048 | medium/4 |
| HAPR-ACL-001 | ACLs Defined in Frontends | medium/4 |
| HAPR-ACL-003 | Rate Limiting Configured | high/7 |
| HAPR-ACL-004 | Stick Tables for Connection Tracking | medium/4 |
| HAPR-ACL-005 | Stats Access Restricted (consolidated) | high/7 |
| HAPR-ACL-006 | Userlist Passwords Hashed | high/7 |
| HAPR-HDR-001 | X-Frame-Options Header Set | medium/4 |
| HAPR-HDR-002 | Content-Security-Policy Header Set | medium/4 |
| HAPR-HDR-003 | X-Content-Type-Options Header Set | medium/4 |
| HAPR-HDR-004 | Referrer-Policy Header Set | low/2 |
| HAPR-REQ-001 | Maximum Request Body Size Limited | medium/4 |
| HAPR-REQ-003 | HTTP Method Filtering | medium/4 |
| HAPR-LOG-002 | Detailed Log Format Configured | medium/4 |
| HAPR-LOG-005 | HTTP or TCP Log Option Enabled | medium/4 |
| HAPR-INF-002 | Custom Error Pages Configured | medium/4 |
| HAPR-INF-003 | Version Information Hidden | medium/4 |
| HAPR-TMO-005 | Timeout Values Are Reasonable | medium/4 |
| HAPR-BKD-001 | Health Checks Configured | high/7 |
| HAPR-BKD-004 | Cookie Attributes Set Securely | medium/4 |
| HAPR-FRT-001 | Connection Limits on Frontends | medium/4 |
| HAPR-FRT-003 | HTTP to HTTPS Redirect | high/7 |
| HAPR-GBL-002 | Stats Socket Permissions Restricted | high/7 |
| HAPR-INF-004 | Stats Page Version Hidden | low/2 |
| HAPR-LOG-004 | Appropriate Log Level | low/2 |

### Level 2 (18 checks) — Enhanced security for sensitive environments

| Check ID | Title | Current Severity |
|---|---|---|
| HAPR-PROC-004 | Ulimits Configured | low/2 |
| HAPR-ACL-002 | Admin Paths Restricted | high/7 |
| HAPR-HDR-005 | Permissions-Policy Header Set | low/2 |
| HAPR-HDR-006 | X-XSS-Protection Not Misconfigured | low/2 |
| HAPR-REQ-002 | URL Length Limits Configured | low/2 |
| HAPR-REQ-004 | Request Header Size Limits | low/2 |
| HAPR-BKD-002 | Connection Limits on Backend Servers | medium/4 |
| HAPR-BKD-003 | Backend SSL/TLS to Servers | medium/4 |
| HAPR-BKD-005 | Retry and Redispatch Configured | low/2 |
| HAPR-FRT-004 | WAF Integration Detected | medium/4 |
| HAPR-GBL-003 | DNS Resolver Configured | low/2 |
| HAPR-SCAN-001 | No Deprecated TLS Versions (Live) | critical/10 |
| HAPR-SCAN-002 | No Weak Ciphers Negotiated (Live) | critical/10 |
| HAPR-SCAN-003 | Valid Certificate Chain (Live) | high/7 |
| HAPR-SCAN-006 | Secure Renegotiation Supported (Live) | medium/4 |
| HAPR-FRT-002 | Global Maxconn Reflected in Frontends | medium/4 |
| HAPR-GBL-005 | **REMOVE** (duplicate of TLS-007) | — |
| HAPR-LOG-003 | **REMOVE** (consolidated into ACL-005) | — |

### Level 3 (6 existing + new checks) — Maximum hardening

| Check ID | Title | Current Severity |
|---|---|---|
| HAPR-FRT-005 | SQL Injection Protection Rules | medium/4 |
| HAPR-FRT-006 | XSS Protection Rules | medium/4 |
| HAPR-SCAN-004 | Certificate Not Expired (Live) | critical/10 |
| HAPR-SCAN-005 | No Known TLS Vulnerabilities (Live) | critical/10 |
| HAPR-CVE-002 | No High Severity CVEs | high/7 |
| HAPR-CVE-003 | HTTP Request Smuggling CVE-2021-40346 | critical/10 |

---

## 5. Scoring Model Recommendations

### Current Model Strengths
- Weighted scoring with PASS/PARTIAL/FAIL/N/A is sound
- Severity weights (critical=10, high=7, medium=4, low=2) are well-calibrated
- N/A exclusion correctly handles non-applicable checks
- Letter grades (A-F) provide clear communication

### Recommended Improvements

1. **Per-tier scoring**: Each tier should produce its own score and grade. A deployment scored
   against Level 2 should show: Baseline=A, Level 1=B, Level 2=C — not a single blended score.

2. **Category minimum thresholds**: Flag categories below 50% regardless of overall score.
   A config scoring 90% overall but 0% on TLS should not receive an A.

3. **Remove duplications before scoring**: Fix the 3 duplication issues identified above to
   prevent single directives from inflating scores.

4. **Weighted category importance**: Consider weighting categories differently. TLS and Process
   security are more critical than Referrer-Policy headers. Example weights:
   - Critical categories (1.5x): process, tls, access, timeouts, cve
   - Standard categories (1.0x): logging, disclosure, backend, frontend, global_defaults
   - Secondary categories (0.75x): headers, request

5. **Compliance mapping in reports**: Show which checks map to specific frameworks
   (PCI DSS, DISA STIG, SOC 2) so consultants can tailor reports to client compliance needs.

---

## 6. HAProxy Official Tutorial Coverage Analysis

Based on analysis of HAProxy's official configuration tutorials at
`haproxy.com/documentation/haproxy-configuration-tutorials/`, the tutorials cover:

### Well-Covered by Current Baseline
- SSL/TLS configuration (certificate management, cipher suites, protocol versions)
- Timeouts (client, server, connect, http-request)
- Health checks (HTTP, TCP, agent checks)
- ACLs and content switching
- Stats page configuration
- Logging and syslog
- Error pages

### Tutorial Topics Missing from Baseline
| Tutorial Topic | Gap | Recommended Action |
|---|---|---|
| OCSP Stapling | Not checked | Add to Level 2 (HAPR-TLS-010) |
| Map Files | Security of map file permissions not checked | Add to Level 2 |
| Circuit Breakers | Error-limit/on-error patterns not detected | Add to Level 1 |
| PROXY Protocol | accept-proxy trust boundary not checked | Add to Level 2 (HAPR-PROXY-001) |
| Performance Tuning (nbthread) | nbproc deprecation not flagged | Add to Level 1 (HAPR-GBL-007) |
| X-Forwarded-For | Header spoofing not detected | Add to Level 1 (HAPR-FRT-007) |
| Variables | insecure-password in env vars not flagged | Already covered by ACL-006 |
| HTTP/2 | Stream limits not checked | Add to Level 3 (HAPR-H2-001) |

---

## 7. Industry Standards Mapping

### Framework Coverage Matrix

| Framework | Baseline | Level 1 | Level 2 | Level 3 |
|---|---|---|---|---|
| **DISA STIG CAT I** | 4/4 (100%) | — | — | — |
| **DISA STIG CAT II** | 4/13 (31%) | 10/13 (77%) | 13/13 (100%) | — |
| **DISA STIG CAT III** | — | 2/3 (67%) | 3/3 (100%) | — |
| **PCI DSS 4.0 Mandatory** | 3/8 (38%) | 6/8 (75%) | 8/8 (100%) | — |
| **NIST 800-52 Rev. 2** | 2/5 (40%) | 4/5 (80%) | 5/5 (100%) | — |
| **OWASP Headers** | 0/10 (0%) | 5/10 (50%) | 8/10 (80%) | 10/10 (100%) |
| **SOC 2 CC6/CC7** | 2/7 (29%) | 5/7 (71%) | 7/7 (100%) | — |
| **Mozilla Intermediate** | Partial | Full | — | — |
| **Mozilla Modern** | — | — | — | Full |
| **FIPS 140-2** | — | — | Partial | Full |

### Key Compliance Gaps to Highlight in Reports
- **PCI DSS 4.0 Req 6.4.2**: WAF is mandatory for public web apps (effective March 2025).
  Currently only checked at baseline level; should be promoted to Level 2 requirement.
- **PCI DSS 4.0.1 Req 4.2.1.1**: Certificate validation + OCSP (effective April 2025).
  Not currently checked. Add OCSP stapling check at Level 2.
- **NIST SP 800-52**: TLS 1.3 support required since January 2024. Currently medium/4 check.

---

## 8. Implementation Roadmap

### Phase 1: Baseline Cleanup (Immediate)
1. Remove duplicate check HAPR-GBL-005
2. Consolidate stats checks (merge LOG-003 into ACL-005)
3. Remove redundant FRT-002
4. Upgrade TMO-004 severity to high/7
5. Fix GBL-003 to return N/A for static-IP configs
6. Update documentation to reflect 66 -> corrected check count
7. Add `tier` field to baseline YAML schema

### Phase 2: Implementation Quality (Next Sprint)
1. Add value validation to header checks (HDR-001 through HDR-005)
2. Fix HSTS max-age validation in TLS-006
3. Improve ACL-001 to check per-frontend coverage
4. Fix REQ-002 and REQ-004 false positive triggers
5. Fix LOG-004 to reject `emerg` as acceptable level

### Phase 3: New Check Development (Level 1)
1. Implement 14 new Level 1 checks identified in Section 3.2
2. Create `hapr-level1.yaml` extending baseline
3. Update engine to support tier-aware scoring

### Phase 4: Advanced Tiers (Level 2 + Level 3)
1. Implement Level 2 checks (SPOE, Lua, Peers, Cache, Compression, PROXY protocol)
2. Implement Level 3 checks (mTLS, JWT, H2, Bot, API Gateway)
3. Create `hapr-level2.yaml` and `hapr-level3.yaml`
4. Add compliance mapping to report output

---

## 9. File Structure Proposal

```
framework/
  hapr-baseline.yaml          # Tier: Baseline (cleaned up, ~14 checks)
  hapr-level1.yaml            # Tier: Level 1 (~42 checks, includes baseline)
  hapr-level2.yaml            # Tier: Level 2 (~32 checks, includes L1)
  hapr-level3.yaml            # Tier: Level 3 (~16 checks, includes L2)
  hapr-compliance-mapping.yaml # Maps check IDs to DISA STIG/PCI DSS/SOC 2/NIST
```

Or alternatively, a single YAML with a `tier` field per check:

```yaml
checks:
  - id: HAPR-PROC-002
    title: Runs as Non-Root User
    tier: baseline        # NEW FIELD
    category: process
    severity: critical
    weight: 10
    ...
```

**Recommendation:** Use the single-file approach with `tier` field. This is simpler to maintain,
avoids cross-file duplication, and the engine can filter by tier at runtime.

---

## Appendix A: Source References

- DISA STIG Web Server SRG: https://www.cyber.mil/stigs/
- NIST SP 800-52 Rev. 2: https://csrc.nist.gov/pubs/sp/800/52/r2/final
- NIST SP 800-123: https://csrc.nist.gov/pubs/sp/800/123/final
- OWASP Secure Headers: https://owasp.org/www-project-secure-headers/
- OWASP HTTP Headers Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
- PCI DSS 4.0: https://www.pcisecuritystandards.org/
- SOC 2 Trust Services Criteria: https://secureframe.com/hub/soc-2/controls
- Mozilla SSL Configuration Generator: https://ssl-config.mozilla.org/
- HAProxy Configuration Tutorials: https://www.haproxy.com/documentation/haproxy-configuration-tutorials/
- HAProxy Security Knowledge Base: https://www.haproxy.com/knowledge-base/security
- SOCFortress HAProxy Hardening Guide: https://socfortress.medium.com/haproxy-secure-deployment-hardening-guide-e03a6ba16a54
- BetterCrypto Applied Crypto Hardening: https://github.com/BetterCrypto/Applied-Crypto-Hardening
- Airship HAProxy Security Guide: https://airshipit.readthedocs.io/en/latest/security/haproxy.html

## Appendix B: Check Count Summary

| Tier | Existing (Reclassified) | New Checks | Total |
|---|---|---|---|
| Baseline | 14 | 3 | 17 |
| Level 1 | 28 | 14 | 42 |
| Level 2 | 16 | 14 | 30 |
| Level 3 | 6 | 10 | 16 |
| **Total Unique** | **64** (after removing 2 dupes) | **41** | **105** |

Note: Tiers are cumulative. A Level 2 assessment runs Baseline + Level 1 + Level 2 checks.
