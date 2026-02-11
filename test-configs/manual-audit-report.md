# Manual Security Audit Report -- HAProxy Configurations

**Auditor**: Senior Cybersecurity Professional (Independent Manual Review)
**Date**: 2026-02-11
**Scope**: 1 live server configuration + 10 GitHub-sourced configurations
**Methodology**: Manual line-by-line review against 13-category security baseline (65 checks)

---

## 1. Executive Summary

This report presents the findings of a manual security audit of HAProxy configurations, conducted independently of the HAPR automated audit tool. The purpose is to provide a human expert baseline for later comparison against the tool's output.

**Live Server Config (`live-server.cfg`)**: This configuration is deliberately a mix of good and bad practices. It demonstrates several strong security measures (HSTS, HTTP-to-HTTPS redirect, X-Frame-Options, Server header removal, reasonable timeouts, health checks) but contains significant weaknesses including TLS 1.0 acceptance, weak cipher suites (DES-CBC3-SHA, RC4-SHA), unauthenticated stats page with admin enabled, missing Content-Security-Policy header, no rate limiting, no chroot, no privilege dropping, and no request size limits. The overall risk posture is **HIGH** due to the combination of critical TLS weaknesses and exposed administrative interface.

**GitHub Configs**: The 10 real-world configurations vary widely. The most hardened are `akhilraj-haproxy-backend.cfg` and `ocp4-helpernode.cfg` (infrastructure configs with chroot, user/group, and logging). The weakest include `triton-moray.cfg` (no logging, missing timeouts, no chroot), `kubernetes-docker-packt.cfg` (minimal security), and `rabbitmq-lb.cfg` (unauthenticated stats page). Most GitHub configs lack HTTP security headers, TLS configuration, rate limiting, and request filtering -- which is partially expected for internal/infrastructure-purpose configs, but still represents missing defense-in-depth.

---

## 2. Live Server Config Audit (`live-server.cfg`)

**File**: `/home/snakep/hapr/test-configs/live-server.cfg`

### 2.1 Findings Table

| Finding ID | Category | Severity | Status | Title | Details | Remediation |
|-----------|----------|----------|--------|-------|---------|-------------|
| MAN-001 | Process Security | High | FAIL | No chroot configured | The global section has no `chroot` directive. If HAProxy is compromised, the attacker has access to the full filesystem. | Add `chroot /var/lib/haproxy` to the global section. |
| MAN-002 | Process Security | Critical | FAIL | No non-root user configured | Neither `user` nor `group` directives are present in the global section. HAProxy will run as whatever user starts the process (potentially root). | Add `user haproxy` and `group haproxy` to the global section. |
| MAN-003 | Process Security | Medium | FAIL | No group directive set | No `group` directive is present in the global section. | Add `group haproxy` to the global section. |
| MAN-004 | Process Security | Low | FAIL | No ulimits configured | No `ulimit-n` directive is set in the global section. Under heavy load, HAProxy could hit OS default file descriptor limits and drop connections. | Add `ulimit-n 65536` (or appropriate value) to the global section. |
| MAN-005 | TLS/SSL Configuration | Critical | FAIL | TLS 1.0 minimum version allowed | `ssl-default-bind-options ssl-min-ver TLSv1.0` explicitly allows TLS 1.0 and TLS 1.1, which are deprecated and have known vulnerabilities (BEAST, POODLE, Lucky13). | Change to `ssl-default-bind-options ssl-min-ver TLSv1.2` or add `no-sslv3 no-tlsv10 no-tlsv11`. |
| MAN-006 | TLS/SSL Configuration | Critical | FAIL | Weak cipher suites included | The cipher string includes `DES-CBC3-SHA` (3DES, vulnerable to Sweet32) and `RC4-SHA` (RC4 is broken with known biases). These ciphers can be exploited to decrypt traffic. | Remove `DES-CBC3-SHA` and `RC4-SHA` from `ssl-default-bind-ciphers`. Add explicit exclusions: `!3DES:!RC4`. |
| MAN-007 | TLS/SSL Configuration | High | PASS | SSL default bind options set | `ssl-default-bind-options` is present in the global section (though the values are insecure, the directive itself exists). | N/A (directive exists; fix the values per MAN-005). |
| MAN-008 | TLS/SSL Configuration | High | PASS | SSL default bind ciphers set | `ssl-default-bind-ciphers` is present in the global section (though it contains weak ciphers). | N/A (directive exists; fix the values per MAN-006). |
| MAN-009 | TLS/SSL Configuration | Medium | PASS | TLS 1.3 ciphersuites configured | `ssl-default-bind-ciphersuites` is explicitly set with strong TLS 1.3 ciphers (AES-128-GCM, AES-256-GCM, CHACHA20-POLY1305). | N/A |
| MAN-010 | TLS/SSL Configuration | High | PASS | HSTS header configured | `Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"` is set on ft_https. The max-age is 1 year, includeSubDomains and preload are enabled -- excellent configuration. | N/A |
| MAN-011 | TLS/SSL Configuration | Medium | PASS | DH parameter size at least 2048 bits | `tune.ssl.default-dh-param 2048` is set. Meets minimum requirements (2048-bit). Consider 4096 for higher assurance. | N/A (consider upgrading to 4096). |
| MAN-012 | Access Control | Medium | PASS | ACLs defined in frontends | ft_https has ACLs for `/api`, `/health`, and static paths. ft_http has an SSL redirect ACL. | N/A |
| MAN-013 | Access Control | High | FAIL | Admin paths not restricted | No ACL-based restriction on administrative paths (e.g., `/admin`, `/manager`). No source IP filtering is applied to any path. | Add ACLs to restrict admin paths: `acl admin_path path_beg /admin` with `http-request deny if admin_path !trusted_src`. |
| MAN-014 | Access Control | High | FAIL | No rate limiting configured | No stick-table, no `http_req_rate`, no `conn_rate`, and no `deny_status 429` rules anywhere in the config. The system is fully exposed to brute-force and DDoS attacks. | Implement stick-table based rate limiting: `stick-table type ip size 100k expire 30s store http_req_rate(10s)` with `http-request deny deny_status 429 if { sc_http_req_rate(0) gt 100 }`. |
| MAN-015 | Access Control | Medium | FAIL | No stick tables for connection tracking | No stick-table is configured in any frontend or backend. There is no mechanism for tracking per-client connection patterns or detecting abuse. | Add stick tables for connection and request rate tracking. |
| MAN-016 | Access Control | High | FAIL | Stats access not restricted -- unauthenticated stats with admin | The stats frontend (`ft_stats`) on port 8404 has `stats enable`, `stats admin if TRUE`, but `stats auth` is commented out. Anyone who can reach port 8404 can view all operational data AND administratively control servers (enable/disable/drain). This is a critical operational risk. | Uncomment `stats auth admin:STRONG_PASSWORD` and change `stats admin if TRUE` to `stats admin if LOCALHOST` or restrict by source IP ACL. |
| MAN-017 | HTTP Security Headers | Medium | PASS | X-Frame-Options header set | `X-Frame-Options "DENY"` is set on ft_https. Prevents clickjacking. | N/A |
| MAN-018 | HTTP Security Headers | Medium | FAIL | Content-Security-Policy header missing | No CSP header is configured on any frontend. This is a key defense against XSS attacks. | Add `http-response set-header Content-Security-Policy "default-src 'self'; script-src 'self'"` to ft_https. |
| MAN-019 | HTTP Security Headers | Medium | PASS | X-Content-Type-Options header set | `X-Content-Type-Options "nosniff"` is set on ft_https. Prevents MIME sniffing. | N/A |
| MAN-020 | HTTP Security Headers | Low | FAIL | Referrer-Policy header missing | No `Referrer-Policy` header is configured. Referrer URLs may leak sensitive path/query data to third parties. | Add `http-response set-header Referrer-Policy "strict-origin-when-cross-origin"` to ft_https. |
| MAN-021 | HTTP Security Headers | Low | FAIL | Permissions-Policy header missing | No `Permissions-Policy` header is configured. Browser features (camera, microphone, geolocation) are not restricted. | Add `http-response set-header Permissions-Policy "camera=(), microphone=(), geolocation=()"` to ft_https. |
| MAN-022 | HTTP Security Headers | Low | PASS | X-XSS-Protection not misconfigured | The `X-XSS-Protection` header is not set at all. Since it is deprecated and can introduce vulnerabilities, its absence is acceptable (PASS). CSP should be used instead. | N/A (though CSP is missing per MAN-018). |
| MAN-023 | Request Handling | Medium | FAIL | No maximum request body size limit | No `req.body_size` ACL or `tune.maxrewrite` directive is present. Attackers can send arbitrarily large payloads to exhaust resources. | Add `http-request deny deny_status 413 if { req.body_size gt 10485760 }` to ft_https. |
| MAN-024 | Request Handling | Low | FAIL | No URL length limits configured | No `url_len` ACL or `tune.http.maxuri` directive. Long URLs could be used for buffer overflow attempts or DoS. | Add `http-request deny deny_status 414 if { url_len gt 8192 }`. |
| MAN-025 | Request Handling | Medium | FAIL | No HTTP method filtering | No ACL restricts HTTP methods. TRACE, DELETE, PUT, OPTIONS, and other methods are all accepted. TRACE can be exploited for cross-site tracing attacks. | Add `acl valid_method method GET HEAD POST` and `http-request deny if !valid_method`. |
| MAN-026 | Request Handling | Low | FAIL | No request header size limits | No `tune.http.maxhdr` or `tune.bufsize` is configured. | Add `tune.http.maxhdr 101` and optionally `tune.bufsize 16384` to the global section. |
| MAN-027 | Logging & Monitoring | High | PASS | Log directive present | `log stdout format raw local0 info` is configured in global. Logging is active. | N/A |
| MAN-028 | Logging & Monitoring | Medium | FAIL | No detailed log format configured | No custom `log-format` is defined. Uses the default httplog format, which may lack fields needed for security analysis (custom timers, captured headers, etc.). | Add a detailed `log-format` string with security-relevant fields: client IP, request, status, timings, captured headers. |
| MAN-029 | Logging & Monitoring | High | FAIL | Stats page has no authentication | Stats is enabled on ft_stats but `stats auth` is commented out. Anyone can view operational metrics. | Add `stats auth admin:STRONG_PASSWORD`. |
| MAN-030 | Logging & Monitoring | Low | PASS | Appropriate log level | Log level is `info` which is appropriate for production -- captures sufficient detail without excessive debug noise. | N/A |
| MAN-031 | Logging & Monitoring | Medium | PASS | HTTP log option enabled | `option httplog` is set in defaults. All HTTP frontends will log request details. | N/A |
| MAN-032 | Information Disclosure | High | PASS | Server header removed | `http-response del-header Server` is set on ft_https. Backend server software versions are not leaked. | N/A |
| MAN-033 | Information Disclosure | Medium | PASS | Custom error pages configured | Error files are configured for 400, 403, 408, 500, 502, 503, 504 in defaults. | N/A |
| MAN-034 | Information Disclosure | Medium | PARTIAL | Version information partially hidden | The Server header is removed on ft_https, but there is no `http-response del-header X-Powered-By` or similar rules. Backend headers that leak version info may still pass through. | Add `http-response del-header X-Powered-By` and review other headers that may leak version info. |
| MAN-035 | Information Disclosure | Low | FAIL | Stats page version not hidden | The stats configuration does not include `stats hide-version`. The HAProxy version is visible on the stats page (which is also unauthenticated -- compounding the risk). | Add `stats hide-version` to the ft_stats section. |
| MAN-036 | Timeout Configuration | High | PASS | Client timeout set | `timeout client 30s` is set in defaults. Reasonable for most web applications. | N/A |
| MAN-037 | Timeout Configuration | High | PASS | Server timeout set | `timeout server 30s` is set in defaults. Reasonable. | N/A |
| MAN-038 | Timeout Configuration | High | PASS | Connect timeout set | `timeout connect 5s` is set in defaults. Appropriate for LAN/cloud backends. | N/A |
| MAN-039 | Timeout Configuration | Medium | PASS | HTTP request timeout set | `timeout http-request 10s` is set in defaults. Good defense against slowloris attacks. | N/A |
| MAN-040 | Timeout Configuration | Medium | PASS | Timeout values are reasonable | All timeouts are within recommended ranges: connect 5s, client 30s, server 30s, http-request 10s, http-keep-alive 10s, queue 30s. None are excessively long. | N/A |
| MAN-041 | Backend Security | High | PASS | Health checks configured | Backend `bk_app` has `option httpchk GET /` with `http-check expect status 200` and server has `check inter 5s fall 3 rise 2`. Good configuration. | N/A |
| MAN-042 | Backend Security | Medium | FAIL | No per-server connection limits | The backend server `app1` has no `maxconn` setting. Under heavy load, the single backend could be overwhelmed. | Add `maxconn 500` (or appropriate value) to the server line. |
| MAN-043 | Backend Security | Medium | FAIL | Backend connections use plain HTTP | Server `app1` connects to `echo:8080` with plain HTTP. No `ssl` keyword on the server line. Backend traffic is unencrypted and could be intercepted on the backend network. | Add `ssl verify required ca-file /path/to/ca-bundle.crt` to backend server connections (if backend supports TLS). |
| MAN-044 | Backend Security | Medium | FAIL | No cookie-based session persistence configured (or cookies lack security attributes) | No `cookie` directive is present in bk_app. If session persistence via cookies were added, it would need `httponly secure` attributes. Currently N/A since no cookies are used, but the absence means no affinity mechanism. | If sticky sessions are needed, add `cookie SERVERID insert indirect nocache httponly secure attr SameSite=Strict`. |
| MAN-045 | Backend Security | Low | PASS | Retry and redispatch configured | `retries 3` and `option redispatch` are set in defaults. Good for fault tolerance. | N/A |
| MAN-046 | Frontend Security | Medium | FAIL | No per-frontend connection limits | None of the three frontends (ft_stats, ft_https, ft_http) have `maxconn` set. They all inherit the global maxconn 4096, meaning a single frontend could consume all available connections. | Add `maxconn` to each frontend appropriate for its expected load. |
| MAN-047 | Frontend Security | Medium | FAIL | No explicit maxconn on frontends | Same as MAN-046 -- no frontend-level maxconn overrides the global setting. | Add per-frontend maxconn values. |
| MAN-048 | Frontend Security | High | PASS | HTTP to HTTPS redirect present | ft_http on port 8080 has `http-request redirect scheme https code 301 unless { ssl_fc }`. All plain HTTP traffic is redirected to HTTPS. | N/A |
| MAN-049 | Frontend Security | Medium | FAIL | No WAF integration | No `filter spoe` or ModSecurity integration is detected. HAProxy has no deep packet inspection capability. | Integrate a WAF via SPOE: `filter spoe engine modsecurity config /etc/haproxy/spoe-modsecurity.conf`. |
| MAN-050 | Frontend Security | Medium | FAIL | No SQL injection protection rules | No ACL rules check for SQL injection patterns in URLs or parameters. | Add `acl sqli_detect url_sub -i select union insert drop update delete` with `http-request deny if sqli_detect`. |
| MAN-051 | Frontend Security | Medium | FAIL | No XSS protection rules | No ACL rules check for cross-site scripting patterns. | Add `acl xss_detect url_sub -i <script javascript: onerror onload` with `http-request deny if xss_detect`. |
| MAN-052 | Global & Defaults | High | PASS | Secure defaults section exists | The defaults section contains mode, log, httplog, forwardfor, http-server-close, all core timeouts, retries, redispatch, and error files. Well-configured. | N/A |
| MAN-053 | Global & Defaults | High | PARTIAL | Stats socket permissions partially restricted | `stats socket /tmp/haproxy.sock mode 660 level admin` -- mode 660 is acceptable (owner and group read/write), but the socket is in /tmp which is world-accessible. No explicit user/group ownership is set on the socket. Level admin provides full control. | Move socket to a restricted directory (e.g., `/var/run/haproxy/`) and add explicit user/group: `stats socket /var/run/haproxy/admin.sock mode 660 level admin user haproxy group haproxy`. |
| MAN-054 | Global & Defaults | Low | FAIL | No DNS resolver configured | No `resolvers` section exists. DNS resolution depends on system resolver. | Add a `resolvers` section with trusted nameservers if backends use hostnames. |
| MAN-055 | Global & Defaults | Medium | PASS | Global maxconn set | `maxconn 4096` is set in the global section. | N/A (consider increasing for production workloads). |
| MAN-056 | Global & Defaults | Medium | PASS | Default DH parameter size set | `tune.ssl.default-dh-param 2048` is explicitly set. | N/A |
| MAN-057 | Live TLS Scan | Critical | EXPECTED FAIL | Deprecated TLS versions likely accepted | Configuration explicitly allows TLS 1.0 (`ssl-min-ver TLSv1.0`). A live scan would confirm TLS 1.0 and TLS 1.1 connections are accepted. | Fix config per MAN-005. |
| MAN-058 | Live TLS Scan | Critical | EXPECTED FAIL | Weak ciphers likely negotiable | DES-CBC3-SHA and RC4-SHA are in the cipher list. A live scan would confirm these can be negotiated. | Fix config per MAN-006. |
| MAN-059 | Live TLS Scan | High | UNKNOWN | Certificate chain validity unknown | The cert file is `/etc/haproxy/certs/haproxy-test.pem`. Being a test cert, it is likely self-signed with an incomplete chain. A live scan would verify. | Ensure the PEM file contains the full certificate chain. |
| MAN-060 | Live TLS Scan | Critical | UNKNOWN | Certificate expiry unknown | Without live scanning, we cannot determine if the test certificate is expired. Test certificates are often short-lived. | Implement automated certificate renewal monitoring. |
| MAN-061 | Live TLS Scan | Critical | UNKNOWN | Known TLS vulnerabilities unknown | Requires live scan with sslyze to check for Heartbleed, ROBOT, CCS Injection. | Run `sslyze --regular <host>:8443` to verify. |
| MAN-062 | Live TLS Scan | Medium | UNKNOWN | Secure renegotiation support unknown | Requires live scan to determine. | Run a live TLS scan to verify. |
| MAN-063 | CVE/Version | Critical | UNKNOWN | HAProxy version unknown -- CVE status undetermined | The config file does not specify an HAProxy version. Without knowing the version, we cannot assess CVE exposure. The configuration references HAProxy 2.x features (`ssl-min-ver`), suggesting version 2.0+. | Determine the running HAProxy version and check against NVD for known CVEs. Ensure version is patched against CVE-2021-40346 (request smuggling). |
| MAN-064 | CVE/Version | Critical | UNKNOWN | HTTP request smuggling CVE-2021-40346 status unknown | Cannot determine if affected without knowing the exact HAProxy version. No mitigation rule (`req.hdr_cnt(content-length) gt 1` denial) is present. | Add `http-request deny if { req.hdr_cnt(content-length) gt 1 }` as a defense-in-depth measure and verify the HAProxy version is patched. |
| MAN-065 | CVE/Version | High | UNKNOWN | High severity CVE status unknown | Cannot assess without version information. | Determine and document the running version. |

### 2.2 Live Server Summary Statistics

| Status | Count |
|--------|-------|
| PASS | 24 |
| FAIL | 30 |
| PARTIAL | 2 |
| UNKNOWN (Live/CVE) | 9 |
| **Total** | **65** |

| Severity | FAIL Count |
|----------|-----------|
| Critical | 5 (known) + 4 (unknown) |
| High | 6 |
| Medium | 14 |
| Low | 5 |

---

## 3. GitHub Configs Audit

### 3.1 akhilraj-haproxy-backend.cfg

**File**: `/home/snakep/hapr/test-configs/github/akhilraj-haproxy-backend.cfg`
**Purpose**: Multi-service HTTP reverse proxy (git, jenkins, maven, nagios)
**Overall Risk**: MEDIUM

**Strengths**:
- Chroot enabled (`/var/lib/haproxy`)
- User/group set (`haproxy`/`haproxy`)
- Daemon mode enabled
- Stats socket with restricted permissions (`mode 660 level admin`)
- Logging configured (two log directives)
- Stats page has authentication (`stats auth admin:admin`)
- SSL default bind options set (`no-sslv3`)
- SSL default bind ciphers configured
- Error files configured
- httplog enabled
- Health checks on all backend servers

**Weaknesses**:

| Finding ID | Severity | Status | Title | Details |
|-----------|----------|--------|-------|---------|
| GH01-001 | Critical | FAIL | Weak cipher suites (3DES included) | Cipher string includes `ECDH+3DES:DH+3DES:RSA+3DES` -- 3DES is vulnerable to Sweet32 attack. |
| GH01-002 | High | FAIL | TLS 1.0/1.1 not fully disabled | `no-sslv3` only disables SSLv3; TLS 1.0 and 1.1 remain allowed. |
| GH01-003 | High | FAIL | Stats credentials are trivial | `stats auth admin:admin` -- extremely weak default credentials. |
| GH01-004 | High | FAIL | No HSTS header | No Strict-Transport-Security header configured. |
| GH01-005 | High | FAIL | No HTTP to HTTPS redirect | Frontend binds on port 80 only with no TLS or redirect. All traffic is unencrypted. |
| GH01-006 | High | FAIL | No rate limiting | No stick-tables or rate limiting mechanisms. |
| GH01-007 | Medium | FAIL | No HTTP security headers | No X-Frame-Options, CSP, X-Content-Type-Options, Referrer-Policy, or Permissions-Policy. |
| GH01-008 | Medium | FAIL | No request size/method filtering | No body size limits, URL length limits, or method filtering. |
| GH01-009 | Medium | FAIL | No per-server connection limits | Backend servers have no `maxconn` settings. |
| GH01-010 | Medium | FAIL | No backend TLS | All backend connections are plain HTTP. |
| GH01-011 | Low | FAIL | No ulimits configured | No `ulimit-n` directive. |
| GH01-012 | Medium | FAIL | No http-request timeout | Missing `timeout http-request` leaves the system vulnerable to slowloris. |
| GH01-013 | Low | FAIL | Stats page version not hidden | No `stats hide-version`. |
| GH01-014 | High | FAIL | Server header not removed | No `http-response del-header Server`. |
| GH01-015 | Low | FAIL | No DH param size set | No `tune.ssl.default-dh-param`. HAProxy defaults to 1024-bit. |

---

### 3.2 bbossgroups-tcp.cfg

**File**: `/home/snakep/hapr/test-configs/github/bbossgroups-tcp.cfg`
**Purpose**: TCP load balancer (likely for an application cluster)
**Overall Risk**: MEDIUM-HIGH

**Strengths**:
- Chroot enabled (`/usr/local/haproxy`)
- Daemon mode
- Global maxconn set (4000)
- Stats socket present
- Good timeout configuration (all timeouts set, http-request at 10s)
- Retries and redispatch configured
- tcplog enabled
- Stats page has authentication (`stats auth admin:admin`)
- Stats page hides version (`stats hide-version`)
- Health checks on servers with proper inter/rise/fall tuning

**Weaknesses**:

| Finding ID | Severity | Status | Title | Details |
|-----------|----------|--------|-------|---------|
| GH02-001 | Critical | FAIL | No user/group configured | No `user` or `group` directive -- runs as whatever user starts it. |
| GH02-002 | High | FAIL | Stats admin enabled unconditionally | `stats admin if TRUE` allows anyone authenticated to admin the servers. Should be restricted to LOCALHOST or specific IPs. |
| GH02-003 | High | FAIL | Weak stats credentials | `stats auth admin:admin` is trivially guessable. |
| GH02-004 | High | FAIL | Stats socket has no permissions set | `stats socket /usr/local/haproxy/stats` has no `mode` restriction -- defaults to 777 (world-accessible). |
| GH02-005 | Medium | FAIL | No TLS configuration | No SSL/TLS is configured. All traffic is unencrypted (TCP mode). |
| GH02-006 | Medium | FAIL | No rate limiting | No stick-tables or connection rate tracking. |
| GH02-007 | Low | FAIL | No ulimits configured | No `ulimit-n` directive. |

---

### 3.3 haproxy-acme-validation.cfg

**File**: `/home/snakep/hapr/test-configs/github/haproxy-acme-validation.cfg`
**Purpose**: HTTPS frontend with ACME/Let's Encrypt certificate validation
**Overall Risk**: HIGH

**Strengths**:
- Chroot enabled (`/var/lib/haproxy`)
- User/group set (`haproxy`/`haproxy`)
- Daemon mode
- Logging configured
- ACME HTTP-01 challenge handling via Lua
- TLS frontend on port 443

**Weaknesses**:

| Finding ID | Severity | Status | Title | Details |
|-----------|----------|--------|-------|---------|
| GH03-001 | Critical | FAIL | No TLS hardening | No `ssl-default-bind-options`, no `ssl-default-bind-ciphers`, no minimum TLS version. Uses OpenSSL defaults which may include weak protocols and ciphers. |
| GH03-002 | High | FAIL | No HSTS header | No Strict-Transport-Security configured. |
| GH03-003 | High | FAIL | No HTTP to HTTPS redirect | Port 80 frontend serves ACME challenges but does not redirect other traffic to HTTPS. |
| GH03-004 | High | FAIL | No rate limiting | No stick-tables or rate limiting. |
| GH03-005 | Medium | FAIL | No HTTP security headers | No X-Frame-Options, CSP, X-Content-Type-Options, etc. |
| GH03-006 | Medium | FAIL | No http-request timeout | Missing `timeout http-request` -- vulnerable to slowloris. |
| GH03-007 | Medium | FAIL | Backend server has no health check | `server server1 127.0.0.1:8002` has no `check` keyword. |
| GH03-008 | Medium | FAIL | No custom error pages | No `errorfile` directives. |
| GH03-009 | Medium | FAIL | No global maxconn | No `maxconn` in global section. |
| GH03-010 | High | FAIL | Server header not removed | No `http-response del-header Server`. |
| GH03-011 | Low | FAIL | No DH param size set | No `tune.ssl.default-dh-param`. |
| GH03-012 | Low | FAIL | No ulimits configured | No `ulimit-n` directive. |
| GH03-013 | High | FAIL | No stats socket | No stats socket for runtime monitoring/management. |

---

### 3.4 jenkins-ha.cfg

**File**: `/home/snakep/hapr/test-configs/github/jenkins-ha.cfg`
**Purpose**: HA load balancer for Jenkins (Web + JNLP agent connections)
**Overall Risk**: MEDIUM

**Strengths**:
- Chroot enabled (`/var/lib/haproxy`)
- User/group set (`haproxy`/`haproxy`)
- Daemon mode
- Good timeout configuration (all core timeouts set)
- Retries, redispatch, maxconn in defaults
- Stick-tables for session persistence (type ip size 1)
- Health checks on backend servers with backup server configuration
- TCP and HTTP modes properly separated
- JNLP frontend has extended client/server timeouts (15m) -- appropriate for long-lived agent connections

**Weaknesses**:

| Finding ID | Severity | Status | Title | Details |
|-----------|----------|--------|-------|---------|
| GH04-001 | High | FAIL | No TLS termination | No SSL/TLS configured on any frontend. Jenkins web UI traffic is unencrypted. |
| GH04-002 | High | FAIL | No HSTS or security headers | No HTTP security headers of any kind. |
| GH04-003 | High | FAIL | No rate limiting for abuse prevention | No rate limiting on any frontend. |
| GH04-004 | Medium | FAIL | No logging (httplog missing in defaults) | `option httplog` not present in defaults; `log global` is set but without httplog the format is minimal. |
| GH04-005 | Medium | FAIL | No error pages configured | No `errorfile` directives. |
| GH04-006 | Medium | FAIL | No server header removal | No information disclosure protection. |
| GH04-007 | High | FAIL | No stats socket | No runtime monitoring/management socket. |
| GH04-008 | Low | FAIL | No ulimits | No `ulimit-n`. |
| GH04-009 | Medium | FAIL | No global maxconn | No `maxconn` in global section. |

---

### 3.5 kubernetes-docker-packt.cfg

**File**: `/home/snakep/hapr/test-configs/github/kubernetes-docker-packt.cfg`
**Purpose**: Kubernetes ingress TCP/HTTP load balancer
**Overall Risk**: HIGH

**Strengths**:
- Logging configured
- Health checks on backend workers (`option httpchk GET /healthz`)
- Daemon mode

**Weaknesses**:

| Finding ID | Severity | Status | Title | Details |
|-----------|----------|--------|-------|---------|
| GH05-001 | Critical | FAIL | No user/group configured | No privilege dropping. |
| GH05-002 | High | FAIL | No chroot | No filesystem isolation. |
| GH05-003 | High | FAIL | No TLS termination | TCP passthrough on port 443 -- TLS is handled by backend, but HAProxy has no visibility into the traffic. |
| GH05-004 | Medium | FAIL | No http-request timeout | Missing from defaults. |
| GH05-005 | Medium | FAIL | No error pages | No `errorfile` directives. |
| GH05-006 | Medium | FAIL | No global maxconn | No connection limits anywhere. |
| GH05-007 | Medium | FAIL | No retries/redispatch | No retry logic for failed connections. |
| GH05-008 | Low | FAIL | No httplog/tcplog in defaults | No detailed logging option. |
| GH05-009 | High | FAIL | No stats socket | No runtime management capability. |
| GH05-010 | Low | FAIL | No ulimits | No file descriptor limits. |

**Note**: As a Kubernetes ingress LB, TCP passthrough is an acceptable pattern. TLS is terminated at the ingress controller. However, the missing process hardening and operational controls are still concerns.

---

### 3.6 ocp4-helpernode.cfg

**File**: `/home/snakep/hapr/test-configs/github/ocp4-helpernode.cfg`
**Purpose**: OpenShift 4 helper node -- load balances API server, machine config, and ingress traffic
**Overall Risk**: MEDIUM

**Strengths**:
- Chroot enabled (`/var/lib/haproxy`)
- User/group set (`haproxy`/`haproxy`)
- Daemon mode
- Global maxconn (4000), defaults maxconn (3000)
- Comprehensive timeout configuration (all timeouts present)
- Stats page with health monitoring URI
- Logging configured
- forwardfor, redispatch, retries all set
- httplog option in defaults
- Health checks with `check-ssl` and `verify none` for API server (appropriate for OCP internal certs)
- Template-based dynamic configuration for scaling

**Weaknesses**:

| Finding ID | Severity | Status | Title | Details |
|-----------|----------|--------|-------|---------|
| GH06-001 | High | FAIL | Stats page has no authentication | `listen stats` on port 9000 with `stats enable` but no `stats auth`. Exposes operational data to anyone on the network. |
| GH06-002 | High | FAIL | No rate limiting | No stick-tables for abuse prevention. |
| GH06-003 | Medium | FAIL | Excessively long client/server timeouts | `timeout client 4h` and `timeout server 4h` are 4 hours. These extremely long timeouts negate slowloris protection and waste resources. While OpenShift may need long-lived connections, 4 hours is excessive. |
| GH06-004 | Medium | FAIL | No HTTP security headers | No security headers on any frontend. |
| GH06-005 | Medium | FAIL | No custom error pages | No `errorfile` directives. |
| GH06-006 | Medium | FAIL | Backend uses `verify none` for SSL | `verify none` skips certificate verification, making connections vulnerable to MITM attacks. This is common in OCP deployments with self-signed certs but is still a risk. |
| GH06-007 | Low | FAIL | Stats version not hidden | No `stats hide-version`. |
| GH06-008 | Low | FAIL | No ulimits | No `ulimit-n`. |
| GH06-009 | High | FAIL | Stats socket permissions not restricted | `stats socket /var/lib/haproxy/stats` has no `mode` specified. |

**Note**: This is a Jinja2 template for infrastructure deployment. Many findings are typical for OpenShift helper nodes. The 4-hour timeouts and `verify none` are contextually common but still represent risk.

---

### 3.7 rabbitmq-lb.cfg

**File**: `/home/snakep/hapr/test-configs/github/rabbitmq-lb.cfg`
**Purpose**: Local RabbitMQ load balancer (SLB Warren pattern)
**Overall Risk**: MEDIUM-HIGH

**Strengths**:
- Logging configured
- Daemon mode
- Stats socket with uid and mode restrictions
- Good defaults with all core timeouts
- Retries and redispatch
- tcplog enabled
- Health checks with inter/rise/fall on servers
- Active/backup server pattern for RabbitMQ HA
- Listening on localhost (127.0.0.1:5680) -- good network restriction

**Weaknesses**:

| Finding ID | Severity | Status | Title | Details |
|-----------|----------|--------|-------|---------|
| GH07-001 | Critical | FAIL | No user/group configured | No privilege dropping directives. |
| GH07-002 | High | FAIL | No chroot | No filesystem isolation. |
| GH07-003 | High | FAIL | Stats page has no authentication | `listen private_monitoring :8101` with stats but no `stats auth`. Despite the name "private_monitoring", it binds to all interfaces (`:8101`). |
| GH07-004 | Low | FAIL | Stats version not hidden | No `stats hide-version`. |
| GH07-005 | Medium | FAIL | No error pages | No `errorfile` directives. |
| GH07-006 | Low | FAIL | No ulimits | No `ulimit-n`. |
| GH07-007 | Medium | FAIL | Stats socket in /tmp | Socket at `/tmp/haproxy_2.socket` is in a world-accessible directory. |

---

### 3.8 rpm-haproxy.cfg

**File**: `/home/snakep/hapr/test-configs/github/rpm-haproxy.cfg`
**Purpose**: Sample DMZ web application proxy with static/dynamic backend separation
**Overall Risk**: MEDIUM

**Strengths**:
- Chroot enabled (`/var/empty`)
- User/group set (`haproxy`/`haproxy`)
- Daemon mode
- Logging configured
- Stats socket with tight permissions (`mode 600 level admin`)
- Global maxconn (10000), frontend maxconn (8000)
- httplog, dontlognull enabled
- Health checks on all backend servers
- Per-server connection limits (maxconn 500)
- Cookie-based session persistence (`insert indirect nocache`)
- fullconn tuning for dynamic server weighting
- Good timeout configuration
- Retries and redispatch
- monitor-uri for health monitoring
- ACL-based routing (host header, path)

**Weaknesses**:

| Finding ID | Severity | Status | Title | Details |
|-----------|----------|--------|-------|---------|
| GH08-001 | High | FAIL | No TLS termination | HTTPS bind is commented out (`#bind *:443 ssl crt /etc/haproxy/haproxy.pem`). All traffic is plain HTTP. |
| GH08-002 | High | FAIL | Stats page at predictable path with no auth | `stats uri /admin/stats` on the public frontend with no authentication. Exposes operational data through the main web frontend. |
| GH08-003 | High | FAIL | No rate limiting | No stick-tables or abuse prevention. |
| GH08-004 | Medium | FAIL | No HTTP security headers | No security headers configured. |
| GH08-005 | Medium | FAIL | Server header not removed | No `http-response del-header Server`. |
| GH08-006 | Medium | FAIL | Cookie not secure | `cookie DYNSRV insert indirect nocache` -- missing `httponly`, `secure`, and `SameSite` attributes. Cookies can be stolen via XSS or sent over plain HTTP. |
| GH08-007 | Medium | FAIL | No error pages | No `errorfile` directives. |
| GH08-008 | Medium | FAIL | No http-request timeout in defaults | Frontend has `timeout client 30s` but no `timeout http-request` for slowloris protection. |
| GH08-009 | Low | FAIL | No ulimits | No `ulimit-n`. |
| GH08-010 | Low | FAIL | No DH param size | No `tune.ssl.default-dh-param`. |

---

### 3.9 severalnines-db-ha.cfg

**File**: `/home/snakep/hapr/test-configs/github/severalnines-db-ha.cfg`
**Purpose**: Database HA proxy (Galera/MySQL clustering)
**Overall Risk**: MEDIUM

**Strengths**:
- User/group set (`nobody`/`nobody`)
- Daemon mode
- Stats socket with restrictive permissions (`mode 600 level admin`, user/group specified)
- Global maxconn (40000), defaults maxconn (40000)
- Good timeout configuration
- Retries and redispatch
- `spread-checks 3` for staggered health checks
- `tcp-smart-accept` and `tcp-smart-connect` for performance
- Userlist-based authentication with admin group separation for stats
- Stats page requires authentication (`http_auth` ACL)
- Stats admin restricted to admin group only
- Separation of read-only and admin access on stats page

**Weaknesses**:

| Finding ID | Severity | Status | Title | Details |
|-----------|----------|--------|-------|---------|
| GH09-001 | High | FAIL | No chroot | No filesystem isolation despite handling database traffic. |
| GH09-002 | Critical | FAIL | Passwords stored with `insecure-password` | `user ADMIN_USER insecure-password ADMIN_PASSWORD` and `user stats insecure-password PASSWORD` -- passwords are stored in plaintext in the config file. While `insecure-password` is an HAProxy keyword (vs `password` for encrypted), using plaintext passwords is a risk if the config file is accessible. |
| GH09-003 | High | FAIL | Stats admin page binds to 0.0.0.0 | `listen admin_page 0.0.0.0:9600` -- accessible from all network interfaces. Should be restricted to management network. |
| GH09-004 | Medium | FAIL | Logging disabled | `#log global` is commented out in defaults. No operational logging is occurring. |
| GH09-005 | Medium | FAIL | No error pages | No `errorfile` directives. |
| GH09-006 | Low | FAIL | No ulimits | No `ulimit-n`. |
| GH09-007 | Low | FAIL | Timeouts may be too short for DB operations | `timeout client 10000ms` (10s) and `timeout server 10000ms` (10s) may be too short for long-running database queries. |

**Note**: The authentication model is well-designed with role separation. The biggest concern is disabled logging and plaintext passwords.

---

### 3.10 triton-moray.cfg

**File**: `/home/snakep/hapr/test-configs/github/triton-moray.cfg`
**Purpose**: Joyent Triton Moray (metadata service) TCP load balancer
**Overall Risk**: HIGH

**Strengths**:
- User/group set (`nobody`/`nobody`)
- Daemon mode
- Global maxconn (65535), defaults maxconn (65535)
- leastconn balancing (good for varying request durations)
- Stats socket present
- `option redispatch` and `option abortonclose`

**Weaknesses**:

| Finding ID | Severity | Status | Title | Details |
|-----------|----------|--------|-------|---------|
| GH10-001 | High | FAIL | No chroot | No filesystem isolation. |
| GH10-002 | High | FAIL | Missing critical timeouts | `timeout client` and `timeout server` are completely missing. Only `timeout queue 0` (infinite!) and `timeout connect 500` (500ms without unit -- interpreted as ms) are set. |
| GH10-003 | High | FAIL | Timeout queue set to 0 (infinite) | `timeout queue 0` disables queue timeout. Queued connections wait forever. |
| GH10-004 | High | FAIL | Stats socket has no permissions | `stats socket /tmp/haproxy.sock` has no `mode`, no `user`, no `group`. In /tmp with default permissions -- anyone on the system can admin HAProxy. |
| GH10-005 | Medium | FAIL | Only 1 retry configured | `retries 1` is very aggressive. One failed attempt and the connection is dropped. |
| GH10-006 | Medium | FAIL | No logging configured | `log 127.0.0.1 local0` is in global but no `log global` in defaults. Frontends and backends will not log. |
| GH10-007 | Medium | FAIL | No health checks on backend servers | Backend template `@@MORAY_INSTANCES@@` suggests dynamic population, but no `check` keyword pattern is indicated. |
| GH10-008 | Medium | FAIL | No error pages | No `errorfile` directives. |
| GH10-009 | Low | FAIL | No ulimits | No `ulimit-n`. |
| GH10-010 | Low | FAIL | No tcplog in defaults | No detailed logging option despite TCP mode. |

**Note**: This is a Triton infrastructure component for internal service mesh. While some hardening is less critical in a controlled environment, the missing timeouts and unsecured stats socket are serious operational risks even internally.

---

## 4. Overall Risk Assessment

### 4.1 Cross-Configuration Analysis

| Security Control | live-server | akhilraj | bbossgrp | acme | jenkins | k8s-packt | ocp4 | rabbitmq | rpm | severalnines | triton |
|-----------------|:-----------:|:--------:|:--------:|:----:|:-------:|:---------:|:----:|:--------:|:---:|:------------:|:------:|
| Chroot | FAIL | PASS | PASS | PASS | PASS | FAIL | PASS | FAIL | PASS | FAIL | FAIL |
| User/Group | FAIL | PASS | FAIL | PASS | PASS | FAIL | PASS | FAIL | PASS | PASS | PASS |
| TLS Hardening | FAIL | PARTIAL | N/A | FAIL | N/A | N/A | N/A | N/A | FAIL | N/A | N/A |
| HSTS | PASS | FAIL | N/A | FAIL | N/A | N/A | N/A | N/A | FAIL | N/A | N/A |
| Security Headers | PARTIAL | FAIL | N/A | FAIL | FAIL | N/A | FAIL | N/A | FAIL | N/A | N/A |
| Rate Limiting | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL |
| Stats Auth | FAIL | PARTIAL | PARTIAL | N/A | N/A | N/A | FAIL | FAIL | FAIL | PASS | N/A |
| Timeouts | PASS | PARTIAL | PASS | PARTIAL | PASS | PARTIAL | PARTIAL | PASS | PARTIAL | PASS | FAIL |
| Health Checks | PASS | PASS | PASS | FAIL | PASS | PASS | PASS | PASS | PASS | N/A | FAIL |
| Error Pages | PASS | PASS | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL |
| Server Header | PASS | FAIL | N/A | FAIL | FAIL | N/A | FAIL | N/A | FAIL | N/A | N/A |
| Logging | PASS | PASS | PASS | PASS | PARTIAL | PARTIAL | PASS | PASS | PASS | FAIL | PARTIAL |
| Request Filtering | FAIL | FAIL | N/A | FAIL | FAIL | N/A | FAIL | N/A | FAIL | N/A | N/A |

### 4.2 Most Common Failures (across all 11 configs)

1. **Rate Limiting** -- Missing in 11/11 configs (100%). This is the most universally absent control.
2. **Request Filtering (body size, URL length, method filtering)** -- Missing in all HTTP-mode configs.
3. **HTTP Security Headers** -- Missing or incomplete in all HTTP-mode configs except live-server (partial).
4. **Ulimits** -- Missing in 11/11 configs (100%).
5. **Custom Error Pages** -- Missing in 8/11 configs.
6. **Stats Page Security** -- Absent or weak authentication in 7/11 configs that have stats enabled.
7. **Server Header Removal** -- Missing in all but live-server.
8. **WAF/Injection Protection** -- Missing in 11/11 configs (100%).

### 4.3 Risk Ratings by Config

| Config | Risk Rating | Primary Concerns |
|--------|------------|------------------|
| live-server.cfg | **HIGH** | TLS 1.0/weak ciphers, unauthenticated admin stats, no process isolation |
| akhilraj-haproxy-backend.cfg | **MEDIUM** | Weak ciphers (3DES), trivial stats password, no TLS on frontends |
| bbossgroups-tcp.cfg | **MEDIUM-HIGH** | No user/group, world-accessible stats socket, weak stats password |
| haproxy-acme-validation.cfg | **HIGH** | No TLS hardening, no timeouts, no security headers, no health checks |
| jenkins-ha.cfg | **MEDIUM** | No TLS, no headers, no rate limiting (but good process hardening) |
| kubernetes-docker-packt.cfg | **HIGH** | Minimal config -- no process hardening, no timeouts, no monitoring |
| ocp4-helpernode.cfg | **MEDIUM** | 4-hour timeouts, unauthenticated stats, verify none on SSL |
| rabbitmq-lb.cfg | **MEDIUM-HIGH** | No user/group, no chroot, unauthenticated stats on all interfaces |
| rpm-haproxy.cfg | **MEDIUM** | No TLS (disabled), unauthenticated stats on public frontend, insecure cookies |
| severalnines-db-ha.cfg | **MEDIUM** | No chroot, plaintext passwords, logging disabled, stats on 0.0.0.0 |
| triton-moray.cfg | **HIGH** | Missing critical timeouts, unsecured stats socket, no health checks, no logging |

---

## 5. Priority Remediation Recommendations

### Priority 1 -- Critical (Immediate Action Required)

1. **Fix TLS configuration on live-server.cfg**: Change `ssl-min-ver TLSv1.0` to `ssl-min-ver TLSv1.2`. Remove `DES-CBC3-SHA` and `RC4-SHA` from cipher suites. These allow attackers to downgrade connections and potentially decrypt traffic.

2. **Secure the stats page on live-server.cfg**: Enable `stats auth` with a strong password. Change `stats admin if TRUE` to `stats admin if LOCALHOST` or a restricted source IP ACL. The current configuration allows anyone on the network to disable backend servers.

3. **Add process isolation across all configs**: Add `chroot`, `user`, and `group` directives where missing. Running HAProxy as root without chroot means any vulnerability grants full system access.

4. **Address plaintext passwords (severalnines)**: Replace `insecure-password` with hashed passwords using `password` directive. Restrict config file permissions to root-only readable (mode 600).

### Priority 2 -- High (Plan for Next Maintenance Window)

5. **Implement rate limiting**: Add stick-table based rate limiting to all HTTP-facing frontends. This is missing universally and leaves every deployment vulnerable to brute-force and application-layer DDoS.

6. **Add HTTP security headers**: At minimum, add X-Frame-Options, X-Content-Type-Options, and Content-Security-Policy to all HTTP frontends performing TLS termination.

7. **Fix stats socket permissions**: Ensure all stats sockets have `mode 660` (or stricter) with explicit user/group ownership. Move sockets out of `/tmp` to a restricted directory.

8. **Add HSTS headers**: All TLS-terminating frontends should set Strict-Transport-Security with at least a 1-year max-age.

9. **Remove/replace the Server header**: Add `http-response del-header Server` to prevent backend version fingerprinting.

10. **Fix timeout issues (triton-moray, ocp4-helpernode)**: Add missing client/server timeouts to triton-moray. Reduce 4-hour timeouts in ocp4-helpernode to reasonable values (e.g., 5-15 minutes if long connections are needed).

### Priority 3 -- Medium (Scheduled Improvement)

11. **Add request filtering**: Implement body size limits, URL length limits, and HTTP method whitelisting on all HTTP frontends.

12. **Enable backend TLS**: Where backend servers support it, enable TLS for backend connections with certificate verification.

13. **Add per-server connection limits**: Set `maxconn` on all backend server lines to prevent individual server overload.

14. **Configure custom error pages**: Add `errorfile` directives for common error codes to prevent information leakage through default error pages.

15. **Enable logging where disabled**: Fix disabled logging in severalnines-db-ha.cfg and improve logging in configs with minimal configuration.

16. **Add WAF integration**: Consider SPOE-based ModSecurity integration for HTTP frontends handling public traffic.

### Priority 4 -- Low (Best Practice Improvements)

17. **Add ulimits**: Set `ulimit-n` in all configurations to prevent file descriptor exhaustion.

18. **Set DH parameters**: Add `tune.ssl.default-dh-param 2048` (or 4096) to all configs with TLS.

19. **Add DNS resolvers**: Configure explicit DNS resolver sections for backends using hostnames.

20. **Add Referrer-Policy and Permissions-Policy headers**: These provide defense-in-depth for privacy and feature restrictions.

21. **Hide stats page version**: Add `stats hide-version` to all stats configurations.

22. **Implement HTTP request smuggling mitigation**: Add `http-request deny if { req.hdr_cnt(content-length) gt 1 }` as defense against CVE-2021-40346 regardless of version.

---

*End of Manual Audit Report*
