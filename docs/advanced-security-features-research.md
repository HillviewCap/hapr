# HAProxy Advanced Security Features Research

## Assessment Tier Definitions

| Tier | Name | Description |
|------|------|-------------|
| **Baseline** | Configuration Hardening | Static config checks. Current HAPR 65-check baseline. No external dependencies. |
| **Level 1** | Enhanced Security Posture | Checks requiring awareness of external integrations, moderate complexity. Suitable for production environments with security requirements. |
| **Level 2** | Advanced Threat Protection | Checks requiring specialized knowledge, external tooling, or enterprise features. For organizations with dedicated security teams. |
| **Level 3** | Zero Trust / Full Stack | Checks requiring architectural-level controls, service mesh patterns, or deep integration with identity/threat-intel systems. For high-security environments. |

---

## 1. SPOE/SPOA — Stream Processing Offload Engine

### What It Does
SPOE (added in HAProxy 1.7) sends live traffic to external programs (SPOA — Stream Processing Offload Agents) for out-of-band processing using the binary SPOP protocol. This enables deep packet inspection, WAF rule evaluation, and custom security logic without modifying HAProxy core.

### Security Benefit
- Enables full WAF integration (ModSecurity, Coraza, CrowdSec) at the proxy layer
- Blocks OWASP Top 10 attacks (SQLi, XSS, RCE) before they reach backends
- Allows real-time IP reputation checking and CAPTCHA challenges
- Decouples security processing from load balancing performance

### Complexity Level
**Advanced** — Requires deploying and maintaining an external SPOA daemon, configuring the SPOP protocol, and managing WAF rulesets (e.g., OWASP CRS v4).

### Assessment Tier
**Level 1** (detection of SPOE filter) / **Level 2** (validation of SPOA configuration quality)

### Key HAProxy Directives
```haproxy
# In frontend/backend
filter spoe engine modsecurity config /etc/haproxy/spoe-modsecurity.conf

# SPOE configuration file (spoe-modsecurity.conf)
[modsecurity]
spoe-agent modsecurity-agent
    messages check-request
    option var-prefix modsec
    timeout hello      100ms
    timeout idle       30s
    timeout processing 15ms
    use-backend spoe-modsecurity

spoe-message check-request
    args unique-id method path query req.ver req.hdrs_bin req.body
    event on-frontend-http-request
```

### Available SPOA Integrations
- **Coraza SPOA**: OWASP Coraza WAF, Go-based, CRS v4 compatible
- **CrowdSec SPOA**: IP reputation + WAF + CAPTCHA
- **ModSecurity SPOA**: Classic ModSecurity WAF engine
- **Fastly Next-Gen WAF**: Commercial WAF via SPOE

### Potential Check IDs
- `HAPR-SPOE-001`: SPOE filter declared in frontends
- `HAPR-SPOE-002`: SPOE agent timeout configuration
- `HAPR-SPOE-003`: SPOE backend availability (health checks on SPOA)

---

## 2. Lua Scripting Security

### What It Does
HAProxy embeds a Lua interpreter (5.3/5.4) for custom logic: request/response manipulation, authentication, header injection, token validation, dynamic routing, background tasks, and event-driven workflows.

### Security Benefit
- Enables custom authentication flows (JWT, OAuth, API key validation)
- Allows complex request inspection beyond ACL capabilities
- Supports dynamic blocklist updates and custom security logic

### Security Risks
- **No sandbox by default**: Lua scripts have access to HAProxy internals
- **Memory exhaustion**: Unbounded Lua memory can crash HAProxy if `tune.lua.maxmem` is not set
- **Blocking I/O**: Standard Lua file/network I/O blocks HAProxy's event loop
- **Thread safety**: Global variables in `lua-load-per-thread` are not synchronized
- **Memory leaks**: Documented issues with vars pools growing unbounded (1.1GB after ~300K requests)
- **Code injection**: If Lua scripts process untrusted input without sanitization

### Complexity Level
**Intermediate** (basic scripts) to **Advanced** (complex auth flows, event framework)

### Assessment Tier
**Level 1** (detect Lua usage and basic safety) / **Level 2** (validate Lua security controls)

### Key HAProxy Directives
```haproxy
global
    # Load Lua script
    lua-load /etc/haproxy/scripts/auth.lua
    lua-load-per-thread /etc/haproxy/scripts/worker.lua

    # CRITICAL: Set memory limit to prevent exhaustion
    tune.lua.maxmem 64  # MB per process

    # Timeout controls
    tune.lua.forced-yield 10000  # Force yield after N instructions
    tune.lua.service-timeout 5000  # ms
```

### Potential Check IDs
- `HAPR-LUA-001`: `tune.lua.maxmem` is set when Lua scripts are loaded
- `HAPR-LUA-002`: `tune.lua.forced-yield` is configured
- `HAPR-LUA-003`: Lua scripts use `lua-load-per-thread` without global variables (advisory)

---

## 3. Maps and ACL Files — External File-Based Access Control

### What It Does
HAProxy maps and ACL files externalize access control rules into plain-text files, enabling dynamic updates via the Runtime API without reloading. Map files store key-value pairs; ACL files store matching patterns.

### Security Benefit
- Centralizes access control rules for easier auditing
- Supports dynamic blocklist/allowlist management via Runtime API
- Reduces config file complexity and associated misconfiguration risk
- Enables integration with external threat intelligence feeds

### Complexity Level
**Intermediate** — Straightforward file management, but requires understanding of Runtime API for dynamic updates.

### Assessment Tier
**Level 1** (detection and file permission checks) / **Level 2** (validation of update mechanisms)

### Key HAProxy Directives
```haproxy
# ACL file usage
acl blocked_ips src -f /etc/haproxy/blocked_ips.acl
http-request deny if blocked_ips

# Map file usage (key -> value lookup)
http-request set-header X-Backend %[path,map_str(/etc/haproxy/routing.map)]

# Virtual file (in-memory only, no disk persistence)
acl dynamic_block src -f -M /etc/haproxy/dynamic_blocks.acl

# Optional file (disk if exists, virtual otherwise)
acl optional_list src -f -- /etc/haproxy/optional.acl

# Runtime API commands for dynamic updates
# echo "add acl /etc/haproxy/blocked_ips.acl 10.0.0.1" | socat stdio /var/run/haproxy.sock
# echo "del acl /etc/haproxy/blocked_ips.acl 10.0.0.1" | socat stdio /var/run/haproxy.sock
```

### Potential Check IDs
- `HAPR-MAP-001`: External ACL/map files have restrictive file permissions
- `HAPR-MAP-002`: Map/ACL files are referenced with absolute paths
- `HAPR-MAP-003`: Runtime API access for map updates is properly secured

---

## 4. Stick Tables — Advanced DDoS/Bot/Abuse Prevention

### What It Does
Stick tables are in-memory key-value stores that track per-client state: connection rates, request rates, error rates, bytes transferred, and session data. Combined with ACLs, they enable real-time abuse detection and automated mitigation.

### Security Benefit
- **DDoS mitigation**: Track and limit connection/request rates per source IP
- **Bot detection**: Identify non-human behavior patterns (high request rates, unique page access)
- **Brute force prevention**: Track authentication failure rates
- **Abuse scoring**: Combine multiple counters for composite threat scoring
- **Session affinity**: Maintain state for load balancing decisions

### Complexity Level
**Intermediate** (basic rate limiting) to **Advanced** (composite scoring, multi-table correlation)

### Assessment Tier
**Baseline** (basic stick table presence — already HAPR-ACL-004) / **Level 1** (advanced tracking configuration) / **Level 2** (composite abuse detection)

### Key HAProxy Directives
```haproxy
# Multi-counter abuse detection
backend abuse_tracking
    stick-table type ip size 500k expire 10m \
        store conn_cur,conn_rate(3s),http_req_rate(10s),http_err_rate(10s),bytes_out_rate(60s),gpc0,gpc1

frontend web
    # Track client IP across multiple counters
    http-request track-sc0 src table abuse_tracking

    # Connection flood protection
    http-request deny deny_status 429 if { sc_conn_rate(0) gt 100 }

    # HTTP request flood
    http-request deny deny_status 429 if { sc_http_req_rate(0) gt 200 }

    # Error rate (scanning/fuzzing detection)
    http-request deny deny_status 403 if { sc_http_err_rate(0) gt 50 }

    # Bandwidth abuse
    http-request deny deny_status 429 if { sc_bytes_out_rate(0) gt 10000000 }

    # General Purpose Counters for custom scoring
    http-request sc-inc-gpc0(0) if { path_beg /login } !{ sc_http_err_rate(0) gt 0 }
    http-request deny if { sc_get_gpc0(0) gt 10 }  # Too many login attempts

    # Tarpit instead of deny (slow down attacker)
    http-request tarpit if { sc_conn_rate(0) gt 50 }
```

### Potential Check IDs
- `HAPR-STICK-001`: Stick table tracks multiple counter types (not just one)
- `HAPR-STICK-002`: Error rate tracking enabled (`http_err_rate`)
- `HAPR-STICK-003`: Stick table entries have reasonable expiry times
- `HAPR-STICK-004`: General purpose counters (gpc) used for composite scoring

---

## 5. SSL/TLS Advanced — OCSP Stapling, mTLS, Certificate Validation

### What It Does
Beyond basic TLS configuration, HAProxy supports OCSP stapling (certificate revocation status embedded in TLS handshake), mutual TLS (client certificate authentication), and advanced certificate validation including CRL checking.

### Security Benefit
- **OCSP stapling**: Faster handshakes, improved privacy (clients don't query OCSP responders), ensures revocation status is available
- **mTLS**: Strong cryptographic client authentication, eliminates password-based auth
- **CRL/OCSP validation**: Detect and reject revoked client certificates
- **Certificate pinning**: Restrict which CAs can issue certificates for your domain

### Complexity Level
**Intermediate** (OCSP stapling) / **Advanced** (mTLS, CRL management)

### Assessment Tier
**Level 1** (OCSP stapling) / **Level 2** (mTLS, client cert validation) / **Level 3** (full zero-trust mTLS architecture)

### Key HAProxy Directives
```haproxy
# OCSP Stapling (HAProxy 2.8+ auto-updates)
global
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

frontend web
    # OCSP stapling is automatic when certificate has OCSP responder URL
    bind *:443 ssl crt /etc/haproxy/certs/server.pem ocsp-update on

# Mutual TLS (Client Certificate Authentication)
frontend mtls_api
    bind *:443 ssl crt /etc/haproxy/certs/server.pem \
        ca-file /etc/haproxy/certs/client-ca.pem \
        verify required \
        crl-file /etc/haproxy/certs/revoked.crl

    # Extract client certificate fields for authorization
    http-request set-header X-Client-CN %{+Q}[ssl_c_s_dn(cn)]
    http-request set-header X-Client-Fingerprint %[ssl_c_sha1,hex]
    http-request set-header X-Client-Verify %[ssl_c_verify]

    # Deny if certificate verification failed
    http-request deny if !{ ssl_c_verify 0 }

    # Optional: route based on certificate OU
    acl admin_cert ssl_c_s_dn(ou) -m str AdminTeam
    use_backend admin_api if admin_cert

# Optional client certs (zero-trust with fallback)
frontend flexible_auth
    bind *:443 ssl crt /etc/haproxy/certs/server.pem \
        ca-file /etc/haproxy/certs/client-ca.pem \
        verify optional

    # Authenticated clients get premium backend
    use_backend premium if { ssl_c_used }
    default_backend standard
```

### Potential Check IDs
- `HAPR-TLSA-001`: OCSP stapling enabled on SSL bind lines
- `HAPR-TLSA-002`: mTLS `verify required` configured where client auth needed
- `HAPR-TLSA-003`: CRL file configured for client certificate validation
- `HAPR-TLSA-004`: Client certificate fields logged for audit trail
- `HAPR-TLSA-005`: `ssl_c_verify` checked in ACLs when using optional verify

---

## 6. HTTP/2 and HTTP/3 (QUIC) Security

### What It Does
HAProxy supports HTTP/2 (h2) multiplexing on frontend and backend connections, and HTTP/3 over QUIC (UDP-based transport) starting from HAProxy 2.6+. These protocols improve performance but introduce new attack surfaces.

### Security Benefit
- **HTTP/2**: Multiplexing eliminates head-of-line blocking at HTTP layer; binary framing reduces parsing ambiguity
- **HTTP/3/QUIC**: UDP-based transport eliminates TCP head-of-line blocking; built-in encryption; connection migration resilience
- **Stream limits**: Protection against resource exhaustion from excessive streams

### Security Risks
- **HTTP/2 request smuggling**: Header manipulation between HTTP/1 and HTTP/2 translation (CVE-2023-25725, CVE-2024-45506)
- **QUIC amplification attacks**: UDP reflection if not properly configured
- **Protocol downgrade**: Attackers may force fallback to weaker HTTP/1.1
- **Implementation maturity**: HTTP/3 support is newer and may have undiscovered vulnerabilities

### Complexity Level
**Intermediate** (HTTP/2) / **Advanced** (HTTP/3/QUIC)

### Assessment Tier
**Level 1** (HTTP/2 configuration validation) / **Level 2** (HTTP/3/QUIC security, protocol negotiation)

### Key HAProxy Directives
```haproxy
global
    # HTTP/2 tuning
    tune.h2.header-table-size 4096
    tune.h2.initial-window-size 65535
    tune.h2.max-concurrent-streams 100  # Limit streams per connection
    tune.h2.max-frame-size 16384

    # QUIC control (HAProxy 3.x+)
    tune.quic.listen on  # Enable QUIC globally

frontend web_h2
    # HTTP/2 on frontend
    bind *:443 ssl crt /etc/haproxy/cert.pem alpn h2,http/1.1

    # HTTP/3 over QUIC
    bind quic4@*:443 ssl crt /etc/haproxy/cert.pem alpn h3

    # Advertise HTTP/3 availability
    http-response set-header alt-svc "h3=\":443\"; ma=86400"

    # HTTP/2 backend connections
    default_backend web_servers

backend web_servers
    server web1 10.0.0.1:443 ssl alpn h2 verify required ca-file /etc/ssl/ca.crt
```

### Potential Check IDs
- `HAPR-H2-001`: `tune.h2.max-concurrent-streams` is set to prevent stream flooding
- `HAPR-H2-002`: HTTP/2 enabled with proper ALPN negotiation
- `HAPR-H3-001`: QUIC bind lines use proper TLS library (quictls, not stock OpenSSL)
- `HAPR-H3-002`: alt-svc header configured for HTTP/3 advertisement

---

## 7. HAProxy Peers — Multi-Node Synchronization Security

### What It Does
The peers protocol enables replication of stick table data between multiple HAProxy instances. In active-standby mode, one-way replication pushes data to standby nodes. Active-active requires the Stick Table Aggregator (Enterprise feature). Also used for seamless reloads (old process pushes state to new process).

### Security Benefit
- Consistent rate limiting across multiple nodes (prevents bypass by rotating IPs across instances)
- Shared abuse detection state in clustered environments
- Session persistence survives node failures and reloads
- Prevents data loss during configuration reloads

### Security Risks
- **Unencrypted peers traffic**: By default, peers protocol is unencrypted — stick table data (including IPs and session info) sent in plaintext
- **No authentication by default**: Any system that can connect to the peers port can inject stick table entries
- **Spoofed entries**: Malicious peer injection could whitelist attacker IPs or blacklist legitimate users

### Complexity Level
**Intermediate** (basic peers) / **Advanced** (TLS-encrypted peers, multi-cluster aggregation)

### Assessment Tier
**Level 1** (peers section detected and access restricted) / **Level 2** (peers TLS encryption, mutual authentication)

### Key HAProxy Directives
```haproxy
# Basic peers (INSECURE without TLS)
peers mycluster
    peer haproxy1 10.0.0.1:10000
    peer haproxy2 10.0.0.2:10000

# Secure peers with TLS (HAProxy Enterprise or custom build)
peers mycluster
    bind *:10000 ssl crt /etc/haproxy/certs/peer.pem ca-file /etc/haproxy/certs/peer-ca.pem verify required
    server haproxy1 10.0.0.1:10000 ssl crt /etc/haproxy/certs/peer.pem ca-file /etc/haproxy/certs/peer-ca.pem verify required
    server haproxy2 10.0.0.2:10000 ssl crt /etc/haproxy/certs/peer.pem ca-file /etc/haproxy/certs/peer-ca.pem verify required

# Reference peers in stick table
backend rate_limit
    stick-table type ip size 200k expire 5m store http_req_rate(10s) peers mycluster
```

### Potential Check IDs
- `HAPR-PEER-001`: Peers section uses TLS encryption
- `HAPR-PEER-002`: Peers bind line restricts access (not `*:port` without ACL)
- `HAPR-PEER-003`: Peer names match across all cluster members (advisory)

---

## 8. Runtime API Security — Stats Socket, Admin Commands

### What It Does
The HAProxy Runtime API (stats socket) provides real-time control: enable/disable servers, modify weights, update ACLs/maps, inspect stick tables, view statistics, and execute admin commands. Accessible via Unix socket or TCP.

### Security Benefit
- Enables dynamic security response (block IPs, disable compromised servers)
- Provides real-time monitoring for incident detection
- Allows configuration changes without full reload

### Security Risks
- **Full admin access**: Admin-level socket can disable all backends, clear stick tables, modify routing
- **TCP exposure**: Binding the socket to a TCP port can expose it to the network
- **No encryption**: The protocol is plaintext
- **No authentication on socket**: Access control relies solely on Unix permissions or network access

### Complexity Level
**Basic** (socket permission hardening — already in baseline) / **Intermediate** (access level separation, TCP exposure prevention)

### Assessment Tier
**Baseline** (already HAPR-GBL-002) / **Level 1** (extended validation)

### Key HAProxy Directives
```haproxy
global
    # GOOD: Unix socket with restrictive permissions
    stats socket /var/run/haproxy/admin.sock mode 660 level admin user haproxy group haproxy

    # Read-only socket for monitoring
    stats socket /var/run/haproxy/stats.sock mode 660 level operator user monitoring group monitoring

    # View-only socket for dashboards
    stats socket /var/run/haproxy/view.sock mode 664 level user

    # DANGEROUS: TCP socket (avoid unless absolutely necessary)
    # stats socket *:9999 level admin  # DO NOT DO THIS

    # If TCP is required, restrict to localhost
    stats socket 127.0.0.1:9999 level operator

    # Timeout for idle connections
    stats timeout 2m
```

### Access Levels
| Level | Capabilities |
|-------|-------------|
| `user` | View-only: show stat, show info, show servers |
| `operator` | + clear counters, set weight, enable/disable server |
| `admin` | Full access: set map, add acl, shutdown, set maxconn |

### Potential Check IDs (extending HAPR-GBL-002)
- `HAPR-API-001`: No TCP-bound stats sockets (or TCP restricted to localhost)
- `HAPR-API-002`: Multiple sockets with different access levels for separation of duties
- `HAPR-API-003`: Stats timeout is set to prevent idle connection accumulation

---

## 9. Content Switching Security — Host/Path Routing

### What It Does
Content switching routes requests to different backends based on request attributes: Host header, URL path, query parameters, headers, cookies, source IP, and more. This is HAProxy's core routing mechanism.

### Security Risks
- **Path traversal**: ACL path rules may be bypassed with encoding tricks (`/admin/../secret`, URL-encoded paths)
- **Host header injection**: Manipulated Host headers can route traffic to unintended backends
- **Fragment bypass**: HAProxy treated `#` as URI component before 2.8.2 — `index.html#.png` could bypass path_end rules
- **HTTP/1 vs HTTP/2 authority mismatch**: Header loss during protocol translation (CVE before 2.7.3)
- **HTTP request smuggling**: Content-Length manipulation to bypass all ACL rules (CVE-2021-40346)
- **Case sensitivity**: Path matching may be case-sensitive while backend is case-insensitive

### Complexity Level
**Intermediate** — Understanding routing bypass techniques requires security expertise.

### Assessment Tier
**Level 1** (routing rule quality validation) / **Level 2** (smuggling/bypass resistance)

### Key HAProxy Directives
```haproxy
frontend web
    # Normalize paths before matching
    http-request normalize-uri path-merge-slashes
    http-request normalize-uri path-strip-dotdot
    http-request normalize-uri percent-decode-unreserved
    http-request normalize-uri percent-to-uppercase

    # Strict Host header validation
    acl valid_host hdr(host) -i www.example.com example.com api.example.com
    http-request deny if !valid_host

    # Case-insensitive path matching with normalization
    acl admin_path path_beg -i /admin /management /console
    acl internal src 10.0.0.0/8
    http-request deny if admin_path !internal

    # Reject ambiguous requests (smuggling prevention)
    http-request deny if { req.hdr_cnt(content-length) gt 1 }
    http-request deny if { req.hdr_cnt(host) gt 1 }

    # Host-based routing
    use_backend api_servers if { hdr(host) -i api.example.com }
    use_backend static_servers if { path_beg /static /assets }
    default_backend web_servers
```

### Potential Check IDs
- `HAPR-ROUTE-001`: URI normalization rules applied before routing decisions
- `HAPR-ROUTE-002`: Host header validation ACL present
- `HAPR-ROUTE-003`: Duplicate header detection (Content-Length, Host)
- `HAPR-ROUTE-004`: Default backend defined (no open routing)

---

## 10. Multi-Process/Multi-Thread Security

### What It Does
HAProxy historically supported `nbproc` (multiple processes) and now uses `nbthread` (multiple threads within a single process). `nbproc` was deprecated in 2.5 and removed in later versions.

### Security Implications
- **nbproc (DEPRECATED)**: Multiple processes had **no shared state** — stick tables, health checks, peers, and stats were isolated per process. This broke rate limiting, session persistence, and abuse detection.
- **nbthread (CURRENT)**: Threads share memory space — stick tables, health checks, and all state are properly synchronized. Session processing is serialized per connection (no locking issues).

### Security Benefit of nbthread
- Consistent stick table state across all threads (rate limiting works correctly)
- Shared health check results (no split-brain on backend availability)
- Proper stats aggregation
- Thread-safe Lua state management (with spinlock protection)

### Complexity Level
**Basic** — Configuration is straightforward; the security impact is about detecting deprecated patterns.

### Assessment Tier
**Baseline** (detect deprecated `nbproc`) / **Level 1** (validate `nbthread` configuration)

### Key HAProxy Directives
```haproxy
global
    # DEPRECATED/REMOVED — DO NOT USE
    # nbproc 4  # Breaks stick tables, peers, health checks

    # CORRECT: Use nbthread
    nbthread 4  # Or omit to auto-detect CPU count (HAProxy 2.5+)
```

### Potential Check IDs
- `HAPR-PROC-005`: `nbproc` is not used (deprecated, breaks security features)
- `HAPR-PROC-006`: `nbthread` is set or auto-detected (not nbproc)

---

## 11. DNS Security — Resolvers, DNS Over TLS

### What It Does
HAProxy has a built-in DNS resolver for service discovery that resolves backend server addresses dynamically. The resolver only supports UDP by default. HAProxy can also serve as a TLS proxy for DNS-over-TLS (DoT) to clients.

### Security Risks
- **DNS spoofing/poisoning**: HAProxy's internal resolver uses UDP — vulnerable to DNS cache poisoning if querying untrusted networks
- **DNS rebinding**: Malicious DNS responses could redirect backend traffic
- **No DNSSEC validation**: HAProxy does not validate DNSSEC signatures
- **Resolver timeout abuse**: Long TTLs can cache poisoned entries

### Complexity Level
**Intermediate** (resolver configuration) / **Advanced** (DNS-over-TLS proxy)

### Assessment Tier
**Level 1** (resolver configuration validation) / **Level 2** (DNS security hardening)

### Key HAProxy Directives
```haproxy
# DNS Resolver configuration
resolvers trusted_dns
    nameserver dns1 10.0.0.2:53
    nameserver dns2 10.0.0.3:53
    accepted_payload_size 8192
    resolve_retries 3
    timeout resolve 1s
    timeout retry 1s
    hold valid 10s       # Short TTL to limit cache poisoning window
    hold nx 5s
    hold refused 5s
    hold timeout 5s
    hold other 5s

backend dynamic_servers
    server-template srv 5 _http._tcp.myservice.consul resolvers trusted_dns resolve-prefer ipv4

# HAProxy as DNS-over-TLS proxy
frontend dns_tls
    bind *:853 ssl crt /etc/haproxy/certs/dns.pem
    mode tcp
    default_backend dns_servers

backend dns_servers
    mode tcp
    server dns1 10.0.0.2:53
```

### Potential Check IDs
- `HAPR-DNS-001`: Resolver uses internal/trusted DNS servers (not public DNS on untrusted paths)
- `HAPR-DNS-002`: Resolver hold times are short (limit cache poisoning window)
- `HAPR-DNS-003`: `resolve_retries` is configured to prevent hanging resolution

---

## 12. PROXY Protocol Security (v1/v2)

### What It Does
The PROXY protocol (invented by HAProxy) preserves original client IP addresses when traffic passes through multiple proxies/load balancers. v1 is text-based; v2 is binary and faster to parse. It prepends connection metadata to the TCP stream.

### Security Risks
- **IP spoofing**: If untrusted clients can send PROXY protocol headers, they can spoof their source IP — this bypasses all IP-based ACLs, rate limiting, and logging
- **Trust boundary violation**: Accepting PROXY protocol from any source negates all IP-based security
- **Protocol confusion**: Misconfigured listeners that auto-detect PROXY protocol can be exploited

### Complexity Level
**Intermediate** — Understanding trust boundaries is critical.

### Assessment Tier
**Level 1** (PROXY protocol trust validation)

### Key HAProxy Directives
```haproxy
frontend web
    # Accept PROXY protocol ONLY from trusted upstream proxies
    bind *:443 ssl crt /etc/haproxy/cert.pem accept-proxy

    # CRITICAL: ACL to restrict PROXY protocol sources
    # (This must be done at the network level or with tcp-request)
    acl trusted_proxy src 10.0.0.100 10.0.0.101
    tcp-request connection reject if !trusted_proxy

# Send PROXY protocol to backend
backend servers
    server web1 10.0.0.1:80 send-proxy-v2
```

### Potential Check IDs
- `HAPR-PROXY-001`: `accept-proxy` bind lines have source IP restrictions
- `HAPR-PROXY-002`: `send-proxy` / `send-proxy-v2` only on trusted backend connections
- `HAPR-PROXY-003`: No wildcard source acceptance with PROXY protocol

---

## 13. Compression Security (BREACH Attack)

### What It Does
HAProxy can compress HTTP responses using gzip, deflate, or other algorithms to reduce bandwidth. The `compression` filter is applied in frontend/backend/listen sections.

### Security Risk
- **BREACH attack (CVE-2013-3587)**: When HTTP compression is enabled on responses that contain secrets (CSRF tokens, session IDs) and the attacker can inject content into the response, the compressed size reveals information about the secret through a side-channel attack. This allows extraction of secrets from HTTPS-encrypted traffic.

### Complexity Level
**Basic** — Simple detection of compression on sensitive endpoints.

### Assessment Tier
**Level 1** (compression detection and risk assessment)

### Key HAProxy Directives
```haproxy
# RISKY: Compression on all responses
frontend web
    compression algo gzip deflate
    compression type text/html text/css application/javascript

# SAFER: Exclude sensitive content types
frontend web_safe
    # Only compress static assets, not dynamic pages with tokens
    compression algo gzip deflate
    compression type text/css application/javascript image/svg+xml
    # Do NOT include text/html or application/json if they contain CSRF tokens

# SAFEST: Disable compression entirely
# (Simply omit compression directives)
```

### Potential Check IDs
- `HAPR-COMP-001`: Compression enabled on `text/html` or `application/json` (BREACH risk warning)
- `HAPR-COMP-002`: Compression used without additional BREACH mitigations (advisory)

---

## 14. Cache Security

### What It Does
HAProxy has a built-in HTTP cache (since 2.0) that stores responses in shared memory. The cache stores responses based on URL and request headers and serves them directly without contacting the backend.

### Security Risks
- **Cache poisoning**: If unkeyed request headers (X-Forwarded-Host, X-Original-URL) influence the response, an attacker can poison the cache with malicious content served to legitimate users
- **Sensitive data caching**: Accidentally caching authenticated responses exposes user data
- **Cache key collision**: Insufficient vary headers can serve one user's content to another

### Security Safeguards Built In
- HAProxy cache **never caches** responses when the request contains an `Authorization` header
- Cache entries respect Cache-Control directives

### Complexity Level
**Intermediate** — Requires understanding of web cache security.

### Assessment Tier
**Level 1** (cache configuration validation) / **Level 2** (cache poisoning resistance)

### Key HAProxy Directives
```haproxy
# Cache configuration
cache my_cache
    total-max-size 256  # MB
    max-object-size 10000  # bytes
    max-age 60  # seconds — keep short to reduce poisoning window
    process-vary on  # Respect Vary header for cache keying

frontend web
    # Cache only safe, public content
    http-request cache-use my_cache if { path_beg /static /assets }
    http-response cache-store my_cache if { path_beg /static /assets }

    # Never cache API or authenticated endpoints
    http-request set-var(txn.no_cache) bool(true) if { path_beg /api /auth /user }
    http-response del-header set-cookie if { var(txn.no_cache) -m bool }
```

### Potential Check IDs
- `HAPR-CACHE-001`: Cache `max-age` is reasonable (not excessively long)
- `HAPR-CACHE-002`: `process-vary` is enabled to prevent cross-user content serving
- `HAPR-CACHE-003`: Cache rules exclude authenticated/API endpoints

---

## 15. JWT Validation

### What It Does
Starting with HAProxy 2.5, built-in JWT validation supports extracting tokens from Authorization headers, validating signatures (RS256, HS256, ES256), and checking claims (issuer, audience, expiration). Before 2.5, Lua scripts (haproxy-lua-oauth) provided this capability.

### Security Benefit
- Token validation at the proxy layer — reject invalid tokens before reaching backends
- Claim-based routing (route to different backends based on JWT roles)
- Centralized authentication enforcement across all services

### Complexity Level
**Intermediate** (basic JWT validation) / **Advanced** (JWKS rotation, claim-based routing)

### Assessment Tier
**Level 2** (JWT configuration validation) / **Level 3** (full OAuth/OIDC flow)

### Key HAProxy Directives
```haproxy
frontend api
    # Extract bearer token
    http-request set-var(txn.bearer) http_auth_bearer

    # Validate JWT header fields
    http-request deny unless { var(txn.bearer),jwt_header_query('$.alg') -m str RS256 }
    http-request deny unless { var(txn.bearer),jwt_header_query('$.typ') -m str JWT }

    # Validate JWT claims
    http-request deny unless { var(txn.bearer),jwt_payload_query('$.iss') -m str "https://auth.example.com" }
    http-request deny unless { var(txn.bearer),jwt_payload_query('$.aud') -m str "my-api" }

    # Check expiration (exp claim)
    http-request deny if { var(txn.bearer),jwt_payload_query('$.exp','int') lt now }

    # Verify signature with public key
    http-request deny unless { var(txn.bearer),jwt_verify(txn.bearer,RS256,/etc/haproxy/certs/jwt-public.pem) -m int 1 }

    # Extract role for routing
    http-request set-header X-User-Role %[var(txn.bearer),jwt_payload_query('$.role')]

    use_backend admin_api if { req.hdr(X-User-Role) -m str admin }
    default_backend user_api
```

### Potential Check IDs
- `HAPR-JWT-001`: JWT signature verification is enforced (not just claim checking)
- `HAPR-JWT-002`: JWT expiration (`exp`) claim is validated
- `HAPR-JWT-003`: Allowed algorithms are explicitly restricted (no `alg: none` bypass)
- `HAPR-JWT-004`: JWT issuer and audience claims are validated

---

## 16. OpenID Connect / OAuth Integration

### What It Does
HAProxy can participate in OAuth 2.0 / OpenID Connect flows as a token validation gateway. HAProxy Enterprise includes a native OIDC SSO module. Community edition can use SPOE agents or Lua scripts for the full Authorization Code Flow.

### Security Benefit
- Centralized authentication at the proxy layer
- Single sign-on across all backend services
- Token refresh handling without backend changes
- Protection against open redirect (signed state parameter)

### Security Considerations
- ID tokens encrypted and stored in httpOnly cookies
- State parameter signed to prevent CSRF in OAuth flow
- Cookie domain and TTL configuration critical for security
- JWKS public key must be securely provisioned and rotated

### Complexity Level
**Advanced** — Requires understanding of OAuth 2.0 flows, OIDC claims, and token lifecycle.

### Assessment Tier
**Level 2** (token validation configuration) / **Level 3** (full OIDC integration with SSO)

### Key HAProxy Directives
```haproxy
# Using SPOE for OIDC (community approach)
filter spoe engine oidc-auth config /etc/haproxy/spoe-oidc.conf

# HAProxy Enterprise OIDC module
frontend web
    bind *:443 ssl crt /etc/haproxy/cert.pem

    # OIDC SSO configuration (Enterprise)
    http-request auth realm myrealm \
        oidc-provider https://auth.example.com/.well-known/openid-configuration \
        oidc-client-id my-app \
        oidc-client-secret $ENV(OIDC_SECRET) \
        oidc-callback-url https://www.example.com/callback

    # Forward authenticated user info to backend
    http-request set-header X-Authenticated-User %[var(sess.oidc.sub)]

# Community approach: JWT validation of OAuth tokens
frontend api
    http-request set-var(txn.bearer) http_auth_bearer
    http-request deny unless { var(txn.bearer),jwt_verify(txn.bearer,RS256,/etc/haproxy/certs/oauth-public.pem) -m int 1 }
```

### Potential Check IDs
- `HAPR-OIDC-001`: OIDC callback URL uses HTTPS
- `HAPR-OIDC-002`: Client secrets not hardcoded (use environment variables)
- `HAPR-OIDC-003`: Session cookies have httpOnly, secure, and SameSite attributes

---

## 17. mTLS for Zero-Trust Architectures

### What It Does
In a zero-trust architecture, every service-to-service connection uses mutual TLS for authentication. HAProxy serves as the mTLS termination point, often integrated with SPIFFE/SPIRE for automatic certificate issuance and rotation.

### Security Benefit
- Cryptographic identity for every service (no network-based trust)
- Automatic certificate rotation eliminates manual certificate management
- No reliance on network perimeter for security
- Lateral movement prevention — compromised services cannot impersonate others

### Complexity Level
**Advanced** — Requires SPIFFE/SPIRE infrastructure, certificate automation, and architectural changes.

### Assessment Tier
**Level 3** (zero-trust mTLS architecture)

### Key HAProxy Directives
```haproxy
# SPIFFE/SPIRE integration
# Each HAProxy instance has a SPIRE Agent providing SVID certificates

frontend service_mesh
    bind *:443 ssl \
        crt /run/spire/svid.pem \
        ca-file /run/spire/bundle.pem \
        verify required

    # Route based on SPIFFE ID from client certificate
    acl service_a ssl_c_s_dn(uri) -m str spiffe://example.org/service-a
    acl service_b ssl_c_s_dn(uri) -m str spiffe://example.org/service-b

    use_backend service_a_backend if service_a
    use_backend service_b_backend if service_b

    # Deny unknown services
    default_backend deny_backend

backend service_a_backend
    server svc-a 10.0.1.1:8080 ssl \
        crt /run/spire/svid.pem \
        ca-file /run/spire/bundle.pem \
        verify required
```

### Potential Check IDs
- `HAPR-ZT-001`: All backend connections use `ssl verify required`
- `HAPR-ZT-002`: SPIFFE/SPIRE SVID certificates configured
- `HAPR-ZT-003`: Certificate-based routing enforced (no network-trust fallback)
- `HAPR-ZT-004`: Default backend denies unknown client certificates

---

## 18. IP Reputation Integration

### What It Does
Integration with IP reputation services (CrowdSec, threat intelligence feeds) enables real-time blocking of known malicious IPs. Implementation can be via Lua bouncer, SPOE agent, or map file with periodic updates.

### Security Benefit
- Proactive blocking of known attackers, scanners, and botnets
- Community-sourced threat intelligence (CrowdSec Community Blocklist)
- Reduces attack surface by filtering malicious traffic before it reaches applications
- Supports multiple remediation actions: block, CAPTCHA, allow with logging

### Complexity Level
**Intermediate** (map-file based blocklists) / **Advanced** (real-time SPOE/Lua integration)

### Assessment Tier
**Level 2** (IP reputation integration) / **Level 3** (real-time threat intelligence with automated response)

### Key HAProxy Directives
```haproxy
# CrowdSec Lua Bouncer integration
global
    lua-prepend-path /usr/lib/crowdsec/lua/haproxy/?.lua
    lua-load /usr/lib/crowdsec/lua/haproxy/crowdsec.lua
    setenv CROWDSEC_CONFIG /etc/crowdsec/bouncers/crowdsec-haproxy-bouncer.conf

frontend web
    stick-table type ip size 10k store gpc0,conn_cur
    http-request lua.crowdsec_allow
    http-request deny if { var(txn.crowdsec_result) -m int 1 }
    http-request redirect location /captcha if { var(txn.crowdsec_result) -m int 2 }

# Map-file based blocklist (simpler, updated by cron/API)
frontend web_simple
    acl blocked_ip src -f /etc/haproxy/blocklist.map
    http-request deny deny_status 403 if blocked_ip

# CrowdSec SPOA integration (alternative)
filter spoe engine crowdsec config /etc/haproxy/spoe-crowdsec.conf
```

### Potential Check IDs
- `HAPR-IPREP-001`: IP reputation integration detected (CrowdSec, blocklist map, or custom)
- `HAPR-IPREP-002`: Blocklist is periodically updated (not stale)
- `HAPR-IPREP-003`: Both block and CAPTCHA remediation paths configured

---

## 19. Bot Management Patterns

### What It Does
HAProxy detects and manages bots through multiple signals: request rate patterns, User-Agent analysis, TLS fingerprinting (JA3/JA4), JavaScript challenges, CAPTCHA integration, and behavioral analysis via stick tables.

### Security Benefit
- Blocks credential stuffing, web scraping, and automated attacks
- Differentiates between legitimate bots (Googlebot) and malicious ones
- Reduces server load from automated traffic
- Protects APIs from unauthorized automated access

### Complexity Level
**Intermediate** (User-Agent/rate-based) / **Advanced** (TLS fingerprinting, JavaScript challenges)

### Assessment Tier
**Level 2** (bot detection patterns) / **Level 3** (TLS fingerprinting, behavioral analysis)

### Key HAProxy Directives
```haproxy
frontend web
    # Track visitor behavior
    stick-table type ip size 200k expire 10m \
        store http_req_rate(10s),http_req_cnt,conn_rate(3s),gpc0,gpc1
    http-request track-sc0 src

    # Known bad bots (User-Agent based)
    acl bad_bot hdr_sub(User-Agent) -i -f /etc/haproxy/bad_bots.lst
    http-request deny if bad_bot

    # Empty User-Agent (common in basic bots)
    acl no_ua hdr_cnt(User-Agent) eq 0
    acl suspicious_rate sc_http_req_rate(0) gt 50
    http-request deny if no_ua suspicious_rate

    # Unique page rate (scrapers hit many unique pages)
    # Use GPC counter to track unique paths per IP
    http-request sc-inc-gpc0(0)
    http-request deny deny_status 429 if { sc_get_gpc0(0) gt 500 }

    # TLS Fingerprinting (HAProxy Enterprise)
    # http-request set-header X-TLS-Fingerprint %[ssl_fc_ja3]
    # acl known_bot_fingerprint req.hdr(X-TLS-Fingerprint) -f /etc/haproxy/bot_fingerprints.lst

    # Allow known good bots with verification
    acl is_googlebot hdr_sub(User-Agent) -i Googlebot
    acl from_google src -f /etc/haproxy/google_ips.acl
    http-request deny if is_googlebot !from_google  # Fake Googlebot
```

### Potential Check IDs
- `HAPR-BOT-001`: User-Agent based bot filtering configured
- `HAPR-BOT-002`: Rate-based bot detection using stick tables
- `HAPR-BOT-003`: Good bot verification (IP validation for claimed bot identity)
- `HAPR-BOT-004`: TLS fingerprinting enabled (Enterprise)

---

## 20. API Gateway Security Patterns

### What It Does
HAProxy functions as a full API gateway: routing, authentication, rate limiting, request transformation, and security enforcement for microservices. It combines multiple security features into a unified entry point.

### Security Benefit
- Centralized security policy enforcement across all APIs
- Per-API rate limiting and quota management
- Authentication/authorization at the gateway (JWT, OAuth, API keys)
- Request validation and transformation before reaching backends
- Protection against API-specific attacks (mass assignment, BOLA, SSRF)

### Complexity Level
**Advanced** — Requires combining multiple HAProxy features (stick tables, Lua, maps, ACLs) into a cohesive security architecture.

### Assessment Tier
**Level 2** (API gateway security patterns) / **Level 3** (full API lifecycle security)

### Key HAProxy Directives
```haproxy
frontend api_gateway
    bind *:443 ssl crt /etc/haproxy/cert.pem alpn h2,http/1.1
    mode http

    # API versioning and routing
    acl api_v1 path_beg /api/v1
    acl api_v2 path_beg /api/v2

    # Per-API rate limiting
    stick-table type string len 128 size 100k expire 1m store http_req_rate(1m)

    # Track by API key + endpoint
    http-request set-var(txn.api_key) req.hdr(X-API-Key)
    http-request track-sc0 var(txn.api_key) if { req.hdr(X-API-Key) -m found }

    # API key validation via map
    http-request deny deny_status 401 unless { req.hdr(X-API-Key) -m found }
    http-request set-var(txn.api_tier) req.hdr(X-API-Key),map(/etc/haproxy/api_keys.map)
    http-request deny deny_status 403 unless { var(txn.api_tier) -m found }

    # Tier-based rate limits
    http-request deny deny_status 429 if { var(txn.api_tier) -m str free } { sc_http_req_rate(0) gt 100 }
    http-request deny deny_status 429 if { var(txn.api_tier) -m str pro }  { sc_http_req_rate(0) gt 1000 }

    # Request body size limits per endpoint
    http-request deny deny_status 413 if api_v1 { req.body_size gt 1048576 }

    # Content-Type enforcement
    http-request deny deny_status 415 if { method POST PUT PATCH } !{ req.hdr(Content-Type) -m sub application/json }

    # Route to versioned backends
    use_backend api_v2_servers if api_v2
    use_backend api_v1_servers if api_v1
    default_backend api_404

backend api_404
    http-request deny deny_status 404
```

### Potential Check IDs
- `HAPR-APIGW-001`: API authentication enforced (JWT, API key, or OAuth)
- `HAPR-APIGW-002`: Per-API or per-consumer rate limiting configured
- `HAPR-APIGW-003`: Content-Type validation on mutation endpoints
- `HAPR-APIGW-004`: API versioning with proper routing
- `HAPR-APIGW-005`: Default backend returns 404/403 (no open fallthrough)

---

## Summary: Proposed Check Distribution by Tier

### Baseline (Current — 65 checks)
Already implemented. Core configuration hardening covering process, TLS, ACLs, headers, request handling, logging, disclosure, timeouts, backend, frontend, globals, live TLS scanning, and CVE detection.

### Level 1 — Enhanced Security Posture (~25 potential new checks)

| Category | Check ID | Description |
|----------|----------|-------------|
| SPOE/WAF | HAPR-SPOE-001 | SPOE filter present in frontends |
| Lua | HAPR-LUA-001 | `tune.lua.maxmem` set when Lua loaded |
| Lua | HAPR-LUA-002 | `tune.lua.forced-yield` configured |
| Maps | HAPR-MAP-001 | External ACL/map file permissions |
| Stick Tables | HAPR-STICK-001 | Multiple counter types tracked |
| Stick Tables | HAPR-STICK-002 | Error rate tracking enabled |
| Stick Tables | HAPR-STICK-003 | Reasonable expiry times |
| TLS Advanced | HAPR-TLSA-001 | OCSP stapling enabled |
| HTTP/2 | HAPR-H2-001 | `tune.h2.max-concurrent-streams` set |
| Peers | HAPR-PEER-001 | Peers use TLS encryption |
| Peers | HAPR-PEER-002 | Peers bind line restricts access |
| Runtime API | HAPR-API-001 | No TCP-bound stats sockets |
| Routing | HAPR-ROUTE-001 | URI normalization applied |
| Routing | HAPR-ROUTE-002 | Host header validation present |
| Routing | HAPR-ROUTE-003 | Duplicate header detection |
| Process | HAPR-PROC-005 | `nbproc` not used (deprecated) |
| DNS | HAPR-DNS-001 | Trusted DNS resolvers configured |
| PROXY | HAPR-PROXY-001 | `accept-proxy` with source restrictions |
| Compression | HAPR-COMP-001 | BREACH risk assessment |
| Cache | HAPR-CACHE-001 | Cache max-age reasonable |
| Cache | HAPR-CACHE-002 | `process-vary` enabled |

### Level 2 — Advanced Threat Protection (~20 potential new checks)

| Category | Check ID | Description |
|----------|----------|-------------|
| SPOE/WAF | HAPR-SPOE-002 | SPOE agent timeouts configured |
| SPOE/WAF | HAPR-SPOE-003 | SPOE backend health checks |
| Stick Tables | HAPR-STICK-004 | GPC counters for composite scoring |
| TLS Advanced | HAPR-TLSA-002 | mTLS `verify required` configured |
| TLS Advanced | HAPR-TLSA-003 | CRL file for client cert validation |
| TLS Advanced | HAPR-TLSA-005 | `ssl_c_verify` checked in ACLs |
| HTTP/3 | HAPR-H3-001 | QUIC with proper TLS library |
| Routing | HAPR-ROUTE-004 | Default backend defined |
| Cache | HAPR-CACHE-003 | Cache excludes auth endpoints |
| JWT | HAPR-JWT-001 | JWT signature verification enforced |
| JWT | HAPR-JWT-002 | JWT expiration validated |
| JWT | HAPR-JWT-003 | Allowed algorithms restricted |
| OIDC | HAPR-OIDC-001 | OIDC callback uses HTTPS |
| IP Rep | HAPR-IPREP-001 | IP reputation integration detected |
| Bot | HAPR-BOT-001 | User-Agent bot filtering |
| Bot | HAPR-BOT-002 | Rate-based bot detection |
| API GW | HAPR-APIGW-001 | API authentication enforced |
| API GW | HAPR-APIGW-002 | Per-API rate limiting |
| API GW | HAPR-APIGW-003 | Content-Type validation |

### Level 3 — Zero Trust / Full Stack (~10 potential new checks)

| Category | Check ID | Description |
|----------|----------|-------------|
| Zero Trust | HAPR-ZT-001 | All backend connections use `ssl verify required` |
| Zero Trust | HAPR-ZT-002 | SPIFFE/SPIRE SVID certificates |
| Zero Trust | HAPR-ZT-003 | Certificate-based routing enforced |
| Zero Trust | HAPR-ZT-004 | Default backend denies unknown certs |
| TLS Advanced | HAPR-TLSA-004 | Client cert fields logged for audit |
| IP Rep | HAPR-IPREP-003 | Block + CAPTCHA remediation paths |
| Bot | HAPR-BOT-003 | Good bot verification |
| Bot | HAPR-BOT-004 | TLS fingerprinting enabled |
| OIDC | HAPR-OIDC-002 | Client secrets not hardcoded |
| OIDC | HAPR-OIDC-003 | Session cookies secured |
| API GW | HAPR-APIGW-004 | API versioning with routing |
| API GW | HAPR-APIGW-005 | Default backend denies (no fallthrough) |

---

## Sources

### SPOE/WAF
- [Extending HAProxy with SPOE](https://www.haproxy.com/blog/extending-haproxy-with-the-stream-processing-offload-engine)
- [Coraza SPOA](https://coraza.io/connectors/coraza-spoa/)
- [CrowdSec HAProxy SPOA](https://docs.crowdsec.net/u/bouncers/haproxy_spoa/)
- [ModSecurity SPOA](https://github.com/jcmoraisjr/modsecurity-spoa)

### Lua Security
- [HAProxy Lua Architecture](https://www.arpalert.org/haproxy-lua.html)
- [Lua Scripting DeepWiki](https://deepwiki.com/haproxy/haproxy/5.1-lua-scripting)
- [HAProxy Lua API Introduction](https://www.haproxy.com/documentation/haproxy-lua-api/getting-started/introduction/)
- [5 Ways to Extend HAProxy with Lua](https://www.haproxy.com/blog/5-ways-to-extend-haproxy-with-lua)

### Stick Tables and DDoS
- [Application-Layer DDoS Protection](https://www.haproxy.com/blog/application-layer-ddos-attack-protection-with-haproxy)
- [Introduction to Stick Tables](https://www.haproxy.com/blog/introduction-to-haproxy-stick-tables)
- [Bot Protection with HAProxy](https://www.haproxy.com/blog/bot-protection-with-haproxy)
- [DDoS Protection and Rate Limiting](https://www.haproxy.com/solutions/ddos-protection-and-rate-limiting)

### TLS Advanced
- [mTLS with Client Certificates](https://www.haproxy.com/blog/restrict-api-access-with-client-certificates-mtls)
- [OCSP Stapling Tutorial](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/security/ssl-tls/ocsp-stapling/)
- [Zero-Trust mTLS with SPIFFE/SPIRE](https://www.haproxy.com/blog/zero-trust-mtls-automation-with-haproxy-and-spiffe-spire)

### HTTP/2 and HTTP/3
- [How to Enable QUIC Load Balancing](https://www.haproxy.com/blog/how-to-enable-quic-load-balancing-on-haproxy)
- [Announcing HAProxy 3.3](https://www.haproxy.com/blog/announcing-haproxy-3-3)

### Peers
- [Peers Configuration](https://www.haproxy.com/documentation/hapee/latest/configuration/config-sections/peers/)
- [Encrypt Peers Traffic](https://www.haproxy.com/documentation/hapee/latest/high-availability/active-active/stick-table-aggregator/encrypt-traffic/)

### Runtime API
- [Dynamic Configuration with Runtime API](https://www.haproxy.com/blog/dynamic-configuration-haproxy-runtime-api)
- [Runtime API Installation](https://www.haproxy.com/documentation/haproxy-runtime-api/installation/)

### Content Switching / HTTP Smuggling
- [CVE-2021-40346 HTTP Smuggling](https://jfrog.com/blog/critical-vulnerability-in-haproxy-cve-2021-40346-integer-overflow-enables-http-smuggling/)
- [HAProxy Content Switching](https://www.haproxy.com/support/technical-notes/an-0057-en-content-switching)
- [CVE-2024-45506 HTTP/2 Loop](https://www.haproxy.com/blog/cve-2024-45506)

### Multi-Thread
- [Multithreading in HAProxy](https://www.haproxy.com/blog/multithreading-in-haproxy)

### Maps and ACLs
- [HAProxy ACLs Complete Guide](https://www.haproxy.com/blog/introduction-to-haproxy-acls)
- [Map Files Tutorial](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/proxying-essentials/custom-rules/map-files/)

### DNS
- [DNS Service Discovery](https://www.haproxy.com/blog/dns-service-discovery-haproxy)
- [DNS Resolution Tutorial](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/dns-resolution/)

### PROXY Protocol
- [PROXY Protocol Specification](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt)
- [PROXY Protocol to Secure Database](https://www.haproxy.com/blog/using-haproxy-with-the-proxy-protocol-to-better-secure-your-database)
- [Preserve Client IP with PROXY Protocol](https://www.haproxy.com/blog/use-the-proxy-protocol-to-preserve-a-clients-ip-address)

### Compression
- [HAProxy Compression Tutorial](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/performance/compression/)
- [BREACH Attack](https://www.startupdefense.io/cyberattacks/breach-attack)

### Cache
- [HAProxy Caching Tutorial](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/performance/caching/)

### JWT
- [Verify OAuth JWT Tokens](https://www.haproxy.com/blog/verify-oauth-jwt-tokens-with-haproxy)
- [OAuth 2.0 Authorization Tutorial](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/security/authentication/oauth-authorization/)

### OIDC/OAuth
- [OIDC SSO Enterprise](https://www.haproxy.com/documentation/haproxy-enterprise/enterprise-modules/single-sign-on/sso-openid-connect/)
- [OIDC with HAProxy and Keycloak](https://mackdanz.net/Add-OIDC-single-sign-on-to-any-website-with-HAProxy-and-Keycloak)
- [API Gateway Part 2: Authentication](https://www.haproxy.com/blog/using-haproxy-as-an-api-gateway-part-2-authentication)

### IP Reputation
- [CrowdSec HAProxy Bouncer](https://docs.crowdsec.net/u/bouncers/haproxy/)
- [CrowdSec Bouncer GitHub](https://github.com/crowdsecurity/cs-haproxy-bouncer)

### Bot Management
- [Bot Protection with HAProxy](https://www.haproxy.com/blog/bot-protection-with-haproxy)
- [Fingerprint Module](https://www.haproxy.com/documentation/hapee/latest/security/bot-management/fingerprint-module/)

### API Gateway
- [API Gateway Part 1: Introduction](https://www.haproxy.com/blog/using-haproxy-as-an-api-gateway-part-1-introduction)
- [API Gateway Part 6: Security](https://www.haproxy.com/blog/using-haproxy-as-an-api-gateway-part-6-security)
- [HAProxy API Gateway at Baeldung](https://www.baeldung.com/devops-haproxy-api-gateway)
