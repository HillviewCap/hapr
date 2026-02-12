# HAProxy Security Guide

HAProxy is one of the most widely deployed reverse proxies and load balancers, yet no CIS benchmark exists for it. This guide provides a brief overview of HAProxy's security-relevant features organized by topic, with curated reference links for deeper learning.

---

## Process Hardening

HAProxy should run with minimal privileges. Key directives:

- **`chroot`** -- Confine the process to a restricted directory tree, limiting filesystem access if compromised.
- **`user` / `group`** -- Drop privileges to a dedicated non-root service account after binding to privileged ports.
- **`daemon`** -- Run as a background service, integrating with init systems.
- **`ulimit-n`** -- Set file descriptor limits to prevent resource exhaustion under load.
- **`nbthread`** -- Use threading (not the deprecated `nbproc`) for multi-core utilization with proper shared state.

**References:**
- [HAProxy Configuration Manual - Global Parameters](https://www.haproxy.com/documentation/haproxy-configuration-manual/latest/#3)
- [SOCFortress HAProxy Hardening Guide](https://socfortress.medium.com/haproxy-secure-deployment-hardening-guide-e03a6ba16a54)
- [Multithreading in HAProxy](https://www.haproxy.com/blog/multithreading-in-haproxy)

---

## TLS/SSL Configuration

Proper TLS configuration is foundational to HAProxy security:

- **Minimum TLS version** -- Enforce TLS 1.2+ with `ssl-min-ver TLSv1.2` or `ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11`.
- **Cipher suites** -- Restrict to strong ciphers. Configure both TLS 1.2 ciphers and TLS 1.3 ciphersuites separately.
- **HSTS** -- Add `Strict-Transport-Security` headers to prevent protocol downgrade attacks.
- **DH parameters** -- Use 2048-bit or larger Diffie-Hellman parameters with `tune.ssl.default-dh-param`.
- **Session tickets** -- Disable TLS session tickets (`no-tls-tickets`) to ensure forward secrecy.
- **OCSP stapling** -- Enable OCSP stapling for faster handshakes and improved revocation checking.

**References:**
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [HAProxy SSL/TLS Tutorials](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/security/ssl-tls/)
- [OCSP Stapling Tutorial](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/security/ssl-tls/ocsp-stapling/)
- [BetterCrypto Applied Crypto Hardening](https://github.com/BetterCrypto/Applied-Crypto-Hardening)
- [NIST SP 800-52 Rev. 2 -- TLS Guidelines](https://csrc.nist.gov/pubs/sp/800/52/r2/final)

---

## Mutual TLS (mTLS)

For zero-trust and service-to-service authentication, HAProxy supports client certificate verification:

- **`verify required`** -- Require clients to present valid certificates.
- **`ca-file`** -- Specify the CA that issued client certificates.
- **`crl-file`** -- Check client certificates against a revocation list.
- **SPIFFE/SPIRE** -- Integration for automatic certificate issuance and rotation in service mesh architectures.

**References:**
- [mTLS with Client Certificates](https://www.haproxy.com/blog/restrict-api-access-with-client-certificates-mtls)
- [Zero-Trust mTLS with SPIFFE/SPIRE](https://www.haproxy.com/blog/zero-trust-mtls-automation-with-haproxy-and-spiffe-spire)

---

## Access Control and Rate Limiting

HAProxy provides multiple mechanisms for controlling access:

- **ACLs** -- Define rules based on source IP, path, headers, and other request attributes.
- **Stick tables** -- In-memory stores that track per-client state (connection rates, request rates, error rates) for real-time abuse detection.
- **Rate limiting** -- Combine stick tables with ACL rules to deny or tarpit clients exceeding thresholds.
- **Stats page security** -- Protect the stats page with authentication and source IP restrictions.

**References:**
- [Introduction to HAProxy ACLs](https://www.haproxy.com/blog/introduction-to-haproxy-acls)
- [Introduction to HAProxy Stick Tables](https://www.haproxy.com/blog/introduction-to-haproxy-stick-tables)
- [Application-Layer DDoS Protection](https://www.haproxy.com/blog/application-layer-ddos-attack-protection-with-haproxy)
- [DDoS Protection and Rate Limiting](https://www.haproxy.com/solutions/ddos-protection-and-rate-limiting)

---

## HTTP Security Headers

HAProxy can inject security headers into responses to protect clients:

- **X-Frame-Options** -- Prevent clickjacking
- **Content-Security-Policy** -- Control resource loading
- **X-Content-Type-Options** -- Prevent MIME sniffing
- **Referrer-Policy** -- Control referrer information
- **Permissions-Policy** -- Restrict browser features
- **Cross-Origin headers** (COOP, COEP, CORP) -- Isolate cross-origin resources

**References:**
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)

---

## Request Handling and Smuggling Prevention

Protect against request-level attacks:

- **Body size limits** -- Use `tune.bufsize` and ACL-based body size checks to prevent oversized requests.
- **URL length limits** -- Restrict URL length to prevent buffer-related attacks.
- **Method filtering** -- Allow only expected HTTP methods (GET, POST, etc.).
- **HTTP request smuggling** -- HAProxy has been subject to smuggling vulnerabilities (CVE-2021-40346, CVE-2023-25725). Keep HAProxy updated and use the HTX engine.
- **HTTP/2 limits** -- Configure `tune.h2.max-concurrent-streams` to prevent stream flooding.

**References:**
- [CVE-2021-40346 HTTP Smuggling Analysis](https://jfrog.com/blog/critical-vulnerability-in-haproxy-cve-2021-40346-integer-overflow-enables-http-smuggling/)
- [CVE-2024-45506 HTTP/2 Loop](https://www.haproxy.com/blog/cve-2024-45506)
- [How to Enable QUIC Load Balancing](https://www.haproxy.com/blog/how-to-enable-quic-load-balancing-on-haproxy)

---

## Logging and Monitoring

Proper logging is essential for incident detection and compliance:

- **`log` directive** -- Send logs to syslog. Use `log stdout format raw local0` for containerized environments.
- **Log format** -- Use `option httplog` for detailed HTTP logging or define custom log formats.
- **Log level** -- Set appropriate levels (`info` or `notice` for production).
- **Remote syslog** -- Forward logs to a central syslog server for retention and analysis.
- **`option dontlognull`** -- Suppress logging of health check probes and port scans.

**References:**
- [HAProxy Logging Configuration](https://www.haproxy.com/blog/introduction-to-haproxy-logging)

---

## Information Disclosure Prevention

Reduce the information available to attackers:

- **Remove server headers** -- Use `http-response del-header Server` to hide backend technology.
- **Custom error pages** -- Replace default error pages that may reveal version information.
- **Hide version** -- Use `http-response del-header X-Powered-By` and configure `stats hide-version`.
- **XFF spoofing prevention** -- Use `http-request del-header X-Forwarded-For` before setting it to prevent client-side spoofing.

**References:**
- [Airship HAProxy Security Guide](https://airshipit.readthedocs.io/en/latest/security/haproxy.html)

---

## Timeouts

Properly configured timeouts prevent resource exhaustion:

- **`timeout client`** -- Maximum time to wait for client data.
- **`timeout server`** -- Maximum time to wait for server response.
- **`timeout connect`** -- Maximum time to wait for a connection to a backend server.
- **`timeout http-request`** -- Critical for slowloris defense. Limits how long HAProxy waits for the complete HTTP request.
- **`timeout http-keep-alive`** -- Limits idle keepalive connections.

All timeouts should be explicitly set in the `defaults` section. Unreasonably long values (e.g., hours) are as problematic as missing timeouts.

---

## SPOE/SPOA -- WAF Integration

The Stream Processing Offload Engine (SPOE) sends traffic to external agents for inspection:

- **ModSecurity SPOA** -- Classic WAF engine
- **Coraza SPOA** -- OWASP Coraza WAF with CRS v4
- **CrowdSec SPOA** -- IP reputation, WAF, and CAPTCHA challenges

This enables OWASP Top 10 attack blocking (SQLi, XSS, RCE) at the proxy layer.

**References:**
- [Extending HAProxy with SPOE](https://www.haproxy.com/blog/extending-haproxy-with-the-stream-processing-offload-engine)
- [Coraza SPOA](https://coraza.io/connectors/coraza-spoa/)
- [CrowdSec HAProxy SPOA](https://docs.crowdsec.net/u/bouncers/haproxy_spoa/)

---

## Lua Scripting Security

HAProxy embeds a Lua interpreter for custom logic (authentication, token validation, dynamic routing):

- **`tune.lua.maxmem`** -- Set memory limits to prevent exhaustion.
- **`tune.lua.forced-yield`** -- Force yield to prevent blocking the event loop.
- **Security risks** -- No sandbox by default, blocking I/O, memory leaks. Use with caution.

**References:**
- [HAProxy Lua API Introduction](https://www.haproxy.com/documentation/haproxy-lua-api/getting-started/introduction/)
- [5 Ways to Extend HAProxy with Lua](https://www.haproxy.com/blog/5-ways-to-extend-haproxy-with-lua)
- [HAProxy Lua Architecture](https://www.arpalert.org/haproxy-lua.html)

---

## Maps and ACL Files

Externalize access control rules for dynamic management:

- **Map files** -- Key-value lookups for routing and decision-making.
- **ACL files** -- External pattern lists for blocklists and allowlists.
- **Runtime API updates** -- Modify maps and ACLs without reloading via the stats socket.

**References:**
- [Map Files Tutorial](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/proxying-essentials/custom-rules/map-files/)
- [HAProxy ACLs Complete Guide](https://www.haproxy.com/blog/introduction-to-haproxy-acls)

---

## Runtime API (Stats Socket)

The HAProxy Runtime API provides real-time control and monitoring:

- **Access levels** -- `user` (view-only), `operator` (limited control), `admin` (full access).
- **Socket permissions** -- Restrict via Unix permissions (`mode 660`, `user`, `group`).
- **Avoid TCP binding** -- TCP-exposed sockets have no encryption or authentication. Use Unix sockets.

**References:**
- [Dynamic Configuration with Runtime API](https://www.haproxy.com/blog/dynamic-configuration-haproxy-runtime-api)
- [Runtime API Installation](https://www.haproxy.com/documentation/haproxy-runtime-api/installation/)

---

## HAProxy Peers

Peers replicate stick table data between HAProxy nodes for consistent rate limiting and session persistence:

- **Security risk** -- Peers traffic is unencrypted by default. Use TLS encryption for peer connections.
- **Access restriction** -- Bind peer ports to internal networks only.

**References:**
- [Peers Configuration](https://www.haproxy.com/documentation/hapee/latest/configuration/config-sections/peers/)
- [Encrypt Peers Traffic](https://www.haproxy.com/documentation/hapee/latest/high-availability/active-active/stick-table-aggregator/encrypt-traffic/)

---

## PROXY Protocol

The PROXY protocol preserves original client IP addresses through proxy chains:

- **Trust boundary** -- Only accept PROXY protocol headers from trusted upstream proxies. Untrusted sources can spoof IPs, bypassing all IP-based security.
- **Source restrictions** -- Always pair `accept-proxy` with source IP ACLs.

**References:**
- [PROXY Protocol Specification](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt)
- [Preserve Client IP with PROXY Protocol](https://www.haproxy.com/blog/use-the-proxy-protocol-to-preserve-a-clients-ip-address)

---

## Compression and BREACH

HTTP compression improves performance but introduces a side-channel risk:

- **BREACH attack (CVE-2013-3587)** -- When compression is applied to responses containing secrets (CSRF tokens, session IDs), an attacker who can inject content can extract those secrets through compressed size changes.
- **Mitigation** -- Avoid compressing `text/html` and `application/json` that contain tokens. Only compress static assets.

**References:**
- [HAProxy Compression Tutorial](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/performance/compression/)

---

## Cache Security

HAProxy's built-in HTTP cache can introduce poisoning risks:

- **Cache poisoning** -- Unkeyed request headers can cause malicious content to be cached and served to legitimate users.
- **`process-vary on`** -- Respect the Vary header to prevent cross-user content serving.
- **Short max-age** -- Limit cache duration to reduce the poisoning window.
- **Exclude authenticated endpoints** -- Never cache responses for API or authenticated routes.

**References:**
- [HAProxy Caching Tutorial](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/performance/caching/)

---

## JWT and OAuth

HAProxy 2.5+ supports built-in JWT validation at the proxy layer:

- **Signature verification** -- Validate RS256, HS256, or ES256 signatures.
- **Claim validation** -- Check issuer, audience, and expiration claims.
- **Algorithm restriction** -- Explicitly restrict allowed algorithms to prevent `alg: none` bypass attacks.

**References:**
- [Verify OAuth JWT Tokens](https://www.haproxy.com/blog/verify-oauth-jwt-tokens-with-haproxy)
- [OAuth 2.0 Authorization Tutorial](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/security/authentication/oauth-authorization/)
- [Using HAProxy as an API Gateway - Authentication](https://www.haproxy.com/blog/using-haproxy-as-an-api-gateway-part-2-authentication)

---

## Bot Detection and IP Reputation

Multiple strategies for managing automated traffic:

- **User-Agent filtering** -- Block known bad bot signatures.
- **Rate-based detection** -- Use stick tables to identify non-human request patterns.
- **CrowdSec integration** -- Community-sourced IP reputation with automated blocking and CAPTCHA.
- **TLS fingerprinting** -- JA3/JA4 fingerprints to identify bot TLS stacks (Enterprise feature).

**References:**
- [Bot Protection with HAProxy](https://www.haproxy.com/blog/bot-protection-with-haproxy)
- [CrowdSec HAProxy Bouncer](https://docs.crowdsec.net/u/bouncers/haproxy/)
- [Fingerprint Module (Enterprise)](https://www.haproxy.com/documentation/hapee/latest/security/bot-management/fingerprint-module/)

---

## API Gateway Patterns

HAProxy can function as a full API gateway:

- **Per-API rate limiting** -- Track requests by API key or consumer.
- **Authentication enforcement** -- JWT, OAuth, or API key validation at the gateway.
- **Content-Type validation** -- Reject mutation requests without proper content types.
- **API versioning** -- Route to versioned backends based on URL path.

**References:**
- [API Gateway Introduction](https://www.haproxy.com/blog/using-haproxy-as-an-api-gateway-part-1-introduction)
- [API Gateway Security](https://www.haproxy.com/blog/using-haproxy-as-an-api-gateway-part-6-security)
- [HAProxy API Gateway at Baeldung](https://www.baeldung.com/devops-haproxy-api-gateway)

---

## Industry Standards References

- [DISA STIG Web Server SRG](https://www.cyber.mil/stigs/)
- [NIST SP 800-52 Rev. 2 -- TLS Guidelines](https://csrc.nist.gov/pubs/sp/800/52/r2/final)
- [NIST SP 800-53 -- Security Controls](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [NIST SP 800-123 -- Server Security](https://csrc.nist.gov/pubs/sp/800/123/final)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [PCI DSS 4.0](https://www.pcisecuritystandards.org/)
- [SOC 2 Trust Services Criteria](https://secureframe.com/hub/soc-2/controls)
- [HAProxy Configuration Tutorials](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/)
- [HAProxy Security Knowledge Base](https://www.haproxy.com/knowledge-base/security)
