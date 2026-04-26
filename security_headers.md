# 🔒 Essential Security Headers — Complete Guide
### Short, Deep, Interview-Ready | How Each Header Kills a Vulnerability

> **What are Security Headers?**
> HTTP response headers sent by the **server to the browser** that instruct the browser how to behave when handling your site's content. They are your **last line of client-side defense** — one line of config, massive security gain.

---

## 🗺️ Quick Reference — All Headers at a Glance

| Header | Kills | Priority |
|--------|-------|----------|
| `Content-Security-Policy` | XSS, Clickjacking, Data Injection | 🔴 Critical |
| `Strict-Transport-Security` | SSL Stripping, MITM, Downgrade Attacks | 🔴 Critical |
| `X-Frame-Options` | Clickjacking | 🟠 High |
| `X-Content-Type-Options` | MIME Sniffing, Drive-by Downloads | 🟠 High |
| `Referrer-Policy` | Sensitive URL Leakage | 🟡 Medium |
| `Permissions-Policy` | Feature Abuse (Camera, Mic, GPS) | 🟡 Medium |
| `Cache-Control` | Sensitive Data in Cache | 🟡 Medium |
| `Cross-Origin-Opener-Policy` | Cross-Origin Info Leaks, Spectre | 🟠 High |
| `Cross-Origin-Embedder-Policy` | Spectre Side-Channel Attacks | 🟠 High |
| `Cross-Origin-Resource-Policy` | Cross-Origin Data Theft | 🟡 Medium |
| `X-XSS-Protection` | Legacy XSS (deprecated but common) | ⚪ Legacy |
| `Expect-CT` | Rogue TLS Certificates | ⚪ Deprecated |

---

---

## 1. Content-Security-Policy (CSP)
### 🏆 The Most Powerful Security Header

### What It Does
Tells the browser **exactly which sources are trusted** for every type of resource — scripts, styles, images, fonts, frames, and more. Any resource not on the whitelist gets **blocked by the browser before it even loads**.

### Vulnerability It Kills
**XSS (Cross-Site Scripting)** — Even if an attacker injects a `<script>` tag, CSP prevents the browser from executing it unless the source is explicitly whitelisted.

```
# Without CSP — attacker's injected script runs freely:
<script src="https://evil.com/steal-cookies.js"></script>  ✅ Browser executes it

# With CSP — browser checks the source against the policy and blocks it:
<script src="https://evil.com/steal-cookies.js"></script>  ❌ Browser blocks it
```

### Header Syntax
```
Content-Security-Policy: <directive> <source-list>; <directive> <source-list>;
```

### Essential Directives Explained

| Directive | Controls | Example Value |
|-----------|----------|---------------|
| `default-src` | Fallback for all resource types | `'self'` |
| `script-src` | JavaScript sources | `'self' https://cdn.trusted.com` |
| `style-src` | CSS sources | `'self' https://fonts.googleapis.com` |
| `img-src` | Image sources | `'self' data: https:` |
| `font-src` | Font sources | `'self' https://fonts.gstatic.com` |
| `connect-src` | XHR/fetch/WebSocket targets | `'self' https://api.myapp.com` |
| `frame-src` | Allowed iframes | `'none'` |
| `object-src` | Plugin content (Flash, etc.) | `'none'` |
| `base-uri` | Restricts `<base>` tag | `'self'` |
| `form-action` | Where forms can submit | `'self'` |
| `upgrade-insecure-requests` | Auto-upgrade HTTP → HTTPS | (no value needed) |
| `report-uri` | Where to send violation reports | `https://report.myapp.com/csp` |

### Source Keyword Values

| Keyword | Meaning | Use |
|---------|---------|-----|
| `'self'` | Same origin only | ✅ Always include |
| `'none'` | Block everything | ✅ For `object-src`, `frame-src` |
| `'unsafe-inline'` | Allow inline scripts/styles | ❌ Defeats XSS protection |
| `'unsafe-eval'` | Allow eval(), setTimeout(string) | ❌ Avoid unless required |
| `'nonce-{value}'` | Allow specific inline block with matching nonce | ✅ Best for inline scripts |
| `'strict-dynamic'` | Trust scripts loaded by trusted scripts | ✅ Modern approach |
| `https:` | Any HTTPS source | ⚠️ Too permissive |

### Production-Grade Values

```http
# 🟢 STRICT — Best for new apps (no inline scripts)
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'nonce-{RANDOM_NONCE}';
  style-src 'self' 'nonce-{RANDOM_NONCE}';
  img-src 'self' data: https:;
  font-src 'self' https://fonts.gstatic.com;
  connect-src 'self' https://api.myapp.com;
  object-src 'none';
  base-uri 'self';
  form-action 'self';
  frame-ancestors 'none';
  upgrade-insecure-requests;
  report-uri https://csp.myapp.com/report;

# 🟡 MODERATE — For apps using CDNs and inline scripts
Content-Security-Policy:
  default-src 'self';
  script-src 'self' https://cdn.jsdelivr.net https://ajax.googleapis.com;
  style-src 'self' https://fonts.googleapis.com 'unsafe-inline';
  img-src 'self' data: https:;
  object-src 'none';
  frame-ancestors 'self';

# 🔵 REPORT-ONLY — For testing CSP without breaking anything
Content-Security-Policy-Report-Only:
  default-src 'self';
  report-uri https://csp.myapp.com/report;
```

### How Nonce Works (The Right Way to Allow Inline Scripts)
```html
<!-- Server generates a fresh random nonce on every request -->
<!-- Python: nonce = secrets.token_hex(16) -->

<!-- In HTTP Header: -->
Content-Security-Policy: script-src 'nonce-abc123xyz'

<!-- In HTML: Only this specific block runs — attacker's injected script won't have the nonce -->
<script nonce="abc123xyz">
  // This trusted inline code runs ✅
</script>

<script>
  evil_code();  // No nonce → browser blocks this ❌
</script>
```

### frame-ancestors vs X-Frame-Options
> `frame-ancestors 'none'` in CSP is the **modern replacement** for `X-Frame-Options: DENY`. Use both for maximum browser compatibility.

---

---

## 2. Strict-Transport-Security (HSTS)
### Forces HTTPS — No Exceptions

### What It Does
Tells the browser: **"This site only works over HTTPS. Never try HTTP. Ever."** Once a browser sees this header, it will automatically upgrade all future requests to HTTPS — even if you type `http://` manually.

### Vulnerability It Kills
**SSL Stripping / MITM (Man-in-the-Middle) Attack / Protocol Downgrade Attack**

```
# Without HSTS — SSL Stripping Attack:
User types: mybank.com  →  Browser first tries: http://mybank.com
Attacker intercepts the HTTP request (you're on public WiFi)
Attacker serves fake HTTP version while talking to real HTTPS site
User never sees HTTPS — session hijacked ❌

# With HSTS — SSL Stripping fails completely:
Browser remembers: "mybank.com = HTTPS only, never HTTP"
Browser directly requests: https://mybank.com  →  Attacker can't intercept ✅
```

### Header Values

```http
# 🟡 BASIC — 6 months, current domain only
Strict-Transport-Security: max-age=15768000

# 🟢 RECOMMENDED — 1 year, includes subdomains
Strict-Transport-Security: max-age=31536000; includeSubDomains

# 🏆 BEST — 2 years + HSTS Preload List (browsers hardcode your domain as HTTPS-only)
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

### Directive Breakdown

| Directive | Meaning |
|-----------|---------|
| `max-age=<seconds>` | How long the browser remembers this rule (minimum 1 year = 31536000) |
| `includeSubDomains` | Applies to all subdomains (api., admin., mail.) — ⚠️ ensure ALL subdomains have HTTPS |
| `preload` | Submit to browser preload lists — domain hardcoded in Chrome/Firefox/Edge source code |

### HSTS Preload List
> Sites on the preload list get HTTPS-only behavior **before they are ever visited** — the protection is baked into the browser itself. Submit your domain at: **hstspreload.org**

### ⚠️ Important Warning
```
# NEVER set HSTS on a site that might not always have HTTPS
# If your cert expires or you switch back to HTTP:
# → All users are LOCKED OUT until max-age expires!

# Safe rollout strategy:
Step 1: max-age=300 (5 min) — test nothing breaks
Step 2: max-age=86400 (1 day) — monitor for issues
Step 3: max-age=2592000 (30 days) — getting confident
Step 4: max-age=31536000; includeSubDomains; preload — production ready
```

---

---

## 3. X-Frame-Options
### Prevents Clickjacking

### What It Does
Controls whether your page can be embedded inside an `<iframe>`, `<frame>`, or `<object>` on another site. Clickjacking attacks layer a transparent iframe of your site over a fake button — the user thinks they're clicking "Win a prize!" but they're actually clicking "Transfer $1000."

### Vulnerability It Kills
**Clickjacking (UI Redressing)**

```
# Clickjacking Attack — Without X-Frame-Options:

<!-- Attacker's malicious page -->
<style>
  iframe { opacity: 0; position: absolute; top: 0; left: 0; }
  .fake-button { position: absolute; top: 120px; left: 60px; }
</style>
<button class="fake-button">🎁 Click here to Win!</button>
<iframe src="https://yourbank.com/transfer?amount=5000&to=hacker"></iframe>

<!-- User clicks "Win!" → Actually clicks the hidden "Confirm Transfer" button! -->
```

### Header Values

```http
# Block all framing — recommended for most apps
X-Frame-Options: DENY

# Allow framing only from same origin (your own site)
X-Frame-Options: SAMEORIGIN

# Allow from specific URI (deprecated — poor browser support)
X-Frame-Options: ALLOW-FROM https://trusted-partner.com  ⚠️ Not widely supported
```

### Modern Replacement
```http
# CSP frame-ancestors is the modern, more flexible solution
Content-Security-Policy: frame-ancestors 'none';          # Same as DENY
Content-Security-Policy: frame-ancestors 'self';          # Same as SAMEORIGIN
Content-Security-Policy: frame-ancestors https://partner.com;  # Specific origin

# Best Practice: Set BOTH for maximum browser compatibility
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none';
```

---

---

## 4. X-Content-Type-Options
### Stops MIME Sniffing

### What It Does
Forces the browser to respect the `Content-Type` header you declare, rather than "sniffing" (guessing) what a file actually is based on its content. Without this, a browser might decide an uploaded `.txt` file is actually JavaScript and execute it.

### Vulnerability It Kills
**MIME Sniffing / Content Type Confusion / Drive-by Download Execution**

```
# MIME Sniffing Attack — Without this header:

# Attacker uploads a file named "photo.jpg" to a user-upload feature
# The file's actual content is: <script>document.location='https://evil.com'</script>
# Without this header, Chrome might sniff it, say "this looks like HTML/JS!" and execute it
# With this header, browser sees Content-Type: image/jpeg and refuses to execute it ✅
```

### Header Value

```http
# Only one valid value — no alternatives
X-Content-Type-Options: nosniff
```

> `nosniff` tells the browser: **"Trust my Content-Type, do not guess."**
> - For scripts and stylesheets: if Content-Type doesn't match, browser blocks the load
> - Prevents browsers from executing uploaded files with wrong/missing MIME types
> - Also blocks "drive-by download" style attacks

---

---

## 5. Referrer-Policy
### Controls URL Leakage in Referer Header

### What It Does
When a user clicks a link from your site to another site, the browser sends the `Referer` header with the full URL of the page they came from. This leaks sensitive information hidden in URLs — like search queries, user IDs, reset tokens, or session parameters.

### Vulnerability It Kills
**Sensitive URL / Token Leakage via Referrer Header**

```
# Without Referrer-Policy — Information Leakage:

# User is on: https://myapp.com/reset-password?token=abc123SECRET
# They click an external link (ad, social share button, etc.)
# Browser sends to the external site:
Referer: https://myapp.com/reset-password?token=abc123SECRET
# External site logs this → attacker has the reset token! ❌

# Other leakage examples:
Referer: https://myapp.com/users/search?query=confidential+project
Referer: https://myapp.com/admin/internal-report?id=9876
```

### Header Values (From Most → Least Restrictive)

```http
# 🏆 STRICTEST — Sends nothing at all
Referrer-Policy: no-referrer

# 🟢 RECOMMENDED — Only sends origin (no path/query) when going cross-origin
# Same-origin: sends full URL | Cross-origin: sends only https://myapp.com
Referrer-Policy: strict-origin-when-cross-origin

# Sends only origin to all destinations (no path ever)
Referrer-Policy: strict-origin

# Sends full URL for same-origin, nothing for cross-origin
Referrer-Policy: same-origin

# ❌ WORST — Sends full URL everywhere (browser default in older browsers)
Referrer-Policy: unsafe-url
```

### Recommended Value
```http
Referrer-Policy: strict-origin-when-cross-origin
```
> This is the **Chrome/Firefox browser default** since 2020 — but explicitly setting it ensures consistent behavior across all browsers.

---

---

## 6. Permissions-Policy (formerly Feature-Policy)
### Disables Browser Features You Don't Need

### What It Does
Gives you fine-grained control over which browser APIs and hardware features your page (and embedded iframes) can access. If your app doesn't need the microphone, **disable it at the header level** — even if XSS runs, it can't hijack the mic.

### Vulnerability It Kills
**Unauthorized Feature/Hardware Access via XSS or Malicious Iframes**

```
# Without Permissions-Policy — XSS gets full feature access:
# Attacker injects XSS → JavaScript grabs the camera stream → exfiltrates video

# With Permissions-Policy: camera=() — camera API is blocked regardless:
navigator.mediaDevices.getUserMedia({ video: true })
→ Permission denied: feature policy blocks camera access ✅
```

### Header Syntax & Values

```http
# Syntax: feature=(allowlist)
# () = nobody   'self' = only same origin   * = everyone

# 🟢 RECOMMENDED — Lock down everything not used
Permissions-Policy:
  camera=(),
  microphone=(),
  geolocation=(),
  payment=(),
  usb=(),
  bluetooth=(),
  accelerometer=(),
  gyroscope=(),
  magnetometer=(),
  display-capture=()

# 🟡 IF YOU USE SOME FEATURES — Allow only what you need
Permissions-Policy:
  camera=(self),
  geolocation=(self "https://maps.partner.com"),
  microphone=(),
  payment=(self)
```

### Common Controllable Features

| Feature | Controls | Recommended |
|---------|----------|-------------|
| `camera` | Webcam access | `()` (deny) unless you need it |
| `microphone` | Mic access | `()` (deny) |
| `geolocation` | GPS/Location | `(self)` or `()` |
| `payment` | Payment Request API | `(self)` or `()` |
| `usb` | USB device access | `()` (deny) |
| `bluetooth` | Bluetooth API | `()` (deny) |
| `fullscreen` | Fullscreen API | `(self)` |
| `display-capture` | Screen sharing | `()` (deny) |
| `accelerometer` | Device motion sensors | `()` (deny) |
| `autoplay` | Auto-playing media | `()` (deny) |

---

---

## 7. Cache-Control
### Prevents Sensitive Data Being Cached

### What It Does
Controls how browsers and intermediate proxies (CDNs, ISPs) cache your responses. For pages containing sensitive data (account info, payment details, medical records), caching is dangerous — a shared computer's browser cache is a goldmine for the next user.

### Vulnerability It Kills
**Sensitive Data Exposure via Browser/Proxy Cache**

```
# Without Cache-Control on a banking page:
User logs into bank → views account balance
User closes browser on a shared/public computer
Next person presses Back button → sees previous user's account details! ❌

# Also: CDN or proxy caches your authenticated page and serves it to others
```

### Header Values

```http
# 🔴 FOR SENSITIVE PAGES (banking, health, personal data, admin panels)
Cache-Control: no-store, no-cache, must-revalidate, private

# 🟡 FOR SEMI-DYNAMIC CONTENT (authenticated but not super sensitive)
Cache-Control: no-cache, private

# 🟢 FOR STATIC ASSETS (JS, CSS, images that change infrequently)
Cache-Control: public, max-age=31536000, immutable

# 🟢 FOR STATIC ASSETS THAT CHANGE SOMETIMES
Cache-Control: public, max-age=86400, stale-while-revalidate=3600
```

### Directive Reference

| Directive | Meaning |
|-----------|---------|
| `no-store` | **Never cache this response anywhere** — not in browser, not in proxy |
| `no-cache` | Can cache but must revalidate with server before using |
| `private` | Only browser can cache it — CDNs/proxies must not |
| `public` | Anyone can cache it (browser + CDN + proxy) |
| `must-revalidate` | Once stale, must revalidate before serving |
| `max-age=<seconds>` | How long the response is considered fresh |
| `immutable` | File will never change — skip revalidation |
| `stale-while-revalidate` | Serve stale content while fetching fresh in background |

### Pragma Header (Legacy)
```http
# Old HTTP/1.0 equivalent — include for old proxy/cache compatibility
Pragma: no-cache

# Use alongside Cache-Control for maximum coverage
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
```

---

---

## 8. Cross-Origin-Opener-Policy (COOP)
### Isolates Your Browsing Context

### What It Does
Prevents other websites from getting a reference to your page's window object via `window.opener` or `window.open()`. Without this, a malicious site you link to (or that opens you in a popup) can execute JavaScript in your page's context.

### Vulnerability It Kills
**Cross-Origin Window Manipulation, XS-Leaks, Spectre Side-Channel Attacks**

```
# Without COOP — Window Opener Attack:

# Your site has: <a href="https://evil.com" target="_blank">Click Me</a>
# evil.com can now do:
window.opener.location = 'https://phishing-clone-of-your-site.com'
# → User sees the original tab (your site) now shows a phishing page! ❌

# Also: attackers can exfiltrate data via SharedArrayBuffer/Spectre timing attacks
```

### Header Values

```http
# 🏆 RECOMMENDED — Most isolated, breaks opener references completely
Cross-Origin-Opener-Policy: same-origin

# Moderate — allows same-origin-allow-popups to work
Cross-Origin-Opener-Policy: same-origin-allow-popups

# Default browser behavior (no isolation — same as not setting the header)
Cross-Origin-Opener-Policy: unsafe-none
```

### Interaction with COEP
> COOP + COEP together enable **`SharedArrayBuffer`** and **high-resolution timers** — required for performance-sensitive apps (WebAssembly, gaming). But both must be set correctly.

```http
# Enable SharedArrayBuffer (needed for some WebAssembly/threading features)
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
```

---

---

## 9. Cross-Origin-Embedder-Policy (COEP)
### Controls What Your Page Can Embed

### What It Does
Requires all resources embedded in your page (images, scripts, iframes) to explicitly opt-in to being loaded cross-origin. Prevents a malicious page from embedding your authenticated resources to read their contents via side-channel attacks.

### Vulnerability It Kills
**Spectre Side-Channel Attacks, Cross-Origin Data Theft**

```
# Without COEP — Spectre Attack:
# A malicious site embeds your authenticated private image
# Uses timing attacks (Spectre CPU vulnerability) to read pixel values
# Reconstructs your private document/image from timing measurements ❌

# With COEP: require-corp
# Your image must have: Cross-Origin-Resource-Policy: cross-origin header to be embeddable
# Without that header, the browser blocks the embed entirely ✅
```

### Header Values

```http
# 🏆 RECOMMENDED — All embedded resources must opt-in via CORP header
Cross-Origin-Embedder-Policy: require-corp

# Modern alternative — uses Fetch metadata to check credentials
Cross-Origin-Embedder-Policy: credentialless

# Default — no restrictions (same as not setting)
Cross-Origin-Embedder-Policy: unsafe-none
```

---

---

## 10. Cross-Origin-Resource-Policy (CORP)
### Controls Who Can Embed Your Resources

### What It Does
The **server-side opt-in** companion to COEP. This header is set on your resources (images, APIs, fonts) to declare who is allowed to load them cross-origin. If a resource doesn't have this header, COEP blocks it.

### Vulnerability It Kills
**Cross-Origin Data Theft, Spectre Memory Attacks, Hotlinking**

```
# Without CORP — Cross-Origin Data Theft:
# Evil site embeds: <img src="https://yourapp.com/api/private-data">
# Browser fetches it (including your auth cookies), side-channel reads response ❌

# With CORP: same-site on your API:
# Browser blocks the cross-origin load entirely ✅
```

### Header Values

```http
# Block all cross-origin loading — most restrictive
Cross-Origin-Resource-Policy: same-origin

# Allow same-site (subdomains ok) but not different sites
Cross-Origin-Resource-Policy: same-site

# Allow anyone to load this resource (for public CDN assets)
Cross-Origin-Resource-Policy: cross-origin
```

### When to Use What

| Resource Type | Recommended CORP |
|--------------|------------------|
| Private API endpoints | `same-origin` |
| Authenticated images/files | `same-origin` |
| Public CDN assets (fonts, images) | `cross-origin` |
| Shared internal microservices | `same-site` |

---

---

## 11. X-XSS-Protection (Legacy — Mostly Deprecated)
### Old Browser XSS Filter

### What It Does
Activates the built-in XSS filter in older browsers (IE, older Safari). Modern browsers (Chrome 78+, Firefox) have **removed** this filter entirely because it was found to create new vulnerabilities. Still worth knowing for legacy systems.

### Header Values

```http
# Disable entirely (recommended for modern apps — prevents filter-based vulnerabilities)
X-XSS-Protection: 0

# Enable filter, block page if XSS detected (legacy behavior)
X-XSS-Protection: 1; mode=block

# Enable with reporting (legacy, report-uri deprecated)
X-XSS-Protection: 1; report=https://example.com/report
```

### Current Guidance
```
Modern apps: Set X-XSS-Protection: 0  +  use CSP instead
Legacy apps: Set X-XSS-Protection: 1; mode=block  (better than nothing)

⚠️ CSP is the real, modern XSS defense — do not rely on X-XSS-Protection
```

---

---

## 🛡️ Complete Production Configuration

### Nginx
```nginx
server {
    # HSTS — Force HTTPS for 2 years
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    # CSP — Restrict resource origins
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-$request_id'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests" always;

    # Prevent MIME sniffing
    add_header X-Content-Type-Options "nosniff" always;

    # Prevent Clickjacking
    add_header X-Frame-Options "DENY" always;

    # Control referrer leakage
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Disable unneeded browser features
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=()" always;

    # Cross-origin isolation
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Embedder-Policy "require-corp" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;

    # Disable legacy XSS filter (use CSP instead)
    add_header X-XSS-Protection "0" always;

    # Sensitive routes — disable caching
    location /account {
        add_header Cache-Control "no-store, no-cache, must-revalidate, private" always;
    }

    # Static assets — aggressive caching
    location /static {
        add_header Cache-Control "public, max-age=31536000, immutable" always;
    }
}
```

### Apache (.htaccess)
```apache
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    Header always set Content-Security-Policy "default-src 'self'; object-src 'none'; frame-ancestors 'none'"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
    Header always set Cross-Origin-Opener-Policy "same-origin"
    Header always set X-XSS-Protection "0"
</IfModule>
```

### Express.js (Node.js) — Using Helmet
```javascript
const helmet = require('helmet');

app.use(helmet({
  // HSTS
  hsts: {
    maxAge: 63072000,
    includeSubDomains: true,
    preload: true
  },

  // CSP
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },

  // X-Frame-Options
  frameguard: { action: 'deny' },

  // X-Content-Type-Options
  noSniff: true,

  // Referrer-Policy
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },

  // X-XSS-Protection disabled (use CSP)
  xssFilter: false,

  // Cross-Origin policies
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginEmbedderPolicy: { policy: 'require-corp' },
  crossOriginResourcePolicy: { policy: 'same-origin' },
  permissionsPolicy: {
    features: {
      camera: [],
      microphone: [],
      geolocation: [],
      payment: [],
    }
  }
}));
```

---

---

## 🧪 How to Test Your Security Headers

### Online Tools
```
https://securityheaders.com         # Grade your headers A+ to F
https://observatory.mozilla.org     # Mozilla Observatory — detailed analysis
https://csp-evaluator.withgoogle.com # Google's CSP Evaluator
https://report-uri.com/home/analyse # Analyze CSP reports
```

### Command Line (curl)
```bash
# View all response headers
curl -I https://yoursite.com

# Check specific header
curl -I https://yoursite.com | grep -i "strict-transport"
curl -I https://yoursite.com | grep -i "content-security-policy"

# Follow redirects and show headers
curl -IL https://yoursite.com

# Test with verbose output
curl -v https://yoursite.com 2>&1 | grep "< "
```

### Browser DevTools
```
Chrome/Firefox → F12 → Network tab → Click any request → Headers tab
Look at: Response Headers section
Check: All security headers are present with correct values
```

---

---

## 📊 Attack → Header Defense Matrix

| Attack Type | Attack Mechanism | Defending Header |
|-------------|-----------------|------------------|
| **XSS** | Injected script executes in browser | `Content-Security-Policy` |
| **Clickjacking** | Transparent iframe trick | `X-Frame-Options` + `CSP: frame-ancestors` |
| **MITM / SSL Strip** | Downgrade HTTPS to HTTP | `Strict-Transport-Security` |
| **MIME Sniffing** | Browser executes wrong file type | `X-Content-Type-Options` |
| **Token Leakage** | URL token sent in Referer header | `Referrer-Policy` |
| **Camera/Mic Hijack** | XSS grabs hardware | `Permissions-Policy` |
| **Cache Snooping** | Sensitive data in browser cache | `Cache-Control` |
| **Spectre Attack** | CPU timing side-channel | `COOP` + `COEP` |
| **Cross-Origin Theft** | Reading cross-origin resources | `CORP` |
| **Protocol Downgrade** | Force old TLS version | `HSTS` + TLS config |
| **Data Injection** | Injecting content into response | `CSP` |

---

---

## 🎯 Interview Quick-Fire Answers

**Q: What is the most important security header?**
> **Content-Security-Policy** — it's the most powerful and addresses the most attack vectors (XSS, clickjacking, data injection). Second most important is **HSTS** for forcing encrypted connections.

**Q: What is the difference between X-Frame-Options and CSP frame-ancestors?**
> Both prevent clickjacking. `X-Frame-Options` is older with limited values (DENY, SAMEORIGIN). `CSP frame-ancestors` is modern, supports multiple trusted origins, and overrides X-Frame-Options in browsers that support CSP. Best practice: set both.

**Q: Why is `unsafe-inline` in CSP bad?**
> It allows any inline `<script>` tag to execute — which is exactly what XSS payloads are. Setting `unsafe-inline` effectively disables XSS protection in CSP. Use nonces or hashes instead.

**Q: What does HSTS preloading do?**
> It submits your domain to a list hardcoded into browsers (Chrome, Firefox, Edge, Safari). Even on first visit (before any header is seen), the browser already knows to use HTTPS only. Eliminates the "first visit" vulnerability of regular HSTS.

**Q: What tool would you use to audit security headers?**
> **securityheaders.com** for a quick grade, **Mozilla Observatory** for detailed analysis, **curl -I** for quick command-line checks, and **Burp Suite** for professional penetration testing.

**Q: What is the Helmet library?**
> A Node.js/Express middleware that sets security headers automatically with sensible defaults. One `app.use(helmet())` line adds most essential security headers. Industry standard for Node.js applications.

---

## 📋 Minimum Security Headers Checklist

```
✅ Strict-Transport-Security       → max-age=31536000; includeSubDomains
✅ Content-Security-Policy         → default-src 'self'; object-src 'none'
✅ X-Frame-Options                 → DENY
✅ X-Content-Type-Options          → nosniff
✅ Referrer-Policy                 → strict-origin-when-cross-origin
✅ Permissions-Policy              → camera=(), microphone=(), geolocation=()
✅ Cache-Control (sensitive pages) → no-store, no-cache, must-revalidate, private
✅ Cross-Origin-Opener-Policy      → same-origin
✅ X-XSS-Protection               → 0  (disabled — use CSP instead)
```

---

> 🔗 **Resources:**
> Mozilla MDN Web Docs — HTTP Headers Reference
> OWASP Secure Headers Project — owasp.org/www-project-secure-headers/
> securityheaders.com — Live header scanner
> helmet.js — Node.js security headers library
