# Application Analysis - Bug Bounty Hunter Guide

## Holistic Application Analysis Approach
Break app into layers → profile tech → ask big questions → prioritize targets

---

## Application Layers (Priority Order)

| Layer | What to Look For |
|-------|-----------------|
| Open Ports & Services | Default creds, service exploits, exposed admin |
| Web Hosting Software | Misconfigs, web server exploits, version disclosure |
| Application Framework | Framework-specific CVEs, default paths |
| Custom Code / COTS | Business logic, injection points, auth flaws |
| JavaScript Libraries | Outdated libs with CVEs, client-side secrets |
| Integrations | OAuth misconfig, SSRF via webhooks, API keys |

---

## Tech Profiling
- **Wappalyzer** → identify full tech stack instantly
- **BuiltWith** → historical tech usage
- **Retire.js** → find outdated JS libraries
- **whatweb** → CLI tech fingerprinting
- Check: `X-Powered-By`, `Server` headers, cookie names, error messages
- Framework tells you: default admin paths, common CVEs, config files

---

## The 6 Big Questions

### 1. How does the app pass data?
```
Traditional:  https://app.com/page?param=value&param2=value2
RESTful:      https://app.com/api/users/123/orders/456
GraphQL:      POST /graphql  { query: "{ user(id:1) { email } }" }
```
- Know this = know WHERE to inject payloads
- Blind injection in wrong place = missed bugs

### 2. How/Where does app reference users?
Look for user identifiers in:
- Cookies: `session=`, `user_id=`, `auth_token=`
- URL params: `?uid=`, `?user=`, `?account_id=`
- Headers: `X-User-ID:`, `X-Account:`
- API responses: `"id":`, `"uuid":`, `"email":`
- **Why**: Find these = find IDOR, BOLA, auth bypass

### 3. Multi-tenancy / User Levels?
```
Unauthenticated → Basic User → Premium User → Account Admin → Super Admin
```
- Test EVERY function at EVERY level
- Can low-priv user access high-priv functions? → Privilege Escalation
- Can User A access User B's data? → IDOR/BOLA
- Missing Function Level Access Control (MFLAC)

### 4. Unique Threat Model?
- Healthcare app: PHI data = HIPAA → information disclosure is CRITICAL
- Finance app: transactions = fraud potential
- SaaS B2B: tenant isolation = org-level IDOR
- What data does this app hold? → sets severity

### 5. Past Security Research & CVEs?
- Search: `site:hackerone.com "target.com"`
- Search: `site:bugcrowd.com "target"`
- Look at disclosed reports → same patterns often repeat
- CVE search for their specific framework version

### 6. How does framework handle vuln classes?
- Rails: CSRF protection built-in → need to bypass, not find absence
- Django: SQL via ORM → raw queries = vuln spots
- Laravel: mass assignment protection → check $fillable
- React: auto-escapes XSS → look for `dangerouslySetInnerHTML`

---

## High-Value Application Areas (Attack Surface)

| Area | Why It's Juicy | Bug Types |
|------|---------------|-----------|
| Authentication | Core trust boundary | Auth bypass, brute force, MFA bypass |
| Search | User input → DB/backend | SQLi, XSS, SSRF |
| Profile/Account | Persistent storage | Stored XSS, IDOR |
| Upload/Export | File processing | XXE, RCE, SSRF, XSS |
| API Endpoints | Often less tested | BOLA, Auth bypass, data exposure |
| Admin Functions | High privilege | Privilege escalation, auth bypass |
| Integrations | 3rd party trust | SSRF, OAuth misconfig |
| Payment | High value target | Logic flaws, price manipulation |
| Password Reset | Auth flow | Account takeover |
