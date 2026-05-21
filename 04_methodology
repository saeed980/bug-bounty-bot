# Testing Methodology & Order of Operations - Bug Bounty Hunter Guide

## My Order of Operations (Follow This Exactly)

```
1. Automated Vuln Discovery [CVEs on tech stack]
2. Walk & Use App + Find Heat Map Areas  
3. Content Discovery
4. Bite-Sized Dynamic Scanning
5. Manual Testing [Payload Fuzz, Logic, IDOR, MFLAC, ++]
```

---

## Step 1: Automated Vuln Discovery

### CVE Scanning
```bash
# Nuclei - template-based scanner
nuclei -u https://target.com -t cves/ -t exposures/
nuclei -u https://target.com -t technologies/

# Nikto - web server scan
nikto -h https://target.com

# WPScan (if WordPress)
wpscan --url https://target.com --enumerate p,u,t

# Nmap for service versions
nmap -sV -sC -p- target.com
```

### Framework CVE Lookup
- Identify version → search `framework X.X.X CVE`
- Sites: NVD, Exploit-DB, PacketStorm
- Check: `searchsploit framework_name version`

---

## Step 2: Walk & Use App → Heat Map

### Tester Flow (3 Levels)

**Level 1 - GUI Testing**
- Use app as normal user
- Note all features, inputs, file uploads
- No tools yet

**Level 2 - Dev Tools**
- Open browser DevTools (F12)
- Network tab → capture ALL requests
- Look for: API calls, tokens in headers, hidden params
- Sources tab → read JavaScript for endpoints, secrets

**Level 3 - Burp Suite**
- Proxy ALL traffic
- Build full site map
- Use Logger++ to capture everything
- Note all params, headers, cookies

### What to Document While Walking
- [ ] All input fields (text, file, URL, search)
- [ ] All API endpoints called
- [ ] Auth tokens and how they're used
- [ ] User references (IDs, emails, UUIDs)
- [ ] File upload endpoints
- [ ] Third-party integrations
- [ ] Admin/privileged functions

---

## Step 3: Content Discovery

```bash
# Directory/File brute force
ffuf -w /wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt \
     -u https://target.com/FUZZ -mc 200,301,302,403

# API endpoint discovery  
ffuf -w /wordlists/api_endpoints.txt \
     -u https://target.com/api/FUZZ

# Backup files
ffuf -w /wordlists/SecLists/Discovery/Web-Content/raft-large-files.txt \
     -u https://target.com/FUZZ \
     -e .bak,.old,.backup,.sql,.zip,.tar.gz

# Parameter discovery
ffuf -w /wordlists/parameters.txt \
     -u https://target.com/page?FUZZ=test
     
# Arjun - auto parameter finder
arjun -u https://target.com/api/endpoint
```

### Important Paths to Check
```
/admin, /administrator, /admin.php
/.git, /.env, /config.php, /wp-config.php
/api/v1/, /api/v2/, /internal/
/swagger, /swagger-ui, /api-docs, /openapi.json
/phpinfo.php, /server-status, /server-info
/.well-known/, /robots.txt, /sitemap.xml
```

---

## Step 4: Dynamic Scanning

```bash
# OWASP ZAP active scan on specific areas
# Burp Scanner on high-heat endpoints only
# Don't scan everything → too noisy, miss important bugs

# Target:
# - Login page (brute force protection?)
# - Upload endpoints
# - Search functions
# - API endpoints
```

---

## Step 5: Manual Testing Priority List

### Priority 1 - High Impact
```
IDOR/BOLA    → Change IDs in every request
Auth Bypass  → Access protected pages without login
SSRF         → Any URL parameter
XXE          → XML inputs, document uploads
SQLi         → All input → DB parameters
```

### Priority 2 - High Impact
```
XSS (Stored) → Persist in other users' pages
JWT Attacks  → Decode, modify, re-sign
CSRF         → State-changing requests without token
Race Cond    → Financial/coupon operations
Host Header  → Password reset flows
```

### Priority 3 - Medium Impact
```
Open Redirect → ?redirect= parameters
CORS Misconfig → Check all origins
LFI           → File path parameters
Sub Takeover  → Dangling CNAMEs
Mass Assign   → Add fields to JSON requests
```

### Priority 4 - Bonus
```
Rate Limiting  → All auth endpoints
OAuth Misconfig → Redirect URI, state param
GraphQL        → Introspection, batching attacks
SSTI           → Template parameters
2FA Bypass     → OTP brute force, flow bypass
```

---

## Burp Suite Essential Workflow

### Must-Have Extensions
- Logger++
- Autorize (IDOR testing)
- Turbo Intruder (race conditions)
- JWT Editor
- Active Scan++
- Param Miner

### Autorize Setup (IDOR Testing)
1. Login as User A → copy session cookie
2. Login as User B → add User A's cookie to Autorize
3. Browse as User B → Autorize auto-tests User A's access
4. Green = unauthorized access = **IDOR found** 🎯

### Turbo Intruder (Race Conditions)
```python
# Send same request 20 times simultaneously
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=20)
    for i in range(20):
        engine.queue(target.req)
```

---

## Report Writing Template

### Severity Rating
- **Critical**: RCE, Auth Bypass to admin, SQLi with data dump
- **High**: SSRF, XXE, Stored XSS, IDOR with sensitive data
- **Medium**: Reflected XSS, CSRF on important actions, Open Redirect
- **Low**: Info disclosure, missing security headers, rate limiting

### Report Structure
```
Title: [Vuln Type] in [Feature] allows [Impact]

Severity: Critical/High/Medium/Low

Summary:
Brief description of the vulnerability

Steps to Reproduce:
1. Navigate to...
2. Set parameter X to...
3. Observe...

Impact:
What an attacker can do

Proof of Concept:
Screenshot / Video / Code

Remediation:
How to fix it
```

---

## Essential Tools List

### Recon
- `amass` - ASN, subdomain enum
- `subfinder` - passive subdomain
- `httpx` - probe live hosts
- `nuclei` - CVE/vuln scanning
- `gowitness` - screenshots

### Web Testing  
- `ffuf` - fuzzing
- `sqlmap` - SQL injection
- `dalfox` - XSS
- `jwt_tool` - JWT attacks
- Burp Suite Pro - everything

### Cloud
- `cloud_enum` - cloud asset discovery
- `S3Scanner` - S3 bucket testing
- `trufflehog` - secret scanning

### Wordlists (SecLists)
```
/Discovery/Web-Content/raft-large-directories.txt
/Discovery/Web-Content/common.txt
/Fuzzing/SQLi/
/Fuzzing/XSS/
/Passwords/Common-Credentials/
```
