import os
import logging
import anthropic
import base64
import re
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

def load_knowledge_base():
    knowledge = ""
    knowledge_dir = "knowledge"
    if os.path.exists(knowledge_dir):
        # Load root knowledge files
        for filename in sorted(os.listdir(knowledge_dir)):
            filepath = os.path.join(knowledge_dir, filename)
            if filename.endswith(".md") and os.path.isfile(filepath):
                with open(filepath, "r", encoding="utf-8") as f:
                    knowledge += f"\n\n{'='*60}\n"
                    knowledge += f"# FILE: {filename}\n"
                    knowledge += f"{'='*60}\n"
                    knowledge += f.read()
        # Load vulnerability-specific knowledge
        vulns_dir = os.path.join(knowledge_dir, "vulns")
        if os.path.exists(vulns_dir):
            for filename in sorted(os.listdir(vulns_dir)):
                filepath = os.path.join(vulns_dir, filename)
                if filename.endswith(".md") and os.path.isfile(filepath):
                    with open(filepath, "r", encoding="utf-8") as f:
                        knowledge += f"\n\n{'='*60}\n"
                        knowledge += f"# VULN FILE: {filename}\n"
                        knowledge += f"{'='*60}\n"
                        knowledge += f.read()
    return knowledge

KNOWLEDGE_BASE = load_knowledge_base()

SYSTEM_PROMPT = f"""You are an elite Bug Bounty Hunter and Web Security Expert with 10+ years experience.

Core expertise: XSS, SQLi, IDOR/BOLA, SSRF, XXE, RCE, CSRF, JWT, OAuth,
Business Logic, Race Conditions, Subdomain Takeover, CORS, LFI, SSTI,
Prototype Pollution, HTTP Request Smuggling, GraphQL, API Security,
Cloud Security (AWS/GCP/Azure), WAF Bypass.

== ANALYSIS GUIDELINES ==

When analyzing SCREENSHOTS:
1. Identify page type (login, admin, API docs, dashboard, upload, etc.)
2. List ALL visible elements: forms, parameters, buttons, error messages
3. Note tech stack indicators (frameworks, libraries, error formats)
4. Suggest specific vulns based on what you see
5. Give exact payloads for each vuln
6. Suggest next recon steps

When analyzing URLs:
1. Break down: protocol, domain, path, parameters, fragments
2. Identify ALL injection points
3. Check for: IDOR (numeric/uuid IDs), path traversal patterns
4. For JS/config files: suggest reading content first, then check for:
   - Backup files (.bak, .old, .orig, .swp, ~)
   - Source maps (.map) = original source code
   - Alternative extensions (.json, .xml, .yaml, .env)
   - Wayback Machine historical versions
   - Hidden API endpoints inside the file
   - Hardcoded secrets (api keys, tokens, passwords)
5. Give curl commands to extract data
6. Suggest directory enumeration paths
7. Check Wayback Machine for old versions

CRITICAL ADDITIONS for JS/Config file URLs:
- ALWAYS suggest reading the file first: curl -s "URL" | grep -iE "(api|key|secret|token|endpoint)"
- Check source maps: URL + ".map"
- Extract endpoints from JS: curl -s "URL" | grep -oE '"(https?://[^"]+)"'
- Wayback Machine: https://web.archive.org/web/*/DOMAIN/*
- JS Beauty: curl -s "URL" | js-beautify

When analyzing HTTP REQUESTS:
1. Identify endpoint, method, content-type
2. Analyze auth: JWT (decode it), session cookies, API keys
3. Find IDOR: any ID, UUID, reference in params/body/path
4. Check for: mass assignment (add extra JSON fields)
5. Test auth removal: what happens without token?
6. Check for missing security headers
7. Give EXACT modified requests for each attack

When analyzing FILES:
1. Extract ALL endpoints, parameters, tokens
2. Find secrets: API keys, passwords, internal URLs
3. Build attack surface map
4. Identify patterns suggesting specific vulns
5. Give prioritized next steps

IMPORTANT RULES:
- Only help with LEGAL security testing and authorized bug bounty programs
- Always verify target is in scope before testing
- Emphasize responsible disclosure
- Mention: check HackerOne/Bugcrowd for program before testing

Always respond in same language as user (Arabic or English).

== REPORT GENERATION MODE ==
When asked to generate a bug bounty report:
1. Use the EXACT format for the requested platform (HackerOne/Bugcrowd/Intigriti)
2. Write a compelling title: "[Vuln Type] in [Feature] leads to [Impact]"
3. Calculate CVSS score accurately
4. Include realistic HTTP requests/responses as PoC
5. Make the impact section convincing and specific
6. Provide actionable remediation with code examples
7. Write as if this is a real submission that should get maximum bounty
8. Use professional security researcher language
9. Include all required sections for the platform

HackerOne format: Summary, Severity+CVSS, Description, Steps To Reproduce, Impact, PoC, Remediation
Bugcrowd format: Bug Description, Severity(P1-P4), Target, Steps, PoC, Impact, Suggested Fix
Intigriti format: Title, Affected Asset, Vulnerability Type, Severity, Technical Description, Reproduction Steps, Evidence, Impact Assessment, Mitigation
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

def detect_url_type(url):
    js_extensions = ['.js', '.ts', '.jsx', '.tsx']
    config_names = ['config', 'settings', 'env', 'constants', 'secrets', 'credentials']
    url_lower = url.lower()
    is_js = any(url_lower.endswith(ext) or (ext + '?') in url_lower for ext in js_extensions)
    is_config = any(name in url_lower for name in config_names)
    return "js_config" if (is_js or is_config) else "regular_url"

def detect_content_type(text):
    http_methods = ['GET ', 'POST ', 'PUT ', 'DELETE ', 'PATCH ', 'OPTIONS ', 'HEAD ']
    url_pattern = re.compile(r'https?://[^\s]+|www\.[^\s]+')
    if any(text.strip().startswith(m) for m in http_methods):
        return "http_request"
    elif url_pattern.search(text):
        urls = url_pattern.findall(text)
        if urls:
            url_type = detect_url_type(urls[0])
            return f"url_{url_type}"
        return "url_regular"
    return "question"

async def send_long_message(update, text):
    if len(text) > 4096:
        parts = [text[i:i+4096] for i in range(0, len(text), 4096)]
        for part in parts:
            await update.message.reply_text(part)
    else:
        await update.message.reply_text(text)

def build_url_prompt(url, content_type):
    if content_type == "url_js_config":
        return (
            f"Analyze this JS/Config file URL from a bug bounty target:\n{url}\n\n"
            f"This is a JavaScript or configuration file. Please provide:\n\n"
            f"1. IMMEDIATE ACTION - Read the file first:\n"
            f"   - curl command to read and grep for secrets\n"
            f"   - What sensitive data to look for inside\n\n"
            f"2. SOURCE MAP CHECK (Critical):\n"
            f"   - Check {url}.map for original source code\n"
            f"   - Explain why source maps are a goldmine\n\n"
            f"3. BACKUP FILES to check:\n"
            f"   - .bak, .old, .orig, .swp, ~, .save variations\n"
            f"   - Give exact URLs to test\n\n"
            f"4. ALTERNATIVE EXTENSIONS:\n"
            f"   - .json, .xml, .yaml, .yml, .env variations\n"
            f"   - Give exact URLs\n\n"
            f"5. WAYBACK MACHINE:\n"
            f"   - Command to find historical versions\n"
            f"   - Why old versions may have exposed secrets\n\n"
            f"6. EXTRACT HIDDEN ENDPOINTS:\n"
            f"   - curl command to extract all URLs from the JS\n"
            f"   - grep patterns for API endpoints\n\n"
            f"7. DIRECTORY ENUMERATION:\n"
            f"   - Parent directories to enumerate\n"
            f"   - Related files to look for\n\n"
            f"8. PATH TRAVERSAL tests\n\n"
            f"9. SECRETS to grep for: api_key, token, password, aws, firebase, etc.\n\n"
            f"Prioritize by impact. Give exact commands for each step."
        )
    else:
        return (
            f"Analyze this URL from a bug bounty target:\n{url}\n\n"
            f"Please provide:\n"
            f"1. URL structure breakdown (domain, path, parameters)\n"
            f"2. ALL injection points identified\n"
            f"3. IDOR opportunities (numeric IDs, UUIDs, references)\n"
            f"4. Vulnerability tests with exact payloads:\n"
            f"   - SQLi, XSS, SSRF, Path Traversal, IDOR\n"
            f"5. Modified URLs for each attack\n"
            f"6. Parameter fuzzing approach\n"
            f"7. Related endpoints to discover\n"
            f"8. Wayback Machine check command\n\n"
            f"Prioritize by impact. Be specific with payloads."
        )

def build_http_prompt(request_text):
    return (
        f"Analyze this HTTP request from a bug bounty target:\n\n"
        f"{request_text}\n\n"
        f"Provide comprehensive analysis:\n\n"
        f"1. ENDPOINT ANALYSIS:\n"
        f"   - Method, path, API version\n"
        f"   - Functionality purpose\n\n"
        f"2. AUTHENTICATION:\n"
        f"   - Token type (JWT/session/API key)\n"
        f"   - If JWT: decode and analyze claims\n"
        f"   - Test removing auth completely\n\n"
        f"3. IDOR OPPORTUNITIES:\n"
        f"   - All IDs, UUIDs, references\n"
        f"   - Exact modified requests to test\n\n"
        f"4. INJECTION POINTS:\n"
        f"   - SQLi, XSS, SSRF, XXE payloads\n"
        f"   - Exact modified requests\n\n"
        f"5. MASS ASSIGNMENT:\n"
        f"   - Extra fields to add to JSON body\n"
        f"   - role, isAdmin, permissions fields\n\n"
        f"6. SECURITY HEADERS CHECK:\n"
        f"   - Missing: CSRF token, security headers\n\n"
        f"7. BUSINESS LOGIC:\n"
        f"   - Logic flaws, race conditions\n\n"
        f"Give EXACT modified requests for each attack. Prioritize by impact."
    )

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    msg = (
        f"🎯 *مرحباً {user.first_name}!*\n\n"
        "أنا بوتك الخبير في *Bug Bounty Hunting* 🔐\n\n"
        "*أقدر أحلل:*\n"
        "🖼️ *Screenshots* - صور من الهدف\n"
        "🔗 *URLs* - روابط عادية أو JS/Config files\n"
        "📋 *HTTP Requests* - من Burp Suite\n"
        "📄 *ملفات* - Burp logs, recon output\n"
        "💬 *أسئلة* - أي سؤال عن Bug Bounty\n\n"
        "*تحليل خاص لـ JS/Config files:*\n"
        "🔑 Secrets & API Keys\n"
        "🗺️ Source Maps\n"
        "💾 Backup Files\n"
        "📜 Wayback Machine\n"
        "🔍 Hidden Endpoints\n\n"
        "*أوامر:*\n"
        "/recon /vulns /tools /methodology /report /clear\n\n"
        "⚠️ *للبرامج المصرح بها فقط*"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🛡️ *كيف تستخدم البوت*\n\n"
        "*1. Screenshot:*\n"
        "📸 ارسل صورة → تحليل فوري\n\n"
        "*2. URL عادي:*\n"
        "🔗 https://target.com/api/user?id=123\n"
        "→ تحليل parameters + payloads\n\n"
        "*3. JS/Config URL:*\n"
        "🔗 https://target.com/config.js\n"
        "→ secrets, source maps, backups, wayback\n\n"
        "*4. HTTP Request:*\n"
        "📋 الصق من Burp Suite\n"
        "→ تحليل auth + IDOR + injections\n\n"
        "*5. ملف:*\n"
        "📄 أي text file أو log\n"
        "→ استخراج endpoints + secrets\n\n"
        "*6. سؤال مباشر:*\n"
        "💬 اسأل أي شيء عن Bug Bounty\n\n"
        "⚠️ للبرامج المصرح بها فقط!"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def recon_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🔍 *Recon Cheatsheet*\n\n"
        "*Subdomains:*\n"
        "```\nsubfinder -d target.com | httpx -silent\n"
        "amass enum -passive -d target.com\n```\n\n"
        "*JS Files Analysis:*\n"
        "```\n# قراءة وإيجاد secrets\ncurl -s URL | grep -iE '(api|key|secret|token|endpoint)'\n\n"
        "# استخراج endpoints\ncurl -s URL | grep -oE '\"(https?://[^\"]+)\"'\n\n"
        "# Source map\ncurl -s URL.map | python3 -m json.tool\n\n"
        "# Wayback Machine\ncurl 'https://web.archive.org/web/*/target.com/ui/*'\n```\n\n"
        "*CVE Scan:*\n"
        "```\nnuclei -l alive.txt -t cves/ -t exposures/\n```\n\n"
        "*Content Discovery:*\n"
        "```\nffuf -w wordlist.txt -u https://target.com/FUZZ\n"
        "ffuf -w files.txt -u https://target.com/FUZZ -e .bak,.old,.map\n```\n\n"
        "*GitHub Secrets:*\n"
        "```\ntrufflehog github --org=target\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def vulns_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🔥 *Vulnerability Priority List*\n\n"
        "*🔴 Critical:*\n"
        "• RCE, Auth Bypass, SQLi\n"
        "• SSRF → Cloud Metadata\n"
        "• XXE → File Read\n"
        "• Secrets in JS files\n\n"
        "*🟠 High:*\n"
        "• IDOR/BOLA\n"
        "• Stored XSS\n"
        "• JWT Attacks\n"
        "• Race Conditions\n"
        "• Source Map Exposure\n\n"
        "*🟡 Medium:*\n"
        "• Reflected XSS\n"
        "• CSRF, Open Redirect\n"
        "• CORS Misconfig\n"
        "• Host Header Injection\n"
        "• Subdomain Takeover\n\n"
        "*🔵 Info:*\n"
        "• Missing Security Headers\n"
        "• Info Disclosure\n"
        "• Backup Files Exposed\n\n"
        "💬 اسألني عن أي ثغرة للتفاصيل!"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def tools_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🛠️ *Essential Tools*\n\n"
        "*Recon:*\n"
        "• subfinder, amass, httpx\n"
        "• gowitness, nuclei, nikto\n\n"
        "*JS Analysis:*\n"
        "• js-beautify\n"
        "• LinkFinder\n"
        "• SecretFinder\n"
        "• source-map-explorer\n\n"
        "*Web Testing:*\n"
        "• Burp Suite Pro\n"
        "• ffuf, sqlmap, dalfox\n"
        "• jwt_tool, arjun\n\n"
        "*Burp Extensions:*\n"
        "• Logger++\n"
        "• Autorize\n"
        "• Turbo Intruder\n"
        "• JWT Editor\n"
        "• JS Miner\n\n"
        "*Secrets:*\n"
        "• trufflehog, gitleaks\n"
        "• SecretFinder\n\n"
        "*Wayback:*\n"
        "• waybackurls\n"
        "• gau (GetAllUrls)\n"
        "```\necho target.com | waybackurls | grep '\\.js$'\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def methodology_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🎯 *Bug Bounty Methodology*\n\n"
        "*1️⃣ Recon*\n"
        "• Subdomains, IPs, ASN, Cloud\n"
        "• GitHub, Shodan, crt.sh\n\n"
        "*2️⃣ JS Analysis (مهم جداً)*\n"
        "• اقرأ كل JS file\n"
        "• ابحث عن secrets وendpoints\n"
        "• تحقق من source maps\n"
        "• Wayback Machine للنسخ القديمة\n\n"
        "*3️⃣ CVE Scan*\n"
        "• nuclei على كل assets\n\n"
        "*4️⃣ Walk the App*\n"
        "• Burp Suite يسجل كل شيء\n"
        "• حدد Heat Map Areas\n\n"
        "*5️⃣ Content Discovery*\n"
        "• Dirs, files, APIs, params\n\n"
        "*6️⃣ Manual Testing*\n"
        "• IDOR, SSRF, XSS, SQLi\n"
        "• Auth bypass, Logic flaws\n\n"
        "*Heat Map 🔥:*\n"
        "🔥🔥🔥 JS/Config files, Upload, Admin\n"
        "🔥🔥 API, Search, Profile, Export\n"
        "🔥 Static pages"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def report_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    args = context.args
    if not args:
        msg = (
            "📝 *نظام توليد التقارير الاحترافية*\n\n"
            "*الاستخدام:*\n"
            "`/report [نوع الثغرة] [المنصة]`\n\n"
            "*أمثلة:*\n"
            "`/report xss hackerone`\n"
            "`/report idor bugcrowd`\n"
            "`/report ssrf intigriti`\n"
            "`/report sqli hackerone`\n"
            "`/report rce bugcrowd`\n"
            "`/report csrf hackerone`\n\n"
            "*أو أخبرني بتفاصيل الثغرة:*\n"
            "اكتب مثلاً:\n"
            "\"اكتب تقرير XSS على HackerOne وجدت في صفحة البروفايل يؤدي لسرقة الكوكيز\"\n\n"
            "*المنصات المدعومة:*\n"
            "• HackerOne (h1)\n"
            "• Bugcrowd (bc)\n"
            "• Intigriti\n"
            "• Generic"
        )
        await update.message.reply_text(msg, parse_mode='Markdown')
        return

    vuln_type = args[0].lower() if args else "general"
    platform = args[1].lower() if len(args) > 1 else "hackerone"
    user_id = update.effective_user.id

    await context.bot.send_chat_action(chat_id=update.effective_chat.id, action="typing")
    await update.message.reply_text(f"📝 جاري إنشاء تقرير {vuln_type.upper()} لـ {platform}...")

    prompt = (
        f"Generate a complete, professional bug bounty report for a {vuln_type.upper()} vulnerability.\n"
        f"Platform: {platform}\n\n"
        f"Requirements:\n"
        f"1. Use the exact report format/template for {platform}\n"
        f"2. Include realistic example values (URLs, payloads, responses)\n"
        f"3. Write a compelling title following best practices\n"
        f"4. Include all sections: Summary, Severity, Description, Steps to Reproduce, Impact, PoC, Remediation\n"
        f"5. Add realistic HTTP requests and responses as PoC\n"
        f"6. Calculate appropriate CVSS score\n"
        f"7. Make it look like a real, high-quality report that would get maximum bounty\n"
        f"8. Include specific remediation code/guidance\n\n"
        f"Generate the complete report now in the format used by {platform}."
    )

    try:
        add_to_history(user_id, "user", prompt)
        client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
        response = client.messages.create(
            model="claude-opus-4-5",
            max_tokens=3000,
            system=SYSTEM_PROMPT,
            messages=get_user_history(user_id)
        )
        result = response.content[0].text
        add_to_history(user_id, "assistant", result)
        await send_long_message(update, result)
    except Exception as e:
        await update.message.reply_text(f"❌ خطأ: {str(e)}")

async def clear_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user_conversations[user_id] = []
    await update.message.reply_text("✅ تم مسح المحادثة!")

async def handle_photo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await context.bot.send_chat_action(
        chat_id=update.effective_chat.id, action="typing"
    )
    try:
        photo = update.message.photo[-1]
        file = await context.bot.get_file(photo.file_id)
        file_bytes = await file.download_as_bytearray()
        image_data = base64.standard_b64encode(bytes(file_bytes)).decode("utf-8")
        caption = update.message.caption or ""
        user_id = update.effective_user.id

        await update.message.reply_text("🔍 جاري تحليل الصورة...")

        client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

        user_content = [
            {
                "type": "image",
                "source": {
                    "type": "base64",
                    "media_type": "image/jpeg",
                    "data": image_data,
                },
            },
            {
                "type": "text",
                "text": (
                    f"Analyze this screenshot from a bug bounty target.\n"
                    f"Context: {caption}\n\n"
                    f"1. What page/feature is this? (login, admin, API, upload, etc.)\n"
                    f"2. List ALL visible elements: forms, inputs, buttons, errors, tokens\n"
                    f"3. Identify tech stack from visible clues\n"
                    f"4. List vulnerabilities to test with EXACT payloads\n"
                    f"5. Priority order by impact\n"
                    f"6. Next recon steps\n"
                    f"7. Are there any exposed secrets or sensitive info visible?\n\n"
                    f"Be specific and actionable. Think like elite bug bounty hunter."
                )
            }
        ]

        response = client.messages.create(
            model="claude-opus-4-5",
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_content}]
        )

        result = response.content[0].text
        add_to_history(user_id, "user", f"[Screenshot] {caption}")
        add_to_history(user_id, "assistant", result)
        await send_long_message(update, result)

    except Exception as e:
        logger.error(f"Photo error: {e}")
        await update.message.reply_text(f"❌ خطأ: {str(e)}")

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await context.bot.send_chat_action(
        chat_id=update.effective_chat.id, action="typing"
    )
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

        await update.message.reply_text(
            f"📄 جاري تحليل: `{filename}`...",
            parse_mode='Markdown'
        )

        try:
            file_content = file_bytes.decode('utf-8')
        except UnicodeDecodeError:
            file_content = file_bytes.decode('latin-1')

        if len(file_content) > 8000:
            file_content = file_content[:8000] + "\n\n[... truncated ...]"

        prompt = (
            f"Analyze this file from a bug bounty engagement.\n"
            f"Filename: {filename}\n"
            f"Context: {caption}\n\n"
            f"FILE CONTENT:\n{file_content}\n\n"
            f"Please:\n"
            f"1. File type and purpose\n"
            f"2. Extract ALL endpoints, parameters, tokens, API keys\n"
            f"3. Find exposed secrets (api keys, passwords, internal URLs)\n"
            f"4. Build attack surface map\n"
            f"5. Identify vulnerability patterns\n"
            f"6. Check for: hardcoded credentials, debug info, internal paths\n"
            f"7. Prioritized next steps with exact commands\n\n"
            f"Think like elite bug bounty hunter. Be specific."
        )

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
        await send_long_message(update, result)

    except Exception as e:
        logger.error(f"Document error: {e}")
        await update.message.reply_text(f"❌ خطأ: {str(e)}")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user_message = update.message.text

    await context.bot.send_chat_action(
        chat_id=update.effective_chat.id, action="typing"
    )

    try:
        content_type = detect_content_type(user_message)

        if content_type == "url_js_config":
            url_match = re.search(r'https?://[^\s]+', user_message)
            url = url_match.group(0) if url_match else user_message
            prompt = build_url_prompt(url, "url_js_config")
            await update.message.reply_text(
                "🔍 تم اكتشاف JS/Config file — تحليل متخصص...",
            )
        elif content_type == "url_regular":
            url_match = re.search(r'https?://[^\s]+', user_message)
            url = url_match.group(0) if url_match else user_message
            prompt = build_url_prompt(url, "url_regular")
        elif content_type == "http_request":
            prompt = build_http_prompt(user_message)
            await update.message.reply_text(
                "📋 تحليل HTTP Request...",
            )
        else:
            prompt = user_message

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
        await send_long_message(update, result)

    except Exception as e:
        logger.error(f"Message error: {e}")
        await update.message.reply_text(f"❌ خطأ: {str(e)}")

def main():
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        raise ValueError("TELEGRAM_BOT_TOKEN environment variable not set!")

    app = Application.builder().token(token).build()

    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("recon", recon_command))
    app.add_handler(CommandHandler("vulns", vulns_command))
    app.add_handler(CommandHandler("tools", tools_command))
    app.add_handler(CommandHandler("methodology", methodology_command))
    app.add_handler(CommandHandler("report", report_command))
    app.add_handler(CommandHandler("clear", clear_command))
    app.add_handler(MessageHandler(filters.PHOTO, handle_photo))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    logger.info("🚀 Bug Bounty Hunter Bot v4 is running...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
