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
        for filename in sorted(os.listdir(knowledge_dir)):
            if filename.endswith(".md"):
                filepath = os.path.join(knowledge_dir, filename)
                with open(filepath, "r", encoding="utf-8") as f:
                    knowledge += f"\n\n{'='*60}\n"
                    knowledge += f"# FILE: {filename}\n"
                    knowledge += f"{'='*60}\n"
                    knowledge += f.read()
    return knowledge

KNOWLEDGE_BASE = load_knowledge_base()

SYSTEM_PROMPT = f"""You are an elite Bug Bounty Hunter and Web Security Expert.

Your expertise: XSS, SQLi, IDOR/BOLA, SSRF, XXE, RCE, CSRF, JWT, OAuth,
Business Logic, Race Conditions, Subdomain Takeover, CORS, LFI, SSTI,
Prototype Pollution, HTTP Request Smuggling, GraphQL, API Security,
Cloud Security (AWS/GCP/Azure), WAF Bypass.

When analyzing:
- SCREENSHOTS: Identify login pages, admin panels, error messages, 
  interesting parameters, forms, API endpoints visible in the image.
  Suggest what vulnerabilities to test based on what you see.

- URLs: Analyze the URL structure, parameters, endpoints.
  Identify injection points, interesting parameters, potential vulnerabilities.
  Give specific payloads to test.

- HTTP REQUESTS: Analyze headers, parameters, cookies, tokens.
  Identify: auth mechanisms, injection points, IDOR opportunities,
  missing security headers, interesting patterns.
  Give exact modified requests to test vulnerabilities.

- FILES (Burp logs, text files): Extract and analyze all endpoints,
  parameters, tokens. Build attack surface map. Prioritize targets.

- GENERAL QUESTIONS: Answer with hacker mindset, give practical
  commands, payloads, and tools.

Always:
1. Think like an attacker
2. Give specific, actionable payloads and commands
3. Prioritize by impact (Critical first)
4. Explain the full attack chain
5. Mention: authorized testing only

RULES:
- Only help with LEGAL security testing and authorized bug bounty programs
- Never assist with illegal hacking or unauthorized access
- Always emphasize responsible disclosure

Respond in the same language the user writes in (Arabic or English).

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

def is_url(text):
    url_pattern = re.compile(
        r'https?://[^\s]+'
        r'|www\.[^\s]+'
        r'|[a-zA-Z0-9-]+\.[a-zA-Z]{2,}[^\s]*'
    )
    return bool(url_pattern.search(text))

def is_http_request(text):
    http_methods = ['GET ', 'POST ', 'PUT ', 'DELETE ', 'PATCH ', 'OPTIONS ', 'HEAD ']
    return any(text.strip().startswith(method) for method in http_methods)

def detect_content_type(text):
    if is_http_request(text):
        return "http_request"
    elif is_url(text):
        return "url"
    else:
        return "question"

async def send_long_message(update, text):
    if len(text) > 4096:
        parts = [text[i:i+4096] for i in range(0, len(text), 4096)]
        for part in parts:
            await update.message.reply_text(part)
    else:
        await update.message.reply_text(text)

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    welcome_msg = (
        f"🎯 *مرحباً {user.first_name}!*\n\n"
        "أنا بوتك الخبير في *Bug Bounty Hunting* 🔐\n\n"
        "*أقدر أحلل:*\n"
        "🖼️ *Screenshots* - ارسل صورة من الهدف\n"
        "🔗 *URLs* - ارسل أي رابط لتحليله\n"
        "📋 *HTTP Requests* - الصق الـ request كامل\n"
        "📄 *ملفات* - Burp logs, text files, reports\n"
        "💬 *أسئلة* - أي سؤال عن Bug Bounty\n\n"
        "*أوامر:*\n"
        "/start - الرئيسية\n"
        "/help - المساعدة\n"
        "/recon - تقنيات Recon\n"
        "/vulns - قائمة الثغرات\n"
        "/tools - الأدوات\n"
        "/methodology - المنهجية\n"
        "/report - نموذج تقرير\n"
        "/clear - مسح المحادثة\n\n"
        "⚠️ *للاختبار القانوني والبرامج المصرح بها فقط*"
    )
    await update.message.reply_text(welcome_msg, parse_mode='Markdown')

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    help_msg = (
        "🛡️ *كيف تستخدم البوت*\n\n"
        "*1. ارسل Screenshot:*\n"
        "📸 صورة من الموقع الهدف\n"
        "→ البوت يحلل ويقترح الثغرات\n\n"
        "*2. ارسل URL:*\n"
        "🔗 https://target.com/api/user?id=123\n"
        "→ البوت يحلل المعاملات ويعطيك payloads\n\n"
        "*3. ارسل HTTP Request:*\n"
        "📋 الصق الـ request من Burp Suite\n"
        "→ البوت يحلل ويقترح الهجمات\n\n"
        "*4. ارسل ملف:*\n"
        "📄 Burp log, recon output, text file\n"
        "→ البوت يستخرج ويحلل كل شيء\n\n"
        "*5. اسأل مباشرة:*\n"
        "💬 كيف أستغل XXE؟\n"
        "→ شرح مع payloads وأوامر\n\n"
        "⚠️ للبرامج المصرح بها فقط!"
    )
    await update.message.reply_text(help_msg, parse_mode='Markdown')

async def recon_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🔍 *Recon Cheatsheet*\n\n"
        "*Subdomains:*\n"
        "```\nsubfinder -d target.com | httpx -silent\n"
        "amass enum -passive -d target.com\n"
        "assetfinder --subs-only target.com\n```\n\n"
        "*Screenshots:*\n"
        "```\ngowitness scan -f alive.txt\n```\n\n"
        "*CVE Scan:*\n"
        "```\nnuclei -l alive.txt -t cves/ -t exposures/\n```\n\n"
        "*Content Discovery:*\n"
        "```\nffuf -w wordlist.txt -u https://target.com/FUZZ\n```\n\n"
        "*GitHub Secrets:*\n"
        "```\ntrufflehog github --org=target\n```\n\n"
        "*Shodan:*\n"
        "```\norg:\"Target\" http.title:\"Dashboard\"\n"
        "ssl:\"target.com\" 200\n```\n\n"
        "*Parameters:*\n"
        "```\narjun -u https://target.com/api/endpoint\n"
        "paramspider -d target.com\n```"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def vulns_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🔥 *Vulnerability Priority List*\n\n"
        "*🔴 Critical:*\n"
        "• RCE - Remote Code Execution\n"
        "• Auth Bypass - تجاوز المصادقة\n"
        "• SQLi - SQL Injection\n"
        "• SSRF - Server-Side Request Forgery\n"
        "• XXE - XML External Entity\n\n"
        "*🟠 High:*\n"
        "• IDOR/BOLA - Broken Object Level Auth\n"
        "• Stored XSS - Cross-Site Scripting\n"
        "• JWT Attacks - alg:none, weak secret\n"
        "• Race Conditions - العمليات المالية\n"
        "• OAuth Misconfig\n\n"
        "*🟡 Medium:*\n"
        "• Reflected XSS\n"
        "• CSRF\n"
        "• Open Redirect\n"
        "• CORS Misconfiguration\n"
        "• Host Header Injection\n"
        "• Subdomain Takeover\n\n"
        "*🔵 Low/Info:*\n"
        "• Missing Security Headers\n"
        "• Information Disclosure\n"
        "• Rate Limiting Missing\n\n"
        "💬 اسألني عن أي ثغرة للتفاصيل!"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def tools_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🛠️ *Essential Bug Bounty Tools*\n\n"
        "*Recon:*\n"
        "• subfinder, amass, assetfinder\n"
        "• httpx, naabu, masscan\n"
        "• gowitness, aquatone\n"
        "• nuclei, nikto\n\n"
        "*Web Testing:*\n"
        "• Burp Suite Pro ← الأساس\n"
        "• ffuf, gobuster, feroxbuster\n"
        "• sqlmap, dalfox\n"
        "• jwt_tool, jwt.io\n"
        "• arjun, paramspider\n\n"
        "*Burp Extensions:*\n"
        "• Logger++\n"
        "• Autorize ← IDOR\n"
        "• Turbo Intruder ← Race Conditions\n"
        "• JWT Editor\n"
        "• Param Miner\n"
        "• Active Scan++\n\n"
        "*Secrets:*\n"
        "• trufflehog, gitleaks, gitrob\n\n"
        "*Cloud:*\n"
        "• cloud_enum, S3Scanner\n"
        "• pacu (AWS), ScoutSuite\n\n"
        "*Wordlists:*\n"
        "• SecLists ← الأساسي\n"
        "• Assetnote Wordlists"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def methodology_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "🎯 *Bug Bounty Methodology*\n\n"
        "*Order of Operations:*\n\n"
        "*1️⃣ Recon*\n"
        "• Subdomains, IPs, ASN\n"
        "• Tech stack, services\n"
        "• GitHub, Shodan, crt.sh\n\n"
        "*2️⃣ CVE Scan*\n"
        "• nuclei على كل الـ assets\n"
        "• Check framework versions\n\n"
        "*3️⃣ Walk the App*\n"
        "• استخدم التطبيق بشكل طبيعي\n"
        "• Burp Suite يسجل كل شيء\n"
        "• حدد Heat Map Areas\n\n"
        "*4️⃣ Content Discovery*\n"
        "• Directories, files, APIs\n"
        "• Hidden parameters\n\n"
        "*5️⃣ Manual Testing*\n"
        "• IDOR على كل ID\n"
        "• SSRF على كل URL param\n"
        "• XSS على كل input\n"
        "• Auth على كل endpoint\n\n"
        "*Heat Map 🔥:*\n"
        "🔥🔥🔥 Upload, Admin, New Features\n"
        "🔥🔥 API, Search, Profile, Export\n"
        "🔥 Static, Marketing pages"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def report_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "📝 *Bug Bounty Report Template*\n\n"
        "*Title:*\n"
        "[Vuln Type] in [Feature] allows [Impact]\n\n"
        "*Severity:* Critical / High / Medium / Low\n\n"
        "*Summary:*\n"
        "وصف مختصر للثغرة وتأثيرها\n\n"
        "*Steps to Reproduce:*\n"
        "1. اذهب إلى...\n"
        "2. أرسل الطلب التالي...\n"
        "3. لاحظ أن...\n\n"
        "*Impact:*\n"
        "ماذا يستطيع المهاجم أن يفعل؟\n\n"
        "*Proof of Concept:*\n"
        "Screenshot / Video / Code\n\n"
        "*Remediation:*\n"
        "كيف يتم الإصلاح؟\n\n"
        "💡 *نصائح:*\n"
        "• فيديو PoC = تقرير أقوى\n"
        "• اشرح الـ impact بوضوح\n"
        "• اقترح الإصلاح دائماً\n"
        "• كن محترفاً في الكتابة"
    )
    await update.message.reply_text(msg, parse_mode='Markdown')

async def clear_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user_conversations[user_id] = []
    await update.message.reply_text("✅ تم مسح المحادثة! ابدأ من جديد.")

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

        client = anthropic.Anthropic(
            api_key=os.environ.get("ANTHROPIC_API_KEY")
        )

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
                    f"Additional context: {caption}\n\n"
                    f"Please:\n"
                    f"1. Identify what you see (login page, admin panel, API, etc.)\n"
                    f"2. List interesting elements (forms, parameters, endpoints, errors)\n"
                    f"3. Suggest specific vulnerabilities to test\n"
                    f"4. Give exact payloads/techniques for each vulnerability\n"
                    f"5. Prioritize by impact (Critical first)\n"
                    f"6. Suggest next recon steps\n\n"
                    f"Think like an elite bug bounty hunter. Be specific and actionable."
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
        add_to_history(user_id, "user", f"[Image analysis] {caption}")
        add_to_history(user_id, "assistant", result)

        await send_long_message(update, result)

    except Exception as e:
        logger.error(f"Photo error: {e}")
        await update.message.reply_text(f"❌ خطأ في تحليل الصورة: {str(e)}")

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
            await update.message.reply_text(
                "❌ الملف كبير جداً (max 5MB)"
            )
            return

        file = await context.bot.get_file(doc.file_id)
        file_bytes = await file.download_as_bytearray()

        await update.message.reply_text(
            f"📄 جاري تحليل الملف: `{filename}`...",
            parse_mode='Markdown'
        )

        try:
            file_content = file_bytes.decode('utf-8')
        except UnicodeDecodeError:
            try:
                file_content = file_bytes.decode('latin-1')
            except Exception:
                file_content = str(file_bytes[:3000])

        if len(file_content) > 8000:
            file_content = file_content[:8000] + "\n\n[... truncated ...]"

        prompt = (
            f"Analyze this file from a bug bounty engagement.\n"
            f"Filename: {filename}\n"
            f"Additional context: {caption}\n\n"
            f"FILE CONTENT:\n{file_content}\n\n"
            f"Please:\n"
            f"1. Identify what type of file this is\n"
            f"2. Extract all endpoints, parameters, tokens, secrets\n"
            f"3. Build an attack surface map\n"
            f"4. Identify vulnerabilities and interesting patterns\n"
            f"5. Prioritize targets by impact\n"
            f"6. Give specific next steps and payloads\n\n"
            f"Think like an elite bug bounty hunter."
        )

        client = anthropic.Anthropic(
            api_key=os.environ.get("ANTHROPIC_API_KEY")
        )

        add_to_history(user_id, "user", prompt)

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
        await update.message.reply_text(f"❌ خطأ في تحليل الملف: {str(e)}")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user_message = update.message.text

    await context.bot.send_chat_action(
        chat_id=update.effective_chat.id, action="typing"
    )

    try:
        content_type = detect_content_type(user_message)

        if content_type == "url":
            prompt = (
                f"Analyze this URL from a bug bounty target:\n{user_message}\n\n"
                f"Please:\n"
                f"1. Break down the URL structure (domain, path, parameters)\n"
                f"2. Identify all injection points and interesting parameters\n"
                f"3. List potential vulnerabilities with exact payloads\n"
                f"4. Give modified URLs to test each vulnerability\n"
                f"5. Suggest additional endpoints to discover\n"
                f"6. Check for: IDOR, SQLi, XSS, SSRF, Path Traversal, etc.\n\n"
                f"Prioritize by impact. Be specific with payloads."
            )
        elif content_type == "http_request":
            prompt = (
                f"Analyze this HTTP request from a bug bounty target:\n\n"
                f"{user_message}\n\n"
                f"Please:\n"
                f"1. Identify the endpoint and HTTP method\n"
                f"2. Analyze all headers, cookies, tokens\n"
                f"3. List all parameters and their purpose\n"
                f"4. Identify security issues:\n"
                f"   - Auth mechanisms (JWT, session, API key)\n"
                f"   - IDOR opportunities (IDs, references)\n"
                f"   - Injection points (SQLi, XSS, SSRF, XXE)\n"
                f"   - Missing security headers\n"
                f"   - CSRF vulnerabilities\n"
                f"5. Give exact modified requests to test each vuln\n"
                f"6. Prioritize by impact\n\n"
                f"Think like an elite bug bounty hunter."
            )
        else:
            prompt = user_message

        add_to_history(user_id, "user", prompt)

        client = anthropic.Anthropic(
            api_key=os.environ.get("ANTHROPIC_API_KEY")
        )

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

    logger.info("🚀 Bug Bounty Hunter Bot v3 is running...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
