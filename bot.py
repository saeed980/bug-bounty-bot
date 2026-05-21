import os
import logging
import anthropic
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

SYSTEM_PROMPT = f"""You are an elite Bug Bounty Hunter and Web Security Expert with deep expertise in:
- Reconnaissance & OSINT
- Web Application Penetration Testing
- Vulnerability Research & Exploitation
- Bug Bounty Programs (HackerOne, Bugcrowd, Intigriti)

Your personality:
- Think like an attacker with a hacker mindset
- Give practical, actionable advice
- Use real-world examples and payloads
- Be direct and specific, no fluff
- Prioritize high-impact vulnerabilities
- Always think about the full attack chain

Your expertise covers: XSS, SQLi, IDOR/BOLA, SSRF, XXE, RCE, CSRF, JWT attacks, OAuth misconfigs,
Business Logic flaws, Race Conditions, Subdomain Takeover, CORS, LFI/RFI, SSTI, Prototype Pollution,
HTTP Request Smuggling, GraphQL, API Security, Cloud Security (AWS/GCP/Azure), WAF Bypass techniques.

IMPORTANT RULES:
- Only help with LEGAL security testing, bug bounty programs, and authorized penetration testing
- Never help with illegal hacking, attacking systems without permission, or malicious activities
- Always emphasize responsible disclosure and ethical hacking
- When giving payloads or techniques, always mention they should only be used on authorized targets

Always respond in the same language the user writes in (Arabic or English).

KNOWLEDGE BASE:
{KNOWLEDGE_BASE}

When responding:
1. Be specific and technical
2. Give actual commands, payloads, and tools when relevant
3. Explain the why behind techniques
4. Suggest the full attack chain when applicable
5. Always mention: authorized testing only
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

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    welcome_msg = (
        f"🎯 *مرحباً {user.first_name}!*\n\n"
        "أنا بوتك الخبير في *Bug Bounty Hunting* و أمن الويب 🔐\n\n"
        "*ما أقدر أساعدك فيه:*\n"
        "🔍 استراتيجيات الـ Recon والـ OSINT\n"
        "🔥 اكتشاف الثغرات (XSS, SQLi, IDOR, SSRF...)\n"
        "📊 تحليل التطبيقات وعمل Heat Mapping\n"
        "🛠️ أدوات وأوامر جاهزة للاستخدام\n"
        "📝 كتابة تقارير Bug Bounty احترافية\n"
        "🎯 استراتيجيات للفوز بـ Bounties\n\n"
        "*أوامر متاحة:*\n"
        "/start - بداية جديدة\n"
        "/help - شرح مفصل\n"
        "/recon - تقنيات الـ Recon\n"
        "/vulns - قائمة الثغرات\n"
        "/tools - أدوات مهمة\n"
        "/methodology - منهجية الاختبار\n"
        "/clear - مسح المحادثة\n\n"
        "💬 أو فقط اسألني أي سؤال مباشرة!\n\n"
        "⚠️ *للاختبار القانوني والبرامج المصرح بها فقط*"
    )
    await update.message.reply_text(welcome_msg, parse_mode='Markdown')

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    help_msg = (
        "🛡️ *Bug Bounty Hunter Bot - دليل الاستخدام*\n\n"
        "*أمثلة على أسئلة:*\n"
        "• كيف أبحث عن Subdomains للهدف؟\n"
        "• شرح هجمة SSRF مع payloads\n"
        "• كيف أكتشف IDOR في API؟\n"
        "• ما الأدوات المطلوبة لـ Bug Bounty؟\n"
        "• كيف أعمل تحليل لتطبيق ويب جديد؟\n"
        "• شرح XXE attack مع مثال عملي\n"
        "• كيف أتحايل على WAF؟\n\n"
        "*المواضيع المتاحة:*\n"
        "🔍 Recon - ASN, Subdomains, OSINT, Shodan\n"
        "🔥 Vulns - XSS, SQLi, IDOR, SSRF, XXE, RCE\n"
        "📊 Analysis - Tech Profiling, Heat Mapping\n"
        "🛠️ Tools - Burp Suite, Nuclei, ffuf, sqlmap\n"
        "🎯 Methodology - Order of Operations\n"
        "📝 Reports - كتابة تقارير احترافية\n\n"
        "⚠️ للاستخدام في البرامج المصرح بها فقط!"
    )
    await update.message.reply_text(help_msg, parse_mode='Markdown')

async def recon_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    recon_msg = (
        "🔍 *تقنيات الـ Recon السريعة*\n\n"
        "*1. Subdomain Enumeration:*\n"
        "```\nsubfinder -d target.com -o subs.txt\n"
        "amass enum -passive -d target.com\n"
        "assetfinder target.com\n```\n\n"
        "*2. Live Hosts:*\n"
        "```\ncat subs.txt | httpx -silent -o alive.txt\n```\n\n"
        "*3. Screenshots:*\n"
        "```\ngowitness scan -f alive.txt\n```\n\n"
        "*4. Shodan:*\n"
        "```\norg:\"Target Company\"\nssl:\"target.com\"\n```\n\n"
        "*5. GitHub Secrets:*\n"
        "```\ntrufflehog github --org=target\n```\n\n"
        "*6. Nuclei CVE Scan:*\n"
        "```\nnuclei -l alive.txt -t cves/ -t exposures/\n```\n\n"
        "💬 اسألني عن أي تقنية بالتفصيل!"
    )
    await update.message.reply_text(recon_msg, parse_mode='Markdown')

async def vulns_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    vulns_msg = (
        "🔥 *قائمة الثغرات حسب الأولوية*\n\n"
        "*🔴 Critical / High:*\n"
        "• IDOR/BOLA - تغيير الـ IDs\n"
        "• SSRF - أي URL parameter\n"
        "• XXE - XML inputs\n"
        "• SQLi - كل input إلى DB\n"
        "• Auth Bypass - تجاوز تسجيل الدخول\n"
        "• RCE - تنفيذ أوامر\n\n"
        "*🟠 High / Medium:*\n"
        "• Stored XSS - يُخزن في قاعدة البيانات\n"
        "• JWT Attacks - alg:none, weak secret\n"
        "• CSRF - طلبات بدون token\n"
        "• Race Conditions - العمليات المالية\n"
        "• Host Header Injection\n\n"
        "*🟡 Medium:*\n"
        "• Reflected XSS\n"
        "• Open Redirect\n"
        "• CORS Misconfiguration\n"
        "• Subdomain Takeover\n"
        "• Mass Assignment\n\n"
        "*🔵 Extra:*\n"
        "• SSTI - قد يؤدي إلى RCE\n"
        "• Prototype Pollution\n"
        "• OAuth Misconfig\n"
        "• GraphQL Attacks\n\n"
        "💬 اسألني عن أي ثغرة بالتفصيل مع الـ payloads!"
    )
    await update.message.reply_text(vulns_msg, parse_mode='Markdown')

async def tools_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    tools_msg = (
        "🛠️ *أدوات Bug Bounty الأساسية*\n\n"
        "*Recon:*\n"
        "• amass - ASN & Subdomains\n"
        "• subfinder - Passive Recon\n"
        "• httpx - HTTP Probing\n"
        "• gowitness - Screenshots\n"
        "• nuclei - CVE Scanning\n\n"
        "*Web Testing:*\n"
        "• Burp Suite Pro - الأساس\n"
        "• ffuf - Fuzzing\n"
        "• sqlmap - SQL Injection\n"
        "• dalfox - XSS\n"
        "• jwt_tool - JWT Attacks\n\n"
        "*Secrets:*\n"
        "• trufflehog - GitHub Secrets\n"
        "• gitleaks - Git Scanning\n\n"
        "*Cloud:*\n"
        "• cloud_enum - Cloud Discovery\n"
        "• S3Scanner - S3 Buckets\n\n"
        "*Burp Extensions:*\n"
        "• Logger++\n"
        "• Autorize (IDOR)\n"
        "• Turbo Intruder\n"
        "• JWT Editor\n"
        "• Param Miner\n\n"
        "💬 اسألني عن استخدام أي أداة!"
    )
    await update.message.reply_text(tools_msg, parse_mode='Markdown')

async def methodology_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    method_msg = (
        "🎯 *منهجية الاختبار - Order of Operations*\n\n"
        "*الخطوات بالترتيب:*\n\n"
        "*1️⃣ Automated Vuln Discovery*\n"
        "```\nnuclei -u target.com -t cves/\nnikto -h target.com\n```\n\n"
        "*2️⃣ Walk & Use App*\n"
        "• استخدم التطبيق كمستخدم عادي\n"
        "• افتح Burp Suite وسجل كل شيء\n"
        "• حدد Heat Map Areas\n\n"
        "*3️⃣ Content Discovery*\n"
        "```\nffuf -w wordlist.txt -u target.com/FUZZ\n```\n\n"
        "*4️⃣ Dynamic Scanning*\n"
        "• Scan فقط الـ High-Heat endpoints\n\n"
        "*5️⃣ Manual Testing*\n"
        "• IDOR - غير كل ID\n"
        "• SSRF - كل URL parameter\n"
        "• XSS - كل input field\n"
        "• SQLi - كل DB query\n\n"
        "*Heat Map Priority:*\n"
        "🔥🔥🔥 File Upload, Admin, New Features\n"
        "🔥🔥 Search, Profile, Export\n"
        "🔥 Static Pages\n\n"
        "💬 اسألني عن أي خطوة بالتفصيل!"
    )
    await update.message.reply_text(method_msg, parse_mode='Markdown')

async def clear_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user_conversations[user_id] = []
    await update.message.reply_text("✅ تم مسح المحادثة! ابدأ سؤالك الجديد.")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user_message = update.message.text

    await context.bot.send_chat_action(
        chat_id=update.effective_chat.id,
        action="typing"
    )

    try:
        add_to_history(user_id, "user", user_message)

        client = anthropic.Anthropic(
            api_key=os.environ.get("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")
        )

        response = client.messages.create(
            model="claude-opus-4-5",
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            messages=get_user_history(user_id)
        )

        assistant_message = response.content[0].text
        add_to_history(user_id, "assistant", assistant_message)

        if len(assistant_message) > 4096:
            parts = [
                assistant_message[i:i+4096]
                for i in range(0, len(assistant_message), 4096)
            ]
            for part in parts:
                await update.message.reply_text(part)
        else:
            await update.message.reply_text(assistant_message)

    except Exception as e:
        logger.error(f"Error: {e}")
        await update.message.reply_text(
            "❌ حدث خطأ، حاول مرة ثانية.\n"
            f"Error: {str(e)}"
        )

def main():
    token = os.environ.get("8932352806:AAHJFUfVdrM3oucm5mH9sWRiCe0tOjlq-nQ")
    if not token:
        raise ValueError("TELEGRAM_BOT_TOKEN environment variable not set!")

    app = Application.builder().token(token).build()

    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("recon", recon_command))
    app.add_handler(CommandHandler("vulns", vulns_command))
    app.add_handler(CommandHandler("tools", tools_command))
    app.add_handler(CommandHandler("methodology", methodology_command))
    app.add_handler(CommandHandler("clear", clear_command))
    app.add_handler(MessageHandler(
        filters.TEXT & ~filters.COMMAND,
        handle_message
    ))

    logger.info("🚀 Bug Bounty Hunter Bot is running...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
