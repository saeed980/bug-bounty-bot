import os
import logging
import anthropic
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# Logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Load knowledge base
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
- Be direct and specific — no fluff
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

You have access to a comprehensive knowledge base of Bug Bounty techniques. Use it to give accurate, 
detailed answers. Always respond in the same language the user writes in (Arabic or English).

KNOWLEDGE BASE:
{KNOWLEDGE_BASE}

When responding:
1. Be specific and technical
2. Give actual commands, payloads, and tools when relevant
3. Explain the "why" behind techniques
4. Suggest the full attack chain when applicable
5. Always mention: authorized testing only
"""

# Store conversation history per user
user_conversations = {}

def get_user_history(user_id: int) -> list:
    if user_id not in user_conversations:
        user_conversations[user_id] = []
    return user_conversations[user_id]

def add_to_history(user_id: int, role: str, content: str):
    history = get_user_history(user_id)
    history.append({"role": role, "content": content})
    # Keep last 20 messages to avoid token limit
    if len(history) > 20:
        user_conversations[user_id] = history[-20:]

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    welcome_msg = f"""🎯 *مرحباً {user.first_name}!*

أنا بوتك الخبير في *Bug Bounty Hunting* و أمن الويب 🔐

*ما أقدر أساعدك فيه:*
🔍 استراتيجيات الـ Recon والـ OSINT
🔥 اكتشاف الثغرات (XSS, SQLi, IDOR, SSRF, ...)
📊 تحليل التطبيقات وعمل Heat Mapping
🛠️ أدوات وأوامر جاهزة للاستخدام
📝 كتابة تقارير Bug Bounty احترافية
🎯 استراتيجيات للفوز بـ Bounties

*أوامر متاحة:*
/start - بداية جديدة
/help - شرح مفصل
/recon - تقنيات الـ Recon
/vulns - قائمة الثغرات
/tools - أدوات مهمة
/methodology - منهجية الاختبار
/clear - مسح المحادثة

💬 أو فقط اسألني أي سؤال مباشرة!

⚠️ *ملاحظة:* هذا البوت للاختبار القانوني والبرامج المصرح بها فقط."""

    await update.message.reply_text(welcome_msg, parse_mode='Markdown')

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    help_msg = """🛡️ *Bug Bounty Hunter Bot - دليل الاستخدام*

*طريقة الاستخدام:*
اكتب سؤالك مباشرة أو اختر أمر من القائمة

*أمثلة على أسئلة:*
• كيف أبحث عن Subdomains للهدف؟
• شرح هجمة SSRF مع payloads
• كيف أكتشف IDOR في API؟
• ما الأدوات المطلوبة لـ Bug Bounty؟
• كيف أعمل تحليل لتطبيق ويب جديد؟
• شرح XXE attack مع مثال عملي
• كيف أتحايل على WAF؟

*المواضيع المتاحة:*
🔍 Recon → ASN, Subdomains, OSINT, Shodan
🔥 Vulns → XSS, SQLi, IDOR, SSRF, XXE, RCE...
📊 Analysis → Tech Profiling, Heat Mapping
🛠️ Tools → Burp Suite, Nuclei, ffuf, sqlmap...
🎯 Methodology → Order of Operations
📝 Reports → كتابة تقارير احترافية

⚠️ للاستخدام في البرامج المصرح بها فقط!"""
    await update.message.reply_text(help_msg, parse_mode='Markdown')

async def recon_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    recon_msg = """🔍 *تقنيات الـ Recon السريعة*

*1. Subdomain Enumeration:*
```
subfinder -d target.com -o subs.txt
amass enum -passive -d target.com
assetfinder target.com
```

*2. Live Hosts:*
```
cat subs.txt | httpx -silent -o alive.txt
```

*3. Screenshots:*
```
gowitness scan -f alive.txt
```

*4. Shodan:*
```
org:"Target Company"
ssl:"target.com"
```

*5. GitHub Secrets:*
```
trufflehog github --org=target
```

*6. Nuclei CVE Scan:*
```
nuclei -l alive.txt -t cves/ -t exposures/
```

💬 اسألني عن أي تقنية بالتفصيل!"""
    await update.message.reply_text(recon_msg, parse_mode='Markdown')

async def vulns_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    vulns_msg = """🔥 *قائمة الثغرات حسب الأولوية*

*🔴 Critical / High:*
• IDOR/BOLA - تغيير الـ IDs
• SSRF - أي URL parameter
• XXE - XML inputs
• SQLi - كل input → DB
• Auth Bypass - تجاوز تسجيل الدخول
• RCE - تنفيذ أوامر

*🟠 High / Medium:*
• Stored XSS - يُخزن في قاعدة البيانات
• JWT Attacks - alg:none, weak secret
• CSRF - طلبات بدون token
• Race Conditions - العمليات المالية
• Host Header Injection

*🟡 Medium:*
• Reflected XSS
• Open Redirect
• CORS Misconfiguration
• Subdomain Takeover
• Mass Assignment

*🔵 Extra:*
• SSTI → RCE
• Prototype Pollution
• OAuth Misconfig
• GraphQL Attacks

💬 اسألني عن أي ثغرة بالتفصيل مع الـ payloads!"""
    await update.message.reply_text(vulns_msg, parse_mode='Markdown')

async def tools_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    tools_msg = """🛠️ *أدوات Bug Bounty الأساسية*

*Recon:*
• `amass` - ASN & Subdomains
• `subfinder` - Passive Recon
• `httpx` - HTTP Probing
• `gowitness` - Screenshots
• `nuclei` - CVE Scanning

*Web Testing:*
• `Burp Suite Pro` - الأساس
• `ffuf` - Fuzzing
• `sqlmap` - SQL Injection
• `dalfox` - XSS
• `jwt_tool` - JWT Attacks

*Secrets:*
• `trufflehog` - GitHub Secrets
• `gitleaks` - Git Scanning

*Cloud:*
• `cloud_enum` - Cloud Discovery
• `S3Scanner` - S3 Buckets

*Burp Extensions:*
• Logger++
• Autorize (IDOR)
• Turbo Intruder
• JWT Editor
• Param Miner

💬 اسألني عن استخدام أي أداة!"""
    await update.message.reply_text(tools_msg, parse_mode='Markdown')

async def methodology_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    method_msg = """🎯 *منهجية الاختبار - Order of Operations*

*الخطوات بالترتيب:*

*1️⃣ Automated Vuln Discovery*
```
nuclei -u target.com -t cves/
nikto -h target.com
```

*2️⃣ Walk & Use App*
• استخدم التطبيق كمستخدم عادي
• افتح Burp Suite وسجل كل شيء
• حدد Heat Map Areas

*3️⃣ Content Discovery*
```
ffuf -w wordlist.txt -u target.com/FUZZ
```

*4️⃣ Dynamic Scanning*
• Scan فقط الـ High-Heat endpoints

*5️⃣ Manual Testing*
• IDOR → غير كل ID
• SSRF → كل URL parameter
• XSS → كل input field
• SQLi → كل DB query

*Heat Map Priority:*
🔥🔥🔥 File Upload, Admin, New Features
🔥🔥 Search, Profile, Export
🔥 Static Pages

💬 اسألني عن أي خطوة بالتفصيل!"""
    await update.message.reply_text(method_msg, parse_mode='Markdown')

async def clear_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user_conversations[user_id] = []
    await update.message.reply_text("✅ تم مسح المحادثة! ابدأ سؤالك الجديد.")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user_message = update.message.text
    
    # Show typing indicator
    await context.bot.send_chat_action(chat_id=update.effective_chat.id, action="typing")
    
    try:
        # Add user message to history
        add_to_history(user_id, "user", user_message)
        
        # Call Claude API
        client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
        
        response = client.messages.create(
            model="claude-opus-4-5",
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            messages=get_user_history(user_id)
        )
        
        assistant_message = response.content[0].text
        
        # Add assistant response to history
        add_to_history(user_id, "assistant", assistant_message)
        
        # Send response (split if too long)
        if len(assistant_message) > 4096:
            parts = [assistant_message[i:i+4096] for i in range(0, len(assistant_message), 4096)]
            for part in parts:
                await update.message.reply_text(part)
        else:
            await update.message.reply_text(assistant_message)
            
    except Exception as e:
        logger.error(f"Error: {e}")
        await update.message.reply_text(
            "❌ حدث خطأ. تأكد من إعداد ANTHROPIC_API_KEY بشكل صحيح.\n"
            f"Error: {str(e)}"
        )

def main():
    token = os.environ.get("8932352806:AAHJFUfVdrM3oucm5mH9sWRiCe0tOjlq-nQ")
    if not token:
        raise ValueError("TELEGRAM_BOT_TOKEN environment variable not set!")
    
    app = Application.builder().token(token).build()
    
    # Commands
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("recon", recon_command))
    app.add_handler(CommandHandler("vulns", vulns_command))
    app.add_handler(CommandHandler("tools", tools_command))
    app.add_handler(CommandHandler("methodology", methodology_command))
    app.add_handler(CommandHandler("clear", clear_command))
    
    # Messages
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    logger.info("🚀 Bug Bounty Hunter Bot is running...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
