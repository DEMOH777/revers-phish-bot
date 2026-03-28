import requests
import telebot
import whois
import re
from datetime import datetime

TOKEN = "8727461047:AAHaWiD9PoExQdid_fDc4Gc2sJRSC3VGLcI"
VT_KEY = "1992e6ca7eb6474426aedee99d9743ce9d93938e75118f899f4ef25a7b6dedbb"

bot = telebot.TeleBot(TOKEN)

def vt_check(url):
    try:
        r = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params={'apikey': VT_KEY, 'resource': url})
        d = r.json()
        if d.get('response_code') == 1:
            p = d.get('positives', 0)
            t = d.get('total', 0)
            return ('danger', f'⚠️ {p}/{t} угроз') if p > 0 else ('safe', f'✅ {p}/{t} угроз')
        return ('unknown', '❓ не найдено')
    except:
        return ('error', '❌ ошибка')

def whois_check(domain):
    try:
        w = whois.whois(domain)
        if w.creation_date:
            c = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            days = (datetime.now() - c).days
            if days < 30: return ('danger', f'⚠️ {days} дней')
            if days < 90: return ('warning', f'⚠️ {days} дней')
            return ('safe', f'✅ {days} дней')
        return ('warning', '⚠️ не определен')
    except:
        return ('warning', '⚠️ whois недоступен')

def bad_words(url):
    words = ['login', 'secure', 'verify', 'account', 'bank', 'paypal', 'confirm', 'update', 'signin', 'auth', 'password']
    return [w for w in words if w in url.lower()]

@bot.message_handler(commands=['start'])
def start(m):
    bot.reply_to(m, 
        "🛡️ **REVERS | Проверка ссылок**\n\n"
        "Бот помогает оценить безопасность ссылок.\n"
        "Анализирует:\n"
        "• репутацию в открытых базах\n"
        "• возраст домена\n"
        "• подозрительные слова\n\n"
        "📌 Автор: @ReversSecurity\n"
        "📌 Канал: <https://t.me/+QTjW7b6ZU1VhODVl>\n\n"
        "🔍 Используй команду: /check ссылка\n"
        "Пример: /check https://google.com"
    )

@bot.message_handler(commands=['help'])
def help_cmd(m):
    bot.reply_to(m, 
        "📖 **Инструкция**\n\n"
        "/check ссылка — проверить ссылку\n\n"
        "Бот покажет:\n"
        "• сколько антивирусов её уже отметили\n"
        "• когда зарегистрирован домен\n"
        "• есть ли в ссылке типичные маркеры мошенников\n\n"
        "🛡️ REVERS — кибербезопасность без компромиссов"
    )

@bot.message_handler(commands=['check'])
def check(m):
    try:
        parts = m.text.split(maxsplit=1)
        if len(parts) < 2:
            bot.reply_to(m, "❌ Укажи ссылку. Пример: /check https://google.com")
            return
        url = parts[1].strip()
        bot.send_chat_action(m.chat.id, 'typing')
        
        domain = re.findall(r'https?://([^/]+)', url)
        domain = domain[0] if domain else url
        
        vt_status, vt_msg = vt_check(url)
        who_status, who_msg = whois_check(domain)
        bad = bad_words(url)
        
        msg = f"🔍 **REVERS | Проверка**\n"
        msg += f"📎 Ссылка: {url}\n"
        msg += f"🌐 Домен: {domain}\n\n"
        msg += f"{vt_msg}\n"
        msg += f"{who_msg}\n"
        msg += f"{'⚠️ Маркеры: ' + ', '.join(bad) if bad else '✅ Подозрительных маркеров нет'}\n\n"
        
        if vt_status == 'danger' or who_status == 'danger' or bad:
            msg += "⚠️ **Внимание: ссылка требует осторожности**\n"
            msg += "Рекомендуем не переходить и не вводить личные данные."
        else:
            msg += "✅ **Предварительных признаков опасности не найдено**\n"
            msg += "Но всегда проверяйте адрес сайта вручную."
        
        msg += f"\n\n🛡️ REVERS | @ReversSecurity"
        bot.reply_to(m, msg)
    except Exception as e:
        bot.reply_to(m, f"❌ Ошибка: {e}")

print("Бот REVERS запущен")
bot.infinity_polling()
