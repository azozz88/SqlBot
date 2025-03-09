import os
from dotenv import load_dotenv
import logging

# تحميل المتغيرات البيئية من ملف .env
load_dotenv()

# الحصول على التوكن من المتغيرات البيئية
TOKEN = os.getenv('DISCORD_TOKEN')

# التحقق من وجود التوكن
if not TOKEN:
    raise ValueError("لم يتم العثور على توكن Discord. تأكد من وجود DISCORD_TOKEN في ملف .env")

# إعدادات القنوات
SCAN_CHANNEL_ID = 1348279064389226546  # آيدي روم الفحص
TICKET_CATEGORY_ID = 1348279001436917841  # آيدي كاتيجوري التذاكر
TICKET_LOG_CHANNEL_ID = 1348281267950583808  # آيدي روم سجلات التذاكر

# إعدادات الأمان
SECURITY_CONFIG = {
    'max_requests_per_minute': 60,
    'timeout_seconds': 30,
    'max_redirects': 5
}

# إعدادات التذاكر
TICKET_CONFIG = {
    'prefix': '『🔒』ticket-',  # بادئة اسم التذكرة
    'staff_roles': [1161291288239427655],  # آيدي رتب الإدارة
    'embed_color': 0x2F3136,  # لون الـ embed
}