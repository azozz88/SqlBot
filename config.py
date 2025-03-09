import os
from dotenv import load_dotenv
import logging

# تحميل المتغيرات البيئية
load_dotenv()

# الحصول على التوكن من المتغيرات البيئية
TOKEN = os.getenv('DISCORD_TOKEN')

# التحقق من وجود التوكن
if not TOKEN:
    raise ValueError("لم يتم العثور على توكن Discord. تأكد من وجود DISCORD_TOKEN في ملف .env")

# إعدادات القنوات
SCAN_CHANNEL_ID = int(os.getenv('SCAN_CHANNEL_ID', '1348279064389226546'))
TICKET_CATEGORY_ID = int(os.getenv('TICKET_CATEGORY_ID', '1348279001436917841'))
TICKET_LOG_CHANNEL_ID = int(os.getenv('TICKET_LOG_CHANNEL_ID', '1348281267950583808'))

# إعدادات الأمان
SECURITY_CONFIG = {
    'max_requests_per_minute': 60,
    'timeout_seconds': 30,
    'max_redirects': 5,
    'allowed_schemes': ['http', 'https'],
    'blocked_ips': [],
    'blocked_domains': [],
    'scan_delay': 2,  # ثواني بين كل فحص
    'max_response_size': 5242880,  # 5MB
    'user_agent': 'SecurityScanner/1.0'
}

# إعدادات التذاكر
TICKET_CONFIG = {
    'prefix': '『🔒』ticket-',  # بادئة اسم التذكرة
    'staff_roles': [1161291288239427655],  # آيدي رتب الإدارة
    'embed_color': 0x2F3136,  # لون الـ embed
    'ticket_limit': 5,  # الحد الأقصى للتذاكر المفتوحة لكل مستخدم
    'auto_close': 24,  # إغلاق تلقائي بعد × ساعة من عدم النشاط
    'cooldown': 300,  # فترة الانتظار بين التذاكر (بالثواني)
}

# إعدادات التسجيل
LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        },
    },
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': 'bot.log',
            'formatter': 'standard'
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'standard'
        }
    },
    'loggers': {
        '': {
            'handlers': ['file', 'console'],
            'level': 'DEBUG',
            'propagate': True
        }
    }
}
