from discord.ext import commands
import discord
from security_scanner import AdvancedSecurityScanner
from ticket_system import TicketSystem
from config import TOKEN
import logging
import asyncio

class SecurityBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.message_content = True
        intents.guilds = True
        intents.messages = True
        super().__init__(command_prefix='!', intents=intents)
        
        # إعداد التسجيل
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('bot.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('SecurityBot')

    async def setup_hook(self):
        try:
            # تحميل الامتدادات
            await self.load_extension('security_scanner')
            await self.load_extension('ticket_system')
            self.logger.info("تم تحميل جميع الامتدادات بنجاح")
        except Exception as e:
            self.logger.error(f"خطأ في تحميل الامتدادات: {e}")
            raise e

    async def on_ready(self):
        self.logger.info(f'Bot is ready as {self.user}')
        await self.change_presence(activity=discord.Game(name="!scan للفحص الأمني"))

    async def on_command_error(self, ctx, error):
        if isinstance(error, commands.CommandNotFound):
            await ctx.send("❌ الأمر غير موجود. استخدم !scan [رابط] لفحص موقع.")
        else:
            self.logger.error(f"Error: {str(error)}")
            await ctx.send(f"❌ حدث خطأ: {str(error)}")

async def main():
    bot = SecurityBot()
    try:
        await bot.start(TOKEN)
    except discord.LoginFailure:
        bot.logger.critical("فشل تسجيل الدخول: توكن غير صالح")
    except Exception as e:
        bot.logger.critical(f"فشل تشغيل البوت: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())