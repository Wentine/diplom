#!/usr/bin/env python3
import psycopg2
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, ReplyKeyboardMarkup, KeyboardButton
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes, JobQueue
import logging
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string
import atexit
from datetime import datetime, timedelta

# Настройка логирования
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Токен твоего Telegram-бота
TOKEN = "7822831638:AAG2JL3I-M8_Uk7CE0cS4zR8i4n7Irf9jBc"

# Конфигурация базы данных
DB_CONFIG = {
    'host': 'localhost',
    'database': 'secure_db',
    'user': 'user1_post',
    'password': '2077',
    'port': '5432'
}

# Флаг для отслеживания запущенного экземпляра
running_instance = False

class DatabaseManager:
    def __init__(self):
        self.conn = None
        self.connect()

    def connect(self):
        try:
            self.conn = psycopg2.connect(**DB_CONFIG)
            self.conn.autocommit = False
            logger.info("Подключение к PostgreSQL установлено")
        except Exception as e:
            logger.error(f"Ошибка подключения к PostgreSQL: {e}")
            raise

    def telegram_authenticate_user(self, username, password):
        try:
            with self.conn.cursor() as cursor:
                cursor.execute(
                    """SELECT telegram_password_hash 
                    FROM users WHERE username = %s AND is_active = TRUE""",
                    (username,)
                )
                result = cursor.fetchone()

                if result and result[0] and check_password_hash(result[0], password):
                    return True
                logger.info(f"Аутентификация для {username} не удалась: пароль не совпадает или не существует")
                return False
        except Exception as e:
            logger.error(f"Ошибка аутентификации Telegram: {e}")
            return False

    def telegram_register_user(self, username, password):
        try:
            with self.conn.cursor() as cursor:
                cursor.execute(
                    """SELECT telegram_password_hash 
                    FROM users WHERE username = %s AND is_active = TRUE""",
                    (username,)
                )
                result = cursor.fetchone()
                if result and result[0]:
                    logger.info(f"Пользователь {username} уже зарегистрирован в Telegram")
                    return False

                password_hash = generate_password_hash(password)
                cursor.execute(
                    """UPDATE users 
                    SET telegram_password_hash = %s
                    WHERE username = %s AND is_active = TRUE""",
                    (password_hash, username)
                )
                if cursor.rowcount > 0:
                    self.conn.commit()
                    logger.info(f"Регистрация в Telegram успешна для {username}")
                    return True
                else:
                    logger.error(f"Пользователь {username} не найден")
                    return False
        except Exception as e:
            logger.error(f"Ошибка регистрации в Telegram: {e}")
            self.conn.rollback()
            return False

    def telegram_generate_new_password(self, username):
        try:
            with self.conn.cursor() as cursor:
                new_password = self._generate_password()
                new_password_hash = generate_password_hash(new_password)
                cursor.execute(
                    """UPDATE users 
                    SET telegram_new_password_hash = %s,
                        telegram_new_password = %s,
                        password_change_time = %s
                    WHERE username = %s AND is_active = TRUE""",
                    (new_password_hash, new_password, datetime.now(), username)
                )
                if cursor.rowcount > 0:
                    self.conn.commit()
                    logger.info(f"Новый пароль сгенерирован для {username}: {new_password}")
                    return new_password
                else:
                    logger.error(f"Пользователь {username} не найден при генерации пароля")
                    return None
        except Exception as e:
            logger.error(f"Ошибка генерации нового пароля: {e}")
            self.conn.rollback()
            return None

    def telegram_get_new_password(self, username):
        try:
            with self.conn.cursor() as cursor:
                cursor.execute(
                    """SELECT telegram_new_password, telegram_new_password_hash 
                    FROM users WHERE username = %s AND is_active = TRUE""",
                    (username,)
                )
                result = cursor.fetchone()
                if result and result[0]:
                    new_password = result[0]
                    new_password_hash = result[1]
                    # Обновляем current_password_hash, чтобы сайт мог авторизовать
                    cursor.execute(
                        """UPDATE users 
                        SET current_password_hash = %s
                        WHERE username = %s AND is_active = TRUE""",
                        (new_password_hash, username)
                    )
                    self.conn.commit()
                    logger.info(f"Пароль получен для {username}, current_password_hash обновлён")
                    return new_password
                logger.info(f"Пароль для {username} недоступен: {result}")
                return None
        except Exception as e:
            logger.error(f"Ошибка получения пароля для {username}: {e}")
            return None

    def has_valid_new_password(self, username):
        try:
            with self.conn.cursor() as cursor:
                cursor.execute(
                    """SELECT telegram_new_password, password_change_time 
                    FROM users WHERE username = %s AND is_active = TRUE""",
                    (username,)
                )
                result = cursor.fetchone()
                if result and result[0]:  # Если пароль существует
                    change_time = result[1]
                    if change_time:
                        current_time = datetime.now()
                        time_diff = current_time - change_time
                        if time_diff < timedelta(minutes=5):
                            logger.info(f"Пароль для {username} ещё действителен")
                            return result[0]  # Возвращаем существующий пароль
                logger.info(f"Нет действительного пароля для {username}")
                return None
        except Exception as e:
            logger.error(f"Ошибка проверки пароля для {username}: {e}")
            return None

    def get_users_for_password_update(self):
        try:
            with self.conn.cursor() as cursor:
                cursor.execute(
                    """SELECT username, password_change_time 
                    FROM users 
                    WHERE telegram_new_password IS NOT NULL AND is_active = TRUE"""
                )
                return cursor.fetchall()
        except Exception as e:
            logger.error(f"Ошибка получения пользователей для обновления пароля: {e}")
            return []

    def _generate_password(self):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=12))

db = DatabaseManager()

# Обработчик команды /start
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    # Создаём меню с кнопками
    keyboard = [
        [KeyboardButton("/register User password")],
        [KeyboardButton("/login User password")]
    ]
    reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True, one_time_keyboard=False)
    await update.message.reply_text(
        "Привет! Выбери действие из меню ниже:",
        reply_markup=reply_markup
    )

# Обработчик команды /login
async def login(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args or len(context.args) != 2:
        await update.message.reply_text("Используй: /login <username> <password>")
        return

    username, password = context.args
    if db.telegram_authenticate_user(username, password):
        await update.message.reply_text(f"Авторизация успешна, {username}!")

        # Проверяем, есть ли действующий пароль
        existing_password = db.has_valid_new_password(username)
        if not existing_password:
            # Генерируем новый пароль только если его нет или он устарел
            new_password = db.telegram_generate_new_password(username)
            if not new_password:
                await update.message.reply_text("Ошибка генерации пароля. Обратитесь к администратору.")
                return
        else:
            logger.info(f"Используем существующий пароль для {username}")

        # Показываем кнопку для получения пароля
        keyboard = [
            [InlineKeyboardButton("Показать пароль", callback_data=f"get_password_{username}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await update.message.reply_text("Нажми, чтобы показать пароль:", reply_markup=reply_markup)
    else:
        await update.message.reply_text("Неверный логин или пароль. Зарегистрируйся с /register.")

# Обработчик команды /register
async def register(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args or len(context.args) != 2:
        await update.message.reply_text("Используй: /register <username> <password>")
        return

    username, password = context.args
    if db.telegram_register_user(username, password):
        await update.message.reply_text(f"Регистрация успешна, {username}!")
    else:
        await update.message.reply_text("Ошибка регистрации. Пользователь уже есть или не создан в системе.")

# Обработчик кнопки "Показать пароль"
async def button(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()

    if query.data.startswith("get_password_"):
        username = query.data.replace("get_password_", "")
        new_password = db.telegram_get_new_password(username)
        if new_password:
            await query.message.reply_text(f"Твой пароль: {new_password}")
        else:
            await query.message.reply_text("Пароль недоступен. Повтори /login для обновления.")

# Функция для обновления паролей каждые 5 минут
async def update_passwords(context: ContextTypes.DEFAULT_TYPE) -> None:
    users = db.get_users_for_password_update()
    current_time = datetime.now()

    for username, change_time in users:
        if change_time and (current_time - change_time) >= timedelta(minutes=5):
            logger.info(f"Обновляю пароль для {username}, прошло 5 минут")
            db.telegram_generate_new_password(username)

def cleanup():
    global running_instance
    running_instance = False
    logger.info("Бот остановлен.")

def main() -> None:
    global running_instance
    if running_instance:
        logger.error("Другой экземпляр бота уже работает. Выход.")
        return

    application = Application.builder().token(TOKEN).build()
    running_instance = True
    atexit.register(cleanup)

    # Настройка JobQueue для обновления паролей каждые 5 минут
    try:
        job_queue = application.job_queue
        if job_queue:
            job_queue.run_repeating(update_passwords, interval=300, first=0)
            logger.info("JobQueue настроен для обновления паролей каждые 5 минут")
        else:
            logger.warning("JobQueue недоступен. Установи python-telegram-bot[job-queue]")
    except AttributeError:
        logger.warning("JobQueue не поддерживается. Установи python-telegram-bot[job-queue] для работы.")

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("login", login))
    application.add_handler(CommandHandler("register", register))
    application.add_handler(CallbackQueryHandler(button))

    application.run_polling()

if __name__ == '__main__':
    main()