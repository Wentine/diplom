#!/usr/bin/env python3
from flask import Flask, render_template_string, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
from cryptography.fernet import Fernet
import os
from datetime import datetime, timedelta
import logging
import requests
import random
import string
import re
from flask_talisman import Talisman
from flask_seasurf import SeaSurf

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler('server.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('SecureServer')

app = Flask(__name__)
app.secret_key = "keyGenDavinhiResolve2005yoou"  # Замени на свой ключ

# Защита заголовков
Talisman(app, content_security_policy=None)
csrf = SeaSurf(app)

# Конфигурация Telegram бота
TELEGRAM_BOT_TOKEN = "7670202314:AAHYpYPRZhdeWYy4DHggWbb9mFFWY-E0tug"
TELEGRAM_CHAT_ID = "648372978"

# Конфигурация базы данных
DB_CONFIG = {
    'host': 'localhost',
    'database': 'secure_db',
    'user': 'user1_post',
    'password': '2077',
    'port': '5432'
}

class DatabaseManager:
    def __init__(self):
        self.conn = None
        self.connect()

    def connect(self):
        try:
            self.conn = psycopg2.connect(**DB_CONFIG)
            self.conn.autocommit = False
            self._initialize_db()
            logger.info("Подключение к PostgreSQL установлено")
        except Exception as e:
            logger.error(f"Ошибка подключения к PostgreSQL: {e}")
            raise

    def _initialize_db(self):
        with self.conn.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    email VARCHAR(100),
                    telegram_id VARCHAR(50) NOT NULL,
                    current_password_hash TEXT NOT NULL,
                    next_password_hash TEXT,
                    password_change_time TIMESTAMP,
                    is_active BOOLEAN DEFAULT TRUE,
                    telegram_password_hash TEXT,
                    telegram_new_password_hash TEXT,
                    telegram_new_password TEXT
                )
            """)
            self.conn.commit()

            cursor.execute("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = 'users'
            """)
            columns = [row[0] for row in cursor.fetchall()]
            if 'password_hash' in columns and 'current_password_hash' not in columns:
                cursor.execute("""
                    ALTER TABLE users
                    RENAME COLUMN password_hash TO current_password_hash
                """)
                logger.info("Миграция: переименован столбец password_hash в current_password_hash")
                self.conn.commit()
            if 'next_password_hash' not in columns:
                cursor.execute("""
                    ALTER TABLE users
                    ADD COLUMN next_password_hash TEXT
                """)
                logger.info("Миграция: добавлен столбец next_password_hash")
                self.conn.commit()
            if 'password_change_time' not in columns:
                cursor.execute("""
                    ALTER TABLE users
                    ADD COLUMN password_change_time TIMESTAMP
                """)
                logger.info("Миграция: добавлен столбец password_change_time")
                self.conn.commit()
            if 'telegram_id' not in columns:
                cursor.execute("""
                    ALTER TABLE users
                    ADD COLUMN telegram_id VARCHAR(50) NOT NULL DEFAULT '0'
                """)
                logger.info("Миграция: добавлен столбец telegram_id")
                self.conn.commit()
            if 'email' not in columns:
                cursor.execute("""
                    ALTER TABLE users
                    ADD COLUMN email VARCHAR(100)
                """)
                logger.info("Миграция: добавлен столбец email")
                self.conn.commit()
            if 'telegram_password_hash' not in columns:
                cursor.execute("""
                    ALTER TABLE users
                    ADD COLUMN telegram_password_hash TEXT
                """)
                logger.info("Миграция: добавлен столбец telegram_password_hash")
                self.conn.commit()
            if 'telegram_new_password_hash' not in columns:
                cursor.execute("""
                    ALTER TABLE users
                    ADD COLUMN telegram_new_password_hash TEXT
                """)
                logger.info("Миграция: добавлен столбец telegram_new_password_hash")
                self.conn.commit()
            if 'telegram_new_password' not in columns:
                cursor.execute("""
                    ALTER TABLE users
                    ADD COLUMN telegram_new_password TEXT
                """)
                logger.info("Миграция: добавлен столбец telegram_new_password")
                self.conn.commit()

            cursor.execute("""
                UPDATE users
                SET current_password_hash = next_password_hash
                WHERE current_password_hash IS NULL AND next_password_hash IS NOT NULL
            """)
            if cursor.rowcount > 0:
                logger.info(f"Исправлено {cursor.rowcount} записей с NULL в current_password_hash")
                self.conn.commit()
            cursor.execute("""
                UPDATE users
                SET current_password_hash = %s
                WHERE current_password_hash IS NULL
            """, (generate_password_hash(self._generate_password()),))
            if cursor.rowcount > 0:
                logger.info(f"Заполнено {cursor.rowcount} записей с новым хешем пароля")
                self.conn.commit()

    def create_user(self, username, email, telegram_id, password):
        next_password = self._generate_password()
        try:
            with self.conn.cursor() as cursor:
                logger.info(f"Попытка создать пользователя: username={username}, telegram_id={telegram_id}, email={email}")
                cursor.execute(
                    """INSERT INTO users 
                    (username, email, telegram_id, current_password_hash, next_password_hash, password_change_time) 
                    VALUES (%s, %s, %s, %s, %s, %s)""",
                    (username, email, telegram_id,
                     generate_password_hash(password),
                     generate_password_hash(next_password),
                     datetime.now() + timedelta(minutes=5)))
                self.conn.commit()
                logger.info(f"Пользователь {username} успешно создан")
                return password, next_password
        except psycopg2.IntegrityError as e:
            logger.error(f"Ошибка создания пользователя (IntegrityError): {e}")
            self.conn.rollback()
            return None, None
        except Exception as e:
            logger.error(f"Неизвестная ошибка при создании пользователя: {e}")
            self.conn.rollback()
            return None, None

    def authenticate_user(self, username, password):
        try:
            with self.conn.cursor() as cursor:
                cursor.execute(
                    """SELECT id, username, current_password_hash, next_password_hash, telegram_new_password_hash 
                    FROM users WHERE username = %s AND is_active = TRUE""",
                    (username,)
                )
                user = cursor.fetchone()

                if not user:
                    return None

                # Проверяем текущий пароль или следующий пароль
                password_matched = False
                if check_password_hash(user[2], password):
                    password_matched = True
                elif user[3] and check_password_hash(user[3], password):
                    password_matched = True
                elif user[4] and check_password_hash(user[4], password):
                    password_matched = True

                if password_matched:
                    # Если использовался telegram_new_password_hash, очищаем его
                    if user[4] and check_password_hash(user[4], password):
                        cursor.execute(
                            """UPDATE users 
                            SET telegram_new_password = NULL, telegram_new_password_hash = NULL
                            WHERE username = %s AND is_active = TRUE""",
                            (username,)
                        )
                        self.conn.commit()
                        logger.info(f"Очищены telegram_new_password и telegram_new_password_hash для {username} после входа")
                    return {'id': user[0], 'username': user[1]}
                return None
        except Exception as e:
            logger.error(f"Ошибка аутентификации: {e}")
            return None

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
                logger.info(f"Telegram аутентификация не удалась для {username}: пароль не совпадает или не существует")
                return False
        except Exception as e:
            logger.error(f"Ошибка Telegram аутентификации: {e}")
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
                    logger.info(f"Telegram регистрация успешна для {username}")
                    return True
                else:
                    logger.error(f"Пользователь {username} не найден")
                    return False
        except Exception as e:
            logger.error(f"Ошибка Telegram регистрации: {e}")
            self.conn.rollback()
            return False

    def request_new_password(self, username, telegram_id):
        try:
            with self.conn.cursor() as cursor:
                new_password = self._generate_password()
                new_password_hash = generate_password_hash(new_password)
                cursor.execute(
                    """UPDATE users 
                    SET current_password_hash = next_password_hash,
                        next_password_hash = %s,
                        password_change_time = %s
                    WHERE username = %s AND telegram_id = %s""",
                    (new_password_hash, datetime.now() + timedelta(minutes=5), username, telegram_id)
                )
                if cursor.rowcount > 0:
                    self.conn.commit()
                    logger.info(f"Новый пароль сгенерирован для {username}")
                    return new_password
                else:
                    logger.error(f"Пользователь {username} не найден или telegram_id не совпадает")
                    return None
        except Exception as e:
            logger.error(f"Ошибка генерации нового пароля: {e}")
            self.conn.rollback()
            return None

    def telegram_generate_new_password(self, username):
        try:
            with self.conn.cursor() as cursor:
                new_password = self._generate_password()
                new_password_hash = generate_password_hash(new_password)
                cursor.execute(
                    """UPDATE users 
                    SET telegram_new_password_hash = %s,
                        telegram_new_password = %s
                    WHERE username = %s AND is_active = TRUE""",
                    (new_password_hash, new_password, username)
                )
                if cursor.rowcount > 0:
                    self.conn.commit()
                    logger.info(f"Новый Telegram пароль сгенерирован для {username}: {new_password}")
                    return new_password
                else:
                    logger.error(f"Пользователь {username} не найден при генерации нового пароля")
                    return None
        except Exception as e:
            logger.error(f"Ошибка генерации нового Telegram пароля: {e}")
            self.conn.rollback()
            return None

    def telegram_get_new_password(self, username):
        try:
            with self.conn.cursor() as cursor:
                cursor.execute(
                    """SELECT telegram_new_password 
                    FROM users WHERE username = %s AND is_active = TRUE""",
                    (username,)
                )
                result = cursor.fetchone()
                if result and result[0]:
                    new_password = result[0]
                    logger.info(f"Новый Telegram пароль получен для {username}")
                    return new_password
                logger.info(f"Новый Telegram пароль НЕ доступен для {username}: telegram_new_password is {result}")
                return None
        except Exception as e:
            logger.error(f"Ошибка получения нового Telegram пароля: {e}")
            return None

    def _generate_password(self):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=12))

db = DatabaseManager()

def send_telegram_message(user_id, message):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    if message == "test":
        data = {
            "chat_id": user_id,
            "text": "Бот успешно запущен и готов к работе! Отправьте /getid, чтобы узнать ваш chat_id."
        }
    else:
        data = {
            "chat_id": user_id,
            "text": message
        }
    try:
        response = requests.post(url, data=data, timeout=10)
        response.raise_for_status()
        logger.info(f"Сообщение отправлено в Telegram для {user_id}: {message}")
    except Exception as e:
        logger.error(
            f"Ошибка отправки сообщения в Telegram: {e} - Response: {e.response.text if hasattr(e, 'response') else 'No response'}")

@app.route('/')
def home():
    if 'user' in session:
        return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Добро пожаловать</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f9;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                }
                .container {
                    background-color: white;
                    padding: 40px;
                    border-radius: 10px;
                    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                    text-align: center;
                }
                h1 {
                    color: #333;
                }
                a {
                    display: inline-block;
                    margin-top: 20px;
                    padding: 10px 20px;
                    background-color: #ff4b5c;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    transition: background-color 0.3s;
                }
                a:hover {
                    background-color: #e04352;
                }
                .button {
                    display: inline-block;
                    margin-top: 10px;
                    padding: 10px 20px;
                    background-color: #4CAF50;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    transition: background-color 0.3s;
                }
                .button:hover {
                    background-color: #45a049;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Добро пожаловать, {{ username }}!</h1>
                <a href="/request_new_password" class="button">Запросить новый пароль</a>
                <a href="/logout">Выйти</a>
            </div>
        </body>
        </html>
        """, username=session['user']['username'])
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        logger.info(f"CSRF token in form (login): {request.form.get('_csrf_token')}")
        logger.info(f"CSRF token in session (login): {session.get('_csrf_token')}")
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            return "Логин и пароль обязательны", 400

        user = db.authenticate_user(username, password)
        if user:
            session['user'] = user
            return redirect(url_for('home'))
        return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Вход</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f9;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                }
                .container {
                    background-color: white;
                    padding: 40px;
                    border-radius: 10px;
                    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                    width: 100%;
                    max-width: 400px;
                    text-align: center;
                }
                h1 {
                    color: #333;
                    margin-bottom: 20px;
                }
                input[type="text"], input[type="password"] {
                    width: 100%;
                    padding: 10px;
                    margin: 10px 0;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    box-sizing: border-box;
                }
                button {
                    width: 100%;
                    padding: 10px;
                    background-color: #4CAF50;
                    color: white;
                    border: none;
                    border-radius: 5px;
                    cursor: pointer;
                    transition: background-color 0.3s;
                }
                button:hover {
                    background-color: #45a049;
                }
                a {
                    display: inline-block;
                    margin-top: 20px;
                    color: #007bff;
                    text-decoration: none;
                }
                a:hover {
                    text-decoration: underline;
                }
                .error {
                    color: #ff4b5c;
                    margin-bottom: 20px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Вход</h1>
                <p class="error">Неверные данные</p>
                <form method="POST">
                    <input type="hidden" name="_csrf_token" value="{{ csrf_token }}">
                    <input type="text" name="username" placeholder="Логин" required><br>
                    <input type="password" name="password" placeholder="Пароль" required><br>
                    <button type="submit">Войти</button>
                    <br><br>
                    <a href="/register">Зарегистрироваться</a>
                </form>
            </div>
        </body>
        </html>
        """, csrf_token=csrf._get_token())

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Вход</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #f4f4f9;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }
            .container {
                background-color: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                width: 100%;
                max-width: 400px;
                text-align: center;
            }
            h1 {
                color: #333;
                margin-bottom: 20px;
            }
            input[type="text"], input[type="password"] {
                width: 100%;
                padding: 10px;
                margin: 10px 0;
                border: 1px solid #ddd;
                border-radius: 5px;
                box-sizing: border-box;
            }
            button {
                width: 100%;
                padding: 10px;
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                transition: background-color 0.3s;
            }
            button:hover {
                background-color: #45a049;
            }
            a {
                display: inline-block;
                margin-top: 20px;
                color: #007bff;
                text-decoration: none;
            }
            a:hover {
                text-decoration: underline;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Вход</h1>
            <form method="POST">
                <input type="hidden" name="_csrf_token" value="{{ csrf_token }}">
                <input type="text" name="username" placeholder="Логин" required><br>
                <input type="password" name="password" placeholder="Пароль" required><br>
                <button type="submit">Войти</button>
                <br><br>
                <a href="/register">Зарегистрироваться</a>
            </form>
        </div>
    </body>
    </html>
    """, csrf_token=csrf._get_token())

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        logger.info(f"CSRF token in form (register): {request.form.get('_csrf_token')}")
        logger.info(f"CSRF token in session (register): {session.get('_csrf_token')}")
        username = request.form.get('username')
        email = request.form.get('email')
        telegram_id = request.form.get('telegram_id')
        password = request.form.get('password')

        logger.info(f"Регистрация: username={username}, email={email}, telegram_id={telegram_id}, password={password}")

        if not username or not password or not telegram_id:
            return render_template_string("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Регистрация</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        background-color: #f4f4f9;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                    }
                    .container {
                        background-color: white;
                        padding: 40px;
                        border-radius: 10px;
                        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                        width: 100%;
                        max-width: 400px;
                        text-align: center;
                    }
                    h1 {
                        color: #333;
                        margin-bottom: 20px;
                    }
                    input[type="text"], input[type="password"], input[type="email"] {
                        width: 100%;
                        padding: 10px;
                        margin: 10px 0;
                        border: 1px solid #ddd;
                        border-radius: 5px;
                        box-sizing: border-box;
                    }
                    button {
                        width: 100%;
                        padding: 10px;
                        background-color: #4CAF50;
                        color: white;
                        border: none;
                        border-radius: 5px;
                        cursor: pointer;
                        transition: background-color 0.3s;
                    }
                    button:hover {
                        background-color: #45a049;
                    }
                    a {
                        display: inline-block;
                        margin-top: 20px;
                        color: #007bff;
                        text-decoration: none;
                    }
                    a:hover {
                        text-decoration: underline;
                    }
                    .error {
                        color: #ff4b5c;
                        margin-bottom: 20px;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Регистрация</h1>
                    <p class="error">Все поля обязательны</p>
                    <form method="POST">
                        <input type="hidden" name="_csrf_token" value="{{ csrf_token }}">
                        <input type="text" name="username" placeholder="Имя пользователя" required value="{{ username }}"><br>
                        <input type="email" name="email" placeholder="Email (опционально)" value="{{ email }}"><br>
                        <input type="text" name="telegram_id" placeholder="Telegram ID" required value="{{ telegram_id }}"><br>
                        <input type="password" name="password" placeholder="Пароль" required><br>
                        <button type="submit">Зарегистрироваться</button>
                        <br><br>
                        <a href="/login">Уже есть аккаунт? Войти</a>
                    </form>
                </div>
            </body>
            </html>
            """, csrf_token=csrf._get_token(), username=username or "", email=email or "",
                                          telegram_id=telegram_id or "")

        if not telegram_id.isdigit():
            return render_template_string("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Регистрация</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        background-color: #f4f4f9;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                    }
                    .container {
                        background-color: white;
                        padding: 40px;
                        border-radius: 10px;
                        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                        width: 100%;
                        max-width: 400px;
                        text-align: center;
                    }
                    h1 {
                        color: #333;
                        margin-bottom: 20px;
                    }
                    input[type="text"], input[type="password"], input[type="email"] {
                        width: 100%;
                        padding: 10px;
                        margin: 10px 0;
                        border: 1px solid #ddd;
                        border-radius: 5px;
                        box-sizing: border-box;
                    }
                    button {
                        width: 100%;
                        padding: 10px;
                        background-color: #4CAF50;
                        color: white;
                        border: none;
                        border-radius: 5px;
                        cursor: pointer;
                        transition: background-color 0.3s;
                    }
                    button:hover {
                        background-color: #45a049;
                    }
                    a {
                        display: inline-block;
                        margin-top: 20px;
                        color: #007bff;
                        text-decoration: none;
                    }
                    a:hover {
                        text-decoration: underline;
                    }
                    .error {
                        color: #ff4b5c;
                        margin-bottom: 20px;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Регистрация</h1>
                    <p class="error">Telegram ID должен быть числовым (например, 123456789)</p>
                    <form method="POST">
                        <input type="hidden" name="_csrf_token" value="{{ csrf_token }}">
                        <input type="text" name="username" placeholder="Имя пользователя" required value="{{ username }}"><br>
                        <input type="email" name="email" placeholder="Email (опционально)" value="{{ email }}"><br>
                        <input type="text" name="telegram_id" placeholder="Telegram ID" required value="{{ telegram_id }}"><br>
                        <input type="password" name="password" placeholder="Пароль" required><br>
                        <button type="submit">Зарегистрироваться</button>
                        <br><br>
                        <a href="/login">Уже есть аккаунт? Войти</a>
                    </form>
                </div>
            </body>
            </html>
            """, csrf_token=csrf._get_token(), username=username, email=email,
                                          telegram_id=telegram_id)

        if email and not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return render_template_string("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Регистрация</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        background-color: #f4f4f9;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                    }
                    .container {
                        background-color: white;
                        padding: 40px;
                        border-radius: 10px;
                        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                        width: 100%;
                        max-width: 400px;
                        text-align: center;
                    }
                    h1 {
                        color: #333;
                        margin-bottom: 20px;
                    }
                    input[type="text"], input[type="password"], input[type="email"] {
                        width: 100%;
                        padding: 10px;
                        margin: 10px 0;
                        border: 1px solid #ddd;
                        border-radius: 5px;
                        box-sizing: border-box;
                    }
                    button {
                        width: 100%;
                        padding: 10px;
                        background-color: #4CAF50;
                        color: white;
                        border: none;
                        border-radius: 5px;
                        cursor: pointer;
                        transition: background-color 0.3s;
                    }
                    button:hover {
                        background-color: #45a049;
                    }
                    a {
                        display: inline-block;
                        margin-top: 20px;
                        color: #007bff;
                        text-decoration: none;
                    }
                    a:hover {
                        text-decoration: underline;
                    }
                    .error {
                        color: #ff4b5c;
                        margin-bottom: 20px;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Регистрация</h1>
                    <p class="error">Неверный формат email</p>
                    <form method="POST">
                        <input type="hidden" name="_csrf_token" value="{{ csrf_token }}">
                        <input type="text" name="username" placeholder="Имя пользователя" required value="{{ username }}"><br>
                        <input type="email" name="email" placeholder="Email (опционально)" value="{{ email }}"><br>
                        <input type="text" name="telegram_id" placeholder="Telegram ID" required value="{{ telegram_id }}"><br>
                        <input type="password" name="password" placeholder="Пароль" required><br>
                        <button type="submit">Зарегистрироваться</button>
                        <br><br>
                        <a href="/login">Уже есть аккаунт? Войти</a>
                    </form>
                </div>
            </body>
            </html>
            """, csrf_token=csrf._get_token(), username=username, email=email,
                                          telegram_id=telegram_id)

        current_password, next_password = db.create_user(username, email, telegram_id, password)
        if current_password:
            logger.info(f"Регистрация успешна для пользователя {username}")
            return render_template_string("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Успешная регистрация</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        background-color: #f4f4f9;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                    }
                    .container {
                        background-color: white;
                        padding: 40px;
                        border-radius: 10px;
                        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                        width: 100%;
                        max-width: 400px;
                        text-align: center;
                    }
                    h1 {
                        color: #333;
                        margin-bottom: 20px;
                    }
                    p {
                        color: #555;
                        margin-bottom: 20px;
                    }
                    a {
                        display: inline-block;
                        padding: 10px 20px;
                        background-color: #4CAF50;
                        color: white;
                        text-decoration: none;
                        border-radius: 5px;
                        transition: background-color 0.3s;
                    }
                    a:hover {
                        background-color: #45a049;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Регистрация успешна!</h1>
                    <p>Используйте ваш логин и пароль для входа.</p>
                    <a href="/login">Войти</a>
                </div>
            </body>
            </html>
            """)
        logger.error(f"Регистрация для пользователя {username} не удалась")
        return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Регистрация</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f9;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                }
                .container {
                    background-color: white;
                    padding: 40px;
                    border-radius: 10px;
                    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                    width: 100%;
                    max-width: 400px;
                    text-align: center;
                }
                h1 {
                    color: #333;
                    margin-bottom: 20px;
                }
                input[type="text"], input[type="password"], input[type="email"] {
                    width: 100%;
                    padding: 10px;
                    margin: 10px 0;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    box-sizing: border-box;
                }
                button {
                    width: 100%;
                    padding: 10px;
                    background-color: #4CAF50;
                    color: white;
                    border: none;
                    border-radius: 5px;
                    cursor: pointer;
                    transition: background-color 0.3s;
                }
                button:hover {
                    background-color: #45a049;
                }
                a {
                    display: inline-block;
                    margin-top: 20px;
                    color: #007bff;
                    text-decoration: none;
                }
                a:hover {
                    text-decoration: underline;
                }
                .error {
                    color: #ff4b5c;
                    margin-bottom: 20px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Регистрация</h1>
                <p class="error">Ошибка регистрации. Проверьте данные или попробуйте позже</p>
                <form method="POST">
                    <input type="hidden" name="_csrf_token" value="{{ csrf_token }}">
                    <input type="text" name="username" placeholder="Имя пользователя" required value="{{ username }}"><br>
                    <input type="email" name="email" placeholder="Email (опционально)" value="{{ email }}"><br>
                    <input type="text" name="telegram_id" placeholder="Telegram ID" required value="{{ telegram_id }}"><br>
                    <input type="password" name="password" placeholder="Пароль" required><br>
                    <button type="submit">Зарегистрироваться</button>
                    <br><br>
                    <a href="/login">Уже есть аккаунт? Войти</a>
                </form>
            </div>
        </body>
        </html>
        """, csrf_token=csrf._get_token(), username=username, email=email, telegram_id=telegram_id)

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Регистрация</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #f4f4f9;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }
            .container {
                background-color: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                width: 100%;
                max-width: 400px;
                text-align: center;
            }
            h1 {
                color: #333;
                margin-bottom: 20px;
            }
            input[type="text"], input[type="password"], input[type="email"] {
                width: 100%;
                padding: 10px;
                margin: 10px 0;
                border: 1px solid #ddd;
                border-radius: 5px;
                box-sizing: border-box;
            }
            button {
                width: 100%;
                padding: 10px;
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                transition: background-color 0.3s;
            }
            button:hover {
                background-color: #45a049;
            }
            a {
                display: inline-block;
                margin-top: 20px;
                color: #007bff;
                text-decoration: none;
            }
            a:hover {
                text-decoration: underline;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Регистрация</h1>
            <form method="POST">
                <input type="hidden" name="_csrf_token" value="{{ csrf_token }}">
                <input type="text" name="username" placeholder="Имя пользователя" required><br>
                <input type="email" name="email" placeholder="Email (опционально)"><br>
                <input type="text" name="telegram_id" placeholder="Telegram ID" required><br>
                <input type="password" name="password" placeholder="Пароль" required><br>
                <button type="submit">Зарегистрироваться</button>
                <br><br>
                <a href="/login">Уже есть аккаунт? Войти</a>
            </form>
        </div>
    </body>
    </html>
    """, csrf_token=csrf._get_token())

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/request_new_password')
def request_new_password():
    if 'user' not in session:
        return redirect(url_for('login'))

    username = session['user']['username']
    telegram_id = None
    try:
        with db.conn.cursor() as cursor:
            cursor.execute("SELECT telegram_id FROM users WHERE username = %s", (username,))
            result = cursor.fetchone()
            if result:
                telegram_id = result[0]
    except Exception as e:
        logger.error(f"Ошибка получения telegram_id: {e}")
        return "Ошибка сервера", 500

    if not telegram_id or not telegram_id.isdigit():
        return "Telegram ID не найден или некорректен", 400

    new_password = db.request_new_password(username, telegram_id)
    if new_password:
        send_telegram_message(telegram_id, "Новый пароль сгенерирован! Используй /login <username> <password> в боте, чтобы получить его.")
        return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Новый пароль</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f9;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                }
                .container {
                    background-color: white;
                    padding: 40px;
                    border-radius: 10px;
                    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                    width: 100%;
                    max-width: 400px;
                    text-align: center;
                }
                h1 {
                    color: #333;
                    margin-bottom: 20px;
                }
                p {
                    color: #555;
                    margin-bottom: 20px;
                }
                a {
                    display: inline-block;
                    padding: 10px 20px;
                    background-color: #4CAF50;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    transition: background-color 0.3s;
                }
                a:hover {
                    background-color: #45a049;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Новый пароль запрошен!</h1>
                <p>Войдите в Telegram-бот и используй /login для получения нового пароля.</p>
                <a href="/">Вернуться на главную</a>
            </div>
        </body>
        </html>
        """)
    return "Не удалось сгенерировать новый пароль", 400

if __name__ == "__main__":
    send_telegram_message(TELEGRAM_CHAT_ID, "test")
    app.run(host='0.0.0.0', port=8443, ssl_context=('server.crt', 'server.key'))