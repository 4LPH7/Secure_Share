# app.py
import os
import uuid
import io
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_wtf import FlaskForm, CSRFProtect
from flask_wtf.csrf import generate_csrf
from wtforms import StringField, PasswordField, validators
from cryptography.fernet import Fernet
import bcrypt

# Initialize Flask app
app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', os.urandom(24)),
    SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', 'sqlite:///securefileshare.db'),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    UPLOAD_FOLDER='uploads',
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB
    MAIL_SERVER=os.environ.get('MAIL_SERVER', 'smtp.gmail.com'),
    MAIL_PORT=os.environ.get('MAIL_PORT', 587),
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.environ.get('MAIL_USERNAME'),
    MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD'),
    MAIL_DEFAULT_SENDER=os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@gmail.com'),
    PASSWORD_RESET_TIMEOUT=3600  # 1 hour
)

# Initialize extensions
db = SQLAlchemy(app)
mail = Mail(app)
csrf = CSRFProtect(app)

# Encryption setup
fernet_key = Fernet.generate_key()
cipher_suite = Fernet(fernet_key)


# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    reset_token = db.Column(db.String(100))
    reset_expires = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    email_verified = db.Column(db.Boolean, default=False)


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(120), nullable=False)
    encrypted_data = db.Column(db.LargeBinary, nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)


class Share(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    token = db.Column(db.String(36), unique=True, nullable=False)
    expiration = db.Column(db.DateTime)
    max_downloads = db.Column(db.Integer)
    download_count = db.Column(db.Integer, default=0)
    password_hash = db.Column(db.String(120))


# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', [
        validators.Length(min=4, max=25),
        validators.DataRequired()
    ])
    email = StringField('Email', [
        validators.Email(),
        validators.DataRequired()
    ])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')


class LoginForm(FlaskForm):
    username = StringField('Username', [validators.DataRequired()])
    password = PasswordField('Password', [validators.DataRequired()])
    remember = validators.Optional()


class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', [
        validators.Email(),
        validators.DataRequired()
    ])


class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')


# Helper functions
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def check_password(password_hash, password):
    return bcrypt.checkpw(password.encode(), password_hash)


def generate_reset_token():
    return str(uuid.uuid4())


# Context processors
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)


@app.context_processor
def inject_now():
    return dict(now=datetime.utcnow())


# Routes
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password(user.password_hash, form.password.data):
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'error')
    return render_template('index.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            if User.query.filter_by(username=form.username.data).first():
                flash('Username already exists', 'error')
                return redirect(url_for('register'))

            if User.query.filter_by(email=form.email.data).first():
                flash('Email already registered', 'error')
                return redirect(url_for('register'))

            new_user = User(
                username=form.username.data,
                email=form.email.data,
                password_hash=hash_password(form.password.data)
            )
            db.session.add(new_user)
            db.session.commit()

            # Send welcome email
            msg = Message('Welcome to SecureShare',
                          recipients=[form.email.data])
            msg.body = f'''Welcome {form.username.data}!

Thank you for registering with SecureShare. Your account has been successfully created.

Start sharing files securely today!'''
            mail.send(msg)

            flash('Registration successful! Please login', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            db.session.rollback()
            logger.error(f"Registration error: {str(e)}")
            flash('An error occurred during registration. Please try again.', 'error')
            return redirect(url_for('register'))

    return render_template('register.html', form=form)


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = generate_reset_token()
            user.reset_token = token
            user.reset_expires = datetime.utcnow() + timedelta(seconds=app.config['PASSWORD_RESET_TIMEOUT'])
            db.session.commit()

            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('Password Reset Request',
                          recipients=[user.email])
            msg.body = f'''To reset your password, visit the following link:
{reset_url}

This link will expire in 1 hour.'''
            mail.send(msg)

        flash('If an account exists with that email, a reset link has been sent', 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html', form=form)


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    if not user or user.reset_expires < datetime.utcnow():
        flash('Invalid or expired reset token', 'error')
        return redirect(url_for('login'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password_hash = hash_password(form.password.data)
        user.reset_token = None
        user.reset_expires = None
        db.session.commit()
        flash('Password updated successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', form=form, token=token)


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    files = File.query.filter_by(user_id=user.id).order_by(File.upload_date.desc()).all()
    return render_template('dashboard.html', user=user, files=files)


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('dashboard'))

    file = request.files['file']
    if file.filename == '':
        flash('Invalid file', 'error')
        return redirect(url_for('dashboard'))

    try:
        encrypted_data = cipher_suite.encrypt(file.read())
        new_file = File(
            user_id=session['user_id'],
            filename=file.filename,
            encrypted_data=encrypted_data
        )
        db.session.add(new_file)
        db.session.commit()
        flash('File uploaded successfully!', 'success')
    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        flash('Error uploading file', 'error')

    return redirect(url_for('dashboard'))


@app.route('/share', methods=['POST'])
def create_share():
    try:
        if 'user_id' not in session:
            return redirect(url_for('login'))

        file_id = request.form.get('file_id')
        expiration_days = request.form.get('expiration')
        max_downloads = request.form.get('max_downloads')
        password = request.form.get('password')

        if not file_id or not file_id.isdigit():
            flash('Invalid file', 'error')
            return redirect(url_for('dashboard'))

        expiration = (datetime.utcnow() + timedelta(days=int(expiration_days))) if expiration_days else None
        password_hash = hash_password(password) if password else None

        new_share = Share(
            file_id=int(file_id),
            token=str(uuid.uuid4()),
            expiration=expiration,
            max_downloads=int(max_downloads) if max_downloads else None,
            password_hash=password_hash
        )
        db.session.add(new_share)
        db.session.commit()

        share_link = url_for('share_file', token=new_share.token, _external=True)
        return render_template('dashboard.html', share_link=share_link)
    except Exception as e:
        logger.error(f"Share creation error: {str(e)}")
        flash('Error creating share link', 'error')
        return redirect(url_for('dashboard'))


@app.route('/share/<token>', methods=['GET', 'POST'])
def share_file(token):
    try:
        share = Share.query.filter_by(token=token).first_or_404()

        if share.expiration and share.expiration < datetime.utcnow():
            flash('This link has expired', 'error')
            return redirect(url_for('home'))

        if share.max_downloads and share.download_count >= share.max_downloads:
            flash('Download limit exceeded', 'error')
            return redirect(url_for('home'))

        if share.password_hash:
            if request.method == 'POST':
                if check_password(share.password_hash, request.form.get('password')):
                    return process_download(share)
                flash('Invalid password', 'error')
            return render_template('share_auth.html', token=token)

        return process_download(share)
    except Exception as e:
        logger.error(f"Share error: {str(e)}")
        flash('Error processing request', 'error')
        return redirect(url_for('home'))


def process_download(share):
    try:
        file = File.query.get_or_404(share.file_id)
        decrypted_data = cipher_suite.decrypt(file.encrypted_data)
        share.download_count += 1
        db.session.commit()
        return send_file(
            io.BytesIO(decrypted_data),
            download_name=file.filename,
            as_attachment=True,
            mimetype='application/octet-stream'
        )
    except Exception as e:
        logger.error(f"Download error: {str(e)}")
        flash('Error downloading file', 'error')
        return redirect(url_for('home'))


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('home'))


@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(host='0.0.0.0', port=5000)
