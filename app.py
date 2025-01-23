import os
import uuid
import io
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, validators
from cryptography.fernet import Fernet
import bcrypt

app = Flask(__name__)

# Auto-generated secrets
app.secret_key = os.urandom(24)
fernet = Fernet.generate_key()

# Configure paths
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///securefileshare.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

# Initialize extensions
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
cipher_suite = Fernet(fernet)


# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


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
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')


class LoginForm(FlaskForm):
    username = StringField('Username', [validators.DataRequired()])
    password = PasswordField('Password', [validators.DataRequired()])


# Helper functions
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def check_password(password_hash, password):
    return bcrypt.checkpw(password.encode(), password_hash)


@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=csrf.generate_csrf)


# Routes
@app.route('/', methods=['GET', 'POST'])
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    login_form = LoginForm()
    reg_form = RegistrationForm()

    if request.method == 'POST':
        if 'login' in request.form and login_form.validate():
            return handle_login(login_form)
        elif 'register' in request.form and reg_form.validate():
            return handle_registration(reg_form)

    return render_template('index.html', login_form=login_form, reg_form=reg_form)


def handle_login(form):
    user = User.query.filter_by(username=form.username.data).first()
    if user and check_password(user.password_hash, form.password.data):
        session['user_id'] = user.id
        flash('Login successful!', 'success')
        return redirect(url_for('dashboard'))
    flash('Invalid credentials', 'error')
    return redirect(url_for('index'))


def handle_registration(form):
    if User.query.filter_by(username=form.username.data).first():
        flash('Username already exists', 'error')
        return redirect(url_for('index'))

    new_user = User(
        username=form.username.data,
        password_hash=hash_password(form.password.data)
    )
    db.session.add(new_user)
    db.session.commit()
    flash('Registration successful! Please login', 'success')
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    user = User.query.get(session['user_id'])
    files = File.query.filter_by(user_id=user.id).order_by(File.upload_date.desc()).all()
    return render_template('dashboard.html', user=user, files=files)


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('index'))

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
        flash('Error uploading file', 'error')

    return redirect(url_for('dashboard'))


@app.route('/share', methods=['POST'])
def create_share():
    try:
        file_id = request.form.get('file_id')
        expiration = request.form.get('expiration')
        max_downloads = request.form.get('max_downloads')
        password = request.form.get('password')

        new_share = Share(
            file_id=file_id,
            token=str(uuid.uuid4()),
            expiration=datetime.utcnow() + timedelta(days=int(expiration)) if expiration else None,
            max_downloads=int(max_downloads) if max_downloads else None,
            password_hash=hash_password(password) if password else None
        )
        db.session.add(new_share)
        db.session.commit()

        share_link = url_for('share_file', token=new_share.token, _external=True)
        return render_template('dashboard.html', share_link=share_link)
    except Exception as e:
        flash('Error creating share link', 'error')
        return redirect(url_for('dashboard'))


@app.route('/share/<token>', methods=['GET', 'POST'])
def share_file(token):
    share = Share.query.filter_by(token=token).first()
    if not share:
        flash('Invalid share link', 'error')
        return redirect(url_for('index'))

    if share.expiration and share.expiration < datetime.utcnow():
        flash('Link expired', 'error')
        return redirect(url_for('index'))

    if share.max_downloads and share.download_count >= share.max_downloads:
        flash('Download limit reached', 'error')
        return redirect(url_for('index'))

    if share.password_hash:
        if request.method == 'POST':
            if check_password(share.password_hash, request.form.get('password')):
                return process_download(share)
            flash('Invalid password', 'error')
        return render_template('share_auth.html', token=token)

    return process_download(share)


def process_download(share):
    try:
        file = File.query.get(share.file_id)
        decrypted_data = cipher_suite.decrypt(file.encrypted_data)
        share.download_count += 1
        db.session.commit()
        return send_file(
            io.BytesIO(decrypted_data),
            download_name=file.filename,
            as_attachment=True
        )
    except Exception as e:
        flash('Error downloading file', 'error')
        return redirect(url_for('index'))


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)
