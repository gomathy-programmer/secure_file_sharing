"""
Secure File Sharing System - Web Edition
=========================================
SRM Institute of Science and Technology, Ramapuram
21CSC203P - Advanced Programming Practices

This Flask app implements the four modules from the project report:

    1. User and Interface Module        -> /register, /login, dashboard UI
                                            (signup/login + password hashing)
    2. Cryptography and Security Module -> AES (via Fernet) encrypts every
                                            file before it is written to disk
    3. Network Communication Module     -> Flask's HTTP server, itself built
                                            on Python's socket module, carries
                                            every request/response
    4. Integrity and Audit Logging      -> SHA-256 checksum verified on every
       Module                              download + ActivityLog audit trail

Run with:  python app.py
Then open: http://127.0.0.1:5000
"""

import os
import base64
import hashlib
from io import BytesIO
from functools import wraps
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_file, abort
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from cryptography.fernet import Fernet, InvalidToken

# ---------------------------------------------------------------------------
# App & folder setup
# ---------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, 'encrypted_storage')
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'change-this-secret-key-for-a-real-deployment'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 25 * 1024 * 1024  # 25 MB per file, plenty for a demo

db = SQLAlchemy(app)

# ---------------------------------------------------------------------------
# Database models -> these map directly onto the ER diagram in the report
# (User, File, Transfer_Log). "Session" in the ER diagram is realised here
# by Flask's built-in secure cookie session, so it doesn't need its own table.
# ---------------------------------------------------------------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class FileRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(255), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    aes_key = db.Column(db.Text, nullable=False)          # per-file AES (Fernet) key, base64
    checksum = db.Column(db.String(64), nullable=False)   # SHA-256 hex digest of original file
    file_size = db.Column(db.Integer)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    owner = db.relationship('User', foreign_keys=[owner_id])
    recipient = db.relationship('User', foreign_keys=[recipient_id])


class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(50))
    detail = db.Column(db.String(255))
    status = db.Column(db.String(20), default='SUCCESS')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User')
# Create tables automatically when the app starts on Render
with app.app_context():
    db.create_all()



# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def log_activity(user_id, action, detail, status='SUCCESS'):
    db.session.add(ActivityLog(user_id=user_id, action=action, detail=detail, status=status))
    db.session.commit()


def current_user():
    uid = session.get('user_id')
    return User.query.get(uid) if uid else None


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    return redirect(url_for('dashboard') if current_user() else url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if not username or not password:
            flash('Username and password are required.', 'danger')
        elif len(password) < 4:
            flash('Password must be at least 4 characters.', 'danger')
        elif User.query.filter_by(username=username).first():
            flash('That username is already taken.', 'danger')
        else:
            user = User(username=username, password_hash=generate_password_hash(password))
            db.session.add(user)
            db.session.commit()
            log_activity(user.id, 'REGISTER', f'New account created: {username}')
            flash('Account created successfully. Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            log_activity(user.id, 'LOGIN', f'{username} logged in')
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('dashboard'))
        log_activity(None, 'LOGIN', f'Failed login attempt for "{username}"', status='FAILED')
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')


@app.route('/logout')
def logout():
    user = current_user()
    if user:
        log_activity(user.id, 'LOGOUT', f'{user.username} logged out')
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user()
    my_files = FileRecord.query.filter_by(owner_id=user.id).order_by(FileRecord.uploaded_at.desc()).all()
    shared_with_me = FileRecord.query.filter_by(recipient_id=user.id).order_by(FileRecord.uploaded_at.desc()).all()
    other_users = User.query.filter(User.id != user.id).order_by(User.username).all()
    return render_template(
        'dashboard.html', user=user, my_files=my_files,
        shared_with_me=shared_with_me, other_users=other_users,
    )


@app.route('/upload', methods=['POST'])
@login_required
def upload():
    user = current_user()
    file = request.files.get('file')
    recipient_username = request.form.get('recipient', '').strip()

    if not file or file.filename == '':
        flash('Please choose a file to upload.', 'danger')
        return redirect(url_for('dashboard'))

    recipient = None
    if recipient_username:
        recipient = User.query.filter_by(username=recipient_username).first()
        if not recipient:
            flash(f'No user named "{recipient_username}" was found.', 'danger')
            return redirect(url_for('dashboard'))
        if recipient.id == user.id:
            flash('You cannot share a file with yourself.', 'danger')
            return redirect(url_for('dashboard'))

    original_name = secure_filename(file.filename)
    file_bytes = file.read()

    # --- Integrity and Audit Logging Module: checksum of the ORIGINAL bytes ---
    checksum = hashlib.sha256(file_bytes).hexdigest()

    # --- Cryptography and Security Module: one-time AES (Fernet) key per file ---
    aes_key = Fernet.generate_key()
    encrypted_bytes = Fernet(aes_key).encrypt(file_bytes)

    stored_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}_{original_name}.enc"
    with open(os.path.join(UPLOAD_DIR, stored_name), 'wb') as f:
        f.write(encrypted_bytes)

    record = FileRecord(
        filename=original_name,
        stored_name=stored_name,
        owner_id=user.id,
        recipient_id=recipient.id if recipient else None,
        aes_key=base64.b64encode(aes_key).decode(),
        checksum=checksum,
        file_size=len(file_bytes),
    )
    db.session.add(record)
    db.session.commit()

    detail = f'"{original_name}" encrypted with AES'
    if recipient:
        detail += f', shared with {recipient.username}'
    log_activity(user.id, 'UPLOAD', detail)

    flash('File encrypted and uploaded successfully.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/download/<int:file_id>')
@login_required
def download(file_id):
    user = current_user()
    record = FileRecord.query.get_or_404(file_id)

    # --- User and Interface Module: only owner or named recipient may fetch it ---
    if record.owner_id != user.id and record.recipient_id != user.id:
        log_activity(user.id, 'DOWNLOAD', f'Unauthorized attempt on "{record.filename}"', status='FAILED')
        abort(403)

    path = os.path.join(UPLOAD_DIR, record.stored_name)
    with open(path, 'rb') as f:
        encrypted_bytes = f.read()

    try:
        aes_key = base64.b64decode(record.aes_key)
        file_bytes = Fernet(aes_key).decrypt(encrypted_bytes)
    except InvalidToken:
        log_activity(user.id, 'DOWNLOAD', f'Decryption FAILED for "{record.filename}"', status='FAILED')
        abort(500, description='Decryption failed - the encrypted file may be corrupted.')

    # --- Integrity check: recompute the checksum and compare to the one taken at upload ---
    if hashlib.sha256(file_bytes).hexdigest() != record.checksum:
        log_activity(user.id, 'DOWNLOAD', f'Checksum MISMATCH on "{record.filename}"', status='FAILED')
        abort(500, description='Integrity check failed: the file may have been tampered with.')

    log_activity(user.id, 'DOWNLOAD', f'"{record.filename}" decrypted and integrity verified')

    return send_file(
        BytesIO(file_bytes),
        as_attachment=True,
        download_name=record.filename,
        mimetype='application/octet-stream',
    )


@app.route('/logs')
@login_required
def logs():
    user = current_user()
    entries = (ActivityLog.query.filter_by(user_id=user.id)
               .order_by(ActivityLog.timestamp.desc()).limit(200).all())
    return render_template('logs.html', user=user, entries=entries)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
