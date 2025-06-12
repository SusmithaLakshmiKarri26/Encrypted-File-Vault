# app.py
from flask import Flask, request, render_template, redirect, url_for, send_file, session, flash
from encryption_utils import encrypt_file, decrypt_file
from cloudinary_utils import upload_to_cloudinary
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from datetime import datetime
import sqlite3
import os
import random
import time
from itsdangerous import URLSafeTimedSerializer
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

# Mail configuration
app.config['MAIL_SERVER'] = os.getenv("MAIL_SERVER")
app.config['MAIL_PORT'] = int(os.getenv("MAIL_PORT"))
app.config['MAIL_USE_TLS'] = os.getenv("MAIL_USE_TLS", "true").lower() == "true"
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_DEFAULT_SENDER")

mail = Mail(app)
serializer = URLSafeTimedSerializer(os.getenv("MAIL_SECRET_KEY"))

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
DATABASE = 'users.db'

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'py', 'java', 'docx'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fullname TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    ''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            otp = str(random.randint(100000, 999999))
            session['otp'] = otp
            session['otp_timestamp'] = time.time()
            session['temp_user'] = username
            send_otp(user['email'], otp)
            return redirect(url_for('verify_otp'))
        else:
            flash('Invalid credentials', 'error')
    return render_template('login.html')

def send_otp(to_email, otp):
    msg = Message(subject="Your OTP Code", recipients=[to_email])
    msg.body = f"Your OTP code is: {otp}"
    mail.send(msg)

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        if time.time() - session.get('otp_timestamp', 0) > 300:
            flash('OTP expired. Please login again.', 'error')
            return redirect(url_for('login'))
        if entered_otp == session.get('otp'):
            session['username'] = session.pop('temp_user')
            session.pop('otp', None)
            session.pop('otp_timestamp', None)
            flash('OTP verified. Logged in successfully.', 'success')
            return render_template('welcome.html', username=session['username'])
        else:
            flash('Invalid OTP', 'error')
    return render_template('verify_otp.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        fullname = request.form.get('fullname')
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')

        if not (fullname and email and username and password):
            flash("Please fill all the fields", "error")
            return render_template('register.html')

        hashed_password = generate_password_hash(password)
        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (fullname, email, username, password) VALUES (?, ?, ?, ?)",
                           (fullname, email, username, hashed_password))
            conn.commit()
            session['username'] = username
            return redirect(url_for('index'))
        except sqlite3.IntegrityError as e:
            if "username" in str(e):
                flash("Username already exists", "error")
            elif "email" in str(e):
                flash("Email already registered", "error")
            else:
                flash("Registration error", "error")
            return render_template('register.html')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/encrypt', methods=['GET', 'POST'])
@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if not session.get('username'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files.get('file')
        password = request.form.get('password')

        if not file or file.filename == '':
            flash('No file selected.', 'error')
            return redirect(request.url)

        if not allowed_file(file.filename):
            flash('Invalid file type. Only specific formats allowed.', 'error')
            return redirect(request.url)

        if not password:
            flash('Password is required.', 'error')
            return redirect(request.url)

        filename = secure_filename(file.filename)
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)

        encrypted_path = encrypt_file(file_path, password)
        cloud_url = upload_to_cloudinary(encrypted_path)

        os.remove(file_path)
        os.remove(encrypted_path)

        return render_template('success.html', message='File encrypted & uploaded!', url=cloud_url)

    return render_template('encrypt.html')

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if not session.get('username'):
        return redirect(url_for('login'))
    if request.method == 'POST':
        file_url = request.form['file_url']
        password = request.form['password']
        sender = request.form['sender']
        username = session.get('username')
        path = decrypt_file(file_url, password)
        if path:
            with open("logs.txt", "a") as log:
                log.write(f"[{datetime.now()}] {username} decrypted {sender}'s file\n")
            return send_file(path, as_attachment=True)
        else:
            flash("Decryption failed. Check password or file URL.")
    return render_template('decrypt.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        conn.close()
        if user:
            token = serializer.dumps(email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message("Reset Your Password", recipients=[email])
            msg.body = f"Click here to reset your password: {reset_url}"
            mail.send(msg)
            flash("Password reset link sent.")
            return redirect(url_for('login'))
        else:
            flash("Email not found.")
    return render_template('forgotpassword.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except Exception:
        flash("Invalid or expired reset link.", "error")
        return redirect(url_for('login'))
    if request.method == 'POST':
        new_password = request.form['new_password']
        if not new_password:
            flash("Enter a new password.", "error")
            return render_template('reset_password.html')
        hashed = generate_password_hash(new_password)
        conn = get_db()
        conn.execute("UPDATE users SET password=? WHERE email=?", (hashed, email))
        conn.commit()
        conn.close()
        flash("Password reset successful.", "success")
        return redirect(url_for('login'))
    return render_template('reset_password.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("Logged out successfully.", "success")
    return redirect(url_for('login'))

@app.route('/about')
def about():
    return render_template('about.html')

@app.after_request
def add_no_cache_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

if __name__ == '__main__':
    app.run(debug=True)
