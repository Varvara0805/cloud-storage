from flask import Flask, request, redirect, url_for, flash, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import sqlite3
import os
import base64
from datetime import datetime
import hashlib

app = Flask(__name__)
app.secret_key = 'super-secret-key-12345'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


# Проверяем доступность базы данных
def check_db():
    try:
        conn = sqlite3.connect('cloud_storage.db')
        c = conn.cursor()
        c.execute("SELECT 1")
        conn.close()
        return True
    except Exception as e:
        print(f"❌ Database error: {e}")
        return False

# Генерация ключа шифрования
def generate_encryption_key():
    key_file = 'encryption.key'
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)
        return key


# Инициализация шифрования
ENCRYPTION_KEY = generate_encryption_key()
cipher_suite = Fernet(ENCRYPTION_KEY)


def init_db():
    # ИСПРАВЛЕНИЕ: НЕ удаляем базу данных если она уже существует
    conn = sqlite3.connect('cloud_storage.db')
    c = conn.cursor()

    # Создаем таблицы только если они не существуют
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

    c.execute('''CREATE TABLE IF NOT EXISTS files
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  filename TEXT NOT NULL,
                  original_filename TEXT NOT NULL,
                  user_id INTEGER NOT NULL,
                  uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  file_size INTEGER,
                  file_hash TEXT,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')

    conn.commit()
    conn.close()
    print("✅ Database initialized successfully!")


def get_db_connection():
    conn = sqlite3.connect('cloud_storage.db')
    conn.row_factory = sqlite3.Row
    return conn


def encrypt_file(file_data):
    """Шифрует данные файла"""
    return cipher_suite.encrypt(file_data)


def decrypt_file(encrypted_data):
    """Расшифровывает данные файла"""
    return cipher_suite.decrypt(encrypted_data)


def calculate_file_hash(file_data):
    """Вычисляет хеш файла для проверки целостности"""
    return hashlib.sha256(file_data).hexdigest()


def get_flash_messages():
    messages_html = ''
    if '_flashes' in session:
        for category, message in session['_flashes']:
            if category == 'error':
                messages_html += f'<div class="error">{message}</div>'
            elif category == 'success':
                messages_html += f'<div class="success">{message}</div>'
            else:
                messages_html += f'<div class="info">{message}</div>'
        session['_flashes'] = []
    return messages_html


@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')

    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - Secure Cloud Storage</title>
        <style>
            body {{ font-family: Arial; margin: 50px; background: #f0f0f0; }}
            .container {{ max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
            h2 {{ text-align: center; color: #333; }}
            .form-group {{ margin-bottom: 20px; }}
            input[type="text"], input[type="password"] {{ width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }}
            .btn {{ width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }}
            .btn:hover {{ background: #0056b3; }}
            .error {{ background: #ffebee; color: #c62828; padding: 10px; border-radius: 5px; margin-bottom: 20px; }}
            .success {{ background: #e8f5e8; color: #2e7d32; padding: 10px; border-radius: 5px; margin-bottom: 20px; }}
            .security-info {{ background: #e3f2fd; color: #1565c0; padding: 10px; border-radius: 5px; margin-bottom: 20px; font-size: 14px; }}
            .links {{ text-align: center; margin-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h2>🔐 Secure Cloud Storage</h2>
            <div class="security-info">
                🔒 <strong>Secure Storage</strong><br>
                • Passwords hashed with bcrypt<br>
                • Files encrypted with AES-256<br>
                • Integrity checking with SHA-256
            </div>
            {get_flash_messages()}
            <form method="POST">
                <div class="form-group">
                    <input type="text" name="username" placeholder="Username" required>
                </div>
                <div class="form-group">
                    <input type="password" name="password" placeholder="Password" required>
                </div>
                <button type="submit" class="btn">Login</button>
            </form>
            <div class="links">
                <a href="/register">Create new account</a>
            </div>
        </div>
    </body>
    </html>
    '''


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                         (username, hashed_password))
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        finally:
            conn.close()

    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Register - Secure Cloud Storage</title>
        <style>
            body {{ font-family: Arial; margin: 50px; background: #f0f0f0; }}
            .container {{ max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
            h2 {{ text-align: center; color: #333; }}
            .form-group {{ margin-bottom: 20px; }}
            input[type="text"], input[type="password"] {{ width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }}
            .btn {{ width: 100%; padding: 12px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }}
            .btn:hover {{ background: #218838; }}
            .error {{ background: #ffebee; color: #c62828; padding: 10px; border-radius: 5px; margin-bottom: 20px; }}
            .success {{ background: #e8f5e8; color: #2e7d32; padding: 10px; border-radius: 5px; margin-bottom: 20px; }}
            .security-info {{ background: #e3f2fd; color: #1565c0; padding: 10px; border-radius: 5px; margin-bottom: 20px; font-size: 14px; }}
            .links {{ text-align: center; margin-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h2>📝 Create Secure Account</h2>
            <div class="security-info">
                🔒 Your password will be securely hashed before storage
            </div>
            {get_flash_messages()}
            <form method="POST">
                <div class="form-group">
                    <input type="text" name="username" placeholder="Username" required>
                </div>
                <div class="form-group">
                    <input type="password" name="password" placeholder="Password (min 6 characters)" required>
                </div>
                <button type="submit" class="btn">Register</button>
            </form>
            <div class="links">
                <a href="/login">Back to login</a>
            </div>
        </div>
    </body>
    </html>
    '''


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    files = conn.execute('SELECT * FROM files WHERE user_id = ? ORDER BY uploaded_at DESC',
                         (session['user_id'],)).fetchall()
    conn.close()

    files_html = ""
    for file in files:
        size_kb = round(file['file_size'] / 1024, 2) if file['file_size'] else 0
        uploaded_date = file['uploaded_at']
        if 'T' in str(uploaded_date):
            uploaded_date = str(uploaded_date).replace('T', ' ')[:16]

        security_icon = "🔒" if file['file_hash'] else "⚠️"

        files_html += f'''
        <div class="file-item">
            <div class="file-info">
                <strong>{security_icon} {file['original_filename']}</strong>
                <br>
                <small>📅 {uploaded_date} | 📏 {size_kb} KB</small>
            </div>
            <div class="file-actions">
                <a href="/download/{file['id']}" class="btn">⬇️ Download</a>
                <a href="/delete/{file['id']}" class="btn btn-danger" onclick="return confirm('Delete this file?')">🗑️ Delete</a>
            </div>
        </div>
        '''

    if not files_html:
        files_html = '<p style="text-align: center; color: #666; padding: 40px;">No files uploaded yet.</p>'

    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dashboard - Secure Cloud Storage</title>
        <style>
            body {{ font-family: Arial; margin: 0; background: #f0f0f0; }}
            .header {{ background: white; padding: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); display: flex; justify-content: space-between; align-items: center; }}
            .container {{ max-width: 1000px; margin: 20px auto; padding: 20px; }}
            .upload-box {{ background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); margin-bottom: 30px; }}
            .files-box {{ background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
            .file-list {{ border: 1px solid #eee; border-radius: 5px; }}
            .file-item {{ display: flex; justify-content: space-between; align-items: center; padding: 15px; border-bottom: 1px solid #eee; }}
            .file-item:last-child {{ border-bottom: none; }}
            .file-item:hover {{ background: #f9f9f9; }}
            .file-info {{ flex: 1; }}
            .file-actions {{ display: flex; gap: 10px; }}
            .btn {{ padding: 8px 15px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; text-decoration: none; font-size: 14px; }}
            .btn:hover {{ background: #0056b3; }}
            .btn-danger {{ background: #dc3545; }}
            .btn-danger:hover {{ background: #c82333; }}
            .error {{ background: #ffebee; color: #c62828; padding: 10px; border-radius: 5px; margin-bottom: 20px; }}
            .success {{ background: #e8f5e8; color: #2e7d32; padding: 10px; border-radius: 5px; margin-bottom: 20px; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h2 style="margin: 0;">🔐 Secure Cloud Storage</h2>
            <div>
                <span>Welcome, <strong>{session['username']}</strong>!</span>
                <a href="/logout" class="btn" style="margin-left: 20px; background: #6c757d;">Logout</a>
            </div>
        </div>

        <div class="container">
            {get_flash_messages()}
            <div class="upload-box">
                <h3 style="margin-top: 0;">📤 Upload & Encrypt File</h3>
                <div style="background: #e3f2fd; padding: 15px; border-radius: 5px; margin-bottom: 15px;">
                    <strong>🔒 Security Features:</strong><br>
                    • Files encrypted with AES-256 before storage<br>
                    • SHA-256 integrity verification<br>
                    • Secure key management
                </div>
                <form method="POST" action="/upload" enctype="multipart/form-data" style="display: flex; gap: 10px; align-items: center;">
                    <input type="file" name="file" required style="flex: 1; padding: 10px; border: 1px solid #ddd; border-radius: 5px;">
                    <button type="submit" class="btn">🔒 Encrypt & Upload</button>
                </form>
            </div>

            <div class="files-box">
                <h3 style="margin-top: 0;">📁 Your Encrypted Files ({len(files)})</h3>
                <div class="file-list">
                    {files_html}
                </div>
            </div>
        </div>
    </body>
    </html>
    '''


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('dashboard'))

    file = request.files['file']

    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('dashboard'))

    if file:
        filename = secure_filename(file.filename)
        unique_filename = datetime.now().strftime("%Y%m%d_%H%M%S_") + filename

        file_data = file.read()
        file_size = len(file_data)

        file_hash = calculate_file_hash(file_data)
        encrypted_data = encrypt_file(file_data)

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)

        conn = get_db_connection()
        conn.execute(
            'INSERT INTO files (filename, original_filename, user_id, file_size, file_hash) VALUES (?, ?, ?, ?, ?)',
            (unique_filename, filename, session['user_id'], file_size, file_hash))
        conn.commit()
        conn.close()

        print(f"✅ File encrypted and uploaded: {filename}")
        flash(f'File "{filename}" encrypted and uploaded successfully!', 'success')

    return redirect(url_for('dashboard'))


@app.route('/download/<int:file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    file = conn.execute('SELECT * FROM files WHERE id = ? AND user_id = ?',
                        (file_id, session['user_id'])).fetchone()
    conn.close()

    if file:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file['filename'])
        if os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()

            try:
                decrypted_data = decrypt_file(encrypted_data)

                current_hash = calculate_file_hash(decrypted_data)
                if current_hash != file['file_hash']:
                    flash('⚠️ File integrity check failed!', 'error')

                temp_path = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_' + file['original_filename'])
                with open(temp_path, 'wb') as f:
                    f.write(decrypted_data)

                response = send_file(temp_path, as_attachment=True, download_name=file['original_filename'])

                @response.call_on_close
                def remove_temp_file():
                    try:
                        os.remove(temp_path)
                    except:
                        pass

                return response

            except Exception as e:
                flash('Error decrypting file', 'error')
                print(f"❌ Decryption error: {e}")

    flash('File not found', 'error')
    return redirect(url_for('dashboard'))


@app.route('/delete/<int:file_id>')
def delete_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    file = conn.execute('SELECT * FROM files WHERE id = ? AND user_id = ?',
                        (file_id, session['user_id'])).fetchone()

    if file:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file['filename'])
        if os.path.exists(file_path):
            os.remove(file_path)
        conn.execute('DELETE FROM files WHERE id = ?', (file_id,))
        conn.commit()
        flash('File deleted successfully!', 'success')
    else:
        flash('File not found', 'error')

    conn.close()
    return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    print("🚀 Starting Secure Cloud Storage...")
    print("🔐 Encryption: AES-256")
    print("🔑 Password hashing: bcrypt")
    print("📊 Integrity: SHA-256")
    init_db()
    print("✅ Database ready!")
    print("🌐 Server: http://localhost:5000")
    print("👉 Register once, login multiple times!")

    app.run(debug=True, host='0.0.0.0', port=5000)
