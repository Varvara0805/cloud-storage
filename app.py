from flask import Flask, request, redirect, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import os
import hashlib
from datetime import datetime
import sqlite3
import io
import cloudinary
import cloudinary.uploader
import cloudinary.api
import requests

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'super-secret-key-12345')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# 🔧 НАСТРОЙКИ CLOUDINARY
cloudinary.config(
    cloud_name=os.environ.get('CLOUDINARY_CLOUD_NAME'),
    api_key=os.environ.get('CLOUDINARY_API_KEY'),
    api_secret=os.environ.get('CLOUDINARY_API_SECRET'),
    secure=True
)

# 🔧 КЛЮЧ ШИФРОВАНИЯ
def get_encryption_key():
    key = os.environ.get('ENCRYPTION_KEY')
    if not key:
        key = Fernet.generate_key().decode()
    return key.encode()

ENCRYPTION_KEY = get_encryption_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

# 🔧 БАЗА ДАННЫХ - ИСПОЛЬЗУЕМ /tmp/ НА RENDER
DB_PATH = '/tmp/cloud_storage.db'

def get_db():
    """Создаем соединение с базой данных"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Инициализация базы данных"""
    conn = get_db()
    
    # Создаем таблицы
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            file_size INTEGER,
            file_hash TEXT,
            cloudinary_url TEXT,
            cloudinary_public_id TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Добавляем тестового пользователя если нет пользователей
    cursor = conn.execute('SELECT COUNT(*) as count FROM users')
    if cursor.fetchone()['count'] == 0:
        hashed_password = generate_password_hash('admin123')
        conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', 
                    ('admin', hashed_password))
        print("✅ Test user created: admin / admin123")
    
    conn.commit()
    conn.close()
    print("✅ Database initialized!")

# 🔧 ИНИЦИАЛИЗИРУЕМ БАЗУ ПРИ ЗАПУСКЕ
init_db()

def encrypt_file(file_data):
    return cipher_suite.encrypt(file_data)

def decrypt_file(encrypted_data):
    return cipher_suite.decrypt(encrypted_data)

def calculate_file_hash(file_data):
    return hashlib.sha256(file_data).hexdigest()

# 🔧 ФУНКЦИИ ДЛЯ CLOUDINARY
def upload_to_cloudinary(encrypted_data, filename):
    try:
        # Создаем временный файл
        temp_path = f"/tmp/temp_{filename}"
        with open(temp_path, "wb") as f:
            f.write(encrypted_data)
        
        # Загружаем в Cloudinary
        result = cloudinary.uploader.upload(
            temp_path,
            public_id=f"secure_storage/{filename}",
            resource_type="auto"
        )
        
        os.remove(temp_path)
        return result
    except Exception as e:
        print(f"❌ Cloudinary upload error: {e}")
        return None

def delete_from_cloudinary(public_id):
    try:
        result = cloudinary.uploader.destroy(public_id)
        return result.get('result') == 'ok'
    except Exception as e:
        print(f"❌ Cloudinary delete error: {e}")
        return False

# СИСТЕМА СООБЩЕНИЙ
messages = []

def add_flash_message(message, category='info'):
    messages.append((category, message))

def get_flash_html():
    global messages
    messages_html = ''
    for category, message in messages:
        if category == 'error':
            messages_html += f'<div style="background: #ffebee; color: #c62828; padding: 10px; border-radius: 5px; margin-bottom: 20px;">{message}</div>'
        elif category == 'success':
            messages_html += f'<div style="background: #e8f5e8; color: #2e7d32; padding: 10px; border-radius: 5px; margin-bottom: 20px;">{message}</div>'
        else:
            messages_html += f'<div style="background: #e3f2fd; color: #1565c0; padding: 10px; border-radius: 5px; margin-bottom: 20px;">{message}</div>'
    messages = []
    return messages_html

# 🎯 МАРШРУТЫ
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect('/dashboard')
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            add_flash_message('Login successful!', 'success')
            return redirect('/dashboard')
        else:
            add_flash_message('Invalid username or password', 'error')
    
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
        </style>
    </head>
    <body>
        <div class="container">
            <h2>🔐 Secure Cloud Storage</h2>
            <div style="background: #e3f2fd; padding: 10px; border-radius: 5px; margin-bottom: 20px;">
                <strong>Test account:</strong><br>
                Username: <code>admin</code><br>
                Password: <code>admin123</code>
            </div>
            {get_flash_html()}
            <form method="POST">
                <div class="form-group">
                    <input type="text" name="username" placeholder="Username" required>
                </div>
                <div class="form-group">
                    <input type="password" name="password" placeholder="Password" required>
                </div>
                <button type="submit" class="btn">Login</button>
            </form>
            <div style="text-align: center; margin-top: 20px;">
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
            add_flash_message('Password must be at least 6 characters', 'error')
            return redirect('/register')
        
        hashed_password = generate_password_hash(password)
        
        conn = get_db()
        try:
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                        (username, hashed_password))
            conn.commit()
            add_flash_message('Registration successful! Please login.', 'success')
            return redirect('/login')
        except sqlite3.IntegrityError:
            add_flash_message('Username already exists', 'error')
            return redirect('/register')
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
        </style>
    </head>
    <body>
        <div class="container">
            <h2>📝 Create Account</h2>
            {get_flash_html()}
            <form method="POST">
                <div class="form-group">
                    <input type="text" name="username" placeholder="Username" required>
                </div>
                <div class="form-group">
                    <input type="password" name="password" placeholder="Password (min 6 characters)" required>
                </div>
                <button type="submit" class="btn">Register</button>
            </form>
            <div style="text-align: center; margin-top: 20px;">
                <a href="/login">Back to login</a>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    
    conn = get_db()
    files_list = conn.execute(
        'SELECT * FROM files WHERE user_id = ? ORDER BY uploaded_at DESC', 
        (session['user_id'],)
    ).fetchall()
    conn.close()
    
    files_html = ""
    for file in files_list:
        size_kb = round(file['file_size'] / 1024, 2) if file['file_size'] else 0
        
        files_html += f'''
        <div style="display: flex; justify-content: space-between; align-items: center; padding: 15px; border-bottom: 1px solid #eee;">
            <div>
                <strong>☁️ {file['original_filename']}</strong>
                <br>
                <small>📏 {size_kb} KB | 🌐 Cloud Storage</small>
            </div>
            <div>
                <a href="/download/{file['id']}" style="padding: 8px 15px; background: #007bff; color: white; border-radius: 5px; text-decoration: none;">⬇️ Download</a>
                <a href="/delete/{file['id']}" style="padding: 8px 15px; background: #dc3545; color: white; border-radius: 5px; text-decoration: none; margin-left: 10px;" onclick="return confirm('Delete this file?')">🗑️ Delete</a>
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
            .header {{ background: white; padding: 20px; display: flex; justify-content: space-between; align-items: center; }}
            .container {{ max-width: 1000px; margin: 20px auto; padding: 20px; }}
            .upload-box {{ background: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
            .files-box {{ background: white; padding: 30px; border-radius: 10px; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h2 style="margin: 0;">☁️ Secure Cloud Storage</h2>
            <div>
                <span>Welcome, <strong>{session.get("username", "User")}</strong>!</span>
                <a href="/logout" style="margin-left: 20px; background: #6c757d; color: white; padding: 8px 15px; border-radius: 5px; text-decoration: none;">Logout</a>
            </div>
        </div>
        
        <div class="container">
            {get_flash_html()}
            <div class="upload-box">
                <h3 style="margin-top: 0;">📤 Upload & Encrypt to Cloud</h3>
                <form method="POST" action="/upload" enctype="multipart/form-data" style="display: flex; gap: 10px; align-items: center;">
                    <input type="file" name="file" required style="flex: 1; padding: 10px; border: 1px solid #ddd; border-radius: 5px;">
                    <button type="submit" style="padding: 10px 20px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer;">☁️ Upload to Cloud</button>
                </form>
            </div>
            
            <div class="files-box">
                <h3 style="margin-top: 0;">📁 Your Cloud Files ({len(files_list)})</h3>
                <div style="border: 1px solid #eee; border-radius: 5px;">
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
        return redirect('/login')
    
    if 'file' not in request.files:
        add_flash_message('No file selected', 'error')
        return redirect('/dashboard')
    
    file = request.files['file']
    
    if file.filename == '':
        add_flash_message('No file selected', 'error')
        return redirect('/dashboard')
    
    if file:
        filename = secure_filename(file.filename)
        unique_filename = datetime.now().strftime("%Y%m%d_%H%M%S_") + filename
        
        file_data = file.read()
        file_size = len(file_data)
        
        file_hash = calculate_file_hash(file_data)
        encrypted_data = encrypt_file(file_data)
        
        # Загружаем в Cloudinary
        cloud_result = upload_to_cloudinary(encrypted_data, unique_filename)
        
        if cloud_result:
            conn = get_db()
            conn.execute('''
                INSERT INTO files 
                (filename, original_filename, user_id, file_size, file_hash, cloudinary_url, cloudinary_public_id) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                unique_filename, filename, session['user_id'], file_size, file_hash,
                cloud_result['secure_url'], cloud_result['public_id']
            ))
            conn.commit()
            conn.close()
            
            add_flash_message(f'File "{filename}" encrypted and uploaded to cloud!', 'success')
        else:
            add_flash_message('Error uploading file to cloud storage', 'error')
    
    return redirect('/dashboard')

@app.route('/download/<int:file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect('/login')
    
    conn = get_db()
    file = conn.execute(
        'SELECT * FROM files WHERE id = ? AND user_id = ?', 
        (file_id, session['user_id'])
    ).fetchone()
    conn.close()
    
    if file:
        try:
            # Скачиваем из Cloudinary
            response = requests.get(file['cloudinary_url'])
            
            if response.status_code == 200:
                encrypted_data = response.content
                decrypted_data = decrypt_file(encrypted_data)
                
                return send_file(
                    io.BytesIO(decrypted_data),
                    as_attachment=True,
                    download_name=file['original_filename']
                )
        except Exception as e:
            print(f"❌ Download error: {e}")
            add_flash_message('Error downloading file from cloud', 'error')
    
    add_flash_message('File not found', 'error')
    return redirect('/dashboard')

@app.route('/delete/<int:file_id>')
def delete_file(file_id):
    if 'user_id' not in session:
        return redirect('/login')
    
    conn = get_db()
    file = conn.execute(
        'SELECT * FROM files WHERE id = ? AND user_id = ?', 
        (file_id, session['user_id'])
    ).fetchone()
    
    if file:
        # Удаляем из Cloudinary
        if file['cloudinary_public_id']:
            delete_success = delete_from_cloudinary(file['cloudinary_public_id'])
            if not delete_success:
                add_flash_message('Warning: File might not be fully deleted from cloud', 'error')
        
        conn.execute('DELETE FROM files WHERE id = ?', (file_id,))
        conn.commit()
        add_flash_message('File deleted successfully!', 'success')
    else:
        add_flash_message('File not found', 'error')
    
    conn.close()
    return redirect('/dashboard')

@app.route('/logout')
def logout():
    session.clear()
    add_flash_message('You have been logged out', 'info')
    return redirect('/login')

if __name__ == '__main__':
    print("🚀 Starting Secure Cloud Storage...")
    print("✅ Database initialized!")
    print("✅ Cloudinary configured!")
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
