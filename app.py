from flask import Flask, request, redirect, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import os
import hashlib
from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursor
import io

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'super-secret-key-12345')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Создаем папку для загрузок
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Получение строки подключения к PostgreSQL из переменных окружения Render
DATABASE_URL = os.environ.get('DATABASE_URL')

# Генерация ключа шифрования (на Render используем фиксированный ключ из переменных окружения)
def get_encryption_key():
    key = os.environ.get('ENCRYPTION_KEY')
    if key:
        return key.encode()
    else:
        # Генерируем новый ключ если нет в переменных окружения
        new_key = Fernet.generate_key()
        print("⚠️  ВНИМАНИЕ: Используется временный ключ шифрования. Для production установите ENCRYPTION_KEY в переменных окружения Render")
        return new_key

ENCRYPTION_KEY = get_encryption_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

def get_db_connection():
    """Установка соединения с PostgreSQL"""
    conn = psycopg2.connect(DATABASE_URL)
    return conn

def init_db():
    """Инициализация таблиц в PostgreSQL"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Создаем таблицу пользователей
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Создаем таблицу файлов
        cur.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id SERIAL PRIMARY KEY,
                filename VARCHAR(255) NOT NULL,
                original_filename VARCHAR(255) NOT NULL,
                user_id INTEGER NOT NULL,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                file_size INTEGER,
                file_hash TEXT
            )
        ''')
        
        conn.commit()
        cur.close()
        conn.close()
        print("✅ PostgreSQL database initialized successfully!")
        return True
    except Exception as e:
        print(f"❌ Database error: {e}")
        return False

def encrypt_file(file_data):
    """Шифрует данные файла"""
    return cipher_suite.encrypt(file_data)

def decrypt_file(encrypted_data):
    """Расшифровывает данные файла"""
    return cipher_suite.decrypt(encrypted_data)

def calculate_file_hash(file_data):
    """Вычисляет хеш файла для проверки целостности"""
    return hashlib.sha256(file_data).hexdigest()

# Простая система flash сообщений
class FlashMessages:
    def __init__(self):
        self.messages = []
    
    def add(self, message, category='info'):
        self.messages.append((category, message))
    
    def get_all(self):
        messages = self.messages.copy()
        self.messages.clear()
        return messages

flash_messages = FlashMessages()

def get_flash_html():
    messages_html = ''
    for category, message in flash_messages.get_all():
        if category == 'error':
            messages_html += f'<div style="background: #ffebee; color: #c62828; padding: 10px; border-radius: 5px; margin-bottom: 20px;">{message}</div>'
        elif category == 'success':
            messages_html += f'<div style="background: #e8f5e8; color: #2e7d32; padding: 10px; border-radius: 5px; margin-bottom: 20px;">{message}</div>'
        else:
            messages_html += f'<div style="background: #e3f2fd; color: #1565c0; padding: 10px; border-radius: 5px; margin-bottom: 20px;">{message}</div>'
    return messages_html

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
        
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash_messages.add('Login successful!', 'success')
            return redirect('/dashboard')
        else:
            flash_messages.add('Invalid username or password', 'error')
    
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
            .security-info {{ background: #e3f2fd; color: #1565c0; padding: 10px; border-radius: 5px; margin-bottom: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h2>🔐 Secure Cloud Storage</h2>
            <div class="security-info">
                <strong>🔒 Secure Features:</strong><br>
                • AES-256 Encryption<br>
                • Password Hashing<br>
                • SHA-256 Integrity<br>
                • PostgreSQL Database
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
            flash_messages.add('Password must be at least 6 characters', 'error')
            return redirect('/register')
        
        hashed_password = generate_password_hash(password)
        
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute('INSERT INTO users (username, password) VALUES (%s, %s)',
                       (username, hashed_password))
            conn.commit()
            flash_messages.add('Registration successful! Please login.', 'success')
            return redirect('/login')
        except psycopg2.IntegrityError:
            flash_messages.add('Username already exists', 'error')
            return redirect('/register')
        finally:
            cur.close()
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
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute('SELECT * FROM files WHERE user_id = %s ORDER BY uploaded_at DESC', 
                (session['user_id'],))
    files = cur.fetchall()
    cur.close()
    conn.close()
    
    files_html = ""
    for file in files:
        size_kb = round(file['file_size'] / 1024, 2) if file['file_size'] else 0
        
        files_html += f'''
        <div style="display: flex; justify-content: space-between; align-items: center; padding: 15px; border-bottom: 1px solid #eee;">
            <div>
                <strong>🔒 {file['original_filename']}</strong>
                <br>
                <small>📏 {size_kb} KB | 📅 {file['uploaded_at'].strftime("%Y-%m-%d %H:%M")}</small>
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
            <h2 style="margin: 0;">🔐 Secure Cloud Storage</h2>
            <div>
                <span>Welcome, <strong>{session.get("username", "User")}</strong>!</span>
                <a href="/logout" style="margin-left: 20px; background: #6c757d; color: white; padding: 8px 15px; border-radius: 5px; text-decoration: none;">Logout</a>
            </div>
        </div>
        
        <div class="container">
            {get_flash_html()}
            <div class="upload-box">
                <h3 style="margin-top: 0;">📤 Upload & Encrypt File</h3>
                <form method="POST" action="/upload" enctype="multipart/form-data" style="display: flex; gap: 10px; align-items: center;">
                    <input type="file" name="file" required style="flex: 1; padding: 10px; border: 1px solid #ddd; border-radius: 5px;">
                    <button type="submit" style="padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer;">🔒 Encrypt & Upload</button>
                </form>
            </div>
            
            <div class="files-box">
                <h3 style="margin-top: 0;">📁 Your Encrypted Files ({len(files)})</h3>
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
        flash_messages.add('No file selected', 'error')
        return redirect('/dashboard')
    
    file = request.files['file']
    
    if file.filename == '':
        flash_messages.add('No file selected', 'error')
        return redirect('/dashboard')
    
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
        cur = conn.cursor()
        cur.execute('INSERT INTO files (filename, original_filename, user_id, file_size, file_hash) VALUES (%s, %s, %s, %s, %s)',
                   (unique_filename, filename, session['user_id'], file_size, file_hash))
        conn.commit()
        cur.close()
        conn.close()
        
        flash_messages.add(f'File "{filename}" encrypted and uploaded successfully!', 'success')
    
    return redirect('/dashboard')

@app.route('/download/<int:file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect('/login')
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute('SELECT * FROM files WHERE id = %s AND user_id = %s', 
               (file_id, session['user_id']))
    file = cur.fetchone()
    cur.close()
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
                    flash_messages.add('⚠️ File integrity check failed!', 'error')
                
                # Отправляем файл напрямую из памяти без создания временного файла
                return send_file(
                    io.BytesIO(decrypted_data),
                    as_attachment=True,
                    download_name=file['original_filename']
                )
                
            except Exception as e:
                flash_messages.add('Error decrypting file', 'error')
                print(f"❌ Decryption error: {e}")
    
    flash_messages.add('File not found', 'error')
    return redirect('/dashboard')

@app.route('/delete/<int:file_id>')
def delete_file(file_id):
    if 'user_id' not in session:
        return redirect('/login')
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute('SELECT * FROM files WHERE id = %s AND user_id = %s', 
               (file_id, session['user_id']))
    file = cur.fetchone()
    
    if file:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file['filename'])
        if os.path.exists(file_path):
            os.remove(file_path)
        cur.execute('DELETE FROM files WHERE id = %s', (file_id,))
        conn.commit()
        flash_messages.add('File deleted successfully!', 'success')
    else:
        flash_messages.add('File not found', 'error')
    
    cur.close()
    conn.close()
    return redirect('/dashboard')

@app.route('/logout')
def logout():
    session.clear()
    flash_messages.add('You have been logged out', 'info')
    return redirect('/login')

if __name__ == '__main__':
    print("🚀 Starting Secure Cloud Storage with PostgreSQL...")
    print("🔐 Encryption: AES-256")
    print("🗄️  Database: PostgreSQL")
    print("📊 Integrity: SHA-256")
    init_db()
    print("✅ Database ready!")
    print("🌐 Server starting...")
    app.run(host='0.0.0.0', port=5000)
