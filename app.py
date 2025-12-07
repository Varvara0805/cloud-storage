from flask import Flask, request, redirect, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import os
import hashlib
from datetime import datetime
import io
import cloudinary
import cloudinary.uploader
import cloudinary.api
import requests
import json
import sqlite3

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
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', Fernet.generate_key().decode()).encode()
cipher_suite = Fernet(ENCRYPTION_KEY)

# 🔧 ПУТЬ К ПОСТОЯННОЙ БАЗЕ ДАННЫХ - АБСОЛЮТНЫЙ ПУТЬ
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'cloud_storage.db')

print("🚀 ЗАПУСК СЕРВЕРА")
print(f"📁 Рабочая директория: {BASE_DIR}")
print(f"🗄️ Путь к базе данных: {DB_PATH}")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    print("🔄 Инициализация базы данных...")
   
    # Проверяем, существует ли уже база данных
    db_exists = os.path.exists(DB_PATH)
    if db_exists:
        print(f"✅ База данных уже существует: {DB_PATH}")
        # Проверяем текущих пользователей
        conn = get_db()
        users = conn.execute('SELECT username FROM users').fetchall()
        conn.close()
        if users:
            print(f"👥 Найдены пользователи: {[user['username'] for user in users]}")
        else:
            print("❌ В базе нет пользователей!")
    else:
        print("🆕 Создаем новую базу данных")
   
    conn = get_db()
   
    # Создаем таблицы если их нет
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
            file_id TEXT UNIQUE NOT NULL,
            filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            user_id TEXT NOT NULL,
            file_size INTEGER,
            cloudinary_url TEXT,
            cloudinary_public_id TEXT,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
   
    # Создаем тестового пользователя только если его нет и если база новая
    if not db_exists:
        cursor = conn.execute('SELECT COUNT(*) as count FROM users')
        if cursor.fetchone()['count'] == 0:
            hashed_pw = generate_password_hash('admin123')
            try:
                conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('admin', hashed_pw))
                print("✅ Тестовый пользователь создан: admin / admin123")
            except sqlite3.IntegrityError:
                print("ℹ️ Тестовый пользователь уже существует")
   
    conn.commit()
   
    # Финальная проверка
    users_count = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
    print(f"📊 Итоговое количество пользователей в БД: {users_count}")
   
    conn.close()
    print(f"✅ База данных готова: {DB_PATH}")

# Инициализируем базу при запуске
init_db()

# 🔧 ФУНКЦИИ
def encrypt_file(file_data):
    return cipher_suite.encrypt(file_data)

def decrypt_file(encrypted_data):
    return cipher_suite.decrypt(encrypted_data)

# 🔧 СИСТЕМА СООБЩЕНИЙ
messages = []
def add_flash_message(message, category='info'):
    messages.append((category, message))
def get_flash_html():
    global messages
    html = ''
    for category, message in messages:
        color = '#c62828' if category == 'error' else '#2e7d32' if category == 'success' else '#1565c0'
        html += f'<div style="background: #f5f5f5; color: {color}; padding: 10px; border-radius: 5px; margin-bottom: 10px; border: 1px solid {color}">{message}</div>'
    messages = []
    return html

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
       
        print(f"🔐 Попытка входа: {username}")
       
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
       
        # ДИАГНОСТИКА: покажем всех пользователей в базе
        all_users = conn.execute('SELECT username FROM users').fetchall()
        print(f"👥 Все пользователи в БД: {[u['username'] for u in all_users]}")
       
        conn.close()
       
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['username']
            session['username'] = user['username']
            add_flash_message('Login successful!', 'success')
            print(f"✅ Успешный вход: {username}")
            return redirect('/dashboard')
        else:
            print(f"❌ Неудачный вход: {username}")
            add_flash_message('Invalid credentials', 'error')
   
    return f'''
    <html><body style="margin: 50px; font-family: Arial;">
        <div style="max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1);">
            <h2>🔐 Login</h2>
            <div style="background: #e3f2fd; padding: 10px; border-radius: 5px; margin-bottom: 20px;">
                <strong>Test:</strong> admin / admin123
            </div>
            {get_flash_html()}
            <form method="POST">
                <input type="text" name="username" placeholder="Username" required style="width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px;">
                <input type="password" name="password" placeholder="Password" required style="width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px;">
                <button type="submit" style="width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer;">Login</button>
            </form>
            <p style="text-align: center; margin-top: 20px;"><a href="/register">Create account</a></p>
        </div>
    </body></html>
    '''

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
       
        print(f"📝 Попытка регистрации: {username}")
       
        if len(password) < 6:
            add_flash_message('Password too short', 'error')
            return redirect('/register')
       
        conn = get_db()
       
        # Проверяем текущих пользователей ДО регистрации
        before_users = conn.execute('SELECT username FROM users').fetchall()
        print(f"👥 Пользователи ДО регистрации: {[u['username'] for u in before_users]}")
       
        try:
            hashed_pw = generate_password_hash(password)
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_pw))
            conn.commit()
           
            # Проверяем текущих пользователей ПОСЛЕ регистрации
            after_users = conn.execute('SELECT username FROM users').fetchall()
            print(f"👥 Пользователи ПОСЛЕ регистрации: {[u['username'] for u in after_users]}")
           
            # ПРОВЕРКА: убедимся что пользователь сохранился
            new_user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
           
            if new_user:
                print(f"✅ НОВЫЙ ПОЛЬЗОВАТЕЛЬ СОХРАНЕН В БД: {username}")
                print(f"📍 Путь к БД: {DB_PATH}")
                add_flash_message('Registration successful!', 'success')
                conn.close()
                return redirect('/login')
            else:
                print(f"❌ ПОЛЬЗОВАТЕЛЬ НЕ СОХРАНИЛСЯ: {username}")
                add_flash_message('Registration failed - user not saved', 'error')
                conn.close()
                return redirect('/register')
               
        except sqlite3.IntegrityError:
            conn.close()
            print(f"❌ Пользователь уже существует: {username}")
            add_flash_message('User already exists', 'error')
   
    return f'''
    <html><body style="margin: 50px; font-family: Arial;">
        <div style="max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1);">
            <h2>📝 Register</h2>
            {get_flash_html()}
            <form method="POST">
                <input type="text" name="username" placeholder="Username" required style="width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px;">
                <input type="password" name="password" placeholder="Password (6+ chars)" required style="width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px;">
                <button type="submit" style="width: 100%; padding: 12px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer;">Register</button>
            </form>
            <p style="text-align: center; margin-top: 20px;"><a href="/login">Back to login</a></p>
        </div>
    </body></html>
    '''

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
   
    user_id = session['user_id']
   
    conn = get_db()
    files_list = conn.execute(
        'SELECT * FROM files WHERE user_id = ? ORDER BY uploaded_at DESC',
        (user_id,)
    ).fetchall()
    conn.close()
   
    files_html = ""
    for file in files_list:
        size_kb = round(file["file_size"]/1024, 1) if file["file_size"] else 0
        upload_date = datetime.strptime(file["uploaded_at"], '%Y-%m-%d %H:%M:%S').strftime('%d.%m.%Y %H:%M') if file["uploaded_at"] else 'Unknown'
       
        files_html += f'''
        <div style="display: flex; justify-content: space-between; align-items: center; padding: 15px; border-bottom: 1px solid #eee;">
            <div>
                <strong>📁 {file["original_filename"]}</strong><br>
                <small>Size: {size_kb} KB | Uploaded: {upload_date}</small>
            </div>
            <div>
                <a href="/download/{file["file_id"]}" style="padding: 8px 15px; background: #007bff; color: white; border-radius: 5px; text-decoration: none; margin: 5px;">⬇️ Download</a>
                <a href="/delete/{file["file_id"]}" onclick="return confirm('Are you sure you want to delete {file["original_filename"]}?')" style="padding: 8px 15px; background: #dc3545; color: white; border-radius: 5px; text-decoration: none; margin: 5px;">🗑️ Delete</a>
            </div>
        </div>
        '''
   
    if not files_html:
        files_html = '<p style="text-align: center; color: #666; padding: 40px;">No files yet. Upload your first file!</p>'
   
    return f'''
    <html><body style="margin: 0; font-family: Arial; background: #f0f0f0;">
        <div style="background: white; padding: 20px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
            <h2 style="margin: 0;">☁️ Cloud Storage</h2>
            <div style="display: flex; align-items: center; gap: 15px;">
                <span>Welcome, <strong>{session["username"]}</strong>!</span>
                <a href="/profile" style="background: #17a2b8; color: white; padding: 8px 15px; border-radius: 5px; text-decoration: none;">👤 Profile</a>
                <a href="/logout" style="background: #6c757d; color: white; padding: 8px 15px; border-radius: 5px; text-decoration: none;">🚪 Logout</a>
            </div>
        </div>
       
        <div style="max-width: 1000px; margin: 20px auto; padding: 20px;">
            {get_flash_html()}
            <div style="background: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <h3 style="margin-top: 0;">📤 Upload File</h3>
                <form method="POST" action="/upload" enctype="multipart/form-data" style="display: flex; gap: 10px; align-items: center;">
                    <input type="file" name="file" required style="flex: 1; padding: 10px; border: 1px solid #ddd; border-radius: 5px;">
                    <button type="submit" style="padding: 10px 20px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer;">📎 Upload</button>
                </form>
                <p style="color: #666; font-size: 14px; margin-top: 10px;">Max file size: 16MB | Files are encrypted before upload</p>
            </div>
           
            <div style="background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <h3 style="margin-top: 0;">📁 Your Files ({len(files_list)})</h3>
                <div style="border: 1px solid #eee; border-radius: 5px;">{files_html}</div>
            </div>
        </div>
    </body></html>
    '''

# ... остальные маршруты (upload, download, delete, profile, logout) остаются без изменений ...

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
   
    try:
        user_id = session['user_id']
        filename = secure_filename(file.filename)
        file_id = hashlib.md5(f"{user_id}_{filename}_{datetime.now()}".encode()).hexdigest()
       
        file_data = file.read()
        file_size = len(file_data)
       
        if file_size > 16 * 1024 * 1024:
            add_flash_message('File too large (max 16MB)', 'error')
            return redirect('/dashboard')
       
        # Шифруем и загружаем в Cloudinary
        encrypted_data = encrypt_file(file_data)
        result = cloudinary.uploader.upload(
            encrypted_data,
            public_id=f"storage/{user_id}/{file_id}_{filename}",
            resource_type="raw"
        )
       
        # Сохраняем в базу данных
        conn = get_db()
        conn.execute('''
            INSERT INTO files (file_id, filename, original_filename, user_id, file_size, cloudinary_url, cloudinary_public_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (file_id, f"{file_id}_{filename}", filename, user_id, file_size, result['secure_url'], result['public_id']))
        conn.commit()
        conn.close()
       
        add_flash_message(f'✅ File "{filename}" uploaded successfully!', 'success')
       
    except Exception as e:
        add_flash_message(f'❌ Upload error: {str(e)}', 'error')
   
    return redirect('/dashboard')

@app.route('/download/<file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect('/login')
   
    conn = get_db()
    file = conn.execute(
        'SELECT * FROM files WHERE file_id = ? AND user_id = ?',
        (file_id, session['user_id'])
    ).fetchone()
    conn.close()
   
    if file:
        try:
            response = requests.get(file['cloudinary_url'])
            if response.status_code == 200:
                decrypted_data = decrypt_file(response.content)
                return send_file(
                    io.BytesIO(decrypted_data),
                    as_attachment=True,
                    download_name=file['original_filename']
                )
            else:
                add_flash_message('File not found on cloud storage', 'error')
        except Exception as e:
            add_flash_message(f'Download error: {str(e)}', 'error')
    else:
        add_flash_message('File not found', 'error')
   
    return redirect('/dashboard')

@app.route('/delete/<file_id>')
def delete_file(file_id):
    if 'user_id' not in session:
        return redirect('/login')
   
    conn = get_db()
   
    # Получаем информацию о файле перед удалением
    file = conn.execute('SELECT * FROM files WHERE file_id = ? AND user_id = ?', (file_id, session['user_id'])).fetchone()
   
    if file:
        try:
            # Удаляем файл из Cloudinary
            if file['cloudinary_public_id']:
                cloudinary.uploader.destroy(file['cloudinary_public_id'], resource_type="raw")
           
            # Удаляем запись из базы данных
            conn.execute('DELETE FROM files WHERE file_id = ? AND user_id = ?', (file_id, session['user_id']))
            conn.commit()
           
            add_flash_message(f'✅ File "{file["original_filename"]}" deleted successfully!', 'success')
        except Exception as e:
            add_flash_message(f'❌ Delete error: {str(e)}', 'error')
    else:
        add_flash_message('File not found', 'error')
   
    conn.close()
    return redirect('/dashboard')

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect('/login')
   
    user_id = session['user_id']
   
    conn = get_db()
   
    # Получаем статистику пользователя
    user_stats = conn.execute('''
        SELECT
            COUNT(*) as total_files,
            COALESCE(SUM(file_size), 0) as total_size,
            MIN(uploaded_at) as first_upload
        FROM files
        WHERE user_id = ?
    ''', (user_id,)).fetchone()
   
    # Получаем информацию о пользователе
    user_info = conn.execute('''
        SELECT username, created_at
        FROM users
        WHERE username = ?
    ''', (user_id,)).fetchone()
   
    conn.close()
   
    total_size_mb = round(user_stats['total_size'] / (1024 * 1024), 2) if user_stats['total_size'] else 0
    total_files = user_stats['total_files'] or 0
   
    # Форматируем даты
    join_date = datetime.strptime(user_info['created_at'], '%Y-%m-%d %H:%M:%S').strftime('%d.%m.%Y') if user_info['created_at'] else 'Unknown'
    first_upload = datetime.strptime(user_stats['first_upload'], '%Y-%m-%d %H:%M:%S').strftime('%d.%m.%Y') if user_stats['first_upload'] else 'No uploads yet'
   
    return f'''
    <html><body style="margin: 0; font-family: Arial; background: #f0f0f0;">
        <div style="background: white; padding: 20px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
            <h2 style="margin: 0;">☁️ Cloud Storage</h2>
            <div style="display: flex; align-items: center; gap: 15px;">
                <span>Welcome, <strong>{session["username"]}</strong>!</span>
                <a href="/dashboard" style="background: #007bff; color: white; padding: 8px 15px; border-radius: 5px; text-decoration: none;">📁 Dashboard</a>
                <a href="/logout" style="background: #6c757d; color: white; padding: 8px 15px; border-radius: 5px; text-decoration: none;">🚪 Logout</a>
            </div>
        </div>
       
        <div style="max-width: 800px; margin: 20px auto; padding: 20px;">
            {get_flash_html()}
            <div style="background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <h2 style="margin-top: 0; color: #333;">👤 User Profile</h2>
               
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px;">
                    <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #007bff;">
                        <h3 style="margin-top: 0; color: #007bff;">Account Info</h3>
                        <p><strong>Username:</strong> {user_info['username']}</p>
                        <p><strong>Member since:</strong> {join_date}</p>
                    </div>
                   
                    <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #28a745;">
                        <h3 style="margin-top: 0; color: #28a745;">Storage Stats</h3>
                        <p><strong>Total files:</strong> {total_files}</p>
                        <p><strong>Total storage used:</strong> {total_size_mb} MB</p>
                        <p><strong>First upload:</strong> {first_upload}</p>
                    </div>
                </div>
               
                <div style="background: #e7f3ff; padding: 20px; border-radius: 8px; border: 1px solid #b3d9ff;">
                    <h3 style="margin-top: 0; color: #0056b3;">💡 Information</h3>
                    <p>• Your files are securely encrypted before uploading to cloud storage</p>
                    <p>• Maximum file size: 16MB per file</p>
                    <p>• All your data persists after server restart</p>
                    <p>• Files are stored in Cloudinary with end-to-end encryption</p>
                </div>
            </div>
        </div>
    </body></html>
    '''

@app.route('/logout')
def logout():
    session.clear()
    add_flash_message('Logged out successfully', 'info')
    return redirect('/login')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"🌐 Сервер запускается на порту {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
