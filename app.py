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
import time

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

# 🔧 ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ДЛЯ ДАННЫХ
users_db = {}
user_files_db = {}

def save_to_cloudinary(data, path):
    """Сохраняет данные в Cloudinary"""
    try:
        json_str = json.dumps(data, ensure_ascii=False, indent=2)
        result = cloudinary.uploader.upload(
            json_str.encode('utf-8'),
            public_id=f"database/{path}",
            resource_type="raw",
            type="upload"
        )
        print(f"✅ Saved to Cloudinary: {path}")
        return True
    except Exception as e:
        print(f"❌ Error saving {path}: {e}")
        return False

def load_from_cloudinary(path):
    """Загружает данные из Cloudinary"""
    try:
        url = cloudinary.utils.cloudinary_url(
            f"database/{path}",
            resource_type='raw',
            type='upload'
        )[0]
        
        url_with_cache = f"{url}?t={int(time.time())}"
        response = requests.get(url_with_cache, timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Loaded from Cloudinary: {path}")
            return data
        else:
            print(f"❌ Failed to load {path}, status: {response.status_code}")
    except Exception as e:
        print(f"❌ Error loading {path}: {e}")
    return None

# 🔧 УЛУЧШЕННАЯ СИСТЕМА СИНХРОНИЗАЦИИ
def initialize_databases():
    """Инициализирует все базы данных при запуске"""
    global users_db, user_files_db
    
    print("🔄 Initializing databases from Cloudinary...")
    
    # Загружаем пользователей
    cloud_users = load_from_cloudinary("users")
    if cloud_users:
        users_db = cloud_users
        print(f"👥 Loaded {len(users_db)} users: {list(users_db.keys())}")
    else:
        # СОЗДАЕМ ТЕСТОВЫХ ПОЛЬЗОВАТЕЛЕЙ
        users_db = {
            "admin": {
                "username": "admin", 
                "password": generate_password_hash("admin123"),
                "created_at": datetime.now().isoformat(),
                "role": "administrator"
            },
            "demo": {
                "username": "demo", 
                "password": generate_password_hash("demo123"),
                "created_at": datetime.now().isoformat(),
                "role": "user"
            },
            "test": {
                "username": "test", 
                "password": generate_password_hash("test123"),
                "created_at": datetime.now().isoformat(),
                "role": "user"
            }
        }
        save_to_cloudinary(users_db, "users")
        print("🔧 Created test users: admin, demo, test")
    
    # Загружаем файлы для каждого пользователя
    user_files_db = {}
    for username in users_db.keys():
        cloud_files = load_from_cloudinary(f"files_{username}")
        if cloud_files is not None:
            user_files_db[username] = cloud_files
            print(f"📁 Loaded {len(cloud_files)} files for {username}")
        else:
            user_files_db[username] = []
            # Сохраняем пустой список файлов для нового пользователя
            save_to_cloudinary([], f"files_{username}")
    
    print("✅ Databases initialized successfully!")

def get_users():
    """Получает всех пользователей"""
    global users_db
    return users_db

def save_users():
    """Сохраняет пользователей в Cloudinary"""
    global users_db
    success = save_to_cloudinary(users_db, "users")
    if success:
        print(f"💾 Users saved: {list(users_db.keys())}")
    return success

def get_user_files(user_id):
    """Получает файлы пользователя"""
    global user_files_db
    
    # Если пользователя нет в памяти, загружаем из Cloudinary
    if user_id not in user_files_db:
        cloud_files = load_from_cloudinary(f"files_{user_id}")
        if cloud_files is not None:
            user_files_db[user_id] = cloud_files
        else:
            user_files_db[user_id] = []
    
    return user_files_db.get(user_id, [])

def save_user_files(user_id):
    """Сохраняет файлы пользователя в Cloudinary"""
    global user_files_db
    
    if user_id in user_files_db:
        files = user_files_db[user_id]
        success = save_to_cloudinary(files, f"files_{user_id}")
        if success:
            print(f"💾 Files saved for {user_id}: {len(files)} files")
        return success
    return False

def save_all_data():
    """Сохраняет ВСЕ данные - пользователей и все файлы"""
    print("💾 Saving ALL data to Cloudinary...")
    
    # Сохраняем пользователей
    users_success = save_users()
    
    # Сохраняем файлы для каждого пользователя
    files_success = True
    for user_id in user_files_db.keys():
        if not save_user_files(user_id):
            files_success = False
    
    if users_success and files_success:
        print("✅ ALL data saved successfully!")
        return True
    else:
        print("⚠️ Some data may not have been saved completely")
        return False

# 🔧 ФУНКЦИИ ШИФРОВАНИЯ
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
        if category == 'error':
            html += f'''
            <div class="alert alert-error">
                <div class="alert-icon">⚠️</div>
                <div class="alert-content">{message}</div>
            </div>
            '''
        elif category == 'success':
            html += f'''
            <div class="alert alert-success">
                <div class="alert-icon">✅</div>
                <div class="alert-content">{message}</div>
            </div>
            '''
        else:
            html += f'''
            <div class="alert alert-info">
                <div class="alert-icon">ℹ️</div>
                <div class="alert-content">{message}</div>
            </div>
            '''
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
        users = get_users()
        
        print(f"🔍 Login attempt: {username}")
        
        user = users.get(username)
        if user and check_password_hash(user['password'], password):
            session['user_id'] = username
            session['username'] = username
            add_flash_message('Login successful!', 'success')
            return redirect('/dashboard')
        else:
            add_flash_message('Invalid username or password', 'error')
    
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login | Secure Cloud Storage</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }
            
            .login-container {
                background: white;
                border-radius: 20px;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                overflow: hidden;
                width: 100%;
                max-width: 440px;
            }
            
            .login-header {
                background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
                color: white;
                padding: 40px 30px;
                text-align: center;
            }
            
            .login-header h1 {
                font-size: 28px;
                font-weight: 700;
                margin-bottom: 8px;
            }
            
            .login-header p {
                opacity: 0.9;
                font-size: 16px;
            }
            
            .login-body {
                padding: 40px 30px;
            }
            
            .demo-accounts {
                background: #f0f9ff;
                border: 1px solid #bae6fd;
                border-radius: 12px;
                padding: 20px;
                margin-bottom: 25px;
            }
            
            .demo-accounts h3 {
                color: #0369a1;
                font-size: 16px;
                margin-bottom: 12px;
                display: flex;
                align-items: center;
                gap: 8px;
            }
            
            .account-list {
                display: grid;
                gap: 10px;
            }
            
            .account-item {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 8px 12px;
                background: white;
                border-radius: 8px;
                border: 1px solid #e0f2fe;
            }
            
            .account-info {
                display: flex;
                align-items: center;
                gap: 8px;
            }
            
            .username {
                font-weight: 600;
                color: #1e293b;
            }
            
            .password {
                font-family: 'Courier New', monospace;
                color: #64748b;
                font-size: 14px;
            }
            
            .role {
                background: #dbeafe;
                color: #1d4ed8;
                padding: 2px 8px;
                border-radius: 12px;
                font-size: 12px;
                font-weight: 600;
            }
            
            .form-group {
                margin-bottom: 20px;
            }
            
            .form-label {
                display: block;
                font-weight: 600;
                color: #374151;
                margin-bottom: 8px;
                font-size: 14px;
            }
            
            .form-input {
                width: 100%;
                padding: 14px 16px;
                border: 2px solid #e5e7eb;
                border-radius: 12px;
                font-size: 16px;
                transition: all 0.3s ease;
            }
            
            .form-input:focus {
                outline: none;
                border-color: #4f46e5;
                box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.1);
            }
            
            .btn {
                width: 100%;
                padding: 14px;
                border: none;
                border-radius: 12px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s ease;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 8px;
            }
            
            .btn-primary {
                background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
                color: white;
            }
            
            .btn-primary:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 20px rgba(79, 70, 229, 0.3);
            }
            
            .btn-secondary {
                background: #10b981;
                color: white;
            }
            
            .btn-secondary:hover {
                background: #059669;
                transform: translateY(-2px);
            }
            
            .login-footer {
                text-align: center;
                margin-top: 25px;
                padding-top: 25px;
                border-top: 1px solid #e5e7eb;
            }
            
            .login-footer p {
                color: #6b7280;
                margin-bottom: 15px;
            }
            
            .alert {
                display: flex;
                align-items: center;
                gap: 12px;
                padding: 16px;
                border-radius: 12px;
                margin-bottom: 20px;
                font-size: 14px;
            }
            
            .alert-error {
                background: #fef2f2;
                border: 1px solid #fecaca;
                color: #dc2626;
            }
            
            .alert-success {
                background: #f0fdf4;
                border: 1px solid #bbf7d0;
                color: #16a34a;
            }
            
            .alert-info {
                background: #f0f9ff;
                border: 1px solid #bae6fd;
                color: #0369a1;
            }
            
            .alert-icon {
                font-size: 18px;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <div class="login-header">
                <h1>🔐 Welcome Back</h1>
                <p>Sign in to your secure cloud storage</p>
            </div>
            
            <div class="login-body">
                <div class="demo-accounts">
                    <h3>👥 Demo Accounts</h3>
                    <div class="account-list">
                        <div class="account-item">
                            <div class="account-info">
                                <span class="username">admin</span>
                                <span class="password">admin123</span>
                            </div>
                            <span class="role">Administrator</span>
                        </div>
                        <div class="account-item">
                            <div class="account-info">
                                <span class="username">demo</span>
                                <span class="password">demo123</span>
                            </div>
                            <span class="role">User</span>
                        </div>
                        <div class="account-item">
                            <div class="account-info">
                                <span class="username">test</span>
                                <span class="password">test123</span>
                            </div>
                            <span class="role">User</span>
                        </div>
                    </div>
                </div>
                
                ''' + get_flash_html() + '''
                
                <form method="POST">
                    <div class="form-group">
                        <label class="form-label">👤 Username</label>
                        <input type="text" name="username" class="form-input" placeholder="Enter your username" required>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">🔑 Password</label>
                        <input type="password" name="password" class="form-input" placeholder="Enter your password" required>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">
                        🚀 Sign In
                    </button>
                </form>
                
                <div class="login-footer">
                    <p>Don't have an account?</p>
                    <a href="/register" class="btn btn-secondary">
                        📝 Create New Account
                    </a>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        if len(username) < 3:
            add_flash_message('Username must be at least 3 characters', 'error')
            return redirect('/register')
            
        if len(password) < 6:
            add_flash_message('Password must be at least 6 characters', 'error')
            return redirect('/register')
        
        users = get_users()
        if username in users:
            add_flash_message('Username already exists', 'error')
            return redirect('/register')
        
        print(f"🔧 Creating new user: {username}")
        
        # СОЗДАЕМ НОВОГО ПОЛЬЗОВАТЕЛЯ
        users_db[username] = {
            'username': username, 
            'password': generate_password_hash(password),
            'created_at': datetime.now().isoformat(),
            'role': 'user'
        }
        
        # СОХРАНЯЕМ ВСЕХ ПОЛЬЗОВАТЕЛЕЙ
        if save_users():
            print(f"✅ User {username} saved successfully")
            
            # СОЗДАЕМ ХРАНИЛИЩЕ ФАЙЛОВ ДЛЯ НОВОГО ПОЛЬЗОВАТЕЛЯ
            user_files_db[username] = []
            if save_user_files(username):
                print(f"✅ Created file storage for {username}")
            
            # Автоматически входим
            session['user_id'] = username
            session['username'] = username
            add_flash_message(f'🎉 Registration successful! Welcome {username}', 'success')
            return redirect('/dashboard')
        else:
            add_flash_message('Registration failed - please try again', 'error')
            return redirect('/register')
    
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Register | Secure Cloud Storage</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }
            
            .register-container {
                background: white;
                border-radius: 20px;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                overflow: hidden;
                width: 100%;
                max-width: 440px;
            }
            
            .register-header {
                background: linear-gradient(135deg, #10b981 0%, #059669 100%);
                color: white;
                padding: 40px 30px;
                text-align: center;
            }
            
            .register-header h1 {
                font-size: 28px;
                font-weight: 700;
                margin-bottom: 8px;
            }
            
            .register-header p {
                opacity: 0.9;
                font-size: 16px;
            }
            
            .register-body {
                padding: 40px 30px;
            }
            
            .requirements {
                background: #fffbeb;
                border: 1px solid #fed7aa;
                border-radius: 12px;
                padding: 20px;
                margin-bottom: 25px;
            }
            
            .requirements h3 {
                color: #ea580c;
                font-size: 16px;
                margin-bottom: 12px;
                display: flex;
                align-items: center;
                gap: 8px;
            }
            
            .requirement-list {
                list-style: none;
            }
            
            .requirement-list li {
                padding: 6px 0;
                color: #92400e;
                display: flex;
                align-items: center;
                gap: 8px;
            }
            
            .form-group {
                margin-bottom: 20px;
            }
            
            .form-label {
                display: block;
                font-weight: 600;
                color: #374151;
                margin-bottom: 8px;
                font-size: 14px;
            }
            
            .form-input {
                width: 100%;
                padding: 14px 16px;
                border: 2px solid #e5e7eb;
                border-radius: 12px;
                font-size: 16px;
                transition: all 0.3s ease;
            }
            
            .form-input:focus {
                outline: none;
                border-color: #10b981;
                box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.1);
            }
            
            .btn {
                width: 100%;
                padding: 14px;
                border: none;
                border-radius: 12px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s ease;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 8px;
            }
            
            .btn-success {
                background: linear-gradient(135deg, #10b981 0%, #059669 100%);
                color: white;
            }
            
            .btn-success:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 20px rgba(16, 185, 129, 0.3);
            }
            
            .btn-secondary {
                background: #6b7280;
                color: white;
            }
            
            .btn-secondary:hover {
                background: #4b5563;
            }
            
            .register-footer {
                text-align: center;
                margin-top: 25px;
                padding-top: 25px;
                border-top: 1px solid #e5e7eb;
            }
            
            .alert {
                display: flex;
                align-items: center;
                gap: 12px;
                padding: 16px;
                border-radius: 12px;
                margin-bottom: 20px;
                font-size: 14px;
            }
            
            .alert-error {
                background: #fef2f2;
                border: 1px solid #fecaca;
                color: #dc2626;
            }
            
            .alert-success {
                background: #f0fdf4;
                border: 1px solid #bbf7d0;
                color: #16a34a;
            }
            
            .alert-info {
                background: #f0f9ff;
                border: 1px solid #bae6fd;
                color: #0369a1;
            }
            
            .alert-icon {
                font-size: 18px;
            }
        </style>
    </head>
    <body>
        <div class="register-container">
            <div class="register-header">
                <h1>📝 Join Us</h1>
                <p>Create your secure cloud storage account</p>
            </div>
            
            <div class="register-body">
                <div class="requirements">
                    <h3>📋 Account Requirements</h3>
                    <ul class="requirement-list">
                        <li>✅ Username: 3+ characters</li>
                        <li>✅ Password: 6+ characters</li>
                        <li>✅ Secure cloud storage</li>
                        <li>✅ End-to-end encryption</li>
                    </ul>
                </div>
                
                ''' + get_flash_html() + '''
                
                <form method="POST">
                    <div class="form-group">
                        <label class="form-label">👤 Choose Username</label>
                        <input type="text" name="username" class="form-input" placeholder="Enter username (3+ characters)" required>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">🔑 Create Password</label>
                        <input type="password" name="password" class="form-input" placeholder="Enter password (6+ characters)" required>
                    </div>
                    
                    <button type="submit" class="btn btn-success">
                        ✅ Create Account
                    </button>
                </form>
                
                <div class="register-footer">
                    <a href="/login" class="btn btn-secondary">
                        ← Back to Login
                    </a>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    
    user_id = session['user_id']
    user_files = get_user_files(user_id)
    
    # УБИРАЕМ ДУБЛИКАТЫ ФАЙЛОВ
    unique_files = []
    seen_ids = set()
    for file in user_files:
        if file['id'] not in seen_ids:
            unique_files.append(file)
            seen_ids.add(file['id'])
    
    # Если нашли дубликаты, сохраняем очищенный список
    if len(unique_files) != len(user_files):
        print(f"🧹 Removed {len(user_files) - len(unique_files)} duplicate files for {user_id}")
        user_files_db[user_id] = unique_files
        save_user_files(user_id)
        user_files = unique_files
    
    files_html = ""
    for file in user_files:
        file_icon = "📄"
        if any(ext in file['name'].lower() for ext in ['.jpg', '.png', '.gif', '.jpeg']):
            file_icon = "🖼️"
        elif any(ext in file['name'].lower() for ext in ['.pdf']):
            file_icon = "📕"
        elif any(ext in file['name'].lower() for ext in ['.doc', '.docx']):
            file_icon = "📝"
        elif any(ext in file['name'].lower() for ext in ['.zip', '.rar']):
            file_icon = "📦"
        
        files_html += f'''
        <div class="file-card">
            <div class="file-info">
                <div class="file-icon">{file_icon}</div>
                <div class="file-details">
                    <div class="file-name">{file.get('name', 'Unnamed')}</div>
                    <div class="file-meta">
                        <span class="file-size">📏 {file.get('size', 0)} KB</span>
                        <span class="file-date">📅 {file.get('date', 'Unknown')}</span>
                    </div>
                </div>
            </div>
            <div class="file-actions">
                <a href="/download/{file['id']}" class="btn-download">
                    ⬇️ Download
                </a>
                <a href="/delete/{file['id']}" onclick="return confirm('Are you sure you want to delete this file?')" class="btn-delete">
                    🗑️ Delete
                </a>
            </div>
        </div>
        '''
    
    if not files_html:
        files_html = '''
        <div class="empty-state">
            <div class="empty-icon">📁</div>
            <h3>No files yet</h3>
            <p>Upload your first file to get started with secure cloud storage</p>
        </div>
        '''
    
    user_info = users_db.get(user_id, {})
    user_role = user_info.get('role', 'user')
    
    return f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Dashboard | Secure Cloud Storage</title>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: #f8fafc;
                color: #334155;
            }}
            
            .navbar {{
                background: white;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                padding: 0 20px;
            }}
            
            .nav-content {{
                max-width: 1200px;
                margin: 0 auto;
                display: flex;
                justify-content: space-between;
                align-items: center;
                height: 70px;
            }}
            
            .nav-brand {{
                display: flex;
                align-items: center;
                gap: 12px;
                font-size: 24px;
                font-weight: 700;
                color: #4f46e5;
            }}
            
            .nav-user {{
                display: flex;
                align-items: center;
                gap: 15px;
            }}
            
            .user-info {{
                display: flex;
                align-items: center;
                gap: 8px;
                background: #f1f5f9;
                padding: 8px 16px;
                border-radius: 20px;
            }}
            
            .user-role {{
                background: #4f46e5;
                color: white;
                padding: 2px 8px;
                border-radius: 12px;
                font-size: 12px;
                font-weight: 600;
            }}
            
            .btn {{
                padding: 8px 16px;
                border: none;
                border-radius: 8px;
                font-weight: 600;
                text-decoration: none;
                cursor: pointer;
                transition: all 0.3s ease;
                display: inline-flex;
                align-items: center;
                gap: 6px;
            }}
            
            .btn-outline {{
                background: white;
                border: 2px solid #e2e8f0;
                color: #475569;
            }}
            
            .btn-outline:hover {{
                border-color: #4f46e5;
                color: #4f46e5;
            }}
            
            .btn-danger {{
                background: #dc2626;
                color: white;
            }}
            
            .btn-danger:hover {{
                background: #b91c1c;
            }}
            
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                padding: 30px 20px;
            }}
            
            .upload-section {{
                background: white;
                padding: 30px;
                border-radius: 16px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.05);
                margin-bottom: 30px;
                border: 2px dashed #e2e8f0;
            }}
            
            .upload-section:hover {{
                border-color: #4f46e5;
            }}
            
            .upload-title {{
                font-size: 20px;
                font-weight: 600;
                margin-bottom: 20px;
                color: #1e293b;
                display: flex;
                align-items: center;
                gap: 10px;
            }}
            
            .upload-form {{
                display: flex;
                gap: 15px;
                align-items: center;
            }}
            
            .file-input {{
                flex: 1;
                padding: 12px 16px;
                border: 2px solid #e2e8f0;
                border-radius: 12px;
                font-size: 16px;
                transition: all 0.3s ease;
            }}
            
            .file-input:focus {{
                outline: none;
                border-color: #4f46e5;
            }}
            
            .btn-primary {{
                background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
                color: white;
                padding: 12px 24px;
                border: none;
                border-radius: 12px;
                font-weight: 600;
            }}
            
            .btn-primary:hover {{
                transform: translateY(-2px);
                box-shadow: 0 8px 20px rgba(79, 70, 229, 0.3);
            }}
            
            .files-section {{
                background: white;
                padding: 30px;
                border-radius: 16px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.05);
            }}
            
            .section-title {{
                font-size: 20px;
                font-weight: 600;
                margin-bottom: 20px;
                color: #1e293b;
                display: flex;
                align-items: center;
                gap: 10px;
            }}
            
            .files-grid {{
                display: grid;
                gap: 15px;
            }}
            
            .file-card {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 20px;
                border: 1px solid #e2e8f0;
                border-radius: 12px;
                transition: all 0.3s ease;
            }}
            
            .file-card:hover {{
                border-color: #4f46e5;
                box-shadow: 0 4px 12px rgba(79, 70, 229, 0.1);
            }}
            
            .file-info {{
                display: flex;
                align-items: center;
                gap: 15px;
            }}
            
            .file-icon {{
                font-size: 24px;
            }}
            
            .file-details {{
                display: flex;
                flex-direction: column;
                gap: 4px;
            }}
            
            .file-name {{
                font-weight: 600;
                color: #1e293b;
            }}
            
            .file-meta {{
                display: flex;
                gap: 15px;
                font-size: 14px;
                color: #64748b;
            }}
            
            .file-actions {{
                display: flex;
                gap: 10px;
            }}
            
            .btn-download {{
                background: #10b981;
                color: white;
                padding: 8px 16px;
                border-radius: 8px;
                text-decoration: none;
                font-size: 14px;
                font-weight: 600;
            }}
            
            .btn-download:hover {{
                background: #059669;
            }}
            
            .btn-delete {{
                background: #ef4444;
                color: white;
                padding: 8px 16px;
                border-radius: 8px;
                text-decoration: none;
                font-size: 14px;
                font-weight: 600;
            }}
            
            .btn-delete:hover {{
                background: #dc2626;
            }}
            
            .empty-state {{
                text-align: center;
                padding: 60px 20px;
                color: #64748b;
            }}
            
            .empty-icon {{
                font-size: 64px;
                margin-bottom: 20px;
            }}
            
            .empty-state h3 {{
                font-size: 20px;
                margin-bottom: 10px;
                color: #475569;
            }}
            
            .alert {{
                display: flex;
                align-items: center;
                gap: 12px;
                padding: 16px;
                border-radius: 12px;
                margin-bottom: 20px;
                font-size: 14px;
            }}
            
            .alert-error {{
                background: #fef2f2;
                border: 1px solid #fecaca;
                color: #dc2626;
            }}
            
            .alert-success {{
                background: #f0fdf4;
                border: 1px solid #bbf7d0;
                color: #16a34a;
            }}
            
            .alert-info {{
                background: #f0f9ff;
                border: 1px solid #bae6fd;
                color: #0369a1;
            }}
            
            .alert-icon {{
                font-size: 18px;
            }}
            
            .stats {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }}
            
            .stat-card {{
                background: white;
                padding: 25px;
                border-radius: 12px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.05);
                text-align: center;
            }}
            
            .stat-number {{
                font-size: 32px;
                font-weight: 700;
                color: #4f46e5;
                margin-bottom: 8px;
            }}
            
            .stat-label {{
                color: #64748b;
                font-size: 14px;
                font-weight: 600;
            }}
        </style>
    </head>
    <body>
        <nav class="navbar">
            <div class="nav-content">
                <div class="nav-brand">
                    ☁️ Secure Cloud Storage
                </div>
                <div class="nav-user">
                    <div class="user-info">
                        👤 {session['username']}
                        <span class="user-role">{user_role}</span>
                    </div>
                    <a href="/debug" class="btn btn-outline">🔧 Debug</a>
                    <a href="/logout" class="btn btn-danger">🚪 Logout</a>
                </div>
            </div>
        </nav>
        
        <div class="container">
            {get_flash_html()}
            
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">{len(user_files)}</div>
                    <div class="stat-label">Total Files</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{sum(f.get('size', 0) for f in user_files)}</div>
                    <div class="stat-label">Total Size (KB)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(users_db)}</div>
                    <div class="stat-label">System Users</div>
                </div>
            </div>
            
            <div class="upload-section">
                <h2 class="upload-title">📤 Upload New File</h2>
                <form method="POST" action="/upload" enctype="multipart/form-data" class="upload-form">
                    <input type="file" name="file" class="file-input" required>
                    <button type="submit" class="btn btn-primary">
                        📎 Upload File
                    </button>
                </form>
            </div>
            
            <div class="files-section">
                <h2 class="section-title">📁 Your Files ({len(user_files)})</h2>
                <div class="files-grid">
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
    
    try:
        user_id = session['user_id']
        filename = secure_filename(file.filename)
        file_id = hashlib.md5(f"{user_id}_{filename}_{datetime.now()}".encode()).hexdigest()
        
        file_data = file.read()
        file_size = len(file_data)
        
        print(f"🔧 Uploading file: {filename} ({file_size} bytes) for user {user_id}")
        
        # Шифруем и загружаем в Cloudinary
        encrypted_data = encrypt_file(file_data)
        result = cloudinary.uploader.upload(
            encrypted_data,
            public_id=f"storage/{user_id}/{file_id}_{filename}",
            resource_type="raw",
            type="upload"
        )
        
        print(f"✅ File uploaded to Cloudinary: {result['secure_url']}")
        
        # Получаем текущие файлы и добавляем новый
        user_files = get_user_files(user_id)
        new_file = {
            'id': file_id,
            'name': filename,
            'size': round(file_size / 1024, 1),
            'url': result['secure_url'],
            'public_id': result['public_id'],
            'date': datetime.now().strftime("%Y-%m-%d %H:%M")
        }
        user_files.append(new_file)
        
        # СОХРАНЯЕМ ФАЙЛЫ ПОЛЬЗОВАТЕЛЯ
        user_files_db[user_id] = user_files
        if save_user_files(user_id):
            print(f"✅ File metadata saved for user {user_id}")
            add_flash_message(f'✅ File "{filename}" uploaded successfully!', 'success')
        else:
            print(f"❌ Failed to save file metadata for user {user_id}")
            add_flash_message(f'❌ Failed to save file info for "{filename}"', 'error')
        
    except Exception as e:
        print(f"❌ Upload error: {e}")
        add_flash_message(f'❌ Upload error: {str(e)}', 'error')
    
    return redirect('/dashboard')

@app.route('/download/<file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect('/login')
    
    user_id = session['user_id']
    user_files = get_user_files(user_id)
    
    file_data = next((f for f in user_files if f['id'] == file_id), None)
    if file_data:
        try:
            response = requests.get(file_data['url'])
            if response.status_code == 200:
                decrypted_data = decrypt_file(response.content)
                return send_file(
                    io.BytesIO(decrypted_data),
                    as_attachment=True,
                    download_name=file_data['name']
                )
            else:
                add_flash_message('File not found on server', 'error')
        except Exception as e:
            print(f"❌ Download error: {e}")
            add_flash_message('Download error', 'error')
    else:
        add_flash_message('File not found', 'error')
    
    return redirect('/dashboard')

@app.route('/delete/<file_id>')
def delete_file(file_id):
    if 'user_id' not in session:
        return redirect('/login')
    
    user_id = session['user_id']
    user_files = get_user_files(user_id)
    
    file_to_delete = next((f for f in user_files if f['id'] == file_id), None)
    if file_to_delete:
        try:
            # Удаляем файл из Cloudinary
            cloudinary.uploader.destroy(file_to_delete['public_id'], resource_type="raw")
            print(f"✅ Deleted file from Cloudinary: {file_to_delete['public_id']}")
        except Exception as e:
            print(f"⚠️ Could not delete from Cloudinary: {e}")
    
    # УДАЛЯЕМ ФАЙЛ ИЗ СПИСКА И СОХРАНЯЕМ ИЗМЕНЕНИЯ
    user_files = [f for f in user_files if f['id'] != file_id]
    user_files_db[user_id] = user_files
    
    # СОХРАНЯЕМ ИЗМЕНЕНИЯ
    if save_user_files(user_id):
        add_flash_message('File deleted successfully', 'success')
    else:
        add_flash_message('File deleted but failed to save changes', 'error')
    
    return redirect('/dashboard')

@app.route('/debug')
def debug_info():
    if 'user_id' not in session:
        return redirect('/login')
        
    users = get_users()
    user_files_count = {}
    
    for username in users.keys():
        files = get_user_files(username)
        user_files_count[username] = len(files)
    
    return f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Debug | Secure Cloud Storage</title>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: #f8fafc;
                color: #334155;
            }}
            
            .navbar {{
                background: white;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                padding: 0 20px;
            }}
            
            .nav-content {{
                max-width: 1200px;
                margin: 0 auto;
                display: flex;
                justify-content: space-between;
                align-items: center;
                height: 70px;
            }}
            
            .nav-brand {{
                display: flex;
                align-items: center;
                gap: 12px;
                font-size: 24px;
                font-weight: 700;
                color: #4f46e5;
            }}
            
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                padding: 30px 20px;
            }}
            
            .debug-section {{
                background: white;
                padding: 30px;
                border-radius: 16px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.05);
                margin-bottom: 20px;
            }}
            
            .section-title {{
                font-size: 20px;
                font-weight: 600;
                margin-bottom: 20px;
                color: #1e293b;
                display: flex;
                align-items: center;
                gap: 10px;
            }}
            
            .users-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
                gap: 15px;
                margin-top: 20px;
            }}
            
            .user-card {{
                background: #f8fafc;
                padding: 20px;
                border-radius: 12px;
                border-left: 4px solid #4f46e5;
            }}
            
            .user-name {{
                font-weight: 600;
                color: #1e293b;
                margin-bottom: 8px;
            }}
            
            .user-meta {{
                font-size: 14px;
                color: #64748b;
            }}
            
            .btn {{
                padding: 12px 20px;
                border: none;
                border-radius: 8px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s ease;
                text-decoration: none;
                display: inline-flex;
                align-items: center;
                gap: 6px;
            }}
            
            .btn-primary {{
                background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
                color: white;
            }}
            
            .btn-primary:hover {{
                transform: translateY(-2px);
                box-shadow: 0 8px 20px rgba(79, 70, 229, 0.3);
            }}
            
            .btn-secondary {{
                background: #6b7280;
                color: white;
            }}
            
            .btn-secondary:hover {{
                background: #4b5563;
            }}
        </style>
    </head>
    <body>
        <nav class="navbar">
            <div class="nav-content">
                <div class="nav-brand">
                    🔧 Debug Information
                </div>
                <div>
                    <a href="/dashboard" class="btn btn-secondary">← Back to Dashboard</a>
                </div>
            </div>
        </nav>
        
        <div class="container">
            <div class="debug-section">
                <h2 class="section-title">👥 Users in Database: {len(users)}</h2>
                <div class="users-grid">
                    {"".join(f'''
                    <div class="user-card">
                        <div class="user-name">{username}</div>
                        <div class="user-meta">
                            Files: {count}<br>
                            Role: {users[username].get('role', 'user')}
                        </div>
                    </div>
                    ''' for username, count in user_files_count.items())}
                </div>
            </div>
            
            <div class="debug-section">
                <h2 class="section-title">💾 Data Management</h2>
                <form method="POST" action="/force-save">
                    <button type="submit" class="btn btn-primary">
                        💾 Force Save All Data
                    </button>
                </form>
                <p style="margin-top: 10px; color: #666; font-size: 14px;">
                    Manually save all users and files to Cloudinary storage
                </p>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/force-save', methods=['POST'])
def force_save():
    """Принудительно сохраняет все данные"""
    if 'user_id' not in session:
        return redirect('/login')
    
    if save_all_data():
        add_flash_message('✅ All data saved successfully!', 'success')
    else:
        add_flash_message('⚠️ Some data may not have been saved completely', 'error')
    
    return redirect('/debug')

@app.route('/logout')
def logout():
    username = session.get('username', 'Unknown')
    session.clear()
    add_flash_message(f'Logged out from {username}', 'info')
    return redirect('/login')

if __name__ == '__main__':
    print("🚀 Starting Secure Cloud Storage...")
    print("✅ Cloudinary database configured!")
    
    # ИНИЦИАЛИЗИРУЕМ ВСЕ ДАННЫЕ ПРИ ЗАПУСКЕ
    initialize_databases()
    
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
