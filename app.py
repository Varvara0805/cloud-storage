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

# 🔧 ПРОСТАЯ БАЗА ДАННЫХ В ПАМЯТИ (для тестирования)
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

# 🔧 БАЗА ДАННЫХ - СИНХРОНИЗАЦИЯ ПАМЯТИ И CLOUDINARY
def get_users():
    """Получает всех пользователей"""
    global users_db
    
    # Пробуем загрузить из Cloudinary
    cloud_users = load_from_cloudinary("users")
    if cloud_users:
        users_db.update(cloud_users)
        print(f"👥 Synced users from Cloudinary: {list(users_db.keys())}")
    
    # Если нет пользователей - создаем admin
    if not users_db:
        users_db = {"admin": {"username": "admin", "password": generate_password_hash("admin123")}}
        save_to_cloudinary(users_db, "users")
        print("🔧 Created default admin user")
    
    return users_db

def save_users(users):
    """Сохраняет пользователей"""
    global users_db
    users_db = users
    return save_to_cloudinary(users, "users")

def get_user_files(user_id):
    """Получает файлы пользователя"""
    global user_files_db
    
    # Загружаем из Cloudinary
    cloud_files = load_from_cloudinary(f"files_{user_id}")
    if cloud_files is not None:
        user_files_db[user_id] = cloud_files
        print(f"📁 Synced files for {user_id}: {len(cloud_files)} files")
    
    return user_files_db.get(user_id, [])

def save_user_files(user_id, files):
    """Сохраняет файлы пользователя"""
    global user_files_db
    user_files_db[user_id] = files
    return save_to_cloudinary(files, f"files_{user_id}")

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
        users = get_users()
        
        print(f"🔍 Login attempt: {username}")
        print(f"🔍 Available users: {list(users.keys())}")
        
        user = users.get(username)
        if user and check_password_hash(user['password'], password):
            session['user_id'] = username
            session['username'] = username
            add_flash_message('Login successful!', 'success')
            return redirect('/dashboard')
        else:
            add_flash_message('Invalid username or password', 'error')
    
    return '''
    <html><body style="margin: 0; font-family: 'Arial', sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh;">
        <div style="display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 20px;">
            <div style="max-width: 400px; width: 100%; background: white; padding: 40px; border-radius: 15px; box-shadow: 0 20px 40px rgba(0,0,0,0.1);">
                <div style="text-align: center; margin-bottom: 30px;">
                    <div style="font-size: 48px; margin-bottom: 10px;">☁️</div>
                    <h2 style="margin: 0; color: #333; font-weight: 600;">CloudSafe Storage</h2>
                    <p style="color: #666; margin: 5px 0 0 0;">Secure your files in the cloud</p>
                </div>
                
                <div style="background: #e3f2fd; padding: 15px; border-radius: 10px; margin-bottom: 25px;">
                    <div style="display: flex; align-items: center; margin-bottom: 8px;">
                        <span style="font-size: 20px; margin-right: 10px;">🔐</span>
                        <strong style="color: #1976d2;">Demo Account</strong>
                    </div>
                    <div style="color: #555; font-size: 14px;">
                        <div>👤 <strong>Username:</strong> <code>admin</code></div>
                        <div>🔑 <strong>Password:</strong> <code>admin123</code></div>
                    </div>
                </div>
                
                ''' + get_flash_html() + '''
                
                <form method="POST">
                    <div style="margin-bottom: 20px;">
                        <label style="display: block; margin-bottom: 8px; font-weight: 600; color: #333;">👤 Username</label>
                        <input type="text" name="username" placeholder="Enter your username" required 
                               style="width: 100%; padding: 14px; border: 2px solid #e1e5e9; border-radius: 10px; font-size: 16px; transition: border-color 0.3s;"
                               onfocus="this.style.borderColor='#007bff'" onblur="this.style.borderColor='#e1e5e9'">
                    </div>
                    <div style="margin-bottom: 25px;">
                        <label style="display: block; margin-bottom: 8px; font-weight: 600; color: #333;">🔑 Password</label>
                        <input type="password" name="password" placeholder="Enter your password" required 
                               style="width: 100%; padding: 14px; border: 2px solid #e1e5e9; border-radius: 10px; font-size: 16px; transition: border-color 0.3s;"
                               onfocus="this.style.borderColor='#007bff'" onblur="this.style.borderColor='#e1e5e9'">
                    </div>
                    <button type="submit" 
                            style="width: 100%; padding: 15px; background: linear-gradient(135deg, #007bff, #0056b3); color: white; border: none; border-radius: 10px; cursor: pointer; font-size: 16px; font-weight: 600; transition: transform 0.2s;"
                            onmouseover="this.style.transform='translateY(-2px)'" 
                            onmouseout="this.style.transform='translateY(0)'">
                        🚀 Sign In
                    </button>
                </form>
                
                <div style="text-align: center; margin-top: 30px; padding-top: 25px; border-top: 1px solid #eee;">
                    <p style="margin-bottom: 15px; color: #666;">Don't have an account?</p>
                    <a href="/register" 
                       style="display: block; padding: 12px; background: linear-gradient(135deg, #28a745, #1e7e34); color: white; border-radius: 10px; text-decoration: none; font-weight: 600; transition: transform 0.2s;"
                       onmouseover="this.style.transform='translateY(-2px)'" 
                       onmouseout="this.style.transform='translateY(0)'">
                       📝 Create New Account
                    </a>
                </div>
            </div>
        </div>
    </body></html>
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
        
        # ПРОСТОЕ СОХРАНЕНИЕ - без сложных проверок
        users[username] = {
            'username': username, 
            'password': generate_password_hash(password),
            'created_at': datetime.now().isoformat()
        }
        
        # Сохраняем пользователей
        if save_users(users):
            print(f"✅ User {username} saved successfully")
            
            # Создаем хранилище файлов
            save_user_files(username, [])
            
            # Автоматически входим
            session['user_id'] = username
            session['username'] = username
            add_flash_message(f'🎉 Registration successful! Welcome {username}', 'success')
            return redirect('/dashboard')
        else:
            add_flash_message('Registration failed - please try again', 'error')
            return redirect('/register')
    
    return '''
    <html><body style="margin: 0; font-family: 'Arial', sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh;">
        <div style="display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 20px;">
            <div style="max-width: 400px; width: 100%; background: white; padding: 40px; border-radius: 15px; box-shadow: 0 20px 40px rgba(0,0,0,0.1);">
                <div style="text-align: center; margin-bottom: 30px;">
                    <div style="font-size: 48px; margin-bottom: 10px;">✨</div>
                    <h2 style="margin: 0; color: #333; font-weight: 600;">Join CloudSafe</h2>
                    <p style="color: #666; margin: 5px 0 0 0;">Create your secure storage account</p>
                </div>
                
                <div style="background: #fff3cd; padding: 15px; border-radius: 10px; margin-bottom: 25px; border-left: 4px solid #ffc107;">
                    <div style="display: flex; align-items: center; margin-bottom: 8px;">
                        <span style="font-size: 20px; margin-right: 10px;">📋</span>
                        <strong style="color: #856404;">Account Requirements</strong>
                    </div>
                    <div style="color: #856404; font-size: 14px;">
                        <div>• Username: 3+ characters</div>
                        <div>• Password: 6+ characters</div>
                    </div>
                </div>
                
                ''' + get_flash_html() + '''
                
                <form method="POST">
                    <div style="margin-bottom: 20px;">
                        <label style="display: block; margin-bottom: 8px; font-weight: 600; color: #333;">👤 Choose Username</label>
                        <input type="text" name="username" placeholder="Enter username (3+ characters)" required 
                               style="width: 100%; padding: 14px; border: 2px solid #e1e5e9; border-radius: 10px; font-size: 16px; transition: border-color 0.3s;"
                               onfocus="this.style.borderColor='#28a745'" onblur="this.style.borderColor='#e1e5e9'">
                    </div>
                    <div style="margin-bottom: 25px;">
                        <label style="display: block; margin-bottom: 8px; font-weight: 600; color: #333;">🔑 Create Password</label>
                        <input type="password" name="password" placeholder="Enter password (6+ characters)" required 
                               style="width: 100%; padding: 14px; border: 2px solid #e1e5e9; border-radius: 10px; font-size: 16px; transition: border-color 0.3s;"
                               onfocus="this.style.borderColor='#28a745'" onblur="this.style.borderColor='#e1e5e9'">
                    </div>
                    <button type="submit" 
                            style="width: 100%; padding: 15px; background: linear-gradient(135deg, #28a745, #1e7e34); color: white; border: none; border-radius: 10px; cursor: pointer; font-size: 16px; font-weight: 600; transition: transform 0.2s;"
                            onmouseover="this.style.transform='translateY(-2px)'" 
                            onmouseout="this.style.transform='translateY(0)'">
                        ✅ Create Account
                    </button>
                </form>
                
                <div style="text-align: center; margin-top: 30px; padding-top: 25px; border-top: 1px solid #eee;">
                    <p style="margin-bottom: 15px; color: #666;">Already have an account?</p>
                    <a href="/login" 
                       style="display: block; padding: 12px; background: linear-gradient(135deg, #6c757d, #545b62); color: white; border-radius: 10px; text-decoration: none; font-weight: 600; transition: transform 0.2s;"
                       onmouseover="this.style.transform='translateY(-2px)'" 
                       onmouseout="this.style.transform='translateY(0)'">
                       ← Back to Login
                    </a>
                </div>
            </div>
        </div>
    </body></html>
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
        save_user_files(user_id, unique_files)
        user_files = unique_files
    
    files_html = ""
    for file in user_files:
        # Определяем иконку по типу файла
        file_icon = "📄"
        file_name = file.get('name', 'Unnamed').lower()
        if any(ext in file_name for ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp']):
            file_icon = "🖼️"
        elif any(ext in file_name for ext in ['.pdf']):
            file_icon = "📕"
        elif any(ext in file_name for ext in ['.doc', '.docx']):
            file_icon = "📝"
        elif any(ext in file_name for ext in ['.zip', '.rar', '.7z']):
            file_icon = "📦"
        elif any(ext in file_name for ext in ['.mp4', '.avi', '.mov']):
            file_icon = "🎬"
        elif any(ext in file_name for ext in ['.mp3', '.wav']):
            file_icon = "🎵"
        
        files_html += f'''
        <div style="display: flex; justify-content: space-between; align-items: center; padding: 20px; border-bottom: 1px solid #eee; transition: background-color 0.2s;" 
             onmouseover="this.style.backgroundColor='#f8f9fa'" 
             onmouseout="this.style.backgroundColor='white'">
            <div style="display: flex; align-items: center; gap: 15px;">
                <div style="font-size: 24px;">{file_icon}</div>
                <div>
                    <strong style="color: #333; font-size: 16px;">{file.get('name', 'Unnamed')}</strong><br>
                    <small style="color: #666;">Size: {file.get('size', 0)} KB • Uploaded: {file.get('date', 'Unknown')}</small>
                </div>
            </div>
            <div style="display: flex; gap: 10px;">
                <a href="/download/{file['id']}" 
                   style="padding: 10px 20px; background: linear-gradient(135deg, #007bff, #0056b3); color: white; border-radius: 8px; text-decoration: none; font-weight: 500; transition: transform 0.2s;"
                   onmouseover="this.style.transform='translateY(-2px)'" 
                   onmouseout="this.style.transform='translateY(0)'">
                   ⬇️ Download
                </a>
                <a href="/delete/{file['id']}" onclick="return confirm('Are you sure you want to delete this file?')"
                   style="padding: 10px 20px; background: linear-gradient(135deg, #dc3545, #c82333); color: white; border-radius: 8px; text-decoration: none; font-weight: 500; transition: transform 0.2s;"
                   onmouseover="this.style.transform='translateY(-2px)'" 
                   onmouseout="this.style.transform='translateY(0)'">
                   🗑️ Delete
                </a>
            </div>
        </div>
        '''
    
    if not files_html:
        files_html = '''
        <div style="text-align: center; padding: 60px 20px; color: #666;">
            <div style="font-size: 64px; margin-bottom: 20px;">📁</div>
            <h3 style="margin: 0 0 10px 0; color: #333;">No files yet</h3>
            <p style="margin: 0;">Upload your first file to get started!</p>
        </div>
        '''
    
    return f'''
    <html><body style="margin: 0; font-family: 'Arial', sans-serif; background: #f8f9fa; min-height: 100vh;">
        <!-- Header -->
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 25px 0; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
            <div style="max-width: 1200px; margin: 0 auto; padding: 0 20px; display: flex; justify-content: space-between; align-items: center;">
                <div style="display: flex; align-items: center; gap: 15px;">
                    <div style="font-size: 32px;">☁️</div>
                    <div>
                        <h1 style="margin: 0; font-size: 28px; font-weight: 700;">CloudSafe Storage</h1>
                        <p style="margin: 0; opacity: 0.9; font-size: 14px;">Secure cloud file storage</p>
                    </div>
                </div>
                <div style="display: flex; align-items: center; gap: 15px;">
                    <div style="background: rgba(255,255,255,0.2); padding: 8px 16px; border-radius: 20px; font-size: 14px;">
                        👋 Welcome, <strong>{session['username']}</strong>
                    </div>
                    <a href="/debug" 
                       style="padding: 10px 20px; background: rgba(255,255,255,0.2); color: white; border-radius: 8px; text-decoration: none; font-weight: 500; transition: background-color 0.2s;"
                       onmouseover="this.style.backgroundColor='rgba(255,255,255,0.3)'" 
                       onmouseout="this.style.backgroundColor='rgba(255,255,255,0.2)'">
                       🔧 Debug
                    </a>
                    <a href="/logout" 
                       style="padding: 10px 20px; background: rgba(255,255,255,0.2); color: white; border-radius: 8px; text-decoration: none; font-weight: 500; transition: background-color 0.2s;"
                       onmouseover="this.style.backgroundColor='rgba(255,255,255,0.3)'" 
                       onmouseout="this.style.backgroundColor='rgba(255,255,255,0.2)'">
                       🚪 Logout
                    </a>
                </div>
            </div>
        </div>
        
        <!-- Main Content -->
        <div style="max-width: 1200px; margin: 0 auto; padding: 40px 20px;">
            {get_flash_html()}
            
            <!-- Upload Section -->
            <div style="background: white; padding: 40px; border-radius: 15px; margin-bottom: 30px; box-shadow: 0 4px 12px rgba(0,0,0,0.05);">
                <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 25px;">
                    <div style="font-size: 32px; color: #28a745;">📤</div>
                    <div>
                        <h3 style="margin: 0; color: #333; font-size: 24px; font-weight: 600;">Upload New File</h3>
                        <p style="margin: 5px 0 0 0; color: #666;">Securely store your files in the cloud</p>
                    </div>
                </div>
                <form method="POST" action="/upload" enctype="multipart/form-data" 
                      style="display: flex; gap: 15px; align-items: center; background: #f8f9fa; padding: 25px; border-radius: 12px; border: 2px dashed #dee2e6;">
                    <div style="flex: 1;">
                        <input type="file" name="file" required 
                               style="width: 100%; padding: 12px; border: 2px solid #e1e5e9; border-radius: 8px; font-size: 16px; background: white;">
                    </div>
                    <button type="submit" 
                            style="padding: 12px 30px; background: linear-gradient(135deg, #28a745, #1e7e34); color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 16px; font-weight: 600; transition: transform 0.2s;"
                            onmouseover="this.style.transform='translateY(-2px)'" 
                            onmouseout="this.style.transform='translateY(0)'">
                        📎 Upload File
                    </button>
                </form>
            </div>
            
            <!-- Files Section -->
            <div style="background: white; padding: 40px; border-radius: 15px; box-shadow: 0 4px 12px rgba(0,0,0,0.05);">
                <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 25px;">
                    <div style="font-size: 32px; color: #007bff;">📁</div>
                    <div>
                        <h3 style="margin: 0; color: #333; font-size: 24px; font-weight: 600;">Your Files</h3>
                        <p style="margin: 5px 0 0 0; color: #666;">{len(user_files)} file(s) stored securely</p>
                    </div>
                </div>
                <div style="border: 1px solid #e9ecef; border-radius: 12px; overflow: hidden;">
                    {files_html}
                </div>
            </div>
        </div>
        
        <!-- Footer -->
        <div style="background: #343a40; color: white; padding: 30px 0; margin-top: 60px;">
            <div style="max-width: 1200px; margin: 0 auto; padding: 0 20px; text-align: center;">
                <div style="display: flex; justify-content: center; gap: 30px; margin-bottom: 20px;">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span style="font-size: 20px;">🔒</span>
                        <span>Encrypted Storage</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span style="font-size: 20px;">☁️</span>
                        <span>Cloud Backup</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span style="font-size: 20px;">⚡</span>
                        <span>Fast Access</span>
                    </div>
                </div>
                <p style="margin: 0; opacity: 0.7;">CloudSafe Storage &copy; 2024 - Your files are safe with us</p>
            </div>
        </div>
    </body></html>
    '''

# ... остальные маршруты (upload, download, delete, debug, logout) остаются без изменений

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
        
        encrypted_data = encrypt_file(file_data)
        result = cloudinary.uploader.upload(
            encrypted_data,
            public_id=f"storage/{user_id}/{file_id}_{filename}",
            resource_type="raw",
            type="upload"
        )
        
        print(f"✅ File uploaded to Cloudinary: {result['secure_url']}")
        
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
        
        if save_user_files(user_id, user_files):
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
            cloudinary.uploader.destroy(file_to_delete['public_id'], resource_type="raw")
            print(f"✅ Deleted file from Cloudinary: {file_to_delete['public_id']}")
        except Exception as e:
            print(f"⚠️ Could not delete from Cloudinary: {e}")
    
    user_files = [f for f in user_files if f['id'] != file_id]
    save_user_files(user_id, user_files)
    
    add_flash_message('File deleted successfully', 'success')
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
    <html><body style="margin: 0; font-family: 'Arial', sans-serif; background: #f8f9fa; min-height: 100vh;">
        <div style="background: white; padding: 20px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
            <h2 style="margin: 0;">🔧 Debug Information</h2>
            <div>
                <a href="/dashboard" style="background: #007bff; color: white; padding: 8px 15px; border-radius: 5px; text-decoration: none;">← Back to Dashboard</a>
            </div>
        </div>
        
        <div style="max-width: 1000px; margin: 20px auto; padding: 20px;">
            <div style="background: white; padding: 30px; border-radius: 10px; margin-bottom: 20px;">
                <h3 style="margin-top: 0;">👥 Users in Database: {len(users)}</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 15px; margin-top: 20px;">
                    {"".join(f'''
                    <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #007bff;">
                        <strong>{username}</strong><br>
                        <small>Files: {count}</small>
                    </div>
                    ''' for username, count in user_files_count.items())}
                </div>
            </div>
        </div>
    </body></html>
    '''

@app.route('/logout')
def logout():
    username = session.get('username', 'Unknown')
    session.clear()
    add_flash_message(f'Logged out from {username}', 'info')
    return redirect('/login')

if __name__ == '__main__':
    print("🚀 Starting Secure Cloud Storage...")
    print("✅ Cloudinary database configured!")
    
    # Инициализируем базу данных
    users = get_users()
    print(f"👥 Loaded {len(users)} users: {list(users.keys())}")
    
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
