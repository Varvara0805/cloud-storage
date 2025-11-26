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
app.secret_key = 'super-secret-key-12345'
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

# 🔧 СИСТЕМА ХРАНЕНИЯ В CLOUDINARY
def save_to_cloudinary(data, path):
    """Сохраняет данные в Cloudinary"""
    try:
        json_str = json.dumps(data, ensure_ascii=False, indent=2)
        result = cloudinary.uploader.upload(
            json_str.encode('utf-8'),
            public_id=f"storage/{path}",
            resource_type="raw",
            type="upload"
        )
        print(f"✅ Saved: {path}")
        return True
    except Exception as e:
        print(f"❌ Error saving {path}: {e}")
        return False

def load_from_cloudinary(path):
    """Загружает данные из Cloudinary"""
    try:
        url = cloudinary.utils.cloudinary_url(f"storage/{path}", resource_type='raw')[0]
        response = requests.get(f"{url}?t={int(time.time())}", timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Loaded: {path}")
            return data
        else:
            print(f"❌ Failed to load {path}: Status {response.status_code}")
    except Exception as e:
        print(f"❌ Error loading {path}: {e}")
    return None

# 🔧 БАЗА ДАННЫХ
def get_users():
    """Получает всех пользователей"""
    users = load_from_cloudinary("users")
    if not users:
        # СОЗДАЕМ ТЕСТОВЫХ ПОЛЬЗОВАТЕЛЕЙ - ПРОСТАЯ СТРУКТУРА
        users = {
            "admin": generate_password_hash("admin123"),
            "demo": generate_password_hash("demo123"),
            "test": generate_password_hash("test123")
        }
        save_to_cloudinary(users, "users")
        print("🔧 Created test users: admin, demo, test")
    return users

def save_users(users):
    """Сохраняет пользователей"""
    return save_to_cloudinary(users, "users")

def get_user_files(user_id):
    """Получает файлы пользователя"""
    files = load_from_cloudinary(f"files_{user_id}")
    if files is None:
        files = []
        print(f"📁 No files found for {user_id}, creating empty list")
    else:
        print(f"📁 Loaded {len(files)} files for {user_id}")
        for file in files:
            print(f"   - {file['name']} ({file['size']} KB)")
    return files

def save_user_files(user_id, files):
    """Сохраняет файлы пользователя"""
    print(f"💾 Saving {len(files)} files for {user_id}")
    return save_to_cloudinary(files, f"files_{user_id}")

# 🔧 ФУНКЦИИ ШИФРОВАНИЯ
def encrypt_file(file_data):
    return cipher_suite.encrypt(file_data)

def decrypt_file(encrypted_data):
    return cipher_suite.decrypt(encrypted_data)

# 🔧 СИСТЕМА СООБЩЕНИЙ
messages = []
def add_message(msg, type='info'):
    messages.append((type, msg))
def get_messages():
    global messages
    html = ''
    for type, msg in messages:
        color = 'red' if type == 'error' else 'green' if type == 'success' else 'blue'
        html += f'<div style="color: {color}; padding: 10px; margin: 10px 0; border: 1px solid {color}">{msg}</div>'
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
        
        # ЗАГРУЖАЕМ СВЕЖИХ ПОЛЬЗОВАТЕЛЕЙ
        users = get_users()
        print(f"🔍 Login attempt: {username}")
        print(f"🔍 Available users: {list(users.keys())}")
        print(f"🔍 Users data: {users}")
        
        if username in users:
            print(f"🔍 User {username} found, checking password...")
            if check_password_hash(users[username], password):
                session['user_id'] = username
                session['username'] = username
                add_message('Login successful!', 'success')
                return redirect('/dashboard')
            else:
                print(f"❌ Wrong password for {username}")
                add_message('Wrong password', 'error')
        else:
            print(f"❌ User {username} not found")
            add_message('User not found', 'error')
    
    return '''
    <html>
    <head><title>Login</title></head>
    <body style="font-family: Arial; margin: 50px;">
        <h2>🔐 Login</h2>
        <div style="background: #f0f0f0; padding: 15px; margin: 20px 0;">
            <strong>Test Accounts:</strong><br>
            👤 admin / admin123<br>
            👤 demo / demo123<br>
            👤 test / test123
        </div>
        ''' + get_messages() + '''
        <form method="POST" style="max-width: 300px;">
            <input type="text" name="username" placeholder="Username" required style="width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px;">
            <input type="password" name="password" placeholder="Password" required style="width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px;">
            <button type="submit" style="width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer;">🚀 Login</button>
        </form>
        <p style="text-align: center; margin-top: 20px;"><a href="/register">Create new account</a></p>
    </body>
    </html>
    '''

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        if len(username) < 3:
            add_message('Username must be at least 3 characters', 'error')
            return redirect('/register')
        
        if len(password) < 6:
            add_message('Password must be at least 6 characters', 'error')
            return redirect('/register')
        
        # ЗАГРУЖАЕМ СВЕЖИХ ПОЛЬЗОВАТЕЛЕЙ
        users = get_users()
        print(f"🔍 Register attempt: {username}")
        print(f"🔍 Current users: {list(users.keys())}")
        
        if username in users:
            add_message('Username already exists', 'error')
            return redirect('/register')
        
        print(f"🔧 Creating new user: {username}")
        
        # ДОБАВЛЯЕМ НОВОГО ПОЛЬЗОВАТЕЛЯ - ПРОСТАЯ СТРУКТУРА
        users[username] = generate_password_hash(password)
        
        print(f"💾 Saving users: {list(users.keys())}")
        
        # СОХРАНЯЕМ ПОЛЬЗОВАТЕЛЕЙ
        if save_users(users):
            print(f"✅ User {username} saved")
            
            # ДАЕМ ВРЕМЯ CLOUDINARY СОХРАНИТЬ
            time.sleep(2)
            
            # ПЕРЕЗАГРУЖАЕМ ДАННЫЕ ДЛЯ ПРОВЕРКИ
            users = load_from_cloudinary("users")
            print(f"🔄 Reloaded users: {list(users.keys())}")
            
            # ПРОВЕРЯЕМ ЧТО ПОЛЬЗОВАТЕЛЬ СОХРАНИЛСЯ
            if username in users:
                # СОЗДАЕМ ПУСТОЙ СПИСОК ФАЙЛОВ
                save_user_files(username, [])
                
                # АВТОМАТИЧЕСКИ ВХОДИМ
                session['user_id'] = username
                session['username'] = username
                add_message(f'🎉 Registration successful! Welcome {username}', 'success')
                return redirect('/dashboard')
            else:
                add_message('User not saved properly - please try logging in manually', 'error')
                return redirect('/login')
        else:
            add_message('Registration failed - could not save to Cloudinary', 'error')
    
    return '''
    <html>
    <head><title>Register</title></head>
    <body style="font-family: Arial; margin: 50px;">
        <h2>📝 Register</h2>
        ''' + get_messages() + '''
        <form method="POST" style="max-width: 300px;">
            <input type="text" name="username" placeholder="Username (3+ chars)" required style="width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px;">
            <input type="password" name="password" placeholder="Password (6+ chars)" required style="width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px;">
            <button type="submit" style="width: 100%; padding: 12px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer;">✅ Create Account</button>
        </form>
        <p style="text-align: center; margin-top: 20px;"><a href="/login">Back to login</a></p>
    </body>
    </html>
    '''

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    
    user_id = session['user_id']
    user_files = get_user_files(user_id)
    
    print(f"🎯 Rendering dashboard for {user_id} with {len(user_files)} files")
    
    files_html = ""
    for file in user_files:
        files_html += f'''
        <div style="display: flex; justify-content: space-between; align-items: center; padding: 15px; border-bottom: 1px solid #eee; background: white; margin: 5px 0; border-radius: 5px;">
            <div>
                <strong>📁 {file['name']}</strong><br>
                <small>Size: {file['size']} KB | Uploaded: {file['date']}</small>
            </div>
            <div>
                <a href="/download/{file['id']}" style="padding: 8px 15px; background: #007bff; color: white; border-radius: 5px; text-decoration: none; margin: 5px;">⬇️ Download</a>
                <a href="/delete/{file['id']}" onclick="return confirm('Delete this file?')" style="padding: 8px 15px; background: #dc3545; color: white; border-radius: 5px; text-decoration: none; margin: 5px;">🗑️ Delete</a>
            </div>
        </div>
        '''
    
    if not files_html:
        files_html = '''
        <div style="text-align: center; padding: 40px; color: #666; background: white; border-radius: 5px;">
            <div style="font-size: 48px; margin-bottom: 20px;">📁</div>
            <h3>No files yet</h3>
            <p>Upload your first file to get started!</p>
        </div>
        '''
    
    return f'''
    <html>
    <head><title>Dashboard</title></head>
    <body style="margin: 0; font-family: Arial; background: #f0f0f0;">
        <div style="background: white; padding: 20px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
            <h2 style="margin: 0;">☁️ Cloud Storage</h2>
            <div>
                Welcome, <strong>{session['username']}</strong>! 
                <a href="/logout" style="margin-left: 20px; background: #6c757d; color: white; padding: 8px 15px; border-radius: 5px; text-decoration: none;">Logout</a>
            </div>
        </div>
        
        <div style="max-width: 1000px; margin: 20px auto; padding: 20px;">
            ''' + get_messages() + '''
            
            <div style="background: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <h3 style="margin-top: 0;">📤 Upload File</h3>
                <form method="POST" action="/upload" enctype="multipart/form-data" style="display: flex; gap: 10px; align-items: center;">
                    <input type="file" name="file" required style="flex: 1; padding: 10px; border: 1px solid #ddd; border-radius: 5px;">
                    <button type="submit" style="padding: 10px 20px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer;">📎 Upload</button>
                </form>
            </div>
            
            <div style="background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <h3 style="margin-top: 0;">📁 Your Files ({len(user_files)})</h3>
                <div style="min-height: 100px;">
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
        add_message('No file selected', 'error')
        return redirect('/dashboard')
    
    file = request.files['file']
    if file.filename == '':
        add_message('No file selected', 'error')
        return redirect('/dashboard')
    
    try:
        user_id = session['user_id']
        filename = secure_filename(file.filename)
        file_id = hashlib.md5(f"{user_id}_{filename}_{datetime.now()}".encode()).hexdigest()
        
        file_data = file.read()
        file_size = len(file_data)
        
        print(f"📤 Uploading file: {filename} ({file_size} bytes) for user {user_id}")
        
        # Шифруем и загружаем в Cloudinary
        encrypted_data = encrypt_file(file_data)
        result = cloudinary.uploader.upload(
            encrypted_data,
            public_id=f"user_files/{user_id}/{file_id}_{filename}",
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
        
        # Сохраняем обновленный список
        if save_user_files(user_id, user_files):
            print(f"✅ File metadata saved for user {user_id}")
            add_message(f'✅ File "{filename}" uploaded successfully!', 'success')
        else:
            print(f"❌ Failed to save file metadata for user {user_id}")
            add_message(f'❌ Failed to save file info', 'error')
        
    except Exception as e:
        print(f"❌ Upload error: {e}")
        add_message(f'❌ Upload error: {str(e)}', 'error')
    
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
                add_message('File not found on server', 'error')
        except Exception as e:
            print(f"❌ Download error: {e}")
            add_message('Download error', 'error')
    else:
        add_message('File not found', 'error')
    
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
    
        # Удаляем из списка файлов
        user_files = [f for f in user_files if f['id'] != file_id]
        
        # Сохраняем обновленный список
        if save_user_files(user_id, user_files):
            add_message('File deleted successfully', 'success')
        else:
            add_message('File deleted but failed to save changes', 'error')
    else:
        add_message('File not found', 'error')
    
    return redirect('/dashboard')

@app.route('/debug')
def debug():
    if 'user_id' not in session:
        return redirect('/login')
    
    users = get_users()
    debug_html = ""
    for username in users.keys():
        files = get_user_files(username)
        debug_html += f'<div style="padding: 10px; border: 1px solid #ccc; margin: 5px 0;">{username}: {len(files)} files</div>'
    
    return f'''
    <html>
    <head><title>Debug</title></head>
    <body style="font-family: Arial; margin: 20px;">
        <h2>Debug Info</h2>
        <a href="/dashboard" style="color: blue; text-decoration: none;">← Back to Dashboard</a>
        <h3>Users: {len(users)}</h3>
        {debug_html}
    </body>
    </html>
    '''

@app.route('/logout')
def logout():
    username = session.get('username', 'Unknown')
    session.clear()
    add_message(f'Logged out from {username}', 'info')
    return redirect('/login')

if __name__ == '__main__':
    print("🚀 Starting Secure Cloud Storage...")
    print("✅ Cloudinary database configured!")
    
    # Инициализируем базу данных
    users = get_users()
    print(f"👥 Loaded {len(users)} users: {list(users.keys())}")
    
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
