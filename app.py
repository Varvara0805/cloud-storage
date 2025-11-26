from flask import Flask, request, redirect, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
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

# 🔧 ПРОСТАЯ СИСТЕМА ХРАНЕНИЯ В CLOUDINARY
def save_data(data, path):
    """Сохраняет данные в Cloudinary"""
    try:
        json_str = json.dumps(data, ensure_ascii=False)
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

def load_data(path):
    """Загружает данные из Cloudinary"""
    try:
        url = cloudinary.utils.cloudinary_url(
            f"storage/{path}",
            resource_type='raw',
            type='upload'
        )[0]
        
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

# 🔧 ИНИЦИАЛИЗАЦИЯ БАЗЫ ДАННЫХ
def init_database():
    """Создает тестовых пользователей если их нет"""
    users = load_data("users")
    
    if not users:
        print("🔧 Creating test users...")
        users = {
            "admin": {
                "username": "admin", 
                "password": generate_password_hash("admin123"),
                "created_at": datetime.now().isoformat()
            },
            "demo": {
                "username": "demo", 
                "password": generate_password_hash("demo123"), 
                "created_at": datetime.now().isoformat()
            },
            "test": {
                "username": "test", 
                "password": generate_password_hash("test123"),
                "created_at": datetime.now().isoformat()
            }
        }
        if save_data(users, "users"):
            print("✅ Test users created: admin, demo, test")
        else:
            print("❌ Failed to create test users")
    
    return users

def get_users():
    """Всегда загружает свежие данные пользователей"""
    return load_data("users") or {}

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
        
        users = get_users()
        print(f"🔍 Login attempt: {username}")
        print(f"🔍 Available users: {list(users.keys())}")
        
        if username in users:
            print(f"🔍 User found: {username}")
            if check_password_hash(users[username]['password'], password):
                session['user_id'] = username
                session['username'] = username
                add_message('Login successful!', 'success')
                return redirect('/dashboard')
            else:
                add_message('Invalid password', 'error')
        else:
            add_message('User not found', 'error')
    
    return '''
    <html>
    <head><title>Login</title></head>
    <body style="font-family: Arial; margin: 50px;">
        <h2>🔐 Login</h2>
        <div style="background: #f0f0f0; padding: 15px; margin: 20px 0;">
            <strong>Test Accounts:</strong><br>
            admin / admin123<br>
            demo / demo123<br>
            test / test123
        </div>
        ''' + get_messages() + '''
        <form method="POST" style="max-width: 300px;">
            <div style="margin: 10px 0;">
                <input type="text" name="username" placeholder="Username" required style="width: 100%; padding: 8px;">
            </div>
            <div style="margin: 10px 0;">
                <input type="password" name="password" placeholder="Password" required style="width: 100%; padding: 8px;">
            </div>
            <button type="submit" style="width: 100%; padding: 10px; background: blue; color: white; border: none;">Login</button>
        </form>
        <p><a href="/register">Create new account</a></p>
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
        
        # ЗАГРУЖАЕМ СВЕЖИЕ ДАННЫЕ
        users = get_users()
        print(f"🔍 Checking username: {username}")
        print(f"🔍 Current users: {list(users.keys())}")
        
        if username in users:
            add_message('Username already exists', 'error')
            return redirect('/register')
        
        print(f"🔧 Creating new user: {username}")
        
        # ДОБАВЛЯЕМ НОВОГО ПОЛЬЗОВАТЕЛЯ
        users[username] = {
            'username': username,
            'password': generate_password_hash(password),
            'created_at': datetime.now().isoformat()
        }
        
        print(f"💾 Saving users: {list(users.keys())}")
        
        # СОХРАНЯЕМ ОБНОВЛЕННЫЙ СПИСОК
        if save_data(users, "users"):
            print(f"✅ User {username} saved successfully")
            
            # СОЗДАЕМ ПУСТОЙ СПИСОК ФАЙЛОВ ДЛЯ НОВОГО ПОЛЬЗОВАТЕЛЯ
            if save_data([], f"files_{username}"):
                print(f"✅ Created file storage for {username}")
            
            # ВХОДИМ В СИСТЕМУ
            session['user_id'] = username
            session['username'] = username
            add_message(f'Registration successful! Welcome {username}', 'success')
            return redirect('/dashboard')
        else:
            add_message('Registration failed - could not save user', 'error')
            return redirect('/register')
    
    return '''
    <html>
    <head><title>Register</title></head>
    <body style="font-family: Arial; margin: 50px;">
        <h2>📝 Register</h2>
        ''' + get_messages() + '''
        <form method="POST" style="max-width: 300px;">
            <div style="margin: 10px 0;">
                <input type="text" name="username" placeholder="Username (3+ chars)" required style="width: 100%; padding: 8px;">
            </div>
            <div style="margin: 10px 0;">
                <input type="password" name="password" placeholder="Password (6+ chars)" required style="width: 100%; padding: 8px;">
            </div>
            <button type="submit" style="width: 100%; padding: 10px; background: green; color: white; border: none;">Register</button>
        </form>
        <p><a href="/login">Back to login</a></p>
    </body>
    </html>
    '''

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    
    user_id = session['user_id']
    user_files = load_data(f"files_{user_id}")
    
    print(f"📁 Loading files for user: {user_id}")
    print(f"📁 Files data: {user_files}")
    
    if user_files is None:
        user_files = []
        print("📁 No files found, creating empty list")
    
    files_html = ""
    for file in user_files:
        files_html += f'''
        <div style="border: 1px solid #ccc; padding: 10px; margin: 5px 0;">
            <strong>📄 {file['name']}</strong> ({file['size']} KB) - {file['date']}
            <div style="margin-top: 5px;">
                <a href="/download/{file['id']}" style="color: green; text-decoration: none; padding: 5px 10px; background: #e8f5e8; border-radius: 3px;">⬇️ Download</a>
                <a href="/delete/{file['id']}" style="color: red; text-decoration: none; padding: 5px 10px; background: #f5e8e8; border-radius: 3px; margin-left: 10px;" onclick="return confirm('Delete this file?')">🗑️ Delete</a>
            </div>
        </div>
        '''
    
    if not files_html:
        files_html = '<div style="text-align: center; padding: 40px; color: #666;">📁 No files yet. Upload your first file!</div>'
    
    return f'''
    <html>
    <head><title>Dashboard</title></head>
    <body style="font-family: Arial; margin: 0; padding: 0; background: #f5f5f5;">
        <div style="background: white; padding: 20px; border-bottom: 1px solid #ddd;">
            <div style="display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto;">
                <h2 style="margin: 0;">☁️ Cloud Storage</h2>
                <div>
                    <span>Welcome, <strong>{session['username']}</strong></span>
                    <a href="/debug" style="margin-left: 15px; color: #666; text-decoration: none;">🔧 Debug</a>
                    <a href="/logout" style="margin-left: 15px; color: #666; text-decoration: none;">🚪 Logout</a>
                </div>
            </div>
        </div>
        
        <div style="max-width: 1200px; margin: 20px auto; padding: 0 20px;">
            ''' + get_messages() + '''
            
            <div style="background: white; padding: 25px; margin: 20px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <h3 style="margin-top: 0;">📤 Upload File</h3>
                <form method="POST" action="/upload" enctype="multipart/form-data" style="display: flex; gap: 10px; align-items: center;">
                    <input type="file" name="file" required style="flex: 1; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                    <button type="submit" style="padding: 8px 20px; background: #4CAF50; color: white; border: none; border-radius: 4px; cursor: pointer;">📎 Upload</button>
                </form>
            </div>
            
            <div style="background: white; padding: 25px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <h3 style="margin-top: 0;">📁 Your Files ({len(user_files)})</h3>
                {files_html}
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
        
        # Сохраняем файл в Cloudinary
        result = cloudinary.uploader.upload(
            file_data,
            public_id=f"user_files/{user_id}/{file_id}_{filename}",
            resource_type="raw",
            type="upload"
        )
        
        print(f"✅ File uploaded to Cloudinary: {result['secure_url']}")
        
        # Загружаем текущие файлы пользователя
        user_files = load_data(f"files_{user_id}")
        if user_files is None:
            user_files = []
        
        # Добавляем новый файл
        new_file = {
            'id': file_id,
            'name': filename,
            'size': round(file_size / 1024, 1),
            'url': result['secure_url'],
            'public_id': result['public_id'],
            'date': datetime.now().strftime("%Y-%m-%d %H:%M")
        }
        user_files.append(new_file)
        
        print(f"💾 Saving file list for {user_id}: {len(user_files)} files")
        
        # Сохраняем обновленный список файлов
        if save_data(user_files, f"files_{user_id}"):
            print(f"✅ File metadata saved for user {user_id}")
            add_message(f'✅ File "{filename}" uploaded successfully!', 'success')
        else:
            print(f"❌ Failed to save file metadata for user {user_id}")
            add_message(f'❌ Failed to save file info', 'error')
        
    except Exception as e:
        print(f"❌ Upload error: {e}")
        add_message(f'Upload error: {str(e)}', 'error')
    
    return redirect('/dashboard')

@app.route('/download/<file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect('/login')
    
    user_id = session['user_id']
    user_files = load_data(f"files_{user_id}") or []
    
    file_data = next((f for f in user_files if f['id'] == file_id), None)
    if file_data:
        try:
            response = requests.get(file_data['url'])
            if response.status_code == 200:
                return send_file(
                    io.BytesIO(response.content),
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
    user_files = load_data(f"files_{user_id}") or []
    
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
        if save_data(user_files, f"files_{user_id}"):
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
    user_files_count = {}
    
    for username in users.keys():
        files = load_data(f"files_{username}") or []
        user_files_count[username] = len(files)
    
    debug_html = ""
    for username, count in user_files_count.items():
        debug_html += f'<div style="padding: 10px; border: 1px solid #ccc; margin: 5px 0;">{username}: {count} files</div>'
    
    return f'''
    <html>
    <head><title>Debug</title></head>
    <body style="font-family: Arial; margin: 20px;">
        <h2>🔧 Debug Info</h2>
        <a href="/dashboard" style="color: blue; text-decoration: none;">← Back to Dashboard</a>
        
        <div style="margin: 20px 0;">
            <h3>Users: {len(users)}</h3>
            {debug_html}
        </div>
        
        <form method="POST" action="/save_all">
            <button type="submit" style="padding: 10px 20px; background: #4CAF50; color: white; border: none; border-radius: 4px; cursor: pointer;">
                💾 Save All Data
            </button>
        </form>
    </body>
    </html>
    '''

@app.route('/save_all', methods=['POST'])
def save_all():
    users = get_users()
    if save_data(users, "users"):
        add_message('All users saved!', 'success')
    
    # Сохраняем файлы всех пользователей
    for username in users.keys():
        files = load_data(f"files_{username}") or []
        save_data(files, f"files_{username}")
    
    return redirect('/debug')

@app.route('/logout')
def logout():
    username = session.get('username', 'Unknown')
    session.clear()
    add_message(f'Logged out from {username}', 'info')
    return redirect('/login')

if __name__ == '__main__':
    print("🚀 Starting Cloud Storage...")
    print("✅ Cloudinary configured!")
    
    # Инициализируем базу данных
    users = init_database()
    print(f"👥 Loaded {len(users)} users: {list(users.keys())}")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
