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

# 🔧 СИСТЕМА ХРАНЕНИЯ
def save_to_cloudinary(data, filename):
    """Сохраняет данные в Cloudinary"""
    try:
        json_str = json.dumps(data, ensure_ascii=False)
        result = cloudinary.uploader.upload(
            json_str.encode('utf-8'),
            public_id=f"storage/{filename}",
            resource_type="raw",
            type="upload"
        )
        print(f"✅ Saved: {filename}")
        return True
    except Exception as e:
        print(f"❌ Error saving {filename}: {e}")
        return False

def load_from_cloudinary(filename):
    """Загружает данные из Cloudinary"""
    try:
        url = cloudinary.utils.cloudinary_url(f"storage/{filename}", resource_type='raw')[0]
        response = requests.get(f"{url}?t={int(time.time())}", timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Loaded: {filename}")
            return data
    except Exception as e:
        print(f"❌ Error loading {filename}: {e}")
    return None

# 🔧 БАЗА ДАННЫХ
def get_users():
    """ВСЕГДА загружает свежих пользователей"""
    users = load_from_cloudinary("users")
    if not users:
        # СОЗДАЕМ ТЕСТОВЫХ ПОЛЬЗОВАТЕЛЕЙ
        users = {
            "admin": generate_password_hash("admin123"),
            "demo": generate_password_hash("demo123"),
            "test": generate_password_hash("test123")
        }
        save_to_cloudinary(users, "users")
        print("🔧 Created test users")
    return users

def save_users(users):
    """Сохраняет пользователей"""
    return save_to_cloudinary(users, "users")

def get_user_files(username):
    """Получает файлы пользователя"""
    return load_from_cloudinary(f"files_{username}") or []

def save_user_files(username, files):
    """Сохраняет файлы пользователя"""
    return save_to_cloudinary(files, f"files_{username}")

# 🔧 СООБЩЕНИЯ
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
        
        # ВСЕГДА ЗАГРУЖАЕМ СВЕЖИХ ПОЛЬЗОВАТЕЛЕЙ
        users = get_users()
        print(f"🔍 Login: {username}")
        print(f"🔍 Users: {list(users.keys())}")
        
        if username in users:
            if check_password_hash(users[username], password):
                session['user_id'] = username
                session['username'] = username
                add_message('Login successful!', 'success')
                return redirect('/dashboard')
            else:
                add_message('Wrong password', 'error')
        else:
            add_message('User not found', 'error')
    
    return '''
    <html>
    <head><title>Login</title></head>
    <body style="font-family: Arial; margin: 50px;">
        <h2>Login</h2>
        <div style="background: #f0f0f0; padding: 15px; margin: 20px 0;">
            <strong>Test Accounts:</strong><br>
            admin / admin123<br>
            demo / demo123<br>
            test / test123
        </div>
        ''' + get_messages() + '''
        <form method="POST" style="max-width: 300px;">
            <input type="text" name="username" placeholder="Username" required style="width: 100%; padding: 8px; margin: 5px 0;"><br>
            <input type="password" name="password" placeholder="Password" required style="width: 100%; padding: 8px; margin: 5px 0;"><br>
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
            add_message('Username too short', 'error')
            return redirect('/register')
        
        if len(password) < 6:
            add_message('Password too short', 'error')
            return redirect('/register')
        
        # ЗАГРУЖАЕМ СВЕЖИХ ПОЛЬЗОВАТЕЛЕЙ
        users = get_users()
        print(f"🔍 Register: {username}")
        print(f"🔍 Current users: {list(users.keys())}")
        
        if username in users:
            add_message('Username exists', 'error')
            return redirect('/register')
        
        # ДОБАВЛЯЕМ НОВОГО ПОЛЬЗОВАТЕЛЯ
        users[username] = generate_password_hash(password)
        print(f"💾 New users: {list(users.keys())}")
        
        # СОХРАНЯЕМ И ПЕРЕЗАГРУЖАЕМ
        if save_users(users):
            print(f"✅ User {username} saved")
            
            # ПЕРЕЗАГРУЖАЕМ ДАННЫЕ
            users = get_users()
            print(f"🔄 Reloaded users: {list(users.keys())}")
            
            # ПРОВЕРЯЕМ ЧТО ПОЛЬЗОВАТЕЛЬ СОХРАНИЛСЯ
            if username in users:
                session['user_id'] = username
                session['username'] = username
                add_message('Registration successful!', 'success')
                return redirect('/dashboard')
            else:
                add_message('User not saved properly', 'error')
        else:
            add_message('Registration failed', 'error')
    
    return '''
    <html>
    <head><title>Register</title></head>
    <body style="font-family: Arial; margin: 50px;">
        <h2>Register</h2>
        ''' + get_messages() + '''
        <form method="POST" style="max-width: 300px;">
            <input type="text" name="username" placeholder="Username (3+ chars)" required style="width: 100%; padding: 8px; margin: 5px 0;"><br>
            <input type="password" name="password" placeholder="Password (6+ chars)" required style="width: 100%; padding: 8px; margin: 5px 0;"><br>
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
    
    user_files = get_user_files(session['user_id'])
    
    files_html = ""
    for file in user_files:
        files_html += f'''
        <div style="border: 1px solid #ccc; padding: 10px; margin: 5px 0;">
            <strong>{file['name']}</strong> ({file['size']} KB)
            <div>
                <a href="/download/{file['id']}">Download</a>
                <a href="/delete/{file['id']}" style="margin-left: 10px; color: red;" onclick="return confirm('Delete?')">Delete</a>
            </div>
        </div>
        '''
    
    if not files_html:
        files_html = '<p>No files yet</p>'
    
    return f'''
    <html>
    <head><title>Dashboard</title></head>
    <body style="font-family: Arial; margin: 20px;">
        <h2>Welcome, {session['username']}!</h2>
        ''' + get_messages() + '''
        <a href="/logout">Logout</a>
        
        <h3>Upload File</h3>
        <form method="POST" action="/upload" enctype="multipart/form-data">
            <input type="file" name="file" required>
            <button type="submit">Upload</button>
        </form>
        
        <h3>Your Files ({len(user_files)})</h3>
        {files_html}
    </body>
    </html>
    '''

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect('/login')
    
    file = request.files['file']
    if file and file.filename:
        user_id = session['user_id']
        filename = secure_filename(file.filename)
        file_id = hashlib.md5(f"{user_id}_{filename}_{datetime.now()}".encode()).hexdigest()
        
        file_data = file.read()
        
        # Сохраняем файл в Cloudinary
        result = cloudinary.uploader.upload(
            file_data,
            public_id=f"user_files/{user_id}/{file_id}",
            resource_type="raw"
        )
        
        # Сохраняем метаданные
        user_files = get_user_files(user_id)
        user_files.append({
            'id': file_id,
            'name': filename,
            'size': round(len(file_data) / 1024, 1),
            'url': result['secure_url'],
            'public_id': result['public_id'],
            'date': datetime.now().strftime("%Y-%m-%d %H:%M")
        })
        
        if save_user_files(user_id, user_files):
            add_message('File uploaded!', 'success')
    
    return redirect('/dashboard')

@app.route('/download/<file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect('/login')
    
    user_files = get_user_files(session['user_id'])
    file_data = next((f for f in user_files if f['id'] == file_id), None)
    
    if file_data:
        response = requests.get(file_data['url'])
        return send_file(
            io.BytesIO(response.content),
            as_attachment=True,
            download_name=file_data['name']
        )
    
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
        cloudinary.uploader.destroy(file_to_delete['public_id'], resource_type="raw")
        user_files = [f for f in user_files if f['id'] != file_id]
        save_user_files(user_id, user_files)
        add_message('File deleted', 'success')
    
    return redirect('/dashboard')

@app.route('/debug')
def debug():
    users = get_users()
    return f'''
    <html>
    <head><title>Debug</title></head>
    <body style="font-family: Arial; margin: 20px;">
        <h2>Debug</h2>
        <p>Users: {list(users.keys())}</p>
        <a href="/dashboard">Back</a>
    </body>
    </html>
    '''

@app.route('/logout')
def logout():
    session.clear()
    add_message('Logged out', 'info')
    return redirect('/login')

if __name__ == '__main__':
    print("🚀 Starting Cloud Storage...")
    # Инициализируем базу при запуске
    users = get_users()
    print(f"👥 Users: {list(users.keys())}")
    app.run(host='0.0.0.0', port=5000, debug=True)
