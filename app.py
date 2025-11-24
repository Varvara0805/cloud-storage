from flask import Flask, request, redirect, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import hashlib
from datetime import datetime
import sqlite3
import io
import atexit
import threading

app = Flask(__name__)
app.secret_key = 'super-secret-key-12345'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Создаем папку для загрузок
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Глобальные переменные для хранения данных в памяти
users_storage = {}
files_storage = {}
user_id_counter = 1
file_id_counter = 1

# Автосохранение в файл при перезапуске
def load_data():
    global users_storage, files_storage, user_id_counter, file_id_counter
    try:
        if os.path.exists('storage_backup.json'):
            import json
            with open('storage_backup.json', 'r') as f:
                data = json.load(f)
                users_storage = data.get('users', {})
                files_storage = data.get('files', {})
                user_id_counter = data.get('user_id_counter', 1)
                file_id_counter = data.get('file_id_counter', 1)
            print("✅ Данные восстановлены из бэкапа")
    except:
        print("⚠️ Не удалось загрузить бэкап, начинаем с чистого листа")

def save_data():
    try:
        import json
        data = {
            'users': users_storage,
            'files': files_storage,
            'user_id_counter': user_id_counter,
            'file_id_counter': file_id_counter
        }
        with open('storage_backup.json', 'w') as f:
            json.dump(data, f)
        print("💾 Данные сохранены в бэкап")
    except:
        print("❌ Ошибка сохранения бэкапа")

# Загружаем данные при старте
load_data()

# Сохраняем данные при остановке
atexit.register(save_data)

# Автосохранение каждые 5 минут
def auto_save():
    while True:
        threading.Event().wait(300)  # 5 минут
        save_data()

# Запускаем автосохранение в отдельном потоке
threading.Thread(target=auto_save, daemon=True).start()

def encrypt_file(file_data):
    """Простое XOR шифрование чтобы файлы не были plain text"""
    key = b'simple-encryption-key-123'
    encrypted = bytearray()
    for i, byte in enumerate(file_data):
        encrypted.append(byte ^ key[i % len(key)])
    return bytes(encrypted)

def decrypt_file(encrypted_data):
    """Дешифрование XOR"""
    return encrypt_file(encrypted_data)  # XOR обратим

def calculate_file_hash(file_data):
    return hashlib.sha256(file_data).hexdigest()

# Простая система сообщений
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
        
        # Ищем пользователя
        for uid, user_data in users_storage.items():
            if user_data['username'] == username and check_password_hash(user_data['password'], password):
                session['user_id'] = uid
                session['username'] = username
                add_flash_message('Login successful!', 'success')
                return redirect('/dashboard')
        
        add_flash_message('Invalid username or password', 'error')
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - Cloud Storage</title>
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
            <h2>🔐 Cloud Storage</h2>
            <div style="background: #e3f2fd; padding: 10px; border-radius: 5px; margin-bottom: 20px;">
                <strong>Demo account:</strong><br>
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
        global user_id_counter
        username = request.form['username']
        password = request.form['password']
        
        if len(password) < 6:
            add_flash_message('Password must be at least 6 characters', 'error')
            return redirect('/register')
        
        # Проверяем нет ли такого пользователя
        for user_data in users_storage.values():
            if user_data['username'] == username:
                add_flash_message('Username already exists', 'error')
                return redirect('/register')
        
        hashed_password = generate_password_hash(password)
        user_id = str(user_id_counter)
        user_id_counter += 1
        
        users_storage[user_id] = {
            'username': username,
            'password': hashed_password,
            'created_at': datetime.now().isoformat()
        }
        
        save_data()  # Сохраняем сразу
        add_flash_message('Registration successful! Please login.', 'success')
        return redirect('/login')
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Register - Cloud Storage</title>
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
    
    user_files = []
    for file_id, file_data in files_storage.items():
        if file_data['user_id'] == session['user_id']:
            user_files.append((file_id, file_data))
    
    # Сортируем по дате (новые сначала)
    user_files.sort(key=lambda x: x[1]['uploaded_at'], reverse=True)
    
    files_html = ""
    for file_id, file_data in user_files:
        size_kb = round(file_data['file_size'] / 1024, 2)
        
        files_html += f'''
        <div style="display: flex; justify-content: space-between; align-items: center; padding: 15px; border-bottom: 1px solid #eee;">
            <div>
                <strong>🔒 {file_data["original_filename"]}</strong>
                <br>
                <small>📏 {size_kb} KB | 📅 {file_data["uploaded_at"][:16]}</small>
            </div>
            <div>
                <a href="/download/{file_id}" style="padding: 8px 15px; background: #007bff; color: white; border-radius: 5px; text-decoration: none;">⬇️ Download</a>
                <a href="/delete/{file_id}" style="padding: 8px 15px; background: #dc3545; color: white; border-radius: 5px; text-decoration: none; margin-left: 10px;" onclick="return confirm('Delete this file?')">🗑️ Delete</a>
            </div>
        </div>
        '''
    
    if not files_html:
        files_html = '<p style="text-align: center; color: #666; padding: 40px;">No files uploaded yet.</p>'
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dashboard - Cloud Storage</title>
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
            <h2 style="margin: 0;">🔐 Cloud Storage</h2>
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
                <h3 style="margin-top: 0;">📁 Your Encrypted Files ({len(user_files)})</h3>
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
        global file_id_counter
        filename = secure_filename(file.filename)
        unique_filename = datetime.now().strftime("%Y%m%d_%H%M%S_") + filename
        
        file_data = file.read()
        file_size = len(file_data)
        
        file_hash = calculate_file_hash(file_data)
        encrypted_data = encrypt_file(file_data)
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)
        
        file_id = str(file_id_counter)
        file_id_counter += 1
        
        files_storage[file_id] = {
            'filename': unique_filename,
            'original_filename': filename,
            'user_id': session['user_id'],
            'uploaded_at': datetime.now().isoformat(),
            'file_size': file_size,
            'file_hash': file_hash
        }
        
        save_data()  # Сохраняем сразу
        add_flash_message(f'File "{filename}" encrypted and uploaded successfully!', 'success')
    
    return redirect('/dashboard')

@app.route('/download/<file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect('/login')
    
    file_data = files_storage.get(file_id)
    if file_data and file_data['user_id'] == session['user_id']:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_data['filename'])
        if os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            try:
                decrypted_data = decrypt_file(encrypted_data)
                return send_file(
                    io.BytesIO(decrypted_data),
                    as_attachment=True,
                    download_name=file_data['original_filename']
                )
            except Exception as e:
                add_flash_message('Error decrypting file', 'error')
    
    add_flash_message('File not found', 'error')
    return redirect('/dashboard')

@app.route('/delete/<file_id>')
def delete_file(file_id):
    if 'user_id' not in session:
        return redirect('/login')
    
    file_data = files_storage.get(file_id)
    if file_data and file_data['user_id'] == session['user_id']:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_data['filename'])
        if os.path.exists(file_path):
            os.remove(file_path)
        del files_storage[file_id]
        save_data()  # Сохраняем изменения
        add_flash_message('File deleted successfully!', 'success')
    else:
        add_flash_message('File not found', 'error')
    
    return redirect('/dashboard')

@app.route('/logout')
def logout():
    session.clear()
    add_flash_message('You have been logged out', 'info')
    return redirect('/login')

if __name__ == '__main__':
    # Создаем тестового пользователя если нет пользователей
    if not users_storage:
        users_storage['1'] = {
            'username': 'admin',
            'password': generate_password_hash('admin123'),
            'created_at': datetime.now().isoformat()
        }
        user_id_counter = 2
        save_data()
        print("✅ Test user created: admin / admin123")
    
    print("🚀 Cloud Storage started!")
    print("💾 Auto-save enabled - files will persist between restarts")
    app.run(host='0.0.0.0', port=5000)
