from flask import Flask, request, redirect, session, send_file, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import os
import hashlib
from datetime import datetime, timedelta
import io
import cloudinary
import cloudinary.uploader
import cloudinary.api
import requests
import json
import base64

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
        print("⚠️  ВНИМАНИЕ: Сгенерирован новый ключ шифрования!")
    return key.encode()

ENCRYPTION_KEY = get_encryption_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

# 🔧 СОХРАНЕНИЕ СЕССИЙ В CLOUDINARY
def save_session(user_id, username):
    """Сохраняем сессию в Cloudinary"""
    session_data = {
        'user_id': user_id,
        'username': username,
        'created_at': datetime.now().isoformat()
    }
    session_id = hashlib.md5(f"{user_id}{datetime.now()}".encode()).hexdigest()
    
    # Сохраняем в Cloudinary
    upload_json(session_data, f'storage/sessions/{session_id}')
    
    # Возвращаем session_id для куки
    return session_id

def get_session(session_id):
    """Получаем сессию из Cloudinary"""
    if not session_id:
        return None
    return download_json(f'storage/sessions/{session_id}')

def delete_session(session_id):
    """Удаляем сессию"""
    if session_id:
        try:
            cloudinary.uploader.destroy(f'storage/sessions/{session_id}')
        except:
            pass

# 🔧 БАЗА ДАННЫХ В CLOUDINARY (остается без изменений)
admin123

def save_user(username, password_hash):
    """Сохраняем пользователя в Cloudinary"""
    user_data = {
        'username': username,
        'password': password_hash,
        'created_at': datetime.now().isoformat()
    }
    return upload_json(user_data, f'storage/users/{username}')

def get_user_files(user_id):
    """Получаем файлы пользователя из Cloudinary"""
    try:
        result = cloudinary.api.resources(
            type='upload',
            prefix=f'storage/files/{user_id}/',
            max_results=100
        )
        files = []
        for resource in result.get('resources', []):
            file_data = download_json(resource['public_id'])
            if file_data:
                files.append(file_data)
        return sorted(files, key=lambda x: x['uploaded_at'], reverse=True)
    except:
        return []

def save_file(file_data):
    """Сохраняем метаданные файла в Cloudinary"""
    return upload_json(file_data, f'storage/files/{file_data["user_id"]}/{file_data["file_id"]}')

def delete_file_data(user_id, file_id):
    """Удаляем метаданные файла"""
    try:
        cloudinary.uploader.destroy(f'storage/files/{user_id}/{file_id}')
        return True
    except:
        return False

# 🔧 ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
def upload_json(data, public_id):
    """Загружает JSON данные в Cloudinary"""
    try:
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            f.flush()
            result = cloudinary.uploader.upload(
                f.filename,
                public_id=public_id,
                resource_type='raw'
            )
        os.unlink(f.name)
        return result
    except Exception as e:
        print(f"Upload JSON error: {e}")
        return None

def download_json(public_id):
    """Скачивает JSON данные из Cloudinary"""
    try:
        url = cloudinary.utils.cloudinary_url(public_id, resource_type='raw')[0]
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
    except:
        return None

def encrypt_file(file_data):
    return cipher_suite.encrypt(file_data)

def decrypt_file(encrypted_data):
    return cipher_suite.decrypt(encrypted_data)

def calculate_file_hash(file_data):
    return hashlib.sha256(file_data).hexdigest()

# 🔧 СИСТЕМА СООБЩЕНИЙ
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

# 🔧 АВТОРИЗАЦИЯ ЧЕРЕЗ КУКИ
def get_current_user():
    """Получаем текущего пользователя из куки"""
    session_id = request.cookies.get('session_id')
    if session_id:
        session_data = get_session(session_id)
        if session_data:
            return session_data
    return None

def login_required(f):
    """Декоратор для проверки авторизации"""
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user:
            return redirect('/login')
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# 🎯 МАРШРУТЫ
@app.route('/')
def index():
    if get_current_user():
        return redirect('/dashboard')
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        users = get_users()
        user = users.get(username)
        
        if user and check_password_hash(user['password'], password):
            # Сохраняем сессию в Cloudinary
            session_id = save_session(username, username)
            
            response = make_response(redirect('/dashboard'))
            # Устанавливаем куки на 30 дней
            response.set_cookie('session_id', session_id, max_age=30*24*60*60)
            add_flash_message('Login successful!', 'success')
            return response
        else:
            add_flash_message('Invalid username or password', 'error')
    
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - Secure Cloud Storage</title>
        <style>
            body { font-family: Arial; margin: 50px; background: #f0f0f0; }
            .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
            h2 { text-align: center; color: #333; }
            .form-group { margin-bottom: 20px; }
            input[type="text"], input[type="password"] { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
            .btn { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
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
            ''' + get_flash_html() + '''
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
        
        users = get_users()
        if username in users:
            add_flash_message('Username already exists', 'error')
            return redirect('/register')
        
        hashed_password = generate_password_hash(password)
        if save_user(username, hashed_password):
            add_flash_message('Registration successful! Please login.', 'success')
            return redirect('/login')
        else:
            add_flash_message('Registration failed', 'error')
    
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Register - Secure Cloud Storage</title>
        <style>
            body { font-family: Arial; margin: 50px; background: #f0f0f0; }
            .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
            h2 { text-align: center; color: #333; }
            .form-group { margin-bottom: 20px; }
            input[type="text"], input[type="password"] { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
            .btn { width: 100%; padding: 12px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>📝 Create Account</h2>
            ''' + get_flash_html() + '''
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
@login_required
def dashboard():
    user = get_current_user()
    files_list = get_user_files(user['user_id'])
    
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
                <a href="/download/{file['file_id']}" style="padding: 8px 15px; background: #007bff; color: white; border-radius: 5px; text-decoration: none;">⬇️ Download</a>
                <a href="/delete/{file['file_id']}" style="padding: 8px 15px; background: #dc3545; color: white; border-radius: 5px; text-decoration: none; margin-left: 10px;" onclick="return confirm('Delete this file?')">🗑️ Delete</a>
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
                <span>Welcome, <strong>{user['username']}</strong>!</span>
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
@login_required
def upload_file():
    user = get_current_user()
    
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
        file_id = hashlib.md5(unique_filename.encode()).hexdigest()
        
        file_data = file.read()
        file_size = len(file_data)
        
        file_hash = calculate_file_hash(file_data)
        encrypted_data = encrypt_file(file_data)
        
        # Загружаем файл в Cloudinary
        cloud_result = cloudinary.uploader.upload(
            encrypted_data,
            public_id=f"storage/uploads/{user['user_id']}/{unique_filename}",
            resource_type="raw"
        )
        
        if cloud_result:
            # Сохраняем метаданные
            file_metadata = {
                'file_id': file_id,
                'filename': unique_filename,
                'original_filename': filename,
                'user_id': user['user_id'],
                'uploaded_at': datetime.now().isoformat(),
                'file_size': file_size,
                'file_hash': file_hash,
                'cloudinary_url': cloud_result['secure_url'],
                'cloudinary_public_id': cloud_result['public_id']
            }
            
            if save_file(file_metadata):
                add_flash_message(f'File "{filename}" encrypted and uploaded to cloud!', 'success')
            else:
                add_flash_message('Error saving file metadata', 'error')
        else:
            add_flash_message('Error uploading file to cloud storage', 'error')
    
    return redirect('/dashboard')

@app.route('/download/<file_id>')
@login_required
def download_file(file_id):
    user = get_current_user()
    files = get_user_files(user['user_id'])
    file_data = next((f for f in files if f['file_id'] == file_id), None)
    
    if file_data:
        try:
            # Скачиваем из Cloudinary
            response = requests.get(file_data['cloudinary_url'])
            
            if response.status_code == 200:
                encrypted_data = response.content
                decrypted_data = decrypt_file(encrypted_data)
                
                return send_file(
                    io.BytesIO(decrypted_data),
                    as_attachment=True,
                    download_name=file_data['original_filename']
                )
        except Exception as e:
            print(f"Download error: {e}")
            add_flash_message('Error downloading file from cloud', 'error')
    
    add_flash_message('File not found', 'error')
    return redirect('/dashboard')

@app.route('/delete/<file_id>')
@login_required
def delete_file(file_id):
    user = get_current_user()
    files = get_user_files(user['user_id'])
    file_data = next((f for f in files if f['file_id'] == file_id), None)
    
    if file_data:
        # Удаляем файл и метаданные
        try:
            cloudinary.uploader.destroy(file_data['cloudinary_public_id'], resource_type='raw')
            delete_file_data(user['user_id'], file_id)
            add_flash_message('File deleted successfully!', 'success')
        except Exception as e:
            add_flash_message('Error deleting file', 'error')
    else:
        add_flash_message('File not found', 'error')
    
    return redirect('/dashboard')

@app.route('/logout')
def logout():
    session_id = request.cookies.get('session_id')
    if session_id:
        delete_session(session_id)
    
    response = make_response(redirect('/login'))
    response.set_cookie('session_id', '', expires=0)
    add_flash_message('You have been logged out', 'info')
    return response

if __name__ == '__main__':
    print("🚀 Starting Secure Cloud Storage...")
    print("✅ Cloudinary storage configured!")
    print("✅ Persistent sessions enabled!")
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

