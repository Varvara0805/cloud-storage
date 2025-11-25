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
import base64

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'super-secret-key-12345')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# 🔧 ГЛОБАЛЬНОЕ ХРАНИЛИЩЕ ДЛЯ ФАЙЛОВ (сохраняется до перезапуска)
user_files_storage = {}



def get_user_files(user_id):
    """Получаем файлы пользователя из памяти"""
    if user_id in user_files_storage:
        files = user_files_storage[user_id]
        print(f"📁 Returning {len(files)} files for user {user_id}")
        return sorted(files, key=lambda x: x.get('uploaded_at', ''), reverse=True)
    else:
        print(f"📁 No files found for user {user_id}")
        return []

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

# 🔧 БАЗА ДАННЫХ В CLOUDINARY
def get_users():

    users = {}
    
    try:
        # Пробуем загрузить пользователей из Cloudinary
        result = cloudinary.api.resources(
            type='upload',
            prefix='database/users/',
            max_results=100
        )
        
        for resource in result.get('resources', []):
            try:
                user_data = download_json(resource['public_id'])
                if user_data and 'username' in user_data:
                    users[user_data['username']] = user_data
                    print(f"✅ Loaded user: {user_data['username']}")
            except Exception as e:
                print(f"⚠️ Error loading user from {resource['public_id']}: {e}")
                
    except Exception as e:
        print(f"⚠️ Cloudinary error: {e}")
    
    # ✅ ГАРАНТИРУЕМ что admin всегда есть
    if 'admin' not in users:
        print("🔧 Creating admin user...")
        admin_data = {
            'username': 'admin',
            'password': generate_password_hash('admin123'),
            'created_at': datetime.now().isoformat()
        }
        
        # Пробуем сохранить в Cloudinary
        cloud_result = upload_json(admin_data, 'database/users/admin')
        if cloud_result:
            print("✅ Admin saved to Cloudinary")
        else:
            print("⚠️ Admin saved to memory only")
        
        users['admin'] = admin_data
    
    print(f"🎯 Available users: {list(users.keys())}")
    return users

def save_user(username, password_hash):
   
    try:
        user_data = {
            'username': username,
            'password': password_hash,
            'created_at': datetime.now().isoformat()
        }
        print(f"🔧 Saving user: {username}")
        
        result = upload_json(user_data, f'database/users/{username}')
        
        if result:
            print(f"✅ User {username} saved successfully!")
            return True
        else:
            print(f"❌ Failed to save user {username}")
            return False
            
    except Exception as e:
        print(f"❌ Error saving user {username}: {e}")
        return False

def get_user_files(user_id):
    """Получаем все файлы пользователя из Cloudinary"""
    try:
        result = cloudinary.api.resources(
            type='upload',
            prefix=f'database/files/{user_id}/',
            max_results=100
        )
        files = []
        for resource in result.get('resources', []):
            file_data = download_json(resource['public_id'])
            if file_data:
                files.append(file_data)
        return sorted(files, key=lambda x: x.get('uploaded_at', ''), reverse=True)
    except Exception as e:
        print(f"❌ Error loading files: {e}")
        return []

def save_file(file_data):
   
    try:
        file_id = file_data['file_id']
        user_id = file_data['user_id']
        
        print(f"🔧 Saving metadata for file: {file_id}")
        
        # Преобразуем данные в JSON строку
        json_str = json.dumps(file_data, ensure_ascii=False)
        
        # Сохраняем как raw файл в Cloudinary
        result = cloudinary.uploader.upload(
            json_str.encode('utf-8'),
            public_id=f"database/files/{user_id}/{file_id}",
            resource_type="raw"
        )
        
        if result:
            print(f"✅ Metadata saved: {file_id}")
            return True
        else:
            print(f"❌ Metadata save failed: {file_id}")
            return False
            
    except Exception as e:
        print(f"❌ Error saving metadata: {e}")
        return False

def delete_file_data(user_id, file_id):
    """Удаляем метаданные файла из Cloudinary"""
    try:
        cloudinary.uploader.destroy(f'database/files/{user_id}/{file_id}')
        return True
    except:
        return False

# 🔧 ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
def upload_json(data, public_id):
    """Загружает JSON данные в Cloudinary"""
    try:
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f, ensure_ascii=False)
            f.flush()
            result = cloudinary.uploader.upload(
                f.filename,
                public_id=public_id,
                resource_type='raw'
            )
        os.unlink(f.name)
        return result
    except Exception as e:
        print(f"❌ Upload JSON error: {e}")
        return None

def download_json(public_id):
    """Скачивает JSON данные из Cloudinary"""
    try:
        url = cloudinary.utils.cloudinary_url(public_id, resource_type='raw')[0]
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        print(f"❌ Download JSON error: {e}")
        return None

def encrypt_file(file_data):
    return cipher_suite.encrypt(file_data)

def decrypt_file(encrypted_data):
    return cipher_suite.decrypt(encrypted_data)

def calculate_file_hash(file_data):
    return hashlib.sha256(file_data).hexdigest()

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
        
        users = get_users()
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
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    
    user_id = session['user_id']
    print(f"🎯 Dashboard loaded for user: {user_id}")
    
    # Получаем файлы
    files_list = get_user_files(user_id)
    print(f"📁 Files returned: {len(files_list)}")
    
    # Отладочная информация
    for i, file in enumerate(files_list):
        print(f"📄 File {i}: {file.get('original_filename', 'unknown')}")
    
    # Генерируем HTML для файлов
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
        print("📭 No files HTML generated")
    
    print("✅ Dashboard HTML generated successfully")
    
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
    
    print("🔧 Upload attempt detected")
    
    if 'file' not in request.files:
        add_flash_message('No file selected', 'error')
        print("❌ No file in request")
        return redirect('/dashboard')
    
    file = request.files['file']
    
    if file.filename == '':
        add_flash_message('No file selected', 'error')
        print("❌ Empty filename")
        return redirect('/dashboard')
    
    try:
        print(f"🔧 Processing file: {file.filename}")
        filename = secure_filename(file.filename)
        unique_filename = datetime.now().strftime("%Y%m%d_%H%M%S_") + filename
        file_id = hashlib.md5(unique_filename.encode()).hexdigest()
        
        # Читаем файл
        file_data = file.read()
        file_size = len(file_data)
        print(f"🔧 File size: {file_size} bytes")
        
        if file_size == 0:
            add_flash_message('File is empty', 'error')
            return redirect('/dashboard')
        
        # Шифруем
        encrypted_data = encrypt_file(file_data)
        print("🔧 File encrypted")
        
        # Загружаем в Cloudinary - УПРОЩЕННАЯ ВЕРСИЯ
        try:
            print("🔧 Uploading to Cloudinary...")
            cloud_result = cloudinary.uploader.upload(
                encrypted_data,
                public_id=f"storage/files/{session['user_id']}/{unique_filename}",
                resource_type="raw"
            )
            print("✅ File uploaded to Cloudinary")
        except Exception as e:
            print(f"❌ Cloudinary upload error: {e}")
            add_flash_message('Error uploading to cloud storage', 'error')
            return redirect('/dashboard')
        
        # Сохраняем метаданные
        file_metadata = {
            'file_id': file_id,
            'filename': unique_filename,
            'original_filename': filename,
            'user_id': session['user_id'],
            'uploaded_at': datetime.now().isoformat(),
            'file_size': file_size,
            'cloudinary_url': cloud_result['secure_url'],
            'cloudinary_public_id': cloud_result['public_id']
        }
        
        # Пробуем сохранить метаданные
        if save_file(file_metadata):
            add_flash_message(f'File "{filename}" uploaded successfully!', 'success')
            print("✅ File metadata saved")
        else:
            add_flash_message('File uploaded but metadata not saved', 'warning')
            print("⚠️ File metadata not saved")
        
    except Exception as e:
        print(f"❌ Upload error: {e}")
        add_flash_message('Error processing file', 'error')
    
    return redirect('/dashboard')
@app.route('/debug_files')
def debug_files():
    """Страница для отладки - показывает все файлы в Cloudinary"""
    if 'user_id' not in session:
        return redirect('/login')
    
    user_id = session['user_id']
    
    # Показываем все файлы пользователя
    try:
        result = cloudinary.api.resources(
            type='upload',
            prefix=f"database/files/{user_id}/",
            max_results=100
        )
        
        debug_html = f"<h2>Debug Files for {user_id}</h2>"
        debug_html += f"<p>Found {len(result.get('resources', []))} metadata files:</p>"
        
        for resource in result.get('resources', []):
            debug_html += f"<p>📄 {resource['public_id']}</p>"
            try:
                file_data = download_json(resource['public_id'])
                if file_data:
                    debug_html += f"<pre>{json.dumps(file_data, indent=2)}</pre>"
            except Exception as e:
                debug_html += f"<p>❌ Error: {e}</p>"
        
        return debug_html
        
    except Exception as e:
        return f"<p>❌ Debug error: {e}</p>"

@app.route('/download/<file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect('/login')
    
    files = get_user_files(session['user_id'])
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
            print(f"❌ Download error: {e}")
            add_flash_message('Error downloading file from cloud', 'error')
    
    add_flash_message('File not found', 'error')
    return redirect('/dashboard')

@app.route('/delete/<file_id>')
def delete_file(file_id):
    if 'user_id' not in session:
        return redirect('/login')
    
    files = get_user_files(session['user_id'])
    file_data = next((f for f in files if f['file_id'] == file_id), None)
    
    if file_data:
        try:
            # Удаляем ФАЙЛ из Cloudinary
            cloudinary.uploader.destroy(file_data['cloudinary_public_id'], resource_type='raw')
            # Удаляем МЕТАДАННЫЕ из Cloudinary
            delete_file_data(session['user_id'], file_id)
            add_flash_message('File deleted successfully!', 'success')
        except Exception as e:
            print(f"❌ Delete error: {e}")
            add_flash_message('Error deleting file', 'error')
    else:
        add_flash_message('File not found', 'error')
    
    return redirect('/dashboard')

@app.route('/logout')
def logout():
    session.clear()
    add_flash_message('You have been logged out', 'info')
    return redirect('/login')

if __name__ == '__main__':
    print("🚀 Starting Secure Cloud Storage...")
    print("✅ Cloudinary database configured!")
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)








