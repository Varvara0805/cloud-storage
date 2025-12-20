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

print("🚀 ЗАПУСК СЕРВЕРА")
print("💾 ВСЕ данные хранятся в Cloudinary")

# 🔧 ГЛОБАЛЬНАЯ ПЕРЕМЕННАЯ ДЛЯ ДАННЫХ
app_data = {
    'users': [],
    'files': [],
    'last_updated': None
}

# 🔧 ФУНКЦИИ ДЛЯ РАБОТЫ С CLOUDINARY DB
def save_to_cloudinary(data):
    """Сохраняем ВСЕ данные в Cloudinary"""
    try:
        data['last_updated'] = str(datetime.now())
        json_data = json.dumps(data, indent=2, default=str)
       
        result = cloudinary.uploader.upload(
            json_data.encode('utf-8'),
            public_id="storage/db/database",
            resource_type="raw",
            overwrite=True
        )
        return True
    except Exception as e:
        print(f"❌ Ошибка сохранения: {e}")
        return False

def load_from_cloudinary():
    """Загружаем ВСЕ данные из Cloudinary"""
    try:
        result = cloudinary.api.resource(
            "storage/db/database",
            resource_type="raw"
        )
       
        response = requests.get(result['secure_url'])
        if response.status_code == 200:
            data = json.loads(response.text)
            print(f"✅ База данных загружена из Cloudinary")
            return data
    except:
        print("ℹ️ Создаем новую базу данных")
   
    return {
        'users': [],
        'files': [],
        'last_updated': str(datetime.now())
    }

def init_db():
    """Инициализация базы данных в Cloudinary"""
    global app_data
   
    print("🔄 Загружаем базу данных из Cloudinary...")
    app_data = load_from_cloudinary()
   
    if not app_data.get('users'):
        hashed_pw = generate_password_hash('admin123')
        app_data['users'] = [{
            'id': 1,
            'username': 'admin',
            'password': hashed_pw,
            'created_at': str(datetime.now())
        }]
        save_to_cloudinary(app_data)
        print("✅ Тестовый пользователь: admin / admin123")
   
    print(f"📊 Пользователей: {len(app_data['users'])}")
    print(f"📊 Файлов: {len(app_data['files'])}")

init_db()

# 🔧 ФУНКЦИИ ДЛЯ РАБОТЫ С ДАННЫМИ
def get_user_by_username(username):
    for user in app_data['users']:
        if user['username'] == username:
            return user
    return None

def get_user_files(user_id):
    return [f for f in app_data['files'] if f['user_id'] == user_id]

def add_user(username, password_hash):
    new_id = max([u['id'] for u in app_data['users']], default=0) + 1
    new_user = {
        'id': new_id,
        'username': username,
        'password': password_hash,
        'created_at': str(datetime.now())
    }
    app_data['users'].append(new_user)
    save_to_cloudinary(app_data)
    return new_user

def add_file(file_data):
    new_id = max([f['id'] for f in app_data['files']], default=0) + 1
    file_data['id'] = new_id
    app_data['files'].append(file_data)
    save_to_cloudinary(app_data)
    return file_data

def delete_file_record(file_id, user_id):
    app_data['files'] = [f for f in app_data['files']
                        if not (f['file_id'] == file_id and f['user_id'] == user_id)]
    save_to_cloudinary(app_data)

def get_file_by_id(file_id, user_id):
    for file in app_data['files']:
        if file['file_id'] == file_id and file['user_id'] == user_id:
            return file
    return None

def encrypt_file(file_data):
    return cipher_suite.encrypt(file_data)

def decrypt_file(encrypted_data):
    return cipher_suite.decrypt(encrypted_data)

messages = []
def add_flash_message(message, category='info'):
    messages.append((category, message))

def get_flash_html():
    global messages
    html = ''
    for category, message in messages:
        if category == 'error':
            html += f'''
            <div style="background: #fee; border-left: 4px solid #f00; padding: 12px; margin: 10px 0; border-radius: 4px; display: flex; align-items: center; gap: 10px;">
                <span style="color: #f00;">⚠️</span>
                <span style="color: #333;">{message}</span>
            </div>
            '''
        elif category == 'success':
            html += f'''
            <div style="background: #efe; border-left: 4px solid #0a0; padding: 12px; margin: 10px 0; border-radius: 4px; display: flex; align-items: center; gap: 10px;">
                <span style="color: #0a0;">✅</span>
                <span style="color: #333;">{message}</span>
            </div>
            '''
        else:
            html += f'''
            <div style="background: #eef; border-left: 4px solid #00a; padding: 12px; margin: 10px 0; border-radius: 4px; display: flex; align-items: center; gap: 10px;">
                <span style="color: #00a;">ℹ️</span>
                <span style="color: #333;">{message}</span>
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
       
        user = get_user_by_username(username)
       
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['username']
            session['username'] = user['username']
            add_flash_message('Login successful!', 'success')
            return redirect('/dashboard')
        else:
            add_flash_message('Invalid credentials', 'error')
   
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login | CloudSecure</title>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                margin: 0;
                padding: 20px;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
            }}
            .login-box {{
                background: white;
                border-radius: 20px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                width: 100%;
                max-width: 400px;
                overflow: hidden;
            }}
            .login-header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 40px 30px;
                text-align: center;
            }}
            .login-header h1 {{
                margin: 0;
                font-size: 28px;
                font-weight: 600;
            }}
            .login-header p {{
                margin: 10px 0 0;
                opacity: 0.9;
            }}
            .login-content {{
                padding: 40px;
            }}
            .test-account {{
                background: #f8f9fa;
                border-radius: 10px;
                padding: 15px;
                margin-bottom: 20px;
                text-align: center;
                border: 1px solid #e9ecef;
            }}
            .test-account strong {{
                color: #333;
                display: block;
                margin-bottom: 5px;
            }}
            .test-account span {{
                color: #666;
                font-size: 14px;
            }}
            .form-group {{
                margin-bottom: 20px;
            }}
            .form-group label {{
                display: block;
                margin-bottom: 8px;
                color: #333;
                font-weight: 500;
            }}
            .form-control {{
                width: 100%;
                padding: 12px 15px;
                border: 2px solid #e1e5e9;
                border-radius: 10px;
                font-size: 16px;
                transition: border-color 0.3s;
            }}
            .form-control:focus {{
                outline: none;
                border-color: #667eea;
            }}
            .btn {{
                width: 100%;
                padding: 15px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border: none;
                border-radius: 10px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: transform 0.3s, box-shadow 0.3s;
            }}
            .btn:hover {{
                transform: translateY(-2px);
                box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4);
            }}
            .register-link {{
                text-align: center;
                margin-top: 20px;
                color: #666;
            }}
            .register-link a {{
                color: #667eea;
                text-decoration: none;
                font-weight: 500;
            }}
            .register-link a:hover {{
                text-decoration: underline;
            }}
        </style>
    </head>
    <body>
        <div class="login-box">
            <div class="login-header">
                <h1>🔐 CloudSecure</h1>
                <p>Secure Cloud Storage</p>
            </div>
            <div class="login-content">
                {get_flash_html()}
                <div class="test-account">
                    <strong>Test Account</strong>
                    <span>admin / admin123</span>
                </div>
                <form method="POST">
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" id="username" name="username" class="form-control" placeholder="Enter username" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" class="form-control" placeholder="Enter password" required>
                    </div>
                    <button type="submit" class="btn">Sign In</button>
                </form>
                <div class="register-link">
                    Don't have an account? <a href="/register">Create one</a>
                </div>
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
       
        if get_user_by_username(username):
            add_flash_message('Username already exists', 'error')
            return redirect('/register')
       
        try:
            hashed_pw = generate_password_hash(password)
            add_user(username, hashed_pw)
            add_flash_message('Registration successful! You can now login', 'success')
            return redirect('/login')
        except Exception as e:
            add_flash_message(f'Registration error: {str(e)}', 'error')
   
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Register | CloudSecure</title>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
                margin: 0;
                padding: 20px;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
            }}
            .register-box {{
                background: white;
                border-radius: 20px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                width: 100%;
                max-width: 400px;
                overflow: hidden;
            }}
            .register-header {{
                background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
                color: white;
                padding: 40px 30px;
                text-align: center;
            }}
            .register-header h1 {{
                margin: 0;
                font-size: 28px;
                font-weight: 600;
            }}
            .register-header p {{
                margin: 10px 0 0;
                opacity: 0.9;
            }}
            .register-content {{
                padding: 40px;
            }}
            .form-group {{
                margin-bottom: 20px;
            }}
            .form-group label {{
                display: block;
                margin-bottom: 8px;
                color: #333;
                font-weight: 500;
            }}
            .form-control {{
                width: 100%;
                padding: 12px 15px;
                border: 2px solid #e1e5e9;
                border-radius: 10px;
                font-size: 16px;
                transition: border-color 0.3s;
            }}
            .form-control:focus {{
                outline: none;
                border-color: #4facfe;
            }}
            .btn {{
                width: 100%;
                padding: 15px;
                background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
                color: white;
                border: none;
                border-radius: 10px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: transform 0.3s, box-shadow 0.3s;
            }}
            .btn:hover {{
                transform: translateY(-2px);
                box-shadow: 0 10px 20px rgba(79, 172, 254, 0.4);
            }}
            .login-link {{
                text-align: center;
                margin-top: 20px;
                color: #666;
            }}
            .login-link a {{
                color: #4facfe;
                text-decoration: none;
                font-weight: 500;
            }}
            .login-link a:hover {{
                text-decoration: underline;
            }}
            .password-hint {{
                font-size: 13px;
                color: #666;
                margin-top: 5px;
            }}
        </style>
    </head>
    <body>
        <div class="register-box">
            <div class="register-header">
                <h1>📝 Create Account</h1>
                <p>Join CloudSecure today</p>
            </div>
            <div class="register-content">
                {get_flash_html()}
                <form method="POST">
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" id="username" name="username" class="form-control" placeholder="Choose username" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" class="form-control" placeholder="At least 6 characters" required>
                        <div class="password-hint">Minimum 6 characters required</div>
                    </div>
                    <button type="submit" class="btn">Create Account</button>
                </form>
                <div class="login-link">
                    Already have an account? <a href="/login">Sign in</a>
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
    files_list = get_user_files(user_id)
   
    files_html = ""
    for file in files_list:
        # Безопасное получение данных
        size_kb = 0
        if file.get("file_size"):
            try:
                size_kb = round(float(file["file_size"])/1024, 1)
            except:
                size_kb = 0
       
        upload_date = 'Unknown'
        if file.get("uploaded_at"):
            try:
                upload_date = datetime.strptime(str(file["uploaded_at"]), '%Y-%m-%d %H:%M:%S').strftime('%d %b %Y, %H:%M')
            except:
                try:
                    upload_date = datetime.strptime(str(file["uploaded_at"]), '%Y-%m-%d').strftime('%d %b %Y')
                except:
                    upload_date = str(file["uploaded_at"])[:16]
       
        filename = file.get("original_filename", "Unknown file")
        file_id = file.get("file_id", "")
       
        files_html += f'''
        <div style="background: white; border: 1px solid #e1e5e9; border-radius: 12px; padding: 20px; margin-bottom: 15px; display: flex; align-items: center; justify-content: space-between; transition: all 0.3s;">
            <div style="display: flex; align-items: center; gap: 15px;">
                <div style="background: linear-gradient(135deg, #667eea, #764ba2); width: 50px; height: 50px; border-radius: 10px; display: flex; align-items: center; justify-content: center; color: white;">
                    📁
                </div>
                <div>
                    <div style="font-weight: 600; color: #333; margin-bottom: 5px;">{filename}</div>
                    <div style="font-size: 13px; color: #666;">
                        <span style="margin-right: 15px;">📦 {size_kb} KB</span>
                        <span>📅 {upload_date}</span>
                    </div>
                </div>
            </div>
            <div style="display: flex; gap: 10px;">
                <a href="/download/{file_id}" style="background: #667eea; color: white; padding: 8px 16px; border-radius: 6px; text-decoration: none; font-size: 14px; font-weight: 500; display: flex; align-items: center; gap: 5px;">
                    ⬇️ Download
                </a>
                <a href="/delete/{file_id}" onclick="return confirm('Delete {filename}?')" style="background: #f56565; color: white; padding: 8px 16px; border-radius: 6px; text-decoration: none; font-size: 14px; font-weight: 500; display: flex; align-items: center; gap: 5px;">
                    🗑️ Delete
                </a>
            </div>
        </div>
        '''
   
    if not files_html:
        files_html = '''
        <div style="text-align: center; padding: 60px 20px; color: #666;">
            <div style="font-size: 60px; margin-bottom: 20px;">📁</div>
            <h3 style="font-size: 24px; font-weight: 500; margin-bottom: 10px;">No files yet</h3>
            <p>Upload your first file to get started</p>
        </div>
        '''
   
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Dashboard | CloudSecure</title>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                margin: 0;
                background: #f5f7fa;
                color: #333;
            }}
            .navbar {{
                background: white;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                padding: 0 40px;
                height: 70px;
                display: flex;
                align-items: center;
                justify-content: space-between;
                position: sticky;
                top: 0;
                z-index: 1000;
            }}
            .logo {{
                display: flex;
                align-items: center;
                gap: 10px;
                font-size: 24px;
                font-weight: 600;
                color: #667eea;
                text-decoration: none;
            }}
            .user-menu {{
                display: flex;
                align-items: center;
                gap: 15px;
            }}
            .user-info {{
                display: flex;
                align-items: center;
                gap: 10px;
            }}
            .avatar {{
                width: 40px;
                height: 40px;
                background: linear-gradient(135deg, #667eea, #764ba2);
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                color: white;
                font-weight: 600;
            }}
            .nav-btn {{
                padding: 10px 20px;
                border-radius: 8px;
                text-decoration: none;
                font-weight: 500;
                font-size: 14px;
            }}
            .nav-btn.primary {{
                background: linear-gradient(135deg, #667eea, #764ba2);
                color: white;
            }}
            .nav-btn.secondary {{
                background: #f8f9fa;
                color: #666;
                border: 1px solid #e1e5e9;
            }}
            .container {{
                max-width: 1200px;
                margin: 40px auto;
                padding: 0 20px;
            }}
            .upload-section {{
                background: white;
                border-radius: 16px;
                padding: 30px;
                box-shadow: 0 4px 20px rgba(0,0,0,0.08);
                margin-bottom: 30px;
            }}
            .section-title {{
                font-size: 24px;
                font-weight: 600;
                margin-bottom: 20px;
                color: #333;
            }}
            .upload-form {{
                display: flex;
                gap: 15px;
                align-items: center;
                margin-bottom: 20px;
            }}
            .file-input {{
                flex: 1;
                padding: 15px;
                border: 2px dashed #cbd5e0;
                border-radius: 10px;
                font-size: 16px;
                background: #f8f9fa;
            }}
            .btn-upload {{
                padding: 15px 30px;
                background: linear-gradient(135deg, #48bb78, #38a169);
                color: white;
                border: none;
                border-radius: 10px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
            }}
            .upload-info {{
                display: flex;
                gap: 20px;
                color: #666;
                font-size: 14px;
            }}
            .files-section {{
                background: white;
                border-radius: 16px;
                padding: 30px;
                box-shadow: 0 4px 20px rgba(0,0,0,0.08);
            }}
            .section-header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 25px;
            }}
            .files-count {{
                background: #edf2f7;
                color: #667eea;
                padding: 8px 16px;
                border-radius: 20px;
                font-weight: 600;
                font-size: 14px;
            }}
            @media (max-width: 768px) {{
                .navbar {{
                    padding: 0 20px;
                }}
                .upload-form {{
                    flex-direction: column;
                }}
                .file-input, .btn-upload {{
                    width: 100%;
                }}
            }}
        </style>
    </head>
    <body>
        <nav class="navbar">
            <a href="/dashboard" class="logo">
                <span>☁️</span>
                <span>CloudSecure</span>
            </a>
            <div class="user-menu">
                <div class="user-info">
                    <div class="avatar">
                        {session["username"][0].upper()}
                    </div>
                    <span>Hello, {session["username"]}</span>
                </div>
                <div style="display: flex; gap: 10px;">
                    <a href="/profile" class="nav-btn primary">👤 Profile</a>
                    <a href="/logout" class="nav-btn secondary">🚪 Logout</a>
                </div>
            </div>
        </nav>
       
        <div class="container">
            {get_flash_html()}
           
            <div class="upload-section">
                <h2 class="section-title">📤 Upload File</h2>
                <form method="POST" action="/upload" enctype="multipart/form-data" class="upload-form">
                    <input type="file" name="file" required class="file-input">
                    <button type="submit" class="btn-upload">📎 Upload File</button>
                </form>
                <div class="upload-info">
                    <div>📦 Max size: 16MB</div>
                    <div>🔒 End-to-end encrypted</div>
                    <div>💾 Data persists after restart</div>
                </div>
            </div>
           
            <div class="files-section">
                <div class="section-header">
                    <h2 class="section-title">📁 Your Files</h2>
                    <div class="files-count">{len(files_list)} files</div>
                </div>
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
       
        encrypted_data = encrypt_file(file_data)
        result = cloudinary.uploader.upload(
            encrypted_data,
            public_id=f"storage/{user_id}/{file_id}_{filename}",
            resource_type="raw"
        )
       
        file_record = {
            'file_id': file_id,
            'filename': f"{file_id}_{filename}",
            'original_filename': filename,
            'user_id': user_id,
            'file_size': file_size,
            'cloudinary_url': result['secure_url'],
            'cloudinary_public_id': result['public_id'],
            'uploaded_at': str(datetime.now())
        }
       
        add_file(file_record)
        add_flash_message(f'File "{filename}" uploaded successfully!', 'success')
       
    except Exception as e:
        add_flash_message(f'Upload error: {str(e)}', 'error')
   
    return redirect('/dashboard')

@app.route('/download/<file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect('/login')
   
    user_id = session['user_id']
    file = get_file_by_id(file_id, user_id)
   
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
   
    user_id = session['user_id']
    file = get_file_by_id(file_id, user_id)
   
    if file:
        try:
            if file['cloudinary_public_id']:
                cloudinary.uploader.destroy(file['cloudinary_public_id'], resource_type="raw")
           
            delete_file_record(file_id, user_id)
            add_flash_message(f'File "{file["original_filename"]}" deleted!', 'success')
        except Exception as e:
            add_flash_message(f'Delete error: {str(e)}', 'error')
    else:
        add_flash_message('File not found', 'error')
   
    return redirect('/dashboard')

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect('/login')
   
    user_id = session['user_id']
    user = get_user_by_username(user_id)
   
    if not user:
        add_flash_message('User not found', 'error')
        return redirect('/logout')
   
    user_files = get_user_files(user_id)
    total_size = sum(f.get('file_size', 0) for f in user_files)
    total_files = len(user_files)
   
    total_size_mb = round(total_size / (1024 * 1024), 2) if total_size else 0
   
    join_date = 'Unknown'
    if user.get('created_at'):
        try:
            join_date = datetime.strptime(str(user['created_at']), '%Y-%m-%d %H:%M:%S').strftime('%B %d, %Y')
        except:
            try:
                join_date = datetime.strptime(str(user['created_at']), '%Y-%m-%d').strftime('%B %d, %Y')
            except:
                join_date = str(user['created_at'])[:10]
   
    first_upload = 'No uploads yet'
    if user_files:
        upload_dates = []
        for f in user_files:
            if f.get('uploaded_at'):
                try:
                    date_obj = datetime.strptime(str(f['uploaded_at']), '%Y-%m-%d %H:%M:%S')
                    upload_dates.append(date_obj)
                except:
                    try:
                        date_obj = datetime.strptime(str(f['uploaded_at']), '%Y-%m-%d')
                        upload_dates.append(date_obj)
                    except:
                        pass
       
        if upload_dates:
            first_upload = min(upload_dates).strftime('%B %d, %Y')
   
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Profile | CloudSecure</title>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                margin: 0;
                background: #f5f7fa;
            }}
            .navbar {{
                background: white;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                padding: 0 40px;
                height: 70px;
                display: flex;
                align-items: center;
                justify-content: space-between;
            }}
            .logo {{
                display: flex;
                align-items: center;
                gap: 10px;
                font-size: 24px;
                font-weight: 600;
                color: #667eea;
                text-decoration: none;
            }}
            .nav-btn {{
                padding: 10px 20px;
                border-radius: 8px;
                text-decoration: none;
                font-weight: 500;
                font-size: 14px;
            }}
            .nav-btn.primary {{
                background: linear-gradient(135deg, #667eea, #764ba2);
                color: white;
            }}
            .nav-btn.secondary {{
                background: #f8f9fa;
                color: #666;
                border: 1px solid #e1e5e9;
            }}
            .container {{
                max-width: 1000px;
                margin: 40px auto;
                padding: 0 20px;
            }}
            .profile-card {{
                background: white;
                border-radius: 20px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.1);
                overflow: hidden;
            }}
            .profile-header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                padding: 60px 40px;
                text-align: center;
                color: white;
            }}
            .avatar-large {{
                width: 120px;
                height: 120px;
                background: linear-gradient(135deg, #ff9a9e 0%, #fad0c4 100%);
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 48px;
                font-weight: 700;
                margin: 0 auto 20px;
                border: 5px solid white;
                box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            }}
            .profile-header h1 {{
                font-size: 36px;
                font-weight: 700;
                margin-bottom: 10px;
            }}
            .profile-header p {{
                opacity: 0.9;
                font-size: 16px;
            }}
            .profile-stats {{
                display: flex;
                gap: 20px;
                padding: 40px;
            }}
            .stat-card {{
                flex: 1;
                background: #f7fafc;
                border-radius: 16px;
                padding: 30px;
                text-align: center;
            }}
            .stat-card.blue {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
            }}
            .stat-card.green {{
                background: linear-gradient(135deg, #48bb78 0%, #38a169 100%);
                color: white;
            }}
            .stat-value {{
                font-size: 48px;
                font-weight: 700;
                margin-bottom: 10px;
            }}
            .stat-label {{
                font-size: 16px;
                opacity: 0.9;
            }}
            .profile-info {{
                padding: 40px;
                background: #f7fafc;
            }}
            .info-grid {{
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 20px;
                margin-bottom: 30px;
            }}
            .info-item {{
                background: white;
                padding: 20px;
                border-radius: 12px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            }}
            .info-item h3 {{
                color: #4a5568;
                font-size: 14px;
                margin-bottom: 8px;
            }}
            .info-item p {{
                font-size: 18px;
                font-weight: 600;
                color: #2d3748;
            }}
            @media (max-width: 768px) {{
                .profile-stats {{
                    flex-direction: column;
                }}
                .info-grid {{
                    grid-template-columns: 1fr;
                }}
                .navbar {{
                    padding: 0 20px;
                }}
            }}
        </style>
    </head>
    <body>
        <nav class="navbar">
            <a href="/dashboard" class="logo">
                <span>☁️</span>
                <span>CloudSecure</span>
            </a>
            <div>
                <a href="/dashboard" class="nav-btn primary">📁 Dashboard</a>
                <a href="/logout" class="nav-btn secondary">🚪 Logout</a>
            </div>
        </nav>
       
        <div class="container">
            {get_flash_html()}
            <div class="profile-card">
                <div class="profile-header">
                    <div class="avatar-large">
                        {session["username"][0].upper()}
                    </div>
                    <h1>{session["username"]}</h1>
                    <p>Cloud Storage User</p>
                </div>
               
                <div class="profile-stats">
                    <div class="stat-card blue">
                        <div class="stat-value">{total_files}</div>
                        <div class="stat-label">Total Files</div>
                    </div>
                    <div class="stat-card green">
                        <div class="stat-value">{total_size_mb}</div>
                        <div class="stat-label">Storage Used (MB)</div>
                    </div>
                </div>
               
                <div class="profile-info">
                    <div class="info-grid">
                        <div class="info-item">
                            <h3>👤 Username</h3>
                            <p>{user['username']}</p>
                        </div>
                        <div class="info-item">
                            <h3>📅 Member Since</h3>
                            <p>{join_date}</p>
                        </div>
                        <div class="info-item">
                            <h3>📤 First Upload</h3>
                            <p>{first_upload}</p>
                        </div>
                        <div class="info-item">
                            <h3>🆔 User ID</h3>
                            <p>{user['id']}</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/logout')
def logout():
    session.clear()
    add_flash_message('Logged out successfully', 'info')
    return redirect('/login')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"🌐 Сервер запускается на порту {port}")
    print(f"💾 ВСЕ данные сохраняются в Cloudinary")
    print(f"👥 Пользователей: {len(app_data['users'])}")
    print(f"📁 Файлов: {len(app_data['files'])}")
    app.run(host='0.0.0.0', port=port, debug=False)

