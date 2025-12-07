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
            <div class="alert alert-error">
                <i class="fas fa-exclamation-circle"></i>
                <span>{message}</span>
            </div>
            '''
        elif category == 'success':
            html += f'''
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i>
                <span>{message}</span>
            </div>
            '''
        else:
            html += f'''
            <div class="alert alert-info">
                <i class="fas fa-info-circle"></i>
                <span>{message}</span>
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
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login | CloudSecure</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        <style>
            :root {{
                --primary: #6366f1;
                --primary-dark: #4f46e5;
                --secondary: #8b5cf6;
                --accent: #ec4899;
                --light: #f8fafc;
                --dark: #1e293b;
                --success: #10b981;
                --error: #ef4444;
                --warning: #f59e0b;
                --gray: #64748b;
                --gray-light: #e2e8f0;
                --shadow: 0 20px 60px rgba(0,0,0,0.3);
                --radius-lg: 24px;
                --radius-md: 16px;
                --radius-sm: 12px;
            }}
           
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
           
            body {{
                font-family: 'Poppins', sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
                position: relative;
                overflow: hidden;
            }}
           
            body::before {{
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" preserveAspectRatio="none"><path fill="rgba(255,255,255,0.05)" d="M0,0 L100,0 L100,100 Z"/></svg>');
                background-size: cover;
                opacity: 0.1;
            }}
           
            .login-container {{
                background: rgba(255, 255, 255, 0.95);
                backdrop-filter: blur(20px);
                border-radius: var(--radius-lg);
                box-shadow: var(--shadow);
                width: 100%;
                max-width: 480px;
                overflow: hidden;
                border: 1px solid rgba(255, 255, 255, 0.2);
                position: relative;
                z-index: 1;
            }}
           
            .login-header {{
                background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
                padding: 60px 40px;
                text-align: center;
                color: white;
                position: relative;
                overflow: hidden;
            }}
           
            .login-header::before {{
                content: '';
                position: absolute;
                top: -50%;
                left: -50%;
                width: 200%;
                height: 200%;
                background: radial-gradient(circle, rgba(255,255,255,0.1) 1px, transparent 1px);
                background-size: 20px 20px;
                opacity: 0.2;
                animation: float 20s linear infinite;
            }}
           
            @keyframes float {{
                0% {{ transform: translate(0, 0) rotate(0deg); }}
                100% {{ transform: translate(-20px, -20px) rotate(360deg); }}
            }}
           
            .logo {{
                font-size: 48px;
                margin-bottom: 20px;
                display: inline-block;
                background: linear-gradient(135deg, #ffffff, rgba(255,255,255,0.8));
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }}
           
            .login-header h1 {{
                font-size: 36px;
                font-weight: 700;
                margin-bottom: 12px;
                letter-spacing: -0.5px;
            }}
           
            .login-header p {{
                font-size: 16px;
                opacity: 0.9;
                font-weight: 300;
            }}
           
            .login-content {{
                padding: 50px 40px;
            }}
           
            .test-card {{
                background: linear-gradient(135deg, rgba(99, 102, 241, 0.1), rgba(139, 92, 246, 0.1));
                border: 2px solid rgba(99, 102, 241, 0.2);
                border-radius: var(--radius-md);
                padding: 24px;
                margin-bottom: 32px;
                text-align: center;
                position: relative;
                overflow: hidden;
            }}
           
            .test-card::before {{
                content: 'TEST';
                position: absolute;
                top: 10px;
                right: 10px;
                background: var(--primary);
                color: white;
                font-size: 11px;
                font-weight: 600;
                padding: 4px 12px;
                border-radius: 20px;
            }}
           
            .test-card strong {{
                color: var(--dark);
                font-size: 18px;
                display: block;
                margin-bottom: 8px;
            }}
           
            .test-card span {{
                color: var(--gray);
                font-size: 15px;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 10px;
            }}
           
            .form-group {{
                margin-bottom: 28px;
                position: relative;
            }}
           
            .form-label {{
                display: flex;
                align-items: center;
                gap: 10px;
                margin-bottom: 12px;
                color: var(--dark);
                font-weight: 500;
                font-size: 15px;
            }}
           
            .form-label i {{
                color: var(--primary);
                font-size: 18px;
                width: 20px;
            }}
           
            .input-with-icon {{
                position: relative;
            }}
           
            .input-with-icon i {{
                position: absolute;
                left: 20px;
                top: 50%;
                transform: translateY(-50%);
                color: var(--gray);
                font-size: 18px;
            }}
           
            .form-control {{
                width: 100%;
                padding: 18px 20px 18px 55px;
                border: 2px solid var(--gray-light);
                border-radius: var(--radius-md);
                font-size: 16px;
                font-family: 'Poppins', sans-serif;
                transition: all 0.3s ease;
                background: var(--light);
                color: var(--dark);
            }}
           
            .form-control:focus {{
                outline: none;
                border-color: var(--primary);
                background: white;
                box-shadow: 0 0 0 4px rgba(99, 102, 241, 0.1);
            }}
           
            .btn {{
                width: 100%;
                padding: 20px;
                background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
                color: white;
                border: none;
                border-radius: var(--radius-md);
                font-size: 17px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s ease;
                font-family: 'Poppins', sans-serif;
                letter-spacing: 0.5px;
                position: relative;
                overflow: hidden;
            }}
           
            .btn::after {{
                content: '';
                position: absolute;
                top: -50%;
                left: -50%;
                width: 200%;
                height: 200%;
                background: linear-gradient(to right, transparent, rgba(255,255,255,0.3), transparent);
                transform: translateX(-100%);
            }}
           
            .btn:hover {{
                transform: translateY(-3px);
                box-shadow: 0 15px 30px rgba(99, 102, 241, 0.4);
            }}
           
            .btn:hover::after {{
                animation: shine 1.5s ease;
            }}
           
            @keyframes shine {{
                100% {{ transform: translateX(100%); }}
            }}
           
            .btn i {{
                margin-right: 10px;
            }}
           
            .register-link {{
                text-align: center;
                margin-top: 32px;
                color: var(--gray);
                font-size: 15px;
            }}
           
            .register-link a {{
                color: var(--primary);
                text-decoration: none;
                font-weight: 600;
                transition: color 0.3s ease;
                display: inline-flex;
                align-items: center;
                gap: 8px;
            }}
           
            .register-link a:hover {{
                color: var(--primary-dark);
            }}
           
            .alert {{
                padding: 18px 20px;
                border-radius: var(--radius-md);
                margin-bottom: 28px;
                display: flex;
                align-items: center;
                gap: 14px;
                animation: slideIn 0.5s ease;
            }}
           
            @keyframes slideIn {{
                from {{ opacity: 0; transform: translateY(-20px); }}
                to {{ opacity: 1; transform: translateY(0); }}
            }}
           
            .alert-error {{
                background: linear-gradient(135deg, rgba(239, 68, 68, 0.1), rgba(220, 38, 38, 0.1));
                border-left: 4px solid var(--error);
                color: var(--error);
            }}
           
            .alert-success {{
                background: linear-gradient(135deg, rgba(16, 185, 129, 0.1), rgba(5, 150, 105, 0.1));
                border-left: 4px solid var(--success);
                color: var(--success);
            }}
           
            .alert-info {{
                background: linear-gradient(135deg, rgba(59, 130, 246, 0.1), rgba(37, 99, 235, 0.1));
                border-left: 4px solid #3b82f6;
                color: #3b82f6;
            }}
           
            .alert i {{
                font-size: 20px;
            }}
           
            @media (max-width: 576px) {{
                .login-container {{
                    margin: 10px;
                }}
               
                .login-header {{
                    padding: 40px 20px;
                }}
               
                .login-content {{
                    padding: 30px 20px;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="login-container">
            <div class="login-header">
                <div class="logo">
                    <i class="fas fa-cloud"></i>
                </div>
                <h1>CloudSecure</h1>
                <p>Secure Cloud Storage with Military-Grade Encryption</p>
            </div>
            <div class="login-content">
                {get_flash_html()}
                <div class="test-card">
                    <strong><i class="fas fa-user-shield"></i> Test Account</strong>
                    <span>
                        <i class="fas fa-user"></i> admin
                        <i class="fas fa-key"></i> admin123
                    </span>
                </div>
                <form method="POST">
                    <div class="form-group">
                        <div class="form-label">
                            <i class="fas fa-user-circle"></i>
                            <span>Username</span>
                        </div>
                        <div class="input-with-icon">
                            <i class="fas fa-user"></i>
                            <input type="text" name="username" class="form-control" placeholder="Enter your username" required>
                        </div>
                    </div>
                    <div class="form-group">
                        <div class="form-label">
                            <i class="fas fa-lock"></i>
                            <span>Password</span>
                        </div>
                        <div class="input-with-icon">
                            <i class="fas fa-key"></i>
                            <input type="password" name="password" class="form-control" placeholder="Enter your password" required>
                        </div>
                    </div>
                    <button type="submit" class="btn">
                        <i class="fas fa-sign-in-alt"></i> Sign In
                    </button>
                </form>
                <div class="register-link">
                    <a href="/register">
                        <i class="fas fa-user-plus"></i> Create New Account
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
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Register | CloudSecure</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        <style>
            :root {{
                --primary: #8b5cf6;
                --primary-dark: #7c3aed;
                --secondary: #ec4899;
                --light: #f8fafc;
                --dark: #1e293b;
                --success: #10b981;
                --error: #ef4444;
                --gray: #64748b;
                --shadow: 0 20px 60px rgba(0,0,0,0.3);
                --radius-lg: 24px;
                --radius-md: 16px;
            }}
           
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
           
            body {{
                font-family: 'Poppins', sans-serif;
                background: linear-gradient(135deg, #8b5cf6 0%, #ec4899 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
                position: relative;
            }}
           
            .register-container {{
                background: rgba(255, 255, 255, 0.95);
                backdrop-filter: blur(20px);
                border-radius: var(--radius-lg);
                box-shadow: var(--shadow);
                width: 100%;
                max-width: 480px;
                overflow: hidden;
                border: 1px solid rgba(255, 255, 255, 0.2);
                animation: fadeIn 0.8s ease;
            }}
           
            @keyframes fadeIn {{
                from {{ opacity: 0; transform: translateY(30px); }}
                to {{ opacity: 1; transform: translateY(0); }}
            }}
           
            .register-header {{
                background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
                padding: 60px 40px;
                text-align: center;
                color: white;
                position: relative;
                overflow: hidden;
            }}
           
            .register-header::before {{
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" preserveAspectRatio="none"><path d="M0,0 C20,40 40,60 100,100 L100,0 Z" fill="rgba(255,255,255,0.1)"/></svg>');
                background-size: cover;
            }}
           
            .register-logo {{
                font-size: 48px;
                margin-bottom: 20px;
                display: inline-block;
                animation: float 3s ease-in-out infinite;
            }}
           
            @keyframes float {{
                0%, 100% {{ transform: translateY(0); }}
                50% {{ transform: translateY(-10px); }}
            }}
           
            .register-header h1 {{
                font-size: 36px;
                font-weight: 700;
                margin-bottom: 12px;
            }}
           
            .register-header p {{
                font-size: 16px;
                opacity: 0.9;
            }}
           
            .register-content {{
                padding: 50px 40px;
            }}
           
            .form-group {{
                margin-bottom: 28px;
            }}
           
            .form-label {{
                display: flex;
                align-items: center;
                gap: 10px;
                margin-bottom: 12px;
                color: var(--dark);
                font-weight: 500;
            }}
           
            .form-label i {{
                color: var(--primary);
                font-size: 18px;
                width: 20px;
            }}
           
            .input-with-icon {{
                position: relative;
            }}
           
            .input-with-icon i {{
                position: absolute;
                left: 20px;
                top: 50%;
                transform: translateY(-50%);
                color: var(--gray);
                font-size: 18px;
            }}
           
            .form-control {{
                width: 100%;
                padding: 18px 20px 18px 55px;
                border: 2px solid #e2e8f0;
                border-radius: var(--radius-md);
                font-size: 16px;
                font-family: 'Poppins', sans-serif;
                transition: all 0.3s ease;
                background: var(--light);
            }}
           
            .form-control:focus {{
                outline: none;
                border-color: var(--primary);
                background: white;
                box-shadow: 0 0 0 4px rgba(139, 92, 246, 0.1);
            }}
           
            .password-requirements {{
                display: flex;
                align-items: center;
                gap: 10px;
                margin-top: 8px;
                color: var(--gray);
                font-size: 14px;
            }}
           
            .password-requirements i {{
                color: var(--success);
            }}
           
            .btn {{
                width: 100%;
                padding: 20px;
                background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
                color: white;
                border: none;
                border-radius: var(--radius-md);
                font-size: 17px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s ease;
                font-family: 'Poppins', sans-serif;
                position: relative;
                overflow: hidden;
            }}
           
            .btn:hover {{
                transform: translateY(-3px);
                box-shadow: 0 15px 30px rgba(139, 92, 246, 0.4);
            }}
           
            .btn i {{
                margin-right: 10px;
            }}
           
            .login-link {{
                text-align: center;
                margin-top: 32px;
                color: var(--gray);
            }}
           
            .login-link a {{
                color: var(--primary);
                text-decoration: none;
                font-weight: 600;
                display: inline-flex;
                align-items: center;
                gap: 8px;
            }}
           
            .login-link a:hover {{
                color: var(--primary-dark);
            }}
           
            .alert {{
                padding: 18px 20px;
                border-radius: var(--radius-md);
                margin-bottom: 28px;
                display: flex;
                align-items: center;
                gap: 14px;
            }}
           
            .alert-error {{
                background: linear-gradient(135deg, rgba(239, 68, 68, 0.1), rgba(220, 38, 38, 0.1));
                border-left: 4px solid var(--error);
                color: var(--error);
            }}
           
            .alert-success {{
                background: linear-gradient(135deg, rgba(16, 185, 129, 0.1), rgba(5, 150, 105, 0.1));
                border-left: 4px solid var(--success);
                color: var(--success);
            }}
           
            .alert-info {{
                background: linear-gradient(135deg, rgba(59, 130, 246, 0.1), rgba(37, 99, 235, 0.1));
                border-left: 4px solid #3b82f6;
                color: #3b82f6;
            }}
           
            .alert i {{
                font-size: 20px;
            }}
           
            @media (max-width: 576px) {{
                .register-container {{
                    margin: 10px;
                }}
               
                .register-header {{
                    padding: 40px 20px;
                }}
               
                .register-content {{
                    padding: 30px 20px;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="register-container">
            <div class="register-header">
                <div class="register-logo">
                    <i class="fas fa-user-plus"></i>
                </div>
                <h1>Create Account</h1>
                <p>Join our secure cloud storage community</p>
            </div>
            <div class="register-content">
                {get_flash_html()}
                <form method="POST">
                    <div class="form-group">
                        <div class="form-label">
                            <i class="fas fa-user-circle"></i>
                            <span>Username</span>
                        </div>
                        <div class="input-with-icon">
                            <i class="fas fa-user"></i>
                            <input type="text" name="username" class="form-control" placeholder="Choose a username" required>
                        </div>
                    </div>
                    <div class="form-group">
                        <div class="form-label">
                            <i class="fas fa-lock"></i>
                            <span>Password</span>
                        </div>
                        <div class="input-with-icon">
                            <i class="fas fa-key"></i>
                            <input type="password" name="password" class="form-control" placeholder="Create a strong password" required>
                        </div>
                        <div class="password-requirements">
                            <i class="fas fa-check-circle"></i>
                            <span>Minimum 6 characters required</span>
                        </div>
                    </div>
                    <button type="submit" class="btn">
                        <i class="fas fa-user-plus"></i> Create Account
                    </button>
                </form>
                <div class="login-link">
                    <a href="/login">
                        <i class="fas fa-sign-in-alt"></i> Already have an account? Sign In
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
    files_list = get_user_files(user_id)
   
    files_html = ""
    for file in files_list:
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
       
        # Определяем иконку по расширению файла
        file_ext = filename.split('.')[-1].lower() if '.' in filename else ''
        file_icon = "fa-file"
        file_color = "#6366f1"
       
        if file_ext in ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg']:
            file_icon = "fa-file-image"
            file_color = "#ec4899"
        elif file_ext in ['pdf']:
            file_icon = "fa-file-pdf"
            file_color = "#ef4444"
        elif file_ext in ['doc', 'docx']:
            file_icon = "fa-file-word"
            file_color = "#3b82f6"
        elif file_ext in ['xls', 'xlsx']:
            file_icon = "fa-file-excel"
            file_color = "#10b981"
        elif file_ext in ['zip', 'rar', '7z', 'tar', 'gz']:
            file_icon = "fa-file-archive"
            file_color = "#f59e0b"
        elif file_ext in ['mp3', 'wav', 'flac']:
            file_icon = "fa-file-audio"
            file_color = "#8b5cf6"
        elif file_ext in ['mp4', 'avi', 'mkv', 'mov']:
            file_icon = "fa-file-video"
            file_color = "#8b5cf6"
       
        files_html += f'''
        <div class="file-card">
            <div class="file-icon" style="background: linear-gradient(135deg, {file_color}20, {file_color}40); border-color: {file_color}60;">
                <i class="fas {file_icon}" style="color: {file_color};"></i>
            </div>
            <div class="file-info">
                <div class="file-name">{filename}</div>
                <div class="file-meta">
                    <span class="file-size"><i class="fas fa-weight-hanging"></i> {size_kb} KB</span>
                    <span class="file-date"><i class="far fa-clock"></i> {upload_date}</span>
                </div>
            </div>
            <div class="file-actions">
                <a href="/download/{file_id}" class="btn-action btn-download">
                    <i class="fas fa-download"></i>
                    <span>Download</span>
                </a>
                <a href="/delete/{file_id}" onclick="return confirm('Delete {filename}?')" class="btn-action btn-delete">
                    <i class="fas fa-trash"></i>
                    <span>Delete</span>
                </a>
            </div>
        </div>
        '''
   
    if not files_html:
        files_html = '''
        <div class="empty-state">
            <div class="empty-icon">
                <i class="fas fa-cloud-upload-alt"></i>
            </div>
            <h3>Your storage is empty</h3>
            <p>Upload your first file to get started</p>
        </div>
        '''
   
    return f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Dashboard | CloudSecure</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        <style>
            :root {{
                --primary: #6366f1;
                --primary-dark: #4f46e5;
                --secondary: #8b5cf6;
                --accent: #ec4899;
                --light: #f8fafc;
                --dark: #1e293b;
                --success: #10b981;
                --error: #ef4444;
                --warning: #f59e0b;
                --gray: #64748b;
                --gray-light: #e2e8f0;
                --radius-lg: 24px;
                --radius-md: 16px;
                --radius-sm: 12px;
                --shadow-sm: 0 4px 20px rgba(0,0,0,0.08);
                --shadow-md: 0 10px 40px rgba(0,0,0,0.12);
            }}
           
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
           
            body {{
                font-family: 'Poppins', sans-serif;
                background: #f1f5f9;
                color: var(--dark);
                min-height: 100vh;
            }}
           
            /* Navigation */
            .navbar {{
                background: white;
                box-shadow: 0 4px 20px rgba(0,0,0,0.08);
                padding: 0 40px;
                height: 80px;
                display: flex;
                align-items: center;
                justify-content: space-between;
                position: sticky;
                top: 0;
                z-index: 1000;
                backdrop-filter: blur(10px);
                background: rgba(255, 255, 255, 0.95);
            }}
           
            .logo {{
                display: flex;
                align-items: center;
                gap: 15px;
                font-size: 26px;
                font-weight: 700;
                color: var(--primary);
                text-decoration: none;
                transition: transform 0.3s ease;
            }}
           
            .logo:hover {{
                transform: translateY(-2px);
            }}
           
            .logo-icon {{
                background: linear-gradient(135deg, var(--primary), var(--secondary));
                width: 50px;
                height: 50px;
                border-radius: 14px;
                display: flex;
                align-items: center;
                justify-content: center;
                color: white;
                font-size: 24px;
            }}
           
            .user-menu {{
                display: flex;
                align-items: center;
                gap: 25px;
            }}
           
            .user-info {{
                display: flex;
                align-items: center;
                gap: 15px;
                padding: 10px 20px;
                background: var(--light);
                border-radius: var(--radius-md);
                border: 2px solid var(--gray-light);
            }}
           
            .avatar {{
                width: 45px;
                height: 45px;
                background: linear-gradient(135deg, var(--primary), var(--secondary));
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                color: white;
                font-weight: 600;
                font-size: 18px;
                box-shadow: 0 4px 12px rgba(99, 102, 241, 0.3);
            }}
           
            .username {{
                font-weight: 500;
                color: var(--dark);
            }}
           
            .nav-links {{
                display: flex;
                gap: 12px;
            }}
           
            .nav-btn {{
                padding: 12px 24px;
                border-radius: var(--radius-md);
                text-decoration: none;
                font-weight: 500;
                font-size: 15px;
                transition: all 0.3s ease;
                display: flex;
                align-items: center;
                gap: 10px;
                border: 2px solid transparent;
            }}
           
            .nav-btn.primary {{
                background: linear-gradient(135deg, var(--primary), var(--secondary));
                color: white;
                box-shadow: 0 4px 15px rgba(99, 102, 241, 0.3);
            }}
           
            .nav-btn.primary:hover {{
                transform: translateY(-3px);
                box-shadow: 0 8px 25px rgba(99, 102, 241, 0.4);
            }}
           
            .nav-btn.secondary {{
                background: white;
                color: var(--gray);
                border-color: var(--gray-light);
            }}
           
            .nav-btn.secondary:hover {{
                background: var(--light);
                transform: translateY(-3px);
                box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            }}
           
            /* Main Content */
            .container {{
                max-width: 1200px;
                margin: 40px auto;
                padding: 0 20px;
            }}
           
            /* Upload Section */
            .upload-section {{
                background: white;
                border-radius: var(--radius-lg);
                padding: 40px;
                box-shadow: var(--shadow-sm);
                margin-bottom: 30px;
                border: 2px dashed var(--gray-light);
                transition: all 0.3s ease;
            }}
           
            .upload-section:hover {{
                border-color: var(--primary);
                box-shadow: var(--shadow-md);
            }}
           
            .section-title {{
                font-size: 28px;
                font-weight: 600;
                margin-bottom: 25px;
                color: var(--dark);
                display: flex;
                align-items: center;
                gap: 15px;
            }}
           
            .upload-form {{
                display: flex;
                gap: 20px;
                align-items: center;
                margin-bottom: 25px;
            }}
           
            .file-input {{
                flex: 1;
                padding: 20px;
                border: 2px dashed var(--gray-light);
                border-radius: var(--radius-md);
                font-size: 16px;
                font-family: 'Poppins', sans-serif;
                background: var(--light);
                transition: all 0.3s ease;
                cursor: pointer;
            }}
           
            .file-input:hover {{
                border-color: var(--primary);
                background: white;
            }}
           
            .btn-upload {{
                padding: 20px 40px;
                background: linear-gradient(135deg, var(--success), #059669);
                color: white;
                border: none;
                border-radius: var(--radius-md);
                font-size: 17px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s ease;
                display: flex;
                align-items: center;
                gap: 12px;
                box-shadow: 0 4px 15px rgba(16, 185, 129, 0.3);
            }}
           
            .btn-upload:hover {{
                transform: translateY(-3px);
                box-shadow: 0 8px 25px rgba(16, 185, 129, 0.4);
            }}
           
            .upload-features {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-top: 30px;
            }}
           
            .feature {{
                display: flex;
                align-items: center;
                gap: 15px;
                padding: 20px;
                background: var(--light);
                border-radius: var(--radius-md);
                transition: all 0.3s ease;
            }}
           
            .feature:hover {{
                background: white;
                transform: translateY(-3px);
                box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            }}
           
            .feature-icon {{
                width: 50px;
                height: 50px;
                background: linear-gradient(135deg, var(--primary), var(--secondary));
                border-radius: 14px;
                display: flex;
                align-items: center;
                justify-content: center;
                color: white;
                font-size: 22px;
            }}
           
            .feature-text {{
                flex: 1;
            }}
           
            .feature-text strong {{
                display: block;
                margin-bottom: 5px;
                color: var(--dark);
            }}
           
            .feature-text span {{
                color: var(--gray);
                font-size: 14px;
            }}
           
            /* Files Section */
            .files-section {{
                background: white;
                border-radius: var(--radius-lg);
                padding: 40px;
                box-shadow: var(--shadow-sm);
            }}
           
            .section-header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 30px;
            }}
           
            .files-count {{
                background: linear-gradient(135deg, var(--primary), var(--secondary));
                color: white;
                padding: 10px 24px;
                border-radius: 30px;
                font-weight: 600;
                font-size: 15px;
                display: flex;
                align-items: center;
                gap: 10px;
                box-shadow: 0 4px 15px rgba(99, 102, 241, 0.3);
            }}
           
            /* File Cards */
            .file-card {{
                display: flex;
                align-items: center;
                padding: 25px;
                background: white;
                border: 2px solid var(--gray-light);
                border-radius: var(--radius-md);
                margin-bottom: 20px;
                transition: all 0.3s ease;
                position: relative;
                overflow: hidden;
            }}
           
            .file-card:hover {{
                transform: translateY(-5px);
                border-color: var(--primary);
                box-shadow: var(--shadow-md);
            }}
           
            .file-card::before {{
                content: '';
                position: absolute;
                left: 0;
                top: 0;
                height: 100%;
                width: 4px;
                background: linear-gradient(to bottom, var(--primary), var(--secondary));
            }}
           
            .file-icon {{
                width: 60px;
                height: 60px;
                border-radius: 16px;
                display: flex;
                align-items: center;
                justify-content: center;
                margin-right: 25px;
                font-size: 28px;
                border: 2px solid;
                flex-shrink: 0;
            }}
           
            .file-info {{
                flex: 1;
                min-width: 0;
            }}
           
            .file-name {{
                font-weight: 600;
                color: var(--dark);
                margin-bottom: 10px;
                font-size: 18px;
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
            }}
           
            .file-meta {{
                display: flex;
                gap: 25px;
                color: var(--gray);
                font-size: 14px;
            }}
           
            .file-meta span {{
                display: flex;
                align-items: center;
                gap: 8px;
            }}
           
            .file-actions {{
                display: flex;
                gap: 15px;
                flex-shrink: 0;
            }}
           
            .btn-action {{
                padding: 12px 24px;
                border-radius: var(--radius-sm);
                text-decoration: none;
                font-weight: 500;
                font-size: 15px;
                display: flex;
                align-items: center;
                gap: 10px;
                transition: all 0.3s ease;
                border: 2px solid transparent;
            }}
           
            .btn-download {{
                background: linear-gradient(135deg, var(--primary), var(--secondary));
                color: white;
                box-shadow: 0 4px 15px rgba(99, 102, 241, 0.3);
            }}
           
            .btn-download:hover {{
                transform: translateY(-3px);
                box-shadow: 0 8px 25px rgba(99, 102, 241, 0.4);
            }}
           
            .btn-delete {{
                background: white;
                color: var(--error);
                border-color: var(--error);
            }}
           
            .btn-delete:hover {{
                background: var(--error);
                color: white;
                transform: translateY(-3px);
                box-shadow: 0 8px 25px rgba(239, 68, 68, 0.3);
            }}
           
            /* Empty State */
            .empty-state {{
                text-align: center;
                padding: 80px 20px;
            }}
           
            .empty-icon {{
                font-size: 80px;
                margin-bottom: 30px;
                color: var(--primary);
                opacity: 0.5;
            }}
           
            .empty-state h3 {{
                font-size: 28px;
                font-weight: 600;
                margin-bottom: 15px;
                color: var(--dark);
            }}
           
            .empty-state p {{
                color: var(--gray);
                font-size: 18px;
                max-width: 400px;
                margin: 0 auto;
            }}
           
            /* Alerts */
            .alert {{
                padding: 20px;
                border-radius: var(--radius-md);
                margin-bottom: 30px;
                display: flex;
                align-items: center;
                gap: 15px;
                animation: slideIn 0.5s ease;
            }}
           
            .alert-error {{
                background: linear-gradient(135deg, rgba(239, 68, 68, 0.1), rgba(220, 38, 38, 0.1));
                border-left: 4px solid var(--error);
                color: var(--error);
            }}
           
            .alert-success {{
                background: linear-gradient(135deg, rgba(16, 185, 129, 0.1), rgba(5, 150, 105, 0.1));
                border-left: 4px solid var(--success);
                color: var(--success);
            }}
           
            .alert-info {{
                background: linear-gradient(135deg, rgba(59, 130, 246, 0.1), rgba(37, 99, 235, 0.1));
                border-left: 4px solid #3b82f6;
                color: #3b82f6;
            }}
           
            .alert i {{
                font-size: 22px;
            }}
           
            /* Responsive */
            @media (max-width: 1024px) {{
                .file-card {{
                    flex-direction: column;
                    text-align: center;
                    gap: 20px;
                }}
               
                .file-icon {{
                    margin-right: 0;
                    margin-bottom: 15px;
                }}
               
                .file-info {{
                    margin-bottom: 15px;
                }}
               
                .file-meta {{
                    justify-content: center;
                    flex-wrap: wrap;
                    gap: 15px;
                }}
            }}
           
            @media (max-width: 768px) {{
                .navbar {{
                    padding: 0 20px;
                    flex-direction: column;
                    height: auto;
                    padding: 20px;
                    gap: 20px;
                }}
               
                .user-menu {{
                    width: 100%;
                    justify-content: space-between;
                }}
               
                .nav-links {{
                    display: none;
                }}
               
                .upload-form {{
                    flex-direction: column;
                }}
               
                .file-input, .btn-upload {{
                    width: 100%;
                }}
               
                .file-actions {{
                    width: 100%;
                    justify-content: center;
                }}
               
                .btn-action {{
                    flex: 1;
                    justify-content: center;
                }}
               
                .upload-features {{
                    grid-template-columns: 1fr;
                }}
               
                .feature {{
                    flex-direction: column;
                    text-align: center;
                }}
               
                .feature-icon {{
                    margin-bottom: 15px;
                }}
            }}
           
            @media (max-width: 480px) {{
                .container {{
                    padding: 0 15px;
                }}
               
                .upload-section, .files-section {{
                    padding: 25px 20px;
                }}
               
                .section-title {{
                    font-size: 24px;
                }}
               
                .file-card {{
                    padding: 20px;
                }}
               
                .btn-action {{
                    padding: 10px 15px;
                    font-size: 14px;
                }}
            }}
           
            /* Animations */
            @keyframes slideIn {{
                from {{ opacity: 0; transform: translateY(-20px); }}
                to {{ opacity: 1; transform: translateY(0); }}
            }}
           
            @keyframes fadeIn {{
                from {{ opacity: 0; }}
                to {{ opacity: 1; }}
            }}
           
            .fade-in {{
                animation: fadeIn 0.8s ease;
            }}
        </style>
    </head>
    <body>
        <nav class="navbar">
            <a href="/dashboard" class="logo">
                <div class="logo-icon">
                    <i class="fas fa-cloud"></i>
                </div>
                <span>CloudSecure</span>
            </a>
            <div class="user-menu">
                <div class="user-info">
                    <div class="avatar">
                        {session["username"][0].upper()}
                    </div>
                    <span class="username">Welcome, {session["username"]}</span>
                </div>
                <div class="nav-links">
                    <a href="/profile" class="nav-btn primary">
                        <i class="fas fa-user-circle"></i>
                        Profile
                    </a>
                    <a href="/logout" class="nav-btn secondary">
                        <i class="fas fa-sign-out-alt"></i>
                        Logout
                    </a>
                </div>
            </div>
        </nav>
       
        <div class="container fade-in">
            {get_flash_html()}
           
            <div class="upload-section">
                <h2 class="section-title">
                    <i class="fas fa-cloud-upload-alt"></i>
                    Upload File
                </h2>
                <form method="POST" action="/upload" enctype="multipart/form-data" class="upload-form">
                    <input type="file" name="file" required class="file-input" id="fileInput">
                    <button type="submit" class="btn-upload">
                        <i class="fas fa-upload"></i>
                        Upload File
                    </button>
                </form>
                <div class="upload-features">
                    <div class="feature">
                        <div class="feature-icon">
                            <i class="fas fa-shield-alt"></i>
                        </div>
                        <div class="feature-text">
                            <strong>End-to-End Encryption</strong>
                            <span>Military-grade AES-256 encryption</span>
                        </div>
                    </div>
                    <div class="feature">
                        <div class="feature-icon">
                            <i class="fas fa-infinity"></i>
                        </div>
                        <div class="feature-text">
                            <strong>Persistent Storage</strong>
                            <span>Files survive server restarts</span>
                        </div>
                    </div>
                    <div class="feature">
                        <div class="feature-icon">
                            <i class="fas fa-bolt"></i>
                        </div>
                        <div class="feature-text">
                            <strong>Fast Transfers</strong>
                            <span>High-speed uploads and downloads</span>
                        </div>
                    </div>
                    <div class="feature">
                        <div class="feature-icon">
                            <i class="fas fa-mobile-alt"></i>
                        </div>
                        <div class="feature-text">
                            <strong>Mobile Ready</strong>
                            <span>Responsive design for all devices</span>
                        </div>
                    </div>
                </div>
            </div>
           
            <div class="files-section">
                <div class="section-header">
                    <h2 class="section-title">
                        <i class="fas fa-folder-open"></i>
                        Your Files
                    </h2>
                    <div class="files-count">
                        <i class="fas fa-file"></i>
                        {len(files_list)} files
                    </div>
                </div>
                {files_html}
            </div>
        </div>
       
        <script>
            // Анимация при выборе файла
            document.getElementById('fileInput').addEventListener('change', function(e) {{
                if (this.files.length > 0) {{
                    const uploadBtn = document.querySelector('.btn-upload');
                    uploadBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Ready to Upload';
                    uploadBtn.style.background = 'linear-gradient(135deg, #f59e0b, #d97706)';
                   
                    setTimeout(() => {{
                        uploadBtn.innerHTML = '<i class="fas fa-upload"></i> Upload File';
                        uploadBtn.style.background = 'linear-gradient(135deg, #10b981, #059669)';
                    }}, 1500);
                }}
            }});
           
            // Плавная анимация карточек при загрузке
            document.addEventListener('DOMContentLoaded', function() {{
                const fileCards = document.querySelectorAll('.file-card');
                fileCards.forEach((card, index) => {{
                    card.style.animationDelay = `${{index * 0.1}}s`;
                    card.style.opacity = '0';
                    card.style.animation = 'fadeIn 0.5s ease forwards';
                }});
            }});
        </script>
    </body>
    </html>
    '''

# Остальные маршруты остаются без изменений, только добавлю иконки в profile

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
   
    # Стили для profile с Font Awesome иконками
    return f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Profile | CloudSecure</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        <style>
            :root {{
                --primary: #6366f1;
                --primary-dark: #4f46e5;
                --secondary: #8b5cf6;
                --accent: #ec4899;
                --light: #f8fafc;
                --dark: #1e293b;
                --success: #10b981;
                --gray: #64748b;
                --radius-lg: 24px;
                --radius-md: 16px;
                --shadow: 0 20px 60px rgba(0,0,0,0.1);
            }}
           
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
           
            body {{
                font-family: 'Poppins', sans-serif;
                background: linear-gradient(135deg, #f1f5f9 0%, #e2e8f0 100%);
                min-height: 100vh;
            }}
           
            .navbar {{
                background: white;
                box-shadow: 0 4px 20px rgba(0,0,0,0.08);
                padding: 0 40px;
                height: 80px;
                display: flex;
                align-items: center;
                justify-content: space-between;
            }}
           
            .logo {{
                display: flex;
                align-items: center;
                gap: 15px;
                font-size: 26px;
                font-weight: 700;
                color: var(--primary);
                text-decoration: none;
            }}
           
            .logo-icon {{
                background: linear-gradient(135deg, var(--primary), var(--secondary));
                width: 50px;
                height: 50px;
                border-radius: 14px;
                display: flex;
                align-items: center;
                justify-content: center;
                color: white;
                font-size: 24px;
            }}
           
            .nav-btn {{
                padding: 12px 24px;
                border-radius: var(--radius-md);
                text-decoration: none;
                font-weight: 500;
                font-size: 15px;
                transition: all 0.3s ease;
                display: flex;
                align-items: center;
                gap: 10px;
            }}
           
            .nav-btn.primary {{
                background: linear-gradient(135deg, var(--primary), var(--secondary));
                color: white;
                box-shadow: 0 4px 15px rgba(99, 102, 241, 0.3);
            }}
           
            .nav-btn.primary:hover {{
                transform: translateY(-3px);
                box-shadow: 0 8px 25px rgba(99, 102, 241, 0.4);
            }}
           
            .nav-btn.secondary {{
                background: white;
                color: var(--gray);
                border: 2px solid var(--gray-light);
            }}
           
            .container {{
                max-width: 1200px;
                margin: 40px auto;
                padding: 0 20px;
            }}
           
            .profile-card {{
                background: white;
                border-radius: var(--radius-lg);
                box-shadow: var(--shadow);
                overflow: hidden;
                animation: fadeIn 0.8s ease;
            }}
           
            @keyframes fadeIn {{
                from {{ opacity: 0; transform: translateY(30px); }}
                to {{ opacity: 1; transform: translateY(0); }}
            }}
           
            .profile-header {{
                background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
                padding: 80px 40px;
                text-align: center;
                color: white;
                position: relative;
                overflow: hidden;
            }}
           
            .profile-header::before {{
                content: '';
                position: absolute;
                top: -50%;
                left: -50%;
                width: 200%;
                height: 200%;
                background: radial-gradient(circle, rgba(255,255,255,0.1) 1px, transparent 1px);
                background-size: 30px 30px;
                opacity: 0.2;
                animation: float 20s linear infinite;
            }}
           
            .avatar-large {{
                width: 150px;
                height: 150px;
                background: linear-gradient(135deg, #ff9a9e 0%, #fad0c4 100%);
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 60px;
                font-weight: 700;
                margin: 0 auto 30px;
                border: 6px solid white;
                box-shadow: 0 20px 50px rgba(0,0,0,0.2);
                position: relative;
                z-index: 1;
            }}
           
            .profile-header h1 {{
                font-size: 42px;
                font-weight: 700;
                margin-bottom: 15px;
                position: relative;
                z-index: 1;
            }}
           
            .profile-header p {{
                font-size: 18px;
                opacity: 0.9;
                position: relative;
                z-index: 1;
            }}
           
            .profile-stats {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 25px;
                padding: 50px;
            }}
           
            .stat-card {{
                background: var(--light);
                border-radius: var(--radius-md);
                padding: 35px 30px;
                text-align: center;
                transition: all 0.3s ease;
                border: 2px solid transparent;
            }}
           
            .stat-card:hover {{
                transform: translateY(-10px);
                border-color: var(--primary);
                box-shadow: 0 15px 40px rgba(0,0,0,0.1);
            }}
           
            .stat-card.blue {{
                background: linear-gradient(135deg, var(--primary), var(--secondary));
                color: white;
            }}
           
            .stat-card.green {{
                background: linear-gradient(135deg, var(--success), #059669);
                color: white;
            }}
           
            .stat-card.pink {{
                background: linear-gradient(135deg, var(--accent), #db2777);
                color: white;
            }}
           
            .stat-card.orange {{
                background: linear-gradient(135deg, #f59e0b, #d97706);
                color: white;
            }}
           
            .stat-icon {{
                font-size: 48px;
                margin-bottom: 20px;
                opacity: 0.9;
            }}
           
            .stat-value {{
                font-size: 52px;
                font-weight: 700;
                margin-bottom: 10px;
            }}
           
            .stat-label {{
                font-size: 18px;
                opacity: 0.9;
            }}
           
            .profile-info {{
                padding: 50px;
                background: var(--light);
            }}
           
            .info-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
                gap: 25px;
                margin-bottom: 40px;
            }}
           
            .info-item {{
                background: white;
                padding: 30px;
                border-radius: var(--radius-md);
                box-shadow: 0 4px 20px rgba(0,0,0,0.05);
                transition: all 0.3s ease;
            }}
           
            .info-item:hover {{
                transform: translateY(-5px);
                box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            }}
           
            .info-icon {{
                width: 60px;
                height: 60px;
                background: linear-gradient(135deg, rgba(99, 102, 241, 0.1), rgba(139, 92, 246, 0.1));
                border-radius: 16px;
                display: flex;
                align-items: center;
                justify-content: center;
                color: var(--primary);
                font-size: 28px;
                margin-bottom: 20px;
            }}
           
            .info-content h3 {{
                color: var(--gray);
                font-size: 14px;
                text-transform: uppercase;
                letter-spacing: 1px;
                margin-bottom: 10px;
            }}
           
            .info-content p {{
                font-size: 22px;
                font-weight: 600;
                color: var(--dark);
            }}
           
            .features {{
                background: white;
                padding: 40px;
                border-radius: var(--radius-md);
                margin-top: 30px;
            }}
           
            .features h2 {{
                color: var(--dark);
                margin-bottom: 30px;
                display: flex;
                align-items: center;
                gap: 15px;
                font-size: 28px;
            }}
           
            .feature-list {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
            }}
           
            .feature-item {{
                display: flex;
                align-items: center;
                gap: 20px;
                padding: 20px;
                background: var(--light);
                border-radius: var(--radius-md);
                transition: all 0.3s ease;
            }}
           
            .feature-item:hover {{
                background: white;
                transform: translateX(10px);
                box-shadow: 0 5px 20px rgba(0,0,0,0.05);
            }}
           
            .feature-item i {{
                color: var(--primary);
                font-size: 24px;
                width: 40px;
            }}
           
            @media (max-width: 768px) {{
                .navbar {{
                    padding: 0 20px;
                    flex-direction: column;
                    height: auto;
                    padding: 20px;
                    gap: 20px;
                }}
               
                .profile-stats {{
                    grid-template-columns: 1fr;
                    padding: 30px 20px;
                }}
               
                .profile-info {{
                    padding: 30px 20px;
                }}
               
                .info-grid {{
                    grid-template-columns: 1fr;
                }}
               
                .profile-header {{
                    padding: 40px 20px;
                }}
               
                .avatar-large {{
                    width: 120px;
                    height: 120px;
                    font-size: 48px;
                }}
               
                .profile-header h1 {{
                    font-size: 32px;
                }}
            }}
        </style>
    </head>
    <body>
        <nav class="navbar">
            <a href="/dashboard" class="logo">
                <div class="logo-icon">
                    <i class="fas fa-cloud"></i>
                </div>
                <span>CloudSecure</span>
            </a>
            <div>
                <a href="/dashboard" class="nav-btn primary">
                    <i class="fas fa-tachometer-alt"></i>
                    Dashboard
                </a>
                <a href="/logout" class="nav-btn secondary">
                    <i class="fas fa-sign-out-alt"></i>
                    Logout
                </a>
            </div>
        </nav>
       
        <div class="container">
            <div class="profile-card">
                <div class="profile-header">
                    <div class="avatar-large">
                        {session["username"][0].upper()}
                    </div>
                    <h1>{session["username"]}</h1>
                    <p>Premium Cloud Storage User</p>
                </div>
               
                <div class="profile-stats">
                    <div class="stat-card blue">
                        <div class="stat-icon">
                            <i class="fas fa-file"></i>
                        </div>
                        <div class="stat-value">{total_files}</div>
                        <div class="stat-label">Total Files</div>
                    </div>
                    <div class="stat-card green">
                        <div class="stat-icon">
                            <i class="fas fa-database"></i>
                        </div>
                        <div class="stat-value">{total_size_mb}</div>
                        <div class="stat-label">Storage Used (MB)</div>
                    </div>
                    <div class="stat-card pink">
                        <div class="stat-icon">
                            <i class="fas fa-user-check"></i>
                        </div>
                        <div class="stat-value">{user['id']}</div>
                        <div class="stat-label">User ID</div>
                    </div>
                    <div class="stat-card orange">
                        <div class="stat-icon">
                            <i class="fas fa-crown"></i>
                        </div>
                        <div class="stat-value">Premium</div>
                        <div class="stat-label">Account Tier</div>
                    </div>
                </div>
               
                <div class="profile-info">
                    <div class="info-grid">
                        <div class="info-item">
                            <div class="info-icon">
                                <i class="fas fa-user-tag"></i>
                            </div>
                            <div class="info-content">
                                <h3>Username</h3>
                                <p>{user['username']}</p>
                            </div>
                        </div>
                        <div class="info-item">
                            <div class="info-icon">
                                <i class="fas fa-calendar-plus"></i>
                            </div>
                            <div class="info-content">
                                <h3>Member Since</h3>
                                <p>{join_date}</p>
                            </div>
                        </div>
                        <div class="info-item">
                            <div class="info-icon">
                                <i class="fas fa-cloud-upload-alt"></i>
                            </div>
                            <div class="info-content">
                                <h3>First Upload</h3>
                                <p>{first_upload}</p>
                            </div>
                        </div>
                        <div class="info-item">
                            <div class="info-icon">
                                <i class="fas fa-shield-alt"></i>
                            </div>
                            <div class="info-content">
                                <h3>Security Level</h3>
                                <p>Military Grade</p>
                            </div>
                        </div>
                    </div>
                   
                    <div class="features">
                        <h2>
                            <i class="fas fa-star"></i>
                            Premium Features
                        </h2>
                        <div class="feature-list">
                            <div class="feature-item">
                                <i class="fas fa-lock"></i>
                                <span>End-to-end encryption</span>
                            </div>
                            <div class="feature-item">
                                <i class="fas fa-infinity"></i>
                                <span>Persistent storage</span>
                            </div>
                            <div class="feature-item">
                                <i class="fas fa-bolt"></i>
                                <span>High-speed transfers</span>
                            </div>
                            <div class="feature-item">
                                <i class="fas fa-mobile-alt"></i>
                                <span>Mobile optimized</span>
                            </div>
                            <div class="feature-item">
                                <i class="fas fa-sync-alt"></i>
                                <span>Automatic backups</span>
                            </div>
                            <div class="feature-item">
                                <i class="fas fa-globe"></i>
                                <span>Global CDN</span>
                            </div>
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
