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

# 🔧 ВСЕ ДАННЫЕ ХРАНЯТСЯ ТОЛЬКО В CLOUDINARY
def save_to_cloudinary(data, path):
    """Сохраняет данные в Cloudinary с повторными попытками"""
    max_retries = 3
    for attempt in range(max_retries):
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
            print(f"❌ Attempt {attempt + 1} error saving {path}: {e}")
            if attempt < max_retries - 1:
                time.sleep(2)
    return False

def load_from_cloudinary(path):
    """Загружает данные из Cloudinary с повторными попытками"""
    max_retries = 5  # Увеличили количество попыток
    for attempt in range(max_retries):
        try:
            url = cloudinary.utils.cloudinary_url(
                f"database/{path}",
                resource_type='raw',
                type='upload'
            )[0]
            
            url_with_cache = f"{url}?t={int(time.time())}"
            print(f"🔍 Attempt {attempt + 1}: Loading from: {url_with_cache}")
            
            response = requests.get(url_with_cache, timeout=10)
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Successfully loaded from Cloudinary: {path}")
                return data
            else:
                print(f"⚠️ Attempt {attempt + 1}: Failed to load {path}, status: {response.status_code}")
        except Exception as e:
            print(f"⚠️ Attempt {attempt + 1}: Error loading {path}: {e}")
        
        if attempt < max_retries - 1:
            time.sleep(3)  # Увеличили задержку
    
    print(f"❌ Failed to load {path} after {max_retries} attempts")
    return None

# 🔧 БАЗА ДАННЫХ В CLOUDINARY
def get_users():
    """Получает всех пользователей"""
    users = load_from_cloudinary("users") or {}
    if not users:
        users = {"admin": {"username": "admin", "password": generate_password_hash("admin123")}}
        save_to_cloudinary(users, "users")
        print("🔧 Created default admin user")
    return users

def save_users(users):
    """Сохраняет пользователей с гарантированным сохранением"""
    success = save_to_cloudinary(users, "users")
    if success:
        time.sleep(4)  # Увеличили задержку для Cloudinary
    return success

def get_user_files(user_id):
    """Получает файлы пользователя"""
    files = load_from_cloudinary(f"files_{user_id}") or []
    print(f"📁 Loaded {len(files)} files for user {user_id}")
    return files

def save_user_files(user_id, files):
    """Сохраняет файлы пользователя"""
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
        
        print(f"🔍 Attempting login for user: {username}")
        print(f"🔍 Available users in database: {list(users.keys())}")
        
        user = users.get(username)
        if user:
            print(f"🔍 User found: {username}")
            if check_password_hash(user['password'], password):
                session['user_id'] = username
                session['username'] = username
                add_flash_message('Login successful!', 'success')
                return redirect('/dashboard')
            else:
                print(f"❌ Invalid password for user: {username}")
        else:
            print(f"❌ User not found: {username}")
        
        add_flash_message('Invalid username or password', 'error')
    
    return '''
    <html><body style="margin: 50px; font-family: Arial;">
        <div style="max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1);">
            <h2>🔐 Login to Cloud Storage</h2>
            <div style="background: #e3f2fd; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
                <strong>Demo Account:</strong><br>
                👤 Username: <code>admin</code><br>
                🔑 Password: <code>admin123</code>
            </div>
            ''' + get_flash_html() + '''
            <form method="POST">
                <div style="margin-bottom: 15px;">
                    <label style="display: block; margin-bottom: 5px; font-weight: bold;">Username:</label>
                    <input type="text" name="username" placeholder="Enter your username" required style="width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 5px;">
                </div>
                <div style="margin-bottom: 20px;">
                    <label style="display: block; margin-bottom: 5px; font-weight: bold;">Password:</label>
                    <input type="password" name="password" placeholder="Enter your password" required style="width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 5px;">
                </div>
                <button type="submit" style="width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 16px;">🚀 Login</button>
            </form>
            <div style="text-align: center; margin-top: 25px; padding-top: 20px; border-top: 1px solid #eee;">
                <p style="margin-bottom: 15px; color: #666;">Don't have an account?</p>
                <a href="/register" style="display: block; padding: 12px; background: #28a745; color: white; border-radius: 5px; text-decoration: none; font-weight: bold;">📝 Create New Account</a>
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
        
        # СОХРАНЯЕМ ПОЛЬЗОВАТЕЛЯ
        users[username] = {
            'username': username, 
            'password': generate_password_hash(password),
            'created_at': datetime.now().isoformat()
        }
        
        print("💾 Saving user to Cloudinary...")
        if save_users(users):
            print("✅ User saved to Cloudinary successfully")
            
            # 🔥 ВАЖНО: Проверяем что пользователь действительно сохранился
            print("🔄 Verifying user was saved...")
            time.sleep(5)  # Даем больше времени Cloudinary
            
            verify_users = get_users()
            if username in verify_users:
                print(f"🎉 SUCCESS: User {username} verified in Cloudinary!")
                
                # Создаем хранилище файлов
                save_user_files(username, [])
                
                # Автоматически входим
                session['user_id'] = username
                session['username'] = username
                add_flash_message(f'🎉 Registration successful! Welcome {username}', 'success')
                return redirect('/dashboard')
            else:
                print(f"❌ FAILED: User {username} not found in Cloudinary after saving!")
                print(f"🔍 Current users in database: {list(verify_users.keys())}")
                
                # Удаляем из локальной памяти
                if username in users:
                    del users[username]
                
                add_flash_message('Registration failed - user not saved properly. Please try again.', 'error')
                return redirect('/register')
        else:
            print("❌ FAILED to save user to Cloudinary")
            if username in users:
                del users[username]
            add_flash_message('Registration failed - could not save to database. Please try again.', 'error')
            return redirect('/register')
    
    return '''
    <html><body style="margin: 50px; font-family: Arial;">
        <div style="max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1);">
            <h2>📝 Create New Account</h2>
            <div style="background: #fff3cd; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
                <strong>Requirements:</strong><br>
                • Username: 3+ characters<br>
                • Password: 6+ characters
            </div>
            ''' + get_flash_html() + '''
            <form method="POST">
                <div style="margin-bottom: 15px;">
                    <label style="display: block; margin-bottom: 5px; font-weight: bold;">Username:</label>
                    <input type="text" name="username" placeholder="Choose a username (3+ chars)" required style="width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 5px;">
                </div>
                <div style="margin-bottom: 20px;">
                    <label style="display: block; margin-bottom: 5px; font-weight: bold;">Password:</label>
                    <input type="password" name="password" placeholder="Create password (6+ chars)" required style="width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 5px;">
                </div>
                <button type="submit" style="width: 100%; padding: 12px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 16px;">✅ Create Account</button>
            </form>
            <p style="text-align: center; margin-top: 25px; padding-top: 20px; border-top: 1px solid #eee;">
                <a href="/login" style="color: #007bff; text-decoration: none;">← Back to Login</a>
            </p>
        </div>
    </body></html>
    '''

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    
    user_id = session['user_id']
    user_files = get_user_files(user_id)
    
    files_html = ""
    for file in user_files:
        files_html += f'''
        <div style="display: flex; justify-content: space-between; align-items: center; padding: 15px; border-bottom: 1px solid #eee;">
            <div>
                <strong>📁 {file.get('name', 'Unnamed')}</strong><br>
                <small>Size: {file.get('size', 0)} KB | Uploaded: {file.get('date', 'Unknown')}</small>
            </div>
            <div>
                <a href="/download/{file['id']}" style="padding: 8px 15px; background: #007bff; color: white; border-radius: 5px; text-decoration: none; margin: 5px;">⬇️ Download</a>
                <a href="/delete/{file['id']}" onclick="return confirm('Delete this file?')" style="padding: 8px 15px; background: #dc3545; color: white; border-radius: 5px; text-decoration: none; margin: 5px;">🗑️ Delete</a>
            </div>
        </div>
        '''
    
    if not files_html:
        files_html = '<p style="text-align: center; color: #666; padding: 40px;">No files yet. Upload your first file!</p>'
    
    return f'''
    <html><body style="margin: 0; font-family: Arial; background: #f0f0f0;">
        <div style="background: white; padding: 20px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
            <h2 style="margin: 0;">☁️ Cloud Storage</h2>
            <div>
                Welcome, <strong>{session['username']}</strong>! 
                <a href="/test-login" style="margin-left: 10px; background: #17a2b8; color: white; padding: 8px 15px; border-radius: 5px; text-decoration: none;">🧪 Test Login</a>
                <a href="/debug" style="margin-left: 10px; background: #6c757d; color: white; padding: 8px 15px; border-radius: 5px; text-decoration: none;">🔧 Debug</a>
                <a href="/logout" style="margin-left: 10px; background: #6c757d; color: white; padding: 8px 15px; border-radius: 5px; text-decoration: none;">Logout</a>
            </div>
        </div>
        
        <div style="max-width: 1000px; margin: 20px auto; padding: 20px;">
            {get_flash_html()}
            
            <div style="background: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <h3 style="margin-top: 0;">📤 Upload File</h3>
                <form method="POST" action="/upload" enctype="multipart/form-data" style="display: flex; gap: 10px; align-items: center;">
                    <input type="file" name="file" required style="flex: 1; padding: 10px; border: 1px solid #ddd; border-radius: 5px;">
                    <button type="submit" style="padding: 10px 20px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer;">📎 Upload</button>
                </form>
            </div>
            
            <div style="background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <h3 style="margin-top: 0;">📁 Your Files ({len(user_files)})</h3>
                <div style="border: 1px solid #eee; border-radius: 5px; min-height: 100px;">
                    {files_html}
                </div>
            </div>
        </div>
    </body></html>
    '''

# 🔧 НОВЫЙ МАРШРУТ ДЛЯ ТЕСТИРОВАНИЯ ВХОДА
@app.route('/test-login')
def test_login():
    """Страница для тестирования входа после регистрации"""
    if 'user_id' not in session:
        return redirect('/login')
    
    current_user = session['user_id']
    users = get_users()
    
    user_exists = current_user in users
    user_files = get_user_files(current_user)
    
    return f'''
    <html><body style="margin: 0; font-family: Arial; background: #f0f0f0;">
        <div style="background: white; padding: 20px; display: flex; justify-content: space-between; align-items: center;">
            <h2 style="margin: 0;">🧪 Login Test</h2>
            <div>
                <a href="/dashboard" style="background: #007bff; color: white; padding: 8px 15px; border-radius: 5px; text-decoration: none;">← Back to Dashboard</a>
            </div>
        </div>
        
        <div style="max-width: 800px; margin: 20px auto; padding: 20px;">
            <div style="background: white; padding: 30px; border-radius: 10px; margin-bottom: 20px;">
                <h3 style="margin-top: 0;">User Login Test</h3>
                <div style="display: grid; gap: 15px;">
                    <div style="padding: 15px; background: {'#d4edda' if user_exists else '#f8d7da'}; border-radius: 5px;">
                        <strong>User in Database:</strong> {'✅ YES' if user_exists else '❌ NO'}<br>
                        <small>Username: {current_user}</small>
                    </div>
                    <div style="padding: 15px; background: #e7f3ff; border-radius: 5px;">
                        <strong>Files Count:</strong> {len(user_files)}<br>
                        <strong>All Users in DB:</strong> {", ".join(users.keys())}
                    </div>
                </div>
            </div>
            
            <div style="background: #fff3cd; padding: 20px; border-radius: 10px;">
                <h4>📝 How to test:</h4>
                <ol>
                    <li>Logout from current account</li>
                    <li>Try to login with the same username/password</li>
                    <li>If login works - user was saved correctly!</li>
                </ol>
                <p><strong>Status:</strong> {'✅ READY FOR TEST' if user_exists else '❌ USER NOT SAVED'}</p>
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
    <html><body style="margin: 0; font-family: Arial; background: #f0f0f0;">
        <div style="background: white; padding: 20px; display: flex; justify-content: space-between; align-items: center;">
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
    
    users = get_users()
    print(f"👥 Loaded {len(users)} users from Cloudinary: {list(users.keys())}")
    
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
