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

# 🔧 ПРОСТАЯ БАЗА В ПАМЯТИ (для мгновенного отображения)
users = {'admin': {'password': generate_password_hash('admin123'), 'username': 'admin'}}
files_db = {}

# 🔧 ФУНКЦИИ ДЛЯ CLOUDINARY
def save_to_cloudinary(data, path):
    """Сохраняет данные в Cloudinary"""
    try:
        json_str = json.dumps(data, ensure_ascii=False)
        result = cloudinary.uploader.upload(
            json_str.encode('utf-8'),
            public_id=f"db/{path}",
            resource_type="raw"
        )
        print(f"✅ Saved to Cloudinary: {path}")
        return True
    except Exception as e:
        print(f"❌ Error saving {path}: {e}")
        return False

def load_from_cloudinary(path):
    """Загружает данные из Cloudinary"""
    try:
        url = cloudinary.utils.cloudinary_url(f"db/{path}", resource_type='raw')[0]
        response = requests.get(url)
        if response.status_code == 200:
            print(f"✅ Loaded from Cloudinary: {path}")
            return response.json()
    except Exception as e:
        print(f"❌ Error loading {path}: {e}")
    return None

# 🔧 ЗАГРУЗКА ДАННЫХ ПРИ ЗАПУСКЕ
def load_all_data():
    """Загружает все данные при запуске"""
    global users, files_db
    
    print("🔄 Loading data from Cloudinary...")
    
    # Загружаем пользователей
    loaded_users = load_from_cloudinary("users")
    if loaded_users:
        users = loaded_users
        print(f"✅ Loaded {len(users)} users")
    else:
        # Создаем admin если нет данных
        users = {'admin': {'password': generate_password_hash('admin123'), 'username': 'admin'}}
        save_to_cloudinary(users, "users")
        print("🔧 Created default admin user")
    
    # Загружаем файлы
    loaded_files = load_from_cloudinary("files")
    if loaded_files:
        files_db = loaded_files
        print(f"✅ Loaded files for {len(files_db)} users")
    else:
        files_db = {}
        print("📭 No files found")

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
        user = users.get(username)
        if user and check_password_hash(user['password'], password):
            session['user_id'] = username
            session['username'] = username
            add_flash_message('Login successful!', 'success')
            return redirect('/dashboard')
        add_flash_message('Invalid credentials', 'error')
    
    return f'''
    <html><body style="margin: 50px; font-family: Arial;">
        <div style="max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1);">
            <h2>🔐 Login</h2>
            <div style="background: #e3f2fd; padding: 10px; border-radius: 5px; margin-bottom: 20px;">
                <strong>Test:</strong> admin / admin123
            </div>
            {get_flash_html()}
            <form method="POST">
                <input type="text" name="username" placeholder="Username" required style="width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px;">
                <input type="password" name="password" placeholder="Password" required style="width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px;">
                <button type="submit" style="width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer;">Login</button>
            </form>
            <p style="text-align: center; margin-top: 20px;"><a href="/register">Create account</a></p>
        </div>
    </body></html>
    '''

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if len(password) < 6:
            add_flash_message('Password must be at least 6 characters', 'error')
            return redirect('/register')
        
        if username in users:
            add_flash_message('Username already exists', 'error')
            return redirect('/register')
        
        users[username] = {'password': generate_password_hash(password), 'username': username}
        files_db[username] = []
        
        # Сохраняем в Cloudinary
        save_to_cloudinary(users, "users")
        save_to_cloudinary(files_db, "files")
        
        add_flash_message('Registration successful! Please login.', 'success')
        return redirect('/login')
    
    return f'''
    <html><body style="margin: 50px; font-family: Arial;">
        <div style="max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1);">
            <h2>📝 Register</h2>
            {get_flash_html()}
            <form method="POST">
                <input type="text" name="username" placeholder="Username" required style="width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px;">
                <input type="password" name="password" placeholder="Password (min 6 characters)" required style="width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px;">
                <button type="submit" style="width: 100%; padding: 12px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer;">Register</button>
            </form>
            <p style="text-align: center; margin-top: 20px;"><a href="/login">Back to login</a></p>
        </div>
    </body></html>
    '''

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    
    user_id = session['user_id']
    files_list = files_db.get(user_id, [])
    
    # 🔧 ОТЛАДКА В КОНСОЛИ
    print(f"🎯 Dashboard for {user_id}")
    print(f"📁 Files in memory: {len(files_list)}")
    for i, file in enumerate(files_list):
        print(f"   {i+1}. {file['name']}")
    
    files_html = ""
    for file in files_list:
        files_html += f'''
        <div style="display: flex; justify-content: space-between; align-items: center; padding: 15px; border-bottom: 1px solid #eee; background: #f9f9f9; margin: 5px; border-radius: 5px;">
            <div>
                <strong>📁 {file["name"]}</strong><br>
                <small>Size: {file["size"]} KB | Uploaded: {file["date"]}</small>
            </div>
            <div>
                <a href="/download/{file["id"]}" style="padding: 8px 15px; background: #007bff; color: white; border-radius: 5px; text-decoration: none; margin: 5px;">⬇️ Download</a>
                <a href="/delete/{file["id"]}" style="padding: 8px 15px; background: #dc3545; color: white; border-radius: 5px; text-decoration: none; margin: 5px;">🗑️ Delete</a>
            </div>
        </div>
        '''
    
    if not files_html:
        files_html = '''
        <div style="text-align: center; color: #666; padding: 40px; background: #f9f9f9; border-radius: 10px;">
            <h3>📭 No files yet</h3>
            <p>Upload your first file using the form above!</p>
        </div>
        '''
    
    return f'''
    <html><body style="margin: 0; font-family: Arial; background: #f0f0f0;">
        <div style="background: white; padding: 20px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1);">
            <h2 style="margin: 0;">☁️ Cloud Storage</h2>
            <div>Welcome, <strong>{session["username"]}</strong>! 
                <a href="/logout" style="margin-left: 20px; background: #6c757d; color: white; padding: 8px 15px; border-radius: 5px; text-decoration: none;">Logout</a>
            </div>
        </div>
        
        <div style="max-width: 1000px; margin: 20px auto; padding: 20px;">
            {get_flash_html()}
            <div style="background: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <h3 style="margin-top: 0;">📤 Upload File</h3>
                <form method="POST" action="/upload" enctype="multipart/form-data" style="display: flex; gap: 10px; align-items: center;">
                    <input type="file" name="file" required style="flex: 1; padding: 10px; border: 1px solid #ddd; border-radius: 5px;">
                    <button type="submit" style="padding: 10px 20px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer; font-weight: bold;">📎 UPLOAD FILE</button>
                </form>
            </div>
            
            <div style="background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <h3 style="margin-top: 0;">📁 Your Files ({len(files_list)})</h3>
                <div style="border: 2px solid #eee; border-radius: 10px; min-height: 200px;">
                    {files_html}
                </div>
            </div>
        </div>
    </body></html>
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
        
        print(f"🔧 Uploading file: {filename} ({file_size} bytes)")
        
        # Шифруем и загружаем в Cloudinary
        encrypted_data = encrypt_file(file_data)
        result = cloudinary.uploader.upload(
            encrypted_data,
            public_id=f"storage/{user_id}/{file_id}_{filename}",
            resource_type="raw"
        )
        
        print(f"✅ File uploaded to Cloudinary: {result['secure_url']}")
        
        # 🔧 ДОБАВЛЯЕМ В ПАМЯТЬ (СРАЗУ ВИДНО)
        if user_id not in files_db:
            files_db[user_id] = []
        
        # Проверяем на дубликаты
        existing_files = [f for f in files_db[user_id] if f['id'] == file_id]
        if not existing_files:
            files_db[user_id].append({
                'id': file_id,
                'name': filename,
                'size': round(file_size / 1024, 1),
                'url': result['secure_url'],
                'public_id': result['public_id'],
                'date': datetime.now().strftime("%Y-%m-%d %H:%M")
            })
            
            # 🔧 СОХРАНЯЕМ В CLOUDINARY
            save_to_cloudinary(files_db, "files")
            
            print(f"✅ File added to memory and Cloudinary")
            print(f"📁 User {user_id} now has {len(files_db[user_id])} files")
            
            add_flash_message(f'✅ File "{filename}" uploaded successfully!', 'success')
        else:
            add_flash_message(f'⚠️ File "{filename}" already exists', 'warning')
        
    except Exception as e:
        print(f"❌ Upload error: {e}")
        add_flash_message(f'❌ Upload error: {str(e)}', 'error')
    
    return redirect('/dashboard')

@app.route('/download/<file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect('/login')
    
    user_id = session['user_id']
    files_list = files_db.get(user_id, [])
    
    file_data = next((f for f in files_list if f['id'] == file_id), None)
    if file_data:
        try:
            response = requests.get(file_data['url'])
            decrypted_data = decrypt_file(response.content)
            return send_file(io.BytesIO(decrypted_data), as_attachment=True, download_name=file_data['name'])
        except:
            add_flash_message('Download error', 'error')
    else:
        add_flash_message('File not found', 'error')
    
    return redirect('/dashboard')

@app.route('/delete/<file_id>')
def delete_file(file_id):
    if 'user_id' not in session:
        return redirect('/login')
    
    user_id = session['user_id']
    if user_id in files_db:
        files_db[user_id] = [f for f in files_db[user_id] if f['id'] != file_id]
        save_to_cloudinary(files_db, "files")
        add_flash_message('File deleted successfully!', 'success')
    
    return redirect('/dashboard')

@app.route('/logout')
def logout():
    session.clear()
    add_flash_message('Logged out', 'info')
    return redirect('/login')

if __name__ == '__main__':
    # 🔧 ЗАГРУЖАЕМ ДАННЫЕ ПРИ ЗАПУСКЕ
    load_all_data()
    
    print("🚀 Server started!")
    print(f"👥 Users: {len(users)}")
    print(f"📁 Files in database: {len(files_db)} users")
    
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
