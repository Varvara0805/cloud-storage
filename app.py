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
   
    # Если нет пользователей, создаем админа
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

# Инициализируем при старте
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
      
        print(f"🔐 Попытка входа: {username}")
      
        user = get_user_by_username(username)
      
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['username']
            session['username'] = user['username']
            add_flash_message('Login successful!', 'success')
            print(f"✅ Успешный вход: {username}")
            return redirect('/dashboard')
        else:
            print(f"❌ Неудачный вход: {username}")
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
      
        print(f"📝 Попытка регистрации: {username}")
      
        if len(password) < 6:
            add_flash_message('Password too short', 'error')
            return redirect('/register')
      
        if get_user_by_username(username):
            print(f"❌ Пользователь уже существует: {username}")
            add_flash_message('User already exists', 'error')
            return redirect('/register')
      
        try:
            hashed_pw = generate_password_hash(password)
            new_user = add_user(username, hashed_pw)
           
            print(f"✅ ПОЛЬЗОВАТЕЛЬ СОХРАНЕН В CLOUDINARY: {username}")
            add_flash_message('Registration successful!', 'success')
            return redirect('/login')
           
        except Exception as e:
            print(f"❌ Ошибка регистрации: {e}")
            add_flash_message(f'Registration error: {str(e)}', 'error')
  
    return f'''
    <html><body style="margin: 50px; font-family: Arial;">
        <div style="max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1);">
            <h2>📝 Register</h2>
            {get_flash_html()}
            <form method="POST">
                <input type="text" name="username" placeholder="Username" required style="width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px;">
                <input type="password" name="password" placeholder="Password (6+ chars)" required style="width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px;">
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
    files_list = get_user_files(user_id)
  
    files_html = ""
    for file in files_list:
        # Безопасное получение размера файла
        size_kb = 0
        if file.get("file_size"):
            try:
                size_kb = round(float(file["file_size"])/1024, 1)
            except:
                size_kb = 0
       
        # Безопасное получение даты
        upload_date = 'Unknown'
        if file.get("uploaded_at"):
            try:
                upload_date = datetime.strptime(str(file["uploaded_at"]), '%Y-%m-%d %H:%M:%S').strftime('%d.%m.%Y %H:%M')
            except:
                try:
                    upload_date = datetime.strptime(str(file["uploaded_at"]), '%Y-%m-%d').strftime('%d.%m.%Y')
                except:
                    upload_date = str(file["uploaded_at"])[:16]
       
        # Безопасное получение имени файла
        filename = file.get("original_filename", "Unknown file")
        file_id = file.get("file_id", "")
       
        files_html += f'''
        <div style="display: flex; justify-content: space-between; align-items: center; padding: 15px; border-bottom: 1px solid #eee;">
            <div>
                <strong>📁 {filename}</strong><br>
                <small>Size: {size_kb} KB | Uploaded: {upload_date}</small>
            </div>
            <div>
                <a href="/download/{file_id}" style="padding: 8px 15px; background: #007bff; color: white; border-radius: 5px; text-decoration: none; margin: 5px;">⬇️ Download</a>
                <a href="/delete/{file_id}" onclick="return confirm('Are you sure you want to delete {filename}?')" style="padding: 8px 15px; background: #dc3545; color: white; border-radius: 5px; text-decoration: none; margin: 5px;">🗑️ Delete</a>
            </div>
        </div>
        '''
  
    if not files_html:
        files_html = '<p style="text-align: center; color: #666; padding: 40px;">No files yet. Upload your first file!</p>'
  
    return f'''
    <html><body style="margin: 0; font-family: Arial; background: #f0f0f0;">
        <div style="background: white; padding: 20px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
            <h2 style="margin: 0;">☁️ Cloud Storage</h2>
            <div style="display: flex; align-items: center; gap: 15px;">
                <span>Welcome, <strong>{session["username"]}</strong>!</span>
                <a href="/profile" style="background: #17a2b8; color: white; padding: 8px 15px; border-radius: 5px; text-decoration: none;">👤 Profile</a>
                <a href="/logout" style="background: #6c757d; color: white; padding: 8px 15px; border-radius: 5px; text-decoration: none;">🚪 Logout</a>
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
                <p style="color: #666; font-size: 14px; margin-top: 10px;">Max file size: 16MB | Files are encrypted before upload</p>
                <p style="color: #28a745; font-size: 12px; margin-top: 5px;">✅ Все данные сохраняются после перезапуска сервера</p>
            </div>
          
            <div style="background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <h3 style="margin-top: 0;">📁 Your Files ({len(files_list)})</h3>
                <div style="border: 1px solid #eee; border-radius: 5px;">{files_html}</div>
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
      
        if file_size > 16 * 1024 * 1024:
            add_flash_message('File too large (max 16MB)', 'error')
            return redirect('/dashboard')
      
        # Шифруем и загружаем в Cloudinary
        encrypted_data = encrypt_file(file_data)
        result = cloudinary.uploader.upload(
            encrypted_data,
            public_id=f"storage/{user_id}/{file_id}_{filename}",
            resource_type="raw"
        )
      
        # Сохраняем метаданные
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
      
        add_flash_message(f'✅ File "{filename}" uploaded successfully!', 'success')
      
    except Exception as e:
        add_flash_message(f'❌ Upload error: {str(e)}', 'error')
  
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
            # Удаляем файл из Cloudinary
            if file['cloudinary_public_id']:
                cloudinary.uploader.destroy(file['cloudinary_public_id'], resource_type="raw")
          
            # Удаляем запись из базы данных
            delete_file_record(file_id, user_id)
          
            add_flash_message(f'✅ File "{file["original_filename"]}" deleted successfully!', 'success')
        except Exception as e:
            add_flash_message(f'❌ Delete error: {str(e)}', 'error')
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
   
    # Получаем статистику пользователя
    user_files = get_user_files(user_id)
    total_size = sum(f.get('file_size', 0) for f in user_files)
    total_files = len(user_files)
  
    total_size_mb = round(total_size / (1024 * 1024), 2) if total_size else 0
  
    # Форматируем даты
    join_date = 'Unknown'
    if user.get('created_at'):
        try:
            join_date = datetime.strptime(str(user['created_at']), '%Y-%m-%d %H:%M:%S').strftime('%d.%m.%Y')
        except:
            try:
                join_date = datetime.strptime(str(user['created_at']), '%Y-%m-%d').strftime('%d.%m.%Y')
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
            first_upload = min(upload_dates).strftime('%d.%m.%Y')
  
    return f'''
    <html><body style="margin: 0; font-family: Arial; background: #f0f0f0;">
        <div style="background: white; padding: 20px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
            <h2 style="margin: 0;">☁️ Cloud Storage</h2>
            <div style="display: flex; align-items: center; gap: 15px;">
                <span>Welcome, <strong>{session["username"]}</strong>!</span>
                <a href="/dashboard" style="background: #007bff; color: white; padding: 8px 15px; border-radius: 5px; text-decoration: none;">📁 Dashboard</a>
                <a href="/logout" style="background: #6c757d; color: white; padding: 8px 15px; border-radius: 5px; text-decoration: none;">🚪 Logout</a>
            </div>
        </div>
      
        <div style="max-width: 800px; margin: 20px auto; padding: 20px;">
            {get_flash_html()}
            <div style="background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <h2 style="margin-top: 0; color: #333;">👤 User Profile</h2>
              
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px;">
                    <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #007bff;">
                        <h3 style="margin-top: 0; color: #007bff;">Account Info</h3>
                        <p><strong>Username:</strong> {user['username']}</p>
                        <p><strong>Member since:</strong> {join_date}</p>
                    </div>
                  
                    <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #28a745;">
                        <h3 style="margin-top: 0; color: #28a745;">Storage Stats</h3>
                        <p><strong>Total files:</strong> {total_files}</p>
                        <p><strong>Total storage used:</strong> {total_size_mb} MB</p>
                        <p><strong>First upload:</strong> {first_upload}</p>
                    </div>
                </div>
              
                <div style="background: #e7f3ff; padding: 20px; border-radius: 8px; border: 1px solid #b3d9ff;">
                    <h3 style="margin-top: 0; color: #0056b3;">💡 Information</h3>
                    <p>✅ <strong>Data persistence:</strong> ALL users and files are saved in Cloudinary</p>
                    <p>✅ <strong>Server restart safe:</strong> Everything survives server restart</p>
                    <p>🔒 <strong>Encryption:</strong> Files are encrypted before uploading to cloud storage</p>
                    <p>☁️ <strong>Cloud storage:</strong> Database and files stored permanently in Cloudinary</p>
                    <p>🔄 <strong>Last sync:</strong> {app_data.get('last_updated', 'Just now')}</p>
                </div>
            </div>
        </div>
    </body></html>
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
