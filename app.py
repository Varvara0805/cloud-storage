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

# 🔧 ФУНКЦИИ ДЛЯ CLOUDINARY
def save_to_cloudinary(data, path):
    """Сохраняет данные в Cloudinary"""
    try:
        json_str = json.dumps(data, ensure_ascii=False, indent=2)
        result = cloudinary.uploader.upload(
            json_str.encode('utf-8'),
            public_id=f"database/{path}",
            resource_type="raw",
            type="upload"
        )
        print(f"✅ СОХРАНЕНО в Cloudinary: {path}")
        # Даем время на сохранение
        time.sleep(2)
        return True
    except Exception as e:
        print(f"❌ ОШИБКА сохранения {path}: {e}")
        return False

def load_from_cloudinary(path):
    """Загружает данные из Cloudinary"""
    try:
        url = cloudinary.utils.cloudinary_url(
            f"database/{path}",
            resource_type='raw',
            type='upload'
        )[0]
        
        # Добавляем timestamp чтобы избежать кеширования
        url_with_cache = f"{url}?t={int(time.time())}"
        print(f"🔍 Загружаем: {url_with_cache}")
        
        response = requests.get(url_with_cache, timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ ЗАГРУЖЕНО из Cloudinary: {path}")
            return data
        else:
            print(f"❌ Ошибка загрузки {path}, статус: {response.status_code}")
    except Exception as e:
        print(f"❌ Ошибка загрузки {path}: {e}")
    return None

# 🔧 БАЗА ДАННЫХ
def get_users():
    """Получает всех пользователей"""
    users = load_from_cloudinary("users")
    if users is None:
        # Если файла нет - создаем admin
        users = {"admin": {"username": "admin", "password": generate_password_hash("admin123")}}
        save_to_cloudinary(users, "users")
        print("🔧 Создан пользователь admin: admin123")
    else:
        print(f"👥 Загружено пользователей: {len(users)}")
    return users

def save_users(users):
    """Сохраняет пользователей"""
    return save_to_cloudinary(users, "users")

def get_user_files(user_id):
    """Получает файлы пользователя"""
    files = load_from_cloudinary(f"files_{user_id}")
    if files is None:
        files = []
    print(f"📁 Файлов у {user_id}: {len(files)}")
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
        
        print(f"🔍 Попытка входа: {username}")
        print(f"🔍 Доступные пользователи: {list(users.keys())}")
        
        user = users.get(username)
        if user and check_password_hash(user['password'], password):
            session['user_id'] = username
            session['username'] = username
            add_flash_message('Вход успешен!', 'success')
            return redirect('/dashboard')
        else:
            add_flash_message('Неверный логин или пароль', 'error')
    
    return '''
    <html><body style="margin: 50px; font-family: Arial;">
        <div style="max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1);">
            <h2>🔐 Вход в Cloud Storage</h2>
            <div style="background: #e3f2fd; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
                <strong>Тестовый аккаунт:</strong><br>
                👤 Логин: <code>admin</code><br>
                🔑 Пароль: <code>admin123</code>
            </div>
            ''' + get_flash_html() + '''
            <form method="POST">
                <input type="text" name="username" placeholder="Логин" required style="width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px;">
                <input type="password" name="password" placeholder="Пароль" required style="width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px;">
                <button type="submit" style="width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer;">Войти</button>
            </form>
            <p style="text-align: center; margin-top: 20px;"><a href="/register">Создать аккаунт</a></p>
        </div>
    </body></html>
    '''

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        if len(username) < 3:
            add_flash_message('Логин должен быть от 3 символов', 'error')
            return redirect('/register')
            
        if len(password) < 6:
            add_flash_message('Пароль должен быть от 6 символов', 'error')
            return redirect('/register')
        
        users = get_users()
        if username in users:
            add_flash_message('Пользователь уже существует', 'error')
            return redirect('/register')
        
        print(f"🔧 Создаем пользователя: {username}")
        
        # Добавляем пользователя
        users[username] = {
            'username': username, 
            'password': generate_password_hash(password),
            'created_at': datetime.now().isoformat()
        }
        
        # Сохраняем пользователей
        if save_users(users):
            print(f"✅ Пользователь {username} сохранен")
            
            # Создаем хранилище файлов
            save_user_files(username, [])
            
            # Автоматически входим
            session['user_id'] = username
            session['username'] = username
            add_flash_message(f'✅ Регистрация успешна! Добро пожаловать {username}', 'success')
            return redirect('/dashboard')
        else:
            add_flash_message('Ошибка регистрации', 'error')
            return redirect('/register')
    
    return '''
    <html><body style="margin: 50px; font-family: Arial;">
        <div style="max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1);">
            <h2>📝 Регистрация</h2>
            ''' + get_flash_html() + '''
            <form method="POST">
                <input type="text" name="username" placeholder="Логин (от 3 символов)" required style="width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px;">
                <input type="password" name="password" placeholder="Пароль (от 6 символов)" required style="width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px;">
                <button type="submit" style="width: 100%; padding: 12px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer;">Создать аккаунт</button>
            </form>
            <p style="text-align: center; margin-top: 20px;"><a href="/login">Назад к входу</a></p>
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
            <div><strong>📁 {file['name']}</strong><br><small>Размер: {file['size']} KB | Загружен: {file['date']}</small></div>
            <div>
                <a href="/download/{file['id']}" style="padding: 8px 15px; background: #007bff; color: white; border-radius: 5px; text-decoration: none; margin: 5px;">⬇️ Скачать</a>
                <a href="/delete/{file['id']}" style="padding: 8px 15px; background: #dc3545; color: white; border-radius: 5px; text-decoration: none; margin: 5px;">🗑️ Удалить</a>
            </div>
        </div>
        '''
    
    if not files_html:
        files_html = '<p style="text-align: center; color: #666; padding: 40px;">Файлов пока нет. Загрузите первый файл!</p>'
    
    return f'''
    <html><body style="margin: 0; font-family: Arial; background: #f0f0f0;">
        <div style="background: white; padding: 20px; display: flex; justify-content: space-between; align-items: center;">
            <h2 style="margin: 0;">☁️ Cloud Storage</h2>
            <div>Привет, <strong>{session['username']}</strong>! 
                <a href="/logout" style="margin-left: 20px; background: #6c757d; color: white; padding: 8px 15px; border-radius: 5px; text-decoration: none;">Выйти</a>
            </div>
        </div>
        
        <div style="max-width: 1000px; margin: 20px auto; padding: 20px;">
            {get_flash_html()}
            <div style="background: white; padding: 30px; border-radius: 10px; margin-bottom: 30px;">
                <h3 style="margin-top: 0;">📤 Загрузить файл</h3>
                <form method="POST" action="/upload" enctype="multipart/form-data" style="display: flex; gap: 10px; align-items: center;">
                    <input type="file" name="file" required style="flex: 1; padding: 10px; border: 1px solid #ddd; border-radius: 5px;">
                    <button type="submit" style="padding: 10px 20px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer;">📎 Загрузить</button>
                </form>
            </div>
            
            <div style="background: white; padding: 30px; border-radius: 10px;">
                <h3 style="margin-top: 0;">📁 Ваши файлы ({len(user_files)})</h3>
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
        add_flash_message('Файл не выбран', 'error')
        return redirect('/dashboard')
    
    file = request.files['file']
    if file.filename == '':
        add_flash_message('Файл не выбран', 'error')
        return redirect('/dashboard')
    
    try:
        user_id = session['user_id']
        filename = secure_filename(file.filename)
        file_id = hashlib.md5(f"{user_id}_{filename}_{datetime.now()}".encode()).hexdigest()
        
        file_data = file.read()
        file_size = len(file_data)
        
        print(f"🔧 Загружаем файл: {filename} ({file_size} bytes)")
        
        # Шифруем и загружаем в Cloudinary
        encrypted_data = encrypt_file(file_data)
        result = cloudinary.uploader.upload(
            encrypted_data,
            public_id=f"storage/{user_id}/{file_id}_{filename}",
            resource_type="raw"
        )
        
        print(f"✅ Файл загружен в Cloudinary: {result['secure_url']}")
        
        # Получаем текущие файлы и добавляем новый
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
        
        # Сохраняем обновленный список
        if save_user_files(user_id, user_files):
            print(f"✅ Метаданные файла сохранены для {user_id}")
            add_flash_message(f'✅ Файл "{filename}" успешно загружен!', 'success')
        else:
            add_flash_message(f'❌ Ошибка сохранения информации о файле', 'error')
        
    except Exception as e:
        print(f"❌ Ошибка загрузки: {e}")
        add_flash_message(f'❌ Ошибка загрузки: {str(e)}', 'error')
    
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
            decrypted_data = decrypt_file(response.content)
            return send_file(
                io.BytesIO(decrypted_data),
                as_attachment=True,
                download_name=file_data['name']
            )
        except:
            add_flash_message('Ошибка скачивания', 'error')
    else:
        add_flash_message('Файл не найден', 'error')
    
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
            # Удаляем файл из Cloudinary
            cloudinary.uploader.destroy(file_to_delete['public_id'], resource_type="raw")
            print(f"✅ Файл удален из Cloudinary: {file_to_delete['public_id']}")
        except Exception as e:
            print(f"⚠️ Не удалось удалить из Cloudinary: {e}")
        
        # Удаляем из списка
        user_files = [f for f in user_files if f['id'] != file_id]
        save_user_files(user_id, user_files)
        
        add_flash_message('Файл удален', 'success')
    else:
        add_flash_message('Файл не найден', 'error')
    
    return redirect('/dashboard')

@app.route('/logout')
def logout():
    session.clear()
    add_flash_message('Вы вышли из системы', 'info')
    return redirect('/login')

if __name__ == '__main__':
    print("🚀 Запуск Secure Cloud Storage...")
    print("✅ Cloudinary настроен!")
    
    # Загружаем пользователей при старте
    users = get_users()
    print(f"👥 Пользователей в системе: {len(users)}")
    
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
