from flask import Flask, request, redirect, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'super-secret-key-12345'

def init_db():
    conn = sqlite3.connect('cloud_storage.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS files
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  filename TEXT NOT NULL,
                  original_filename TEXT NOT NULL,
                  user_id INTEGER NOT NULL)''')
    
    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect('cloud_storage.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    if 'user_id' in session:
        return f'''
        <!DOCTYPE html>
        <html>
        <head><title>Cloud Storage</title></head>
        <body>
            <h1>✅ Добро пожаловать, {session["username"]}!</h1>
            <p>Вы вошли в систему.</p>
            <a href="/dashboard">Дашборд</a> | <a href="/logout">Выйти</a>
        </body>
        </html>
        '''
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', 
                           (username, password)).fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect('/dashboard')
        else:
            return '<script>alert("Ошибка входа"); window.location.href="/login";</script>'
    
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - Cloud Storage</title>
        <style>
            body { font-family: Arial; margin: 50px; background: #f0f0f0; }
            .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
            h2 { text-align: center; }
            .form-group { margin-bottom: 20px; }
            input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
            .btn { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 5px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>🔐 Вход</h2>
            <form method="POST">
                <div class="form-group">
                    <input type="text" name="username" placeholder="Логин" required>
                </div>
                <div class="form-group">
                    <input type="password" name="password" placeholder="Пароль" required>
                </div>
                <button type="submit" class="btn">Войти</button>
            </form>
            <div style="text-align: center; margin-top: 20px;">
                <a href="/register">Создать аккаунт</a>
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
        
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', 
                        (username, password))
            conn.commit()
            return '<script>alert("Регистрация успешна!"); window.location.href="/login";</script>'
        except:
            return '<script>alert("Логин занят"); window.location.href="/register";</script>'
        finally:
            conn.close()
    
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Register - Cloud Storage</title>
        <style>
            body { font-family: Arial; margin: 50px; background: #f0f0f0; }
            .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
            h2 { text-align: center; }
            .form-group { margin-bottom: 20px; }
            input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
            .btn { width: 100%; padding: 12px; background: #28a745; color: white; border: none; border-radius: 5px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>📝 Регистрация</h2>
            <form method="POST">
                <div class="form-group">
                    <input type="text" name="username" placeholder="Логин" required>
                </div>
                <div class="form-group">
                    <input type="password" name="password" placeholder="Пароль" required>
                </div>
                <button type="submit" class="btn">Зарегистрироваться</button>
            </form>
            <div style="text-align: center; margin-top: 20px;">
                <a href="/login">Назад к входу</a>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dashboard - Cloud Storage</title>
        <style>
            body {{ font-family: Arial; margin: 0; background: #f0f0f0; }}
            .header {{ background: white; padding: 20px; display: flex; justify-content: space-between; }}
            .container {{ max-width: 1000px; margin: 20px auto; padding: 20px; }}
            .upload-box {{ background: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h2>📁 Cloud Storage</h2>
            <div>
                <span>Привет, <strong>{session["username"]}</strong>!</span>
                <a href="/logout" style="margin-left: 20px; background: #6c757d; color: white; padding: 8px 15px; border-radius: 5px; text-decoration: none;">Выйти</a>
            </div>
        </div>
        
        <div class="container">
            <div class="upload-box">
                <h3>📤 Загрузка файлов</h3>
                <p>Функционал загрузки будет добавлен на следующем шаге</p>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)
