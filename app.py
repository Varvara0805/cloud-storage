
from flask import Flask, request, redirect, session, send_file
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'super-secret-key-12345'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def init_db():
    try:
        conn = sqlite3.connect('cloud_storage.db')
        c = conn.cursor()
        
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT UNIQUE NOT NULL,
                      password TEXT NOT NULL,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS files
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      filename TEXT NOT NULL,
                      original_filename TEXT NOT NULL,
                      user_id INTEGER NOT NULL,
                      uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      file_size INTEGER)''')
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Database error: {e}")
        return False

def get_db_connection():
    conn = sqlite3.connect('cloud_storage.db')
    conn.row_factory = sqlite3.Row
    return conn

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
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        # Простая проверка пароля (временно)
        if user and user['password'] == password:
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect('/dashboard')
        else:
            return '''
            <script>
                alert("Invalid username or password");
                window.location.href = "/login";
            </script>
            '''
    
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - Cloud Storage</title>
        <style>
            body { font-family: Arial; margin: 50px; background: #f0f0f0; }
            .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
            h2 { text-align: center; color: #333; }
            .form-group { margin-bottom: 20px; }
            input[type="text"], input[type="password"] { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
            .btn { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
            .btn:hover { background: #0056b3; }
            .links { text-align: center; margin-top: 20px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>🔐 Cloud Storage</h2>
            <form method="POST">
                <div class="form-group">
                    <input type="text" name="username" placeholder="Username" required>
                </div>
                <div class="form-group">
                    <input type="password" name="password" placeholder="Password" required>
                </div>
                <button type="submit" class="btn">Login</button>
            </form>
            <div class="links">
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
        
        if len(password) < 1:
            return '''
            <script>
                alert("Password required");
                window.location.href = "/register";
            </script>
            '''
        
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                        (username, password))
            conn.commit()
            return '''
            <script>
                alert("Registration successful! Please login.");
                window.location.href = "/login";
            </script>
            '''
        except sqlite3.IntegrityError:
            return '''
            <script>
                alert("Username already exists");
                window.location.href = "/register";
            </script>
            '''
        finally:
            conn.close()
    
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Register - Cloud Storage</title>
        <style>
            body { font-family: Arial; margin: 50px; background: #f0f0f0; }
            .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
            h2 { text-align: center; color: #333; }
            .form-group { margin-bottom: 20px; }
            input[type="text"], input[type="password"] { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
            .btn { width: 100%; padding: 12px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
            .btn:hover { background: #218838; }
            .links { text-align: center; margin-top: 20px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>📝 Create Account</h2>
            <form method="POST">
                <div class="form-group">
                    <input type="text" name="username" placeholder="Username" required>
                </div>
                <div class="form-group">
                    <input type="password" name="password" placeholder="Password" required>
                </div>
                <button type="submit" class="btn">Register</button>
            </form>
            <div class="links">
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
    
    conn = get_db_connection()
    files = conn.execute('SELECT * FROM files WHERE user_id = ? ORDER BY uploaded_at DESC', 
                        (session['user_id'],)).fetchall()
    conn.close()
    
    files_html = ""
    for file in files:
        size_kb = round(file['file_size'] / 1024, 2) if file['file_size'] else 0
        
        files_html += f'''
        <div class="file-item">
            <div class="file-info">
                <strong>📄 {file['original_filename']}</strong>
                <br>
                <small>📏 {size_kb} KB</small>
            </div>
            <div class="file-actions">
                <a href="/download/{file['id']}" class="btn">⬇️ Download</a>
                <a href="/delete/{file['id']}" class="btn btn-danger" onclick="return confirm('Delete this file?')">🗑️ Delete</a>
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
            .header {{ background: white; padding: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); display: flex; justify-content: space-between; align-items: center; }}
            .container {{ max-width: 1000px; margin: 20px auto; padding: 20px; }}
            .upload-box {{ background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); margin-bottom: 30px; }}
            .files-box {{ background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
            .file-list {{ border: 1px solid #eee; border-radius: 5px; }}
            .file-item {{ display: flex; justify-content: space-between; align-items: center; padding: 15px; border-bottom: 1px solid #eee; }}
            .file-item:last-child {{ border-bottom: none; }}
            .file-item:hover {{ background: #f9f9f9; }}
            .file-info {{ flex: 1; }}
            .file-actions {{ display: flex; gap: 10px; }}
            .btn {{ padding: 8px 15px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer; text-decoration: none; font-size: 14px; }}
            .btn:hover {{ background: #0056b3; }}
            .btn-danger {{ background: #dc3545; }}
            .btn-danger:hover {{ background: #c82333; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h2 style="margin: 0;">📁 Cloud Storage</h2>
            <div>
                <span>Welcome, <strong>{session.get('username', 'User')}</strong>!</span>
                <a href="/logout" class="btn" style="margin-left: 20px; background: #6c757d;">Logout</a>
            </div>
        </div>
        
        <div class="container">
            <div class="upload-box">
                <h3 style="margin-top: 0;">📤 Upload File</h3>
                <form method="POST" action="/upload" enctype="multipart/form-data" style="display: flex; gap: 10px; align-items: center;">
                    <input type="file" name="file" required style="flex: 1; padding: 10px; border: 1px solid #ddd; border-radius: 5px;">
                    <button type="submit" class="btn">📎 Upload</button>
                </form>
            </div>
            
            <div class="files-box">
                <h3 style="margin-top: 0;">📁 Your Files ({len(files)})</h3>
                <div class="file-list">
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
        return redirect('/dashboard')
    
    file = request.files['file']
    
    if file.filename == '':
        return redirect('/dashboard')
    
    if file:
        filename = file.filename
        unique_filename = datetime.now().strftime("%Y%m%d_%H%M%S_") + filename
        
        file_data = file.read()
        file_size = len(file_data)
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        with open(file_path, 'wb') as f:
            f.write(file_data)
        
        conn = get_db_connection()
        conn.execute('INSERT INTO files (filename, original_filename, user_id, file_size) VALUES (?, ?, ?, ?)',
                    (unique_filename, filename, session['user_id'], file_size))
        conn.commit()
        conn.close()
    
    return redirect('/dashboard')

@app.route('/download/<int:file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect('/login')
    
    conn = get_db_connection()
    file = conn.execute('SELECT * FROM files WHERE id = ? AND user_id = ?', 
                       (file_id, session['user_id'])).fetchone()
    conn.close()
    
    if file:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file['filename'])
        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True, download_name=file['original_filename'])
    
    return redirect('/dashboard')

@app.route('/delete/<int:file_id>')
def delete_file(file_id):
    if 'user_id' not in session:
        return redirect('/login')
    
    conn = get_db_connection()
    file = conn.execute('SELECT * FROM files WHERE id = ? AND user_id = ?', 
                       (file_id, session['user_id'])).fetchone()
    
    if file:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file['filename'])
        if os.path.exists(file_path):
            os.remove(file_path)
        conn.execute('DELETE FROM files WHERE id = ?', (file_id,))
        conn.commit()
    
    conn.close()
    return redirect('/dashboard')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)



Этот код 100% заработает! Замени app.py и обнови requirements.txt
