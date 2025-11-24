from flask import Flask

app = Flask(__name__)

@app.route('/')
def hello():
    return '''
    <!DOCTYPE html>
    <html>
    <head><title>Cloud Storage</title></head>
    <body>
        <h1>✅ Cloud Storage работает!</h1>
        <p>Приложение успешно запущено.</p>
        <a href="/login">Вход</a> | <a href="/register">Регистрация</a>
    </body>
    </html>
    '''

@app.route('/login')
def login():
    return '<h1>Страница входа</h1><a href="/">Назад</a>'

@app.route('/register')
def register():
    return '<h1>Страница регистрации</h1><a href="/">Назад</a>'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
