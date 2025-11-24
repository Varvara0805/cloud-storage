from flask import Flask

app = Flask(__name__)

@app.route('/')
def home():
    return '''
    <!DOCTYPE html>
    <html>
    <head><title>Cloud Storage</title></head>
    <body>
        <h1>✅ Cloud Storage Works!</h1>
        <p>Application is running successfully.</p>
        <a href="/login">Login</a> | <a href="/register">Register</a>
    </body>
    </html>
    '''

@app.route('/login')
def login():
    return '<h1>Login Page</h1><a href="/">Home</a>'

@app.route('/register')
def register():
    return '<h1>Register Page</h1><a href="/">Home</a>'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
