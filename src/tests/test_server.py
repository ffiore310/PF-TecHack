#!/usr/bin/env python3

"""
Servidor web vulnerável para testes.
NÃO USE ESTE SERVIDOR EM PRODUÇÃO - ELE É INTENCIONALMENTE VULNERÁVEL!
"""

from flask import Flask, request, render_template_string

app = Flask(__name__)

# Template vulnerável a XSS
TEMPLATE = '''
<!DOCTYPE html>
<html>
    <head><title>Test Page</title></head>
    <body>
        <h1>Test Page</h1>
        <p>Message: {% autoescape false %}{{ message }}{% endautoescape %}</p>
        <form method="GET">
            <input type="text" name="message" />
            <input type="submit" value="Send" />
        </form>
        <hr>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="username" />
            <input type="password" name="password" placeholder="password" />
            <input type="submit" value="Login" />
        </form>
    </body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def index():
    # Vulnerável a XSS
    message = request.args.get('message', '')
    if request.method == 'POST':
        message = request.form.get('message', '')
    return render_template_string(TEMPLATE, message=message)

@app.route('/login', methods=['POST'])
def login():
    # Vulnerável a SQL Injection
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    # Simula um erro SQL quando detecta tentativa de injection
    if "'" in username or "'" in password:
        return "Error: MySQL Error 1064: SQL syntax error"
    
    return f"Login attempt with username: {username}"

if __name__ == '__main__':
    print("Starting vulnerable test server on http://localhost:5000")
    print("WARNING: This server is intentionally vulnerable. DO NOT USE IN PRODUCTION!")
    app.run(debug=False, host='localhost', port=5000)
