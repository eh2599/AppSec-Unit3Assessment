import secrets
import subprocess

from flask import Flask, render_template, request, session, make_response
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
# Set secret key to randomly generated value
secret_key = secrets.token_urlsafe(32)
app.config['SECRET_KEY'] = secret_key
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
    PERMANENT_SESSION_LIFETIME=600,
    WTF_CSRF_TIME_LIMIT=None
)

# Reference for bcrypt implementation: https://flask-bcrypt.readthedocs.io/en/latest/
bcrypt = Bcrypt(app)

# Reference for CSRF implementation: https://flask-wtf.readthedocs.io/en/stable/csrf.html
csrf = CSRFProtect(app)

registered_users = {}


# Reference used for after_request decorator:
# https://stackoverflow.com/questions/29464276/add-response-headers-to-flask-web-app
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src \'self\' "
    response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


@app.route('/')
def index():
    if 'username' in session:
        username = session['username']
        return render_template('logged_in_index.html', username=username)
    else:
        return render_template('index.html')


def register_with_user_info(username, hashed_password, phone):
    if username in registered_users:
        return render_template('username_already_exists.html', username=username)
    else:
        registered_users[username] = [hashed_password, phone]
        return render_template('registration_complete.html', username=username)


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    elif request.method == 'POST':
        username = request.values['uname']
        hashed_password = bcrypt.generate_password_hash(request.values['pword']).decode('utf-8')
        phone = request.values['2fa']
        return register_with_user_info(username, hashed_password, phone)


def check_user_authentication(username, password, phone):
    if username not in registered_users:
        return render_template('login_failure.html')
    else:
        if bcrypt.check_password_hash(registered_users[username][0], password):
            if phone == registered_users[username][1]:
                session.clear()
                session['username'] = username
                session.permanent = True
                return render_template('login_success.html')
            else:
                return render_template('tfa_failure.html')
        else:
            return render_template('login_failure.html')


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        username = request.values['uname']
        password = request.values['pword']
        phone = request.values['2fa']
        return check_user_authentication(username, password, phone)


@app.route('/spell_check', methods=['POST', 'GET'])
def spell_check():
    if 'username' in session:
        username = session['username']
        if request.method == 'GET':
            return render_template('spell_check.html', username=username)
        elif request.method == 'POST':
            fp = open('input_text.txt', 'w')
            fp.write(str(request.values['inputtext']))
            fp.close()
            text_to_check = str(request.values['inputtext'])
            # Reference for implementing subprocess: https://docs.python.org/2/library/subprocess.html
            result = subprocess.check_output(["./a.out", "input_text.txt", "wordlist.txt"]).decode(
                "utf-8").strip().replace('\n', ', ')
            return render_template('spell_check_results.html', text_to_check=text_to_check, result=result)
    else:
        return render_template('not_logged_in.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    return render_template('index.html')


if __name__ == '__main__':
    app.run()
