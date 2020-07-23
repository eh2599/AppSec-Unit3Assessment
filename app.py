import os
import secrets
import subprocess

from flask import Flask, render_template, request, session
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy

project_dir = os.path.dirname(os.path.abspath(__file__))
database_file = "sqlite:///{}".format(os.path.join(project_dir, "spellcheckerdatabase.db"))

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
app.config["SQLALCHEMY_DATABASE_URI"] = database_file

db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(60), nullable=False)
    phone = db.Column(db.String(11))
    admin = db.Column(db.Boolean, nullable=False)

class Query(db.Model):
    __tablename__ = 'queries'
    query_id = db.Column(db.Integer, primary_key=True)
    query_text = db.Column(db.String(5000), nullable=False)
    query_results = db.Column(db.String(5000))
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)


# Reference for bcrypt implementation: https://flask-bcrypt.readthedocs.io/en/latest/
bcrypt = Bcrypt(app)

# Reference for CSRF implementation: https://flask-wtf.readthedocs.io/en/stable/csrf.html
csrf = CSRFProtect(app)


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
    existing_user = User.query.filter_by(username=username).first()
    if existing_user is not None:
        return render_template('username_already_exists.html', username=username)
    else:
        new_user = User(username=username,password=hashed_password,phone=phone,admin=False)
        db.session.add(new_user)
        db.session.commit()
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
    user = User.query.filter_by(username=username).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return render_template('login_failure.html')
    else:
        if user.phone == phone:
            session.clear()
            session['username'] = username
            session.permanent = True
            return render_template('login_success.html')
        else:
            return render_template('tfa_failure.html')


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
            user = User.query.filter_by(username=username).first()
            fp = open('input_text.txt', 'w')
            fp.write(str(request.values['inputtext']))
            fp.close()
            text_to_check = str(request.values['inputtext'])
            # Reference for implementing subprocess: https://docs.python.org/2/library/subprocess.html
            result = subprocess.check_output(["./a.out", "input_text.txt", "wordlist.txt"]).decode(
                "utf-8").strip().replace('\n', ', ')
            query = Query(query_text=text_to_check,query_results=result,user_id=user.user_id)
            db.session.add(query)
            db.session.commit()
            return render_template('spell_check_results.html', text_to_check=text_to_check, result=result)
    else:
        return render_template('not_logged_in.html')


@app.route('/history', methods=['GET'])
def history():
    if 'username' in session:
        username = session['username']
        queries = Query.query.all()
        num_queries = Query.query.count()
        return render_template('history.html', queries=queries, num_queries=num_queries, username=username)
    else:
        return render_template('not_logged_in.html')


@app.route('/history/query<int:query_id>', methods=['GET'])
def query_review(query_id):
    if 'username' in session:
        username = session['username']
        query = Query.query.filter_by(query_id=query_id).first()
        return render_template('query_review.html', query=query, username=username)
    else:
        return render_template('not_logged_in.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    return render_template('index.html')


if __name__ == '__main__':
    app.run()
