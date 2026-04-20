from flask import Blueprint, render_template, request, redirect, url_for, session
from functools import wraps
import hashlib
import os
from dotenv import load_dotenv

load_dotenv()

auth = Blueprint('auth', __name__)

USERS = {
    os.getenv("ADMIN_USER", "admin"): hashlib.sha256(
        os.getenv("ADMIN_PASS", "cybershield123").encode()
    ).hexdigest()
}

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('logged_in'):
        return redirect(url_for('main.index'))

    error = None

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if username in USERS and USERS[username] == hash_password(password):
            session['logged_in'] = True
            session['username'] = username
            session.permanent = True
            return redirect(url_for('main.index'))
        else:
            error = "Invalid credentials"

    return render_template('login.html', error=error)

@auth.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))
