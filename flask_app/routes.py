from flask import render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_app import app, db
from flask_app.models import User


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['POST'])
def login():
    login = request.form['login']
    password = request.form['password']
    user = User.query.filter_by(login=login).first()
    if user and check_password_hash(user.password, password):
        session['user_id'] = user.id
        return redirect(url_for('welcome'))
    else:
        flash('Invalid login or password')
        return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(login=login, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('register.html')


@app.route('/welcome')
def welcome():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        return render_template('welcome.html', user=user)
    return redirect(url_for('index'))
