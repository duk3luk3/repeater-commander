# app.py
import flask
from flask import Flask, request, jsonify, render_template, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user, login_required

from passlib.hash import pbkdf2_sha256

from forms import LoginForm, ActionForm

import server

import sys
import secrets
import yaml
import json
import socket
import os

#DB_STR = os.environ.get('DATABASE_URL', 'sqlite:///:memory:')
DB_STR = 'sqlite:///:memory:'
#DB_STR = "sqlite:///example.sqlite"

app_secret = os.environ.get('APP_SECRET', secrets.token_urlsafe(16))

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = DB_STR
app.config["SECRET_KEY"] = app_secret

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

REPEATER_LISTENER = ('127.0.0.1', 53555)
LISTENER_FILE = 'connections.txt'
#listener_thread = server.start(REPEATER_LISTENER, LISTENER_FILE)

REPEATER_ACTIONS = yaml.load("""
---
- key: Log_Write
  label: Just make a Log Entry
  button: Send Log
  guard: no
  comment: yes
- key: Monitor_Start
  label: Start Monitoring
  button: Start
  guard: no
  comment: no
- key: Monitor_Stop
  label: Stop Monitoring
  button: Stop
  guard: no
  comment: no
- key: Shutdown_10
  label: Shutdown Repeater for 10 minutes
  button: Send Shutdown
  guard: yes
  comment: no
- key: Shutdown_60
  label: Shutdown Repeater for 1 hours
  button: Send Shutdown
  guard: yes
  comment: no
- key: Shutdown_360
  label: Shutdown Repeater for 6 hours
  button: Send Shutdown
  guard: yes
  comment: no
"""
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    authenticated = db.Column(db.Boolean, default=False)


    def __repr__(self):
        return f"<User username={self.username} >"

    def asdict(self):
        dict_ = {}
        for key in self.__mapper__.c.keys():
            dict_[key] = getattr(self, key)
        return dict_

    def set_password(self, password):
        hashed = pbkdf2_sha256.hash(password)
        self.password_hash = hashed

    def verify_password(self, password):
        hashed = pbkdf2_sha256.hash(password)
        return pbkdf2_sha256.verify(password, hashed)

    def get_id(self):
        return self.id

    def is_authenticated(self):
        return self.authenticated

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

class LogEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.DateTime())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter(User.id == user_id).one_or_none()

def find_user(user_name):
    return User.query.filter(User.username == user_name).one_or_none()

@app.before_first_request
def init_app():
    db.Model.metadata.create_all(db.engine)
    user = User(username="test")
    user.set_password('1234')
    db.session.add(user)
    db.session.commit()

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Here we use a class of some kind to represent and validate our
    # client-side form data. For example, WTForms is a library that will
    # handle this for us, and we use a custom LoginForm to validate.
    form = LoginForm(request.form, csrf_context=session)
    if form.validate():
        print('processing form', file=sys.stderr)
        # Login and validate the user.
        # user should be an instance of your `User` class

        user = find_user(form.name.data)

#        if not user:
#            user = User(username=form.name.data)
#            user.set_password(form.password.data)
#            db.session.add(user)
#            db.session.commit()

        if user:

            login_user(user)

            flask.flash('Logged in successfully.')

            #next = flask.request.args.get('next')
            ## is_safe_url should check if the url is safe for redirects.
            ## See http://flask.pocoo.org/snippets/62/ for an example.
            #if not is_safe_url(next):
            #    return flask.abort(400)

            #return flask.redirect(next or flask.url_for('index'))
            return flask.redirect(flask.url_for('index'))
        else:
            flask.flash('Error logging in')
    print('rendering form', file=sys.stderr)
    return flask.render_template('login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    if request.method == 'POST':
        """Logout the current user."""
        user = current_user
        user.authenticated = False
        db.session.add(user)
        db.session.commit()
        logout_user()
        return flask.redirect(flask.url_for('index'))
    else:
        return render_template("logout.html")


@app.route('/action', methods=["POST"])
@login_required
def action():
    form = ActionForm(request.form, csrf_context=session)

    comment_value = request.form['comment']
    action_value = request.form['action']
    user_name = current_user.username
    valid_form = form.validate()

    action_data = dict(comment=comment_value, action=action_value, user=user_name, valid=valid_form)

    if valid_form:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(REPEATER_LISTENER)
        s.send(json.dumps(action_data).encode())
        s.close()

    return jsonify(action_data)


@app.route('/getusers/', methods=['GET'])
def getusers():
    users = User.query.all()
    return jsonify([u.asdict() for u in users])

# A welcome message to test our server
@app.route('/')
def index():
    form = ActionForm(request.form, csrf_context=session)

    if os.path.exists(LISTENER_FILE):
        with open(LISTENER_FILE) as f:
            connections = f.read()
    else:
        connections = 'No file'

    return render_template("index.html",actions=REPEATER_ACTIONS, form=form, connections=connections)


if __name__ == '__main__':
    # Threaded option to enable multiple instances for multiple user access support
    app.run(threaded=True, port=5000)
