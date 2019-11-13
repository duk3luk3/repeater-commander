# app.py
import flask
from flask import Flask, request, jsonify, render_template, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func as sql_func
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
import traceback
from time import sleep

DB_STR = os.environ.get('DATABASE_URL', 'sqlite:///:memory:')
#DB_STR = 'sqlite:///:memory:'
#DB_STR = "sqlite:///example.sqlite"

app_secret = os.environ.get('APP_SECRET', secrets.token_urlsafe(16))

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = DB_STR
app.config["SECRET_KEY"] = app_secret

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

repeater_listen_ip = os.environ.get('LISTENER_IP')
repeater_listen_port = os.environ.get('LISTENER_PORT')

if repeater_listen_ip:
    REPEATER_LISTENER = (repeater_listen_ip, int(repeater_listen_port))
    LISTENER_FILE = ''
else:
    # For debugging - start dummy listener
    REPEATER_LISTENER = ('127.0.0.1', 53555)
    LISTENER_FILE = 'connections.txt'
    listener_thread = server.start(REPEATER_LISTENER, LISTENER_FILE)

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
- key: Shutdown_2
  label: Shutdown Repeater for 2 minutes (for testing)
  button: Send Shutdown
  guard: yes
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
    ts = db.Column(db.DateTime(timezone=True), server_default=sql_func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user_ip = db.Column(db.String(128))
    action = db.Column(db.String(128))
    comment = db.Column(db.String(128))
    submitted = db.Column(db.Boolean)
    submit_result = db.Column(db.String(128))
    user = db.relationship("User")

    def from_action(action_dict, user):
        ev = LogEvent()
        ev.user = user
        ev.user_ip = action_dict['ip']
        ev.action = action_dict['action']
        ev.comment = action_dict['comment']
        ev.submitted = action_dict['submitted']
        ev.submit_result = action_dict['submit_result']
        return ev

def get_client_ip():
    proxy_ip = request.headers.get('X-Forwarded-For')
    if proxy_ip:
        return proxy_ip
    else:
        return request.remote_addr

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter(User.id == user_id).one_or_none()

def find_user(user_name):
    return User.query.filter(User.username == user_name).one_or_none()

@app.before_first_request
def init_app():
    db.Model.metadata.create_all(db.engine)

    users = os.environ.get('APP_CREATE_USERS')

    if users:
        users = users.split(':')
        for user_name in users:
            user_rec = find_user(user_name)
            if not user_rec:
                user_pw = secrets.token_urlsafe(16)
                print(f'Creating user: {user_name}:{user_pw}')
                user = User(username=user_name)
                user.set_password(user_pw)
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


# A welcome message to test our server
@app.route('/', methods=['GET', 'POST'])
def index():
    form = ActionForm(request.form, csrf_context=session)

    if request.method == 'POST' and form.validate() and current_user.is_authenticated:
        comment_value = request.form['comment']
        action_value = request.form['action']
        user_name = current_user.username
        user_ip = get_client_ip()

        action_data = dict(comment=comment_value, action=action_value, user=user_name, ip=user_ip)

        rx = ""

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10.0)

            s.connect(REPEATER_LISTENER)

            try:
                hello_msg = s.recv(5)
                print(f'hello msg: {hello_msg}', file=sys.stderr)
            except socket.timeout:
                traceback.print_exc(file=sys.stderr)

            #send_delay = request.form.get('test_send_delay') or 0
            #sleep(int(send_delay))
            #if action_value == 'test_send':
            #    msg = comment_value.encode()
            #else:
            #    msg = json.dumps(action_data).encode()
            msg = json.dumps(action_data).encode()
            msg_len = len(msg)
            print(f'Sending {msg_len}b message: {msg}', file=sys.stderr)
            s.send(msg)
            #recv_delay = request.form.get('test_recv_delay') or 0
            #sleep(int(recv_delay))

            try:
                rx = s.recv(2)
            except ConnectionResetError:
                traceback.print_exc(file=sys.stderr)
                pass
            s.close()

            if len(rx) > 0:
                action_data['submitted'] = True
                action_data['submit_result'] = "Server reply: " + rx.decode()
            else:
                action_data['submitted'] = True
                action_data['submit_result'] = '<Unknown - no reply>'

        except Exception as e:
            traceback.print_exc(file=sys.stderr)
            action_data['submitted'] = False
            action_data['submit_result'] = 'Unexpected error while sending: ' + str(e)

        ev = LogEvent.from_action(action_data, current_user)
        db.session.add(ev)
        db.session.commit()
    else:
        action_data = None

    connections = ''
    logs = []

    if current_user.is_authenticated:
        if os.path.exists(LISTENER_FILE):
            with open(LISTENER_FILE) as f:
                connections = f.read()
        else:
            connections = 'No file'

        logs = LogEvent.query.order_by(LogEvent.ts.desc()).limit(10).all()

    return render_template("index.html",actions=REPEATER_ACTIONS, form=form, connections=connections, logs=logs, action=action_data)


if __name__ == '__main__':
    # Threaded option to enable multiple instances for multiple user access support
    app.run(threaded=True, port=5000)
