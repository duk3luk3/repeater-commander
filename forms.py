from wtforms import Form, StringField, PasswordField, validators, SubmitField, SelectField
from wtforms.ext.csrf.session import SessionSecureForm
import secrets
import os

from wtforms.validators import ValidationError, DataRequired, Email, EqualTo, Length

app_secret = os.environ.get('APP_SECRET', secrets.token_urlsafe(16))

class LoginForm(SessionSecureForm):
    """User Signup Form."""

    SECRET_KEY = app_secret.encode()
    TIME_LIMIT = None

    name = StringField('Name', [
        DataRequired(message=('Don\'t be shy!'))
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Please enter a password."),
    ])
    submit = SubmitField('Login')

class ActionForm(SessionSecureForm):
    """User Signup Form."""

    SECRET_KEY = app_secret.encode()
    TIME_LIMIT = None

