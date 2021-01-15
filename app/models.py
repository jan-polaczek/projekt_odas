from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import and_
import bcrypt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import html
import re
import uuid
import os
from email_validator import validate_email, EmailNotValidError
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename

from app.mail import send_reset_password_token
from app.ip import get_location_from_ip

from sqlalchemy.ext.hybrid import hybrid_property

db = SQLAlchemy()

MAX_LOGIN_AMOUNT = int(os.environ.get('MAX_LOGIN_AMOUNT'))
MAX_LOGIN_TIME_DIF_SEC = int(os.environ.get('MAX_LOGIN_TIME_DIF_SEC'))
NOTE_TOKEN_DURATION_SEC = int(os.environ.get('NOTE_TOKEN_DURATION_SEC'))
RESET_TOKEN_DURATION_SEC = int(os.environ.get('RESET_TOKEN_DURATION_SEC'))
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}
UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER')


def generate_uuid():
    return str(uuid.uuid4())


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(30))
    last_name = db.Column(db.String(30))
    password = db.Column(db.String(60))
    email = db.Column(db.String(50))

    def __init__(self, **kwargs):
        if 'password' in kwargs:
            kwargs['password'] = User.hash_password(kwargs['password'])
        super().__init__(**kwargs)

    def check_password(self, password):
        return password and bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

    def change_password(self, new_password):
        errors = []
        if len(new_password) < 8:
            errors.append('Hasło musi składać się z co najmniej 8 znaków.')
        else:
            self.password = User.hash_password(new_password)
            db.session.commit()
        return {'errors': errors}

    @staticmethod
    def hash_password(password):
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=14))

    def __repr__(self):
        return f'User: {self.email}'

    def as_dict(self):
        res = {
            'id': self.id,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.email,
        }
        return res

    @hybrid_property
    def full_name(self):
        return self.first_name + ' ' + self.last_name

    @staticmethod
    def authorize(email, password):
        user = User.query.filter_by(email=email).first()
        if user is None or not user.check_password(password):
            return None
        else:
            return user

    @staticmethod
    def check_email(email):
        res = {}
        if User.query.filter_by(email=email).first() is None:
            res[email] = 'available'
        else:
            res[email] = 'unavailable'
        return res

    @staticmethod
    def register(**kwargs):
        errors = []
        user_data = {}
        if User.is_valid('email', kwargs.get('email', '')):
            user_data['email'] = kwargs.get('email')
        else:
            errors.append('Niepoprawny adres email')
        if User.is_valid('password', kwargs.get('password', '')):
            user_data['password'] = kwargs.get('password')
        else:
            errors.append('Błędne hasło')
        if User.is_valid('first_name', kwargs.get('first_name', '')):
            user_data['first_name'] = kwargs.get('first_name')
        else:
            errors.append('Błędne imię')
        if User.is_valid('last_name', kwargs.get('last_name', '')):
            user_data['last_name'] = kwargs.get('last_name')
        else:
            errors.append('Błędne nazwisko')
        if User.check_email(kwargs.get('email'))[kwargs.get('email')] == 'unavailable':
            errors.append('Nazwa użytkownika zajęta')

        safe_data = {}
        for key in user_data:
            safe_data[key] = html.escape(user_data[key])

        if len(errors) == 0:
            user = User(**user_data)
            db.session.add(user)
            db.session.commit()
        else:
            user = None
        return {'user': user, 'errors': errors}

    @staticmethod
    def is_valid(field, value):
        PL = 'ĄĆĘŁŃÓŚŹŻ'
        pl = 'ąćęłńóśźż'
        if field == 'first_name':
            return re.compile(f'[A-Z{PL}][a-z{pl}]+').match(value)
        if field == 'last_name':
            return re.compile(f'[A-Z{PL}][a-z{pl}]+').match(value)
        if field == 'password':
            return re.compile('.{8,}').match(value.strip())
        if field == 'email':
            try:
                validate_email(value)
                return True
            except EmailNotValidError as e:
                return False
        return False


class Session(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=generate_uuid, unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User')
    csrf_token = db.Column(db.String(36), default=generate_uuid, nullable=False)

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    @staticmethod
    def register(**kwargs):
        s = Session(**kwargs)
        db.session.add(s)
        db.session.commit()
        return s


class Note(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=generate_uuid, unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User')
    password = db.Column(db.String(60))
    title = db.Column(db.String(30))
    text = db.Column(db.String(1000))
    file_path = db.Column(db.String(100))
    filename = db.Column(db.String(100))
    is_public = db.Column(db.Boolean())
    iv = db.Column(db.Binary())
    key_salt = db.Column(db.Binary())

    def __init__(self, **kwargs):
        if 'password' in kwargs and kwargs['password'] != '':
            kwargs['text'], kwargs['key_salt'], kwargs['iv'] = Note.encrypt_text(kwargs['text'], kwargs['password'])
            kwargs['password'] = bcrypt.hashpw(kwargs['password'].encode('utf-8'), bcrypt.gensalt())
        super().__init__(**kwargs)

    def check_password(self, password):
        return password and bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

    def get_plaintext(self, password):
        if self.password:
            key = bcrypt.kdf(password.encode('utf-8'), self.key_salt, 16, 12)
            cipher = AES.new(key, AES.MODE_CFB, iv=self.iv)
            b64_decoded = base64.b64decode(self.text)
            decrypted = cipher.decrypt(b64_decoded)
            decoded = bytes(decrypted).decode('utf-8')
            return decoded
        else:
            return self.text

    @staticmethod
    def register(file, **kwargs):
        errors = []
        if len(kwargs.get('title')) > 30:
            errors.append('Tytuł nie może przekraczać 30 znaków.')
        if len(kwargs.get('text')) > 1000:
            errors.append('Treść nie może przekraczać 1000 znaków.')

        safe_data = {}
        for key in kwargs:
            if isinstance(kwargs[key], str):
                safe_data[key] = html.escape(kwargs[key])
            else:
                safe_data[key] = kwargs[key]

        if file.filename != '':
            if not allowed_file(file.filename):
                errors.append('Niedozwolone rozszerzenie pliku.')
            else:
                filename = secure_filename(file.filename)
                dirpath = os.path.join(UPLOAD_FOLDER, datetime.now().strftime('%Y-%m-%d'))
                if not os.path.exists(dirpath):
                    os.makedirs(dirpath)
                path = os.path.join(dirpath, generate_uuid())
                safe_data['filename'] = filename
                safe_data['file_path'] = path
        if len(errors) == 0:
            if safe_data.get('file_path', False):
                file.save(safe_data['file_path'])
            note = Note(**safe_data)
            db.session.add(note)
            db.session.commit()
        else:
            note = None
        return {'note': note, 'errors': errors}

    @staticmethod
    def get_authors_notes(user_id):
        return Note.query.filter(and_(Note.is_public, Note.user_id == user_id))

    @staticmethod
    def encrypt_text(text, password):
        key_salt = get_random_bytes(16)
        iv = get_random_bytes(16)
        key = bcrypt.kdf(password.encode('utf-8'), key_salt, 16, 12)
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        encoded = text.encode('utf-8')
        encrypted = cipher.encrypt(encoded)
        return base64.b64encode(encrypted), key_salt, iv


class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50))
    ip = db.Column(db.String(15))
    successful = db.Column(db.Boolean())
    timestamp = db.Column(db.DateTime(), default=datetime.now)
    location = db.Column(db.String(100))

    @staticmethod
    def check_if_can_log_in(ip):
        min_time = datetime.now() - timedelta(seconds=MAX_LOGIN_TIME_DIF_SEC)
        attempts = LoginAttempt.query.filter(and_(LoginAttempt.ip == ip, LoginAttempt.timestamp >= min_time, LoginAttempt.successful == False))
        return attempts.count() <= MAX_LOGIN_AMOUNT, MAX_LOGIN_AMOUNT - attempts.count()

    @staticmethod
    def register(**kwargs):
        la = LoginAttempt(**kwargs)
        la.location = get_location_from_ip(la.ip)
        db.session.add(la)
        db.session.commit()
        return la


class ResetPasswordToken(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=generate_uuid, unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User')
    timestamp = db.Column(db.DateTime(), default=datetime.now)

    def check_if_valid(self):
        max_time = self.timestamp + timedelta(seconds=NOTE_TOKEN_DURATION_SEC)
        return datetime.now() <= max_time

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    @staticmethod
    def register(email):
        user = User.query.filter_by(email=email).first()
        if user is None:
            return None
        else:
            ResetPasswordToken.query.filter_by(user_id=user.id).delete()
            rpt = ResetPasswordToken(user_id=user.id)
            db.session.add(rpt)
            db.session.commit()
            send_reset_password_token(user, rpt.id)
            return rpt
