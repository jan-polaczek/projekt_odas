import os

from flask import Blueprint, render_template, request, redirect, session, url_for, send_file
from functools import update_wrapper, wraps
import odas.models as models
import datetime
import time

LOGIN_WAIT_TIME_SEC = int(os.environ.get('LOGIN_WAIT_TIME_SEC'))

web = Blueprint('web', __name__, template_folder='templates')


@web.after_request
def add_content_security_header(resp):
    resp.headers['Content-Security-Policy']='default-src \'self\''
    return resp


def protected(fn):
    def wrapped_function(*args, **kwargs):
        sid = session.get('sid')
        if sid is None:
            return redirect(url_for('web.index'))
        kwargs['user'] = models.Session.query.get(session['sid']).user
        return fn(*args, **kwargs)
    return update_wrapper(wrapped_function, fn)


def csrf_protected(fn):
    def wrapped_function(*args, **kwargs):
        if request.method == 'POST':
            sid = session.get('sid')
            if sid is None:
                return redirect(url_for('web.index'))
            csrf_token = models.Session.query.get(session['sid']).csrf_token
            received_token = request.form.get('csrf_token')
            if csrf_token == received_token:
                print(request.form.to_dict())
                form = {k: v for k, v in request.form.to_dict().items() if k != 'csrf_token'}
                kwargs['form'] = form
                return fn(*args, **kwargs)
            else:
                return 'Niewłaściwy żeton csrf', 403
        else:
            return fn(*args, **kwargs)
    return update_wrapper(wrapped_function, fn)


def note_protection(fn):
    @wraps(fn)
    def decorated_view(*args, **kwargs):
        note_id = kwargs.get('note_id')
        user = models.Session.query.get(session['sid']).user

        if not note_id:
            token_id = kwargs.get('token_id')
            token = models.NoteToken.query.get(token_id)
            if token is not None:
                note_id = token.verify(user.id)
                if not note_id:
                    note_id = 0

        note = models.Note.query.get(note_id)
        if note is not None:
            if note.is_public or note.user == user:
                return fn(*args, **kwargs)
        return redirect(url_for('web.index'))
    return decorated_view


@web.context_processor
def session_info():
    logged_in = 'sid' in session
    if logged_in:
        try:
            s = models.Session.query.get(session['sid'])
            user = s.user.as_dict()
            csrf_token = s.csrf_token
        except (TypeError, AttributeError):
            user = None
            csrf_token = None
            logged_in = False
            session.clear()
    else:
        user = None
        csrf_token = None
    return dict(logged_in=logged_in, user=user, csrf_token=csrf_token)


@web.route('/')
def index():
    return render_template('index.html')


@web.route('/sign-up')
def sign_up():
    return render_template('sign_up.html')


@web.route('/login')
def login():
    return render_template('login.html')


@web.route('/authorize', methods=['POST'])
def authorize():
    time.sleep(LOGIN_WAIT_TIME_SEC)
    email = request.form.get('email')
    password = request.form.get('password')
    ip = request.remote_addr
    can_log_in, remaining_attempts = models.LoginAttempt.check_if_can_log_in(ip)
    if not can_log_in:
        error = 'Możliwość logowania została zablokowana ze względu na zbyt dużą liczbę nieudanych prób.'
        return render_template('login.html', errors=[error])
    user = models.User.authorize(email, password)
    if user is None:
        error = 'Niewłaściwa nazwa użytkownika i/lub hasło!'
        if remaining_attempts >= 5 or remaining_attempts == 0:
            msg = f'Pozostało {remaining_attempts} prób logowania.'
        elif remaining_attempts == 1:
            msg = 'Pozostała 1 próba logowania.'
        else:
            msg = f'Pozostały {remaining_attempts} próby logowania.'
        models.LoginAttempt.register(email=email, ip=ip, successful=False)
        return render_template('login.html', errors=[error], messages=[msg])
    else:
        ses = models.Session.register(user_id=user.id)
        session['sid'] = ses.id
        session['timestamp'] = datetime.datetime.now().timestamp()
        models.LoginAttempt.register(email=email, ip=ip, successful=True)
        return redirect(url_for('web.index'))


@web.route('/register', methods=['POST'])
def register():
    data = request.form.to_dict()
    data['user_type'] = 'sender'
    result = models.User.register(**data)
    if len(result['errors']) == 0:
        return redirect(url_for('web.login'))
    else:
        return render_template('sign_up.html', errors=result['errors'])


@web.route('/logout')
def logout():
    models.Session.query.get(session.get('sid')).delete()
    session.clear()
    return redirect(url_for('web.index'))


@web.route('/notes/new', methods=['GET', 'POST'])
@protected
@csrf_protected
def new_note(**kwargs):
    if request.method == 'GET':
        return render_template('new_note.html')
    elif request.method == 'POST':
        data = kwargs['form']
        data['user_id'] = kwargs['user'].id
        data['is_public'] = True if data.get('is_public') else False
        result = models.Note.register(request.files['attachment'], **data)
        if len(result['errors']) == 0:
            return redirect(url_for('web.my_notes'))
        else:
            return render_template('new_note.html', errors=result['errors'])


@web.route('/notes')
@protected
def my_notes(**kwargs):
    user = kwargs['user']
    notes = models.Note.query.filter_by(user_id=user.id)
    return render_template('my_notes.html', notes=notes)

'''
@web.route('/notes/authorize/<note_id>', methods=['GET', 'POST'])
@protected
@note_protection
@csrf_protected
def note_authorize(note_id, **kwargs):
    note = models.Note.query.get(note_id)
    user = kwargs['user']
    if request.method == 'GET':
        if note.password:
            return render_template('note_authorize.html', note_id=note_id)
        else:
            return render_template('note.html', note=note)
    elif request.method == 'POST':
        password = request.form.get('password')
        if note.check_password(password):
            token = models.NoteToken.register(user_id=user.id, note_id=note.id)
            return redirect(url_for('web.note_detail', token_id=token.id))
        else:
            error = 'Niewłaściwe hasło.'
            return render_template('note_authorize.html', note_id=note_id, errors=[error])


@web.route('/notes/<token_id>')
@protected
@note_protection
def note_detail(token_id, **kwargs):
    token = models.NoteToken.query.get(token_id)
    user = kwargs['user']
    note_id = token.verify(user.id)
    note = models.Note.query.get(note_id)
    token.delete()
    return render_template('note.html', note=note)
'''

@web.route('/notes/authorize/<note_id>', methods=['GET', 'POST'])
@protected
@note_protection
@csrf_protected
def note_authorize(note_id, **kwargs):
    note = models.Note.query.get(note_id)
    user = kwargs['user']
    if request.method == 'GET':
        if note.password:
            return render_template('note_authorize.html', note_id=note_id)
        else:
            return note_detail(note, None)
    elif request.method == 'POST':
        password = request.form.get('password')
        if note.check_password(password):
            return note_detail(note, password)
        else:
            error = 'Niewłaściwe hasło.'
            return render_template('note_authorize.html', note_id=note_id, errors=[error])


def note_detail(note, password):
    note.plaintext = note.get_plaintext(password)
    return render_template('note.html', note=note)

@web.route('/download-note/<note_id>')
@protected
@note_protection
def download_note(note_id, **kwargs):
    note = models.Note.query.get(note_id)
    path = os.path.abspath(note.file_path)
    if os.path.exists(path):
        return send_file(path, attachment_filename=note.filename, as_attachment=True)
    else:
        error = 'Nie znaleziono pliku.'
        return render_template('index.html', errors=[error])


@web.route('/notes/public')
@protected
def public_notes(**kwargs):
    author = request.args.get('author')
    if author:
        notes = models.Note.get_authors_notes(author)
        return render_template('author_notes.html', notes=notes)
    else:
        notes = models.Note.query.filter_by(is_public=True)
        return render_template('public_notes.html', notes=notes)


@web.route('/login-attempts')
@protected
def login_attempts(**kwargs):
    user = kwargs['user']
    attempts = models.LoginAttempt.query\
        .filter_by(email=user.email)\
        .order_by(models.LoginAttempt.id.desc())
    return render_template('login_attempts.html', attempts=attempts)


@web.route('/reset-password/<token_id>', methods=['GET', 'POST'])
def reset_password(token_id):
    token = models.ResetPasswordToken.query.get(token_id)
    if token is None or not token.check_if_valid():
        error = 'Podany link stracił ważność.'
        return render_template('index.html', errors=[error])
    else:
        if request.method == 'GET':
            return render_template('reset_password.html', token_id=token_id)
        else:
            user = token.user
            result = user.change_password(request.form.get('password'))
            if len(result['errors']) == 0:
                message = 'Pomyślnie zmieniono hasło.'
                token.delete()
                return render_template('index.html', messages=[message])
            else:
                return render_template('reset_password.html', token_id=token_id, errors=result.errors)


@web.route('/reset-password/send-token', methods=['GET', 'POST'])
def send_reset_token():
    if request.method == 'GET':
        return render_template('send_reset_token.html')
    elif request.method == 'POST':
        email = request.form.get('email')
        models.ResetPasswordToken.register(email)
        msg = 'Jeżeli podany adres mailowy istnieje w naszej bazie, to została wysłana nań wiadomość z dalszą instrukcją odzyskiwania konta'
        return render_template('index.html', messages=[msg])
