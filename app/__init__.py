import os
import click
import json
from flask import send_from_directory
from app.customFlask import CustomFlask
from app.web import web as web
import app.models as models
from app.mail import mail as mail
from app.mail import send_test_message as send_test_message

app = CustomFlask(__name__)

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SECRET_KEY=os.environ.get('FLASK_SECRET_KEY'),
    SQLALCHEMY_DATABASE_URI=os.environ.get('DB_URI'),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    MAX_CONTENT_LENGTH=10 * 1024 * 1024,
    MAIL_SERVER=os.environ.get('MAIL_SERVER'),
    MAIL_PORT=os.environ.get('MAIL_PORT'),
    MAIL_USERNAME=os.environ.get('MAIL_USERNAME'),
    MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD'),
    MAIL_DEFAULT_SENDER=os.environ.get('MAIL_DEFAULT_SENDER'),
    MAIL_USE_SSL=True,
)

models.db.init_app(app)
mail.init_app(app)
app.register_blueprint(web, url_prefix='/')


@app.cli.command()
def reset_db():
    click.echo('Resetting database...')
    models.db.drop_all()
    models.db.create_all()
    load_data('data.json')
    click.echo('Database reset.')


@app.cli.command()
def test_mail():
    send_test_message(app.config.get('MAIL_DEFAULT_SENDER'))


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static/images'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')


def load_data(path):
    with open(path, 'r', encoding='utf-8') as file:
        data_string = file.read()
        data = json.loads(data_string)
        for user in data['users']:
            models.User.register(**user)    # tutaj jest tylko jedno konto służące jako honeypot


if __name__ == '__main__':
    app.run()


