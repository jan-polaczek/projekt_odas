from flask_mail import Mail, Message
from flask import url_for
import os

mail = Mail()
reset_token_duration_min = int(os.environ.get('RESET_TOKEN_DURATION_SEC')) / 60

def send_test_message(recipient):
    msg = Message('Test', recipients=[recipient])
    mail.send(msg)


def send_reset_password_token(recipient, token):
    url = url_for('web.reset_password', token_id=token, _external=True)
    msg = Message('Resetowanie hasła w NoteVault', recipients=[recipient.email])
    msg.html = f'<h2>Witaj, {recipient.full_name}!</h2>' \
               f'W serwisie NoteVault wysłano żądanie zmiany hasła dla Twojego konta.<br>' \
               f'Zmień hasło korzystając z tego linku: <a href="{url}">{url}</a><br>' \
               f'Link straci ważność w ciągu {int(reset_token_duration_min)} minut.<br>' \
               f'Jeżeli to nie Ty wysłałaś(eś) to żądanie, skontaktuj się z administratorem serwisu.<br>' \
               f'Pozdrawiamy<br>' \
               f'Zespół NoteVault'
    mail.send(msg)
