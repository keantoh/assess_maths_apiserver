import smtplib
from email.mime.text import MIMEText
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google.auth import exceptions
import base64
import os
from dotenv import load_dotenv

load_dotenv()
gmail_refresh_token = os.getenv('GMAIL_REFRESH_TOKEN')
gmail_client_id = os.getenv('GMAIL_CLIENT_ID')
gmail_client_secret = os.getenv('GMAIL_CLIENT_SECRET')
TOKEN_URI = 'https://oauth2.googleapis.com/token'
MY_EMAIL = 'assess.maths.app@gmail.com'


def get_oauth2_token():
    creds = Credentials(
        None,
        refresh_token=gmail_refresh_token,
        token_uri=TOKEN_URI,
        client_id=gmail_client_id,
        client_secret=gmail_client_secret,
    )
    try:
        creds.refresh(Request())
    except exceptions.RefreshError as e:
        print(f"Failed to refresh token: {e}")
        return None

    return creds.token


def generate_oauth2_string(access_token, as_base64=False) -> str:
    auth_string = 'user=' + MY_EMAIL + '\1auth=Bearer ' + access_token + '\1\1'
    if as_base64:
        auth_string = base64.b64encode(
            auth_string.encode('ascii')).decode('ascii')
    return auth_string


def send_email(subject, msg, recipient):
    access_token = get_oauth2_token()
    auth_string = generate_oauth2_string(access_token, as_base64=True)

    msg = MIMEText(msg)
    msg['Subject'] = subject
    msg['From'] = MY_EMAIL
    msg['To'] = recipient

    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.docmd('AUTH', 'XOAUTH2 ' + auth_string)
    server.sendmail(MY_EMAIL, recipient, msg.as_string())
    server.quit()
