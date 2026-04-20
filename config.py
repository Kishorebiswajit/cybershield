import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "cybershield-dev-key-change-in-prod")
    DEBUG = os.getenv("DEBUG", "False") == "True"
    NVD_API_KEY = os.getenv("NVD_API_KEY", "")

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    WTF_CSRF_ENABLED = True
    WTF_CSRF_SSL_STRICT = False
    WTF_CSRF_TIME_LIMIT = None

    RATELIMIT_STORAGE_URI = "memory://"
    RATELIMIT_DEFAULT = "200 per day;50 per hour"

    MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.getenv("MAIL_PORT", 587))
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.getenv("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER = os.getenv("MAIL_USERNAME", "")
    ALERT_RECIPIENT = os.getenv("ALERT_RECIPIENT", "")
