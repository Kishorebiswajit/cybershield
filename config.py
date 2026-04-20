import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "cybershield-dev-key-change-in-prod")
    DEBUG = True  # On for development
    NVD_API_KEY = os.getenv("NVD_API_KEY", "")

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    WTF_CSRF_ENABLED = True
    WTF_CSRF_SSL_STRICT = False

    RATELIMIT_STORAGE_URI = "memory://"
    RATELIMIT_DEFAULT = "5000 per hour"  # FIXED: Stops the "Too Many Requests" error

    MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.getenv("MAIL_PORT", 587))
    MAIL_USE_TLS = True
