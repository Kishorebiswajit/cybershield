from flask import Flask
from flask_socketio import SocketIO
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail
from datetime import timedelta
from config import Config

socketio = SocketIO()
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
mail = Mail()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

    socketio.init_app(app, async_mode='threading', cors_allowed_origins='*')
    limiter.init_app(app)
    mail.init_app(app)

    from app.routes import main
    app.register_blueprint(main)

    from app.auth import auth
    app.register_blueprint(auth)

    return app
