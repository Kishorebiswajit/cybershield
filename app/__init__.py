from flask import Flask
from flask_socketio import SocketIO
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
import os

socketio = SocketIO()
limiter = Limiter(key_func=get_remote_address)
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')
    
    # Initialize extensions
    socketio.init_app(app)
    limiter.init_app(app)
    login_manager.init_app(app)
    
    # Register blueprints
    from app.routes import main
    app.register_blueprint(main)
    
    return app
