from flask import Flask
from flask_socketio import SocketIO
from config import Config

socketio = SocketIO()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    socketio.init_app(app, async_mode='threading', cors_allowed_origins='*')

    from app.routes import main
    app.register_blueprint(main)

    return app
