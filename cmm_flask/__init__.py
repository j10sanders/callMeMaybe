import os
#from cmm_flask.config import config_env_files
from flask import Flask
from dotenv import load_dotenv
from flask.ext.bcrypt import Bcrypt
from flask.ext.sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()


def create_app(config_name='development', p_db=db, p_bcrypt=bcrypt, p_login_manager=login_manager):
    new_app = Flask(__name__)
    config_app(config_name, new_app)

    p_db.init_app(new_app)
    p_bcrypt.init_app(new_app)
    p_login_manager.init_app(new_app)
    p_login_manager.login_view = 'register'
    return new_app


def config_app(config_name, new_app):
	#new_app.config.from_object(config_env_files[config_name])
	APP_ROOT = os.path.join(os.path.dirname(__file__), '..')   # refers to application_top
	dotenv_path = os.path.join(APP_ROOT, '.env')
	load_dotenv(dotenv_path)


app = create_app()

import cmm_flask.views
