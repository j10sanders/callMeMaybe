import os
from cmm_flask.config import config_env_files
from flask import Flask
from flask.ext.bcrypt import Bcrypt
from flask.ext.sqlalchemy import SQLAlchemy
from flask_cors import CORS

db = SQLAlchemy()
bcrypt = Bcrypt()

def create_app(config_name='development', p_db=db, p_bcrypt=bcrypt):
    new_app = Flask(__name__, static_folder="./static/dist")
    CORS(new_app)
    new_app.debug = True
    config_app(config_name, new_app)
    p_db.init_app(new_app)
    p_bcrypt.init_app(new_app)
    return new_app


def config_app(config_name, new_app):
    is_prod = os.environ.get('IS_HEROKU', None)

    if is_prod:
        config_name = 'heroku'

    new_app.config.from_object(config_env_files[config_name])


app = create_app()


import cmm_flask.views
from . import admin_login