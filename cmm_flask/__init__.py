import os
from cmm_flask.config import config_env_files
from flask import Flask

from flask.ext.bcrypt import Bcrypt
from flask.ext.sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()

def create_app(config_name='development', p_db=db, p_bcrypt=bcrypt, p_login_manager=login_manager):
    new_app = Flask(__name__)
    new_app.debug = True
    # env.init_app(new_app)
    config_app(config_name, new_app)
    p_db.init_app(new_app)
    p_bcrypt.init_app(new_app)
    p_login_manager.init_app(new_app)
    p_login_manager.login_view = 'register'
    return new_app


def config_app(config_name, new_app):
    # is_prod = os.environ.get('IS_HEROKU', None)

    # if is_prod:
    #     print("IM PROPSDDDDDDDDDDDDDDDDDDDD")
    #     config_name = 'heroku'
    
    # print(config_name)
    new_app.config.from_object(config_env_files[config_name])



app = create_app()

import cmm_flask.views
