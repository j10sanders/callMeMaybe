from flask.ext.login import LoginManager

from . import app
from cmm_flask.models.admins import AdminUser
from cmm_flask import db
from flask import request, redirect, url_for

login_manager = LoginManager()
login_manager.init_app(app)

login_manager.login_view = "login_get"
login_manager.login_message_category = "danger"

@login_manager.user_loader
def load_user(id):
    return db.session.query(AdminUser).get(int(id))