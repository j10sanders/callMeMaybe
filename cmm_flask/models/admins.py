from cmm_flask.models import app_db, app
from flask.ext.login import UserMixin
db = app_db()
# bcrypt = bcrypt()

class AdminUser(db.Model, UserMixin):
    __tablename__ = "admins"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)
    password = db.Column(db.String(128), nullable=False)

    def __init__(self, name, password):
    	self.name = name
    	self.password = password