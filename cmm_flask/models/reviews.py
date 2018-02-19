from cmm_flask.models import app_db, app
import datetime

db = app_db()

class Review(db.Model):
    __tablename__ = "reviews"

    id = db.Column(db.Integer, primary_key=True)
    stars = db.Column(db.DateTime, nullable=False)
    comment = db.Column(db.DateTime, nullable=False)
    host_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    host = db.relationship("User", back_populates="reviews")
    time = db.Column(db.DateTime, nullable=True)

    def __init__(self, start_time, end_time, host):
        self.stars = start_time
        self.comment = end_time
        self.host = host
        self.time = datetime.datetime.now()
