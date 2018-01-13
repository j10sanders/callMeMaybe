from cmm_flask.models import app_db, app
import pdb

db = app_db()


class TimeSlot(db.Model):
    __tablename__ = "timeslots"

    id = db.Column(db.Integer, primary_key=True)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    host_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    host = db.relationship("User", back_populates="timeslots")

    def __init__(self, start_time, end_time, host):
        self.start_time = start_time
        self.end_time = end_time
        self.host = host
