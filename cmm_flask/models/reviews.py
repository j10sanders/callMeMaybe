from cmm_flask.models import app_db, app
import datetime

db = app_db()

class Review(db.Model):
    __tablename__ = "reviews"

    id = db.Column(db.Integer, primary_key=True)
    stars = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.String, nullable=False)
    host = db.relationship("User", back_populates="reviews")
    host_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'))
    guest_id = db.Column(db.String, nullable=True)
    guest_initials = db.Column(db.String, nullable=True)
    time = db.Column(db.DateTime, default=datetime.datetime.now())
    


    # def __init__(self, stars, comment, host, guest):
    #     print(stars, comment, host, guest)
    #     self.stars = stars
    #     self.comment = comment
    #     self.host = host
    #     self.time = datetime.datetime.now()
    #     self.guest = guest
