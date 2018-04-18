from cmm_flask.models import app_db

db = app_db()

class Referral(db.Model):
    __tablename__ = "referrals"

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String)
    host_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    host = db.relationship("User", back_populates="referrals")
    referents = db.relationship("Referent", back_populates="referral", passive_deletes=True)