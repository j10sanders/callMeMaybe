from cmm_flask.models import app_db
from flask import render_template
import datetime, pytz
import smtplib

db = app_db()

class Referent(db.Model):
    __tablename__ = "referents"

    id = db.Column(db.Integer, primary_key=True)
    referent_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    referral_id = db.Column(db.Integer, db.ForeignKey('referrals.id', ondelete='CASCADE'))
    referent = db.relationship("User", back_populates="referents")
    referral = db.relationship("Referral", back_populates="referents")
    start_time = db.Column(db.DateTime)

    def __init__(self, discussion_profile='', referent=''):
        self.referral = referral
        self.referent = referent
