from cmm_flask.models import app_db, auth_token, account_sid, phone_number, application_sid
from flask import render_template
from twilio.rest import Client
import datetime, pytz
from sqlalchemy.sql import func
import pdb
import smtplib

db = app_db()


class Conversation(db.Model):
    __tablename__ = "conversations"

    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String, nullable=False)
    status = db.Column(db.Enum('confirmed', 'rejected', name='conversation_status_enum'),
                       default='confirmed')
    guest_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    discussion_profile_id = db.Column(db.Integer, db.ForeignKey('discussion_profiles.id', ondelete='CASCADE'))
    guest = db.relationship("User", back_populates="conversations")
    guest_phone_number = db.Column(db.String)
    guest_email = db.Column(db.String)
    discussion_profile = db.relationship("DiscussionProfile", back_populates="conversations")
    start_time = db.Column(db.DateTime, server_default=func.now(), nullable=False )
    reviewed = db.Column(db.Boolean, nullable=True, default=False)
    unsubscribed = db.Column(db.Boolean, nullable=True, default=False)

    def __init__(self, message='', discussion_profile='', guest_phone_number='', start_time=datetime.datetime.now(), guest='', guest_email=''):
        self.message = message
        self.guest_phone_number = guest_phone_number
        self.discussion_profile = discussion_profile
        self.status = 'confirmed'
        self.start_time = start_time
        self.guest = guest
        self.guest_email = guest_email

    def confirm(self):
        self.status = 'confirmed'

    def reject(self):
        self.status = 'rejected'

    def __repr__(self):
        return '<Conversation {0}>'.format(self.id)

    def send_email(self):
        if self.unsubscribed or self.reviewed or not self.guest:
            return
        elif datetime.datetime.utcnow() < self.start_time:
            return
        elif self.guest.first_name == 'anonymous':
            return
        else:
            print(datetime.datetime.utcnow() - datetime.timedelta(minutes=15), self.start_time)
            # gfn = self.guest.first_name
            # gln = self.guest.last_name
            # hfn = self.discussion_profile.host.first_name,
            # hln = self.discussion_profile.host.last_name
            # content = 'Subject: How was your conversation with {} {}!\nHi, {} {}.  We hope your conversation with {} {} was helpful.  Please leave a review here http://localhost:3000/discussionProfile?id={} '.format(
            #     hfn, hln, gfn, gln, hfn, hln, discussion_profile_id)
            # smtp_server = smtplib.SMTP('smtp.gmail.com', 587)
            # smtp_server.ehlo()
            # smtp_server.starttls()
            # smtp_server.login('pwreset.winthemini@gmail.com', GMAIL)
            # smtp_server.sendmail('pwreset.winthemini@gmail.com', 'jonsandersss@gmail.com', content)
            # smtp_server.quit()
            print(self.id)

            # {'guest first_name': self.guest.first_name, 'guest last_name': self.guest.last_name,
            # 'host first_name': self.discussion_profile.host.first_name, 'host last_name': self.discussion_profile.host.last_name, 
            # 'discussion_profile_id': self.discussion_profile_id}

    def notify_host(self):
        fmt = '%Y-%m-%d %I:%M %p %Z'
        local_tz = pytz.timezone(self.discussion_profile.timezone)
        aware = self.start_time.replace(tzinfo = pytz.UTC)
        in_local = aware.astimezone(local_tz)
        self._send_message(self.discussion_profile.host.phone_number,
        
                           # render_template('messages/sms_host.txt',
                           #                 #name=self.guest.name,
                           #                 description=self.discussion_profile.description,
                           #                 message=self.message))
                           "You've been booked for a dimpull conversation at {}.  The user says, '{}'.  If you need to cancel, please login to dimpull.com".format(in_local.strftime(fmt), self.message))

    def notify_guest(self):
        self._send_message(self.guest_phone_number,
                           # render_template('messages/sms_guest.txt',
                           #                 description=self.discussion_profile.description,
                           #                 status=self.status))
                          "Your call has been booked.  Make sure you don't miss it!")
        ### need error handling.  When this fails I should know, and it should be save to this conversation.


    def _send_message(self, to, message): 
        self._get_twilio_client().messages \
                                 .create(to,
                                         from_=phone_number(),
                                         body=message)

    def _get_twilio_client(self):
        print("SID, token", Client(account_sid()), Client(auth_token()))
        return Client(account_sid(), auth_token())
