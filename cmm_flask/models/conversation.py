from cmm_flask.models import app_db, auth_token, account_sid, phone_number, application_sid
from flask import render_template
from twilio.rest import Client
import datetime, pytz
from sqlalchemy.sql import func
import pdb

DB = app_db()


class Conversation(DB.Model):
    __tablename__ = "conversations"

    id = DB.Column(DB.Integer, primary_key=True)
    message = DB.Column(DB.String, nullable=False)
    status = DB.Column(DB.Enum('pending', 'confirmed', 'rejected', name='conversation_status_enum'),
                       default='pending')
    
    #guest_id = DB.Column(DB.Integer, DB.ForeignKey('users.id'))
    discussion_profile_id = DB.Column(DB.Integer, DB.ForeignKey('discussion_profiles.id', ondelete='CASCADE'))
    #guest = DB.relationship("User", back_populates="conversations")
    guest_phone_number = DB.Column(DB.String)
    discussion_profile = DB.relationship("DiscussionProfile", back_populates="conversations")
    start_time = DB.Column(DB.DateTime, server_default=func.now(), nullable=False )

    def __init__(self, message, discussion_profile, guest_phone_number, start_time):
        self.message = message
        self.guest_phone_number = guest_phone_number
        self.discussion_profile = discussion_profile
        self.status = 'pending'
        self.start_time = start_time

    def confirm(self):
        self.status = 'confirmed'

    def reject(self):
        self.status = 'rejected'

    def __repr__(self):
        return '<Conversation {0}>'.format(self.id)

    def notify_host(self):
        fmt = '%Y-%m-%d %I:%M %p %Z'
        local_tz = pytz.timezone(self.discussion_profile.timezone)
        aware = self.start_time.replace(tzinfo = pytz.UTC)
        in_local = aware.astimezone(local_tz)
        # date_w_tz = local_tz.localize(self.start_time)
        self._send_message(self.discussion_profile.host.phone_number,
        
                           # render_template('messages/sms_host.txt',
                           #                 #name=self.guest.name,
                           #                 description=self.discussion_profile.description,
                           #                 message=self.message))
                           "Hey!  You have a Dimpull request for a conversation at {} about: '{}'  Reply [accept] or [reject]".format(in_local.strftime(fmt), self.message))

    def notify_guest(self):
        self._send_message(self.guest_phone_number,
                           # render_template('messages/sms_guest.txt',
                           #                 description=self.discussion_profile.description,
                           #                 status=self.status))
                          "hello guest. your call was something")
        ### need error handling.  When this fails I should know, and it should be save to this conversation.


    def _send_message(self, to, message): 
        self._get_twilio_client().messages \
                                 .create(to,
                                         from_=phone_number(),
                                         body=message)

    def _get_twilio_client(self):
        print("SID, token", Client(account_sid()), Client(auth_token()))
        return Client(account_sid(), auth_token())
