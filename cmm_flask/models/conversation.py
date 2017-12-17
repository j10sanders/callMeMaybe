from cmm_flask.models import app_db, auth_token, account_sid, phone_number, application_sid
from flask import render_template
from twilio.rest import Client

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
    guest_phone_number = db.Column(db.String)
    discussion_profile = DB.relationship("DiscussionProfile", back_populates="conversations")

    def __init__(self, message, discussion_profile, guest_phone_number):
        self.message = message
        self.guest_phone_number = guest_phone_number
        self.discussion_profile = discussion_profile
        self.status = 'pending'

    def confirm(self):
        self.status = 'confirmed'

    def reject(self):
        self.status = 'rejected'

    def __repr__(self):
        return '<Conversation {0}>'.format(self.id)

    def notify_host(self):
        self._send_message(self.discussion_profile.host.phone_number,
                           render_template('messages/sms_host.txt',
                                           name=self.guest.name,
                                           description=self.discussion_profile.description,
                                           message=self.message))

    def notify_guest(self):
        self._send_message(self.guest.phone_number,
                           render_template('messages/sms_guest.txt',
                                           description=self.discussion_profile.description,
                                           status=self.status))

    

    def _send_message(self, to, message):
        self._get_twilio_client().messages \
                                 .create(to,
                                         from_=phone_number(),
                                         body=message)
