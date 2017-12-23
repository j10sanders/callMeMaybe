from cmm_flask.models import app_db, auth_token, account_sid, phone_number, application_sid
from twilio.rest import Client
import pdb

db = app_db()


class DiscussionProfile(db.Model):
    __tablename__ = "discussion_profiles"

    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String, nullable=False)
    image_url = db.Column(db.String, nullable=False)

    host_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    host = db.relationship("User", back_populates="discussion_profiles")
    conversations = db.relationship("Conversation", back_populates="discussion_profile", passive_deletes=True)
    anonymous_phone_number = db.Column(db.String, nullable=True)

    def __init__(self, description, image_url, host):
        self.description = description
        self.image_url = image_url
        self.host = host

    def __repr__(self):
        return '<DiscussionProfile {0} {1}>'.format(self.id, self.description)

    def buy_number(self, area_code=917):
        numbers = self._get_twilio_client().available_phone_numbers("US") \
                                           .local \
                                           .list(area_code=area_code,
                                                 sms_enabled=True,
                                                 voice_enabled=True)

        if numbers:
            number = self._purchase_number(numbers[0])
            self.anonymous_phone_number = number.phone_number
            return number
        else:
            numbers = self._get_twilio_client().available_phone_numbers("US") \
                                               .local \
                                               .list(sms_enabled=True, voice_enabled=True)
            if numbers:
                number = self._purchase_number(numbers[0])
                self.anonymous_phone_number = number.phone_number
                return number

        return None

    def test_buy_number(self, area_code=814):
        numbers = self._get_twilio_client().available_phone_numbers("US") \
                                           .local \
                                           .list(area_code=area_code,
                                                 sms_enabled=True,
                                                 voice_enabled=True)
        if numbers:
            number=numbers[0].phone_number
            self.anonymous_phone_number = number
            return number
        else:
            number = +18148385175
            self.anonymous_phone_number = number
            return number

        return None

    def _purchase_number(self, number):
        return self._get_twilio_client().incoming_phone_numbers \
                                        .create(sms_application_sid=application_sid(),
                                                voice_application_sid=application_sid(),
                                                phone_number=number.phone_number)

    def _get_twilio_client(self):
        return Client(account_sid(), auth_token())