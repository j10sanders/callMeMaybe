from cmm_flask.models import app_db, auth_token, account_sid, phone_number, application_sid
from twilio.rest import Client
from sqlalchemy import false

db = app_db()

class DiscussionProfile(db.Model):
    __tablename__ = "discussion_profiles"

    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String)
    description = db.Column(db.String, nullable=True)
    image_url = db.Column(db.String, nullable=True)
    otherProfile = db.Column(db.String, nullable=True)
    price = db.Column(db.Float, nullable=True)
    host_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    host = db.relationship("User", back_populates="discussion_profiles")
    conversations = db.relationship("Conversation", back_populates="discussion_profile", passive_deletes=True)
    anonymous_phone_number = db.Column(db.String, nullable=True)
    timezone = db.Column(db.String, server_default='America/New_York', nullable=True)
    who = db.Column(db.String, nullable=True)
    origin = db.Column(db.String, nullable=True)
    excites = db.Column(db.String, nullable=True)
    helps = db.Column(db.String, nullable=True)
    public = db.Column(db.Boolean, nullable=False, server_default=false())
    front_page = db.Column(db.Boolean, nullable=False, server_default=false())
    submitFull = db.Column(db.Boolean, nullable=False, server_default=false())
    walletAddress = db.Column(db.String, nullable=True)
    medium = db.Column(db.String, nullable=True)
    twitter = db.Column(db.String, nullable=True)
    linkedin = db.Column(db.String, nullable=True)
    github = db.Column(db.String, nullable=True)
    vipid = db.Column(db.String, nullable=True)

    def __init__(self, host, otherProfile):
        # self.description = description
        # self.image_url = image_url
        self.host = host
        self.otherProfile = otherProfile
        # self.price = price
        # self.timezone = timezone
        # self.who = who

    def __repr__(self):
        return '<DiscussionProfile {0} {1}>'.format(self.id, self.description)

    def buy_number(self):
        numbers = self._get_twilio_client().available_phone_numbers("US") \
                                           .local \
                                           .list(
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
