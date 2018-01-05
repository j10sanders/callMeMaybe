from cmm_flask.models import app_db, app
# from cmm_flask.models import bcrypt
import datetime
import jwt

db = app_db()
# bcrypt = bcrypt()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.String, nullable=False)
    # first_name = db.Column(db.String, nullable=False, server_default="default first name")
    # last_name = db.Column(db.String, nullable=False, server_default="default last name")
    # email = db.Column(db.String(255), unique=True, nullable=False)
    # password = db.Column(db.String(255), nullable=False)
    registered_on = db.Column(db.DateTime, nullable=True)
    phone_number = db.Column(db.String, nullable=True)
    area_code = db.Column(db.String, nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)

    #conversations = db.relationship("Conversation", back_populates="guest")
    discussion_profiles = db.relationship("DiscussionProfile", back_populates="host")

    def __init__(self, user_id, area_code, phone_number, admin=False):
        # self.email = email
        # self.name = name
        # self.password = bcrypt.generate_password_hash(
        #     password, app.config.get('BCRYPT_LOG_ROUNDS')
        # ).decode()
        self.user_id = user_id
        self.registered_on = datetime.datetime.now()
        self.admin = admin
        self.phone_number = phone_number
        self.area_code = area_code
        

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        try:
            return unicode(self.id)
        except NameError:
            return str(self.id)

    # Python 3

    def __unicode__(self):
        return self.user_id

    def __repr__(self):
        return '<User %r>' % (self.user_id)

#     def is_authenticated(self):
#         return True

#     def is_active(self):
#         return True

#     def is_anonymous(self):
#         return False

#     def get_id(self):
#         try:
#             return unicode(self.id)
#         except NameError:
#             return str(self.id)

#     # Python 3

#     def __unicode__(self):
#         return self.id

#     def __repr__(self):
#         return '<User %r>' % (self.id)

#         def encode_auth_token(self, user_id):
#             """
#             Generates the Auth Token
#             :return: string
#             """
#             try:
#                 payload = {
#                     'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=5),
#                     'iat': datetime.datetime.utcnow(),
#                     'sub': user_id
#                 }
#                 return jwt.encode(
#                     payload,
#                     app.config.get('SECRET_KEY'),
#                     algorithm='HS256'
#                 )
#             except Exception as e:
#                 return e

#     @staticmethod
#     def decode_auth_token(auth_token):
#         """
#         Decodes the auth token
#         :param auth_token:
#         :return: integer|string
#         """
#         try:
#             payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'))
#             is_blacklisted_token = BlacklistToken.check_blacklist(auth_token)
#             if is_blacklisted_token:
#                 return 'Token blacklisted. Please log in again.'
#             else:
#                 return payload['sub']
#         except jwt.ExpiredSignatureError:
#             return 'Signature expired. Please log in again.'
#         except jwt.InvalidTokenError:
#             return 'Invalid token. Please log in again.'


# class BlacklistToken(db.Model):
#     """
#     Token Model for storing JWT tokens
#     """
#     __tablename__ = 'blacklist_tokens'

#     id = db.Column(db.Integer, primary_key=True, autoincrement=True)
#     token = db.Column(db.String(500), unique=True, nullable=False)
#     blacklisted_on = db.Column(db.DateTime, nullable=False)

#     def __init__(self, token):
#         self.token = token
#         self.blacklisted_on = datetime.datetime.now()

#     def __repr__(self):
#         return '<id: token: {}'.format(self.token)

#     @staticmethod
#     def check_blacklist(auth_token):
#         # check whether auth token has been blacklisted
#         res = BlacklistToken.query.filter_by(token=str(auth_token)).first()
#         if res:
#             return True
#         else:
#             return False