import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))


class DefaultConfig(object):
    APP_ROOT = os.path.join(os.path.dirname(__file__), '..')   # refers to application_top
    dotenv_path = os.path.join(APP_ROOT, '.env')
    load_dotenv(dotenv_path)
    TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
    TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
    TWILIO_NUMBER =  os.environ.get("TWILIO_NUMBER")
    APPLICATION_SID = os.environ.get("APPLICATION_SID")
    SQLALCHEMY_DATABASE_URI =  os.environ["DATABASE_URL"]
    SECRET_KEY = os.environ.get("SECRET_KEY", os.urandom(12))
    RECAPTCHA_PUBLIC_KEY = "6Le1oTwUAAAAAFTxrBQ5y45_ZUBRAzJnheaw1UG3"
    RECAPTCHA_PRIVATE_KEY = os.environ.get("RECAPTCHA_PRIVATE_KEY")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    REACT_APP_USERS_SERVICE_URL='http://localhost:5000'
    BCRYPT_LOG_ROUNDS = 13
    AUTH0_CLIENT_ID = os.environ.get("CLIENT_ID")
    AUTH0_DOMAIN = os.environ.get("DOMAIN")
    AUTH0_CLIENT_SECRET = os.environ.get("CLIENT_SECRET")

class DevelopmentConfig(DefaultConfig):
    DEBUG = True
    BCRYPT_LOG_ROUNDS = 4
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:password@localhost/auth'

class HerokuConfig(DefaultConfig):
    DEBUG = True
    # SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:password@localhost/auth'


class TestConfig(DefaultConfig):
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:password@localhost/auth'
    PRESERVE_CONTEXT_ON_EXCEPTION = False
    DEBUG = True
    TESTING = True
    LOGIN_DISABLED = True
    WTF_CSRF_ENABLED = False
    BCRYPT_LOG_ROUNDS = 4


config_env_files = {
    'test': 'cmm_flask.config.TestConfig',
    'development': 'cmm_flask.config.DevelopmentConfig',
    'heroku': 'cmm_flask.config.HerokuConfig',
}