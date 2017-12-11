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

class DevelopmentConfig(DefaultConfig):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:password@localhost/conversation'

class HerokuConfig(DefaultConfig):
    DEBUG = True
    # SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:password@localhost/conversation'


class TestConfig(DefaultConfig):
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:password@localhost/conversation'
    PRESERVE_CONTEXT_ON_EXCEPTION = False
    DEBUG = True
    TESTING = True
    LOGIN_DISABLED = True
    WTF_CSRF_ENABLED = False


config_env_files = {
    'test': 'cmm_flask.config.TestConfig',
    'development': 'cmm_flask.config.DevelopmentConfig',
    'heroku': 'cmm_flask.config.HerokuConfig',
}