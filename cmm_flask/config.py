import os

basedir = os.path.abspath(os.path.dirname(__file__))


import os
class DevelopmentConfig(object):
    SQLALCHEMY_DATABASE_URI =  os.environ["DATABASE_URL"]
    DEBUG = False
    SECRET_KEY = os.environ.get("CROSSWORD_SECRET_KEY", os.urandom(12))


# config_env_files = {
#     'test': 'cmm_flask.config.TestConfig',
#     'development': 'cmm_flask.config.DevelopmentConfig',
# }