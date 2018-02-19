from datetime import datetime
import time
from cmm_flask.models.user import User
from cmm_flask.models.discussion_profile import DiscussionProfile
from cmm_flask.models.conversation import Conversation
from apscheduler.schedulers.background import BackgroundScheduler
from os import environ as env
from cmm_flask import db, bcrypt, app
import atexit

GMAIL = env.get("GMAIL")

def sendEmails():
    with app.app_context():
        print(datetime.now())
        conversations = Conversation.query.all()
        for convo in conversations:
            convo.send_email()
    atexit.register(lambda: scheduler.shutdown())

scheduler = BackgroundScheduler()
scheduler.add_job(sendEmails, 'interval', seconds=30)
scheduler.start()

