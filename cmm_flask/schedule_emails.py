from datetime import datetime
import time
from cmm_flask.models.user import User
from cmm_flask.models.discussion_profile import DiscussionProfile
from cmm_flask.models.conversation import Conversation
from apscheduler.schedulers.background import BackgroundScheduler
from os import environ as env
from cmm_flask import db, bcrypt, app
# ENV_FILE = find_dotenv()
# if ENV_FILE:
#     load_dotenv(ENV_FILE)
GMAIL = env.get("GMAIL")

def sendEmails():
	with app.app_context():
	    conversations = Conversation.query.all()
	    for convo in conversations:
	    	print(convo.start_time)
    # adminUrl = 'http://localhost:5000/admin/user/edit/?id={}&url=%2Fadmin%2Fuser%2F'.format(host.id)
    # content = 'Subject: New Expert Request!\n{} with message {}'.format(adminUrl, form['message'])
    # smtp_server = smtplib.SMTP('smtp.gmail.com', 587)
    # smtp_server.ehlo()
    # smtp_server.starttls()
    # smtp_server.login('pwreset.winthemini@gmail.com', GMAIL)
    # smtp_server.sendmail('pwreset.winthemini@gmail.com', 'jonsandersss@gmail.com', content)
    # smtp_server.quit()

scheduler = BackgroundScheduler()
scheduler.add_job(sendEmails, 'interval', seconds=3)
scheduler.start()

