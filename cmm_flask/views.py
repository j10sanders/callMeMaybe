from cmm_flask import db, bcrypt, app, login_manager
from flask import session, g, request, flash, Blueprint, render_template
from flask.ext.login import login_user, logout_user, current_user, login_required
import twilio.twiml
from flask_wtf import RecaptchaField
from twilio.twiml.messaging_response import Message, MessagingResponse
from twilio.twiml.voice_response import Dial, Number, VoiceResponse
from cmm_flask.forms import RegisterForm, LoginForm, DiscussionProfileForm, ConversationForm, \
    ConversationConfirmationForm, ExchangeForm
from cmm_flask.view_helpers import twiml, view, redirect_to, view_with_params
from cmm_flask.models import init_models_module
import json

init_models_module(db, bcrypt, app)

from cmm_flask.models.user import User
from cmm_flask.models.discussion_profile import DiscussionProfile
from cmm_flask.models.conversation import Conversation
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import Forbidden
import pdb

@app.route('/api/register', methods=["POST"])
def register():
    # form = RegisterForm()
    form=request.get_json()
    print(form, "HELLO")
    # pdb.set_trace()

    tel = form['phone_number'] #"+{0}{1}".format(form.country_code.data, form.phone_number.data)
    if User.query.filter(User.email == form['email']).count() > 0:
        # form.email.errors.append("Email address already in use.")
        print("Email address already in use.")
        return "Email address already in use."
    elif User.query.filter(User.phone_number == tel).count() > 0:
        #form.email.errors.append("Phone number already in use.")
        #return view('register', form)
        return "Phone number already in use."

    user = User(
            name=form['name'],
            email=form['email'],
            password=generate_password_hash(form['password']),
            phone_number=tel,
            area_code=str(tel)[0:3])

    db.session.add(user)
    db.session.commit()
    login_user(user, remember=True)

    #return redirect_to('home')
    return "redirect to home"


@app.route('/api/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            candidate_user = User.query.filter(User.email == form.email.data).first()

            if candidate_user is None or not check_password_hash(candidate_user.password,
                                                                        form.password.data):
                form.password.errors.append("Invalid credentials.")
                return view('login', form)

            login_user(candidate_user, remember=True)
            return redirect_to('home')
    return view('login', form)
    


@app.route('/logout', methods=["POST"])
@login_required
def logout():
    logout_user()
    return redirect_to('home')


# @app.route('/', methods=['GET'])
# def index():
#     return render_template('index.html')


@app.route('/<path:path>', methods=['GET'])
def any_root_path(path):
    return render_template('index.html')




# @app.route('/home', methods=["GET"])
# def home():
#     return render_template('./src/home.html')


@app.route('/api/discussions', methods=["GET"])
def discussions():
    discussion_profiles = DiscussionProfile.query.all()
    obj = []
    for ds in discussion_profiles:
        obj.append({'id':ds.id, 'host':ds.host.name, 'image':ds.image_url, 'description': ds.description})
    # pdb.set_trace()
    objs=json.dumps(obj)
    return objs


@app.route('/conversations', methods=["GET"])
@app.route('/conversations/', methods=["POST"], defaults={'discussion_id': None})
@app.route('/conversations/<discussion_id>', methods=["GET", "POST"])
def new_conversation():
    discussion_id = request.query_string[3:] # ex) 'id=423'
    # pdb.set_trace()
    discussion_profile = None
    # form.discussion_id.data = discussion_id

    if request.method == 'POST': #this is where I'll need truffle/Meta Mask.  May also need to send a verification text.
        if form.validate_on_submit():
            # guest = User.query.get(current_user.get_id())

            #guest_phone_number = form.phone_number.data
            guest_phone_number = generate_password_hash(form.message.phone_number)
            discussion_profile = DiscussionProfile.query.get(form.discussion_id.data)
            conversation = Conversation(form.message.data, discussion_profile, guest_phone_number)
            db.session.add(conversation)
            db.session.commit()

            conversation.notify_host()

            return redirect_to('discussions')

    if discussion_id is not None:
        dp = DiscussionProfile.query.get(int(discussion_id))
    profile=json.dumps({'host': dp.host.name, 'image': dp.image_url, 'description': dp.description,
        'anonymous_phone_number': dp.anonymous_phone_number
    })
    return profile


@app.route('/discussions/new', methods=["GET", "POST"])
@login_required
def new_discussion():
    form = DiscussionProfileForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            host = User.query.get(current_user.get_id())
            # anonymous_phone_number = DiscussionProfile.buy_number() #missing required self.
            discussion = DiscussionProfile(form.description.data, form.image_url.data, host) #need to push an anon phone # here.
            discussion.anonymous_phone_number = discussion.buy_number().phone_number
            db.session.add(discussion)
            db.session.commit()
            return redirect_to('discussions')

    return view('discussion_new', form)

@app.route('/discussions/test_new', methods=["GET", "POST"])
@login_required
def test_new_discussion():
    form = DiscussionProfileForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            host = User.query.get(current_user.get_id())
            # anonymous_phone_number = DiscussionProfile.buy_number() #missing required self.
            discussion = DiscussionProfile(form.description.data, form.image_url.data, host) #need to push an anon phone # here.
            discussion.anonymous_phone_number = discussion.test_buy_number()
            db.session.add(discussion)
            db.session.commit()
            return redirect_to('discussions')

    return view('discussion_new', form)



# @app.route('/conversations/', methods=["POST"], defaults={'discussion_id': None})
# @app.route('/conversations/<discussion_id>', methods=["GET", "POST"])
# def new_conversation(discussion_id):
#     discussion_profile = None
#     form = ConversationForm()
#     form.discussion_id.data = discussion_id

#     if request.method == 'POST': #this is where I'll need truffle/Meta Mask.  May also need to send a verification text.
#         if form.validate_on_submit():
#             # guest = User.query.get(current_user.get_id())

#             #guest_phone_number = form.phone_number.data
#             guest_phone_number = generate_password_hash(form.message.phone_number)
#             discussion_profile = DiscussionProfile.query.get(form.discussion_id.data)
#             conversation = Conversation(form.message.data, discussion_profile, guest_phone_number)
#             db.session.add(conversation)
#             db.session.commit()

#             conversation.notify_host()

#             return redirect_to('discussions')

#     if discussion_id is not None:
#         discussion_profile = DiscussionProfile.query.get(discussion_id)

#     return view_with_params('conversation', discussion_profile=discussion_profile, form=form)


# @app.route('/conversations', methods=["GET"])
# def conversations():
#     user = User.query.get(current_user.get_id())
#     conversations_as_host = Conversation.query \
#         .filter(DiscussionProfile.host_id == current_user.get_id() and len(DiscussionProfile.conversations) > 0) \
#         .join(DiscussionProfile) \
#         .filter(Conversation.discussion_profile_id == DiscussionProfile.id) \
#         .all()

#     conversations_as_guest = user.conversations

#     return view_with_params('conversations',
#                             conversations_as_guest=conversations_as_guest,
#                             conversations_as_host=conversations_as_host)


@app.route('/conversations/confirm', methods=["POST"])
def confirm_conversation():
    form = ConversationConfirmationForm()
    sms_response_text = "Sorry, it looks like you don't have any conversations to respond to."
    user = User.query.filter(User.phone_number == form.From.data).first()
    conversation = Conversation \
        .query \
        .filter(Conversation.status == 'pending'
                and Conversation.discussion_profile.host.id == user.id) \
        .first()
    if conversation is not None:
        if 'yes' in form.Body.data or 'accept' in form.Body.data or 'Accept' in form.Body.data:
            conversation.confirm()
            if conversation.discussion_profile.anonymous_phone_number is None:
                conversation.discussion_profile.buy_number(user.area_code)
        else:
            conversation.reject()
        db.session.commit()
        sms_response_text = "You have successfully {0} the conversation".format(conversation.status)
        conversation.notify_guest()
    return twiml(_respond_message(sms_response_text))


@app.route('/exchange/sms', methods=["POST"])
def exchange_sms():
    form = ExchangeForm()
    outgoing_number = _gather_outgoing_phone_number(form.From.data, form.To.data)

    response = twilio.twiml.Response()
    response.addSms(form.Body.data, to=outgoing_number)
    return twiml(response)


@app.route('/exchange/voice', methods=["POST"])
def exchange_voice():
    form = ExchangeForm()
    outgoing_number = _gather_outgoing_phone_number(form.From.data, form.To.data)

    # response = twilio.twiml.Response()
    # # response.addPlay("http://howtodocs.s3.amazonaws.com/howdy-tng.mp3")
    # response.addDial(outgoing_number)

    response = VoiceResponse()
    dial = Dial(caller_id = form.To.data) # the number the person calls is the same as the reciever sees.
    dial.number(outgoing_number)
    response.append(dial)

    return twiml(response)


# controller utils
@app.before_request
def before_request():
    g.user = current_user
    uri_pattern = request.url_rule
    if current_user.is_authenticated and (
                        uri_pattern == '/' or uri_pattern == '/login' or uri_pattern == '/register'):
        redirect_to('home')


@login_manager.user_loader
def load_user(id):
    try:
        return User.query.get(id)
    except:
        return None


def _gather_outgoing_phone_number(incoming_phone_number, anonymous_phone_number):
    #for all numbers in conversation?


    vacay = Conversation.query \
        .filter(Conversation.discussion_profile.anonymous_phone_number == anonymous_phone_number) \
        .first()
    if check_password_hash(conversation.guest_phone_number, incoming_phone_number):
    # if conversation.guest_phone_number == incoming_phone_number:
        return conversation.discussion_profile.host.phone_number

    return conversation.guest_phone_number


def _respond_message(message):
    response = MessagingResponse()

    response.message(message)
    # response = twilio.twiml.Response()
    # response.message(message)
    return response
