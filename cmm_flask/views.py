from cmm_flask import db, bcrypt, app, login_manager
from flask import session, g, request, flash, Blueprint, render_template, Blueprint, make_response, jsonify
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
from flask.views import MethodView

init_models_module(db, bcrypt, app)

from cmm_flask.models.user import User, BlacklistToken
from cmm_flask.models.discussion_profile import DiscussionProfile
from cmm_flask.models.conversation import Conversation
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import Forbidden
import pdb

auth_blueprint = Blueprint('auth', __name__)

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

'''blueprint views: '''

auth_blueprint = Blueprint('auth', __name__)

class RegisterAPI(MethodView):
    """
    User Registration Resource
    """

    def post(self):
        pdb.set_trace()
        # get the post data
        post_data = request.get_json()
        # check if user already exists
        user = User.query.filter_by(email=post_data.get('email')).first()
        if not user:
            try:
                user = User(
                    email=post_data.get('email'),
                    password=post_data.get('password')
                )

                # insert the user
                db.session.add(user)
                db.session.commit()
                # generate the auth token
                auth_token = user.encode_auth_token(user.id)
                responseObject = {
                    'status': 'success',
                    'message': 'Successfully registered.',
                    'auth_token': auth_token.decode()
                }
                return make_response(jsonify(responseObject)), 201
            except Exception as e:
                responseObject = {
                    'status': 'fail',
                    'message': 'Some error occurred. Please try again.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'User already exists. Please Log in.',
            }
            return make_response(jsonify(responseObject)), 202

class LoginAPI(MethodView):
    """
    User Login Resource
    """
    def post(self):
        # get the post data
        post_data = request.get_json()
        try:
            # fetch the user data
            user = User.query.filter_by(
                email=post_data.get('email')
            ).first()
            if user and bcrypt.check_password_hash(
                user.password, post_data.get('password')
            ):
                auth_token = user.encode_auth_token(user.id)
                if auth_token:
                    responseObject = {
                        'status': 'success',
                        'message': 'Successfully logged in.',
                        'auth_token': auth_token.decode()
                    }
                    return make_response(jsonify(responseObject)), 200
            else:
                responseObject = {
                    'status': 'fail',
                    'message': 'User does not exist.'
                }
                return make_response(jsonify(responseObject)), 404
        except Exception as e:
            print(e)
            responseObject = {
                'status': 'fail',
                'message': 'Try again'
            }
            return make_response(jsonify(responseObject)), 500

class UserAPI(MethodView):
    """
    User Resource
    """
    def get(self):
        # get the auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                responseObject = {
                    'status': 'fail',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                user = User.query.filter_by(id=resp).first()
                responseObject = {
                    'status': 'success',
                    'data': {
                        'user_id': user.id,
                        'email': user.email,
                        'admin': user.admin,
                        'registered_on': user.registered_on
                    }
                }
                return make_response(jsonify(responseObject)), 200
            responseObject = {
                'status': 'fail',
                'message': resp
            }
            return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 401

class LogoutAPI(MethodView):
    """
    Logout Resource
    """
    def post(self):
        # get auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                # mark the token as blacklisted
                blacklist_token = BlacklistToken(token=auth_token)
                try:
                    # insert the token
                    db.session.add(blacklist_token)
                    db.session.commit()
                    responseObject = {
                        'status': 'success',
                        'message': 'Successfully logged out.'
                    }
                    return make_response(jsonify(responseObject)), 200
                except Exception as e:
                    responseObject = {
                        'status': 'fail',
                        'message': e
                    }
                    return make_response(jsonify(responseObject)), 200
            else:
                responseObject = {
                    'status': 'fail',
                    'message': resp
                }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 403

# define the API resources
registration_view = RegisterAPI.as_view('register_api')
login_view = LoginAPI.as_view('login_api')
user_view = UserAPI.as_view('user_api')
logout_view = LogoutAPI.as_view('logout_api')

# add Rules for API Endpoints
auth_blueprint.add_url_rule(
    '/auth/register',
    view_func=registration_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/login',
    view_func=login_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/status',
    view_func=user_view,
    methods=['GET']
)
auth_blueprint.add_url_rule(
    '/auth/logout',
    view_func=logout_view,
    methods=['POST']
)
