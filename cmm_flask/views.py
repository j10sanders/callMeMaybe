from cmm_flask import db, bcrypt, app
from flask import session, g, request, flash, render_template, make_response, jsonify, _app_ctx_stack
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
from functools import wraps
from os import environ as env
from six.moves.urllib.request import urlopen
from flask_cors import cross_origin
from jose import jwt
from dotenv import load_dotenv, find_dotenv

init_models_module(db, bcrypt, app)

from cmm_flask.models.user import User
from cmm_flask.models.discussion_profile import DiscussionProfile
from cmm_flask.models.conversation import Conversation
from cmm_flask.models.timeslot import TimeSlot
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import Forbidden
import pdb
import datetime

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)
AUTH0_DOMAIN = env.get("AUTH0_DOMAIN")
AUTH0_AUDIENCE = 'https://jonsanders.auth0.com/api/v2/'
ALGORITHMS = ["RS256"]


###
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

def get_token_auth_header():
    """Obtains the access token from the Authorization Header
    """
    auth = request.headers.get("Authorization", None)
    if not auth:
        raise AuthError({"code": "authorization_header_missing",
                        "description":
                            "Authorization header is expected"}, 401)

    parts = auth.split()

    if parts[0].lower() != "bearer":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Authorization header must start with"
                            " Bearer"}, 401)
    elif len(parts) == 1:
        raise AuthError({"code": "invalid_header",
                        "description": "Token not found"}, 401)
    elif len(parts) > 2:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Authorization header must be"
                            " Bearer token"}, 401)

    token = parts[1]
    return token


def requires_scope(required_scope):
    """Determines if the required scope is present in the access token
    Args:
        required_scope (str): The scope required to access the resource
    """
    token = get_token_auth_header()
    unverified_claims = jwt.get_unverified_claims(token)
    if unverified_claims.get("scope"):
        token_scopes = unverified_claims["scope"].split()
        for token_scope in token_scopes:
            if token_scope == required_scope:
                return True
    return False



def requires_auth(f):
    """Determines if the access token is valid
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_auth_header()
        jsonurl = urlopen("https://"+AUTH0_DOMAIN+"/.well-known/jwks.json")
        jwks = json.loads(jsonurl.read())
        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.JWTError:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Invalid header. "
                                "Use an RS256 signed JWT Access Token"}, 401)
        if unverified_header["alg"] == "HS256":
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Invalid header. "
                                "Use an RS256 signed JWT Access Token"}, 401)
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
        if rsa_key:
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=ALGORITHMS,
                    audience=AUTH0_AUDIENCE,
                    issuer="https://"+AUTH0_DOMAIN+"/"
                )
            except jwt.ExpiredSignatureError:
                raise AuthError({"code": "token_expired",
                                "description": "token is expired"}, 401)
            except jwt.JWTClaimsError:
                raise AuthError({"code": "invalid_claims",
                                "description":
                                    "incorrect claims,"
                                    " please check the audience and issuer"}, 401)
            except Exception:
                raise AuthError({"code": "invalid_header",
                                "description":
                                    "Unable to parse authentication"
                                    " token."}, 400)

            _app_ctx_stack.top.current_user = payload
            return f(*args, **kwargs)
        raise AuthError({"code": "invalid_header",
                        "description": "Unable to find appropriate key"}, 400)
    return decorated

###



@app.route('/api/register', methods=["POST"])
# @cross_origin(headers=["Access-Control-Allow-Origin", "*"])
def register():
    # form = RegisterForm()
    form=request.get_json()
    if User.query.filter(User.user_id == form['user_id']).count() > 0:
        return "user previously registered."
    if "phone_number" in form:
        tel = form['phone_number'].replace('-', '') #"+{0}{1}".format(form.country_code.data, form.phone_number.data)
        
        if User.query.filter(User.phone_number == tel).count() > 0:
            #form.email.errors.append("Phone number already in use.")
            #return view('register', form)
            return "Phone number already in use."
        # db.drop_all()
        # db.create_all()
        user = User(
                user_id=form['user_id'],
                # email=form['email'],
                # password=generate_password_hash(form['password']),
                first_name=form['first_name'],
                last_name=form['last_name'],
                auth_pic=form['auth_pic'],
                phone_number=tel,
                area_code=tel[2:5]
            )

        db.session.add(user)
        db.session.commit()
        print(form, "HELLO")
        return "done"

    else: 
        return "register phone"

def get_user_id(t):
    s_t = t.split()
    token = s_t[1]
    jsonurl = urlopen("https://"+AUTH0_DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    payload = jwt.decode(
        token,
        rsa_key,
        algorithms=ALGORITHMS,
        audience=AUTH0_AUDIENCE,
        issuer="https://"+AUTH0_DOMAIN+"/"
    )
    return payload['sub']

@app.route('/api/discussions', methods=["GET"])
@cross_origin(headers=["Content-Type", "Authorization"])
# @cross_origin(headers=["Access-Control-Allow-Origin", "*"])
# @requires_auth
def discussions():
    discussion_profiles = DiscussionProfile.query.all()
    obj = []
    for ds in discussion_profiles:
        obj.append({'id':ds.id, 'first_name':ds.host.first_name, 'last_name':ds.host.last_name, 
            'auth_pic': ds.host.auth_pic, 'image':ds.image_url, 'description': ds.description,
            })
    objs=json.dumps(obj)
    return objs


@app.route('/api/mydiscussions', methods=["GET"])
@cross_origin(headers=["Content-Type", "Authorization"])
def mydiscussions(): 
    try:
        user_id = get_user_id(request.headers.get("Authorization", None))
    except AttributeError:
        user_id = "nope"
    host = User.query.filter(User.user_id == user_id).one()
    dps = host.discussion_profiles
    if len(dps) > 0:
        obj = []
        for ds in dps:
            obj.append({'id':ds.id, 'first_name':ds.host.first_name, 'last_name':ds.host.last_name, 
                'auth_pic': ds.host.auth_pic, 'image':ds.image_url, 'description': ds.description,
                })
        objs=json.dumps(obj)
        return objs
    else:
        return "user has no discussion profiles"
    return "error"

@app.route('/discussion', methods=["GET"])
@app.route('/discussion/<discussion_id>', methods=["GET"])
@cross_origin(headers=["Content-Type", "Authorization"])
def discussion_profile(): 
    try:
        user_id = get_user_id(request.headers.get("Authorization", None))
    except AttributeError:
        user_id = "nope"
    discussion_id = request.query_string[3:] # ex) 'id=423'
    discussion_profile = None
    if discussion_id is not None:
        dp = DiscussionProfile.query.get(int(discussion_id))
        is_users = False
        if dp.host.user_id == user_id:
            is_users = True
        profile=json.dumps({'host': dp.host.user_id, 'image': dp.image_url, 'description': dp.description,
            'anonymous_phone_number': dp.anonymous_phone_number, 'auth_pic': dp.host.auth_pic, 'first_name':dp.host.first_name, 
            'last_name':dp.host.last_name, 'is_users': is_users
        })
        return profile
    return "error"


@app.route('/api/discussions/new', methods=["GET", "POST"])
# @cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
def new_discussion():
    form=request.get_json()
    if request.method == 'POST':
        host = User.query.filter(User.user_id == form['user_id']).one()
        # host = session.query(User).filter_by(user_id=form['user_id']).one()
        # anonymous_phone_number = DiscussionProfile.buy_number() #missing required self.
        discussion = DiscussionProfile(
            description = form['description'], 
            image_url = form['image_url'], 
            host = host,
            otherProfile = form['otherProfile'],
            price = float(form['price'])
        ) #need to push an anon phone # here.
        discussion.anonymous_phone_number = discussion.buy_number().phone_number
        db.session.add(discussion)
        db.session.commit()
        return 'success'

    return "error"

### 

@app.route('/editdiscussions/<discussion_id>', methods=["GET", "POST"])
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
def edit_discussion():
    try:
        user_id = get_user_id(request.headers.get("Authorization", None))
    except AttributeError:
        user_id = "nope"
    
    discussion_id = request.query_string[3:]

    if request.method == 'POST':
        #I think below works.  maybe some way to integrate it into current method?  Or maybe not, since it needs to keep current discussion id
        
        '''host = User.query.filter(User.user_id == form['user_id']).one()
        # host = session.query(User).filter_by(user_id=form['user_id']).one()
        # anonymous_phone_number = DiscussionProfile.buy_number() #missing required self.
        discussion = DiscussionProfile(
            description = form['description'], 
            image_url = form['image_url'], 
            host = host,
            otherProfile = form['otherProfile'],
            price = float(form['price'])
        ) #need to push an anon phone # here.
        discussion.anonymous_phone_number = discussion.buy_number().phone_number
        db.session.add(discussion)
        db.session.commit()
        return 'success' '''

    if request.method == 'GET':
        form=request.get_json()
        #return all the info for that discussion id, if user is correct


    return "error"


@app.route('/conversations', methods=["GET", "POST"])
@app.route('/conversations/', methods=["POST"])
@app.route('/conversations/<discussion_id>', methods=["GET", "POST"])
def new_conversation():
    discussion_id = request.query_string[3:] # ex) 'id=423'
    discussion_profile = None
    # form.discussion_id.data = discussion_id
    form=request.get_json()
    if 'phone_number' in form: #this is where I'll need truffle/Meta Mask.  May also need to send a verification text.
        # guest_phone_number = generate_password_hash(form['phone_number'])
        guest_phone_number = form['phone_number'].replace('-', '')
        discussion_profile = DiscussionProfile.query.get(int(discussion_id))
        conversation = Conversation(form['message'], discussion_profile, guest_phone_number=form['phone_number'].replace('-', ''))
        db.session.add(conversation)
        db.session.commit()

        conversation.notify_host()

        return 'whitelisted'
    return "error"


@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
@app.route('/api/savetimeslots', methods=["POST"])
def savetimeslots():
    form=request.get_json()
    if request.method == 'POST':
        host = User.query.filter(User.user_id == form['user_id']).one()
        times = form['times']
        for i in times:
            timeslot = TimeSlot(
                start_time = i['startDate'],
                end_time = i['endDate'],
                host = host,
            )
            db.session.add(timeslot)
            db.session.commit()
        return 'success'
    return 'error'


@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
@app.route('/api/gettimeslots/', methods=["GET"])
# @app.route('/api/gettimeslots/<discussion_id>', methods=["GET", "POST"])
def gettimeslots():
    form=request.get_json()
    discussion_id = request.query_string[3:]
    discussion_profile = DiscussionProfile.query.get(int(discussion_id))
    host = discussion_profile.host
    obj = []
    for i in host.timeslots:
        if datetime.datetime.now() < i.end_time:
            obj.append({'start_time': i.start_time.isoformat(), 'end_time': i.end_time.isoformat()})

    times=json.dumps(obj)
    print(times)
    return times

    # return 'error'

@app.route('/discussions/test_new', methods=["GET", "POST"])
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


def _gather_outgoing_phone_number(incoming_phone_number, anonymous_phone_number):
    #for all numbers in conversation?
    print("gathering")
    vacay = Conversation.query \
        .filter(Conversation.discussion_profile.anonymous_phone_number == anonymous_phone_number) \
        .first()
    # if check_password_hash(conversation.guest_phone_number, incoming_phone_number):
    if conversation.guest_phone_number == incoming_phone_number:
        return conversation.discussion_profile.host.phone_number

    return conversation.guest_phone_number


def _respond_message(message):
    response = MessagingResponse()

    response.message(message)
    # response = twilio.twiml.Response()
    # response.message(message)
    return response