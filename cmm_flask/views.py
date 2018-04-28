from cmm_flask import db, bcrypt, app
from flask import session, g, request, flash, render_template, make_response, jsonify, _app_ctx_stack, redirect, url_for
import twilio.twiml
from flask_wtf import RecaptchaField
from twilio.twiml.messaging_response import Message, MessagingResponse
from twilio.twiml.voice_response import Dial, Number, VoiceResponse
from cmm_flask.forms import RegisterForm, LoginForm, DiscussionProfileForm, ConversationForm, \
    ConversationConfirmationForm, ExchangeForm
from cmm_flask.view_helpers import twiml, view, redirect_to, view_with_params
from cmm_flask.models import init_models_module
import json, random, string
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
from cmm_flask.models.referral import Referral
from cmm_flask.models.referents import Referent
from cmm_flask.models.conversation import Conversation
from cmm_flask.models.timeslot import TimeSlot
from cmm_flask.models.reviews import Review
from cmm_flask.models.admins import AdminUser
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import Forbidden
import pdb
import datetime, pytz, requests
from flask_admin import Admin, expose
from flask_admin.contrib.sqla import ModelView
from flask.ext.login import login_user, logout_user, login_required
from flask.ext.login import current_user
from sqlalchemy.exc import IntegrityError
from sqlalchemy import exists
from flask_admin.contrib import sqla
import dateutil.parser
from ics import Calendar, Event
from sqlalchemy import exc
from email.utils import parsedate_to_datetime
from web3.auto import w3

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)
GMAIL = env.get("GMAIL")
AUTH0_DOMAIN = env.get("AUTH0_DOMAIN")
AUTH0_AUDIENCE = env.get("AUTH0_AUDIENCE")
MAILGUN_API_KEY = env.get("MAILGUN_API_KEY")
OCTOPUS_KEY=env.get("OCTOPUS_KEY")
ALGORITHMS = ["RS256"]

class MyView(sqla.ModelView):
    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login_get', next=request.url))
        redirect(request.args.get('next') or url_for("admin.index"))

class MyRefView(sqla.ModelView):
    form_columns = ['host_id', 'host', 'referents', 'code']
    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login_get', next=request.url))
        redirect(request.args.get('next') or url_for("admin.index"))

@app.route("/login", methods=["GET"])
def login_get():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login_post():
    name = request.form["name"]
    password = request.form["password"]
    user = AdminUser.query.filter(AdminUser.name == name).one()
    if not user or not check_password_hash(user.password, password):
        return redirect(url_for("login_get"))
    login_user(user, remember=True)
    return redirect(request.args.get('next') or url_for("admin.index"))

@app.route("/register", methods=["GET"])
def register_get():
    return render_template('register.html')

@app.route("/register", methods=["POST"])
def register_post():
    try: 
        if request.form["name"] not in ["jon", "alex"]:
            return "You aren't an admin.  Get out of here."
        name = AdminUser(name=request.form["name"], password=generate_password_hash(request.form["password"]))
        db.session.add(name)
        db.session.commit()
        login_user(name)
        return redirect(request.args.get("next") or url_for("admin.index"))
    except IntegrityError:
        session.rollback()
        return redirect(url_for("register_get"))

@app.route("/log_out", methods=["GET", "POST"])
def logout():
    logout_user()
    return redirect(url_for("login_get"))

admin=Admin(app, name="Dimpull Dashboard")
admin.add_view(MyView(User, db.session))
admin.add_view(MyView(DiscussionProfile, db.session))
admin.add_view(MyView(Conversation, db.session))
admin.add_view(MyView(TimeSlot, db.session))
admin.add_view(MyView(Review, db.session))
admin.add_view(MyRefView(Referral, db.session))
admin.add_view(MyView(Referent, db.session))

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

@app.route('/api/register', methods=["GET", "POST"])
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
def register(user_id="nope", tel=None, email=None):
    if tel is not None: #this is a user who is requesting a call
        user = User(
            user_id=user_id,
            phone_number=tel,
            area_code=tel[2:5],
            email=email,
            requestExpert=False,
            first_name=email[0],
            last_name=email[1],
            registered_on=datetime.datetime.utcnow()
        )
        db.session.add(user)
        db.session.commit()
        return 'ok'
        # TODO deal with users who request to be an expert after making a call

    try:
        user_id = get_user_id(request.headers.get("Authorization", None))
    except AttributeError:
        user_id = "nope"
    form=request.get_json()
    if request.method != 'GET': #Options is sent locally, instead of post
        if "phone_number" in form:
            tel = form['phone_number'].replace('-', '')
        if 'user_id' in form:
            user_id = form['user_id']
        if User.query.filter(User.phone_number == tel).count() > 0:
            return "Phone number already in use."
        if User.query.filter(User.user_id == user_id).count() > 0:
            user = User.query.filter(User.user_id == user_id).first()
            if User.query.filter(User.phone_number == tel).count() > 0:
                return "Phone number already in use."
            user.phone_number = tel
            user.area_code=tel[2:5]
            db.session.commit()
            return "Updated"
        user = User(
                user_id=user_id,
                first_name=form['first_name'],
                last_name=form['last_name'],
                auth_pic=form['auth_pic'],
                phone_number=tel,
                area_code=tel[2:5],
                requestExpert=True,
            )
        resp = requests.post(
            "https://api.mailgun.net/v3/dimpull.com/messages",
            auth=("api", MAILGUN_API_KEY),
            data={"from": "Jon jon@dimpull.com",
                  "to": ["jonsandersss@gmail.com", "jonsandersss@gmail.com"],
                  "subject": "Someone registered",
                  "text": form['first_name'] + " " + form['last_name']})
        db.session.add(user)
        db.session.commit()
        return "done"
    if User.query.filter(User.user_id == user_id).count() > 0:
        user = User.query.filter(User.user_id == user_id).one()
        if len(user.discussion_profiles) > 0:
            dpId = {'dp': user.discussion_profiles[0].id, 'url': user.discussion_profiles[0].url}
            return json.dumps(dpId)
        return "user previously registered."
    else: 
        return "register phone"

@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
@app.route('/senderror', methods=["POST"])
def senderror():
    form=request.get_json()
    resp = requests.post(
            "https://api.mailgun.net/v3/dimpull.com/messages",
            auth=("api", MAILGUN_API_KEY),
            data={"from": "Jon jon@dimpull.com",
                  "to": ["jonsandersss@gmail.com", "jonsandersss@gmail.com"],
                  "subject": "Someone had an error making a profile",
                  "text": form['err'] + " " + form['email']})
    return

@app.route('/expertrequest', methods=["GET, POST"])
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
def expert_request():
    form = request.get_json()
    return 


@app.route('/api/discussions/<home>', methods=["GET"])
def discussions(home=None):
    discussion_profiles = DiscussionProfile.query.all()
    obj = []
    for ds in discussion_profiles:
        if ds.public:
            if home == 'home':
                if ds.front_page:
                    obj.append(_get_dps(ds)) 
            else:
                obj.append(_get_dps(ds)) 
        objs=json.dumps(obj)
    return objs

def _get_dps(ds):
    ratings = []
    rating = 0
    for i in ds.host.reviews:
        ratings.append(i.stars)
        rating += i.stars
    if len(ratings) > 0:
        averageRating = rating/len(ratings)
    else:
        averageRating = False
    obj = {'id': ds.id, 'url': ds.url, 'first_name': ds.host.first_name, 'last_name': ds.host.last_name, 
        'auth_pic': ds.host.auth_pic, 'image': ds.image_url, 'description': ds.description, 'who': ds.who, 'price': ds.price*1.18, 
        'averageRating': averageRating
    }
    return obj

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
            obj.append({'id':ds.id, 'url': ds.url, 'first_name': ds.host.first_name, 'last_name': ds.host.last_name, 
                'auth_pic': ds.host.auth_pic, 'image':ds.image_url, 'description': ds.description,
                })
        objs=json.dumps(obj)
        return objs
    else:
        return "user has no discussion profiles"
    return "error"

def url_to_dp(url):
    url = url.lower()
    try:
        dp = db.session.query(DiscussionProfile).filter_by(url = url).one()
    except exc.SQLAlchemyError:
        return '404'
    return dp

@app.route('/expert', methods=["GET"])
@app.route('/expert/<url>', methods=["GET"])
@cross_origin(headers=["Content-Type", "Authorization"])
def discussion_profile(url): 
    dp = url_to_dp(url)
    try:
        user_id = get_user_id(request.headers.get("Authorization", None))
    except AttributeError:
        user_id = "nope"
    discussion_profile = None
    if url is not None:
        if dp == '404':
            return '404'
        if not dp:
            return "does not exist"
        if not dp.host.expert:
            return "not an expert yet"
        if not dp.anonymous_phone_number:
            dp.buy_number().phone_number
            db.session.add(dp)
            db.session.commit()
        is_users = False
        if dp.host.user_id == user_id:
            is_users = True
            if not dp.price:
                return 'editProfile'
        who, excites, helps, origin, linkedin, medium, github, twitter = '', '', '', '', '', '', '', ''
        if dp.who:
            who = dp.who
        if dp.excites:
            excites = dp.excites
        if dp.origin:
            origin = dp.origin
        if dp.helps:
            helps = dp.helps
        if dp.twitter:
            twitter = dp.twitter
        if dp.linkedin:
            linkedin = dp.linkedin
        if dp.github:
            github = dp.github
        if dp.medium:
            medium = dp.medium  
        profile={'host': dp.host.user_id, 'image': dp.image_url, 'description': dp.description,
            'anonymous_phone_number': dp.anonymous_phone_number, 'auth_pic': dp.host.auth_pic, 'first_name':dp.host.first_name, 
            'last_name':dp.host.last_name, 'is_users': is_users, 'price': dp.price*1.18, 'otherProfile': dp.otherProfile, 'who': who,
            'origin': dp.origin, 'excites': dp.excites, 'helps': dp.helps, 'url': dp.url, 'id': dp.id, 'linkedin': linkedin,
            'github': github, 'medium': medium, 'twitter': twitter
        }
        reviews = []
        ratings = []
        rating = 0
        for i in dp.host.reviews:
            reviews.append({"stars": i.stars, "comment": i.comment, "guest_initials": i.guest_initials})
            ratings.append(i.stars)
            rating += i.stars
        if len(reviews) > 0:
            if len(ratings) > 0:
                averageRating = rating/len(ratings)
                profile["averageRating"] = averageRating
            profile["reviewlist"] = reviews
        if len(need_review(dp.host, user_id)) > 0:
            profile["needReview"] = True
        else:
            profile = json.dumps(profile)
        return profile
    return "error"

@app.route('/api/discussions/new', methods=["GET", "POST"])
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
def new_discussion():
    form=request.get_json()
    if request.method == 'POST':
        try:
            user_id = get_user_id(request.headers.get("Authorization", None))
        except AttributeError:
            user_id = "nope"
        host = User.query.filter(User.user_id == user_id).one()
        url = _make_url(host)
        discussion = DiscussionProfile(
            host = host,
            otherProfile = form['otherProfile'],
        )
        discussion.url = url
        host.requestExpert = True
        host.email = form["email"]
        host.messageforAdmins = form['message']
        refs = host.referrals
        if len(host.referrals) < 1:
            for x in range(0, 100):
                code = ''.join(random.choices(string.ascii_letters + string.digits, k=7))
                (ret, ), = db.session.query(exists().where(Referral.code==code))
                if not ret:
                    referral = Referral(
                        host = host,
                        code=code
                    )
                db.session.add(referral)
                db.session.add(discussion)
                db.session.commit()
                return url
    return "error"

def _make_url(host):
    name = host.first_name.lower() + '-' + host.last_name.lower()
    for x in range(0, 100):
        if x == 0:
            newName = name
        else: 
            newName = name + str(x)
        (ret, ), = db.session.query(exists().where(DiscussionProfile.url==newName))
        if not ret:
            return newName

def _make_random_id(review):
    for x in range(0, 100):
        code = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
        if review:
            (ret, ), = db.session.query(exists().where(Referral.code==code))
        else:
            (ret, ), = db.session.query(exists().where(DiscussionProfile.vipid==code))
        if not ret:
            return code
    return 'error'

@app.route('/url', methods=["GET"])
@app.route('/urlcheck/<url>', methods=["GET"])
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
def url_check(url):
    url = url.lower()
    (ret, ), = db.session.query(exists().where(DiscussionProfile.url==url))
    if ret:
        try:
            user_id = get_user_id(request.headers.get("Authorization", None))
        except AttributeError:
            return "not available"
        host = User.query.filter(User.user_id == user_id).one()
        if host.discussion_profiles[0].url == url:
            return "available"
        return "not available"
    else:
        return "available"

@app.route('/deleteDiscussion', methods=["GET"])
@app.route('/deleteDiscussion/<discussion_id>', methods=["GET"])
@cross_origin(headers=["Content-Type", "Authorization"])
def deleted_discussion(discussion_id): 
    try:
        user_id = get_user_id(request.headers.get("Authorization", None))
    except AttributeError:
        user_id = "nope"
    if discussion_id is not None:
        dp = DiscussionProfile.query.get(int(discussion_id))
        if dp.host.user_id == user_id:
            db.session.delete(dp)
            db.session.commit()
            return "deleted"
    return "error"

@app.route('/editProfile', methods=["GET", "POST"])
@app.route('/editProfile/<url>', methods=["GET", "POST"])
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
def edit_discussion(url=None):
    try:
        user_id = get_user_id(request.headers.get("Authorization", None))
    except AttributeError:
        user_id = "nope"

    if User.query.filter(User.user_id == user_id).count() > 0:
        user = User.query.filter(User.user_id == user_id).one()
    else:
        return '404'
    if url:
        dp = url_to_dp(url)
        if dp == '404':
            return '404'
    else:
        dp = user.discussion_profiles[0]
    if request.method == 'POST':
        form=request.get_json()
        if dp.host.user_id == form['user_id']:
            dp.public = form['submitFull']
            dp.submitFull = form['submitFull']
            dp.description = form['description']
            dp.image_url = form['image_url']
            # dp.otherProfile = form['otherProfile'],
            dp.price = float(form['price'])
            dp.timezone = form['timezone']
            dp.who = form['who']
            dp.excites = form['excites']
            dp.origin = form['origin']
            dp.helps = form['helps']
            dp.url = form['url'].lower()
            dp.walletAddress = form['walletAddress']
            dp.linkedin = form['linkedin']
            dp.medium = form['medium']
            dp.twitter = form['twitter']
            dp.github = form['github']
            db.session.commit()
            resp = requests.post(
                "https://api.mailgun.net/v3/dimpull.com/messages",
                auth=("api", MAILGUN_API_KEY),
                data={"from": "Jon jon@dimpull.com",
                      "to": ["jonsandersss@gmail.com", "jonsandersss@gmail.com"],
                      "subject": "Someone edited their profile",
                      "text": url})
            return 'success'
        else: 
            return "wrong user"

    if request.method == 'GET':
        if len(user.discussion_profiles) < 1:
            return 'newProfile' # TODO: check what client does
        dp = user.discussion_profiles[0]
        if dp.host.user_id != user_id:
            return "Not this user's"

        who, excites, helps, origin, url, walletAddress, linkedin, medium, twitter, github = '', '', '', '', '', '', '', '', '', ''
        if dp.who:
            who = dp.who
        if dp.excites:
            excites = dp.excites
        if dp.origin:
            origin = dp.origin
        if dp.helps:
            helps = dp.helps
        if dp.url:
            url = dp.url
        if dp.walletAddress:
            walletAddress = dp.walletAddress
        if dp.twitter:
            twitter = dp.twitter
        if dp.linkedin:
            linkedin = dp.linkedin
        if dp.github:
            github = dp.github
        if dp.medium:
            medium = dp.medium 
        return jsonify({'description': dp.description, 'image_url': dp.image_url, 'price': dp.price, 'otherProfile': dp.otherProfile, 
            'timezone': dp.timezone, 'who': who, 'excites': excites, 'origin': origin, "helps": helps, 'url': url,
            'walletAddress': walletAddress, 'github': github, 'linkedin': linkedin, 'medium': medium, 'twitter': twitter,
            'first_name': dp.host.first_name, 'last_name': dp.host.last_name})
    return "error"

@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
@cross_origin(headers=["Content-Type", "Authorization"])
@app.route('/holdtimeslot/<dpid>', methods=["POST"])
def host_timeslot(dpid):
    form=request.get_json()
    discussion_profile = DiscussionProfile.query.get(int(dpid))
    time = form['start_time']
    host = discussion_profile.host
    newdate = dateutil.parser.parse(time)
    naive = newdate.replace(tzinfo=None)
    for slot in host.timeslots:
        if slot.start_time == naive:
            if not slot.pending or (slot.pending_time - datetime.datetime.utcnow()).total_seconds() / 60 > 12.1:
                slot.pending = True
                slot.pending_time = datetime.datetime.utcnow()
                db.session.commit()
                return "added pending"
            return "currently pending"
    return "error"

@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
@cross_origin(headers=["Content-Type", "Authorization"])
@app.route('/conversations/<dpid>', methods=["GET", "POST"])
def new_conversation(dpid):
    form=request.get_json()
    try:
        user_id = get_user_id(request.headers.get("Authorization", None))
        try: 
            guest = User.query.filter(User.user_id == user_id).one()
        except exc.SQLAlchemyError:
            register(user_id, form['phone_number'], form['email'])
            guest = User.query.filter(User.user_id == user_id).one()
    except AttributeError:
        guest = User.query.filter(User.user_id == 'Anonymous').one()
        user_id = None
    discussion_profile = None

    if 'phone_number' in form:
        guest_phone_number = form['phone_number'].replace('-', '')
        guest_email = form['email']

    if user_id is not None:
        if guest.phone_number != guest_phone_number:
            guest.phone_number = guest_phone_number

    time = form['start_time']
    guest_wallet_address = form['fromAddress']
    discussion_profile = DiscussionProfile.query.get(int(dpid))
    discussion_profile.vipid = _make_random_id(review=False)
    review_id = _make_random_id(review=True)
    conversation = Conversation(message=form['message'], discussion_profile=discussion_profile, guest_phone_number=guest_phone_number,
        start_time=time, guest=guest, guest_email=guest_email, review_id=review_id, guest_wallet_address=guest_wallet_address)
    host = discussion_profile.host
    hostEmail = host.email
    newdate = dateutil.parser.parse(time)
    naive = newdate.replace(tzinfo=None)
    for i in host.timeslots:
        if i.start_time == naive:
            db.session.delete(i)

    db.session.add(conversation)
    db.session.commit()
    conversation.notify_host()

    anonymous_phone_number = discussion_profile.anonymous_phone_number

    c = Calendar()
    e = Event()
    e.name = "Dimpull Call"
    e.begin = naive
    e.duration = {"minutes": 30}
    e.location = anonymous_phone_number
    c.events.append(e)
    
    with open('dimpull.ics', 'w+') as my_file:
        my_file.writelines(c)

    messageForHost = "Calendar invite attached.  Message from caller: '" + form['message'] + "' --- They will show up in your Caller ID as calling from: " + anonymous_phone_number + "."
    messageForCaller = "Calendar invite attached.  This is the message you sent to " + host.first_name + " " + host.last_name + ": '" + form['message'] + "' --- The number to call " + host.first_name + " at is: " + anonymous_phone_number + "."

    hostResp = requests.post(
        "https://api.mailgun.net/v3/dimpull.com/messages",
        auth=("api", MAILGUN_API_KEY),
        data={"from": "Jon jon@dimpull.com",
              "to": [host.email],
              "subject": "Someone Scheduled a Dimpull Call With You",
              "text": messageForHost},
        files=[("attachment", open('my.ics'))])
    callerResp = requests.post(
        "https://api.mailgun.net/v3/dimpull.com/messages",
        auth=("api", MAILGUN_API_KEY),
        data={"from": "Jon jon@dimpull.com",
              "to": [guest_email],
              "subject": "You scheduled a call",
              "text": messageForCaller},
        files=[("attachment", open('my.ics'))])
    jonResp = requests.post(
        "https://api.mailgun.net/v3/dimpull.com/messages",
        auth=("api", MAILGUN_API_KEY),
        data={"from": "Jon jon@dimpull.com",
              "to": ["jonsandersss@gmail.com"],
              "subject": "You scheduled a call",
              "text": messageForCaller},
        files=[("attachment", open('my.ics'))])
    obj = {'anonymous_phone_number': anonymous_phone_number, 'whitelisted': True, 'hostFirstName': host.first_name}
    obj = json.dumps(obj)
    return obj

@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
@app.route('/api/savetimeslots', methods=["POST"])
def savetimeslots():
    form=request.get_json()
    if request.method == 'POST':
        host = User.query.filter(User.user_id == form['user_id']).one()
        times = form['times']
        # Remove old timeslots in case the user deleted any.
        db.session.query(TimeSlot).filter_by(host = host).delete() 
        for i in times:
            timeslot = TimeSlot(
                start_time = i['start'],
                end_time = i['end'],
                host = host,
            )
            db.session.add(timeslot)
            db.session.commit()
        return 'success'
    return 'error'

@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
@cross_origin(headers=["Content-Type", "Authorization"])
@app.route('/submitreview', methods=["POST"])
def submitreview():
    try:
        user_id = get_user_id(request.headers.get("Authorization", None))
        guest = User.query.filter(User.user_id == user_id).one()
    except (AttributeError, exc.SQLAlchemyError):
        guest = User.query.filter(User.user_id == 'Anonymous').one()
        user_id = None
    form=request.get_json()
    if request.method == 'POST':
        stars = form['stars']
        comment = form['comment']
        if form['initials']:
            initials = form['initials']
        else:
            initials = "{}{}".format(guest.first_name[0], guest.last_name[0])
        dp = url_to_dp(form['url'])
        review = Review(
            stars = stars,
            comment = comment,
            host = dp.host,
            guest_id = user_id,
            guest_initials = initials
        )
        if form['cid']:
            conversation = Conversation.query.get(int(form['cid']))
        else:
            conversation = need_review(dp.host, user_id)
        conversation.reviewed = True
        db.session.add(review)
        db.session.commit()
        return 'success'
    return 'error'

@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
@app.route('/checkvip/<vip>', methods=["POST"])
def check_vip_id(vip):
    form=request.get_json()
    dp = url_to_dp(form['url'])
    if dp.vipid == vip:
        return 'confirmed'
    return 'no'

@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
@app.route('/checkreviewid/<rid>', methods=["POST"])
def check_review_id(rid):
    form=request.get_json()
    dp = url_to_dp(form['url'])
    conversations = dp.conversations
    for i in conversations:
        if i.review_id == rid and i.reviewed is False:
            obj = {'confirmed': 'confirmed', 'cid': i.id}
            returnvals = json.dumps(obj)
            return returnvals
    return 'no'

def need_review(host, user_id):
    # TODO: use joins instead of "has" https://stackoverflow.com/questions/8561470/sqlalchemy-filtering-by-relationship-attribute
    conversation = Conversation \
        .query \
        .filter(Conversation.status == 'confirmed', Conversation.discussion_profile.has(host = host), Conversation.guest.has(user_id = user_id), Conversation.reviewed == False, Conversation.start_time < datetime.datetime.utcnow()) \
        .all()
    return conversation

@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
@cross_origin(headers=["Content-Type", "Authorization"])
@app.route('/api/getmytimeslots', methods=["GET"])
def getmytimeslots():
    try:
        user_id = get_user_id(request.headers.get("Authorization", None))
    except AttributeError:
        user_id = "nope"
        return "not authenticated"
    host = User.query.filter(User.user_id == user_id).one()
    obj = []
    for i in host.timeslots:
        if datetime.datetime.now() < i.end_time:
            obj.append({'start': i.start_time.isoformat(), 'end': i.end_time.isoformat()})

    times=json.dumps(obj)
    return times

@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
@app.route('/addemail', methods=["POST"])
def addemail():
    form=request.get_json()
    payload ={'api_key': OCTOPUS_KEY, 'email_address': form['email'], 'subscribed': True}
    r = requests.post("https://emailoctopus.com/api/1.3/lists/6543ad73-3cfa-11e8-a3c9-06b79b628af2/contacts", 
       data={'api_key': OCTOPUS_KEY, 'email_address': form['email'], 'subscribed': True})
    return "submitted"

@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
@app.route('/availability/<dp>', methods=["GET"])
def gettimeslots(dp):
    discussion_profile = DiscussionProfile.query.get(int(dp))
    host = discussion_profile.host
    obj = []
    for i in host.timeslots:
        if datetime.datetime.now() < i.end_time:
            if not i.pending or (datetime.datetime.utcnow() - i.pending_time).total_seconds() / 60 > 16:
                obj.append({'start': i.start_time.isoformat(), 'end': i.end_time.isoformat()})
    times=json.dumps(obj)
    return times

@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
@app.route('/walletandprice/<dp>', methods=["GET"])
def getwallet(dp):
    discussion_profile = DiscussionProfile.query.get(int(dp))
    obj = {'walletAddress': discussion_profile.walletAddress, 'price': round(discussion_profile.price * 1.18,2)}
    walletandprice = json.dumps(obj)
    return walletandprice

# @app.route('/discussions/test_new', methods=["GET", "POST"])
# def test_new_discussion():
#     form = DiscussionProfileForm()
#     if request.method == 'POST':
#         if form.validate_on_submit():
#             host = User.query.get(current_user.get_id())
#             # anonymous_phone_number = DiscussionProfile.buy_number() #missing required self.
#             discussion = DiscussionProfile(form.description.data, form.image_url.data, host) #need to push an anon phone # here.
#             discussion.anonymous_phone_number = discussion.test_buy_number()
#             db.session.add(discussion)
#             db.session.commit()
#             return redirect_to('discussions')
#     return view('discussion_new', form)

@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
@cross_origin(headers=["Content-Type", "Authorization"])
@app.route('/getprofile', methods=["GET"])
def getprofile():
    try:
        user_id = get_user_id(request.headers.get("Authorization", None))
    except AttributeError:
        user_id = "nope"
        return "not authenticated"
    try: 
        user = User.query.filter(User.user_id == user_id).one()
    except:
        return "not authenticated"
    if user:
        return json.dumps({'user_id': user.user_id, 'phone_number': user.phone_number, 'expert': user.expert})
    return

@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
@cross_origin(headers=["Content-Type", "Authorization"])
@app.route('/addReferent/<code>', methods=["GET"])
def add_ref(code):
    # This code is a bit weird because addReferent is called before the user is registered (so it just checks if code is valid)
    # And again when the user is registered, so it applys the code/adds the referent row
    try:
        user_id = get_user_id(request.headers.get("Authorization", None))
    except AttributeError:
        user_id = "nope"
        return "not authenticated"
    try: 
        user = User.query.filter(User.user_id == user_id).one()
        try:
            referral = Referral.query.filter(Referral.code == code).one()
            referent = Referent(referent=user, referral=referral)
            db.session.add(referent)
            db.session.commit()
            return "applied"
        except:
            return "not accepted"
    except:
        try:
            referral = Referral.query.filter(Referral.code == code).one()
        except:
            return "referral code doesn't exist"
        return "referral code accepted"
    return "not accepted"


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
                return "no number for some reason"
                # conversation.discussion_profile.buy_number(user.area_code)
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
    response = VoiceResponse()
    try: 
        outgoing_number = _gather_outgoing_phone_number(form.From.data, form.To.data)
    except ValueError as e:
        response.say(str(e))
        return twiml(response)
    if outgoing_number:
        dial = Dial(caller_id = form.To.data) # the number the person calls is the same as the reciever sees.
        dial.number(outgoing_number, status_callback='http://62c61501.ngrok.io/status_callback')
        response.append(dial)
    return twiml(response)

@app.route('/status_callback', methods=["POST"])
def status_callback():
    r = request.values
    call_from = r.get('From') 
    twilio_time = r.get('Timestamp')
    timestamp = parsedate_to_datetime(twilio_time)
    dp = DiscussionProfile.query.filter(DiscussionProfile.anonymous_phone_number == call_from).one()
    conversations = dp.conversations
    conversation = None
    for i in conversations:
        if (timestamp - i.start_time.replace(tzinfo = pytz.UTC)).total_seconds()/60 > -3 and (timestamp - i.start_time.replace(tzinfo = pytz.UTC)).total_seconds()/60 < 30:
            conversation = i
            try: 
                t = conversation.caller_sid
                conversation.call_timestamp = timestamp
                conversation.caller_sid = conversation.caller_sid + " " + r.get('CallSid')
                conversation.call_duration = conversation.call_duration + " " + r.get('CallDuration')
                conversation.call_status = conversation.call_status + " " + r.get('CallStatus')
                conversation.parent_call_sid = conversation.parent_call_sid + " " + r.get('ParentCallSid')
            except (AttributeError, TypeError):
                conversation.call_timestamp = timestamp
                conversation.caller_sid = r.get('CallSid')
                conversation.call_duration = r.get('CallDuration')
                conversation.call_status = r.get('CallStatus')
                conversation.parent_call_sid = r.get('ParentCallSid')
            db.session.commit()
            url = dp.url + "/review=" + conversation.review_id
            if int(r.get('CallDuration')) > 600:
                # TODO: call end function.
                # transaction = {
                #     'to': '0x8850259566e9d03a1524e35687db2c78d4003409',
                #     'gas': 2000000,
                #     'gasPrice': 234567897654321,
                #     'nonce': 0,
                #     'chainId': 1
                # }
                abi = [{"constant":false,"inputs":[{"name":"payer","type":"address"},{"name":"payee","type":"address"}],"name":"refund","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"price","type":"uint256"}],"name":"setFee","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"owner","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"payer","type":"address"},{"name":"payee","type":"address"}],"name":"end","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"","type":"address"},{"name":"","type":"address"}],"name":"balances","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"payee","type":"address"}],"name":"start","outputs":[],"payable":true,"stateMutability":"payable","type":"function"},{"constant":true,"inputs":[],"name":"fee","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"inputs":[],"payable":false,"stateMutability":"nonpayable","type":"constructor"}]
                escrow = w3.eth.contract(address='0x8850259566e9d03a1524e35687db2c78d4003409', abi=abi)
                nonce = w3.eth.getTransactionCount('0x532DE4B689dD9DBDC9C9D2d51450487b09224CE8')
                escrow_end = escrow.end.sendTransaction(
                        '0x8850259566e9d03a1524e35687db2c78d4003409',
                        1,
                ).buildTransaction({
                    'chainId': 1,
                    'gas': 70000,
                    'gasPrice': w3.toWei('1', 'gwei'),
                    'nonce': nonce,
                })

                print(escrow_end)
                private_key = '750d3e619c9c54a6e48d99b2bac5010b2c606509ceec7a470ac7158ef6dab384'

                signed_txn = w3.eth.account.signTransaction(escrow_end, private_key=private_key)
                signed_txn.hash
                signed_txn.rawTransaction
                signed_txn.r
                signed_txn.s
                signed_txn.v
                w3.eth.sendRawTransaction(signed_txn.rawTransaction)  
                w3.toHex(w3.sha3(signed_txn.rawTransaction))

            text = "Hello.  We hope your call with " + dp.host.first_name + " was valuable.  Please leave a review at: www.dimpull.com/" + url + "."
            resp = requests.post(
                "https://api.mailgun.net/v3/dimpull.com/messages",
                auth=("api", MAILGUN_API_KEY),
                data={"from": "Dimpull jon@dimpull.com",
                      "to": [conversation.guest_email],
                      "subject": "How was your call?",
                      "text": text})
            return 'success'
    return 'fail'

def _gather_outgoing_phone_number(incoming_phone_number, anonymous_phone_number):
    # conversation = Conversation.query \
    #     .filter(DiscussionProfile.anonymous_phone_number == anonymous_phone_number) \
    #     .first()
    dp = DiscussionProfile.query.filter(DiscussionProfile.anonymous_phone_number == anonymous_phone_number).one()
    conversations = dp.conversations
    conversation = None
    for i in conversations:
        if i.guest_phone_number == incoming_phone_number:
            conversation = i

    # print("guest number: ", conversation.guest_phone_number, anonymous_phone_number)
    # if conversation.guest_phone_number == incoming_phone_number:
    #     return conversation.discussion_profile.host.phone_number
    # pdb.set_trace()
    difference = (datetime.datetime.utcnow() - conversation.start_time).total_seconds() / 60
    # print(datetime.datetime.now(), conversation.start_time, conversation.discussion_profile, conversation.message)
    if difference > 30:
        raise ValueError("Sorry, you needed to call within the 30 minute timeslot you booked.  It has been {} minutes since the start of your timeslot.".format(str(round(difference,1))))
    else:
        if difference < -3:
            raise ValueError("The timeslot you booked doesn't start for {} minutes".format(str(round(difference,1))))
        elif conversation.guest_phone_number == incoming_phone_number:
            return conversation.discussion_profile.host.phone_number
        else:
            return "fail"

def _respond_message(message):
    response = MessagingResponse()

    response.message(message)
    # response = twilio.twiml.Response()
    # response.message(message)
    return response