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
from cmm_flask.models.reviews import Review
from cmm_flask.models.admins import AdminUser
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import Forbidden
import pdb
import datetime
from flask_admin import Admin, expose
from flask_admin.contrib.sqla import ModelView
from flask.ext.login import login_user, logout_user, login_required
from flask.ext.login import current_user
from sqlalchemy.exc import IntegrityError
from sqlalchemy import exists
from flask_admin.contrib import sqla
import yagmail
import dateutil.parser

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)
GMAIL = env.get("GMAIL")
AUTH0_DOMAIN = env.get("AUTH0_DOMAIN")
AUTH0_AUDIENCE = env.get("AUTH0_AUDIENCE")
ALGORITHMS = ["RS256"]

class MyView(sqla.ModelView):

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
    # print("LOGOUT")
    logout_user()
    return redirect(url_for("login_get"))


admin=Admin(app, name="Dimpull Dashboard")
admin.add_view(MyView(User, db.session))
admin.add_view(MyView(DiscussionProfile, db.session))
admin.add_view(MyView(Conversation, db.session))
admin.add_view(MyView(TimeSlot, db.session))
admin.add_view(MyView(Review, db.session))


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
def register():
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
            )
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

@app.route('/expertrequest', methods=["GET, POST"])
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
def expert_request():
    form = request.get_json()
    return 


@app.route('/api/discussions', methods=["GET"])
def discussions():
    discussion_profiles = DiscussionProfile.query.all()
    obj = []
    for ds in discussion_profiles:
        if ds.public:
            obj.append({'id': ds.id, 'url': ds.url, 'first_name': ds.host.first_name, 'last_name': ds.host.last_name, 
                'auth_pic': ds.host.auth_pic, 'image': ds.image_url, 'description': ds.description,
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
            obj.append({'id':ds.id, 'url': ds.url, 'first_name': ds.host.first_name, 'last_name': ds.host.last_name, 
                'auth_pic': ds.host.auth_pic, 'image':ds.image_url, 'description': ds.description,
                })
        objs=json.dumps(obj)
        return objs
    else:
        return "user has no discussion profiles"
    return "error"

@app.route('/expert', methods=["GET"])
@app.route('/expert/<url>', methods=["GET"])
@cross_origin(headers=["Content-Type", "Authorization"])
def discussion_profile(url): 
    try:
        user_id = get_user_id(request.headers.get("Authorization", None))
    except AttributeError:
        user_id = "nope"
    discussion_profile = None

    if url is not None:
        # dp = DiscussionProfile.query.get(int(discussion_id))
        dp = db.session.query(DiscussionProfile).filter_by(url = url).one()
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
        who, excites, helps, origin = '', '', '', ''
        if dp.who:
            who = dp.who
        if dp.excites:
            excites = dp.excites
        if dp.origin:
            origin = dp.origin
        if dp.helps:
            helps = dp.helps
        profile={'host': dp.host.user_id, 'image': dp.image_url, 'description': dp.description,
            'anonymous_phone_number': dp.anonymous_phone_number, 'auth_pic': dp.host.auth_pic, 'first_name':dp.host.first_name, 
            'last_name':dp.host.last_name, 'is_users': is_users, 'price': dp.price*1.185, 'otherProfile': dp.otherProfile, 'who': who,
            'origin': dp.origin, 'excites': dp.excites, 'helps': dp.helps, 'url': dp.url, 'id': dp.id
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
                averageRating = round(rating/len(ratings),2)
                profile["averageRating"] = averageRating
            profile["reviewlist"] = reviews
        if len(need_review(dp.host, user_id)) > 0:
            profile["needReview"] = True
        profile = json.dumps(profile)
        return profile
    return "error"


def need_review(host, user_id):
    # TODO: use joins instead of "has" https://stackoverflow.com/questions/8561470/sqlalchemy-filtering-by-relationship-attribute
    conversation = Conversation \
        .query \
        .filter(Conversation.status == 'confirmed', Conversation.discussion_profile.has(host = host), Conversation.guest.has(user_id = user_id), Conversation.reviewed == False) \
        .all()
    return conversation

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
        discussion = DiscussionProfile(
            # description = form['description'], 
            # image_url = form['image_url'], 
            host = host,
            otherProfile = form['otherProfile'],
            # email = form['email'],
            # price = float(form['price']),
            # timezone = form['timezone'],
            # who = form['who']
        ) #need to push an anon phone # here.
        # discussion.anonymous_phone_number = discussion.buy_number().phone_number
        host.requestExpert = True
        host.email = form["email"]
        host.messageforAdmins = form['message']
        db.session.add(discussion)
        db.session.commit()

        # adminUrl = 'http://localhost:5000/admin/user/edit/?id={}&url=%2Fadmin%2Fuser%2F'.format(host.id)
        # yag = yagmail.SMTP('pwreset.winthemini@gmail.com', GMAIL)
        # contents = [adminUrl]
        # yag.send(to = 'jonsandersss@gmail.com', subject='New Expert Request', contents=contents)
        # content = 'Subject: New Expert Request!\n{} with message {}'.format(adminUrl, form['message'])
        # smtp_server = smtplib.SMTP('smtp.gmail.com', 587)
        # smtp_server.ehlo()
        # smtp_server.starttls()
        # smtp_server.login('pwreset.winthemini@gmail.com', GMAIL)
        # smtp_server.sendmail('pwreset.winthemini@gmail.com', 'jonsandersss@gmail.com', content)
        # smtp_server.quit()

        return "success"
    return "error"

@app.route('/url', methods=["GET"])
@app.route('/urlcheck/<url>', methods=["GET"])
@cross_origin(headers=["Content-Type", "Authorization"])
@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
def url_check(url):
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
def deleted_discussion(): 
    try:
        user_id = get_user_id(request.headers.get("Authorization", None))
    except AttributeError:
        user_id = "nope"
    discussion_id = request.query_string[3:] # ex) 'id=423'
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
def edit_discussion(url):
    # pdb.set_trace()
    # discussion_id = dpid
    # dp = DiscussionProfile.query.get(int(discussion_id))
    dp = db.session.query(DiscussionProfile).filter_by(url = url).one()
    # dp = db.session.query(DiscussionProfile).filter_by(url = url).one()
    if request.method == 'POST':
        form=request.get_json()
        if dp.host.user_id == form['user_id']:
            dp.description = form['description'], 
            dp.image_url = form['image_url'], 
            dp.otherProfile = form['otherProfile'],
            dp.price = float(form['price']),
            dp.timezone = form['timezone'],
            dp.who = form['who'],
            dp.excites = form['excites'],
            dp.origin = form['origin'],
            dp.helps = form['helps'],
            dp.url = form['url'],
            dp.walletAddress = form['walletAddress']
            db.session.commit()
            return 'success'
        else: 
            return "wrong user"

    if request.method == 'GET':
        try:
            user_id = get_user_id(request.headers.get("Authorization", None))
        except AttributeError:
            user_id = "nope"
        if dp.host.user_id != user_id:
            return "Not this user's"

        who, excites, helps, origin, url, walletAddress = '', '', '', '', '', ''
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
        return jsonify({'description': dp.description, 'image_url': dp.image_url, 'price': dp.price, 'otherProfile': dp.otherProfile, 'timezone': dp.timezone,
            'who': who, 'excites': excites, 'origin': origin, "helps": helps, 'url': url, 'walletAddress': walletAddress})
    return "error"

@cross_origin(headers=["Access-Control-Allow-Origin", "*"])
@cross_origin(headers=["Content-Type", "Authorization"])
# @app.route('/conversations', methods=["GET", "POST"])
# @app.route('/conversations/', methods=["POST"])
@app.route('/conversations/<dpid>', methods=["GET", "POST"])
def new_conversation(dpid):
    try:
        user_id = get_user_id(request.headers.get("Authorization", None))
        guest = User.query.filter(User.user_id == user_id).one()
    except AttributeError:
        guest = User.query.filter(User.user_id == 'Anonymous').one()
        user_id = None
    # discussion_id = request.query_string[3:] # ex) 'id=423'
    discussion_profile = None
    form=request.get_json()
    #this is where I'll need truffle/Meta Mask.  May also need to send a verification text.
    if 'phone_number' in form:
        guest_phone_number = form['phone_number'].replace('-', '')
        guest_email = form['email']
    
    if user_id is not None:
        if guest.phone_number != guest_phone_number:
            guest.phone_number = guest_phone_number

    time = form['start_time']
    discussion_profile = DiscussionProfile.query.get(int(dpid))
    conversation = Conversation(form['message'], discussion_profile, guest_phone_number=guest_phone_number, start_time=time, guest=guest, guest_email=guest_email)
    host = discussion_profile.host
    newdate = dateutil.parser.parse(time)
    naive = newdate.replace(tzinfo=None)
    for i in host.timeslots:
        if i.start_time == naive:
            db.session.delete(i)

    db.session.add(conversation)
    db.session.commit()
    conversation.notify_host()
    return 'whitelisted'



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
    except AttributeError:
        guest = User.query.filter(User.user_id == 'anonymous').one()
        user_id = None
    form=request.get_json()
    if request.method == 'POST':
        stars = form['stars']
        comment = form['comment']
        dp = DiscussionProfile.query.get(int(form['discussion_id']))
        review = Review(
            stars = stars,
            comment = comment,
            host = dp.host,
            guest_id = user_id,
            guest_initials = "{}{}".format(guest.first_name[0], guest.last_name[0])
        )
        conversation = need_review(dp.host, user_id)
        for i in conversation:
            i.reviewed = True
        db.session.add(review)
        db.session.commit()
        return 'success'
    return 'error'


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
@app.route('/availability/<dp>', methods=["GET"])
def gettimeslots(dp):
    discussion_profile = DiscussionProfile.query.get(int(dp))
    host = discussion_profile.host
    obj = []
    for i in host.timeslots:
        if datetime.datetime.now() < i.end_time:
            obj.append({'start': i.start_time.isoformat(), 'end': i.end_time.isoformat()})
    times=json.dumps(obj)
    return times

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
        dial.number(outgoing_number)
        response.append(dial)

    return twiml(response)


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