from airtng_flask import db, bcrypt, app, login_manager
from flask import session, g, request, flash, Blueprint
from flask.ext.login import login_user, logout_user, current_user, login_required
import twilio.twiml
from twilio.twiml.messaging_response import Message, MessagingResponse
from twilio.twiml.voice_response import Dial, Number, VoiceResponse

from airtng_flask.forms import RegisterForm, LoginForm, VacationPropertyForm, ReservationForm, \
    ReservationConfirmationForm, ExchangeForm
from airtng_flask.view_helpers import twiml, view, redirect_to, view_with_params
from airtng_flask.models import init_models_module

init_models_module(db, bcrypt, app)

from airtng_flask.models.user import User
from airtng_flask.models.vacation_property import VacationProperty
from airtng_flask.models.reservation import Reservation
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import Forbidden
import pdb

@app.route('/', methods=["GET", "POST"])
@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if request.method == 'POST':
        if form.validate_on_submit():

            if User.query.filter(User.email == form.email.data).count() > 0:
                form.email.errors.append("Email address already in use.")
                return view('register', form)

            user = User(
                    name=form.name.data,
                    email=form.email.data,
                    # password=form.password.data,
                    password=generate_password_hash(form.password.data),
                    phone_number="+{0}{1}".format(form.country_code.data, form.phone_number.data),
                    area_code=str(form.phone_number.data)[0:3])

            db.session.add(user)
            db.session.commit()
            login_user(user, remember=True)

            return redirect_to('home')
        else:
            return view('register', form)

    return view('register', form)


@app.route('/login', methods=["GET", "POST"])
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


@app.route('/home', methods=["GET"])
@login_required
def home():
    return view('home')


@app.route('/properties', methods=["GET"])
@login_required
def properties():
    vacation_properties = VacationProperty.query.all()
    return view_with_params('properties', vacation_properties=vacation_properties)


@app.route('/properties/new', methods=["GET", "POST"])
@login_required
def new_property():
    form = VacationPropertyForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            host = User.query.get(current_user.get_id())
            pdb.set_trace()
            # anonymous_phone_number = VacationProperty.buy_number() #missing required self.
            property = VacationProperty(form.description.data, form.image_url.data, host) #need to push an anon phone # here.
            property.anonymous_phone_number = property.buy_number().phone_number
            db.session.add(property)
            db.session.commit()
            return redirect_to('properties')

    return view('property_new', form)


@app.route('/reservations/', methods=["POST"], defaults={'property_id': None})
@app.route('/reservations/<property_id>', methods=["GET", "POST"])
@login_required
def new_reservation(property_id):
    vacation_property = None
    form = ReservationForm()
    form.property_id.data = property_id

    if request.method == 'POST':
        if form.validate_on_submit():
            guest = User.query.get(current_user.get_id())

            vacation_property = VacationProperty.query.get(form.property_id.data)
            reservation = Reservation(form.message.data, vacation_property, guest)
            db.session.add(reservation)
            db.session.commit()

            reservation.notify_host()

            return redirect_to('properties')

    if property_id is not None:
        vacation_property = VacationProperty.query.get(property_id)

    return view_with_params('reservation', vacation_property=vacation_property, form=form)


@app.route('/reservations', methods=["GET"])
@login_required
def reservations():
    user = User.query.get(current_user.get_id())
    reservations_as_host = Reservation.query \
        .filter(VacationProperty.host_id == current_user.get_id() and len(VacationProperty.reservations) > 0) \
        .join(VacationProperty) \
        .filter(Reservation.vacation_property_id == VacationProperty.id) \
        .all()

    reservations_as_guest = user.reservations

    return view_with_params('reservations',
                            reservations_as_guest=reservations_as_guest,
                            reservations_as_host=reservations_as_host)


@app.route('/reservations/confirm', methods=["POST"])
def confirm_reservation():
    form = ReservationConfirmationForm()
    sms_response_text = "Sorry, it looks like you don't have any reservations to respond to."
    user = User.query.filter(User.phone_number == form.From.data).first()
    reservation = Reservation \
        .query \
        .filter(Reservation.status == 'pending'
                and Reservation.vacation_property.host.id == user.id) \
        .first()
    print("mayube it is none")
    if reservation is not None:
        if 'yes' in form.Body.data or 'accept' in form.Body.data or 'Accept' in form.Body.data:
            reservation.confirm()
            if reservation.vacation_property.anonymous_phone_number is not None:
                print("about to buy.  I bet this is the issue")
                reservation.vacation_property.buy_number(user.area_code)
                print('nevermind')
        else:
            reservation.reject()
        db.session.commit()
        sms_response_text = "You have successfully {0} the reservation".format(reservation.status)
        reservation.notify_guest()
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
    vacay = Reservation.query \
        .filter(Reservation.vacation_property.anonymous_phone_number == anonymous_phone_number) \
        .first()
    print(vacay) # None
    if reservation.guest.phone_number == incoming_phone_number:
        return reservation.vacation_property.host.phone_number

    return reservation.guest.phone_number


def _respond_message(message):
    response = MessagingResponse()

    response.message(message)
    # response = twilio.twiml.Response()
    # response.message(message)
    return response
