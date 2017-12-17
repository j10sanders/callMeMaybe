# from flask import Flask, request, redirect
# from twilio.twiml.voice_response import VoiceResponse, Gather, Dial, Number

# app = Flask(__name__)

# callers = {
#     "+19175387146": "Jon",
#     "+15854744914": "Alex",
# }

# @app.route("/", methods=['GET', 'POST'])
# def hello_monkey():
#     from_number = request.values.get('From', None)
#     if from_number in callers:
#         caller = callers[from_number]
#     else:
#         caller = "unknown caller"

#     resp = VoiceResponse()
#     # Greet the caller by name
#     resp.say("Hello " + caller)

#     # Say a command, and listen for the caller to press a key. When they press
#     # a key, redirect them to /handle-key.
#     g = Gather(numDigits=1, action="/handle-key", method="POST")
#     g.say("To connect, press 1. Press any other key to start over.")
#     resp.append(g)

#     return str(resp)

# @app.route("/handle-key", methods=['GET', 'POST'])
# def handle_key():
#     """Handle key press from a user."""

#     # Get the digit pressed by the user
#     digit_pressed = request.values.get('Digits', None)
#     if digit_pressed == "1":
#         resp = VoiceResponse()
#         resp.dial('+18004444444')
#         # resp.dial("+17072355112")
#         resp.say("The call failed, or the remote party hung up. Goodbye.")
#         print(resp)
#         return str(resp)

#     # If the caller pressed anything but 1, redirect them to the homepage.
#     else:
#         return redirect("/")

# # @app.route("/handleDialCallStatus", methods=['GET', 'POST'])
# # def handle_key(DialCallStatus):
# #     print(DialCallStatus)
# #     return DialCallStatus


# if __name__ == "__main__":
#     app.run(debug=True)

from werkzeug.security import check_password_hash, generate_password_hash

x = "Hello world"
y = "yes"

z = generate_password_hash(x)
print(z)
y = generate_password_hash(y)
print(y)

d = generate_password_hash("Hello world")
print(d)

for i in [z,y,d]:
	print(check_password_hash(i, "Hello world"))