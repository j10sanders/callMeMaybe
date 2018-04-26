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
#     app.run(debug="True")
# import cryptocompare
# coin_data = cryptocompare.get_price('ETH',curr='USD')
# print(coin_data['ETH']['USD'])
# from solc import install_solc
# install_solc('v0.4.19')
from web3 import Web3, HTTPProvider
import json, pdb
from solc import compile_standard
import os
# import escrow.sol


contract_source_code = '''
pragma solidity ^0.4.13;

contract Escrow {
  address public owner;
  uint public fee;

  //Balances temporarily made public for testing; to be removed
  mapping (address =>  mapping (address => uint)) public balances;

  function Escrow() public {
    owner = msg.sender;
  }

  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  //Fee should be set in PPM
  function setFee(uint price) onlyOwner external {
    fee = price;
  }

  function start(address payee) payable external {
    balances[msg.sender][payee] = balances[msg.sender][payee] + msg.value;
  }

  function end(address payer, address payee) onlyOwner external returns(bool){
    uint value = balances[payer][payee];
    uint paidFee = value / (1000000 / fee);
    uint payment = value - paidFee;
    balances[payer][payee] = 0;
    payee.transfer(payment);
    owner.transfer(paidFee);
    return true;
  }
  
  function refund(address payer, address payee) onlyOwner external returns(bool){
    uint value = balances[payer][payee];
    balances[payer][payee] = 0;
    payer.transfer(value);
    return true;
  }
}
'''
provider = HTTPProvider('https://ropsten.infura.io/SzMj9kYHCc61XSf9IFDh')
w3 = Web3(provider)

assert w3.isConnected()
from solc.wrapper import get_solc_binary_path
# pdb.set_trace()
get_solc_binary_path()

# pdb.set_trace()
# os.environ['SOLC_BINARY']
# pdb.set_trace()
# contract_source_code = json.dumps(contract_source_code)

with open('escrow.sol', 'r') as f:
	contract_source_code = f.read()
	compiled_sol = compile_standard({
		'language': 'Solidity',
		'sources': {'escrow.sol': contract_source_code}},
		solc_binary="/home/jonathan/.py-solc/solc-v0.4.19/bin/solc")
# #     # d = json_data
# #     # print(d)
# 	json.load(f)
#     pdb.set_trace()
#     contract_source_code = f.read()
#     abi = compile_source(contract_source_code)
# os.environ['SOLC_BINARY'] = get_solc_binary_path()
#contract_source_code = json.dumps(contract_source_code)
# contract_source_code = json.loads(contract_source_code)

pdb.set_trace()

escrow = w3.eth.contract(address='0x8850259566e9d03a1524e35687db2c78d4003409', abi=abi)
nonce = w3.eth.getTransactionCount('0x532DE4B689dD9DBDC9C9D2d51450487b09224CE8')

pdb.set_trace()

escrow_end = escrow.functions.end("0x07de4977770Df1f77d7D73141063c7085Bed716a", "0x532DE4B689dD9DBDC9C9D2d51450487b09224CE8")
pdb.set_trace()


escrow_end.sendTransaction(
        '0x8850259566e9d03a1524e35687db2c78d4003409',
        1,
).buildTransaction({
    'chainId': 1,
    'gas': 70000,
    'gasPrice': w3.toWei('1', 'gwei'),
    'nonce': nonce,
})
pdb.set_trace();
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
pdb.set_trace