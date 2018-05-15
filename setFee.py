# from solc import install_solc
# install_solc('v0.4.19')
from web3 import Web3, HTTPProvider
import json, pdb
from solc import compile_standard
from solc.wrapper import get_solc_binary_path
import os
from web3.middleware import geth_poa_middleware
# import escrow.sol

provider = HTTPProvider('https://rinkeby.infura.io/I5csQZeeCq5xFJFx11J4 ')
w3 = Web3(provider)
w3.middleware_stack.inject(geth_poa_middleware, layer=0)

assert w3.isConnected()
from solc.wrapper import get_solc_binary_path
get_solc_binary_path()

# pdb.set_trace()
# os.environ['SOLC_BINARY']
# pdb.set_trace()
# contract_source_code = json.dumps(contract_source_code)

# os.environ['SOLC_BINARY']


os.environ['SOLC_BINARY'] = "/home/jonathan/.py-solc/solc-v0.4.17/bin/solc"
with open('escrow.sol', 'r') as f:
	contract_source_code = f.read()
	compiled_sol = compile_standard({
		'language': "Solidity", 
		'sources': {'escrow.sol': {'content': contract_source_code}}, 
		'outputSelection': {'*': {'*': ['metadata', 'evm.bytecode', 'abi', 'evm.opcodes']}}}
	)

escrow = w3.eth.contract(address='0xCc6671AB27d7D13fAA27106bE8348642b0f84398', abi=compiled_sol.get('contracts')['escrow.sol']['Escrow']['abi'])
nonce = w3.eth.getTransactionCount('0x532DE4B689dD9DBDC9C9D2d51450487b09224CE8')

pdb.set_trace()

# escrow_end = escrow.functions.end(
# 		'0x532DE4B689dD9DBDC9C9D2d51450487b09224CE8',
# 		'0x67e91efB35803381801A0DE70734a62F487803ea'
# 	).buildTransaction({
# 		'from': '0x532DE4B689dD9DBDC9C9D2d51450487b09224CE8',
# 		'chainId': 3,
# 		'gas': 970000,
# 		'gasPrice': w3.toWei('1', 'gwei'),
# 		'nonce': nonce,
# 	})

escrow_end = escrow.functions.setFee(
		18000
	).buildTransaction({
		'from': '0x532DE4B689dD9DBDC9C9D2d51450487b09224CE8',
		'chainId': 4,
		'gas': 70000,
		'gasPrice': w3.toWei('1', 'gwei'),
		'nonce': nonce,
	})

# escrow_end = escrow.functions.balances(
# 		'0x532DE4B689dD9DBDC9C9D2d51450487b09224CE8',
# 		'0x07de4977770Df1f77d7D73141063c7085Bed716a'
# 	).call({'from': '0x532DE4B689dD9DBDC9C9D2d51450487b09224CE8'})

# escrow_end = escrow.functions.balances(
# 		'0x532DE4B689dD9DBDC9C9D2d51450487b09224CE8',
# 		'0x07de4977770Df1f77d7D73141063c7085Bed716a'
# 	).call({'from': '0x532DE4B689dD9DBDC9C9D2d51450487b09224CE8'})

pdb.set_trace();
# print(escrow_end)
private_key = '750d3e619c9c54a6e48d99b2bac5010b2c606509ceec7a470ac7158ef6dab384'

w3.eth.enable_unaudited_features()
signed_txn = w3.eth.account.signTransaction(escrow_end, private_key=private_key)
signed_txn.hash
signed_txn.rawTransaction
signed_txn.r
signed_txn.s
signed_txn.v
w3.eth.sendRawTransaction(signed_txn.rawTransaction)    
w3.toHex(w3.sha3(signed_txn.rawTransaction))
