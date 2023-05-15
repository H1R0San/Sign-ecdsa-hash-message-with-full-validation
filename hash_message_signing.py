from bitcoinlib.keys import Key
from bitcoinlib.transactions import P2PKHInput, P2PKHOutput, P2PKHTransaction
from bitcoinlib.script import OP_CHECKSIG
from bitcoinlib.wallets import Wallet
import hashlib

# Hash message
z = '2e1d1cc2a4ca52c6f6178570da8375365bc06416b898eb9436f328a4eb72d22d'

# Generate public key from genesis block pubkey
GENESIS_BLOCK_PUBKEY = '04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f'
pubkey = Key(GENESIS_BLOCK_PUBKEY).public_hex()

# Create transaction input
input_script = P2PKHInput.unlocking_script(pubkey)
input_sequence = 0xffffffff
input_txid = '0000000000000000000000000000000000000000000000000000000000000000'
input_index = 0
input_amount = 0
input_obj = P2PKHInput(input_script, input_sequence, input_txid, input_index, input_amount)

# Create transaction output
output_script = P2PKHOutput.locking_script(pubkey)
output_amount = 0
output_obj = P2PKHOutput(output_script, output_amount)

# Create transaction
transaction_obj = P2PKHTransaction([input_obj], [output_obj])

# Sign the hash message with the provided public key
signature = transaction_obj.sign_input(0, pubkey, hash_type='SIGHASH_ALL')

# Add the signature to the input script
input_script.script = [signature, pubkey, OP_CHECKSIG]

# Verify the signature
verify_hash = hashlib.sha256(hashlib.sha256(bytes.fromhex(z)).digest()).digest()
verification_result = transaction_obj.input[0].verify_input(verify_hash, 0)

# Print validation result
print("Validation Result:", verification_result)