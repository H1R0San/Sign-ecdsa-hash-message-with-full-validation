from bitcoinlib.keys import Key, S256Point
from bitcoinlib.transactions import Transaction
from bitcoinlib.services.services import Service
from bitcoinlib.encoding import hash160, double_sha256, to_bytes, to_hex_string
from bitcoinlib import flags
from ecdsa.util import string_to_number
import hashlib

# Set network and service provider
flags.TESTNET = True
service = Service('bitcoind')

# Define the public key
GENESIS_BLOCK_PUBKEY = '04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f'
pubkey = Key.from_text(GENESIS_BLOCK_PUBKEY)

# Define the Z message to be signed
z_msg = '2e1d1cc2a4ca52c6f6178570da8375365bc06416b898eb9436f328a4eb72d22d'
z_bytes = bytes.fromhex(z_msg)

# Generate the signature
sig = pubkey.sign(z_bytes)

# Verify the signature
assert pubkey.verify(z_bytes, sig)

# Print the signature and verification
print("Valid signature of the Z message:")
print("signature: ", sig.hex())
print("verification: ", pubkey.verify(z_bytes, sig))
