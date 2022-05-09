"""
The rcrypt module implements various cryptographic functions that are required
by the Helium cryptocurrency application.
The Base58 package encodes strings into Base58 format.
This module requires the pycryptodome package to be installed.
This module uses Python's regular expression module re.
This module uses Python's secrets module to generate cryptographically secure
hexadecimal encoded strings.
"""

# Standard library modules.
import logging
import re
import secrets
from tabnanny import check

# 3rd-party modules.
import base58

# 3rd-party library objects.
from Crypto.Hash import RIPEMD160, SHA256, SHA3_256
from Crypto.PublicKey import DSA, ECC
from Crypto.Signature import DSS


# Log debugging messages to the file 'debug.log'.
logging_format = '%(asctime)s:%(levelname)s:%(message)s'
logging.basicConfig(filename='debug.log', filemode='w',
                    format=logging_format, level=logging.DEBUG)

def make_SHA256_hash(message: str) -> str:
  """Computes the SHA-256 message digest or cryptographic hash for a given
  string. The hexadecimal format of the message digest is 64 bytes long.

  Args:
      message (str): A text message to compute the secure hash value.

  Returns:
      string: A sequence of hexadecimal digits of the secure hash value.
  """

  # Convert the received msg string to a sequence of ASCII bytes.
  message = bytes(message, 'ascii')

  # Compute the SHA-256 message digest of msg and convert to a hexadecimal
  # format.
  hash_object = SHA256.new()
  hash_object.update(message)

  return hash_object.hexdigest()


def validate_SHA256_hash(digest: str) -> bool:
  """Tests whether a string has an encoding conforming to a SHA-256 message
  digest in hexadecimal string format (64 bytes).

  Args:
      digest (str): A SHA-256 message digest.

  Returns:
      bool: Validation result.
  """

  # A hexadecimal SHA-256 message digest must be 64 bytes long.
  if len(digest) != 64:
    return False

  # This regular expression tests that the received string contains only
  # hexadecimal characters.
  if not re.search('[^0-9a-fA-F]', digest):
    return True

  return False


def make_RIPEMD160_hash(message: str) -> str:
  """Computes the RIPEMD-160 message digest or cryptographic hash for a given
  string. The hexadecimal format of the message digest is 40 bytes long.
  RIPEMD-160 is a cryptographic algorythm that emits a 20 bytes message
  digest.

  Args:
      message (str): A text message to compute the secure hash value.

  Returns:
      string: A sequence of hexadecimal digits of the secure hash value.
  """

  # Convert message to an ASCII byte stream.
  bstr = bytes(message, 'ascii')

  # Generate the RIPEMD hash of the message.
  hash = RIPEMD160.new()
  hash.update(bstr)

  # Convert to a hexadecimal encoded string.
  hex_hash = hash.hexdigest()

  return hex_hash


def validate_RIPEMD160_hash(digest: str) -> bool:
  """Tests whether a string has an encoding conforming to a RIPEMD-160 message
  digest in hexadecimal string format (64 bytes).

  Args:
      digest (str): A RIPEMD-160 message digest.

  Returns:
      bool: Validation result.
  """

  # A hexadecimal RIPEMD-160 message digest must be 40 bytes long.
  if len(digest) != 40:
    return False

  # This regular expression tests that the received string contains only
  # hexadecimal characters.
  if not re.search('[^0-9a-fA-F]', digest):
    return True

  return False


def make_ecc_keys() -> tuple:
  """Makes a private-public key pair using elliptic curve cryptographic
  functions in the pycryptodome package.

  Returns:
      tuple(str): A private-public key pair in PEM format.
  """

  # Generate an ecc oject.
  ecc_key = ECC.generate(curve='P-256')

  # Get the public key object.
  pk_object = ecc_key.public_key()

  # Export the private-public key pair in PEM format.
  key_pair = (ecc_key.export_key(format='PEM'), pk_object.export_key(format='PEM'))

  return key_pair


def sign_message(private_key: str, message: str) -> str:
  """Digitally signs a message using a private key generated using the elliptic
  curve cryptography module of the pychryptodome package.

  Args:
      private_key (str): A private key in PEM format.
      message (str): A string message to be digitally signed.

  Returns:
      str: A hex encoded signature string.
  """

  # Import the PEM format private key.
  priv_key = ECC.import_key(private_key)

  # Convert the message to a byte stream and compute the SHA-256 message digest
  # of the message.
  bstr = bytes(message, 'ascii')
  hash = SHA256.new(bstr)

  # Create a digital signature object from the private key.
  signer = DSS.new(priv_key, 'fips-186-3')

  # Sign the SHA-256 message digest.
  signature = signer.sign(hash)
  hex_signature = signature.hex()

  return hex_signature


def verify_signature(public_key: str, message: str, signature: str) -> bool:
  """Tests whether a message is digitally signed by a private key to which a
  public key is paired.

  Args:
      public_key (str): An ECC public key in PEM format.
      message (str): A message to be verified.
      signature (str): A digital signature of the message.

  Returns:
      bool: Validation result.
  """

  try:
    # Convert the message to a byte stream and compute the SHA-256 hash.
    msg = bytes(message, 'ascii')
    msg_hash = SHA256.new(msg)

    # Convert the signature to a byte stream.
    signature = bytes.fromhex(signature)

    # Import the PEM formatted public key and create a signature verified
    # object from the public key.
    pub_key = ECC.import_key(public_key)
    verifier = DSS.new(pub_key, 'fips-186-3')

    # Verify the authenticity of the signed message.
    verifier.verify(msg_hash, signature)

    return True

  except Exception as err:
    logging.debug(f'verify_signature: exception {err}')

  return False


def make_address(prefix: str) -> str:
  """Generates a Helium address from an ECC public key in PEM format.

  Args:
      prefix (str): A single numeric character which describes the type of the
      address. This prefix must be '1'.

  Returns:
      str: A generated address.
  """

  key = ECC.generate(curve='P-256')
  __private_key = key.export_key(format='PEM')
  public_key = key.public_key().export_key(format='PEM')
  pub_key_hash = make_SHA256_hash(public_key)
  hash = make_RIPEMD160_hash(pub_key_hash)
  prefix_hash = prefix + hash

  # Make a checksum.
  full_checksum = make_SHA256_hash(prefix_hash)
  checksum = full_checksum[-4:]

  # Add the checksum to the combined hash.
  address = prefix_hash + checksum

  # Encode an address as a Base58 sequence of bytes.
  base58_address = base58.b58encode(address.encode())

  # Convert a byte sequence to a string.
  address = base58_address.decode('ascii')

  return address


def validate_address(address: str) -> bool:
  """Validates a Helium address using the four character checksum appended to
  the address.

  Args:
      address (str): A Base58 encoded address.

  Returns:
      bool: Validation result.
  """

  # Encode the string address to a sequence of bytes.
  bstr = address.encode('ascii')

  # Reverse the Base58 encoding of the address.
  decoded_address = base58.b58decode(bstr)

  # Convert the address to a string.
  str_address = decoded_address.decode('ascii')

  # Length must be RIPEMD-160 hash length + length of checksum + 1.
  if len(str_address) != 45 or str_address[0] != '1':
    return False

  # Extract the checksum.
  extracted_checksum = str_address[-4:]

  # Extract the checksum out of the string address and compute the SHA-256 hash
  # of the remaining string address.
  hash = make_SHA256_hash(str_address[:-4])

  # Get the computed checksum from the hash.
  checksum = hash[-4:]

  return extracted_checksum == checksum


def make_uuid() -> str:
  """Makes an universally unique 256 bit id encoded as a hexadecimal string
  that is used as a transaction identifier. Users the Python standard library
  secrets module to generate a cryptographic strong random 32 byte string
  encoded as a hexadecimal string of 64 bytes long.

  Returns:
      str: An unique transaction identifier.
  """

  transaction_id = secrets.token_hex(32)

  return transaction_id
