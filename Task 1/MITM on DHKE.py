
# Homwork lecture 2 Implement a man-in-the-middle attack (in one program) on DHKE.

import parameters
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
import os

# Key generation for Alice and Bob
parameters = dh.generate_parameters(generator=2, key_size=2024)

# Generate private keys
alice_private_key = parameters.generate_private_key()
bob_private_key = parameters.generate_private_key()

# Generate public keys
alice_public_key = alice_private_key.public_key()
bob_public_key =  bob_private_key.public_key()

# Serialize public keys to share them
alice_public_bytes = alice_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

bob_public_bytes = bob_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)


# Now Alice and Bob can exchange their public keys 
# Alice computes the shared secret using Bob's public key
alice_shared_secret = alice_private_key.exchange(bob_public_key)

# Bob computes the shared secret using Alice's public key
bob_shared_secret = bob_private_key.exchange(alice_public_key)

# Both shared secrets should be the same
assert alice_shared_secret == bob_shared_secret

# Derive a key from the shared secret
salt = os.urandom(16)  # Should be stored and used consistently
kdf = Scrypt(
    salt=salt,
    length=32,
    n=2**14,
    r=8,
    p=1,
)
key = kdf.derive(alice_shared_secret)

# Eve intercepts and generates her own keys
eve_private_key_1 = parameters.generate_private_key()
eve_private_key_2 = parameters.generate_private_key()
eve_public_key_1 = eve_private_key_1.public_key()
eve_public_key_2 = eve_private_key_2.public_key()

# Exchange public keys
alice_public_numbers = alice_public_key.public_numbers()
bob_public_numbers = bob_public_key.public_numbers()
eve_public_numbers_1 = eve_public_key_1.public_numbers()
eve_public_numbers_2 = eve_public_key_2.public_numbers()

# Alice thinks she is sharing with Bob, but it's with Eve
shared_key_1 = alice_private_key.exchange(eve_public_key_1)
shared_key_2 = bob_private_key.exchange(eve_public_key_2)

# Eve computes the shared keys with Alice and Bob
eve_shared_key_1 = eve_private_key_1.exchange(alice_public_key)
eve_shared_key_2 = eve_private_key_2.exchange(bob_public_key)

print(f"Alice's shared key (with Eve): {shared_key_1}")
print(f"Bob's shared key (with Eve): {shared_key_2}")
print(f"Eve's shared key with Alice: {eve_shared_key_1}")
print(f"Eve's shared key with Bob: {eve_shared_key_2}")