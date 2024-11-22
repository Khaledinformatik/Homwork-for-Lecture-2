# Use the example code ‘ECDSA.py’ to demonstrate the nonce-reuse attack on ECDSA


from ecdsa import SigningKey, util
from ecdsa import NIST256p as CURVE
from hashlib import sha256 as HASH_FUNC

# Function to sign a message using ECDSA
def ecdsa_sign(message, private_key, nonce=None):
    signature = None # If the nonce is explicitly specified
    if nonce:
        signature = private_key.sign(
            message,
            k=nonce,
            hashfunc=HASH_FUNC,
            sigencode=util.sigencode_der
        )
    else:
        signature = private_key.sign(
            message,
            hashfunc=HASH_FUNC,
            sigencode=util.sigencode_der
        )
    return signature

# Function to verify ECDSA signature
def ecdsa_verify(signature, message, public_key):
    try:
        is_valid = public_key.verify(
            signature,
            message,
            hashfunc=HASH_FUNC,
            sigdecode=util.sigdecode_der
        )
        return is_valid
    except:
        return False


# Compute the inverse of a number modulus
def invert(number, modulus): 
    inverse = None
    try:
        inverse = pow(number, -1, modulus)
    except:
        print("Non-invertible element.")
    return inverse

def main():
    # Generate ECDSA key pair
    private_key = SigningKey.generate(CURVE)
    public_key = private_key.get_verifying_key()
    order_CURVE = CURVE.order

    # Print the sk
    private_key_int = private_key.privkey.secret_multiplier
    print("\nPrivate Key (decimal):", private_key_int)

    # Two different messages to be signed message1 , message2
    message1 = b"Hello, Alice!"
    message2 = b"Hello, Bob!"

    # Hash messages
    h1 = int.from_bytes(HASH_FUNC(message1).digest(), byteorder='big')
    h2 = int.from_bytes(HASH_FUNC(message2).digest(), byteorder='big')

    # Use the same fixed nonce for both signatures
    nonce = 34119 % order_CURVE
    signature1 = ecdsa_sign(message1, private_key, nonce)
    signature2 = ecdsa_sign(message2, private_key, nonce)

    r1, s1 = util.sigdecode_der(signature1, order_CURVE)
    r2, s2 = util.sigdecode_der(signature2, order_CURVE)

    if r1 != r2:
        print("Error: Nonce reuse not detected correctly.")
        return

    print("\nSignature 1 (r, s):")
    print("r =", r1)
    print("s =", s1)

    print("\nSignature 2 (r, s):")
    print("r =", r2)
    print("s =", s2)

    # Nonce-reuse attack
    s_diff = (s1 - s2) % order_CURVE
    if s_diff == 0:
        print("Error: s1 and s2 are equal, cannot perform attack.")
        return

    # Recover the private key
    s_diff_inv = invert(s_diff, order_CURVE)
    if s_diff_inv is None:
        print("Error: Cannot invert s_diff.")
        return
    h_diff = (h1 - h2) % order_CURVE
    secret_key_recovered = (h_diff * s_diff_inv) % order_CURVE
    print("\nRecovered Private Key (decimal):", secret_key_recovered)

    # Verify the recovered private key matches the original
    if secret_key_recovered == private_key_int:
        print("Success: Private key successfully recovered!")
    else:
        print("Failure: Private key recovery failed.")

if __name__ == "__main__":
    main()