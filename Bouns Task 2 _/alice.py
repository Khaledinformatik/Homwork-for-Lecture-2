# Bouns Homwork : Use a trusted server and signatures to securely exchange public keys (using sockets)

# alice.py


import socket
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import ssl

#  secure key generation and loading
def load_alice_private_key():

    try:
        with open('alice_private_key.pem', 'rb') as key_file:
            return serialization.load_pem_private_key(key_file.read(), password=None)
    except FileNotFoundError:
        print("Alice's private key not found. Generate one securely.")
        return None

def load_server_public_key():
    try:
        with open('server_public_key.pem', 'rb') as key_file:
            return serialization.load_pem_public_key(key_file.read())
    except FileNotFoundError:
        print("Server's public key not found.")
        return None

def get_signature_from_server(data):
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH) #Use SSL/TLS
    with socket.create_connection(('localhost', 65432)) as sock:
        with context.wrap_socket(sock, server_hostname='localhost') as ssock: #wrap socket for SSL
            ssock.sendall(data)
            signature = ssock.recv(4096)
    return signature

def verify_signature(public_key, signature, data):
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False

if __name__ == "__main__":
    alice_private_key = load_alice_private_key()
    if alice_private_key is None:
        exit(1) #Exit if key loading fails
    alice_public_key = alice_private_key.public_key()
    alice_public_pem = alice_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

