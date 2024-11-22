
# Bouns Homwork : Use a trusted server and signatures to securely exchange public keys (using sockets)

# bob.py

import socket
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Load the server's public key
def load_server_public_key(server_public_key_path):
    try:
        with open(server_public_key_path, 'rb') as key_file:
            server_public_key = serialization.load_pem_public_key(key_file.read())
        return server_public_key
    except FileNotFoundError:
        print(f"Error: Server public key file not found at {server_public_key_path}")
        return None

# Generate Bob's RSA key pair
bob_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
bob_public_key = bob_private_key.public_key()

# Serialize Bob's public key
bob_public_pem = bob_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

def get_signature_from_server(server_address, data):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(server_address)
            s.sendall(data)
            signature = s.recv(4096)
        return signature
    except socket.error as e:
        print(f"Error connecting to server: {e}")
        return None

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
    server_address = ('localhost', 65432)  # Load from config or environment variable
    server_public_key_path = 'server_public_key.pem'

    server_public_key = load_server_public_key(server_public_key_path)
    if not server_public_key:
        exit(1)
