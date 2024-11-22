
# Bouns Homwork : Use a trusted server and signatures to securely exchange public keys (using sockets)

# server.py

import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# Generate server's RSA key pair
server_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
server_public_key = server_private_key.public_key()

# Serialize the public key for sharing
server_public_pem = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)


def sign_data(private_key, data):
    # Sign the provided data using the private key.
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def handle_client(conn, addr):
    # "Handle incoming client connections.
    print(f"Connected by {addr}")
    data = conn.recv(4096)

    if data:
        # Sign the received public key
        signature = sign_data(server_private_key, data)
        # Send the signature back to the client
        conn.sendall(signature)

    conn.close()


def start_server(host='localhost', port=65432):
    #Start the signing server.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        print(f"Server is listening on {host}:{port}")

        while True:
            conn, addr = server_socket.accept()
            handle_client(conn, addr)


if __name__ == "__main__":
    start_server()
