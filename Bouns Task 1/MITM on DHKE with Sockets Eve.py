# Eve.py
import socket
import random

# Diffie-Hellman parameters 
p = 23  # A prime number
g = 5   # A primitive root modulo p

# Eve's private keys
e1 = random.randint(1, p - 1)
e2 = random.randint(1, p - 1)

# Eve's public keys
E1 = pow(g, e1, p)  # Eve's public key for Alice
E2 = pow(g, e2, p)  # Eve's public key for Bob

def eve():
    try:
        # Set up server to listen for Alice's message
        server_alice = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_alice.bind(('localhost', 9999))
        server_alice.listen(1)
        conn_alice, addr_alice = server_alice.accept()

        # Receive public key A from Alice
        A = int(conn_alice.recv(1024).decode())

        # Send Eve's public key E1 to Alice, pretending to be Bob
        conn_alice.send(str(E1).encode())

        # Compute shared secret with Alice
        shared_secret_eve_alice = pow(A, e1, p)
        print(f"Eve's shared secret with Alice: {shared_secret_eve_alice}")

        conn_alice.close()
        server_alice.close()

        # Connect to Bob and act as Alice
        client_bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_bob.connect(('localhost', 10000))

        # Send Eve's public key E2 to Bob, pretending to be Alice
        client_bob.send(str(E2).encode())

        # Receive public key B from Bob
        B = int(client_bob.recv(1024).decode())

        # Compute shared secret with Bob
        shared_secret_eve_bob = pow(B, e2, p)
        print(f"Eve's shared secret with Bob: {shared_secret_eve_bob}")

        client_bob.close()
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    eve()