# Bonus: Implement a man-in-the-middle attack on DHKE using sockets.
# Alice.py
from random import random
from socket import socket

# Diffie-Hellman parameters 
p = 23  # A prime number
g = 5   # A primitive root modulo p

# Alice's private key
a = random.randint(1, p- 1)
A = pow(g, a, p)  # Alice's public key


def alice():
    # Connect to Eve
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('localhost', 9999))

    # Send public key A to Bob through Eve
    s.send(str(A).encode())

    # Receive modified public key B from Eve (pretending to be Bob)
    B = int(s.recv(1024).decode())

    # Compute the shared secret
    shared_secret = pow(B, a, p)
    print(f"Alice's shared secret: {shared_secret}")

    s.close()


if __name__ == "__main__":
    alice()