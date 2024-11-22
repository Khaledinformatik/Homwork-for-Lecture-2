
# Bonus: Implement a man-in-the-middle attack on DHKE using sockets.
# Bob.py


# Bob.py
import socket
import random

# Diffie-Hellman parameters 
p = 23  # A prime number
g = 5  # A primitive root modulo p

# Bob's private key
b = random.randint(1, p - 1)
B = pow(g, b, p)  # Bob's public key


def bob():
    # Set up server to listen for Alice's message through Eve
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 10000))
    server.listen(1)

    conn, addr = server.accept()
    # Receive public key A from Alice (actually Eve)
    A = int(conn.recv(1024).decode())

    # Send public key B to Alice through Eve
    conn.send(str(B).encode())

    # Compute the shared secret
    shared_secret = pow(A, b, p)
    print(f"Bob's shared secret: {shared_secret}")

    conn.close()
    server.close()


if __name__ == "__main__":
    bob()
