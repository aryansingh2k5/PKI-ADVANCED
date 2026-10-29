import socket
import threading
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from utils import decrypt_aes

PASSWORD = b"securepassword"

# Load private key
with open("server_key.pem", "rb") as f:
    private_key = load_pem_private_key(f.read(), password=PASSWORD)

def handle_client(conn, addr):
    print(f"[LOG] Connected: {addr}")

    # Send certificate
    with open("server_cert.pem", "rb") as f:
        conn.send(f.read())

    # Receive AES key (encrypted with RSA)
    encrypted_key = conn.recv(4096)
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Receive nonce + ciphertext
    nonce = conn.recv(1024)
    ciphertext = conn.recv(4096)

    decrypted = decrypt_aes(aes_key, nonce, ciphertext).decode()
    message, timestamp = decrypted.split("|")

    # Replay protection
    if abs(time.time() - float(timestamp)) > 10:
        print("[WARNING] Replay attack detected!")
        conn.close()
        return

    print(f"[LOG] Message: {message}")

    # Sign actual message
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    conn.send(signature)
    conn.close()

server = socket.socket()
server.bind(("localhost", 5000))
server.listen(5)

print("[LOG] Server running...")

while True:
    conn, addr = server.accept()
    threading.Thread(target=handle_client, args=(conn, addr)).start()