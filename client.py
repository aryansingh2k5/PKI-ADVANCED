import socket
import time
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from utils import generate_aes_key, encrypt_aes

client = socket.socket()
client.connect(("localhost", 5000))

# Receive certificate
cert_data = client.recv(4096)
certificate = x509.load_pem_x509_certificate(cert_data)
public_key = certificate.public_key()

# Verify certificate (self-signed)
public_key.verify(
    certificate.signature,
    certificate.tbs_certificate_bytes,
    padding.PKCS1v15(),
    certificate.signature_hash_algorithm,
)

print("[LOG] Certificate verified!")

# Generate AES key
aes_key = generate_aes_key()

# Encrypt AES key using RSA
encrypted_key = public_key.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

client.send(encrypted_key)

# Prepare message with timestamp
message = f"Hello Secure Server|{time.time()}".encode()

nonce, ciphertext = encrypt_aes(aes_key, message)

client.send(nonce)
client.send(ciphertext)

# Receive signature
signature = client.recv(4096)

# Verify signature
try:
    public_key.verify(
        signature,
        b"Hello Secure Server",
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("[LOG] Signature Verified!")
except:
    print("[ERROR] Signature Verification Failed!")

client.close()