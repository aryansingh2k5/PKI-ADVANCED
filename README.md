# PKI Advanced Secure Communication System

 Overview
This project demonstrates a secure client-server communication system using Public Key Infrastructure (PKI). It ensures confidentiality, integrity, and authentication using cryptographic techniques such as RSA, AES, and Digital Signatures.

---

## Features
- RSA Encryption for secure key exchange
- AES Hybrid Encryption for efficient communication
- X.509 Certificate Generation
- Certificate Verification to prevent MITM attacks
- Digital Signature Verification
- Replay Attack Protection using timestamps
- Multi-client support using threading

---

## Concepts Used
- Public Key Infrastructure (PKI)
- Asymmetric Encryption (RSA)
- Symmetric Encryption (AES)
- Digital Signatures (PSS)
- Secure Key Exchange
- Man-in-the-Middle Attack Prevention

---

## How It Works

1. Server generates RSA key pair and certificate
2. Client connects and verifies server certificate
3. Client generates an AES key
4. AES key is encrypted using RSA public key
5. Message is encrypted using AES
6. Server decrypts the message and validates timestamp
7. Server signs the response using private key
8. Client verifies the signature using public key

---

## How to Run

### 1. Install dependencies
```bash
pip install cryptography
2. Generate certificate
python generate_cert.py
3. Run server
python server.py
4. Run client
python client.py
