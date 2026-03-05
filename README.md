# CryptoSign

A web-based **Public Key Infrastructure (PKI) tool** for digital file signing, signature verification, hybrid encryption, and certificate management. Built with Python/Flask and the `cryptography` library.

> **ST6051CEM — Practical Cryptography | Softwarica College / Coventry University**
> **Author:** Avinabh
> **GitHub:** [https://github.com/AuguStus0502/CryptoSign](https://github.com/AuguStus0502/CryptoSign)
> **Video Demo:** *(coming soon — link will be added before submission)*

---

## Features

| Feature | Description |
|---|---|
| **RSA Key Generation** | 2048 / 3072 / 4096-bit key pairs with password-protected PKCS#8 storage |
| **PKCS#12 Export** | Export keys + certificates as `.p12` bundles for use with OS keystores / HSMs |
| **Digital Signatures** | RSA-PSS (SHA-256) — sign any file, download a portable `.sig.json` |
| **Signature Verification** | Verify any file against its `.sig.json` without an account |
| **Hybrid Encryption** | AES-256-GCM + RSA-OAEP — encrypt messages and files of any size |
| **X.509 Certificates** | Self-signed certificates auto-generated for every key pair |
| **Certificate Pinning** | SHA-256 fingerprint pinning helper to prevent MITM attacks |
| **Replay-Attack Prevention** | Signed envelopes with nonce + timestamp validation |
| **Forward Secrecy** | Ephemeral ECDH (P-256) + HKDF-SHA256 session key derivation |
| **Audit Logging** | Every action recorded with user, IP, and timestamp |
| **Admin Panel** | User management, key overview, full audit log |

---

## Quickstart

### Prerequisites

- Python 3.10+
- pip

### Installation

```bash

git clone https://github.com/AuguStus0502/CryptoSign.git
cd cryptosign


python -m venv venv
source venv/bin/activate        


pip install -r requirements.txt


python app.py
```

The app will be available at **http://127.0.0.1:5001**

A default admin account is created automatically on first run:
- **Username:** `admin`
- **Password:** `admin6217`

> Change the default admin password immediately in production.

---

## Usage Guide

### Regular Users

1. **Register** at `/register` — provide username, email, password, and three security questions.
2. **Generate a Key Pair** at `/keys` — choose key name, size (2048/3072/4096-bit), and key password. A self-signed X.509 certificate is generated automatically.
3. **Sign a File** at `/sign` — upload any file, select a key, enter key password. Download the `.sig.json` signature bundle.
4. **Verify a File** at `/verify` — upload the original file + `.sig.json` to verify the signature.
5. **Encrypt / Decrypt** at `/encrypt` — hybrid-encrypt messages to any user's public key; decrypt with your private key password.
6. **Export PKCS#12** at `/keys` — download key + certificate as a `.p12` for use in browsers or OS keystores.
7. **View History** at `/history` — see all files you have signed.

### Admin

Log in at `/admin/login`. From the admin panel you can create/manage users, view all key pairs, and browse the full audit log.

---

## Cryptographic Design

### Key Storage
Private keys are stored encrypted with **PKCS#8 + BestAvailableEncryption** (AES-256-CBC, scrypt KDF). Keys never leave the server unencrypted.

### Digital Signatures
Files are signed with **RSA-PSS** (SHA-256, maximum salt length). PSS provides stronger security guarantees than the legacy PKCS#1 v1.5 scheme.

### Hybrid Encryption
Pure RSA is limited to ~190 bytes (2048-bit). CryptoSign uses hybrid encryption for all data:
1. Generate a random 256-bit AES session key
2. Encrypt data with **AES-256-GCM** (authenticated encryption)
3. Encrypt the session key with **RSA-OAEP** (SHA-256)

### Replay-Attack Prevention
Signed envelopes embed a **128-bit random nonce** and **UTC timestamp**. Verification rejects any envelope whose nonce has been seen before, or whose timestamp exceeds the freshness window.

### Forward Secrecy
Session keys are derived from **ephemeral ECDH** (P-256) exchanges using **HKDF-SHA256**. Discarding ephemeral keys after use ensures past sessions cannot be decrypted even if the long-term key is later compromised.

### MITM Prevention
Each certificate's **SHA-256 fingerprint** can be pinned. Any certificate substitution by an attacker produces a different fingerprint and is rejected.

---

## Running Tests

```bash

pip install pytest
pytest tests/ -v


python -m unittest discover tests/ -v
```

The test suite covers **39 test cases** across 8 categories including simulated attacks (replay, MITM, forged signatures, tampered ciphertext, key impersonation).

---

## Project Structure

```
cryptosign/
├── app.py                     
├── crypto_utils.py            
├── requirements.txt
├── README.md
├── LICENSE
├── tests/
│   └── test_crypto_utils.py   
├── templates/
│   ├── admin/
│   └── *.html
├── static/
├── keystores/                 
└── instance/                  
```

---

## Extending CryptoSign

All cryptographic operations are isolated in `crypto_utils.py`. To add a new algorithm:

1. Add your function to `crypto_utils.py` with a full docstring
2. Import and wire it in `app.py`
3. Add unit tests in `tests/test_crypto_utils.py`

You can also import `crypto_utils` directly into any Python project:

```python
from crypto_utils import generate_rsa_keypair, sign_file_data, encrypt_file
```

---

## Security Notes

- Uses self-signed certificates. For production, certificates should be issued by a trusted CA.
- Change default admin credentials before deployment.
- `keystores/` and `instance/` are excluded from version control — back them up separately.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

## Acknowledgements

Built using the [cryptography](https://cryptography.io/) library (Apache 2.0 / BSD).
