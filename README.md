# 🔐 Secure Code Signing

> A web-based **Public Key Infrastructure (PKI)** tool for digital file signing, signature verification, hybrid encryption, and certificate management — built from scratch with Python and Flask.

---

**Author:** Avinabh Jung Shrestha
**Course:** ST6051CEM — Practical Cryptography
**Institution:** Softwarica College of IT & E-Commerce | In collaboration with Coventry University
**GitHub:** [https://github.com/AuguStus0502/Secure-Code-Signing](https://github.com/AuguStus0502/Secure-Code-Signing)
**Video Demo:** [https://youtu.be/nFa3lsYcrFc](https://youtu.be/nFa3lsYcrFc)

---

## What Is This?

Secure Code Signing is an open-source cryptographic tool that solves two core real-world problems:

1. **Proving authenticity** — Digitally sign any file (PDF, Word, ZIP, anything) so the recipient can verify it came from you and was not tampered with.
2. **Ensuring confidentiality** — Encrypt messages so only the intended recipient can decrypt them using their private key.

Think of it as a mini version of the cryptographic systems used by banks, law firms, and software companies — but open-source and running in your browser.

---

## Features

| Feature | Description |
|---|---|
| 🔑 **RSA Key Generation** | 2048 / 3072 / 4096-bit key pairs with password-protected PKCS#8 storage |
| 📦 **PKCS#12 Export** | Export keys + certificates as `.p12` bundles for OS keystores / HSMs |
| ✍️ **Digital Signatures** | RSA-PSS (SHA-256) — sign any file, download a portable `.sig.json` |
| ✅ **Signature Verification** | Verify any file against its `.sig.json` — no account needed |
| 🔒 **Hybrid Encryption** | AES-256-GCM + RSA-OAEP — encrypt messages and files of any size |
| 📜 **X.509 Certificates** | Self-signed certificates auto-generated for every key pair |
| 📌 **Certificate Pinning** | SHA-256 fingerprint pinning to prevent MITM attacks |
| 🛡️ **Replay-Attack Prevention** | Signed envelopes with nonce + timestamp validation |
| ⏩ **Forward Secrecy** | Ephemeral ECDH (P-256) + HKDF-SHA256 session key derivation |
| 📋 **Audit Logging** | Every action recorded with user, IP, and timestamp |
| 👤 **Admin Panel** | User management, key overview, password reset, full audit log |

---

## Quickstart

### Prerequisites

- Python 3.10+
- pip

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/AuguStus0502/Secure-Code-Signing.git
cd Secure-Code-Signing

# 2. Create and activate a virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the application
python app.py
```

The app will be available at **http://127.0.0.1:5001**

A default admin account is created automatically on first run:
- **Username:** `admin`
- **Password:** `admin6217`

> ⚠️ Change the default admin password immediately in production.

---

## Usage Guide

### Regular Users

1. **Register** at `/register` — provide username, email, password, and three security questions for account recovery.
2. **Generate a Key Pair** at `/keys` — choose key name, size (2048/3072/4096-bit), and key password. A self-signed X.509 certificate is auto-generated.
3. **Sign a File** at `/sign` — upload any file (up to 500 MB), select a key, enter key password. Download the `.sig.json` signature bundle.
4. **Verify a File** at `/verify` — upload the original file + `.sig.json` to confirm authenticity and detect tampering.
5. **Encrypt / Decrypt** at `/encrypt` — hybrid-encrypt messages to any user's public key; decrypt with your private key password.
6. **Export PKCS#12** at `/keys` — download key + certificate as a `.p12` file for use in browsers or OS keystores.
7. **View History** at `/history` — see a full log of all files you have signed.

### Admin

Log in at `/admin/login`. The admin panel lets you:
- Create, activate, deactivate, block, or delete user accounts
- Reset any user's password (forces them to change it on next login)
- Promote users to admin role
- View all RSA key pairs across the platform
- Browse the full paginated audit log

---

## Cryptographic Design

### Key Storage
Private keys are encrypted with **PKCS#8 + BestAvailableEncryption** (AES-256-CBC, scrypt KDF) before being written to disk. Keys never leave the server unencrypted.

### Digital Signatures
Files are signed with **RSA-PSS** (SHA-256, maximum salt length). PSS is more secure than the legacy PKCS#1 v1.5 scheme as it uses probabilistic padding, resisting chosen-ciphertext attacks.

### Hybrid Encryption
Pure RSA encryption is limited to ~190 bytes (2048-bit key). Secure Code Signing uses hybrid encryption for all data:
1. Generate a random 256-bit AES session key
2. Encrypt data with **AES-256-GCM** (provides both confidentiality and integrity)
3. Encrypt the session key with **RSA-OAEP** (SHA-256)

### Replay-Attack Prevention
Every signed envelope embeds a **128-bit random nonce** and a **UTC timestamp**. The verifier rejects any envelope whose nonce has been used before, or whose timestamp falls outside the allowed freshness window — preventing attackers from reusing captured messages.

### Forward Secrecy
Session keys are derived from **ephemeral ECDH** (P-256) exchanges using **HKDF-SHA256**. Ephemeral keys are discarded after each session, meaning past communications cannot be decrypted even if the long-term private key is later compromised.

### MITM Prevention
Each certificate's **SHA-256 fingerprint** can be pinned by clients. Any certificate substituted by a man-in-the-middle attacker produces a different fingerprint and is rejected immediately.

---

## Running Tests

```bash
# Using pytest (recommended)
pip install pytest
pytest tests/ -v

# Using built-in unittest (no extra dependencies)
python -m unittest discover tests/ -v
```

The test suite covers **39 test cases** across 8 categories:

- Key generation and serialisation
- PKCS#12 export and import
- Digital signatures
- Hybrid encryption (messages and files)
- X.509 certificates and fingerprint pinning
- Replay-attack prevention (nonce reuse, expired envelopes, tampered payloads)
- Forward secrecy (ECDH key exchange)
- Multi-user signing and attack simulations (forged signatures, MITM, key impersonation)

---

## Project Structure

```
Secure-Code-Signing/
├── app.py                     # Flask application, routes, models
├── crypto_utils.py            # All cryptographic primitives
├── requirements.txt           # Python dependencies
├── README.md
├── tests/
│   ├── __init__.py
│   └── test_crypto_utils.py   # 39 unit + attack simulation tests
├── templates/
│   ├── admin/                 # Admin panel templates
│   └── *.html                 # User-facing templates
├── static/                    # CSS, JS, images
├── keystores/                 # Encrypted private keys (gitignored)
└── instance/                  # SQLite database (gitignored)
```

---

## Extending This Tool

All cryptographic operations are isolated in `crypto_utils.py`. To add a new algorithm:

1. Add your function to `crypto_utils.py` with a full docstring
2. Import and wire it in `app.py`
3. Add unit tests in `tests/test_crypto_utils.py`

You can also import `crypto_utils` directly into any Python project:

```python
from crypto_utils import generate_rsa_keypair, sign_file_data, encrypt_file
```

---

## Real-World Use Cases

**1. Legal Document Signing** — A lawyer signs a contract PDF before sending it to a client. The client verifies the signature to confirm it came from the lawyer and was not altered in transit.

**2. Secure Internal Communications** — A company encrypts sensitive memos to specific recipients. Even if the message is intercepted, it cannot be read without the recipient's private key.

**3. Software Release Verification** — A developer signs each software release archive. Users verify the signature before installing to prevent supply chain attacks.

---

## Security Notes

- Uses self-signed certificates. For production deployments, certificates should be issued by a trusted Certificate Authority.
- Change default admin credentials before deploying to any shared environment.
- `keystores/` and `instance/` are excluded from version control — back these up separately.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

## Acknowledgements

Built using the [cryptography](https://cryptography.io/) library (Apache 2.0 / BSD).
