"""
crypto_utils.py - Cryptographic Primitives for CryptoSign
Uses the `cryptography` library for all operations.

Features:
  - RSA key pair generation (2048 / 3072 / 4096-bit)
  - PKCS#8 password-protected PEM key storage
  - PKCS#12 (.p12) keystore export/import
  - RSA-PSS digital signatures (SHA-256)
  - Hybrid encryption: AES-256-GCM + RSA-OAEP  (messages & files)
  - Self-signed X.509 certificate generation
  - Replay-attack prevention via signed timestamps + nonce
  - Forward-secrecy helper: ephemeral session key derivation (HKDF)
  - MITM protection: certificate fingerprint pinning helper
"""

import hashlib
import hmac
import base64
import os
import time
import secrets
from datetime import datetime, timedelta, timezone
from typing import Dict, Tuple

from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import hashes, serialization, hmac as crypto_hmac
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509
from cryptography.x509.oid import NameOID


# ─────────────────────────────────────────────
# RSA Key Generation
# ─────────────────────────────────────────────
def generate_rsa_keypair(key_size: int = 2048):
    """Generate an RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


# ─────────────────────────────────────────────
# Serialization
# ─────────────────────────────────────────────
def serialize_public_key(public_key: RSAPublicKey) -> bytes:
    """Serialize a public key to PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def serialize_private_key_encrypted(private_key: RSAPrivateKey, password: str) -> bytes:
    """Serialize and encrypt a private key with a password (PKCS8 / BestAvailableEncryption)."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8'))
    )


def load_private_key(pem_data: bytes, password: str) -> RSAPrivateKey:
    """Load an encrypted private key from PEM bytes."""
    return serialization.load_pem_private_key(
        pem_data,
        password=password.encode('utf-8'),
        backend=default_backend()
    )


# ─────────────────────────────────────────────
# Key Fingerprint
# ─────────────────────────────────────────────
def get_key_fingerprint(public_key: RSAPublicKey) -> str:
    """Return SHA-256 fingerprint of the public key (hex)."""
    pub_bytes = serialize_public_key(public_key)
    digest = hashlib.sha256(pub_bytes).hexdigest()
    # Format as pairs: AA:BB:CC...
    return ':'.join(digest[i:i+2].upper() for i in range(0, min(40, len(digest)), 2))


# ─────────────────────────────────────────────
# Digital Signatures (RSA-PSS with SHA-256)
# ─────────────────────────────────────────────
def sign_file_data(private_key: RSAPrivateKey, data: bytes) -> bytes:
    """
    Sign data using RSA-PSS with SHA-256.
    RSA-PSS provides stronger security guarantees than PKCS#1 v1.5.
    """
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_file_signature(public_key: RSAPublicKey, data: bytes, signature: bytes) -> bool:
    """
    Verify an RSA-PSS signature. Returns True if valid, False otherwise.
    Prevents MITM and replay attacks by binding data to signature.
    """
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
    except Exception:
        return False


# ─────────────────────────────────────────────
# Self-Signed X.509 Certificate Generation
# ─────────────────────────────────────────────
def generate_certificate(private_key: RSAPrivateKey,
                          public_key: RSAPublicKey,
                          common_name: str,
                          valid_days: int = 365) -> bytes:
    """
    Generate a self-signed X.509 certificate for the key pair.
    Used for certificate-based authentication.
    """
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,             "NP"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,   "Bagmati"),
        x509.NameAttribute(NameOID.LOCALITY_NAME,            "Kathmandu"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,        "CryptoSign"),
        x509.NameAttribute(NameOID.COMMON_NAME,              common_name),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=valid_days))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    return cert.public_bytes(serialization.Encoding.PEM)


# ─────────────────────────────────────────────
# Hybrid Encryption (RSA + AES-GCM)
# ─────────────────────────────────────────────
def encrypt_message(public_key: RSAPublicKey, message: bytes) -> dict:
    """
    Hybrid encryption:
      1. Generate a random AES-256 session key
      2. Encrypt message with AES-GCM
      3. Encrypt session key with RSA-OAEP
    Returns dict with encrypted_key and ciphertext (both base64-encoded).
    """
    import os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    session_key = os.urandom(32)   # AES-256
    nonce       = os.urandom(12)   # 96-bit nonce for GCM
    aesgcm      = AESGCM(session_key)
    ciphertext  = aesgcm.encrypt(nonce, message, None)

    encrypted_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {
        'encrypted_key': base64.b64encode(encrypted_key).decode(),
        'nonce':         base64.b64encode(nonce).decode(),
        'ciphertext':    base64.b64encode(ciphertext).decode(),
    }


def decrypt_message(private_key: RSAPrivateKey, encrypted_data: dict) -> bytes:
    """
    Decrypt a hybrid-encrypted message.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    encrypted_key = base64.b64decode(encrypted_data['encrypted_key'])
    nonce         = base64.b64decode(encrypted_data['nonce'])
    ciphertext    = base64.b64decode(encrypted_data['ciphertext'])

    session_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    aesgcm    = AESGCM(session_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext


# ─────────────────────────────────────────────
# PKCS#12 Keystore Export / Import
# ─────────────────────────────────────────────
def export_pkcs12(private_key: RSAPrivateKey,
                  certificate_pem: bytes,
                  password: str,
                  friendly_name: str = "CryptoSign Key") -> bytes:
    """
    Export a private key + certificate as a PKCS#12 (.p12) bundle.
    PKCS#12 is an industry-standard format accepted by browsers, OS keystores,
    and HSMs — providing stronger portability than raw PEM files.

    Args:
        private_key:     RSA private key object
        certificate_pem: PEM-encoded X.509 certificate bytes
        password:        Password to protect the bundle
        friendly_name:   Human-readable label stored inside the .p12

    Returns:
        Raw bytes of the .p12 file
    """
    cert = x509.load_pem_x509_certificate(certificate_pem, default_backend())
    p12_bytes = pkcs12.serialize_key_and_certificates(
        name=friendly_name.encode("utf-8"),
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password.encode("utf-8")
        ),
    )
    return p12_bytes


def import_pkcs12(p12_bytes: bytes, password: str) -> Tuple[RSAPrivateKey, bytes, str]:
    """
    Import a PKCS#12 bundle.

    Returns:
        (private_key, certificate_pem_bytes, friendly_name_str)
    """
    priv, cert, _ = pkcs12.load_key_and_certificates(
        p12_bytes,
        password.encode("utf-8"),
        default_backend(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    friendly = name[0].value if name else "imported"
    return priv, cert_pem, friendly


# ─────────────────────────────────────────────
# Replay-Attack Prevention
# ─────────────────────────────────────────────
def create_signed_envelope(private_key: RSAPrivateKey,
                            payload: bytes,
                            max_age_seconds: int = 300) -> Dict:
    """
    Wrap a payload in a tamper-evident, replay-resistant envelope.

    Replay attacks are prevented by embedding:
      - A cryptographically random nonce (one-time value)
      - A UTC timestamp (ISO-8601)
    Both are included in the data that is signed, so an attacker cannot reuse
    a captured envelope: the timestamp will have expired and the nonce can be
    checked against a seen-nonce store.

    Args:
        private_key:      Signer's RSA private key
        payload:          Arbitrary bytes to protect
        max_age_seconds:  Validity window (default 5 minutes)

    Returns:
        dict with keys: payload_b64, nonce, timestamp, max_age, signature_b64
    """
    nonce     = secrets.token_hex(16)                          # 128-bit random nonce
    timestamp = datetime.now(timezone.utc).isoformat()
    signed_data = (
        base64.b64encode(payload).decode()
        + nonce
        + timestamp
    ).encode("utf-8")

    signature = private_key.sign(
        signed_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    return {
        "payload_b64":   base64.b64encode(payload).decode(),
        "nonce":         nonce,
        "timestamp":     timestamp,
        "max_age":       max_age_seconds,
        "signature_b64": base64.b64encode(signature).decode(),
    }


def verify_signed_envelope(public_key: RSAPublicKey,
                            envelope: Dict,
                            seen_nonces: set) -> Tuple[bool, str, bytes]:
    """
    Verify a signed envelope and defend against replay attacks.

    Checks:
      1. Signature is cryptographically valid (MITM / tampering detection)
      2. Timestamp is within the allowed max_age window (freshness check)
      3. Nonce has not been seen before (replay-attack prevention)

    Args:
        public_key:   Signer's RSA public key
        envelope:     dict returned by create_signed_envelope()
        seen_nonces:  Mutable set of already-used nonces (caller manages)

    Returns:
        (ok: bool, reason: str, payload: bytes)
        If ok is False, reason explains why verification failed.
    """
    try:
        payload_b64 = envelope["payload_b64"]
        nonce       = envelope["nonce"]
        timestamp   = envelope["timestamp"]
        max_age     = int(envelope.get("max_age", 300))
        signature   = base64.b64decode(envelope["signature_b64"])
    except (KeyError, Exception) as exc:
        return False, f"Malformed envelope: {exc}", b""

    # 1. Replay check — nonce must be fresh
    if nonce in seen_nonces:
        return False, "Replay attack detected: nonce already used.", b""

    # 2. Freshness check — timestamp must be within max_age
    try:
        sent_at = datetime.fromisoformat(timestamp)
        age     = (datetime.now(timezone.utc) - sent_at).total_seconds()
        if age > max_age:
            return False, f"Envelope expired ({age:.0f}s old, max {max_age}s).", b""
        if age < -10:
            return False, "Envelope timestamp is in the future (clock skew / tampering).", b""
    except ValueError:
        return False, "Invalid timestamp format.", b""

    # 3. Signature verification (MITM / tampering detection)
    signed_data = (payload_b64 + nonce + timestamp).encode("utf-8")
    try:
        public_key.verify(
            signature,
            signed_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    except Exception:
        return False, "Invalid signature — message may have been tampered.", b""

    # Mark nonce as used AFTER all checks pass
    seen_nonces.add(nonce)
    return True, "OK", base64.b64decode(payload_b64)


# ─────────────────────────────────────────────
# Forward Secrecy — Ephemeral Session Key
# ─────────────────────────────────────────────
def derive_session_key(shared_secret: bytes,
                        salt: bytes = None,
                        info: bytes = b"cryptosign-session-v1",
                        key_length: int = 32) -> bytes:
    """
    Derive a fresh symmetric session key from a shared secret using HKDF-SHA256.

    Forward secrecy means that compromising a long-term private key does NOT
    expose past session keys.  Each session derives its own key from fresh
    ephemeral material (e.g. from an ECDH exchange), so old sessions remain
    protected even if the long-term key is later exposed.

    Args:
        shared_secret: Bytes from an ECDH key agreement (or any shared secret)
        salt:          Random salt (generated per-session if not provided)
        info:          Context/application label for domain separation
        key_length:    Output key length in bytes (32 = AES-256)

    Returns:
        Derived key bytes
    """
    if salt is None:
        salt = os.urandom(32)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        info=info,
        backend=default_backend(),
    )
    return hkdf.derive(shared_secret)


def generate_ephemeral_ecdh_keypair():
    """
    Generate an ephemeral ECDH key pair (P-256 curve).
    Used in forward-secrecy key exchanges: each session gets a new key pair
    that is discarded after use, so past traffic cannot be decrypted later.

    Returns:
        (private_key, public_key) — both EC key objects
    """
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    return private_key, private_key.public_key()


def ecdh_shared_secret(private_key, peer_public_key) -> bytes:
    """
    Perform ECDH key agreement to produce a shared secret.

    Args:
        private_key:     Our ephemeral EC private key
        peer_public_key: Peer's EC public key

    Returns:
        Raw shared secret bytes (should be passed to derive_session_key)
    """
    from cryptography.hazmat.primitives.asymmetric.ec import ECDH
    shared = private_key.exchange(ECDH(), peer_public_key)
    return shared


# ─────────────────────────────────────────────
# MITM Protection — Certificate Fingerprint Pinning
# ─────────────────────────────────────────────
def get_certificate_fingerprint(cert_pem: bytes) -> str:
    """
    Compute the SHA-256 fingerprint of a PEM certificate.
    Used for certificate pinning: clients store the expected fingerprint
    and reject any certificate with a different fingerprint, even if that
    certificate is signed by a trusted CA — preventing MITM attacks.

    Returns:
        Colon-separated hex fingerprint string (e.g. "AA:BB:CC:...")
    """
    cert    = x509.load_pem_x509_certificate(cert_pem, default_backend())
    digest  = cert.fingerprint(hashes.SHA256())
    return ":".join(f"{b:02X}" for b in digest)


def verify_certificate_pin(cert_pem: bytes, expected_fingerprint: str) -> bool:
    """
    Verify a certificate matches a pinned fingerprint.
    Returns True only if the fingerprint matches exactly.
    """
    actual = get_certificate_fingerprint(cert_pem)
    return hmac.compare_digest(actual.upper(), expected_fingerprint.upper())


# ─────────────────────────────────────────────
# File Hybrid Encryption (large files)
# ─────────────────────────────────────────────
def encrypt_file(public_key: RSAPublicKey, file_data: bytes) -> Dict:
    """
    Hybrid-encrypt arbitrary file data (AES-256-GCM + RSA-OAEP).

    Unlike pure RSA encryption (limited to ~190 bytes for 2048-bit keys),
    hybrid encryption works for files of any size:
      1. Generate a random 256-bit AES session key
      2. Encrypt the file with AES-256-GCM (authenticated encryption)
      3. Encrypt the session key with RSA-OAEP

    The recipient only needs the RSA private key to decrypt.

    Returns:
        dict with encrypted_key, nonce, ciphertext (all base64-encoded)
    """
    session_key = os.urandom(32)   # AES-256
    nonce       = os.urandom(12)   # 96-bit GCM nonce

    aesgcm     = AESGCM(session_key)
    ciphertext = aesgcm.encrypt(nonce, file_data, None)

    encrypted_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return {
        "encrypted_key": base64.b64encode(encrypted_key).decode(),
        "nonce":         base64.b64encode(nonce).decode(),
        "ciphertext":    base64.b64encode(ciphertext).decode(),
        "algorithm":     "AES-256-GCM + RSA-OAEP",
    }


def decrypt_file(private_key: RSAPrivateKey, encrypted_data: Dict) -> bytes:
    """
    Decrypt a hybrid-encrypted file.

    Args:
        private_key:    RSA private key
        encrypted_data: dict returned by encrypt_file()

    Returns:
        Original plaintext bytes
    """
    encrypted_key = base64.b64decode(encrypted_data["encrypted_key"])
    nonce         = base64.b64decode(encrypted_data["nonce"])
    ciphertext    = base64.b64decode(encrypted_data["ciphertext"])

    session_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    aesgcm = AESGCM(session_key)
    return aesgcm.decrypt(nonce, ciphertext, None)
