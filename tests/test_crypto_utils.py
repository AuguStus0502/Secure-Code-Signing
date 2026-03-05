"""
tests/test_crypto_utils.py — CryptoSign Unit Tests
Run: python -m unittest discover tests/ -v   OR   pytest tests/ -v
"""
import os, sys, time, base64, unittest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from crypto_utils import (
    generate_rsa_keypair, serialize_public_key,
    serialize_private_key_encrypted, load_private_key, get_key_fingerprint,
    generate_certificate, get_certificate_fingerprint, verify_certificate_pin,
    export_pkcs12, import_pkcs12,
    sign_file_data, verify_file_signature,
    encrypt_message, decrypt_message, encrypt_file, decrypt_file,
    create_signed_envelope, verify_signed_envelope,
    generate_ephemeral_ecdh_keypair, ecdh_shared_secret, derive_session_key,
)

class TestKeyGeneration(unittest.TestCase):
    def setUp(self): self.priv, self.pub = generate_rsa_keypair(2048)
    def test_key_size(self): self.assertEqual(self.priv.key_size, 2048)
    def test_4096_key(self): priv,_=generate_rsa_keypair(4096); self.assertEqual(priv.key_size,4096)
    def test_public_pem(self): self.assertTrue(serialize_public_key(self.pub).startswith(b"-----BEGIN PUBLIC KEY-----"))
    def test_encrypted_round_trip(self):
        pem=serialize_private_key_encrypted(self.priv,"pass123")
        self.assertIn(b"ENCRYPTED",pem)
        self.assertEqual(load_private_key(pem,"pass123").key_size, 2048)
    def test_wrong_password_raises(self):
        pem=serialize_private_key_encrypted(self.priv,"correct")
        with self.assertRaises(Exception): load_private_key(pem,"wrong")
    def test_fingerprint_format(self):
        fp=get_key_fingerprint(self.pub); parts=fp.split(":")
        self.assertEqual(len(parts),20); self.assertTrue(all(len(p)==2 for p in parts))
    def test_unique_fingerprints(self):
        _,p1=generate_rsa_keypair(2048); _,p2=generate_rsa_keypair(2048)
        self.assertNotEqual(get_key_fingerprint(p1),get_key_fingerprint(p2))

class TestPKCS12(unittest.TestCase):
    def setUp(self):
        self.priv,self.pub=generate_rsa_keypair(2048)
        self.cert=generate_certificate(self.priv,self.pub,"testuser")
    def test_export_bytes(self):
        p12=export_pkcs12(self.priv,self.cert,"pw","My Key")
        self.assertIsInstance(p12,bytes); self.assertGreater(len(p12),0)
    def test_round_trip(self):
        p12=export_pkcs12(self.priv,self.cert,"pw!")
        loaded_priv,_,_=import_pkcs12(p12,"pw!")
        sig=sign_file_data(loaded_priv,b"test")
        self.assertTrue(verify_file_signature(loaded_priv.public_key(),b"test",sig))
    def test_wrong_password_raises(self):
        p12=export_pkcs12(self.priv,self.cert,"right")
        with self.assertRaises(Exception): import_pkcs12(p12,"wrong")

class TestDigitalSignatures(unittest.TestCase):
    def setUp(self): self.priv,self.pub=generate_rsa_keypair(2048)
    def test_sign_verify(self):
        data=b"contract"; sig=sign_file_data(self.priv,data)
        self.assertTrue(verify_file_signature(self.pub,data,sig))
    def test_tampered_data_fails(self):
        sig=sign_file_data(self.priv,b"original")
        self.assertFalse(verify_file_signature(self.pub,b"tampered",sig))
    def test_wrong_key_fails(self):
        _,pub2=generate_rsa_keypair(2048)
        sig=sign_file_data(self.priv,b"data")
        self.assertFalse(verify_file_signature(pub2,b"data",sig))
    def test_corrupted_signature_fails(self):
        sig=bytearray(sign_file_data(self.priv,b"data")); sig[10]^=0xFF
        self.assertFalse(verify_file_signature(self.pub,b"data",bytes(sig)))
    def test_large_file(self):
        data=os.urandom(1024*1024); sig=sign_file_data(self.priv,data)
        self.assertTrue(verify_file_signature(self.pub,data,sig))

class TestHybridEncryption(unittest.TestCase):
    def setUp(self): self.priv,self.pub=generate_rsa_keypair(2048)
    def test_message_round_trip(self):
        enc=encrypt_message(self.pub,b"secret")
        self.assertEqual(decrypt_message(self.priv,enc),b"secret")
    def test_required_fields(self):
        enc=encrypt_message(self.pub,b"x")
        self.assertTrue({"encrypted_key","nonce","ciphertext"}.issubset(enc.keys()))
    def test_wrong_key_cannot_decrypt(self):
        priv2,_=generate_rsa_keypair(2048)
        enc=encrypt_message(self.pub,b"secret")
        with self.assertRaises(Exception): decrypt_message(priv2,enc)
    def test_tampered_ciphertext_fails(self):
        enc=encrypt_message(self.pub,b"tamper me")
        raw=bytearray(base64.b64decode(enc["ciphertext"])); raw[5]^=0xFF
        enc["ciphertext"]=base64.b64encode(bytes(raw)).decode()
        with self.assertRaises(Exception): decrypt_message(self.priv,enc)
    def test_each_encryption_unique(self):
        e1=encrypt_message(self.pub,b"same"); e2=encrypt_message(self.pub,b"same")
        self.assertNotEqual(e1["ciphertext"],e2["ciphertext"])
    def test_file_round_trip(self):
        data=os.urandom(512*1024)
        self.assertEqual(decrypt_file(self.priv,encrypt_file(self.pub,data)),data)
    def test_file_metadata(self):
        self.assertEqual(encrypt_file(self.pub,b"d").get("algorithm"),"AES-256-GCM + RSA-OAEP")
    def test_hybrid_handles_large_data(self):
        """Pure RSA cannot encrypt >190 bytes; hybrid has no size limit."""
        large=os.urandom(10*1024)
        self.assertEqual(decrypt_file(self.priv,encrypt_file(self.pub,large)),large)

class TestCertificates(unittest.TestCase):
    def setUp(self):
        self.priv,self.pub=generate_rsa_keypair(2048)
        self.cert=generate_certificate(self.priv,self.pub,"testuser")
    def test_pem_format(self): self.assertTrue(self.cert.startswith(b"-----BEGIN CERTIFICATE-----"))
    def test_fingerprint_string(self): fp=get_certificate_fingerprint(self.cert); self.assertIn(":",fp)
    def test_pinning_valid(self):
        fp=get_certificate_fingerprint(self.cert)
        self.assertTrue(verify_certificate_pin(self.cert,fp))
    def test_pinning_rejects_mitm_cert(self):
        """MITM attack: attacker substitutes their own certificate — must be rejected."""
        priv2,pub2=generate_rsa_keypair(2048)
        cert2=generate_certificate(priv2,pub2,"attacker")
        fp_orig=get_certificate_fingerprint(self.cert)
        self.assertFalse(verify_certificate_pin(cert2,fp_orig))

class TestReplayAttackPrevention(unittest.TestCase):
    def setUp(self): self.priv,self.pub=generate_rsa_keypair(2048)
    def test_valid_envelope(self):
        env=create_signed_envelope(self.priv,b"payload",max_age_seconds=60)
        ok,reason,decoded=verify_signed_envelope(self.pub,env,set())
        self.assertTrue(ok,msg=reason); self.assertEqual(decoded,b"payload")
    def test_replay_blocked(self):
        """Attack: re-send a captured valid envelope (e.g. duplicate payment)."""
        env=create_signed_envelope(self.priv,b"pay $100",max_age_seconds=60)
        seen=set()
        ok1,_,_=verify_signed_envelope(self.pub,env,seen); self.assertTrue(ok1)
        ok2,reason2,_=verify_signed_envelope(self.pub,env,seen)
        self.assertFalse(ok2)
        self.assertTrue("replay" in reason2.lower() or "nonce" in reason2.lower())
    def test_expired_envelope_rejected(self):
        env=create_signed_envelope(self.priv,b"stale",max_age_seconds=0)
        time.sleep(1)
        ok,reason,_=verify_signed_envelope(self.pub,env,set())
        self.assertFalse(ok); self.assertIn("expired",reason.lower())
    def test_tampered_payload_rejected(self):
        """Attack: MITM modifies payload after signing."""
        env=create_signed_envelope(self.priv,b"original",max_age_seconds=60)
        env["payload_b64"]=base64.b64encode(b"modified").decode()
        ok,reason,_=verify_signed_envelope(self.pub,env,set())
        self.assertFalse(ok)
    def test_wrong_signing_key_rejected(self):
        priv2,_=generate_rsa_keypair(2048)
        env=create_signed_envelope(priv2,b"impersonation",max_age_seconds=60)
        ok,_,_=verify_signed_envelope(self.pub,env,set())
        self.assertFalse(ok)

class TestForwardSecrecy(unittest.TestCase):
    def test_same_shared_secret(self):
        priv_a,pub_a=generate_ephemeral_ecdh_keypair()
        priv_b,pub_b=generate_ephemeral_ecdh_keypair()
        self.assertEqual(ecdh_shared_secret(priv_a,pub_b),ecdh_shared_secret(priv_b,pub_a))
    def test_session_key_length(self):
        priv_a,pub_a=generate_ephemeral_ecdh_keypair()
        priv_b,pub_b=generate_ephemeral_ecdh_keypair()
        key=derive_session_key(ecdh_shared_secret(priv_a,pub_b),salt=os.urandom(32))
        self.assertEqual(len(key),32)
    def test_different_sessions_different_keys(self):
        pa1,pb1_pub=generate_ephemeral_ecdh_keypair(); pb1,pa1_pub=generate_ephemeral_ecdh_keypair()
        pa2,pb2_pub=generate_ephemeral_ecdh_keypair(); pb2,pa2_pub=generate_ephemeral_ecdh_keypair()
        k1=derive_session_key(ecdh_shared_secret(pa1,pa1_pub))
        k2=derive_session_key(ecdh_shared_secret(pa2,pa2_pub))
        self.assertNotEqual(k1,k2)
    def test_long_term_key_does_not_expose_past_session(self):
        """Core forward-secrecy guarantee: past sessions remain protected after key compromise."""
        priv_a,pub_a=generate_ephemeral_ecdh_keypair()
        priv_b,pub_b=generate_ephemeral_ecdh_keypair()
        past_key=derive_session_key(ecdh_shared_secret(priv_a,pub_b),salt=b"s1")
        nonce=os.urandom(12)
        ct=AESGCM(past_key).encrypt(nonce,b"secret past message",None)
        lt_priv,_=generate_rsa_keypair(2048)
        lt_bytes=lt_priv.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
        self.assertNotIn(past_key,lt_bytes)  # long-term key can't recover past session key
        self.assertGreater(len(ct),0)

class TestMultiUserScenario(unittest.TestCase):
    def test_three_users_sign_independently(self):
        users={n:dict(zip(["priv","pub"],generate_rsa_keypair(2048))) for n in ["alice","bob","carol"]}
        doc=b"Board resolution"
        sigs={n:sign_file_data(k["priv"],doc) for n,k in users.items()}
        for n,k in users.items():
            self.assertTrue(verify_file_signature(k["pub"],doc,sigs[n]),f"{n} sig should be valid")
        self.assertFalse(verify_file_signature(users["bob"]["pub"],doc,sigs["alice"]))
    def test_forged_signature_rejected(self):
        _,pub_victim=generate_rsa_keypair(2048)
        priv_att,_=generate_rsa_keypair(2048)
        self.assertFalse(verify_file_signature(pub_victim,b"data",sign_file_data(priv_att,b"data")))
    def test_document_tamper_detected(self):
        priv,pub=generate_rsa_keypair(2048)
        sig=sign_file_data(priv,b"Pay $1000")
        self.assertTrue(verify_file_signature(pub,b"Pay $1000",sig))
        self.assertFalse(verify_file_signature(pub,b"Pay $9999",sig))

if __name__=="__main__": unittest.main(verbosity=2)
