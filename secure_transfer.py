"""
Secure File Transfer using Hybrid Cryptography
----------------------------------------------
Confidentiality : AES-256-GCM encrypts the file (symmetric, fast)
Key exchange    : RSA-OAEP (SHA-256) wraps the AES key for the receiver
Integrity       : SHA-256 digest of the plaintext + GCM authentication tag
Authentication  : RSA-PSS digital signature by the sender

Usage:
  python secure_transfer.py keygen alice
  python secure_transfer.py keygen bob
  python secure_transfer.py encrypt  file.txt out.sft  --sender alice --receiver bob
  python secure_transfer.py decrypt  out.sft  restored/ --receiver bob --sender alice
  python secure_transfer.py serve    restored/ --receiver bob --sender alice --port 9000
  python secure_transfer.py send     file.txt  --sender alice --receiver bob --port 9000
  python secure_transfer.py demo      # full walkthrough incl. attack simulations
  python secure_transfer.py test      # run the 15 built-in test cases
"""
import argparse
import base64
import hashlib
import json
import os
import shutil
import socket
import struct
import tempfile
import threading
import time
import unittest

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_DIR = "keys"
MAX_ENVELOPE = 512 * 1024 * 1024  # 512 MB safety cap


class SecurityError(Exception):
    """Raised when authentication, integrity or decryption fails."""


# ---------------------------------------------------------------- keys
def generate_keypair(name, key_dir=KEY_DIR, bits=3072):
    os.makedirs(key_dir, exist_ok=True)
    private = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    with open(os.path.join(key_dir, f"{name}_private.pem"), "wb") as f:
        f.write(private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
    with open(os.path.join(key_dir, f"{name}_public.pem"), "wb") as f:
        f.write(private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))


def load_private(name, key_dir=KEY_DIR):
    with open(os.path.join(key_dir, f"{name}_private.pem"), "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public(name, key_dir=KEY_DIR):
    with open(os.path.join(key_dir, f"{name}_public.pem"), "rb") as f:
        return serialization.load_pem_public_key(f.read())


# ------------------------------------------------------------ helpers
def _b64(b):
    return base64.b64encode(b).decode()


def _unb64(s):
    return base64.b64decode(s.encode())


def _signed_bytes(filename, sha256_hex, enc_key, nonce, ciphertext):
    """Canonical byte string covered by the digital signature."""
    parts = [filename.encode(), sha256_hex.encode(), enc_key, nonce,
             hashlib.sha256(ciphertext).digest()]
    return b"|".join(_b64(p).encode() for p in parts)


_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                   salt_length=padding.PSS.MAX_LENGTH)
_OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)


# ------------------------------------------------------------- sender
def encrypt_file(data: bytes, filename: str, sender_private, receiver_public) -> bytes:
    """Return a serialized envelope (JSON bytes) for `data`."""
    filename = os.path.basename(filename)
    sha256_hex = hashlib.sha256(data).hexdigest()           # integrity

    aes_key = AESGCM.generate_key(bit_length=256)           # session key
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, data, filename.encode())

    enc_key = receiver_public.encrypt(aes_key, _OAEP)       # key exchange

    signature = sender_private.sign(                        # authentication
        _signed_bytes(filename, sha256_hex, enc_key, nonce, ciphertext),
        _PSS, hashes.SHA256())

    envelope = {
        "version": 1,
        "filename": filename,
        "sha256": sha256_hex,
        "enc_key": _b64(enc_key),
        "nonce": _b64(nonce),
        "ciphertext": _b64(ciphertext),
        "signature": _b64(signature),
    }
    return json.dumps(envelope).encode()


# ----------------------------------------------------------- receiver
def decrypt_file(envelope_bytes: bytes, receiver_private, sender_public):
    """Verify + decrypt an envelope. Returns (filename, plaintext)."""
    try:
        env = json.loads(envelope_bytes)
        filename = os.path.basename(env["filename"])
        sha256_hex = env["sha256"]
        enc_key = _unb64(env["enc_key"])
        nonce = _unb64(env["nonce"])
        ciphertext = _unb64(env["ciphertext"])
        signature = _unb64(env["signature"])
    except (ValueError, KeyError, TypeError) as e:
        raise SecurityError(f"Malformed envelope: {e}")

    # 1. Authenticate the sender (before touching anything else)
    try:
        sender_public.verify(
            signature,
            _signed_bytes(filename, sha256_hex, enc_key, nonce, ciphertext),
            _PSS, hashes.SHA256())
    except InvalidSignature:
        raise SecurityError("Signature verification FAILED: sender not authentic "
                            "or message tampered.")

    # 2. Unwrap the AES key with our RSA private key
    try:
        aes_key = receiver_private.decrypt(enc_key, _OAEP)
    except ValueError:
        raise SecurityError("AES key could not be decrypted (wrong receiver key?).")

    # 3. Decrypt (GCM also authenticates the ciphertext)
    try:
        plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, filename.encode())
    except InvalidTag:
        raise SecurityError("AES-GCM authentication failed: ciphertext corrupted.")

    # 4. Independent SHA-256 integrity check
    if hashlib.sha256(plaintext).hexdigest() != sha256_hex:
        raise SecurityError("SHA-256 mismatch: file integrity check FAILED.")

    return filename, plaintext


# ------------------------------------------------------------ network
def _send_msg(sock, payload: bytes):
    sock.sendall(struct.pack(">Q", len(payload)) + payload)


def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(65536, n - len(buf)))
        if not chunk:
            raise ConnectionError("Connection closed early")
        buf.extend(chunk)
    return bytes(buf)


def _recv_msg(sock):
    (length,) = struct.unpack(">Q", _recv_exact(sock, 8))
    if length > MAX_ENVELOPE:
        raise SecurityError("Envelope too large")
    return _recv_exact(sock, length)


def send_file(path, host, port, sender, receiver, key_dir=KEY_DIR):
    with open(path, "rb") as f:
        data = f.read()
    env = encrypt_file(data, path, load_private(sender, key_dir),
                       load_public(receiver, key_dir))
    with socket.create_connection((host, port)) as s:
        _send_msg(s, env)
        reply = _recv_msg(s).decode()
    print("Receiver replied:", reply)


def serve(out_dir, port, receiver, sender, key_dir=KEY_DIR, host="0.0.0.0", once=False):
    os.makedirs(out_dir, exist_ok=True)
    priv, pub = load_private(receiver, key_dir), load_public(sender, key_dir)
    with socket.socket() as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(1)
        print(f"Listening on {host}:{port} ...")
        while True:
            conn, addr = srv.accept()
            with conn:
                try:
                    name, data = decrypt_file(_recv_msg(conn), priv, pub)
                    with open(os.path.join(out_dir, name), "wb") as f:
                        f.write(data)
                    print(f"[OK] {addr[0]}: saved {name} ({len(data)} bytes), "
                          f"signature + SHA-256 verified")
                    _send_msg(conn, b"OK: file received and verified")
                except SecurityError as e:
                    print(f"[REJECTED] {addr[0]}: {e}")
                    _send_msg(conn, f"REJECTED: {e}".encode())
            if once:
                break



# -------------------------------------------------------------- tests
class TestHybridTransfer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        for n in ("alice", "bob", "mallory"):
            generate_keypair(n, cls.dir, bits=2048)  # 2048 = faster tests
        cls.alice_priv, cls.alice_pub = load_private("alice", cls.dir), load_public("alice", cls.dir)
        cls.bob_priv, cls.bob_pub = load_private("bob", cls.dir), load_public("bob", cls.dir)
        cls.mal_priv, cls.mal_pub = load_private("mallory", cls.dir), load_public("mallory", cls.dir)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir)

    def _env(self, data=b"top secret", name="a.txt"):
        return encrypt_file(data, name, self.alice_priv, self.bob_pub)

    def _tamper(self, env_bytes, field, new_value=None):
        env = json.loads(env_bytes)
        if new_value is None:  # flip one bit of a base64 field
            raw = bytearray(_unb64(env[field])); raw[0] ^= 1
            env[field] = _b64(bytes(raw))
        else:
            env[field] = new_value
        return json.dumps(env).encode()

    def _rejects(self, env, priv=None, pub=None):
        with self.assertRaises(SecurityError) as cm:
            decrypt_file(env, priv or self.bob_priv, pub or self.alice_pub)
        return str(cm.exception)

    def test_01_roundtrip_text(self):
        self.assertEqual(decrypt_file(self._env(), self.bob_priv, self.alice_pub),
                         ("a.txt", b"top secret"))

    def test_02_roundtrip_binary_5mb(self):
        data = os.urandom(5 * 1024 * 1024)
        self.assertEqual(decrypt_file(self._env(data, "big.bin"), self.bob_priv, self.alice_pub)[1], data)

    def test_03_empty_file(self):
        self.assertEqual(decrypt_file(self._env(b"", "e"), self.bob_priv, self.alice_pub)[1], b"")

    def test_04_ciphertext_hides_plaintext(self):
        env = json.loads(self._env(b"PLAINTEXT-MARKER"))
        self.assertNotIn(b"PLAINTEXT-MARKER", _unb64(env["ciphertext"]))

    def test_05_unique_key_and_nonce_per_transfer(self):
        a, b = json.loads(self._env()), json.loads(self._env())
        for k in ("enc_key", "nonce", "ciphertext"):
            self.assertNotEqual(a[k], b[k])

    def test_06_tampered_ciphertext_rejected(self):
        self._rejects(self._tamper(self._env(), "ciphertext"))

    def test_07_tampered_hash_rejected(self):
        self._rejects(self._tamper(self._env(), "sha256", "0" * 64))

    def test_08_tampered_wrapped_key_rejected(self):
        self._rejects(self._tamper(self._env(), "enc_key"))

    def test_09_tampered_filename_rejected(self):
        self._rejects(self._tamper(self._env(), "filename", "evil.sh"))

    def test_10_tampered_signature_rejected(self):
        self._rejects(self._tamper(self._env(), "signature"))

    def test_11_impersonation_rejected(self):
        forged = encrypt_file(b"x", "a.txt", self.mal_priv, self.bob_pub)
        self.assertIn("Signature", self._rejects(forged))

    def test_12_wrong_receiver_cannot_decrypt(self):
        self._rejects(self._env(), priv=self.mal_priv)

    def test_13_malformed_envelope_rejected(self):
        for bad in (b"not json", b"{}", b'{"filename": 1}'):
            self._rejects(bad)

    def test_14_path_traversal_filename_sanitised(self):
        env = encrypt_file(b"x", "../../etc/passwd", self.alice_priv, self.bob_pub)
        self.assertEqual(decrypt_file(env, self.bob_priv, self.alice_pub)[0], "passwd")

    def test_15_network_transfer(self):
        src, out = os.path.join(self.dir, "hello.txt"), os.path.join(self.dir, "recv")
        with open(src, "wb") as f:
            f.write(b"hello over the wire")
        t = threading.Thread(target=serve, kwargs=dict(
            out_dir=out, port=9555, receiver="bob", sender="alice",
            key_dir=self.dir, host="127.0.0.1", once=True), daemon=True)
        t.start(); time.sleep(0.5)
        send_file(src, "127.0.0.1", 9555, "alice", "bob", self.dir)
        t.join(5)
        with open(os.path.join(out, "hello.txt"), "rb") as f:
            self.assertEqual(f.read(), b"hello over the wire")


def run_tests():
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestHybridTransfer)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)


# --------------------------------------------------------------- demo
def run_demo():
    d = tempfile.mkdtemp()
    try:
        print("1. Generating RSA key pairs for Alice (sender), Bob (receiver), Mallory (attacker)")
        for n in ("alice", "bob", "mallory"):
            generate_keypair(n, d, bits=2048)
        a_priv, a_pub = load_private("alice", d), load_public("alice", d)
        b_priv, b_pub = load_private("bob", d), load_public("bob", d)
        m_priv = load_private("mallory", d)

        data = b"Confidential report: Q3 results"
        print(f"2. Alice encrypts + signs a {len(data)}-byte file for Bob")
        env = encrypt_file(data, "report.txt", a_priv, b_pub)
        e = json.loads(env)
        print("   SHA-256     :", e["sha256"])
        print("   Wrapped key :", e["enc_key"][:40] + "...")
        print("   Ciphertext  :", e["ciphertext"][:40] + "...")

        name, out = decrypt_file(env, b_priv, a_pub)
        print(f"3. Bob verifies signature, decrypts, checks hash -> {name}: {out!r}  [OK]")

        print("4. Attack simulations (all should be REJECTED):")
        t = json.loads(env); t["ciphertext"] = _b64(b"\x00" + _unb64(t["ciphertext"])[1:])
        attacks = {
            "Tampered ciphertext": json.dumps(t).encode(),
            "Mallory impersonates Alice": encrypt_file(data, "report.txt", m_priv, b_pub),
        }
        for label, evil in attacks.items():
            try:
                decrypt_file(evil, b_priv, a_pub)
                print(f"   {label}: ACCEPTED (BUG!)")
            except SecurityError as ex:
                print(f"   {label}: REJECTED -> {ex}")
    finally:
        shutil.rmtree(d)


# ---------------------------------------------------------------- CLI
def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen"); k.add_argument("name")

    e = sub.add_parser("encrypt"); e.add_argument("infile"); e.add_argument("outfile")
    e.add_argument("--sender", required=True); e.add_argument("--receiver", required=True)

    d = sub.add_parser("decrypt"); d.add_argument("infile"); d.add_argument("outdir")
    d.add_argument("--receiver", required=True); d.add_argument("--sender", required=True)

    sv = sub.add_parser("serve"); sv.add_argument("outdir")
    sv.add_argument("--receiver", required=True); sv.add_argument("--sender", required=True)
    sv.add_argument("--port", type=int, default=9000)

    sn = sub.add_parser("send"); sn.add_argument("infile")
    sn.add_argument("--sender", required=True); sn.add_argument("--receiver", required=True)
    sn.add_argument("--host", default="127.0.0.1"); sn.add_argument("--port", type=int, default=9000)

    sub.add_parser("demo", help="run a guided demo with attack simulations")
    sub.add_parser("test", help="run the built-in test cases")

    a = p.parse_args()
    if a.cmd == "demo":
        run_demo()
    elif a.cmd == "test":
        run_tests()
    elif a.cmd == "keygen":
        generate_keypair(a.name)
        print(f"Keys written to {KEY_DIR}/{a.name}_(private|public).pem")
    elif a.cmd == "encrypt":
        with open(a.infile, "rb") as f:
            env = encrypt_file(f.read(), a.infile, load_private(a.sender),
                               load_public(a.receiver))
        with open(a.outfile, "wb") as f:
            f.write(env)
        print("Encrypted + signed ->", a.outfile)
    elif a.cmd == "decrypt":
        with open(a.infile, "rb") as f:
            try:
                name, data = decrypt_file(f.read(), load_private(a.receiver),
                                          load_public(a.sender))
            except SecurityError as ex:
                print("REJECTED:", ex); raise SystemExit(1)
        os.makedirs(a.outdir, exist_ok=True)
        with open(os.path.join(a.outdir, name), "wb") as f:
            f.write(data)
        print(f"Verified + decrypted -> {a.outdir}/{name}")
    elif a.cmd == "serve":
        serve(a.outdir, a.port, a.receiver, a.sender)
    elif a.cmd == "send":
        send_file(a.infile, a.host, a.port, a.sender, a.receiver)


if __name__ == "__main__":
    main()
