# Secure File Transfer using Hybrid Cryptography

A single-file Python application (`secure_transfer.py`) that transfers files with
confidentiality, integrity and sender authentication.

| Goal | Mechanism |
|---|---|
| Confidentiality | AES-256-GCM encrypts the file |
| Key exchange | AES key wrapped with the receiver's RSA public key (RSA-OAEP, SHA-256) |
| Integrity | SHA-256 digest of the file, plus the GCM authentication tag |
| Authentication | Sender signs the envelope with RSA-PSS (SHA-256) |

## Requirements

- Python 3.9+
- `pip install cryptography`

## Quick start

```bash
python secure_transfer.py demo    # guided walkthrough with attack simulations
python secure_transfer.py test    # runs the 15 built-in test cases
```

## Usage

**1. Generate key pairs** (once per user; public keys are shared, private keys stay secret)

```bash
python secure_transfer.py keygen alice     # sender
python secure_transfer.py keygen bob       # receiver
```
Keys are written to `keys/<name>_private.pem` and `keys/<name>_public.pem`.
Each party must have the other's *public* key in its `keys/` folder.

**2a. File-to-file mode**

```bash
python secure_transfer.py encrypt report.pdf report.sft --sender alice --receiver bob
python secure_transfer.py decrypt report.sft received/  --receiver bob --sender alice
```

**2b. Network mode (TCP)**

```bash
# Receiver machine
python secure_transfer.py serve received/ --receiver bob --sender alice --port 9000

# Sender machine
python secure_transfer.py send report.pdf --sender alice --receiver bob --host <receiver-ip> --port 9000
```

## How it works

**Sender**
1. Compute SHA-256 of the file.
2. Generate a random AES-256 key and nonce; encrypt the file (AES-GCM).
3. Encrypt the AES key with the receiver's RSA public key.
4. Sign (filename, hash, wrapped key, nonce, ciphertext digest) with the sender's private key.
5. Package everything as a JSON envelope.

**Receiver**
1. Verify the signature (authenticates sender, detects tampering).
2. Decrypt the AES key with its RSA private key.
3. Decrypt the file (GCM tag check).
4. Recompute SHA-256 and compare with the envelope's hash.

If any step fails the file is rejected and nothing is written.

## Envelope format

```json
{
  "version": 1,
  "filename": "report.pdf",
  "sha256": "<hex digest of plaintext>",
  "enc_key": "<base64 RSA-OAEP wrapped AES key>",
  "nonce": "<base64 12-byte GCM nonce>",
  "ciphertext": "<base64 AES-GCM ciphertext + tag>",
  "signature": "<base64 RSA-PSS signature>"
}
```

## Test cases (`python secure_transfer.py test`)

| # | Test | Expected |
|---|---|---|
| 1-3 | Round-trip: text, 5 MB binary, empty file | Identical output |
| 4 | Plaintext visible in ciphertext? | No |
| 5 | Key / nonce reuse across transfers | Always different |
| 6-10 | Tamper with ciphertext, hash, wrapped key, filename, signature | Rejected |
| 11 | Attacker signs as sender | Rejected |
| 12 | Wrong receiver key | Rejected |
| 13 | Malformed envelope | Rejected |
| 14 | Filename `../../etc/passwd` | Saved as `passwd` |
| 15 | Full transfer over TCP | File received and verified |

## Limitations / future work

- Public keys are exchanged manually; a real system would use certificates / a CA.
- No replay protection (could add a signed timestamp or counter).
- Whole file is held in memory; large files would need chunked encryption.
- Private keys are stored unencrypted on disk (could add passphrase protection).
- The TCP channel itself is plain; security comes from the envelope, not TLS.
