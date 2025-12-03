# try_decrypt_local.py
import base64, pathlib, sys
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

pkey = pathlib.Path("student_private.pem")
if not pkey.exists():
    print("student_private.pem missing"); sys.exit(1)

encf = pathlib.Path("encrypted_seed.txt")
if not encf.exists():
    print("encrypted_seed.txt missing"); sys.exit(1)

priv = serialization.load_pem_private_key(pkey.read_bytes(), password=None)

s = encf.read_text().strip()
try:
    cipher = base64.b64decode(s)
except Exception as e:
    print("Base64 decode error:", e)
    sys.exit(1)

print("Ciphertext bytes:", len(cipher))

try:
    plain = priv.decrypt(
        cipher,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    try:
        print("Decryption success. Plaintext (utf-8):", plain.decode())
    except:
        print("Decryption success. Plaintext (hex):", plain.hex())
except Exception as e:
    print("Decryption failed:", repr(e))
