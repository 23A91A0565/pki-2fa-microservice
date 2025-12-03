# check_cipher_len.py
import base64, pathlib, sys
p = pathlib.Path("encrypted_seed.txt")
print("encrypted_seed.txt exists?", p.exists())
if not p.exists():
    sys.exit(0)
s = p.read_text().strip()
print("Base64 length (chars):", len(s))
try:
    b = base64.b64decode(s)
    print("Ciphertext bytes length:", len(b))
except Exception as e:
    print("Base64 decode error:", e)
