# check_key.py
from cryptography.hazmat.primitives import serialization
import os
path = "student_private.pem"
if not os.path.exists(path):
    print("ERROR: student_private.pem not found in current folder.")
    raise SystemExit(1)

with open(path, "rb") as f:
    data = f.read()

priv = serialization.load_pem_private_key(data, password=None)
# key_size is in bits
key_size_bits = priv.key_size
key_size_bytes = key_size_bits // 8
print("Private key size:", key_size_bits, "bits (", key_size_bytes, "bytes )")
