# decrypt_seed.py
import base64, os, sys
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

PRIVATE_KEY_FILE = "student_private.pem"
ENCRYPTED_SEED_FILE = "encrypted_seed.txt"
OUTPUT_DIR = "data"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "seed.txt")
HEX_CHARS = set("0123456789abcdefABCDEF")

def load_private_key(path: str, password: bytes | None = None):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Private key file not found: {path}")
    data = open(path, "rb").read()
    return serialization.load_pem_private_key(data, password=password)

def decrypt_seed_b64(encrypted_seed_b64: str, private_key) -> str:
    try:
        ciphertext = base64.b64decode(encrypted_seed_b64)
    except Exception as e:
        raise RuntimeError(f"Base64 decode failed: {e}")

    try:
        plaintext_bytes = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            )
        )
    except Exception as e:
        raise RuntimeError(f"RSA decryption failed (wrong key or ciphertext?): {e}")

    try:
        plaintext_str = plaintext_bytes.decode("utf-8")
    except Exception:
        raise RuntimeError("Decrypted plaintext is not UTF-8. Decryption returned bytes: " + plaintext_bytes.hex())

    seed = plaintext_str.strip()
    if len(seed) != 64:
        raise RuntimeError(f"Invalid seed length: {len(seed)} (expected 64). Value: {seed!r}")
    if not all(ch in HEX_CHARS for ch in seed):
        raise RuntimeError("Decrypted seed contains non-hex characters. Expected 64 hex chars 0-9a-f.")
    return seed.lower()

def main():
    if not os.path.exists(ENCRYPTED_SEED_FILE):
        print(f"Error: {ENCRYPTED_SEED_FILE} not found.")
        sys.exit(1)
    if not os.path.exists(PRIVATE_KEY_FILE):
        print(f"Error: {PRIVATE_KEY_FILE} not found.")
        sys.exit(1)

    enc_b64 = open(ENCRYPTED_SEED_FILE, "r", encoding="utf-8").read().strip()
    if not enc_b64:
        print("Error: encrypted_seed.txt is empty.")
        sys.exit(1)

    try:
        priv = load_private_key(PRIVATE_KEY_FILE, password=None)
    except Exception as e:
        print("Failed to load private key:", e)
        sys.exit(1)

    try:
        seed_hex = decrypt_seed_b64(enc_b64, priv)
    except Exception as e:
        print("Decryption/validation error:", e)
        sys.exit(1)

    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(seed_hex + "\n")

    print("SUCCESS: decrypted seed written to", OUTPUT_FILE)
    print("Seed (first 16 chars):", seed_hex[:16], "... (length:", len(seed_hex), ")")

if __name__ == "__main__":
    main()
