#  commit_proof.py
import subprocess
import base64
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# --- Implementation functions ---

def sign_message(message: str, private_key) -> bytes:
    """
    Sign a message using RSA-PSS with SHA-256.

    - message: ASCII/UTF-8 string (e.g. commit hash)
    - private_key: RSA private key object (from cryptography)
    Returns signature bytes.
    """
    msg_bytes = message.encode("utf-8")            # CRITICAL: sign ASCII/UTF-8 bytes
    signature = private_key.sign(
        msg_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def encrypt_with_public_key(data: bytes, public_key) -> bytes:
    """
    Encrypt data using RSA/OAEP with SHA-256.
    - data: bytes to encrypt
    - public_key: RSA public key object
    Returns ciphertext bytes.
    """
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ),
    )
    return ciphertext

# --- Helpers to load keys ---

def load_private_key(path: str):
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Private key file not found: {path}")
    data = p.read_bytes()
    return serialization.load_pem_private_key(data, password=None)

def load_public_key(path: str):
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Public key file not found: {path}")
    data = p.read_bytes()
    return serialization.load_pem_public_key(data)

# --- Main flow ---

def get_last_commit_hash() -> str:
    # Use git to get the latest commit full hash (40 hex chars)
    out = subprocess.run(["git", "log", "-1", "--format=%H"], capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"git command failed: {out.stderr.strip()}")
    commit_hash = out.stdout.strip()
    if len(commit_hash) != 40:
        raise ValueError(f"unexpected commit hash: {commit_hash!r}")
    return commit_hash

def main():
    # paths (adjust if needed)
    priv_path = "student_private.pem"
    instr_pub_path = "instructor_public.pem"

    # 1. Ensure git has latest commit and commit exists
    commit_hash = get_last_commit_hash()
    print("Commit Hash:", commit_hash)

    # 2. Load student private key
    priv = load_private_key(priv_path)

    # 3. Sign commit hash (ASCII bytes)
    signature = sign_message(commit_hash, priv)
    print("Signature length (bytes):", len(signature))

    # 4. Load instructor public key
    instr_pub = load_public_key(instr_pub_path)

    # 5. Encrypt the signature with instructor public key (RSA OAEP SHA-256)
    ciphertext = encrypt_with_public_key(signature, instr_pub)
    print("Encrypted signature length (bytes):", len(ciphertext))

    # 6. Base64 encode ciphertext and print single-line string
    b64 = base64.b64encode(ciphertext).decode("ascii")
    print("\n--- OUTPUT (base64 encrypted signature) ---")
    print(b64)
    print("\n--- DONE ---")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("ERROR:", str(e), file=sys.stderr)
        sys.exit(1)
