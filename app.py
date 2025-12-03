# app.py
import os
import time
import base64
from pathlib import Path
from flask import Flask, request, jsonify

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Import totp helpers (you should have totp_utils.py already)
from totp_utils import generate_totp_code, verify_totp_code

# --- Configuration ---
PRIVATE_KEY_PATH = "student_private.pem"   # local private key (DO NOT commit)
DATA_DIR = "data"
SEED_FILE = os.path.join(DATA_DIR, "seed.txt")
TOTP_PERIOD = 30

app = Flask(__name__)

def load_seed() -> str:
    """Return the decrypted hex seed from disk or raise FileNotFoundError."""
    if not os.path.exists(SEED_FILE):
        raise FileNotFoundError("Seed not decrypted yet")
    seed = Path(SEED_FILE).read_text().strip()
    if not seed:
        raise ValueError("Seed file is empty")
    return seed


def load_private_key(path: str):
    """Load PEM private key from file."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Private key file not found: {path}")
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def rsa_oaep_decrypt_b64(encrypted_b64: str, private_key) -> bytes:
    """Base64-decode then RSA-OAEP-SHA256 decrypt -> returns plaintext bytes."""
    try:
        ciphertext = base64.b64decode(encrypted_b64)
    except Exception as e:
        raise ValueError(f"base64 decode failed: {e}")

    try:
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return plaintext
    except Exception as e:
        raise ValueError(f"RSA decryption failed: {e}")


@app.route("/decrypt-seed", methods=["POST"])
def decrypt_seed_endpoint():
    """
    POST /decrypt-seed
    Body JSON: { "encrypted_seed": "<base64 string>" }
    - Loads local private key
    - Base64-decodes and RSA-OAEP-SHA256 decrypts
    - Validates decrypted seed is 64-hex
    - Saves to data/seed.txt and returns {"status":"ok"}
    """
    data = request.get_json(silent=True)
    if not data or "encrypted_seed" not in data:
        return jsonify({"error": "Missing field: encrypted_seed"}), 400

    encrypted_b64 = data["encrypted_seed"]

    # load private key
    try:
        priv = load_private_key(PRIVATE_KEY_PATH)
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        return jsonify({"error": f"Failed to load private key: {e}"}), 500

    # decrypt
    try:
        plaintext_bytes = rsa_oaep_decrypt_b64(encrypted_b64, priv)
    except ValueError as e:
        # treat as client error if base64/decrypt failed
        return jsonify({"error": str(e)}), 400

    # decode and validate seed
    try:
        seed_str = plaintext_bytes.decode("utf-8").strip()
    except Exception:
        return jsonify({"error": "Decrypted seed is not valid UTF-8"}), 500

    if len(seed_str) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in seed_str):
        return jsonify({"error": "Invalid seed format; expected 64-character hex string"}), 400

    # ensure data dir exists and write seed
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(SEED_FILE, "w", encoding="utf-8") as f:
        f.write(seed_str.lower() + "\n")

    return jsonify({"status": "ok"}), 200


@app.route("/generate-2fa", methods=["GET"])
def generate_2fa():
    """
    GET /generate-2fa
    Returns current TOTP code and seconds remaining in the period.
    If seed missing -> 500 with error.
    """
    if not os.path.exists(SEED_FILE):
        return jsonify({"error": "Seed not decrypted yet"}), 500

    seed = Path(SEED_FILE).read_text().strip()
    if not seed:
        return jsonify({"error": "Seed file empty"}), 500

    try:
        code = generate_totp_code(seed)
    except Exception as e:
        return jsonify({"error": f"TOTP generation failed: {e}"}), 500

    now = int(time.time())
    seconds_elapsed = now % TOTP_PERIOD
    valid_for = TOTP_PERIOD - seconds_elapsed

    return jsonify({"code": code, "valid_for": valid_for}), 200


@app.route("/verify-2fa", methods=["POST"])
def verify_2fa():
    """
    POST /verify-2fa
    Body: { "code": "123456" }
    Returns {"valid": true/false}
    """
    data = request.get_json(silent=True)
    if not data or "code" not in data:
        return jsonify({"error": "Missing code"}), 400

    code = str(data["code"]).strip()
    if not code:
        return jsonify({"error": "Missing code"}), 400

    # load seed safely
    try:
        seed = load_seed()
    except FileNotFoundError:
        return jsonify({"error": "Seed not decrypted yet"}), 500
    except Exception as e:
        return jsonify({"error": f"Failed to read seed: {e}"}), 500

    # Verify using totp_utils.verify_totp_code (handles pyotp differences)
    try:
        valid = verify_totp_code(seed, code, valid_window=1)
    except Exception as e:
        return jsonify({"error": f"Verification failed: {e}"}), 500

    return jsonify({"valid": bool(valid)}), 200



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
