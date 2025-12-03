# tests/test_totp.py
from pathlib import Path
from totp_utils import generate_totp_code, verify_totp_code

def test_totp_roundtrip():
    seed = Path("data/seed.txt").read_text().strip()
    code = generate_totp_code(seed)
    assert verify_totp_code(seed, code, valid_window=1)
