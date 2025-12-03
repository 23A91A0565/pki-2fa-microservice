# test_totp_run.py
from pathlib import Path
from totp_utils import generate_totp_code, verify_totp_code

seed = Path("data/seed.txt").read_text().strip()
print("Seed prefix:", seed[:16], "...")

code = generate_totp_code(seed)
print("Generated TOTP:", code)

ok = verify_totp_code(seed, code, valid_window=1)
print("Verify result:", ok)
