#!/usr/bin/env python3
from datetime import datetime, timezone
import os, sys

try:
    from totp_utils import generate_totp_code
except Exception as e:
    print(f"ERROR importing totp_utils: {e}", flush=True)
    sys.exit(1)

SEED_FILE = "/app/data/seed.txt"

def read_seed():
    if not os.path.exists(SEED_FILE):
        raise FileNotFoundError("seed file missing")
    seed = open(SEED_FILE, "r", encoding="utf-8").read().strip()
    if len(seed) != 64:
        raise ValueError("invalid seed length")
    return seed

def main():
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    try:
        seed = read_seed()
        code = generate_totp_code(seed)
        print(f"{ts} - 2FA Code: {code}", flush=True)
    except Exception as e:
        print(f"{ts} - ERROR: {e}", flush=True)

if __name__ == "__main__":
    main()
