# totp_utils.py
import base64
import pyotp

HEX_CHARS = set("0123456789abcdefABCDEF")

def _hex_to_base32(hex_seed: str) -> str:
    """
    Convert a 64-character hex string to a Base32 secret string suitable for TOTP.
    - Accepts uppercase or lowercase hex.
    - Returns an uppercase base32 string without '=' padding (works with pyotp).
    """
    # basic validation
    if not isinstance(hex_seed, str):
        raise TypeError("hex_seed must be a string")
    hex_seed = hex_seed.strip()
    if len(hex_seed) != 64:
        raise ValueError(f"hex_seed length is {len(hex_seed)}; expected 64")
    if any(ch not in HEX_CHARS for ch in hex_seed):
        raise ValueError("hex_seed contains non-hex characters")

    # bytes from hex
    seed_bytes = bytes.fromhex(hex_seed)
    # base32 encode -> returns bytes with padding "="
    b32 = base64.b32encode(seed_bytes).decode("ascii")
    # strip padding and uppercase (pyotp accepts uppercase)
    return b32.rstrip("=")

def generate_totp_code(hex_seed: str) -> str:
    """
    Generate current TOTP code (6 digits) from a 64-char hex seed.
    Uses SHA-1, 30s period, 6 digits (pyotp defaults).
    """
    secret_b32 = _hex_to_base32(hex_seed)
    totp = pyotp.TOTP(secret_b32, digits=6, interval=30, digest="sha1")
    return totp.now()  # returns a zero-padded string like "012345"

def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify a TOTP code with time-window tolerance.
    - valid_window=1 means accept codes for (current ± 1 period), i.e. ±30s.
    Returns True if valid, False otherwise.
    """
    secret_b32 = _hex_to_base32(hex_seed)
    totp = pyotp.TOTP(secret_b32, digits=6, interval=30, digest="sha1")
    # pyotp.TOTP.verify accepts window parameter
    # When window=1, verify checks codes in [-1, 0, +1] steps
    return totp.verify(code, valid_window=valid_window)
