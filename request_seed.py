# debug_request_seed_fixed.py
import json, sys, os
import requests

STUDENT_ID = "23A91A0565"
REPO_WITH = "https://github.com/23A91A0565/pki-2fa-microservice.git"
REPO_WITHOUT = "https://github.com/23A91A0565/pki-2fa-microservice"

# CORRECTED API URL (copy the exact working one you used earlier)
API_URL = "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws"
PUBKEY_FILE = "student_public.pem"

def read_pub_single(path):
    import os
    if not os.path.exists(path):
        raise FileNotFoundError(f"Public key file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        txt = f.read()
    # Normalize newlines to LF and return the raw PEM (do NOT escape them as \\n)
    return txt.replace("\r\n", "\n").replace("\r", "\n")

def try_post(repo_url):
    try:
        pk = read_pub_single(PUBKEY_FILE)
    except Exception as e:
        print("Failed to read public key:", e)
        return

    payload = {
        "student_id": STUDENT_ID,
        "github_repo_url": repo_url,
        "public_key": pk
    }
    print("\n--- Trying repo_url =", repo_url)
    print("Payload preview (trimmed):")
    p = payload.copy()
    p["public_key"] = p["public_key"][:120] + "..." if len(p["public_key"])>120 else p["public_key"]
    print(json.dumps(p, indent=2))

    try:
        r = requests.post(API_URL, json=payload, timeout=20)
    except requests.exceptions.RequestException as e:
        print("Network error:", repr(e))
        return

    print("HTTP", r.status_code)
    print("Response headers:")
    for k,v in r.headers.items():
        print(k + ":", v)
    print("Response body:")
    # Try to pretty-print JSON if possible
    try:
        js = r.json()
        print(json.dumps(js, indent=2))
    except ValueError:
        print(r.text)

def main():
    try_post(REPO_WITH)
    try_post(REPO_WITHOUT)

if __name__ == "__main__":
    main()
