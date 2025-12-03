from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_keypair(key_size: int = 4096):
    """
    Generate RSA key pair (4096-bit, exponent 65537)
    Returns (private_pem_bytes, public_pem_bytes)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem

if __name__ == "__main__":
    private_pem, public_pem = generate_rsa_keypair()
    with open("student_private.pem", "wb") as f:
        f.write(private_pem)
    with open("student_public.pem", "wb") as f:
        f.write(public_pem)
    print("Generated student_private.pem and student_public.pem")
