import base64
import secrets

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def genkey() -> str:
    private = X25519PrivateKey.generate()
    return base64.b64encode(private.private_bytes_raw()).decode()


def genpsk() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode()


def pubkey(private_key: str) -> str:
    raw = base64.b64decode(private_key)
    public = X25519PrivateKey.from_private_bytes(raw).public_key()
    return base64.b64encode(public.public_bytes_raw()).decode()


def generate_keypair() -> tuple[str, str]:
    private = genkey()
    return private, pubkey(private)
