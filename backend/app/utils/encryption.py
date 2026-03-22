import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import settings


_DEV_KEY = b"\x00" * 32  # Fixed zero key — DEV_MODE only, never use in production


def _get_key() -> bytes:
    """Get the AES-256-GCM encryption key from settings."""
    key_b64 = settings.ENCRYPTION_KEY
    if not key_b64 or key_b64 == "your-32-byte-base64-encoded-key":
        if settings.DEV_MODE:
            return _DEV_KEY
        raise ValueError("ENCRYPTION_KEY is not set")
    return base64.b64decode(key_b64)


def encrypt_token(plaintext: str) -> bytes:
    """Encrypt a GitHub token using AES-256-GCM."""
    key = _get_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    # Prepend nonce to ciphertext for storage
    return nonce + ciphertext


def decrypt_token(encrypted: bytes) -> str:
    """Decrypt a GitHub token using AES-256-GCM."""
    key = _get_key()
    aesgcm = AESGCM(key)
    nonce = encrypted[:12]
    ciphertext = encrypted[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")
