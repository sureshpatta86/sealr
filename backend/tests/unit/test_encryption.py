"""Tests for AES-256-GCM encryption utilities."""

import pytest
from app.utils.encryption import encrypt_token, decrypt_token


class TestEncryption:
    def test_encrypt_decrypt_roundtrip(self):
        original = "ghp_test123456789abcdefghijklmnopqrstuvwx"
        encrypted = encrypt_token(original)
        decrypted = decrypt_token(encrypted)
        assert decrypted == original

    def test_encrypted_differs_from_original(self):
        original = "ghp_secret_token"
        encrypted = encrypt_token(original)
        assert encrypted != original

    def test_different_encryptions_differ(self):
        """AES-GCM uses random nonce, so encryptions should differ."""
        original = "ghp_test_token"
        enc1 = encrypt_token(original)
        enc2 = encrypt_token(original)
        assert enc1 != enc2  # Different nonces

    def test_empty_string(self):
        encrypted = encrypt_token("")
        decrypted = decrypt_token(encrypted)
        assert decrypted == ""

    def test_unicode(self):
        original = "token_with_unicode_日本語"
        encrypted = encrypt_token(original)
        decrypted = decrypt_token(encrypted)
        assert decrypted == original
