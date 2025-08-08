# SPDX-License-Identifier: Prosperity-3.0.0
# © 2025 ã — see LICENSE.md for terms.

"""
Configuration Loader - Encryption Manager

Handles AES256 encryption and decryption of obfuscated configuration values.
"""

import base64
import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from typing import Any


class EncryptionManager:
    """Manages AES256 encryption for obfuscated configuration values."""

    def __init__(self) -> None:
        # Generate AES256 key for obfuscation
        self._encryption_key = secrets.token_bytes(32)  # 256 bits / 8 = 32 bytes

    def obfuscate(self, value: Any) -> str:
        """Encrypt and encode a value for obfuscation."""
        if not isinstance(value, str):
            value = str(value)

        # Convert to bytes
        plaintext = value.encode("utf-8")

        # Generate random IV
        iv = secrets.token_bytes(16)  # AES block size is 16 bytes

        # Pad the plaintext
        padder = padding.PKCS7(128).padder()  # AES block size is 128 bits
        padded_data = padder.update(plaintext)
        padded_data += padder.finalize()

        # Encrypt
        cipher = Cipher(
            algorithms.AES(self._encryption_key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Combine IV and ciphertext, then base64 encode
        encrypted_data = iv + ciphertext
        encoded_data = base64.b64encode(encrypted_data).decode("ascii")

        return f"obfuscated:{encoded_data}"

    def reveal(self, obfuscated_value: str) -> str:
        """Decrypt an obfuscated value."""
        if not isinstance(obfuscated_value, str):
            raise ValueError("Obfuscated value must be a string")

        if not obfuscated_value.startswith("obfuscated:"):
            raise ValueError("Value is not obfuscated (missing 'obfuscated:' prefix)")

        # Remove prefix
        encoded_data = obfuscated_value[11:]  # len("obfuscated:") = 11

        try:
            # Base64 decode
            encrypted_data = base64.b64decode(encoded_data)
        except Exception as e:
            raise ValueError(f"Invalid base64 encoding: {e}")

        if len(encrypted_data) < 16:
            raise ValueError("Invalid encrypted data (too short)")

        # Extract IV and ciphertext
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        try:
            # Decrypt
            cipher = Cipher(
                algorithms.AES(self._encryption_key),
                modes.CBC(iv),
                backend=default_backend(),
            )
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            # Unpad
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext)
            plaintext += unpadder.finalize()

            return plaintext.decode("utf-8")
        except Exception as e:
            raise ValueError(f"Failed to decrypt value: {e}")
