#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Request secret decryption helpers."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from typing import TypeVar

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel


_AES_GCM_NONCE_LENGTH = 12
_AES_256_KEY_HEX_LENGTH = 64
_AES_256_KEY_LENGTH = 32

_RequestT = TypeVar("_RequestT", bound=BaseModel)


@dataclass(frozen=True)
class SecretDecryptionConfig:
    """Configuration for optional request secret decryption."""

    enabled: bool = False
    encryption_key: str | None = None


class SecretDecryptor:
    """Decrypt AES-256-GCM request secrets when enabled."""

    def __init__(self, config: SecretDecryptionConfig | None = None) -> None:
        self._config = config or SecretDecryptionConfig()

    @property
    def enabled(self) -> bool:
        """Return whether decryption is enabled."""
        return self._config.enabled

    def decrypt_required(self, value: str, field_name: str = "secret") -> str:
        """Decrypt a required secret field or return it unchanged when disabled."""
        decrypted = self.decrypt(value, field_name=field_name)
        if decrypted is None:
            raise ValueError(f"secret value is required for {field_name}")
        return decrypted

    def decrypt(self, value: str | None, field_name: str = "secret") -> str | None:
        """Decrypt an optional secret field or return it unchanged when disabled."""
        if not self._config.enabled:
            return value
        if value is None or value == "":
            return value

        combined = self._decode_ciphertext(value)
        if combined is None:
            raise ValueError(f"secret decrypt failed for {field_name}: invalid base64")
        if len(combined) <= _AES_GCM_NONCE_LENGTH:
            raise ValueError(f"secret decrypt failed for {field_name}: encrypted data is too short")

        nonce = combined[:_AES_GCM_NONCE_LENGTH]
        ciphertext = combined[_AES_GCM_NONCE_LENGTH:]
        key = self._key()
        try:
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
            return plaintext.decode("utf-8")
        except (InvalidTag, UnicodeDecodeError) as exc:
            raise ValueError(f"secret decrypt failed for {field_name}") from exc

    def _key(self) -> bytes:
        key = (self._config.encryption_key or "").strip()
        if len(key) != _AES_256_KEY_HEX_LENGTH:
            raise ValueError("secrets.encryption_key must be a 64-character hex string")
        try:
            key_bytes = bytes.fromhex(key)
        except ValueError as exc:
            raise ValueError("secrets.encryption_key must be a 64-character hex string") from exc
        if len(key_bytes) != _AES_256_KEY_LENGTH:
            raise ValueError("secrets.encryption_key must decode to 32 bytes")
        return key_bytes

    @staticmethod
    def _decode_ciphertext(value: str) -> bytes | None:
        try:
            return base64.b64decode(value.encode(), validate=True)
        except binascii.Error:
            return None


def create_secret_decryptor(
    enabled: bool | None = False,
    encryption_key: str | None = None,
) -> SecretDecryptor:
    """Create a request secret decryptor from configuration values."""
    return SecretDecryptor(
        SecretDecryptionConfig(
            enabled=bool(enabled),
            encryption_key=encryption_key,
        )
    )


def decrypt_common_request_secrets(
    request: _RequestT,
    decryptor: SecretDecryptor,
) -> _RequestT:
    """Return a request copy with common password fields decrypted."""
    return request.model_copy(
        update={
            "password": decryptor.decrypt_required(
                request.password,
                field_name="password",
            ),
            "enable_password": decryptor.decrypt(
                request.enable_password,
                field_name="enable_password",
            ),
        }
    )
