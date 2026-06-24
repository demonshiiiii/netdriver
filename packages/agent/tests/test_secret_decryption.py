#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from netdriver_agent.api.rest.v1.api import cmd, connect
from netdriver_agent.models.cmd import Command, CommandRequest
from netdriver_agent.models.common import CommonResponse
from netdriver_agent.models.conn import ConnectRequest
from netdriver_agent.models.header import CommonHeaders
from netdriver_agent.security.secret_decryption import (
    SecretDecryptionConfig,
    SecretDecryptor,
    decrypt_common_request_secrets,
)


_KEY_HEX = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
_KEY = bytes.fromhex(_KEY_HEX)
_NONCE = b"123456789012"


def _encrypt_aes_gcm_secret(plaintext: str) -> str:
    ciphertext = AESGCM(_KEY).encrypt(_NONCE, plaintext.encode(), None)
    return base64.b64encode(_NONCE + ciphertext).decode()


def _enabled_decryptor() -> SecretDecryptor:
    return SecretDecryptor(SecretDecryptionConfig(enabled=True, encryption_key=_KEY_HEX))


class _FakeHandler:
    def __init__(self) -> None:
        self.captured = None

    async def handle(self, request):
        self.captured = request
        return CommonResponse.ok()


@pytest.mark.unit
def test_secret_decryptor_returns_original_value_when_disabled() -> None:
    decryptor = SecretDecryptor(SecretDecryptionConfig(enabled=False, encryption_key=None))

    assert decryptor.decrypt_required("plain-password") == "plain-password"
    assert decryptor.decrypt("") == ""
    assert decryptor.decrypt(None) is None


@pytest.mark.unit
def test_secret_decryptor_decrypts_aes_gcm_value() -> None:
    decryptor = SecretDecryptor(
        SecretDecryptionConfig(enabled=True, encryption_key=_KEY_HEX)
    )

    assert decryptor.decrypt_required(_encrypt_aes_gcm_secret("Admin123!")) == "Admin123!"


@pytest.mark.unit
def test_secret_decryptor_rejects_plaintext_value_when_enabled() -> None:
    decryptor = SecretDecryptor(
        SecretDecryptionConfig(enabled=True, encryption_key=_KEY_HEX)
    )

    with pytest.raises(ValueError, match="password.*invalid base64"):
        decryptor.decrypt_required("plain-password", field_name="password")


@pytest.mark.unit
def test_secret_decryptor_rejects_invalid_enabled_key() -> None:
    decryptor = SecretDecryptor(
        SecretDecryptionConfig(enabled=True, encryption_key="not-hex")
    )

    with pytest.raises(ValueError, match="encryption_key"):
        decryptor.decrypt_required(_encrypt_aes_gcm_secret("Admin123!"))


@pytest.mark.unit
def test_secret_decryptor_rejects_invalid_encrypted_ciphertext() -> None:
    decryptor = SecretDecryptor(
        SecretDecryptionConfig(enabled=True, encryption_key=_KEY_HEX)
    )
    tampered = _encrypt_aes_gcm_secret("Admin123!")[:-2] + "AA"

    with pytest.raises(ValueError, match="decrypt"):
        decryptor.decrypt_required(tampered)


@pytest.mark.unit
def test_decrypt_common_request_secrets_decrypts_password_fields() -> None:
    decryptor = SecretDecryptor(
        SecretDecryptionConfig(enabled=True, encryption_key=_KEY_HEX)
    )
    request = ConnectRequest(
        protocol="ssh",
        ip="192.0.2.10",
        port=22,
        username="admin",
        password=_encrypt_aes_gcm_secret("login-secret"),
        enable_password=_encrypt_aes_gcm_secret("enable-secret"),
        vendor="cisco",
        model="asa",
        version="9.8",
    )

    decrypted = decrypt_common_request_secrets(request, decryptor)

    assert decrypted.password == "login-secret"
    assert decrypted.enable_password == "enable-secret"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_cmd_route_decrypts_common_request_secrets_before_handler() -> None:
    handler = _FakeHandler()
    request = CommandRequest(
        protocol="ssh",
        ip="192.0.2.10",
        port=22,
        username="admin",
        password=_encrypt_aes_gcm_secret("login-secret"),
        enable_password=_encrypt_aes_gcm_secret("enable-secret"),
        vendor="cisco",
        model="asa",
        version="9.8",
        commands=[
            Command(
                type="raw",
                mode="login",
                command="show version",
            )
        ],
    )

    await cmd(
        command=request,
        headers=CommonHeaders(),
        handler=handler,
        secret_decryptor=_enabled_decryptor(),
    )

    assert handler.captured.password == "login-secret"
    assert handler.captured.enable_password == "enable-secret"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_connect_route_decrypts_common_request_secrets_before_handler() -> None:
    handler = _FakeHandler()
    request = ConnectRequest(
        protocol="ssh",
        ip="192.0.2.10",
        port=22,
        username="admin",
        password=_encrypt_aes_gcm_secret("login-secret"),
        enable_password=_encrypt_aes_gcm_secret("enable-secret"),
        vendor="cisco",
        model="asa",
        version="9.8",
    )

    await connect(
        request=request,
        headers=CommonHeaders(),
        handler=handler,
        secret_decryptor=_enabled_decryptor(),
    )

    assert handler.captured.password == "login-secret"
    assert handler.captured.enable_password == "enable-secret"
