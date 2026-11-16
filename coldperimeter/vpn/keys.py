"""WireGuard key material, generated locally.

Keys never leave this process except inside the configuration files the
operator saves. They must not be logged or stored in scan results.
"""

from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


@dataclass(frozen=True)
class KeyPair:
    private: str
    public: str

    def __repr__(self) -> str:  # never print the private key by accident
        return f"KeyPair(public={self.public!r})"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def generate_keypair() -> KeyPair:
    key = X25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return KeyPair(private=_b64(private), public=_b64(public))


def public_from_private(private: str) -> str:
    key = X25519PrivateKey.from_private_bytes(base64.b64decode(private))
    return _b64(
        key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    )


def generate_preshared_key() -> str:
    return _b64(os.urandom(32))


def is_valid_key(text: str) -> bool:
    """A WireGuard key is 32 bytes, base64 encoded."""
    try:
        return len(base64.b64decode(text, validate=True)) == 32
    except (binascii.Error, ValueError):
        return False
