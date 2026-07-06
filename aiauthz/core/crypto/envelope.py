# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from aiauthz.core.crypto.keys import get_key_provider


def _aesgcm() -> AESGCM:
    return AESGCM(get_key_provider().master_key())


def encrypt(plaintext: bytes, associated: bytes | None = None) -> bytes:
    nonce = os.urandom(12)
    ct = _aesgcm().encrypt(nonce, plaintext, associated)
    return nonce + ct


def decrypt(blob: bytes, associated: bytes | None = None) -> bytes:
    nonce, ct = blob[:12], blob[12:]
    return _aesgcm().decrypt(nonce, ct, associated)


def encrypt_str(s: str) -> bytes:
    return encrypt(s.encode("utf-8"))


def decrypt_str(blob: bytes) -> str:
    return decrypt(blob).decode("utf-8")
