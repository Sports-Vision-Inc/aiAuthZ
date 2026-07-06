# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

from __future__ import annotations

import base64
import hashlib
from abc import ABC, abstractmethod
from functools import lru_cache

from aiauthz.config import get_settings


class KeyProvider(ABC):
    @abstractmethod
    def master_key(self) -> bytes:
        ...


class EnvVarKeyProvider(KeyProvider):
    def __init__(self, raw: str) -> None:
        self._raw = raw

    def master_key(self) -> bytes:
        # Accept either a 32-byte url-safe base64 value or any string;
        # for the latter the SHA-256 digest yields the working key.
        try:
            decoded = base64.urlsafe_b64decode(self._raw.encode())
            if len(decoded) >= 32:
                return decoded[:32]
        except Exception:
            pass
        return hashlib.sha256(self._raw.encode()).digest()


class VaultKeyProvider(KeyProvider):  # pragma: no cover
    def __init__(self, *args, **kwargs) -> None:
        raise NotImplementedError("VaultKeyProvider not yet implemented")

    def master_key(self) -> bytes:
        raise NotImplementedError


class AWSKMSKeyProvider(KeyProvider):  # pragma: no cover - placeholder
    def __init__(self, *args, **kwargs) -> None:
        raise NotImplementedError("AWSKMSKeyProvider not yet implemented")

    def master_key(self) -> bytes:
        raise NotImplementedError


@lru_cache(maxsize=1)
def get_key_provider() -> KeyProvider:
    settings = get_settings()
    return EnvVarKeyProvider(settings.master_key)
