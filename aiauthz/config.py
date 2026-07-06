# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env.local", ".env"),
        env_prefix="AIAUTHZ_",
        case_sensitive=False,
        extra="ignore",
    )

    mode: Literal["dev", "self_hosted", "hosted"] = "dev"

    database_url: str = "sqlite:///./data/aiauthz.db"
    redis_url: str = ""

    # Required. The application refuses to start without it.
    # Generate with:
    #   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    master_key: str = ""

    nonce_ttl_seconds: int = 300

    watermark_dir: Path = Path("./storage/watermarks")
    watermark_enabled: bool = True
    watermark_store: Literal["db", "file"] = "db"
    # Receipt mechanism for accepted messages:
    #   signed_qr  — cryptographically signed QR (exact, robust; recommended)
    #   watermark  — invisible DWT spread-spectrum (for real cover images)
    receipt_mode: Literal["signed_qr", "watermark"] = "signed_qr"

    tools_config: str | None = None

    host: str = "127.0.0.1"
    port: int = 8080


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
        if not _settings.master_key:
            raise RuntimeError(
                "AIAUTHZ_MASTER_KEY is not set. Generate one with "
                '`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` '
                "and place it in your .env / secrets manager."
            )
        if _settings.watermark_store == "file":
            _settings.watermark_dir.mkdir(parents=True, exist_ok=True)
        if _settings.database_url.startswith("sqlite"):
            Path("./data").mkdir(parents=True, exist_ok=True)
    return _settings


def reset_settings() -> None:
    global _settings
    _settings = None
