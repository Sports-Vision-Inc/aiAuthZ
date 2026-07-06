from __future__ import annotations

import hashlib
import io
import secrets

import pytest
from PIL import Image

from aiauthz.core.watermark.signed_qr import receipt_bytes, verify_receipt

# The signed-QR path needs an OpenCV decoder; skip cleanly if unavailable.
cv2 = pytest.importorskip("cv2")


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def test_receipt_verifies_for_right_key():
    key = secrets.token_bytes(32)
    content = "authorize prod deploy"
    png = receipt_bytes(user_key=key, user_id="u", message_id="m1", content=content)
    r = verify_receipt(
        png_bytes=png, user_key=key, user_id="u",
        message_id="m1", content_sha256=_sha(content),
    )
    assert r["ok"] is True
    assert r["reason"] == "verified"


def test_receipt_rejects_wrong_key():
    key = secrets.token_bytes(32)
    content = "authorize prod deploy"
    png = receipt_bytes(user_key=key, user_id="u", message_id="m1", content=content)
    for _ in range(10):
        r = verify_receipt(
            png_bytes=png, user_key=secrets.token_bytes(32), user_id="u",
            message_id="m1", content_sha256=_sha(content),
        )
        assert r["ok"] is False
        # It decodes fine — it's the signature that fails.
        assert r["reason"] in ("signature_mismatch", "qr_unreadable")


def test_receipt_rejects_wrong_identifiers():
    key = secrets.token_bytes(32)
    content = "authorize prod deploy"
    png = receipt_bytes(user_key=key, user_id="u", message_id="m1", content=content)
    r = verify_receipt(
        png_bytes=png, user_key=key, user_id="u",
        message_id="m-OTHER", content_sha256=_sha(content),
    )
    assert r["ok"] is False


def _jpeg(png: bytes, q: int) -> bytes:
    im = Image.open(io.BytesIO(png)).convert("L")
    b = io.BytesIO()
    im.save(b, "JPEG", quality=q)
    return b.getvalue()


def test_receipt_survives_heavy_jpeg():
    """The receipt is designed to survive lossy channels; a plain byte
    signature would break on any re-compression."""
    key = secrets.token_bytes(32)
    content = "authorize prod deploy"
    png = receipt_bytes(user_key=key, user_id="u", message_id="m1", content=content)
    degraded = _jpeg(png, 30)
    r = verify_receipt(
        png_bytes=degraded, user_key=key, user_id="u",
        message_id="m1", content_sha256=_sha(content),
    )
    assert r["ok"] is True
