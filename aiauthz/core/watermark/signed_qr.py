# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

"""Cryptographically signed audit receipts (the primary receipt mechanism).

A receipt is a signed QR code whose only job is to be an unforgeable,
verifiable record of an authorized action:

  * Unforgeability is an HMAC-SHA256 signature, checked by constant-time
    compare — no similarity threshold, so the signature either verifies or not.
  * Robustness comes from the QR code's Reed-Solomon error correction (level H
    recovers ~30% erasure), so the receipt survives lossy channels such as
    screenshots and re-compression as long as it remains scannable.
  * It is human-usable: anyone can scan the receipt to read its identifiers
    and (with the key) verify it.

The invisible DWT spread-spectrum watermark (see dwt_svd.py) covers the
different case of marking a real cover image imperceptibly.

The signed payload contains only identifiers, a content hash, and the tag —
never the plaintext message.
"""

from __future__ import annotations

import hashlib
import hmac
import io

import numpy as np
import qrcode
from PIL import Image

RECEIPT_VERSION = "v2"
_SIG_BYTES = 16  # 128-bit truncated HMAC tag — ample for forgery resistance


def _canonical(user_id: str, message_id: str, content_sha256: str) -> bytes:
    return f"aiauthz:{RECEIPT_VERSION}:{user_id}:{message_id}:{content_sha256}".encode()


def sign(user_key: bytes, user_id: str, message_id: str, content_sha256: str) -> str:
    tag = hmac.new(user_key, _canonical(user_id, message_id, content_sha256), hashlib.sha256).digest()
    return tag[:_SIG_BYTES].hex()


def receipt_payload(user_key: bytes, user_id: str, message_id: str, content_sha256: str) -> str:
    sig = sign(user_key, user_id, message_id, content_sha256)
    return f"aiauthz:{RECEIPT_VERSION}:{user_id}:{message_id}:{content_sha256}:{sig}"


def receipt_bytes(
    *, user_key: bytes, user_id: str, message_id: str, content: str, box_size: int = 8,
) -> bytes:
    """Return the signed-QR receipt PNG for a message.

    ``content`` is hashed before encoding; only the hash and identifiers plus
    the HMAC tag are placed in the QR. High error correction (H) maximizes
    survival through lossy channels."""
    content_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
    payload = receipt_payload(user_key, user_id, message_id, content_sha256)
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_H,  # ~30% recovery
        box_size=box_size,
        border=4,
    )
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("L")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _decode_qr(png_bytes: bytes) -> str | None:
    """Decode a (possibly degraded) QR image. Returns the payload or None.

    Note the reliability ceiling here is the *decoder*, not the QR's
    robustness — a dedicated scanner (phone camera, zbar) reads these
    essentially perfectly. We use OpenCV so there is no system-library
    dependency, with a clean-upscale + binarize pass that lifts its hit rate
    close to a dedicated scanner's."""
    try:
        import cv2  # local import; opencv is an optional runtime dep
    except Exception:  # pragma: no cover - environments without cv2
        return None
    detector = cv2.QRCodeDetector()

    base = Image.open(io.BytesIO(png_bytes)).convert("L")
    # Clean LANCZOS upscale (not blocky pixel-replication) so the detector has
    # plenty of resolution, then a threshold pass to sharpen soft edges left by
    # lossy channels back into crisp modules.
    upscaled = base.resize((600, 600), Image.LANCZOS) if base.size[0] < 600 else base
    up = np.asarray(upscaled)
    candidates = [
        np.where(up > up.mean(), 255, 0).astype(np.uint8),
        up,
        np.asarray(base),
    ]
    for cand in candidates:
        data, _, _ = detector.detectAndDecode(cand)
        if data:
            return data
    return None


def verify_receipt(
    *, png_bytes: bytes, user_key: bytes, user_id: str, message_id: str, content_sha256: str,
) -> dict:
    """Verify a signed-QR receipt. Decodes the QR, checks the identifiers
    match, and constant-time-compares the HMAC tag. Exact — no threshold."""
    payload = _decode_qr(png_bytes)
    if payload is None:
        return {"ok": False, "decoded": False, "reason": "qr_unreadable"}
    parts = payload.split(":")
    # aiauthz : v2 : user_id : message_id : content_sha256 : sig
    if len(parts) != 6 or parts[0] != "aiauthz" or parts[1] != RECEIPT_VERSION:
        return {"ok": False, "decoded": True, "reason": "bad_payload_format"}
    _, _, uid, mid, sha, sig = parts
    if (uid, mid, sha) != (user_id, message_id, content_sha256):
        return {"ok": False, "decoded": True, "reason": "identifier_mismatch"}
    expected = sign(user_key, user_id, message_id, content_sha256)
    if not hmac.compare_digest(sig, expected):
        return {"ok": False, "decoded": True, "reason": "signature_mismatch"}
    return {"ok": True, "decoded": True, "reason": "verified"}
