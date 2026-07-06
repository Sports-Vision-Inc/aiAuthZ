# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

"""Keyed DWT-domain watermarking (secret-key spread-spectrum detector).

Builds on Kodathala Sai Varun et al., "Robust DWT-SVD Domain Image
Watermarking based on Iterative Blending", J. Phys.: Conf. Ser. 2070 012111
(2021), and adapts it into a *keyed audit-provenance* scheme.

The embedded mark is a **secret pseudorandom pattern** derived from
``HMAC(user_key, user_id:message_id:content_sha256)`` — NOT a publicly
reconstructable image. It is added, spread-spectrum style, across the
low-frequency LL2 DWT sub-band of a public QR cover:

    LL2' = LL2_host + gain * std(LL2_host) * w

Detection is *semi-blind*: the verifier regenerates the public host cover from
the claimed identifiers (no key needed for the cover), subtracts it from the
received image's LL2 band, and correlates the residual against the key-derived
pattern ``w``. Under the right key the normalized correlation is high (~0.75+);
under any wrong key, wrong user_id, or wrong message_id the expected pattern is
statistically independent of what was embedded, so the correlation drops to ~0.
Forging a verifiable receipt therefore requires the user's HMAC secret.

Embedding uses additive spread-spectrum in the low-frequency coefficient domain
(the Cox et al. construction), which is robust to lossy channels and cleanly
key-discriminating. The plaintext message is never embedded — only a hash of it
travels, in the visible QR cover.
"""

from __future__ import annotations

import hashlib
import hmac
import io
from pathlib import Path

import numpy as np
import pywt
import qrcode
from PIL import Image

IMG_SIZE = 256
# 2-level Haar DWT of a 256×256 image → 64×64 LL2 → 4096 coefficients. The
# keyed mark is a spread-spectrum pattern over that whole low-frequency band.
LL2_COEFFS = 64 * 64
# Embedding-strength band (fraction of the LL2 std added per coefficient).
# ~0.05 gives ≈37 dB PSNR (imperceptible) while keeping clean key separation.
GAIN_MIN = 0.05
GAIN_MAX = 0.09
# Detection threshold on the normalized correlation between the residual
# (received − host, over the LL2 band) and the key-derived pattern. Right key
# ≈ 0.75; wrong key ≈ 0 (std ≈ 1/sqrt(4096) ≈ 0.016). 0.35 sits far from both.
DEFAULT_THRESHOLD = 0.35


def _hmac(user_key: bytes, message: str) -> bytes:
    return hmac.new(user_key, message.encode("utf-8"), hashlib.sha256).digest()


def derive_alpha_n(user_key: bytes, message_id: str) -> tuple[float, int]:
    """Per-message (alpha, n) derivation, used as a keyed pseudo-random
    primitive by callers and tests. Embedding strength itself comes from
    :func:`derive_gain`."""
    seed = _hmac(user_key, message_id)
    a_int = int.from_bytes(seed[:4], "big")
    n_int = int.from_bytes(seed[4:5], "big")
    alpha = 0.05 + (a_int / 0xFFFFFFFF) * 0.90
    n = 1 + (n_int % 6)
    return float(alpha), int(n)


def derive_gain(user_key: bytes, user_id: str, message_id: str, content_sha256: str) -> float:
    """Per-message embedding gain in [GAIN_MIN, GAIN_MAX], keyed."""
    seed = _hmac(user_key, f"gain:{user_id}:{message_id}:{content_sha256}")
    frac = int.from_bytes(seed[:4], "big") / 0xFFFFFFFF
    return GAIN_MIN + frac * (GAIN_MAX - GAIN_MIN)


def derive_mark(
    user_key: bytes, user_id: str, message_id: str, content_sha256: str,
    length: int = LL2_COEFFS,
) -> np.ndarray:
    """Secret spread-spectrum pattern, derived from the user key.

    Independent of the key, an attacker cannot reproduce this pattern, so the
    detector's correlation against it is a key-sensitive test."""
    seed = _hmac(user_key, f"mark:{user_id}:{message_id}:{content_sha256}")
    rng = np.random.default_rng(int.from_bytes(seed[:8], "big"))
    return rng.standard_normal(length)


def _render_qr(payload: str, size: int = IMG_SIZE) -> np.ndarray:
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=4,
        border=2,
    )
    qr.add_data(payload)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white").convert("L")
    image = image.resize((size, size), Image.NEAREST)
    return np.asarray(image, dtype=np.float64)


def host_image_for(user_id: str, message_id: str, content_sha256: str) -> np.ndarray:
    """Public QR-coded cover image. Carries only metadata + a content hash."""
    payload = f"aiauthz:v1:{user_id}:{message_id}:{content_sha256}"
    return _render_qr(payload)


def watermark_image_for(user_id: str, message_id: str) -> np.ndarray:
    """Public QR binding the artifact to a user/message (visible layer)."""
    payload = f"aiauthz:user:{user_id}:msg:{message_id}"
    return _render_qr(payload)


def _dwt2_level2(x: np.ndarray):
    LL1, sub1 = pywt.dwt2(x, "haar")
    LL2, sub2 = pywt.dwt2(LL1, "haar")
    return LL2, sub2, sub1


def _idwt2_level2(LL2, sub2, sub1) -> np.ndarray:
    LL1 = pywt.idwt2((LL2, sub2), "haar")
    return pywt.idwt2((LL1, sub1), "haar")


def embed_mark(host: np.ndarray, mark: np.ndarray, gain: float) -> np.ndarray:
    """Additively embed the keyed spread-spectrum mark across the LL2 band."""
    LL2, sub2, sub1 = _dwt2_level2(host)
    flat = LL2.flatten()
    k = min(flat.size, mark.size)
    scale = gain * float(np.std(flat))
    flat[:k] = flat[:k] + scale * mark[:k]
    LL2_new = flat.reshape(LL2.shape)
    return _idwt2_level2(LL2_new, sub2, sub1)


def residual_ll2(embedded: np.ndarray, host_LL2: np.ndarray) -> np.ndarray:
    """Return the received-minus-host residual over the LL2 band, flattened.
    Correlating this against the key-derived pattern is the detection test."""
    LL2, _, _ = _dwt2_level2(embedded)
    k = min(LL2.size, host_LL2.size)
    return (LL2.flatten()[:k] - host_LL2.flatten()[:k])


# --- Backwards-compatible aliases used by older callers/tests --------------
def embed_watermark(host, watermark, alpha, n):  # noqa: D401 - legacy shim
    """Deprecated: legacy blend embed. Prefer :func:`embed_mark`."""
    LL2, sub2, sub1 = _dwt2_level2(host)
    wm_LL2, _, _ = _dwt2_level2(watermark)
    Uh, Sh, Vh = np.linalg.svd(LL2, full_matrices=False)
    _, Sw, _ = np.linalg.svd(wm_LL2, full_matrices=False)
    blend = alpha ** n
    S_new = (1.0 - blend) * Sh + blend * Sw
    embedded = _idwt2_level2((Uh * S_new) @ Vh, sub2, sub1)
    return embedded, {"S_host": Sh.tolist(), "alpha": alpha, "n": n}


def extract_watermark(embedded, S_host, alpha, n):  # noqa: D401 - legacy shim
    emb_LL2, _, _ = _dwt2_level2(embedded)
    Ux, Sx, Vx = np.linalg.svd(emb_LL2, full_matrices=False)
    blend = alpha ** n
    Sw_recovered = (Sx - (1.0 - blend) * S_host) / blend
    return (Ux * Sw_recovered) @ Vx


def _cosine(a: np.ndarray, b: np.ndarray) -> float:
    k = min(len(a), len(b))
    a, b = a[:k], b[:k]
    denom = np.linalg.norm(a) * np.linalg.norm(b)
    return float(np.dot(a, b) / denom) if denom > 0 else 0.0


def watermark_bytes(
    *, user_key: bytes, user_id: str, message_id: str, content: str,
) -> bytes:
    """Return the watermarked PNG bytes for ``message_id``.

    The content is hashed before encoding; the hash and identifiers travel in
    the visible QR cover, while a secret keyed mark is embedded via DWT-SVD.
    The plaintext content is never reflected into the artifact."""
    content_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
    host = host_image_for(user_id, message_id, content_sha256)
    mark = derive_mark(user_key, user_id, message_id, content_sha256)
    gain = derive_gain(user_key, user_id, message_id, content_sha256)

    embedded = embed_mark(host, mark, gain)
    embedded_uint = np.clip(np.rint(embedded), 0, 255).astype(np.uint8)

    buffer = io.BytesIO()
    Image.fromarray(embedded_uint, mode="L").save(buffer, format="PNG")
    return buffer.getvalue()


def verify_watermark(
    *,
    png_bytes: bytes,
    user_key: bytes,
    user_id: str,
    message_id: str,
    content_sha256: str,
    similarity_threshold: float = DEFAULT_THRESHOLD,
) -> dict:
    """Verify a watermarked PNG under the claimed identifiers and key.

    Returns ``ok`` (correlation ≥ threshold), the normalized ``cosine``
    correlation between recovered and key-derived marks, and the keyed
    ``gain``. Wrong key, wrong user_id, or wrong message_id all change the
    expected mark and drive the correlation toward zero."""
    embedded = np.asarray(
        Image.open(io.BytesIO(png_bytes)).convert("L"), dtype=np.float64,
    )
    host = host_image_for(user_id, message_id, content_sha256)
    host_LL2, _, _ = _dwt2_level2(host)

    mark_expected = derive_mark(user_key, user_id, message_id, content_sha256)

    # Correlate the received-minus-host LL2 residual against the key-derived
    # pattern. Scale-invariant, so the keyed gain need not be inverted; any
    # wrong key / user_id / message_id yields an independent pattern → ~0.
    residual = residual_ll2(embedded, host_LL2)
    cosine = _cosine(residual, mark_expected)
    return {
        "ok": bool(cosine >= similarity_threshold),
        "cosine": cosine,
        "gain": derive_gain(user_key, user_id, message_id, content_sha256),
        "threshold": similarity_threshold,
        # Kept for response-schema compatibility with the audit route.
        "alpha": None,
        "n": None,
        "ratio": None,
    }


def watermark_message(
    *, user_key: bytes, user_id: str, message_id: str, content: str, output_dir: Path,
) -> str:
    """Write the watermark PNG to ``output_dir`` and return its absolute path."""
    payload = watermark_bytes(
        user_key=user_key, user_id=user_id, message_id=message_id, content=content,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / f"{message_id}.png"
    out_path.write_bytes(payload)
    return str(out_path)
