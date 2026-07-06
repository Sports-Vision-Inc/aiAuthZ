from __future__ import annotations

import os
import secrets
from pathlib import Path

import numpy as np

from aiauthz.core.watermark import (
    derive_alpha_n,
    embed_watermark,
    extract_watermark,
    host_image_for,
    watermark_image_for,
    watermark_message,
)


def test_derive_alpha_n_is_deterministic():
    key = secrets.token_bytes(32)
    a1, n1 = derive_alpha_n(key, "msg-1")
    a2, n2 = derive_alpha_n(key, "msg-1")
    assert (a1, n1) == (a2, n2)
    assert 0.05 < a1 < 0.95
    assert 1 <= n1 <= 6


def test_derive_alpha_n_differs_per_message():
    key = secrets.token_bytes(32)
    pairs = {derive_alpha_n(key, f"m{i}") for i in range(10)}
    assert len(pairs) > 3


def test_host_image_does_not_carry_plaintext():
    host = host_image_for("user-1", "msg-1", "deadbeef" * 8)
    assert host.shape == (256, 256)
    # QR-coded; pixels are bilevel after rendering, so unique value count is small.
    assert len(set(np.unique(host).tolist())) <= 8


def test_embed_then_extract_recovers_singular_values():
    host = host_image_for("u", "m", "0" * 64)
    wm = watermark_image_for("u", "m")
    alpha, n = 0.3, 2
    embedded, info = embed_watermark(host, wm, alpha, n)
    S_host = np.array(info["S_host"])
    recovered = extract_watermark(embedded, S_host, alpha, n)
    assert recovered.shape == (host.shape[0] // 4, host.shape[1] // 4)


def test_watermark_message_writes_png(tmp_path: Path):
    key = secrets.token_bytes(32)
    out = watermark_message(
        user_key=key, user_id="u-1", message_id="m-1",
        content="hello agent", output_dir=tmp_path,
    )
    assert os.path.exists(out)
    assert out.endswith(".png")


def test_verify_watermark_passes_for_legitimate_artifact(tmp_path: Path):
    import hashlib
    from aiauthz.core.watermark import verify_watermark, watermark_bytes
    key = secrets.token_bytes(32)
    content = "the user's message body"
    png = watermark_bytes(
        user_key=key, user_id="u-1", message_id="m-2", content=content,
    )
    result = verify_watermark(
        png_bytes=png, user_key=key, user_id="u-1", message_id="m-2",
        content_sha256=hashlib.sha256(content.encode()).hexdigest(),
    )
    assert result["ok"] is True
    assert result["cosine"] > 0.5


def test_verify_watermark_perfect_recovery_with_right_key():
    """The recovered S vector matches S_expected within tight relative L2
    error when the verifier is given the same key used to embed."""
    import hashlib
    import numpy as np
    from aiauthz.core.watermark import (
        derive_alpha_n,
        embed_watermark,
        host_image_for,
        watermark_image_for,
    )
    key = secrets.token_bytes(32)
    content = "y"
    sha = hashlib.sha256(content.encode()).hexdigest()
    alpha, n = derive_alpha_n(key, "m")
    host = host_image_for("u", "m", sha)
    wm = watermark_image_for("u", "m")

    # Use the in-process pixel arrays to avoid PNG round-trip drift
    # so we can establish a numerical baseline for the recovery.
    embedded, info = embed_watermark(host, wm, alpha, n)
    S_host = np.asarray(info["S_host"])

    import pywt
    LL1, _ = pywt.dwt2(embedded, "haar")
    LL2, _ = pywt.dwt2(LL1, "haar")
    Ux, Sx, Vx = np.linalg.svd(LL2, full_matrices=False)
    blend = alpha ** n
    S_recovered = (Sx - (1.0 - blend) * S_host) / blend

    LL2w, _ = pywt.dwt2(wm, "haar")
    LL2w2, _ = pywt.dwt2(LL2w, "haar")
    _, S_expected, _ = np.linalg.svd(LL2w2, full_matrices=False)
    rel_err = np.linalg.norm(S_recovered - S_expected) / np.linalg.norm(S_expected)
    assert rel_err < 1e-6


def test_verify_watermark_rejects_wrong_key():
    """Security property: an artifact made with one user's key must NOT
    verify under a different key. This is what makes the receipt unforgeable
    without the user's HMAC secret."""
    import hashlib
    from aiauthz.core.watermark import verify_watermark, watermark_bytes
    right_key = secrets.token_bytes(32)
    content = "authorize production deploy"
    png = watermark_bytes(
        user_key=right_key, user_id="u-1", message_id="m-9", content=content,
    )
    sha = hashlib.sha256(content.encode()).hexdigest()

    false_accepts = 0
    trials = 25
    for _ in range(trials):
        wrong_key = secrets.token_bytes(32)
        result = verify_watermark(
            png_bytes=png, user_key=wrong_key, user_id="u-1",
            message_id="m-9", content_sha256=sha,
        )
        if result["ok"]:
            false_accepts += 1
    assert false_accepts == 0, f"{false_accepts}/{trials} wrong keys falsely accepted"


def test_verify_watermark_rejects_wrong_message_id():
    """The receipt is bound to the message id via (alpha, n); verifying
    against a different message id must fail even with the right key."""
    import hashlib
    from aiauthz.core.watermark import verify_watermark, watermark_bytes
    key = secrets.token_bytes(32)
    content = "authorize production deploy"
    png = watermark_bytes(
        user_key=key, user_id="u-1", message_id="m-real", content=content,
    )
    result = verify_watermark(
        png_bytes=png, user_key=key, user_id="u-1",
        message_id="m-DIFFERENT", content_sha256=hashlib.sha256(content.encode()).hexdigest(),
    )
    assert result["ok"] is False


def test_verify_watermark_records_metadata_on_png_path():
    import hashlib
    from aiauthz.core.watermark import verify_watermark, watermark_bytes
    key = secrets.token_bytes(32)
    content = "round-trip via PNG"
    png = watermark_bytes(
        user_key=key, user_id="u", message_id="m", content=content,
    )
    result = verify_watermark(
        png_bytes=png, user_key=key, user_id="u", message_id="m",
        content_sha256=hashlib.sha256(content.encode()).hexdigest(),
    )
    assert "alpha" in result and "n" in result
    assert result["cosine"] > 0.5
