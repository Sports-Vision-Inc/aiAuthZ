# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 SportsVision AI <https://www.sportsvision.ai>
# Part of aiAuthZ — identity and authorization for AI agents.
# See NOTICE and LICENSE at the repository root.

from .dwt_svd import (
    derive_alpha_n,
    embed_watermark,
    extract_watermark,
    host_image_for,
    verify_watermark,
    watermark_bytes,
    watermark_image_for,
    watermark_message,
)
from .signed_qr import receipt_bytes, receipt_payload, sign, verify_receipt

__all__ = [
    # Primary receipt mechanism: cryptographically signed QR.
    "receipt_bytes",
    "receipt_payload",
    "sign",
    "verify_receipt",
    # Secondary: invisible DWT spread-spectrum for marking real cover images.
    "derive_alpha_n",
    "embed_watermark",
    "extract_watermark",
    "host_image_for",
    "verify_watermark",
    "watermark_bytes",
    "watermark_image_for",
    "watermark_message",
]
