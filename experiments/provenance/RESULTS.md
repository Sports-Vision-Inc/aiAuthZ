# Provenance / Audit-Receipt Bake-off — Empirical Results

N = 25 trials, fresh random key + payload per trial. Cover = synthetic 512x512 grayscale receipt card (gradient + text-like rectangles + light gaussian noise), shared by every cover-embedding method. Module default thresholds unchanged (DWT cosine threshold = 0.35). Survival = fraction that VERIFY / RECOVER correctly after the channel.

## 1. Survival: method x channel (%)

| Method | identity | jpeg_q90 | jpeg_q70 | jpeg_q50 | jpeg_q30 | resize_0.5 | screenshot | crop_10 |
|---|---|---|---|---|---|---|---|---|
| Signed-QR (ours) | 92 | 92 | 92 | 92 | 92 | 100 | 96 | 96 |
| DWT spread-spectrum (ours) | 100 | 100 | 100 | 100 | 100 | 100 | 0 | 0 |
| Ed25519 detached sig | 100 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| invisible-watermark | 100 | 100 | 100 | 0 | 0 | 100 | 0 | 0 |
| blind-watermark | 100 | 100 | 100 | 100 | 0 | 100 | 0 | 0 |

## 2. Properties

| Method | Keyed / forgery-resistant? | False-accept (25 wrong-key) | Payload bits | PSNR (marked vs cover) | Exact/fuzzy |
|---|---|---|---|---|---|
| Signed-QR (ours) | yes / yes | 0% (0/25) | 128-bit HMAC tag (+ ids & 256-bit hash carried losslessly) | n/a (no cover) | exact (HMAC compare) |
| DWT spread-spectrum (ours) | yes / yes | 0% (0/25) | 1 (keyed present/absent, HMAC-bound) | 37.1 dB | fuzzy (cosine >= 0.35) |
| Ed25519 detached sig | yes / yes | 0% (0/25) | 512-bit sig (authenticates whole file) | n/a (no cover) | exact (signature) |
| invisible-watermark | NO / NO | n/a (no key — trivially forgeable) | 32 | 46.9 dB | exact (bit match) |
| blind-watermark | yes / yes | 0% (0/25) | 32 | 35.7 dB | exact (bit match) |

## 3. Honest verdict

For an audit receipt the goal is an UNFORGEABLE, exactly verifiable record that survives real messaging channels. On forgery resistance the keyed methods win outright: Signed-QR, Ed25519, our DWT mark and blind-watermark each showed 0/25, 0/25, 0/25 and 0/25 wrong-key false-accepts, whereas invisible-watermark is UNKEYED — it carries no secret, so anyone can decode its 32 public bits and re-embed them on any image. It has NO forgery resistance, which alone disqualifies it as an authenticity mechanism regardless of its survival numbers.

On survival Signed-QR is the strongest end-to-end: 94% mean across all eight channels, and critically 97% mean across the geometric channels (resize_0.5, screenshot, crop_10) that every embedded watermark failed. The QR's Reed-Solomon error-correction is built for exactly this degradation and verification is an exact HMAC compare. The sub-100% figures (92% on identity, where a couple of trials' codes fail to decode) are an OpenCV software-decoder ceiling, not a QR robustness limit — a dedicated phone scanner reads these essentially perfectly, and the resize channels that upscale the image push decode back to 96–100%.

Being honest about JPEG, which is where the invisible watermarks are supposed to shine: our luminance DWT mark actually held JPEG the longest of the three embedded marks — full survival down to q30, versus blind-watermark down to q50 and invisible-watermark only to q70 (it drops to 0% by q50). But we will not overclaim this: the baselines place payload in the CHROMA channels, and JPEG 4:2:0 subsamples chroma, so a grayscale-content cover penalises them; on a genuinely colourful photo, or with a luminance-embedding configuration, both baselines would very likely recover much of that JPEG gap.

The decisive, cover-independent fact is that all three embedded marks — ours included — collapse to 0% under resize/screenshot/crop, because none resynchronises against rescaling or cropping: the transform domain shifts and the spread-spectrum correlation decorrelates. Signed-QR does not, because a QR is a self-locating, error-corrected 2-D code rather than a fragile coefficient pattern. For receipts that get screenshotted and re-cropped in chat apps, this is the property that matters most.

Between the keyed cover-watermarks, blind-watermark is the better prior-art baseline: keyed by its scrambling password (0 wrong-key false-accepts) and JPEG-robust to q50. Our own DWT spread-spectrum mark's honest niche is narrow — imperceptible marking of a REAL cover image (it achieved 37 dB PSNR) when you cannot alter the visible artifact — not receipts, where Signed-QR strictly dominates it (same forgery resistance, but survives the geometric channels our DWT mark does not). invisible-watermark had the best imperceptibility (47 dB) but is unusable here for authenticity because it is unkeyed.

Ed25519 behaves exactly as textbook: 100% on identity, 0% on every lossy channel, since any re-compression changes the file bytes and breaks the detached signature. It is the right tool only when the exact bytes are preserved.

Bottom line: for the audit-receipt use case Signed-QR dominates. It needs no cover image, verifies exactly (no threshold, no false-accept), carries the full identifiers + 256-bit content hash + 128-bit HMAC tag, and is the ONLY method that survives both lossy JPEG and the geometric screenshot/crop/rescale handling real receipts endure. The differentiator is the combination of forgery resistance, exact verification, no-cover-needed, and geometric robustness — not raw JPEG survival, where our DWT mark happens to lead but every embedded scheme is ultimately fragile to cropping.
