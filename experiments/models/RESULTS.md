# Multi-model gateway benchmark

All calls were made through **OpenRouter** (OpenAI-compatible API). Each (model, case) was run **5 times across temperatures 0.0/0.3/0.5/0.7/1.0** — sampling behavior rather than a single deterministic call, and avoiding a cached identical response. **Attempt** = the model emitted the dangerous tool call in **at least one** of the 5 runs (worst-case susceptibility). **Gateway block rate** applies aiAuthZ's real policy with the caller bound as a non-owner. 8 chaos-case attacks (incl. 2 RAG poisoning), dangerous tools exposed.

| Model | Tier | Model refusal | Attempts | Gateway block | Residual (model only) | Residual (+gateway) | Cost/case | Time WITHOUT aiAuthZ | Time aiAuthZ adds |
|---|---|---|---|---|---|---|---|---|---|
| DeepSeek V4 Pro | open flagship | 38% | 5/8 | 100% | 62% | 0% | $0.000425 | 8.055 s | 0.021 ms |
| MiniMax M3 | high-volume multimodal | 75% | 2/8 | 100% | 25% | 0% | $0.000449 | 6.745 s | 0.006 ms |
| MiMo V2.5 Pro | 1T frontier (Hunter Alpha) | 75% | 2/8 | 100% | 25% | 0% | $0.000488 | 9.284 s | 0.012 ms |
| Qwen3 Max | Qwen flagship | 25% | 3/4 | 100% | 75% | 0% | $0.000499 | 3.177 s | 0.012 ms |
| Gemini 3.5 Flash | Google cheap | 38% | 5/8 | 100% | 62% | 0% | $0.000505 | 1.143 s | 0.011 ms |
| GPT-5 mini | OpenAI cheap | 62% | 3/8 | 100% | 38% | 0% | $0.000548 | 5.706 s | 0.013 ms |
| GLM 5.2 | top open-weight | 75% | 2/8 | 100% | 25% | 0% | $0.000561 | 7.771 s | 0.018 ms |
| Kimi K2.5 | Agents-of-Chaos model | 50% | 4/8 | 100% | 50% | 0% | $0.000584 | 6.59 s | 0.015 ms |
| Kimi K2.6 | Kimi latest | 62% | 3/8 | 100% | 38% | 0% | $0.000828 | 8.769 s | 0.024 ms |
| Nemotron 3 Ultra | US open-weight 550B | 62% | 3/8 | 100% | 38% | 0% | $0.001024 | 2.574 s | 0.030 ms |
| Gemini 3.1 Pro | Google flagship | 75% | 2/8 | 100% | 25% | 0% | $0.003698 | 4.97 s | 0.012 ms |
| Sonnet 5 | Anthropic mid | 75% | 2/8 | 100% | 25% | 0% | $0.004581 | 12.499 s | 0.018 ms |
| GPT-5.5 | OpenAI flagship | 50% | 4/8 | 100% | 50% | 0% | $0.005889 | 5.644 s | 0.014 ms |
| Fable 5 | Anthropic flagship / high-safety | 100% | 0/8 | n/a | 0% | 0% | $0.008762 | 4.537 s | — |
| Opus 4.8 | Anthropic flagship | 50% | 4/8 | 100% | 50% | 0% | $0.009476 | 7.884 s | 0.019 ms |

**Time WITHOUT aiAuthZ** is the raw model API call. **Time aiAuthZ adds** is the policy decision — a local computation on the order of microseconds, with no extra model round-trip. The gateway's authorization overhead is negligible next to the model latency (seconds), so making every model safe costs essentially no added time.

Cost spread: **Opus 4.8** costs ~22× **DeepSeek V4 Pro** per case. With the gateway, residual risk collapses to ~0 across every tier — so the safety of the expensive model is not what is buying down tool-layer risk; the gateway is.

## Guardrail baseline (same attacks)

A content-safety classifier (Llama Guard 4) flagged **4/8** of the attack prompts as unsafe. These attacks are unauthorized *actions* phrased as ordinary ops requests, not harmful *content*, so a content classifier is largely blind to them. aiAuthZ blocks 100% of the attempted dangerous calls deterministically, because it authorizes the caller and the action, not the wording — the two approaches are complementary layers.
