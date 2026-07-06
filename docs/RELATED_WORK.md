# Related work

How aiAuthZ relates to prior work in agent security and content provenance. The
short version: aiAuthZ does not invent identity binding, tool-call policy,
watermarking, or signed receipts — it composes them at per-message granularity,
off-host, and welds them to survivable receipts. Each entry below notes whether
it binds a cryptographic caller identity *per tool-call message* (our seam).

## Concurrent prior art on deterministic pre-action authorization (2026) — read first

Off-host, deterministic, argument-level tool-call authorization is **not novel to
aiAuthZ**. Two 2026 systems publish the same core pattern, and we cite them
prominently rather than claim a first:

- **Open Agent Passport (OAP)** — "Before the Tool Call: Deterministic Pre-Action
  Authorization for Autonomous AI Agents" ([arXiv:2603.20953](https://arxiv.org/abs/2603.20953)).
  Intercepts each tool call synchronously, evaluates it against a declarative
  policy pack (amount caps, domain/recipient allowlists, rate limits, PII flags,
  restricted to a decidable fragment) in a cloud registry, is fail-closed, and
  emits Ed25519-signed, SHA-256 hash-chained audit records. Measured 53 ms median
  decision; 0% attack success across 879 attempts under a restrictive policy in a
  live $5,000 bounty. **Explicitly does not authenticate end-user identity per
  message** (it verifies the agent passport, not the sender), and by design does
  not defend content-level attacks.
- **AIP — Agent Identity Protocol** ([arXiv:2603.24775](https://arxiv.org/abs/2603.24775)).
  Invocation-Bound Capability Tokens (signed JWT / Biscuit+Datalog) fusing
  identity, attenuated delegation, and provenance across MCP/A2A. Delegation- and
  provenance-focused; no argument-level egress policy engine.

**What this means for aiAuthZ's claims.** We do **not** claim to be first or
unique at off-host deterministic pre-action authorization — OAP and AIP are
concurrent art with large overlap on our properties #2 (off-host), #3
(argument-level policy), #4 (hash-chained audit), and #7 (deterministic). Our
defensible contribution is the *combination* plus three specifics neither ships:
**per-inbound-user-message HMAC identity** (OAP authenticates the agent, not the
sender — the axis our `scripts/defense_comparison.py` isolates, where an
OAP-style action-only policy misses the identity-spoofing chaos cases), a
**survivable signed QR receipt** for human-verifiable action attestation (OAP's
Ed25519-over-bytes audit records do not survive re-compression — our provenance
bake-off measures exactly this), and a **credential broker** so the agent host
holds no secrets. Also honest: our per-message HMAC is symmetric — cheaper and
lower-latency than OAP's Ed25519, but it does not provide third-party
non-repudiation the way an asymmetric signature does. And we share OAP's core
limitations: a fully compromised runtime can bypass the hook, and a sequence of
individually-permitted calls can still compose into an unwanted outcome.

## Agent authorization / tool-call security

**CaMeL — "Defeating Prompt Injections by Design"** (Google DeepMind, 2025,
[arXiv:2503.18813](https://arxiv.org/abs/2503.18813)). Extracts control/data
flow from the trusted query into an explicit program so untrusted data can't
influence control flow; value-attached capabilities enforce policy at tool-call
time. In-process, design-time. No per-message cryptographic caller identity, no
off-host decision, no signed receipt. Complementary.

**Progent — "Programmable Privilege Control for LLM Agents"** (2025,
[arXiv:2504.11703](https://arxiv.org/abs/2504.11703)). A DSL for least-privilege
policies over tool calls, checked deterministically per call. The closest analog
to our policy layer — but it runs *in-process* and gates *actions*, not
*authenticated identities*; no per-message HMAC, no off-host trust boundary, no
receipt.

**IsolateGPT / SecGPT** (NDSS 2025,
[arXiv:2403.04960](https://arxiv.org/abs/2403.04960)). Execution isolation: each
agent "app" runs in its own instance, interacting through permissioned
interfaces. Pure isolation/sandboxing with user-in-the-loop prompts; no
cryptographic per-message identity or signed audit. Orthogonal.

**ToolEmu** (ICLR 2024, [arXiv:2309.15817](https://arxiv.org/abs/2309.15817)). An
LM-emulated sandbox to red-team agents across toolkits. A risk-discovery harness,
not an enforcement mechanism — useful to *generate* tests for a gateway.

**AgentDojo** (NeurIPS 2024 D&B,
[arXiv:2406.13352](https://arxiv.org/abs/2406.13352)). 97 tasks + 629 security
cases measuring indirect prompt-injection success and defense efficacy. This is
the benchmark to evaluate aiAuthZ against CaMeL/Progent; a head-to-head on it is
our stated next step (see WHITEPAPER §8), not yet done.

**Guardrails** — Llama Guard (Meta,
[arXiv:2312.06674](https://arxiv.org/abs/2312.06674)), NeMo Guardrails (NVIDIA),
Constitutional Classifiers (Anthropic,
[arXiv:2501.18837](https://arxiv.org/abs/2501.18837)). Probabilistic content
classifiers over prompt/response. None binds a cryptographic caller identity or
makes a deterministic authorization decision. We benchmark Llama Guard 4 on our
attack set (WHITEPAPER §6.4): it caught 4/8, being blind to authorization
attacks phrased as ordinary requests. Complementary layer.

**MCP security** — tool-poisoning via tool metadata
([Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)),
threat-model and SoK papers
([arXiv:2603.22489](https://arxiv.org/abs/2603.22489),
[arXiv:2512.08290](https://arxiv.org/pdf/2512.08290)), and **ETDI**
([arXiv:2506.01333](https://arxiv.org/pdf/2506.01333)), which authenticates tool
*definitions* via OAuth. ETDI is prior art to cite and distinguish: it
authenticates definitions; aiAuthZ authenticates each runtime *call message*.

**Workload / agent identity** — **SPIFFE/SPIRE** ([spiffe.io](https://spiffe.io))
issues short-lived cryptographic workload identities (SVIDs); the **OAuth
on-behalf-of-for-agents** IETF draft and **RFC 8693** token exchange encode
agent/user identity into tokens; **AIP**
([arXiv:2603.24775](https://arxiv.org/pdf/2603.24775)) covers verifiable
delegation. These bind identity to a *workload/session/token*, not to each
individual tool-call message, and carry no application-layer tool policy or
signed receipt.

## Content provenance / receipts

**C2PA / Content Credentials** ([c2pa.org](https://c2pa.org/faqs/)). Manifest +
X.509 claim signature. The hard binding fails on any re-encode; messaging apps
strip the manifest; screenshots destroy it. Durability then depends on a
soft-binding watermark/fingerprint. Library: `c2pa-python`.

**Detached digital signature** over file bytes (`cryptography`, Ed25519). Maximal
forgery resistance, zero survival to any re-encode — our textbook lower bound
(WHITEPAPER §6.5).

**invisible-watermark** ([ShieldMnt](https://github.com/ShieldMnt/invisible-watermark),
`imwatermark`). DWT-DCT / DWT-DCT-SVD blind watermark used by Stable Diffusion.
**Unkeyed** — carries no secret, so it is trivially forgeable and unusable for
authenticity (WHITEPAPER §6.5).

**blind-watermark** ([guofei9987](https://github.com/guofei9987/blind_watermark)).
Keyed DWT-DCT-SVD; survives JPEG well (to ~q50 in our test) but 0% under
screenshot/crop, like all embedded schemes.

**RivaGAN** ([arXiv:1909.01285](https://arxiv.org/abs/1909.01285)),
**perceptual hashing** (`ImageHash`: pHash/aHash/dHash). RivaGAN is a learned
robust watermark (~32 bits); perceptual hashes give content identity but not
authenticity (collisions findable), suitable only as a soft-binding lookup key.

**Signed QR** for provenance is commodity (transit tickets, EU Digital COVID
Certificate). Our contribution is the use context (agent-action receipts) and
the empirical demonstration (WHITEPAPER §6.5) that it dominates embedded
watermarks for artifacts that get screenshotted and re-cropped.

## Positioning

Prior identity work binds identity to a session/token/workload/tool-definition;
aiAuthZ binds a fresh HMAC to **every individual agent→tool message**, moves the
authorization decision **off-host**, and welds it to **survivable signed
receipts**. That composition — per-message granularity + cross-trust-domain
enforcement + forgery-resistant, geometrically-robust receipts — is the seam
that workload-identity systems, in-process agent defenses, and content
guardrails each leave open.
