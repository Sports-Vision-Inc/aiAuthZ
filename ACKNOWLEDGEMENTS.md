# Acknowledgements

aiAuthZ is the work of a small team standing on the shoulders of a much
larger one. This file is the canonical place to see the people and
projects whose research, code, and operational experience made this
possible.

If your name belongs here and is missing, open a PR. We will accept it.

## Research that shaped the threat model

- Shapira, N., Wendler, C., Yen, A., Bau, D., et al.
  *Agents of Chaos.* arXiv:2602.20021 (2026).
  The eleven case studies in the paper are the design specification
  this gateway answers to. We consider every one of the named
  red-teamers (Natalie, Chris, Avery, Andy, Adam, Alex, Aditya, Sam,
  Olivia, EunJeong, Hadas, Negev, Tomer, Atai, Christoph, Jaden,
  Sigi, Ayelet, Yotam) co-authors of the threat model.
- The OWASP Foundation contributors who produced the
  *OWASP Top 10 for Large Language Model Applications, version 2025.*
- The NIST team behind the *AI Risk Management Framework* and the
  *AI Test, Evaluation, Validation, and Verification* working group.
- Greshake et al., *Not what you've signed up for*, the original
  indirect-prompt-injection paper.
- Lynch, Wright, Larson et al., *Agentic Misalignment*, the empirical
  study of insider-threat behavior in long-running agents.

## Code we depend on

- **Anthropic Python SDK** — `anthropic`. Drives the validator's
  model-mediated suite.
- **OpenRouter** — multi-vendor inference; lets the validator drive
  Claude, OpenAI, and other Claude-family models through a single
  client.
- **NousResearch / hermes-agent** — the agent runtime we wired aiAuthZ
  into for the L3 evaluation.
- **openclaw / openclaw** — the agent runtime referenced throughout
  the *Agents of Chaos* paper; the streamable-http MCP support in
  this repo was added so that integration is round-trip clean.
- **Model Context Protocol** maintainers — the specification this
  gateway speaks fluently.
- **FastAPI**, **SQLAlchemy**, **Pydantic**, **Pillow**, **PyWavelets**,
  **NumPy**, **cryptography**, **fakeredis**, **httpx**, **uvicorn**,
  **typer**, **rich** — the Python ecosystem this project depends on
  for its day-to-day mechanics.
- **garak** (Leon Derczynski et al.), **promptfoo**, **mcp-scan**
  (Lasso Security) — open-source LLM red-teaming tools we recommend
  to anyone running aiAuthZ in production.

## Drafting and review

- **Claude Code** (Anthropic), used as a coding assistant under
  human review. Substantial fractions of the implementation, tests,
  and prose in this repository were drafted with its help. Errors
  remain ours.

## Sponsors and operators

This space is for individual sponsors, advisors, and operators who
contribute time, infrastructure, or capital to the SportsVision AI
mission. Open a PR to add yourself.

## A note on the SportsVision AI mission

[SportsVision AI](https://www.sportsvision.ai) builds AI agents with
video understanding for sports. We use that surface — the most
universally accessible language we know — to teach math, science,
art, teamwork, and social equality to underrepresented athletes who
would not otherwise see those tools at home or in school. aiAuthZ is
the identity layer that runs the platform. Sponsorship of this repo
funds the platform that runs the programs.
