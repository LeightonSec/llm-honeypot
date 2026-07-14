# CLAUDE.md — LLM Honeypot

A deliberately exposed fake AI assistant ("Aria by NexusAI Labs") that silently logs and
classifies attack attempts in real-time. Three-layer LOCAL detection pipeline; patterns
derived from the ai-firewall project. Phase B semantic layer WIRED (G2, 2026-07-14) and
default-OFF: with `SEMANTIC_ENABLED=1`, the one ambiguous cell (unknown+MEDIUM) gets a
second opinion from the pinned ai-firewall judge — escalation-only, additive-only merge,
budget-capped. Design rationale lives in DECISIONS.md (P1–P6, G2-W); it wins over this file.

---

## SOC Toolkit Position

- **Layer:** Research (Layer 5)
- **Depends on:** with the semantic layer OFF (default), nothing external at runtime (Flask, pydantic, vaderSentiment, python-dotenv). With `SEMANTIC_ENABLED=1`: ai-firewall (pinned git dep @91fc9aa, installed `--no-deps`) + anthropic (pinned in the hashed lockfile)
- **Feeds into:** Incident Tracker (future), Unified Dashboard (future)
- **Gap it fills:** Live attack capture and classification against a realistic AI target

---

## Architecture

- `app.py` — Flask server, rate limiting, session fingerprinting, security headers, dashboard auth; owns the semantic layer's ledger + judge seam (G2-W)
- `classifier.py` — Full detection pipeline: sentiment → keyword/firewall → pattern classifier
- `semantic.py` — Phase B semantic layer: routing/admission/execution + additive-only merge; `evaluate()` is the ONLY path to the judge
- `sentiment.py` — Layer 1: VADER + emotion/framing detection, two-signal risk bump
- `db.py` — SQLite logging, attack storage, stats queries, inline schema migrations
- `templates/` — Honeypot face UI (Aria) and live dashboard

---

## Detection Pipeline — Three Layers

### Layer 1 — Sentiment (sentiment.py)
- VADER polarity scoring
- Emotion pattern matching: grief, urgency, sympathy, guilt
- Framing detection: grandmother, fictional_wrapper, roleplay, hypothetical, authority_claim
- Two-signal risk bump: emotional_loading >= 0.5 AND corroborating attack keyword
- Exception: grandmother framing bumps unconditionally — known high-confidence vector
- Prevents false positives on genuinely distressed users — do not change this logic

### Layer 2 — Keyword scanner (classifier.py, local-only)
- `_local_analyse()` runs unconditionally: weighted keyword/pattern scoring
- This LOCAL layer still has no ai-firewall import — the judge lives behind
  `semantic.evaluate()` (called from app.py, never from here). Legacy
  comments/docstrings in this file that call the local scan a "fallback" or
  reference an "LLM verdict" predate Phase A — clean up in G3

### Layer 3 — Pattern Classifier (classifier.py)
- NFKC normalisation + Cyrillic/Greek confusable map before matching
- Base64 payload extraction — decodes hidden instructions in encoded blobs
- Obfuscation scoring — detects character-level homoglyph evasion
- Five attack type classification with weighted pattern scoring
- Promotion: if pattern classifier says unknown but Layer 2 scored HIGH/JAILBREAK, promote to jailbreak (comments call this "LLM promotion" — legacy naming, the verdict is local)
- Sentiment risk bump applied after the keyword layer

---

## Attack Types Classified

| Type | What it catches |
|------|----------------|
| prompt_injection | Instruction overrides, system-prompt manipulation, template injection |
| jailbreak | DAN, developer mode, liberation framing, encoded payloads |
| data_extraction | Training data probing, system prompt leaks, config fishing |
| social_engineering | Authority claims, urgency, fictional wrappers, emotional manipulation |
| reconnaissance | Capability mapping, model fingerprinting, connection probing |

---

## Current Status

✅ Complete — LeightonSec/llm-honeypot
✅ Three-layer detection pipeline
✅ VADER sentiment analysis with emotion/framing detection
✅ Two-signal risk bump — prevents false positives on distressed users
✅ Unicode confusable normalisation — defeats homoglyph evasion
✅ Base64 payload extraction — catches encoded instruction injection
✅ Obfuscation scoring
✅ Five attack type classification
✅ Layer-2 verdict promotion logic (local)
✅ Session fingerprinting — SHA-256 prompt hashing, replay detection
✅ Partial LRU eviction — handles 10k+ IP floods safely
✅ Security headers — CSP, X-Frame-Options, nosniff, Referrer-Policy
✅ Dashboard secret protection via header or URL param
✅ Rate limiting — 20 requests per IP per 60 seconds
✅ TRUST_PROXY support for reverse proxy deployments
✅ Local pipeline + default-OFF semantic judge (ai-firewall pinned @91fc9aa; escalation-only, budget-capped, wired G2 2026-07-14)
✅ Crescendo attack analysis in ANALYSIS.md

---

## Security Configuration

- `DASHBOARD_SECRET` in `.env` — locks /dashboard, /api/attacks, /api/stats, /export
- `TRUST_PROXY=1` only behind a trusted reverse proxy — never on direct exposure
- `FLASK_DEBUG` never enabled on internet-facing host
- Rate limit store evicts oldest 20% at 10k IPs — not a full reset
- Fingerprint store clears both stores consistently at 50k entries
- The honeypot face is intentionally open — never run on infrastructure with internal access

---

## Known Issues

- Rate limit and fingerprint stores in-memory — reset on restart
- Single worker only — stores are not thread-safe for multi-worker WSGI
- AbuseIPDB not integrated — attacker IPs not enriched
- `datetime.utcnow()` deprecated in Python 3.12+ — replace with `datetime.now(datetime.UTC)` in db.py

---

## Next Steps

- Auto-POST to Incident Tracker on HIGH severity detections
- AbuseIPDB integration for attacker IP enrichment
- Persistent fingerprint store across restarts
- Unified Dashboard integration

---

## Tech Stack

- Python, Flask
- vaderSentiment
- SQLite
- python-dotenv
- Anthropic Claude API via the pinned ai-firewall library (Phase B semantic judge — default OFF)

---

## Security Rules

- `DASHBOARD_SECRET` in `.env` — never committed. `ANTHROPIC_API_KEY` ONLY when `SEMANTIC_ENABLED=1`, and only a dedicated spend-capped key (DECISIONS.md P2); never configure a credential on the honeypot host that no code uses
- `.env`, `venv/`, `honeypot.db` gitignored
- Never expose dashboard without DASHBOARD_SECRET set
- Never run with FLASK_DEBUG=1 on internet-facing host
- Never run behind a multi-worker WSGI server without adding store locking
- Rotate API key immediately if exposure suspected

---

## Conventions

- Detection pipeline always runs: sentiment → firewall → classifier — do not reorder
- Two-signal requirement in sentiment.py — do not remove the corroborating_signal check
- Grandmother exception is intentional — do not remove
- Attack categories defined in HONEYPOT_PATTERNS in classifier.py — add new types there only
- Fake responses defined in FAKE_RESPONSES in classifier.py — add new pools there only
- Normalise before pattern matching — always use normalize_for_matching()
- Severity always strings: "HIGH", "MEDIUM", "LOW"
- Schema migrations handled inline in init_db() — add new columns there, never recreate the table
- Severity always strings: "HIGH", "MEDIUM", "LOW"
- Port: 5001, host: 0.0.0.0 (intentional — honeypot must be reachable)