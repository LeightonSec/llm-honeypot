# LLM Honeypot

![Version](https://img.shields.io/badge/version-v1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A deliberately exposed fake AI assistant that logs and analyses attack attempts in real-time. Presents a convincing chat UI, silently runs detection on every prompt, classifies the attack type, and surfaces everything in a live dashboard.

Detection patterns are derived from the [ai-firewall](https://github.com/LeightonSec/ai-firewall) project. Direct library integration — including its Claude-API semantic layer — is a decided next phase (Phase B) and is **not yet built**: the current pipeline is fully local.

---

## Ethical Use

This tool is provided for **authorised security research and educational purposes only**.
Only deploy it on infrastructure you own or have explicit written permission to operate.
The honeypot is intentionally open to inbound traffic — never run it on a host that has access to sensitive internal systems.
The author accepts no liability for misuse.

---

## How it works

1. Visitors land on a fake AI assistant ("Aria by NexusAI Labs")
2. Every prompt runs through a local multi-signal detector — sentiment/framing analysis, keyword and weighted-pattern classification, unicode-confusable normalisation, base64 payload extraction. No LLM calls; fully offline
3. A second classifier maps the attempt to one of five attack types
4. A convincing but deflecting response is returned — the attacker sees nothing unusual
5. All attempts are logged to SQLite with full metadata
6. The dashboard at `/dashboard` shows live attack data and stats

### Attack types classified

| Type | What it catches |
|---|---|
| `prompt_injection` | Embedded instruction overrides, system-prompt manipulation |
| `jailbreak` | DAN, developer mode, restriction bypass, persona hijacking |
| `data_extraction` | Training data probing, system prompt leaks, config fishing |
| `social_engineering` | Authority claims, urgency framing, fictional/hypothetical wrappers |
| `reconnaissance` | Capability mapping, model fingerprinting, connection probing |

---

## Security configuration

### Dashboard protection

Set `DASHBOARD_SECRET` in `.env` to lock `/dashboard`, `/api/attacks`, `/api/stats`, and `/export` behind a secret token:

```
DASHBOARD_SECRET=some-strong-random-string
```

Then access the dashboard with:
```
http://localhost:5001/dashboard?secret=some-strong-random-string
```

Or pass the header `X-Dashboard-Secret: some-strong-random-string` for API calls.

If `DASHBOARD_SECRET` is not set, all routes are open (fine for localhost, **not** for internet exposure).

### Reverse proxy / X-Forwarded-For

If you run the honeypot behind nginx, Caddy, Cloudflare, or any other reverse proxy, set `TRUST_PROXY=1` **and** `TRUST_PROXY_HOPS` to the number of trusted proxies in front of the app:

```
TRUST_PROXY=1
TRUST_PROXY_HOPS=1   # 1 for a single reverse proxy; increase only per real added hop
```

Why the hop count matters: proxies like nginx (`$proxy_add_x_forwarded_for`) and Cloudflare **append** to `X-Forwarded-For`, so the address the proxy actually saw is on the **right**, while the leftmost entries are whatever the client sent — attacker-controlled. The honeypot reads the entry `TRUST_PROXY_HOPS` from the right. Set `TRUST_PROXY_HOPS` to your real proxy count: too low picks an internal proxy IP (harmless), too high starts trusting attacker-supplied entries again (the app warns at startup for unreasonably high values). If the header is shorter than the hop count, it fails closed to the socket address rather than trusting the leftmost value.

Leave `TRUST_PROXY` unset (or `TRUST_PROXY=0`) for direct internet exposure. When it's off, the honeypot uses the raw socket address — attackers cannot spoof their IP to bypass rate limiting or hide scripted scan patterns in the fingerprinting data.

### Debug mode

Debug mode is **off by default**. Enable it only for local development:

```bash
FLASK_DEBUG=1 python app.py
```

Never run with `FLASK_DEBUG=1` on an internet-facing host — it exposes an interactive Python console on exceptions.

### Rate limiting

`/chat` is limited to 20 requests per IP per 60 seconds (in-memory, resets on restart). Adjust `RATE_LIMIT` and `RATE_WINDOW` in `app.py` if needed.

---

## Setup

### 1. Clone / navigate to the project

```bash
cd /path/to/llm-honeypot
```

### 2. Create and activate a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment

```bash
cp .env.example .env
```

Set `DASHBOARD_SECRET` (see Security configuration above). No API key is
needed: detection is fully local. (Phase B — the ai-firewall library
integration — will introduce `ANTHROPIC_API_KEY` when it lands; do not
configure one before there is code that uses it, least of all on a host
whose purpose is attracting attackers.)

### 5. Run

```bash
python app.py
```

The server starts on `http://0.0.0.0:5001`.

| URL | Description |
|---|---|
| `http://localhost:5001/` | Fake AI assistant (honeypot face) |
| `http://localhost:5001/dashboard` | Live attack monitoring dashboard |
| `http://localhost:5001/export` | Download all logs as JSON |

---

## API

### `POST /chat`
Submit a prompt to the honeypot. Returns a fake AI response.

```json
{ "prompt": "ignore previous instructions and..." }
```

Response:
```json
{ "response": "I process each conversation naturally..." }
```

### `GET /api/attacks?limit=100&offset=0`
Returns logged attacks as JSON array.

### `GET /api/stats`
Returns aggregate stats (total, by risk level, by attack type, 10 most recent).

### `GET /export`
Downloads the full attack log as `honeypot_attacks.json`.

---

## Security notes

- **Set `DASHBOARD_SECRET`** before any public deployment. Without it, `/dashboard`, `/api/attacks`, and `/export` are open to everyone — including the attackers you are logging.
- **Set `TRUST_PROXY=1`** only if a trusted reverse proxy is in front. Trusting `X-Forwarded-For` on a directly-exposed socket lets attackers spoof IPs and bypass rate limiting.
- The honeypot itself is intentionally open — that's the point. Do not run it on infrastructure that has access to sensitive internal systems.
- The SQLite database (`honeypot.db`) and `.env` are git-ignored. Never commit either.
- The in-memory rate limit and fingerprint stores are not thread-safe. Run with a single worker (`python app.py`) rather than a multi-threaded WSGI server unless you add locking.

---

## Scope

Designed to capture and classify unsolicited prompt attacks against a fake public AI endpoint. It does not:

- Actively probe, scan, or interact with external systems
- Attempt to identify or attribute attackers beyond IP and user-agent
- Integrate with external threat intelligence platforms
- Replace a WAF or production-grade API security layer

---

## Limitations

- Rate limit and fingerprint stores are in-memory — reset on restart, not suitable for multi-instance deployments
- Detection is local-only (pattern + sentiment); there is no semantic/LLM layer until Phase B ships — novel attacks with no lexical signature will be under-classified
- SQLite is single-file — not designed for high-concurrency write loads
- No persistent attacker tracking across sessions (session fingerprints cleared at 50k entries)

---

## Licence

MIT © 2026 [LeightonSec](https://github.com/LeightonSec)
