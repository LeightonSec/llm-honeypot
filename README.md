# LLM Honeypot

A deliberately exposed fake AI assistant that logs and analyses attack attempts in real-time. Presents a convincing chat UI, silently runs detection on every prompt, classifies the attack type, and surfaces everything in a live dashboard.

Built on top of the [ai-firewall](../ai-firewall) detection engine.

---

## How it works

1. Visitors land on a fake AI assistant ("Aria by NexusAI Labs")
2. Every prompt is passed through the ai-firewall's two-layer detector (keyword scan + Claude API)
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

If you run the honeypot behind nginx, Caddy, Cloudflare, or any other reverse proxy, set `TRUST_PROXY=1` so the real visitor IP is extracted from `X-Forwarded-For`:

```
TRUST_PROXY=1
```

Leave it unset (or `TRUST_PROXY=0`) for direct internet exposure. When `TRUST_PROXY` is off, the honeypot uses the raw socket address — attackers cannot spoof their IP to bypass rate limiting or hide scripted scan patterns in the fingerprinting data.

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

Edit `.env` and add your Anthropic API key:

```
ANTHROPIC_API_KEY=sk-ant-...
```

> The key is used by the ai-firewall detector for semantic analysis. If `../ai-firewall` is unavailable, the honeypot falls back to local keyword-only detection automatically.

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
- Rotate your Anthropic API key if you suspect it has been exposed.
- The in-memory rate limit and fingerprint stores are not thread-safe. Run with a single worker (`python app.py`) rather than a multi-threaded WSGI server unless you add locking.
