import hashlib
import hmac
import ipaddress
import json
import os
import sys
import threading
from collections import defaultdict
from time import time

from flask import Flask, Response, jsonify, render_template, request
from pydantic import ValidationError

from classifier import analyse_and_classify
from db import export_all, get_attacks, get_stats, init_db, log_attack
from schemas import AttackFilter, ChatRequest

DASHBOARD_SECRET = os.environ.get('DASHBOARD_SECRET', '')
DAST_MODE = os.environ.get('DAST_MODE', '').lower() == 'true'
# TRUST_PROXY must be set explicitly; without it X-Forwarded-For is ignored so
# attackers can't spoof their IP to bypass rate limiting or fingerprinting.
TRUST_PROXY = os.environ.get('TRUST_PROXY', '0') == '1'
# Number of trusted proxy hops in front of the app (only consulted when
# TRUST_PROXY=1). Appending proxies — nginx `$proxy_add_x_forwarded_for`,
# Cloudflare — push the REAL client toward the RIGHT of X-Forwarded-For: the
# leftmost entries are whatever the client sent (attacker-controlled), and each
# trusted proxy appends one entry on the right. The real client is therefore
# the entry TRUST_PROXY_HOPS from the right. This MUST equal the actual number
# of trusted proxies: set it too high and you start trusting attacker-supplied
# leftward entries again (see DECISIONS.md "XFF leftmost-trust").
try:
    TRUST_PROXY_HOPS = max(1, int(os.environ.get('TRUST_PROXY_HOPS', '1')))
except ValueError:
    TRUST_PROXY_HOPS = 1
# Loud signal on an almost-certainly-wrong value. max() guards the low end, but
# nothing stops a typo (TRUST_PROXY_HOPS=50) from silently walking the trust
# boundary back toward the client-controlled leftmost entries. More than a
# handful of trusted proxies is real but rare; warn rather than hard-fail so a
# genuine deep chain still works, but the misconfiguration is never silent.
_SANE_MAX_HOPS = 8
if TRUST_PROXY and TRUST_PROXY_HOPS > _SANE_MAX_HOPS:
    print(
        f"WARNING: TRUST_PROXY_HOPS={TRUST_PROXY_HOPS} is unusually high "
        f"(> {_SANE_MAX_HOPS}). If this exceeds your real proxy count, "
        f"attacker-supplied X-Forwarded-For entries become trusted. Verify topology.",
        file=sys.stderr,
    )

app = Flask(__name__)
init_db()

if not DASHBOARD_SECRET:
    import sys
    print(
        "WARNING: DASHBOARD_SECRET is not set. "
        "Dashboard, API, and export endpoints are publicly accessible. "
        "Set DASHBOARD_SECRET in your environment before any public deployment.",
        file=sys.stderr,
    )

if DAST_MODE:
    import sys
    print(
        "WARNING: DAST_MODE is active — /chat responses include classification metadata. "
        "Disable before any public deployment.",
        file=sys.stderr,
    )

_rate_lock = threading.Lock()
_fp_lock   = threading.Lock()

_rate_store: dict = defaultdict(list)
RATE_LIMIT  = 20   # max requests per IP
RATE_WINDOW = 60   # seconds

# Session fingerprinting: track payload hashes to detect replay and scripted scans
_fingerprint_counts: dict = {}          # prompt_hash -> times seen (any IP)
_ip_payload_counts: dict = defaultdict(set)  # ip -> set of distinct payload hashes


def get_client_ip() -> str:
    if TRUST_PROXY:
        forwarded = request.headers.get('X-Forwarded-For', '')
        if forwarded:
            # Strip whitespace and drop empty entries (e.g. from a trailing
            # comma) before indexing, so positions count real hops only.
            parts = [p.strip() for p in forwarded.split(',') if p.strip()]
            # Take the entry our OWN trusted proxy chain observed, counting from
            # the RIGHT. The leftmost entries are whatever the client sent —
            # attacker-controlled — so the previous `split(',')[0]` trusted the
            # spoof directly. FAIL CLOSED when the header is shorter than our
            # topology: falling back to parts[0] there would trust that same
            # leftmost spoof, so instead fall through to remote_addr (the
            # proxy's own IP — over-restrictive, i.e. safe, not exploitable).
            if len(parts) >= TRUST_PROXY_HOPS:
                candidate = parts[-TRUST_PROXY_HOPS]
                # Sanitise: printable ASCII only, max IPv6 length (45 chars).
                sanitised = ''.join(c for c in candidate if c.isprintable() and c not in '\r\n')[:45]
                try:
                    ipaddress.ip_address(sanitised)
                    return sanitised
                except ValueError:
                    pass  # not a valid IP — fall through to remote_addr
    return request.remote_addr or '0.0.0.0'


def is_rate_limited(ip: str) -> bool:
    now = time()
    with _rate_lock:
        window = [t for t in _rate_store[ip] if now - t < RATE_WINDOW]
        if len(window) >= RATE_LIMIT:
            _rate_store[ip] = window
            return True
        window.append(now)
        _rate_store[ip] = window
        # Partial LRU eviction: drop the oldest 20% of IPs rather than clearing all,
        # so a 10 001-IP flood can't reset every rate limit simultaneously.
        if len(_rate_store) > 10_000:
            for k in list(_rate_store)[:2_000]:
                del _rate_store[k]
    return False


def _prompt_fingerprint(prompt: str) -> str:
    """Stable SHA-256 hash of a normalised prompt — used for replay detection."""
    normalised = prompt.strip().lower()
    return hashlib.sha256(normalised.encode()).hexdigest()[:16]


def _check_fingerprint(ip: str, prompt: str) -> dict:
    """Record this (ip, prompt) pair and return replay/scan context."""
    fp = _prompt_fingerprint(prompt)
    with _fp_lock:
        prior = _fingerprint_counts.get(fp, 0)
        _fingerprint_counts[fp] = prior + 1
        _ip_payload_counts[ip].add(fp)
        ip_unique = len(_ip_payload_counts[ip])
        # Evict when stores grow very large (long-running deployments).
        # Both stores are cleared together to keep them consistent.
        if len(_fingerprint_counts) > 50_000:
            _fingerprint_counts.clear()
            _ip_payload_counts.clear()
    return {
        "payload_hash": fp,
        "prior_occurrences": prior,
        "is_replay": prior > 0,
        "ip_unique_payloads": ip_unique,
    }


def dashboard_auth_error():
    """Return a 401 Response if DASHBOARD_SECRET is set and the request lacks it.
    Pass secret via X-Dashboard-Secret header or ?secret= URL parameter."""
    if not DASHBOARD_SECRET:
        return None  # no secret configured — allow (local use)
    # Raw secret token compared in constant time below; not schema-validatable input.
    provided = request.headers.get('X-Dashboard-Secret', '') or request.args.get('secret', '')  # gate: ignore — secret token equality check, not a data sink
    if not hmac.compare_digest(provided, DASHBOARD_SECRET):
        return Response('Unauthorized', 401)
    return None


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    return response


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/chat', methods=['POST'])  # gate: ignore — local honeypot, unauthenticated POST by design, documented in Gate 2 trust boundary map
def chat():
    ip = get_client_ip()
    if is_rate_limited(ip):
        return jsonify({'error': 'Too many requests'}), 429

    raw = request.get_json(silent=True) or {}  # gate: ignore — validated immediately via ChatRequest pydantic model below
    try:
        body = ChatRequest(**raw)
    except ValidationError:
        return jsonify({'error': 'No prompt provided'}), 400
    prompt = body.prompt.strip()
    if not prompt:
        return jsonify({'error': 'No prompt provided'}), 400

    user_agent = request.headers.get('User-Agent', '')[:512]

    analysis = analyse_and_classify(prompt)
    analysis["flags"] = _check_fingerprint(ip, prompt)
    log_attack(ip, user_agent, prompt, analysis)

    if DAST_MODE:
        return jsonify({
            'response': analysis['fake_response'],
            'classification': analysis['attack_type'],
            'risk_level': analysis['risk_level'],
            'api_verdict': analysis.get('api_verdict', ''),
        })
    return jsonify({'response': analysis['fake_response']})


@app.route('/dashboard')
def dashboard():
    err = dashboard_auth_error()
    if err:
        return err
    return render_template('dashboard.html', dashboard_secret=DASHBOARD_SECRET)


@app.route('/api/attacks')
def api_attacks():
    ip = get_client_ip()
    if is_rate_limited(ip):
        return jsonify({'error': 'Too many requests'}), 429
    err = dashboard_auth_error()
    if err:
        return err
    try:
        filters = AttackFilter(
            limit=request.args.get('limit', 50),    # gate: ignore — validated by AttackFilter pydantic model (bounds + type coercion)
            offset=request.args.get('offset', 0),    # gate: ignore — validated by AttackFilter pydantic model (bounds + type coercion)
        )
    except ValidationError:
        return jsonify({'error': 'Invalid parameters'}), 400
    return jsonify(get_attacks(filters.limit, filters.offset))


@app.route('/api/stats')
def api_stats():
    ip = get_client_ip()
    if is_rate_limited(ip):
        return jsonify({'error': 'Too many requests'}), 429
    err = dashboard_auth_error()
    if err:
        return err
    return jsonify(get_stats())


@app.route('/export')
def export():
    ip = get_client_ip()
    if is_rate_limited(ip):
        return jsonify({'error': 'Too many requests'}), 429
    err = dashboard_auth_error()
    if err:
        return err
    data = export_all()
    json_str = json.dumps(data, indent=2, default=str)
    return Response(
        json_str,
        mimetype='application/json',
        headers={'Content-Disposition': 'attachment; filename=honeypot_attacks.json'},
    )


if __name__ == '__main__':
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(debug=debug, host='0.0.0.0', port=5001)
