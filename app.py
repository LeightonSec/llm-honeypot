import ipaddress
import os
import json
import hashlib
import threading
from collections import defaultdict
from time import time

from flask import Flask, request, jsonify, render_template, Response

from classifier import analyse_and_classify
from db import init_db, log_attack, get_attacks, get_stats, export_all

DASHBOARD_SECRET = os.environ.get('DASHBOARD_SECRET', '')
# TRUST_PROXY must be set explicitly; without it X-Forwarded-For is ignored so
# attackers can't spoof their IP to bypass rate limiting or fingerprinting.
TRUST_PROXY = os.environ.get('TRUST_PROXY', '0') == '1'

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
            raw = forwarded.split(',')[0].strip()
            # Sanitise: printable ASCII only, max IPv6 length (45 chars)
            sanitised = ''.join(c for c in raw if c.isprintable() and c not in '\r\n')[:45]
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
    provided = request.headers.get('X-Dashboard-Secret', '') or request.args.get('secret', '')
    if provided != DASHBOARD_SECRET:
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


@app.route('/chat', methods=['POST'])
def chat():
    ip = get_client_ip()
    if is_rate_limited(ip):
        return jsonify({'error': 'Too many requests'}), 429

    data = request.get_json(silent=True) or {}
    prompt = (data.get('prompt') or '').strip()

    if not prompt:
        return jsonify({'error': 'No prompt provided'}), 400
    if len(prompt) > 4000:
        return jsonify({'error': 'Message too long'}), 400

    user_agent = request.headers.get('User-Agent', '')[:512]

    analysis = analyse_and_classify(prompt)
    analysis["flags"] = _check_fingerprint(ip, prompt)
    log_attack(ip, user_agent, prompt, analysis)

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
        limit  = max(0, min(int(request.args.get('limit', 50)), 500))
        offset = max(int(request.args.get('offset', 0)), 0)
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid parameters'}), 400
    return jsonify(get_attacks(limit, offset))


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
