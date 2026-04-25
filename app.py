import os
import json
from collections import defaultdict
from time import time

from flask import Flask, request, jsonify, render_template, Response

from classifier import analyse_and_classify
from db import init_db, log_attack, get_attacks, get_stats, export_all

app = Flask(__name__)
init_db()

DASHBOARD_SECRET = os.environ.get('DASHBOARD_SECRET', '')

_rate_store: dict = defaultdict(list)
RATE_LIMIT  = 20   # max requests per IP
RATE_WINDOW = 60   # seconds


def get_client_ip() -> str:
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        ip = forwarded.split(',')[0].strip()
        # Sanitise: printable ASCII only, max IPv6 length (45 chars)
        ip = ''.join(c for c in ip if c.isprintable() and c not in '\r\n')[:45]
        return ip or '0.0.0.0'
    return request.remote_addr or '0.0.0.0'


def is_rate_limited(ip: str) -> bool:
    now = time()
    _rate_store[ip] = [t for t in _rate_store[ip] if now - t < RATE_WINDOW]
    if len(_rate_store[ip]) >= RATE_LIMIT:
        return True
    _rate_store[ip].append(now)
    if len(_rate_store) > 10000:
        _rate_store.clear()
    return False


def dashboard_auth_error():
    """Return a 401 Response if DASHBOARD_SECRET is set and the request lacks it.
    Pass secret via ?secret=VALUE or X-Dashboard-Secret header."""
    if not DASHBOARD_SECRET:
        return None  # no secret configured — allow (local use)
    provided = (
        request.args.get('secret', '')
        or request.headers.get('X-Dashboard-Secret', '')
    )
    if provided != DASHBOARD_SECRET:
        return Response('Unauthorized', 401)
    return None


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
    log_attack(ip, user_agent, prompt, analysis)

    return jsonify({'response': analysis['fake_response']})


@app.route('/dashboard')
def dashboard():
    err = dashboard_auth_error()
    if err:
        return err
    return render_template('dashboard.html')


@app.route('/api/attacks')
def api_attacks():
    err = dashboard_auth_error()
    if err:
        return err
    try:
        limit  = min(int(request.args.get('limit', 50)), 500)
        offset = max(int(request.args.get('offset', 0)), 0)
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid parameters'}), 400
    return jsonify(get_attacks(limit, offset))


@app.route('/api/stats')
def api_stats():
    err = dashboard_auth_error()
    if err:
        return err
    return jsonify(get_stats())


@app.route('/export')
def export():
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
