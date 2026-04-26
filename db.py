import sqlite3
import json
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), 'honeypot.db')


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS attacks (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp     TEXT NOT NULL,
                ip_address    TEXT,
                user_agent    TEXT,
                prompt        TEXT NOT NULL,
                response      TEXT,
                attack_type   TEXT,
                risk_level    TEXT,
                keyword_score INTEGER DEFAULT 0,
                keyword_matches TEXT DEFAULT '{}',
                api_verdict   TEXT,
                api_confidence TEXT,
                api_reason    TEXT,
                flags         TEXT DEFAULT '{}'
            )
        ''')
        # Migration: add flags to existing databases that pre-date this column
        try:
            conn.execute("ALTER TABLE attacks ADD COLUMN flags TEXT DEFAULT '{}'")
        except sqlite3.OperationalError:
            pass  # column already exists
        conn.commit()


def log_attack(ip: str, user_agent: str, prompt: str, analysis: dict) -> int:
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            '''INSERT INTO attacks
               (timestamp, ip_address, user_agent, prompt, response, attack_type,
                risk_level, keyword_score, keyword_matches, api_verdict, api_confidence,
                api_reason, flags)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (
                datetime.utcnow().isoformat(),
                ip,
                user_agent,
                prompt,
                analysis.get("fake_response", ""),
                analysis.get("attack_type", "unknown"),
                analysis.get("risk_level", "LOW"),
                analysis.get("keyword_score", 0),
                json.dumps(analysis.get("keyword_matches", {})),
                analysis.get("api_verdict", "UNKNOWN"),
                analysis.get("api_confidence", "UNKNOWN"),
                analysis.get("api_reason", ""),
                json.dumps(analysis.get("flags", {})),
            )
        )
        conn.commit()
        return cursor.lastrowid


def get_attacks(limit: int = 100, offset: int = 0) -> list:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            'SELECT * FROM attacks ORDER BY id DESC LIMIT ? OFFSET ?',
            (limit, offset)
        ).fetchall()

    result = []
    for row in rows:
        d = dict(row)
        for field in ('keyword_matches', 'flags'):
            try:
                d[field] = json.loads(d.get(field) or '{}')
            except (json.JSONDecodeError, TypeError):
                d[field] = {}
        result.append(d)
    return result


def get_stats() -> dict:
    with sqlite3.connect(DB_PATH) as conn:
        total = conn.execute('SELECT COUNT(*) FROM attacks').fetchone()[0]

        by_risk = {}
        for row in conn.execute(
            'SELECT risk_level, COUNT(*) FROM attacks GROUP BY risk_level'
        ).fetchall():
            by_risk[row[0]] = row[1]

        by_type = {}
        for row in conn.execute(
            'SELECT attack_type, COUNT(*) FROM attacks GROUP BY attack_type'
        ).fetchall():
            by_type[row[0]] = row[1]

        recent_rows = conn.execute(
            'SELECT id, timestamp, ip_address, attack_type, risk_level, prompt '
            'FROM attacks ORDER BY id DESC LIMIT 10'
        ).fetchall()

    recent = [
        dict(zip(["id", "timestamp", "ip_address", "attack_type", "risk_level", "prompt"], r))
        for r in recent_rows
    ]

    return {
        "total": total,
        "by_risk": by_risk,
        "by_type": by_type,
        "recent": recent,
    }


def export_all() -> list:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute('SELECT * FROM attacks ORDER BY id ASC').fetchall()

    result = []
    for row in rows:
        d = dict(row)
        for field in ('keyword_matches', 'flags'):
            try:
                d[field] = json.loads(d.get(field) or '{}')
            except (json.JSONDecodeError, TypeError):
                d[field] = {}
        result.append(d)
    return result
