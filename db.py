import json
import os
import sqlite3
from datetime import datetime, timezone

from pydantic import ValidationError

from schemas import AnalysisRecord
from semantic import DISAGREEMENTS, SKIP_REASONS, VERDICT_TO_SEVERITY

DB_PATH = os.path.join(os.path.dirname(__file__), 'honeypot.db')


def _vocab_check(col: str, values) -> str:
    """Column definition with a CHECK constraint derived from semantic.py (V5).

    Interpolating a Python collection into SQL is safe ONLY because every value
    is a hardcoded string literal defined in semantic.py, never derived from
    config or external input — nothing here is escaped. The assert below turns
    that discipline invariant into a schema-build-time check: a future
    vocabulary loaded from config or a plugin registry crashes loudly here
    instead of shipping a SQL injection vector.
    """
    for v in values:
        assert v.replace("_", "").isalnum(), f"unsafe value in vocab for {col}: {v!r}"
    vocab = ", ".join(f"'{v}'" for v in sorted(values))
    return f"TEXT CHECK ({col} IN ({vocab}) OR {col} IS NULL)"


# The three closed-vocabulary semantic columns (V5), generated from semantic.py's
# constants at schema-build time — never hand-copied lists. The judge's REASON is
# free text and deliberately has NO column (P4: no judge free text reaches
# storage or a render sink); CONFIDENCE is unpersisted until something consumes it.
SEMANTIC_COLUMNS = [
    ("semantic_verdict",      _vocab_check("semantic_verdict", set(VERDICT_TO_SEVERITY))),
    ("semantic_skip_reason",  _vocab_check("semantic_skip_reason", SKIP_REASONS)),
    ("semantic_disagreement", _vocab_check("semantic_disagreement", DISAGREEMENTS)),
]


def init_db():
    # Fresh databases get the semantic CHECK constraints via CREATE TABLE
    # (universal); pre-Phase-B databases get them via ALTER TABLE below. Both
    # paths consume SEMANTIC_COLUMNS — the vocabulary is derived once.
    semantic_defs = ",\n                ".join(
        f"{col} {definition}" for col, definition in SEMANTIC_COLUMNS
    )
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(f'''
            CREATE TABLE IF NOT EXISTS attacks (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       TEXT NOT NULL,
                ip_address      TEXT,
                user_agent      TEXT,
                prompt          TEXT NOT NULL,
                response        TEXT,
                attack_type     TEXT,
                risk_level      TEXT,
                keyword_score   INTEGER DEFAULT 0,
                keyword_matches TEXT DEFAULT '{{}}',
                api_verdict     TEXT,
                api_confidence  TEXT,
                api_reason      TEXT,
                flags           TEXT DEFAULT '{{}}',
                sentiment_score REAL DEFAULT 0.0,
                framing_type    TEXT DEFAULT 'none',
                {semantic_defs}
            )
        ''')  # gate: ignore — interpolated SQL is built only from semantic.py's hardcoded vocabularies, validated in _vocab_check; no external input can reach it
        # Migrations: add columns to databases that pre-date them
        for col, definition in [
            ("flags",           "TEXT DEFAULT '{}'"),
            ("sentiment_score", "REAL DEFAULT 0.0"),
            ("framing_type",    "TEXT DEFAULT 'none'"),
            *SEMANTIC_COLUMNS,
        ]:
            try:
                conn.execute(f"ALTER TABLE attacks ADD COLUMN {col} {definition}")
            except sqlite3.OperationalError as exc:
                # V5: ONLY "column already exists" may be swallowed. Anything
                # else — notably a platform refusing or not enforcing
                # ADD COLUMN ... CHECK — must surface loudly; swallowing it
                # would silently ship an unconstrained column, the exact
                # silent-weaker outcome V5 rejects.
                if "duplicate column name" not in str(exc):
                    raise
        conn.commit()


def log_attack(ip: str, user_agent: str, prompt: str, analysis: dict) -> int:
    try:
        record = AnalysisRecord(**analysis)
    except ValidationError:
        record = AnalysisRecord()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            '''INSERT INTO attacks
               (timestamp, ip_address, user_agent, prompt, response, attack_type,
                risk_level, keyword_score, keyword_matches, api_verdict, api_confidence,
                api_reason, flags, sentiment_score, framing_type,
                semantic_verdict, semantic_skip_reason, semantic_disagreement)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (
                datetime.now(timezone.utc).isoformat(),
                ip,
                user_agent,
                prompt,
                record.fake_response,
                record.attack_type,
                record.risk_level,
                record.keyword_score,
                json.dumps(record.keyword_matches),
                record.api_verdict,
                record.api_confidence,
                record.api_reason,
                json.dumps(record.flags),
                record.sentiment_score,
                record.framing_type,
                record.semantic_verdict,
                record.semantic_skip_reason,
                record.semantic_disagreement,
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
                parsed = json.loads(d.get(field) or '{}')  # gate: ignore — parses this app's own json.dumps output from a trusted DB column, guarded by try/except + isinstance
                d[field] = parsed if isinstance(parsed, dict) else {}
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


def purge_old_attacks(days: int = 90) -> int:
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "DELETE FROM attacks WHERE timestamp < datetime('now', ?)",
            (f"-{days} days",),
        )
        conn.commit()
        return cursor.rowcount


def get_retention_stats() -> dict:
    with sqlite3.connect(DB_PATH) as conn:
        total, oldest = conn.execute(
            "SELECT COUNT(*), MIN(timestamp) FROM attacks"
        ).fetchone()
        eligible = conn.execute(
            "SELECT COUNT(*) FROM attacks WHERE timestamp < datetime('now', '-90 days')"
        ).fetchone()[0]
    return {"total": total, "oldest_timestamp": oldest, "eligible_for_purge": eligible}


def export_all() -> list:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute('SELECT * FROM attacks ORDER BY id ASC').fetchall()

    result = []
    for row in rows:
        d = dict(row)
        for field in ('keyword_matches', 'flags'):
            try:
                parsed = json.loads(d.get(field) or '{}')  # gate: ignore — parses this app's own json.dumps output from a trusted DB column, guarded by try/except + isinstance
                d[field] = parsed if isinstance(parsed, dict) else {}
            except (json.JSONDecodeError, TypeError):
                d[field] = {}
        result.append(d)
    return result
