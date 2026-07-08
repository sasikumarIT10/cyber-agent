"""SQLite-backed persistence for the Cybersecurity AI Agent.

Survives device restarts — stores:
  - Conversation history (messages per session)
  - Rate-limit counters (requests per API key per window)
  - Auth lockout state (failed attempts per IP)
  - Agent runtime metadata (last start, clean shutdown flag)
"""

import json
import sqlite3
import time
import logging
import threading
from pathlib import Path
from contextlib import contextmanager
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_DB_PATH = Path(__file__).parent / "data" / "agent_state.db"
_lock = threading.Lock()


def _ensure_dir():
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)


@contextmanager
def _conn():
    """Thread-safe SQLite connection context manager."""
    _ensure_dir()
    connection = sqlite3.connect(str(_DB_PATH), timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")  # better concurrent reads
    connection.execute("PRAGMA busy_timeout=5000")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db():
    """Create tables if they don't exist. Call once at startup."""
    with _conn() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS conversations (
                session_id  TEXT NOT NULL,
                seq         INTEGER NOT NULL,
                role        TEXT NOT NULL,
                content     TEXT NOT NULL,
                created_at  TEXT DEFAULT (datetime('now')),
                PRIMARY KEY (session_id, seq)
            );

            CREATE TABLE IF NOT EXISTS rate_limits (
                api_key     TEXT NOT NULL,
                window_start REAL NOT NULL,
                request_count INTEGER DEFAULT 1,
                PRIMARY KEY (api_key)
            );

            CREATE TABLE IF NOT EXISTS lockouts (
                ip_address  TEXT PRIMARY KEY,
                attempts    INTEGER DEFAULT 0,
                locked_until REAL DEFAULT 0,
                last_attempt REAL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS runtime_meta (
                key   TEXT PRIMARY KEY,
                value TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_conv_session ON conversations(session_id);
            CREATE INDEX IF NOT EXISTS idx_lockout_ip ON lockouts(ip_address);
        """)
        # Mark startup
        db.execute(
            "INSERT OR REPLACE INTO runtime_meta(key, value) VALUES (?, ?)",
            ("last_start", datetime.now(timezone.utc).isoformat()),
        )
        db.execute(
            "INSERT OR REPLACE INTO runtime_meta(key, value) VALUES (?, ?)",
            ("clean_shutdown", "false"),
        )
    logger.info("Persistence DB initialized at %s", _DB_PATH)


def mark_clean_shutdown():
    """Called during graceful shutdown."""
    try:
        with _conn() as db:
            db.execute(
                "INSERT OR REPLACE INTO runtime_meta(key, value) VALUES (?, ?)",
                ("clean_shutdown", "true"),
            )
            db.execute(
                "INSERT OR REPLACE INTO runtime_meta(key, value) VALUES (?, ?)",
                ("last_shutdown", datetime.now(timezone.utc).isoformat()),
            )
        logger.info("Clean shutdown recorded.")
    except Exception as e:
        logger.error("Failed to record shutdown: %s", e)


def was_clean_shutdown() -> bool:
    """Check if the previous run ended cleanly."""
    try:
        with _conn() as db:
            row = db.execute(
                "SELECT value FROM runtime_meta WHERE key='clean_shutdown'"
            ).fetchone()
            return row and row["value"] == "true"
    except Exception:
        return False


# ---------- Conversation persistence ----------

def save_message(session_id: str, role: str, content: str):
    """Append a message to a conversation session."""
    with _lock:
        with _conn() as db:
            seq = db.execute(
                "SELECT COALESCE(MAX(seq), -1) + 1 FROM conversations WHERE session_id=?",
                (session_id,),
            ).fetchone()[0]
            db.execute(
                "INSERT INTO conversations(session_id, seq, role, content) VALUES (?, ?, ?, ?)",
                (session_id, seq, role, content),
            )


def load_conversation(session_id: str) -> list[dict]:
    """Load all messages for a session, ordered."""
    with _conn() as db:
        rows = db.execute(
            "SELECT role, content FROM conversations WHERE session_id=? ORDER BY seq",
            (session_id,),
        ).fetchall()
        return [{"role": r["role"], "content": r["content"]} for r in rows]


def list_sessions(limit: int = 20) -> list[dict]:
    """List recent conversation sessions."""
    with _conn() as db:
        rows = db.execute("""
            SELECT session_id, MIN(created_at) as started, MAX(created_at) as last_msg,
                   COUNT(*) as msg_count
            FROM conversations
            GROUP BY session_id
            ORDER BY last_msg DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]


def delete_old_conversations(days: int = 30):
    """Purge conversations older than N days."""
    with _conn() as db:
        db.execute(
            "DELETE FROM conversations WHERE created_at < datetime('now', ?)",
            (f"-{days} days",),
        )
        deleted = db.execute("SELECT changes()").fetchone()[0]
        if deleted:
            logger.info("Purged %d old conversation messages", deleted)


# ---------- Rate-limit persistence ----------

def get_rate_count(api_key: str, window_seconds: int = 60) -> int:
    """Get current request count for an API key within the rate window."""
    now = time.time()
    with _conn() as db:
        row = db.execute(
            "SELECT window_start, request_count FROM rate_limits WHERE api_key=?",
            (api_key,),
        ).fetchone()
        if row and (now - row["window_start"]) < window_seconds:
            return row["request_count"]
        return 0


def increment_rate_count(api_key: str, window_seconds: int = 60):
    """Increment the rate counter, resetting if the window has expired."""
    now = time.time()
    with _lock:
        with _conn() as db:
            row = db.execute(
                "SELECT window_start, request_count FROM rate_limits WHERE api_key=?",
                (api_key,),
            ).fetchone()
            if row and (now - row["window_start"]) < window_seconds:
                db.execute(
                    "UPDATE rate_limits SET request_count = request_count + 1 WHERE api_key=?",
                    (api_key,),
                )
            else:
                db.execute(
                    "INSERT OR REPLACE INTO rate_limits(api_key, window_start, request_count) VALUES (?, ?, 1)",
                    (api_key, now),
                )


# ---------- Lockout persistence ----------

def get_lockout(ip: str) -> dict:
    """Get lockout state for an IP."""
    with _conn() as db:
        row = db.execute(
            "SELECT attempts, locked_until, last_attempt FROM lockouts WHERE ip_address=?",
            (ip,),
        ).fetchone()
        if row:
            return {"attempts": row["attempts"], "locked_until": row["locked_until"], "last_attempt": row["last_attempt"]}
        return {"attempts": 0, "locked_until": 0, "last_attempt": 0}


def record_failed_auth(ip: str, lockout_duration: int = 900):
    """Record a failed auth attempt; auto-lock after 5 failures."""
    now = time.time()
    with _lock:
        with _conn() as db:
            row = db.execute(
                "SELECT attempts FROM lockouts WHERE ip_address=?", (ip,)
            ).fetchone()
            attempts = (row["attempts"] + 1) if row else 1
            locked_until = (now + lockout_duration) if attempts >= 5 else 0
            db.execute(
                "INSERT OR REPLACE INTO lockouts(ip_address, attempts, locked_until, last_attempt) VALUES (?, ?, ?, ?)",
                (ip, attempts, locked_until, now),
            )
            if attempts >= 5:
                logger.warning("IP %s locked out after %d failed attempts", ip, attempts)


def is_locked_out(ip: str) -> bool:
    """Check if an IP is currently locked out."""
    state = get_lockout(ip)
    if state["locked_until"] > time.time():
        return True
    # If lockout expired, reset
    if state["locked_until"] > 0 and state["locked_until"] <= time.time():
        clear_lockout(ip)
    return False


def clear_lockout(ip: str):
    """Clear lockout for an IP (e.g., after expiry or manual reset)."""
    with _conn() as db:
        db.execute("DELETE FROM lockouts WHERE ip_address=?", (ip,))


def reset_all_lockouts():
    """Clear all expired lockouts on startup."""
    now = time.time()
    with _conn() as db:
        db.execute("DELETE FROM lockouts WHERE locked_until > 0 AND locked_until <= ?", (now,))


# ---------- Startup recovery ----------

def startup_recovery():
    """Run on agent startup to recover from unclean shutdown."""
    if not was_clean_shutdown():
        logger.warning("Previous shutdown was NOT clean — running recovery...")
    else:
        logger.info("Previous shutdown was clean.")

    # Clean up expired lockouts
    reset_all_lockouts()

    # Purge old conversations (older than 30 days)
    delete_old_conversations(30)

    logger.info("Startup recovery complete.")
