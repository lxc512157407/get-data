"""
📦 极简攻击向量知识库 - 公开仓库专用

这是可以 100% 公开的极简版本，只负责存储采集到的情报
"""
import sqlite3
from pathlib import Path
from contextlib import contextmanager


@contextmanager
def get_db():
    db_path = Path(__file__).parent.parent.parent / "attack_vectors.db"
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    _init_db(conn)
    try:
        yield conn
    finally:
        conn.close()


def _init_db(conn):
    conn.execute("""
    CREATE TABLE IF NOT EXISTS attack_vectors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT UNIQUE,
        source TEXT,
        category TEXT DEFAULT 'intelligence',
        created_at TEXT,
        collected_at TEXT
    )
    """)
    conn.commit()


def insert_vector(conn, title: str, source: str, category: str = "intelligence"):
    from datetime import datetime
    cursor = conn.execute("""
    INSERT OR IGNORE INTO attack_vectors (title, source, category, created_at, collected_at)
    VALUES (?, ?, ?, ?, ?)
    """, (
        title,
        source,
        category,
        datetime.now().isoformat(),
        datetime.now().isoformat()
    ))
    conn.commit()
    return cursor.rowcount > 0


def get_stats(conn):
    cursor = conn.execute("SELECT COUNT(*) FROM attack_vectors")
    total = cursor.fetchone()[0]
    return {"total_vectors": total}


def vector_exists(conn, title: str) -> bool:
    cursor = conn.execute("SELECT 1 FROM attack_vectors WHERE title = ? LIMIT 1", (title,))
    return cursor.fetchone() is not None
