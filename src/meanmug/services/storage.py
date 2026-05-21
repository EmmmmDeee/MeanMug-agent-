from __future__ import annotations

import aiosqlite

SCHEMA = """
CREATE TABLE IF NOT EXISTS audits (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    content    TEXT    NOT NULL,
    analysis   TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""


async def open_db(path: str) -> aiosqlite.Connection:
    db = await aiosqlite.connect(path)
    await db.executescript(SCHEMA)
    await db.commit()
    return db


async def record_audit(
    db: aiosqlite.Connection,
    user_id: int,
    content: str,
    analysis: str | None = None,
) -> None:
    await db.execute(
        "INSERT INTO audits (user_id, content, analysis) VALUES (?, ?, ?)",
        (user_id, content[:2000], analysis),
    )
    await db.commit()
