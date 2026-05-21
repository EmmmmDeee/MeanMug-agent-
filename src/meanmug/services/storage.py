from __future__ import annotations

import aiosqlite

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL UNIQUE,
    user_id    INTEGER NOT NULL,
    status     TEXT    NOT NULL DEFAULT 'open',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    closed_at  DATETIME
);

CREATE TABLE IF NOT EXISTS audits (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    content    TEXT    NOT NULL,
    analysis   TEXT,
    case_id    INTEGER REFERENCES cases(id),
    refusal    INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audits_user ON audits(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audits_case ON audits(case_id, created_at DESC);
"""

_ADDITIVE_COLUMNS = (
    ("analysis", "ALTER TABLE audits ADD COLUMN analysis TEXT"),
    ("case_id", "ALTER TABLE audits ADD COLUMN case_id INTEGER REFERENCES cases(id)"),
    ("refusal", "ALTER TABLE audits ADD COLUMN refusal INTEGER NOT NULL DEFAULT 0"),
)


async def open_db(path: str) -> aiosqlite.Connection:
    db = await aiosqlite.connect(path)
    await db.executescript(SCHEMA)
    await _migrate(db)
    await db.commit()
    return db


async def _migrate(db: aiosqlite.Connection) -> None:
    async with db.execute("PRAGMA table_info(audits)") as cur:
        cols = {row[1] for row in await cur.fetchall()}
    for col, ddl in _ADDITIVE_COLUMNS:
        if col not in cols:
            await db.execute(ddl)


async def record_audit(
    db: aiosqlite.Connection,
    user_id: int,
    content: str,
    analysis: str | None = None,
    case_id: int | None = None,
    refusal: bool = False,
) -> None:
    await db.execute(
        "INSERT INTO audits (user_id, content, analysis, case_id, refusal) VALUES (?, ?, ?, ?, ?)",
        (user_id, content[:2000], analysis, case_id, int(refusal)),
    )
    await db.commit()


async def recent_audits(
    db: aiosqlite.Connection,
    user_id: int,
    limit: int,
    case_id: int | None = None,
) -> list[tuple[int, str, str | None, str]]:
    if case_id is None:
        query = (
            "SELECT id, content, analysis, created_at "
            "FROM audits WHERE user_id = ? ORDER BY created_at DESC LIMIT ?"
        )
        args: tuple = (user_id, limit)
    else:
        query = (
            "SELECT id, content, analysis, created_at "
            "FROM audits WHERE user_id = ? AND case_id = ? "
            "ORDER BY created_at DESC LIMIT ?"
        )
        args = (user_id, case_id, limit)
    async with db.execute(query, args) as cur:
        return list(await cur.fetchall())


async def create_case(db: aiosqlite.Connection, name: str, user_id: int) -> int:
    cursor = await db.execute(
        "INSERT INTO cases (name, user_id) VALUES (?, ?)", (name, user_id)
    )
    await db.commit()
    return int(cursor.lastrowid)


async def get_case_by_name(
    db: aiosqlite.Connection, name: str
) -> tuple[int, str, int, str, str, str | None] | None:
    async with db.execute(
        "SELECT id, name, user_id, status, created_at, closed_at FROM cases WHERE name = ?",
        (name,),
    ) as cur:
        row = await cur.fetchone()
        return tuple(row) if row else None  # type: ignore[return-value]


async def list_cases(
    db: aiosqlite.Connection, status: str | None = None, limit: int = 25
) -> list[tuple[int, str, str, str]]:
    if status:
        query = "SELECT id, name, status, created_at FROM cases WHERE status = ? ORDER BY created_at DESC LIMIT ?"
        args: tuple = (status, limit)
    else:
        query = "SELECT id, name, status, created_at FROM cases ORDER BY created_at DESC LIMIT ?"
        args = (limit,)
    async with db.execute(query, args) as cur:
        return list(await cur.fetchall())


async def close_case(db: aiosqlite.Connection, case_id: int) -> None:
    await db.execute(
        "UPDATE cases SET status='closed', closed_at=CURRENT_TIMESTAMP WHERE id=?",
        (case_id,),
    )
    await db.commit()


async def case_audits(
    db: aiosqlite.Connection, case_id: int, limit: int = 20
) -> list[tuple[str, str, str | None]]:
    async with db.execute(
        "SELECT created_at, content, analysis FROM audits "
        "WHERE case_id = ? ORDER BY created_at DESC LIMIT ?",
        (case_id, limit),
    ) as cur:
        return list(await cur.fetchall())


async def integrity_ok(db: aiosqlite.Connection) -> bool:
    async with db.execute("PRAGMA integrity_check") as cur:
        row = await cur.fetchone()
    return bool(row) and row[0] == "ok"
