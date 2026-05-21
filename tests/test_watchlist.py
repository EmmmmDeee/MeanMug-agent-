from __future__ import annotations

import pytest

from meanmug.database import (
    add_watch,
    list_watches,
    open_db,
    remove_watch,
    watch_hits,
)


@pytest.mark.asyncio
async def test_add_dedupe_list_remove(tmp_path):
    db = await open_db(str(tmp_path / "x.db"))
    assert await add_watch(db, "Alice", "handle", 1, "vip") is True
    # normalized lowercase + same kind → dedupe
    assert await add_watch(db, "alice", "handle", 1) is False
    # different kind for same identifier → allowed
    assert await add_watch(db, "alice", "email", 1) is True

    rows = await list_watches(db)
    assert {(r[1], r[2]) for r in rows} == {("alice", "handle"), ("alice", "email")}

    assert await remove_watch(db, "alice", "handle") == 1
    assert await remove_watch(db, "alice") == 1  # removes remaining
    assert await list_watches(db) == []
    await db.close()


@pytest.mark.asyncio
async def test_watch_hits_intersection(tmp_path):
    db = await open_db(str(tmp_path / "x.db"))
    await add_watch(db, "alice", "handle", 1)
    await add_watch(db, "evil.io", "domain", 1)
    await add_watch(db, "8.8.8.8", "ip", 1)

    indicators = {
        "ips": ["1.1.1.1", "8.8.8.8"],
        "domains": ["evil.io"],
        "emails": [],
        "handles": ["bob"],
    }
    hits = await watch_hits(db, indicators)
    assert sorted(hits) == [("8.8.8.8", "ip"), ("evil.io", "domain")]
    await db.close()
