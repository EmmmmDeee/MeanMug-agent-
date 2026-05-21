from __future__ import annotations

import asyncio

import pytest

from meanmug.services.storage import (
    case_audits,
    close_case,
    create_case,
    get_case_by_name,
    integrity_ok,
    list_cases,
    open_db,
    recent_audits,
    record_audit,
)


@pytest.mark.asyncio
async def test_full_case_lifecycle(tmp_path):
    db = await open_db(str(tmp_path / "x.db"))
    case_id = await create_case(db, "alpha", 1)
    assert isinstance(case_id, int)
    row = await get_case_by_name(db, "alpha")
    assert row and row[3] == "open"

    await record_audit(db, 1, "input", analysis="analysis", case_id=case_id)
    audits = await case_audits(db, case_id)
    assert len(audits) == 1

    recent = await recent_audits(db, 1, 5)
    assert recent[0][1] == "input"

    by_case = await recent_audits(db, 1, 5, case_id=case_id)
    assert len(by_case) == 1
    no_match = await recent_audits(db, 1, 5, case_id=9999)
    assert no_match == []

    listing = await list_cases(db, status="open")
    assert any(c[1] == "alpha" for c in listing)

    await close_case(db, case_id)
    row2 = await get_case_by_name(db, "alpha")
    assert row2 and row2[3] == "closed"
    assert await integrity_ok(db)
    await db.close()


@pytest.mark.asyncio
async def test_refusal_audit_flag(tmp_path):
    db = await open_db(str(tmp_path / "x.db"))
    await record_audit(db, 1, "danger", refusal=True)
    async with db.execute("SELECT refusal FROM audits WHERE user_id=1") as cur:
        rows = await cur.fetchall()
    assert rows[0][0] == 1
    await db.close()
