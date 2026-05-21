from __future__ import annotations

import shutil
import time
from pathlib import Path

import pytest

from meanmug.ops import (
    ESSENTIAL_FILES,
    MissingEssentialError,
    snapshot,
    verify_essentials,
)

ROOT = Path(__file__).resolve().parents[1]


def _populate(target: Path) -> None:
    for f in ESSENTIAL_FILES:
        src = ROOT / f
        dst = target / f
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def test_verify_essentials_passes_on_real_repo():
    verify_essentials(ROOT)


def test_verify_essentials_fails_when_missing(tmp_path):
    with pytest.raises(MissingEssentialError):
        verify_essentials(tmp_path)


def test_snapshot_then_no_op(tmp_path):
    _populate(tmp_path)
    first = snapshot(tmp_path)
    assert first["status"] == "snapshotted"
    assert first["files"] == len(ESSENTIAL_FILES)
    second = snapshot(tmp_path)
    assert second["status"] == "no-op"
    assert second["matched"] == first["timestamp"]


def test_snapshot_after_change(tmp_path):
    _populate(tmp_path)
    first = snapshot(tmp_path)
    assert first["status"] == "snapshotted"
    (tmp_path / "pyproject.toml").write_text(
        (tmp_path / "pyproject.toml").read_text() + "\n# touched\n"
    )
    time.sleep(1.1)
    third = snapshot(tmp_path)
    assert third["status"] == "snapshotted"
    assert third["state_hash"] != first["state_hash"]


def test_snapshot_target_must_be_essential(tmp_path):
    _populate(tmp_path)
    with pytest.raises(ValueError):
        snapshot(tmp_path, target="README.md")
