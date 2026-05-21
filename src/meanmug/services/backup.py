from __future__ import annotations

import hashlib
import json
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

ESSENTIAL_FILES: tuple[str, ...] = (
    "SYSTEM_PROMPT.md",
    ".env.example",
    "pyproject.toml",
    "src/meanmug/core/config.py",
    "src/meanmug/services/glm.py",
    "src/meanmug/services/storage.py",
)


class MissingEssentialError(RuntimeError):
    """Raised when one or more essential config files are absent."""


def verify_essentials(repo_root: Path) -> None:
    missing = [f for f in ESSENTIAL_FILES if not (repo_root / f).is_file()]
    if missing:
        raise MissingEssentialError(
            f"refusing to start; missing essential config: {', '.join(missing)}"
        )


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _build_manifest(repo_root: Path, files: tuple[str, ...]) -> dict[str, str]:
    return {f: _hash_file(repo_root / f) for f in files if (repo_root / f).is_file()}


def _latest_snapshot(backups_root: Path) -> Path | None:
    if not backups_root.is_dir():
        return None
    dirs = sorted(
        (p for p in backups_root.iterdir() if p.is_dir()),
        key=lambda p: p.name,
        reverse=True,
    )
    return dirs[0] if dirs else None


def snapshot(repo_root: Path, target: str | None = None) -> dict[str, object]:
    """Snapshot essential config files into backups/<UTC-ts>/.

    Content-hashed: if the current state matches the latest snapshot's manifest,
    returns {'status': 'no-op'}. Otherwise creates a new directory.
    """
    files: tuple[str, ...]
    if target is None:
        files = ESSENTIAL_FILES
    else:
        if target not in ESSENTIAL_FILES:
            raise ValueError(f"{target!r} is not in the essential set")
        files = (target,)

    manifest = _build_manifest(repo_root, files)
    manifest_json = json.dumps(manifest, sort_keys=True, indent=2)
    state_hash = hashlib.sha256(manifest_json.encode()).hexdigest()[:16]

    backups_root = repo_root / "backups"
    backups_root.mkdir(exist_ok=True)

    latest = _latest_snapshot(backups_root)
    if latest is not None:
        manifest_path = latest / "manifest.json"
        if manifest_path.is_file():
            prior = json.loads(manifest_path.read_text())
            if prior == manifest:
                return {"status": "no-op", "matched": latest.name}

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    snap_dir = backups_root / timestamp
    snap_dir.mkdir(parents=True, exist_ok=True)
    (snap_dir / "manifest.json").write_text(manifest_json, encoding="utf-8")
    for f in manifest:
        src = repo_root / f
        dst = snap_dir / f.replace("/", "__")
        shutil.copy2(src, dst)

    log.info("snapshot %s with %d files (state=%s)", timestamp, len(manifest), state_hash)
    return {
        "status": "snapshotted",
        "timestamp": timestamp,
        "files": len(manifest),
        "state_hash": state_hash,
    }


def latest_snapshot_name(repo_root: Path) -> str | None:
    snap = _latest_snapshot(repo_root / "backups")
    return snap.name if snap else None
