from pathlib import Path

from meanmug.ops import parse_changelog as _parse_changelog

ROOT = Path(__file__).resolve().parents[1]


def test_parses_repo_changelog_in_order():
    text = (ROOT / "CHANGELOG.md").read_text()
    entries = _parse_changelog(text)
    assert len(entries) >= 4
    assert all("`" in e for e in entries)


def test_ignores_non_bullet_lines():
    text = "# Header\n\nsome prose\n- `abc123` — entry one\n- not an entry (no backtick)\n- `def456` — entry two\n"
    out = _parse_changelog(text)
    assert out == ["`abc123` — entry one", "`def456` — entry two"]
