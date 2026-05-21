from meanmug.services.extract import extract_indicators


def test_extracts_ipv4():
    out = extract_indicators("contact 8.8.8.8 and 1.1.1.1")
    assert out["ips"] == ["1.1.1.1", "8.8.8.8"]


def test_extracts_domain_and_email():
    out = extract_indicators("ping evil.io from bad@evil.io and good@example.com")
    assert "evil.io" in out["domains"]
    assert "example.com" in out["domains"]
    assert out["emails"] == ["bad@evil.io", "good@example.com"]


def test_dedupe_and_sort():
    out = extract_indicators("8.8.8.8 8.8.8.8 1.1.1.1")
    assert out["ips"] == ["1.1.1.1", "8.8.8.8"]


def test_empty_input():
    out = extract_indicators("no indicators here")
    assert out == {"ips": [], "domains": [], "emails": []}
