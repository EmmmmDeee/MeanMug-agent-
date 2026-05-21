from meanmug.bot import chunk_text


def test_short_text_single_chunk():
    assert chunk_text("hello") == ["hello"]


def test_respects_limit():
    text = ("paragraph one.\n\n" * 200).strip()
    chunks = chunk_text(text, limit=500)
    assert all(len(c) <= 500 for c in chunks)
    assert len(chunks) > 1


def test_prefers_paragraph_boundary():
    # paragraph break must be past the half-limit point to be selected
    text = ("a" * 60) + "\n\n" + ("b" * 60) + "\n\n" + ("c" * 60)
    chunks = chunk_text(text, limit=100)
    assert chunks[0].endswith("a" * 60)
    assert chunks[1].startswith("b" * 60)


def test_round_trip_no_data_loss():
    text = "alpha\n\nbeta\n\ngamma " + "y" * 5000
    chunks = chunk_text(text, limit=200)
    joined = " ".join(chunks)
    assert joined.replace(" ", "").replace("\n", "") == text.replace(" ", "").replace("\n", "")
