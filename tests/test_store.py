from pathlib import Path

from verderer.store import ContentAddressedStore


def test_put_is_content_addressed_and_dedups(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path / "blobs")
    first = store.put(b"hello")
    again = store.put(b"hello")
    assert first == again  # identity = content
    assert store.has(first)
    assert store.get(first) == b"hello"
    assert store.put(b"world") != first
