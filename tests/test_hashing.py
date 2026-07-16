from verderer.hashing import multihash_sha256, verify_multihash

# sha256("") = e3b0c442…b855; the multihash prepends the sha2-256 prefix 1220.
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_multihash_known_vector() -> None:
    assert multihash_sha256(b"") == "1220" + EMPTY_SHA256


def test_verify_roundtrip() -> None:
    mh = multihash_sha256(b"verderer")
    assert verify_multihash(b"verderer", mh)
    assert not verify_multihash(b"verderer!", mh)
