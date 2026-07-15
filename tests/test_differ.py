from annals.differ.normalize import normalize_html
from annals.differ.termwatch import term_watch


def test_normalize_strips_page_chrome() -> None:
    html = (
        "<html><head><style>.x{}</style></head>"
        "<body><nav>menu</nav><p>Climate change is real.</p><footer>foot</footer></body></html>"
    )
    assert normalize_html(html) == "Climate change is real."


def test_term_disappearance_is_high_severity() -> None:
    terms = ["climate change", "resilience"]
    diffs = term_watch(
        "The agency studies climate change closely.",
        "The agency studies resilience closely.",
        terms,
        target_id="t",
        detected_at="2026-01-01T00:00:00Z",
        from_hash="a",
        to_hash="b",
    )
    by_term = {d.evidence["term"]: d for d in diffs}
    assert by_term["climate change"].severity == "High"  # disappeared
    assert by_term["climate change"].evidence == {"term": "climate change", "from": 1, "to": 0}
    assert by_term["resilience"].evidence["to"] == 1  # appeared
