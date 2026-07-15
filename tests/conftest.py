import pytest

from annals.ledger.core import LedgerBinaryNotFound, find_binary


@pytest.fixture(scope="session")
def ledger_built() -> None:
    """Skip ledger-backed tests if the Rust trust kernel hasn't been built."""
    try:
        find_binary("annals-ledger")
        find_binary("annals-verify")
    except LedgerBinaryNotFound as error:  # pragma: no cover - environment dependent
        pytest.skip(str(error))
