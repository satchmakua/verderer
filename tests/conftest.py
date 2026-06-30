import pytest

from druid.ledger.core import LedgerBinaryNotFound, find_binary


@pytest.fixture(scope="session")
def ledger_built() -> None:
    """Skip ledger-backed tests if the Rust trust kernel hasn't been built."""
    try:
        find_binary("druid-ledger")
        find_binary("druid-verify")
    except LedgerBinaryNotFound as error:  # pragma: no cover - environment dependent
        pytest.skip(str(error))
