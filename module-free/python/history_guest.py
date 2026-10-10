"""Backend entrypoint for the shared history guest control."""

from settings import RUNTIME_DIR, HISTORY_TIMEOUT_SECONDS
from shared.python.fixture_drivers.history_guest import main

if __name__ == "__main__":
    main(RUNTIME_DIR, HISTORY_TIMEOUT_SECONDS)
