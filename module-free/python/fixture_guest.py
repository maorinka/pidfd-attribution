"""Backend entrypoint for the shared fixture guest control."""

from settings import RUNTIME_DIR
from shared.python.fixture_drivers.fixture_guest import main

if __name__ == "__main__":
    main(RUNTIME_DIR)
