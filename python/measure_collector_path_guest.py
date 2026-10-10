"""Backend entrypoint for the shared measure collector path guest control."""

from settings import RUNTIME_DIR
from shared.python.fixture_drivers.measure_collector_path_guest import main

if __name__ == "__main__":
    main(RUNTIME_DIR)
