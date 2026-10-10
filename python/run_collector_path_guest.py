"""Backend entrypoint for shared fixture build and correctness checks."""

import settings
from shared.python.fixture_drivers.run_collector_path_guest import (
    build,
    preflight,
    main,
)

if __name__ == "__main__":
    main()
