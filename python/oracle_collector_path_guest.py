# SPDX-License-Identifier: GPL-2.0-only
"""Backend entrypoint for independent source-position oracle checks."""

import settings
from shared.python.fixture_drivers.oracle_collector_path_guest import main

if __name__ == "__main__":
    main()
