# SPDX-License-Identifier: GPL-2.0-only
"""Backend entrypoint for the shared compat guest control."""

from settings import RUNTIME_DIR
from shared.python.fixture_drivers.compat_guest import main

if __name__ == "__main__":
    main(RUNTIME_DIR)
