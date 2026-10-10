"""Backend entrypoint for shared measured interpreter preparation."""

import settings
from shared.python.fixture_drivers.prepare_guest import prepare, sha256_file

if __name__ == "__main__":
    prepare()
