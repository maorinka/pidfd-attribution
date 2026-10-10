#!/usr/bin/env bash
set -euo pipefail
directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$(uname -s)" != Linux ]]; then
  echo 'Run this sensor inside Ubuntu Linux.' >&2
  exit 1
fi
interpreter="${PIDFD_PYTHON:-/usr/bin/python3}"
if [[ "$interpreter" != /* || ! -x "$interpreter" ]]; then
  echo 'PIDFD_PYTHON must name an executable absolute interpreter path.' >&2
  exit 1
fi
exec "$interpreter" "$directory/python/service.py" "$@"
