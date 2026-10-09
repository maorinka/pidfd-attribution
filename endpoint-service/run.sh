#!/usr/bin/env bash
set -euo pipefail
directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$(uname -s)" != Linux ]]; then
  echo 'Run this sensor inside Ubuntu Linux.' >&2
  exit 1
fi
exec /usr/bin/python3 "$directory/service.py" "$@"
