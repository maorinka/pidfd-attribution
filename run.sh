#!/usr/bin/env bash
set -euo pipefail
directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$(uname -s)" != Linux ]]; then
  echo 'Run this repository inside Ubuntu 26.04 LTS Linux.' >&2
  exit 1
fi
if [[ ! -x /usr/bin/python3.14 ]]; then
  echo 'Install dependencies first: sudo ./install-ubuntu.sh' >&2
  exit 1
fi
if [[ $EUID -eq 0 ]]; then
  exec /usr/bin/python3.14 "$directory/validate_guest.py" "$@"
else
  exec sudo /usr/bin/python3.14 "$directory/validate_guest.py" "$@"
fi
