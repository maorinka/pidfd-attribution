#!/usr/bin/env bash
set -euo pipefail
directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$(uname -s)" != Linux ]]; then
  echo 'Run this repository inside Ubuntu Linux.' >&2
  exit 1
fi
source /etc/os-release
case "$VERSION_ID" in
  22.04) interpreter=/usr/bin/python3.10 ;;
  24.04) interpreter=/usr/bin/python3.12 ;;
  26.04) interpreter=/usr/bin/python3.14 ;;
  *) echo 'Supported Ubuntu releases: 22.04, 24.04 and 26.04.' >&2; exit 1 ;;
esac
if [[ ! -x "$interpreter" ]]; then
  echo 'Install dependencies first: sudo ./install-ubuntu.sh' >&2
  exit 1
fi
if [[ $EUID -eq 0 ]]; then
  exec "$interpreter" "$directory/validate_guest.py" "$@"
else
  exec sudo "$interpreter" "$directory/validate_guest.py" "$@"
fi
