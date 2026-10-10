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
interpreter="${PIDFD_PYTHON:-$interpreter}"
if [[ "$interpreter" != /* ]]; then
  echo 'PIDFD_PYTHON must be an absolute interpreter path.' >&2
  exit 1
fi
if [[ ! -x "$interpreter" ]]; then
  echo 'Install dependencies first: sudo ./install-ubuntu.sh' >&2
  exit 1
fi
if [[ $EUID -eq 0 ]]; then
  exec "$interpreter" "$directory/python/validate_guest.py" "$@"
else
  preserve=()
  while IFS= read -r name; do
    case "$name" in PIDFD_*) preserve+=("$name") ;; esac
  done < <(compgen -e)
  if (( ${#preserve[@]} )); then
    printf -v preserve_list '%s,' "${preserve[@]}"
    preserve_list="${preserve_list%,}"
    exec sudo --preserve-env="$preserve_list" "$interpreter" "$directory/python/validate_guest.py" "$@"
  fi
  exec sudo "$interpreter" "$directory/python/validate_guest.py" "$@"
fi
