#!/usr/bin/env bash
set -euo pipefail
if [[ "$(uname -s)" != Linux || $EUID -ne 0 ]]; then
  echo 'Run: sudo ./install-ubuntu.sh' >&2
  exit 1
fi
source /etc/os-release
if [[ "$ID" != ubuntu || "$VERSION_ID" != 26.04 ]]; then
  echo 'This installer targets Ubuntu 26.04 LTS (including 26.04.1).' >&2
  exit 1
fi
apt-get update
apt-get install -y build-essential clang llvm libbpf-dev libelf-dev zlib1g-dev \
  python3.14 python3.14-dev binutils pahole bpftool kmod \
  "linux-headers-$(uname -r)"
echo 'Dependencies installed. Run: sudo ./run.sh doctor'
