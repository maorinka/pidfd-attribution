#!/usr/bin/env bash
set -euo pipefail
if [[ "$(uname -s)" != Linux || $EUID -ne 0 ]]; then
  echo 'Run: sudo ./install-ubuntu.sh' >&2
  exit 1
fi
source /etc/os-release
kernel_release="$(uname -r)"
kernel_major="${kernel_release%%.*}"
kernel_rest="${kernel_release#*.}"
kernel_minor="${kernel_rest%%.*}"
if (( kernel_major < 6 || (kernel_major == 6 && kernel_minor < 8) )); then
  echo 'This collection path requires Linux 6.8 or newer.' >&2
  if [[ "$VERSION_ID" == 22.04 ]]; then
    echo 'On your own Ubuntu 22.04 VM/computer: sudo apt-get install linux-generic-hwe-22.04; reboot into it, then rerun this installer.' >&2
  fi
  exit 1
fi
if [[ "$ID" != ubuntu || ! "$VERSION_ID" =~ ^(22\.04|24\.04|26\.04)$ ]]; then
  echo 'This installer targets Ubuntu 22.04, 24.04 and 26.04 LTS.' >&2
  exit 1
fi
case "$VERSION_ID" in
  22.04) python_packages=(python3.10 python3.10-dev); bpf_packages=(gcc-12 linux-tools-common "linux-tools-$(uname -r)") ;;
  24.04) python_packages=(python3.12 python3.12-dev); bpf_packages=(linux-tools-common "linux-tools-$(uname -r)") ;;
  26.04) python_packages=(python3.14 python3.14-dev); bpf_packages=(bpftool) ;;
esac
apt-get update
apt-get install -y build-essential clang llvm libbpf-dev libelf-dev zlib1g-dev \
  "${python_packages[@]}" "${bpf_packages[@]}" binutils pahole kmod \
  "linux-headers-$(uname -r)"
if [[ "$VERSION_ID" == 22.04 ]]; then
  # Jammy's libbpf 0.5 lacks the dynptr headers and named-uprobe API.
  # Reuse verified artifacts; publish new builds outside the source checkout.
  apt-get install -y pkg-config
  canonical_installer="$(readlink -f -- "${BASH_SOURCE[0]}")"
  installer_directory="$(dirname -- "$canonical_installer")"
  cache_helper=
  for candidate in "$installer_directory/libbpf_cache.py" \
                   "$installer_directory/shared/libbpf_cache.py" \
                   "$installer_directory/../shared/libbpf_cache.py"; do
    if [[ -f "$candidate" ]]; then
      cache_helper="$candidate"
      break
    fi
  done
  if [[ -z "$cache_helper" ]]; then
    echo 'The source checkout is missing shared/libbpf_cache.py.' >&2
    exit 1
  fi
  python3 "$cache_helper"
fi
echo "Dependencies installed. Continue with this backend's ./run.sh commands."
