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
  "${python_packages[@]}" "${bpf_packages[@]}" binutils \
  "linux-headers-$(uname -r)"
if [[ "$VERSION_ID" == 22.04 ]]; then
  # Jammy's libbpf 0.5 lacks the dynptr headers and named-uprobe API.
  # Keep the newer static library local to this checkout.
  apt-get install -y curl pkg-config
  directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
  build_directory="$(mktemp -d /var/tmp/pidfd-libbpf.XXXXXXXX)"
  trap 'rm -rf -- "$build_directory"' EXIT
  curl --fail --location https://codeload.github.com/libbpf/libbpf/tar.gz/refs/tags/v1.3.0 -o "$build_directory/libbpf.tar.gz"
  (cd "$build_directory" && echo '11db86acd627e468bc48b7258c1130aba41a12c4d364f78e184fd2f5a913d861  libbpf.tar.gz' | sha256sum --check)
  tar -xzf "$build_directory/libbpf.tar.gz" -C "$build_directory"
  mkdir -p "$build_directory/build"
  make -C "$build_directory/libbpf-1.3.0/src" -j2 BUILD_STATIC_ONLY=1 \
    OBJDIR="$build_directory/build" PREFIX="$directory/.deps" LIBDIR="$directory/.deps/lib" install
fi
echo 'Dependencies installed. Run: sudo ./run.sh doctor'
