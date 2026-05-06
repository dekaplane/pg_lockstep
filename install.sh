#!/usr/bin/env bash
set -euo pipefail

REPO="${PG_LOCKSTEP_REPO:-dekaplane/pg_lockstep}"
VERSION="${PG_LOCKSTEP_VERSION:-}"
PG_MAJOR="${PG_LOCKSTEP_PG_MAJOR:-}"
INSTALL_RELAY="1"
SUDO=()

usage() {
  cat <<'USAGE'
Install pg_lockstep Debian/Ubuntu packages from GitHub Releases.

Usage:
  install.sh [--version vX.Y.Z] [--pg-major 16|17] [--no-relay]

Environment:
  PG_LOCKSTEP_VERSION     Release version or tag, for example v0.1.2
  PG_LOCKSTEP_PG_MAJOR    PostgreSQL major version: 16 or 17
  PG_LOCKSTEP_REPO        GitHub repo, default dekaplane/pg_lockstep

This installs package files only. Run CREATE EXTENSION in each database you
want pg_lockstep to protect.
USAGE
}

fail() {
  echo "error: $*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h)
      usage
      exit 0
      ;;
    --no-relay)
      INSTALL_RELAY="0"
      shift
      ;;
    --version)
      [[ $# -ge 2 ]] || fail "--version requires a value"
      VERSION="$2"
      shift 2
      ;;
    --pg-major)
      [[ $# -ge 2 ]] || fail "--pg-major requires 16 or 17"
      PG_MAJOR="$2"
      shift 2
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

detect_platform() {
  [[ -r /etc/os-release ]] || fail "only Debian/Ubuntu systems are supported"
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}" in
    debian|ubuntu) ;;
    *) fail "only Debian/Ubuntu systems are supported; detected ${ID:-unknown}" ;;
  esac

  local arch
  if command -v dpkg >/dev/null 2>&1; then
    arch="$(dpkg --print-architecture)"
  else
    arch="$(uname -m)"
  fi
  case "${arch}" in
    amd64|x86_64) ;;
    *) fail "only amd64/x86_64 is supported; detected ${arch}" ;;
  esac
}

detect_privilege_runner() {
  if [[ "${EUID}" -eq 0 ]]; then
    SUDO=()
    return
  fi
  command -v sudo >/dev/null 2>&1 || fail "root privileges are required; rerun with sudo or install sudo"
  SUDO=(sudo)
}

detect_pg_major() {
  if [[ -n "${PG_MAJOR}" ]]; then
    [[ "${PG_MAJOR}" == "16" || "${PG_MAJOR}" == "17" ]] || fail "--pg-major must be 16 or 17"
    echo "${PG_MAJOR}"
    return
  fi

  if [[ -x /usr/lib/postgresql/17/bin/pg_config ]] || dpkg -s postgresql-17 >/dev/null 2>&1; then
    echo "17"
    return
  fi
  if [[ -x /usr/lib/postgresql/16/bin/pg_config ]] || dpkg -s postgresql-16 >/dev/null 2>&1; then
    echo "16"
    return
  fi

  fail "could not detect PostgreSQL 16 or 17; pass --pg-major 16 or --pg-major 17"
}

release_base_url() {
  if [[ -n "${VERSION}" ]]; then
    local tag="${VERSION}"
    [[ "${tag}" == v* ]] || tag="v${tag}"
    echo "https://github.com/${REPO}/releases/download/${tag}"
  else
    echo "https://github.com/${REPO}/releases/latest/download"
  fi
}

download_file() {
  local url="$1"
  local output="$2"
  curl -fL --retry 3 --retry-delay 2 -o "${output}" "${url}"
}

main() {
  detect_platform
  detect_privilege_runner

  local pg_major
  pg_major="$(detect_pg_major)"

  local tmp_dir
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "${tmp_dir}"' EXIT

  local base_url
  base_url="$(release_base_url)"

  echo "Downloading pg_lockstep release assets from ${base_url}"
  download_file "${base_url}/SHA256SUMS" "${tmp_dir}/SHA256SUMS" || echo "warning: SHA256SUMS not found; checksum verification skipped" >&2

  local extension_deb relay_deb
  if [[ -s "${tmp_dir}/SHA256SUMS" ]]; then
    extension_deb="$(awk -v pkg="postgresql-${pg_major}-pg-lockstep_" '$2 ~ pkg {gsub(/^\.\//, "", $2); print $2; exit}' "${tmp_dir}/SHA256SUMS")"
    relay_deb="$(awk -v pkg="pg-lockstep-relay_" '$2 ~ pkg {gsub(/^\.\//, "", $2); print $2; exit}' "${tmp_dir}/SHA256SUMS")"
  fi

  if [[ -z "${extension_deb:-}" ]]; then
    [[ -n "${VERSION}" ]] || fail "could not determine extension package name without SHA256SUMS; pass --version vX.Y.Z"
    local version_no_v="${VERSION#v}"
    extension_deb="postgresql-${pg_major}-pg-lockstep_${version_no_v}-1_amd64.deb"
  fi
  if [[ "${INSTALL_RELAY}" == "1" && -z "${relay_deb:-}" ]]; then
    [[ -n "${VERSION}" ]] || fail "could not determine relay package name without SHA256SUMS; pass --version vX.Y.Z"
    local version_no_v="${VERSION#v}"
    relay_deb="pg-lockstep-relay_${version_no_v}-1_amd64.deb"
  fi

  download_file "${base_url}/${extension_deb}" "${tmp_dir}/${extension_deb}"
  if [[ "${INSTALL_RELAY}" == "1" ]]; then
    download_file "${base_url}/${relay_deb}" "${tmp_dir}/${relay_deb}"
  fi

  if [[ -s "${tmp_dir}/SHA256SUMS" ]]; then
    (
      cd "${tmp_dir}"
      grep -E "(postgresql-${pg_major}-pg-lockstep_|pg-lockstep-relay_)" SHA256SUMS >SHA256SUMS.selected
      if [[ "${INSTALL_RELAY}" != "1" ]]; then
        grep "postgresql-${pg_major}-pg-lockstep_" SHA256SUMS >SHA256SUMS.selected
      fi
      sha256sum -c SHA256SUMS.selected
    )
  fi

  "${SUDO[@]}" apt install -y "${tmp_dir}/${extension_deb}"
  if [[ "${INSTALL_RELAY}" == "1" ]]; then
    "${SUDO[@]}" apt install -y "${tmp_dir}/${relay_deb}"
  fi

  cat <<NEXT

pg_lockstep packages installed.

Next steps in each database you want to protect:
  CREATE EXTENSION IF NOT EXISTS pg_lockstep;
  SELECT lockstep.enable('observe');
  SELECT lockstep.doctor();

The extension/package is named pg_lockstep. SQL functions live in schema
lockstep because PostgreSQL reserves pg_* schema names.
NEXT
}

main "$@"
