#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build/deb"
DIST_DIR="${ROOT_DIR}/dist"
PACKAGE_REVISION="1"
ARCH="amd64"

fail() {
  echo "error: $*" >&2
  exit 1
}

require_file() {
  local path="$1"
  [[ -f "${ROOT_DIR}/${path}" ]] || fail "required file missing: ${path}"
}

resolve_version() {
  if [[ -n "${PG_LOCKSTEP_VERSION:-}" ]]; then
    echo "${PG_LOCKSTEP_VERSION#v}"
    return
  fi

  if git -C "${ROOT_DIR}" describe --exact-match --tags HEAD >/dev/null 2>&1; then
    local tag
    tag="$(git -C "${ROOT_DIR}" describe --exact-match --tags HEAD)"
    if [[ "${tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo "${tag#v}"
      return
    fi
  fi

  echo "0.1.1-dev"
}

write_control() {
  local path="$1"
  local package="$2"
  local version="$3"
  local depends="$4"
  local description="$5"

  mkdir -p "$(dirname "${path}")"
  cat >"${path}" <<CONTROL
Package: ${package}
Version: ${version}-${PACKAGE_REVISION}
Section: database
Priority: optional
Architecture: ${ARCH}
Maintainer: pg_lockstep maintainers <security@dekaplane.com>
Depends: ${depends}
Homepage: https://github.com/dekaplane/pg_lockstep
Description: ${description}
 pg_lockstep is an offline-first PostgreSQL command interlock for destructive
 or suspicious database operations. The SQL extension performs local policy
 evaluation, audit logging, approvals, and optional PostgreSQL NOTIFY alerts.
CONTROL
}

copy_extension_files() {
  local pg_major="$1"
  local dest="$2/usr/share/postgresql/${pg_major}/extension"

  mkdir -p "${dest}"
  cp "${ROOT_DIR}/pg_lockstep.control" "${dest}/"
  cp "${ROOT_DIR}"/pg_lockstep--*.sql "${dest}/"
}

build_extension_package() {
  local pg_major="$1"
  local version="$2"
  local package="postgresql-${pg_major}-pg-lockstep"
  local pkg_dir="${BUILD_DIR}/${package}"
  local deb="${DIST_DIR}/${package}_${version}-${PACKAGE_REVISION}_${ARCH}.deb"

  rm -rf "${pkg_dir}"
  mkdir -p "${pkg_dir}/DEBIAN"
  write_control \
    "${pkg_dir}/DEBIAN/control" \
    "${package}" \
    "${version}" \
    "postgresql-${pg_major}" \
    "PostgreSQL ${pg_major} extension files for pg_lockstep"
  copy_extension_files "${pg_major}" "${pkg_dir}"
  dpkg-deb --build --root-owner-group "${pkg_dir}" "${deb}" >/dev/null
}

build_relay_package() {
  local version="$1"
  local package="pg-lockstep-relay"
  local pkg_dir="${BUILD_DIR}/${package}"
  local deb="${DIST_DIR}/${package}_${version}-${PACKAGE_REVISION}_${ARCH}.deb"

  rm -rf "${pkg_dir}"
  mkdir -p \
    "${pkg_dir}/DEBIAN" \
    "${pkg_dir}/usr/bin" \
    "${pkg_dir}/etc/pg-lockstep" \
    "${pkg_dir}/lib/systemd/system"

  write_control \
    "${pkg_dir}/DEBIAN/control" \
    "${package}" \
    "${version}" \
    "python3, python3-psycopg | python3-psycopg2, python3-requests, postgresql-client" \
    "optional local PostgreSQL LISTEN/NOTIFY relay for pg_lockstep"

  install -m 0755 "${ROOT_DIR}/relay/pg_lockstep_relay.py" "${pkg_dir}/usr/bin/pg-lockstep-relay"
  install -m 0644 "${ROOT_DIR}/relay/relay.env.example" "${pkg_dir}/etc/pg-lockstep/relay.env.example"
  install -m 0644 \
    "${ROOT_DIR}/packaging/debian/pg-lockstep-relay/pg-lockstep-relay.service" \
    "${pkg_dir}/lib/systemd/system/pg-lockstep-relay.service"

  dpkg-deb --build --root-owner-group "${pkg_dir}" "${deb}" >/dev/null
}

write_checksums() {
  (
    cd "${DIST_DIR}"
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum ./*.deb >SHA256SUMS
    else
      shasum -a 256 ./*.deb >SHA256SUMS
    fi
  )
}

main() {
  command -v dpkg-deb >/dev/null 2>&1 || fail "dpkg-deb is required"
  require_file "pg_lockstep.control"
  require_file "relay/pg_lockstep_relay.py"
  require_file "relay/relay.env.example"
  require_file "packaging/debian/pg-lockstep-relay/pg-lockstep-relay.service"
  compgen -G "${ROOT_DIR}/pg_lockstep--*.sql" >/dev/null || fail "required extension SQL files missing: pg_lockstep--*.sql"

  local version
  version="$(resolve_version)"

  rm -rf "${BUILD_DIR}"
  mkdir -p "${BUILD_DIR}" "${DIST_DIR}"
  rm -f "${DIST_DIR}"/*.deb "${DIST_DIR}/SHA256SUMS"

  build_extension_package "16" "${version}"
  build_extension_package "17" "${version}"
  build_relay_package "${version}"
  write_checksums

  echo "Built Debian artifacts:"
  (
    cd "${DIST_DIR}"
    ls -1 ./*.deb SHA256SUMS
  )
}

main "$@"
