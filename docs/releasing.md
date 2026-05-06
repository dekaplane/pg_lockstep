# Releasing Debian Packages

Debian/Ubuntu packages are hosted as GitHub Release assets. There is no APT
repository in this release path.

## Local Build

```sh
scripts/build-debs.sh
```

The script writes:

- `dist/postgresql-16-pg-lockstep_<version>-1_amd64.deb`
- `dist/postgresql-17-pg-lockstep_<version>-1_amd64.deb`
- `dist/pg-lockstep-relay_<version>-1_amd64.deb`
- `dist/SHA256SUMS`

Version resolution:

- `PG_LOCKSTEP_VERSION` when set
- current exact git tag `vX.Y.Z`
- otherwise `0.1.1-dev`

## Tag Release

```sh
git tag v0.1.2
git push origin v0.1.2
```

The GitHub Action builds the packages and uploads `dist/*.deb` plus
`dist/SHA256SUMS` to the matching GitHub Release using GitHub's built-in
`GITHUB_TOKEN`.

## Manual Fallback

If the workflow fails, build locally or in a clean Linux builder:

```sh
PG_LOCKSTEP_VERSION=0.1.2 scripts/build-debs.sh
```

Create or edit the GitHub Release for `v0.1.2`, then upload the three `.deb`
files and `SHA256SUMS` from `dist/`.

Do not upload secrets, private DSNs, private keys, customer logs, or local
configuration files.
