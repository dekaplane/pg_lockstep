# Release Checklist

- [ ] Confirm the version and release tag.
- [ ] Run `scripts/build-debs.sh`.
- [ ] Inspect package contents with `dpkg-deb --contents`.
- [ ] Verify `dist/SHA256SUMS`.
- [ ] Confirm the release contains exactly the expected `.deb` assets.
- [ ] Test `install.sh` on a clean supported Debian/Ubuntu host.
- [ ] Run `CREATE EXTENSION IF NOT EXISTS pg_lockstep;` in a test database.
- [ ] Run `SELECT lockstep.enable('observe');`.
- [ ] Run `SELECT lockstep.doctor();`.
- [ ] Confirm no secrets, private DSNs, tokens, dumps, keys, or local env files are committed or uploaded.
- [ ] Confirm install and release docs are current.
