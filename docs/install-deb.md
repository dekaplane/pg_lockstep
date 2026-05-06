# Debian/Ubuntu Installation

`pg_lockstep` publishes `.deb` packages as GitHub Release assets. There is no
APT repository yet.

Supported platforms:

- Ubuntu 22.04 and 24.04
- Debian 12
- amd64 only
- PostgreSQL 16 or 17

## One-Shot Install

```sh
curl -fsSL https://raw.githubusercontent.com/dekaplane/pg_lockstep/main/install.sh | sudo bash
```

Install for a specific PostgreSQL major or release:

```sh
curl -fsSL https://raw.githubusercontent.com/dekaplane/pg_lockstep/main/install.sh | sudo bash -s -- --pg-major 17 --version v0.1.2
```

Skip the optional relay package:

```sh
curl -fsSL https://raw.githubusercontent.com/dekaplane/pg_lockstep/main/install.sh | sudo bash -s -- --no-relay
```

The packages install extension files globally. You still enable the extension
per database:

```sql
CREATE EXTENSION IF NOT EXISTS pg_lockstep;
SELECT lockstep.enable('observe');
SELECT lockstep.doctor();
```

The extension is named `pg_lockstep`; SQL functions live in the `lockstep`
schema because PostgreSQL reserves `pg_*` schema names.

## Manual Release Asset Install

Download the package that matches the installed PostgreSQL major:

```sh
VERSION=0.1.2
curl -fLO "https://github.com/dekaplane/pg_lockstep/releases/download/v${VERSION}/postgresql-17-pg-lockstep_${VERSION}-1_amd64.deb"
curl -fLO "https://github.com/dekaplane/pg_lockstep/releases/download/v${VERSION}/pg-lockstep-relay_${VERSION}-1_amd64.deb"
curl -fLO "https://github.com/dekaplane/pg_lockstep/releases/download/v${VERSION}/SHA256SUMS"
```

Verify checksums:

```sh
sha256sum -c SHA256SUMS
```

Install:

```sh
sudo apt install ./postgresql-17-pg-lockstep_${VERSION}-1_amd64.deb
sudo apt install ./pg-lockstep-relay_${VERSION}-1_amd64.deb
```

## Relay Setup

The relay package installs `/usr/bin/pg-lockstep-relay`, an example environment
file, and a systemd unit. It does not auto-enable the service.

```sh
sudo install -m 0600 /etc/pg-lockstep/relay.env.example /etc/pg-lockstep/relay.env
sudo editor /etc/pg-lockstep/relay.env
sudo systemctl daemon-reload
sudo systemctl enable --now pg-lockstep-relay
```

Slack forwarding is optional. Keep real Slack tokens and private DSNs out of
git, shell history, screenshots, and issue reports.

## Uninstall

Remove package files:

```sh
sudo apt remove postgresql-17-pg-lockstep pg-lockstep-relay
```

Drop the extension from a database only when you intentionally want to remove
its SQL objects there:

```sql
DROP EXTENSION pg_lockstep;
```

## Current Release Scope

The SQL/event-trigger release is database-local. It can protect many
database-local DDL operations and opt-in protected-table DELETE paths, but it
cannot reliably protect `DROP DATABASE` issued from another database. True
superusers can bypass event-trigger mode.
