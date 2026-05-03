# pg_lockstep

`pg_lockstep` is an offline-first PostgreSQL extension that detects destructive or suspicious SQL before execution, scores the risk locally, records structured JSON audit events, and blocks or warns according to local policy.

It is a native PostgreSQL command interlock. Dangerous database actions require policy clearance or an explicit local approval step.

## What It Is Not

`pg_lockstep` is not a SQL chatbot, not a cloud firewall, not a proxy, and not telemetry. The extension does not call external APIs, does not use an LLM in the hot path, and does not send Slack messages itself.

## Quickstart

From a PostgreSQL extension build environment:

```sh
make install
psql -d postgres -c "CREATE EXTENSION IF NOT EXISTS pgcrypto;"
psql -d postgres -c "CREATE EXTENSION pg_lockstep;"
psql -d postgres -c "SELECT lockstep.enable('observe');"
```

Upgrade an existing installation:

```sh
make install
psql -d topology_db -c "ALTER EXTENSION pg_lockstep UPDATE TO '0.1.1';"
```

Try observe mode:

```sql
CREATE TABLE demo_users (id bigserial PRIMARY KEY, email text);
DROP TABLE demo_users;
SELECT event FROM lockstep.current_events(5);
```

Observe mode never blocks. It audits decisions and emits notifications for warn/block-worthy events when notifications are enabled.

Try enforce mode:

```sql
SELECT lockstep.enable('enforce');
CREATE TABLE demo_users (id bigserial PRIMARY KEY, email text);
DROP TABLE demo_users;
```

The `DROP TABLE` should fail with:

```text
ERROR:  pg_lockstep blocked command
DETAIL: { ... JSON event ... }
```

## Approval Flow

Request and approve a local single-use token:

```sql
SELECT lockstep.request_approval('DROP TABLE', NULL, 'planned cleanup', 'OPS-123') AS approval_id;
SELECT lockstep.approve('<approval-id>', current_user) AS token;
SET pg_lockstep.approval_token = '<token>';
DROP TABLE demo_users;
```

The token is stored server-side, expires locally, and is consumed once.

## Protected-Table DELETE

PostgreSQL event triggers do not fire for DML, so `pg_lockstep` protects `DELETE` through opt-in table triggers:

```sql
CREATE TABLE demo_users (id bigserial PRIMARY KEY, email text);
SELECT lockstep.protect_table('public', 'demo_users');
SELECT lockstep.enable('enforce');
DELETE FROM demo_users;
```

Unqualified `DELETE FROM demo_users;` is blocked on protected tables. `DELETE ... WHERE ...` is allowed by this current release trigger path. Use `SELECT lockstep.protect_all_tables('public');` to install the trigger across a schema.

## Doctor

Run posture diagnostics from SQL:

```sql
SELECT lockstep.doctor();
```

Or from the CLI:

```sh
pip install -r cli/requirements.txt
bin/pg_lockstep doctor --dsn postgresql://localhost/topology_db
```

Doctor reports unsafe database ownership, login-capable superusers, non-enforcing mode, disabled event triggers, and the current release scope limitation. It explicitly warns that event-trigger mode cannot reliably protect cluster-level commands such as `DROP DATABASE`.

## SQL Namespace

The extension/package and CLI are named `pg_lockstep`. PostgreSQL reserves schema names beginning with `pg_`, so SQL objects are installed in the `lockstep` schema. The NOTIFY channel and approval-token session setting still use the `pg_lockstep` prefix.

## Relay Flow

Run the optional local relay:

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r relay/requirements.txt
python relay/pg_lockstep_relay.py --dsn postgresql://postgres:postgres@localhost:5432/postgres
```

Slack forwarding is optional:

```sh
export PG_LOCKSTEP_SLACK_BOT_TOKEN=xoxb-...
export PG_LOCKSTEP_SLACK_CHANNEL=C0123456789
```

The relay listens to `pg_lockstep_events`. If Slack fails, database enforcement is unaffected.

Test Slack without waiting for a database event:

```sh
python relay/pg_lockstep_relay.py --test-slack
```

PostgreSQL only delivers `NOTIFY` after commit. A blocked command raises an exception, so its `NOTIFY` is rolled back with the failed statement. The relay receives committed warn/observe events, not blocked-statement notifications from the same transaction.

For blocked-command alerts in the SQL/event-trigger release, enable the optional local `dblink` delivery path:

```sql
CREATE EXTENSION IF NOT EXISTS dblink;
SELECT lockstep.configure_blocked_alerts(
  true,
  'dbname=topology_db',
  true
);
```

The third argument includes a trusted-channel approval token in the alert payload. Treat the Slack channel as sensitive: the token is single-use and expires according to `token_ttl_minutes`.

## Modes

- `observe`: audit only, never block.
- `warn`: audit and notify, never block.
- `enforce`: block `block` and `require_approval` policy decisions unless a valid token is set.
- `lockdown`: require approval for all high and critical DDL.

## Offline Guarantee

The extension performs local deterministic scoring, policy matching, audit writes, approval checks, and PostgreSQL `NOTIFY`. It does not make network calls and has no cloud dependency.

## Limitations

The current release uses `ddl_command_start` event triggers. PostgreSQL exposes reliable command tags there, but not rich object identity for every command.

The current release includes opt-in trigger protection for unqualified protected-table `DELETE`, but it is not a general SQL parser and does not catch every all-row DML form such as `DELETE FROM table WHERE true`. Broader DML protection for `DELETE`, `UPDATE`, and `COPY` is future work and likely requires native hooks.

Cluster-level operations such as `DROP DATABASE` are not reliably intercepted by the current release SQL/event-trigger, even when `pg_lockstep` is installed in the `postgres` maintenance database. A superuser connected as `psql -U postgres` can drop databases unless PostgreSQL itself is protected by a native, cluster-loaded hook extension and by normal operational controls.

Superusers can usually disable event triggers or extensions. `pg_lockstep` reduces accidents and migration mistakes; it is not a replacement for least privilege or a full database activity monitoring platform.

Because blocked statements are raised from a transactional event trigger, audit table writes and ordinary `NOTIFY` messages for the blocked attempt can roll back with the statement. The optional local `dblink` alert path can emit a committed blocked-event notification before the command is blocked.

See [docs/](docs/) for architecture, policy, approval, relay, threat model, and future hook design.
