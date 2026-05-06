# Quickstart

## Install

```sh
make install
psql -d postgres -c "CREATE EXTENSION IF NOT EXISTS pgcrypto;"
psql -d postgres -c "CREATE EXTENSION pg_lockstep;"
```

For an existing database with an older installed extension body:

```sh
make install
psql -d topology_db -c "ALTER EXTENSION pg_lockstep UPDATE TO '0.1.1';"
```

`pg_lockstep` depends on `pgcrypto` for UUIDs, hashes, and random tokens. PostgreSQL reserves schema names beginning with `pg_`, so SQL objects are installed in the `lockstep` schema. The extension creates local policy tables, audit tables, approval tables, helper functions, and a disabled event trigger.

## Observe Mode

```sql
SELECT lockstep.enable('observe');
CREATE TABLE demo_users (id bigserial PRIMARY KEY, email text);
DROP TABLE demo_users;
SELECT command_tag, risk, score, action, event
FROM lockstep.current_events(5);
```

Observe mode is the safest first rollout mode. It never blocks commands.

## Enforce Mode

```sql
SELECT lockstep.enable('enforce');
CREATE TABLE demo_users (id bigserial PRIMARY KEY, email text);
DROP TABLE demo_users;
```

Default policy requires approval for destructive DDL such as `DROP TABLE`.

## Local Approval

```sql
SELECT lockstep.request_approval('DROP TABLE', NULL, 'planned cleanup', 'OPS-123');
SELECT lockstep.approve('<approval-id>', current_user);
SET pg_lockstep.approval_token = '<token>';
DROP TABLE demo_users;
```

Tokens are local, server-side, expiring, and single-use.

## Protected-Table DELETE

```sql
CREATE TABLE demo_users (id bigserial PRIMARY KEY, email text);
SELECT lockstep.protect_table('public', 'demo_users');
SELECT lockstep.enable('enforce');
DELETE FROM demo_users;
```

The unqualified `DELETE` is evaluated as command tag `DELETE` against object identity `public.demo_users`. Request approval with the same object identity:

```sql
SELECT lockstep.request_approval('DELETE', 'public.demo_users', 'planned cleanup', 'OPS-124');
```

## Doctor

```sql
SELECT lockstep.doctor();
```

```sh
bin/pg_lockstep doctor --dsn postgresql://localhost/topology_db
```

Doctor explains unsafe posture and the current release limitation around cluster-level commands such as `DROP DATABASE`.
