# Doctor

`pg_lockstep doctor` is a posture diagnostic for the current release SQL/event-trigger.

The SQL function is:

```sql
SELECT lockstep.doctor();
```

The CLI command is:

```sh
bin/pg_lockstep doctor --dsn postgresql://localhost/topology_db
```

PostgreSQL reserves schema names beginning with `pg_`, so SQL objects live in the `lockstep` schema even though the project and CLI are named `pg_lockstep`.

## Output

Doctor returns JSONB with:

- `overall_status`: `ok`, `warn`, or `critical`
- `checked_at`
- `database_name`
- `current_user`
- `session_user`
- `server_version`
- `pg_lockstep_mode`
- `pg_lockstep_version`
- `summary`
- `findings`
- `recommendations`
- `limitations`

## Checks

Doctor checks SQL-visible posture:

- current release event-trigger scope limitation.
- Whether the pg_lockstep event trigger is enabled.
- Whether mode is enforcing.
- Whether the current database is owned by a login role.
- Whether the current database is owned by a superuser.
- Whether the current database is owned by `postgres`.
- Whether current or session user is a superuser.
- Whether login-capable superuser roles exist.
- Whether login roles with `CREATEDB` exist.

## Uncertainty

Doctor cannot read every host-level or file-level control from ordinary SQL. In particular, it cannot fully verify `pg_hba.conf`, network exposure, bastion policy, OS access, or whether a role is usable remotely. Findings that depend on those controls use medium or low confidence.

## Product Truth

pg_lockstep current release is database-local. It can protect many DDL operations issued inside the protected database. It cannot reliably intercept shared-object or cluster-level commands such as `DROP DATABASE`, `CREATE DATABASE`, `ALTER SYSTEM`, tablespace changes, or actions by PostgreSQL superusers. Native hook mode with `ProcessUtility_hook` and `shared_preload_libraries` is required for that tier of enforcement.
