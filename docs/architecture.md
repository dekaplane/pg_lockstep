# Architecture

`pg_lockstep` starts as a SQL and PL/pgSQL PostgreSQL extension. The current release enforcement point is a PostgreSQL event trigger on `ddl_command_start`. PostgreSQL reserves schema names beginning with `pg_`, so SQL objects are installed in the `lockstep` schema.

## Extension-First

The interlock runs inside PostgreSQL rather than in a wrapper script or proxy. This keeps enforcement near the command execution path and works with any client that connects to the database.

## Hot Path

The hot path is intentionally boring:

1. PostgreSQL receives a DDL command.
2. The event trigger fires.
3. `tg_tag` is evaluated locally.
4. A deterministic risk score is generated.
5. Local policy chooses an action.
6. A JSON audit event is written.
7. PostgreSQL `NOTIFY` is emitted for warn/block-worthy events.
8. The command is allowed or blocked.

No network calls, cloud APIs, or LLM calls occur in the hot path.

## DML Guard Path

PostgreSQL event triggers do not see ordinary DML. The current release adds an opt-in table trigger path through `lockstep.protect_table(schema, table)`. The trigger evaluates unqualified `DELETE FROM table` against the same policy, approval, audit, and NOTIFY machinery.

## Cluster Boundary

The current release SQL/event-trigger is database-local. It can help with DDL issued inside a protected database, but it is not a cluster-wide interlock. PostgreSQL 14 testing showed that `DROP DATABASE` issued from the `postgres` maintenance database was not blocked or audited by an event trigger. Cluster-wide enforcement needs a native `ProcessUtility_hook` extension loaded with `shared_preload_libraries`.

## Alert Path

The relay is separate. It can `LISTEN pg_lockstep_events`, print JSON, and optionally post to Slack. Relay failures do not change database enforcement.

## Stable Data Model

Policy, audit, approval, and object tag tables are designed to survive a future native C hook implementation. Stronger interception can reuse the same tables and JSON event format.
