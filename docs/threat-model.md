# Threat Model

`pg_lockstep` reduces accidental destructive operations, risky migrations, and agentic tooling mistakes. It is not a full database activity monitoring platform.

## In Scope

- Local detection of dangerous DDL command tags.
- Deterministic risk scoring.
- Policy-based warn, block, and approval decisions.
- Local JSON audit trail.
- Optional local `NOTIFY` events for external relays.
- Single-use local approval tokens.
- Opt-in unqualified DELETE protection on protected tables.

## Out of Scope

- Replacement for least privilege.
- Protection from fully trusted superusers.
- Network firewall behavior.
- Cloud policy service.
- Telemetry.
- General DML row-impact estimation in the current release.

## Important Assumptions

Superusers may be able to disable extensions, event triggers, or modify audit tables in the current release. Managed PostgreSQL services may restrict extension installation or event trigger support.

A user connected as a PostgreSQL superuser, for example `psql -U postgres`, can perform cluster-level operations such as `DROP DATABASE` outside the protection of the current release SQL/event-trigger. Protect this with least privilege, restricted superuser access, backups, operational controls, and the future native hook design.

Slack relay messages are alerting only, not enforcement. If the relay stops or Slack is down, PostgreSQL still applies local policy.

Offline mode is the default trust model: policy, approvals, and audit are local to the database.

Blocked-statement audit has a current-release transactional caveat: when PostgreSQL aborts a statement because an event trigger raises an exception, ordinary audit table writes and `NOTIFY` messages from that statement are rolled back. The exception `DETAIL` carries the JSON event for operator capture.
