# Policy

Policy lives in `lockstep.policy`. Rules are local rows and can match command tag, database, role, and minimum score.

## Actions

- `allow`: record the event and allow execution.
- `warn`: record the event, optionally notify, and allow execution.
- `block`: block in `enforce` and `lockdown` modes.
- `require_approval`: require a valid local token in `enforce` and `lockdown` modes.

## Default Rules

The extension installs default rules:

- `DROP DATABASE`, `DROP SCHEMA`, `DROP TABLE`, `TRUNCATE TABLE`: require approval.
- Protected-table unqualified `DELETE`: require approval.
- `ALTER TABLE`: require approval because subcommands can be destructive.
- `ALTER ROLE`: require approval.
- `CREATE ROLE`, `GRANT`, `REVOKE`: warn.
- `CREATE EXTENSION`, `DROP EXTENSION`: require approval.

## Scores

Base scores are deterministic. Examples:

- `DROP DATABASE`: 100
- `DROP TABLE`: 95
- `TRUNCATE`: 90
- `DELETE`: 90
- `ALTER TABLE`: 85
- `ALTER ROLE`: 90
- `CREATE ROLE`: 75
- `GRANT`: 75
- `REVOKE`: 70
- `CREATE TABLE`: 20

Adjustments include production-like database names, superuser-like roles, known object tags when identity is available, and interactive `psql` sessions.

## Risk Mapping

- `0-19`: safe
- `20-39`: notice
- `40-69`: warn
- `70-89`: high
- `90-100`: critical
