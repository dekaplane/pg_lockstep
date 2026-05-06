# Future Native Hooks

The current release starts with SQL and PL/pgSQL event triggers because it is easy to inspect, install, and reason about. The next enforcement tier is a native C extension.

## ProcessUtility_hook

`ProcessUtility_hook` can intercept utility commands more directly than event triggers. It can provide stronger coverage for DDL and administrative statements, richer parse-tree context, and fewer blind spots.

This path usually requires `shared_preload_libraries`, because hooks must be installed when PostgreSQL starts.

This is the required path for cluster-level commands such as `DROP DATABASE`. SQL event triggers are database-local and did not block `DROP DATABASE` in PostgreSQL 14 testing, even when installed in the `postgres` maintenance database.

## ExecutorStart_hook

Future DML protection can use executor or planner hooks to estimate or inspect row-impact risk for:

- `DELETE`
- `UPDATE`
- `COPY`
- Large writes from migrations

The current release includes opt-in trigger protection for unqualified DELETE on protected tables. General DML protection still needs native hooks to avoid unacceptable overhead and false confidence.

## Stable Tables

The policy, audit, approvals, settings, and object tag tables can remain stable. A native hook can write the same JSON audit event format and call equivalent policy logic.

Native code can also address the current-release transactional audit limitation for blocked statements by integrating with PostgreSQL logging or by using a carefully designed out-of-transaction audit path.

## Why The Current Release Is Event-Trigger First

Event triggers make the first product portable and transparent. They also expose the most important limitation early: command tags are reliable, but object identity at `ddl_command_start` is limited. That honesty is preferable to a complicated first release that is harder to audit.
