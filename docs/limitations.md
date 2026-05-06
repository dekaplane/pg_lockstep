# Limitations

The current release uses `ddl_command_start` event triggers. This gives a reliable `tg_tag` but limited object identity. `object_identity` is nullable by design; the extension should not fake precision.

Cluster-level commands such as `DROP DATABASE` are not reliably intercepted by the current release SQL/event-trigger. Testing on PostgreSQL 14 showed that enabling `pg_lockstep` in the `postgres` database did not block or audit `DROP DATABASE some_db`. Native hooks are required for this class of protection.

General DML commands such as arbitrary `DELETE`, `UPDATE`, and `COPY` are not protected in the current release. There is opt-in trigger protection for unqualified `DELETE FROM table` on tables registered with `lockstep.protect_table`, but it does not catch every all-row form such as `DELETE FROM table WHERE true`.

Superusers can usually bypass or disable event triggers. Treat `pg_lockstep` as a command interlock and audit aid, not a substitute for least privilege.

Managed PostgreSQL services may restrict event triggers, extension installation, or `pgcrypto`.

Audit data is stored in the same database. For stronger tamper resistance, ship audit events to append-only storage out-of-band.

Blocked statements raise an exception from the event trigger. PostgreSQL rolls back table writes and `NOTIFY` messages in that failed statement transaction, so The current release includes the blocked event JSON in the exception `DETAIL` but does not guarantee durable audit rows for blocked attempts. Durable blocked-attempt audit is a target for the native hook design.
