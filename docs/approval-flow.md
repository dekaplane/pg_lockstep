# Approval Flow

Approvals are local database rows in `lockstep.approvals`.

## Request

```sql
SELECT lockstep.request_approval('DROP TABLE', NULL, 'planned maintenance', 'OPS-123');
```

The request stores the command fingerprint, requester, database, reason, ticket, and expiry.

## Approve

```sql
SELECT lockstep.approve('<approval-id>', current_user);
```

Approval returns a random local token. The token is stored server-side and does not need JWT.

## Use

```sql
SET pg_lockstep.approval_token = '<token>';
DROP TABLE demo_users;
```

When the event trigger sees a `require_approval` action, it compares the session token to an approved, unexpired, unused approval with the same command fingerprint. A match is consumed and marked `used`.

Use the token returned by `lockstep.approve(...)`, not the approval UUID. For protected-table DELETE approvals, include the object identity:

```sql
SELECT lockstep.request_approval('DELETE', 'public.demo_users', 'planned cleanup', 'OPS-124');
```

## Trusted Alert Tokens

If `lockstep.configure_blocked_alerts(true, conninfo, true)` is enabled, pg_lockstep creates an approved, single-use token in a separate local PostgreSQL transaction for blocked `require_approval` events and includes it in the relay payload. This is intended only for trusted operational alert channels such as a restricted Slack incident channel.

## Reject

```sql
SELECT lockstep.reject('<approval-id>', current_user, 'not enough context');
```

Rejected approvals cannot be consumed.
