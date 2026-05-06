# Security Policy

Please do not include secrets in public issues or pull requests.

Do not post database dumps, connection strings, Slack tokens, private keys,
credentials, customer logs, screenshots containing tokens, or production policy
files in public reports.

For sensitive vulnerability reports, use GitHub Security Advisories if
available for this repository. If advisories are unavailable, open a minimal
public issue that does not disclose exploit details or secrets and ask for a
private coordination channel.

`pg_lockstep` is a PostgreSQL-native safety extension. The current SQL/event
trigger release is not a replacement for least privilege, audited superuser
access, backups, or change-management controls.
