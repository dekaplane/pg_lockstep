INSERT INTO lockstep.policy (name, command_tag, action, reason) VALUES
  ('default_drop_database_requires_approval', 'DROP DATABASE', 'require_approval', 'destructive DDL'),
  ('default_drop_schema_requires_approval', 'DROP SCHEMA', 'require_approval', 'destructive DDL'),
  ('default_drop_table_requires_approval', 'DROP TABLE', 'require_approval', 'destructive DDL'),
  ('default_truncate_requires_approval', 'TRUNCATE TABLE', 'require_approval', 'destructive DDL'),
  ('default_delete_requires_approval', 'DELETE', 'require_approval', 'unqualified protected-table DELETE'),
  ('default_alter_table_requires_approval', 'ALTER TABLE', 'require_approval', 'ALTER TABLE can be destructive'),
  ('default_alter_role_requires_approval', 'ALTER ROLE', 'require_approval', 'privilege administration'),
  ('default_create_role_warns', 'CREATE ROLE', 'warn', 'role administration'),
  ('default_grant_warns', 'GRANT', 'warn', 'privilege administration'),
  ('default_revoke_warns', 'REVOKE', 'warn', 'privilege administration'),
  ('default_create_extension_requires_approval', 'CREATE EXTENSION', 'require_approval', 'extension installation changes database behavior'),
  ('default_drop_extension_requires_approval', 'DROP EXTENSION', 'require_approval', 'extension removal changes database behavior')
ON CONFLICT (name) DO UPDATE
SET command_tag = EXCLUDED.command_tag,
    action = EXCLUDED.action,
    reason = EXCLUDED.reason,
    enabled = true;
