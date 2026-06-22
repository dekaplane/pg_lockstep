\echo Use "CREATE EXTENSION pg_lockstep" to load this file. \quit

CREATE SCHEMA IF NOT EXISTS lockstep;

COMMENT ON SCHEMA lockstep IS
'Local PostgreSQL command interlock schema for policy, approvals, and audit events.';

CREATE TABLE lockstep.settings (
  key text PRIMARY KEY,
  value jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE lockstep.settings IS 'Key/value runtime settings for lockstep.';
COMMENT ON COLUMN lockstep.settings.key IS 'Setting name.';
COMMENT ON COLUMN lockstep.settings.value IS 'JSONB setting value.';
COMMENT ON COLUMN lockstep.settings.updated_at IS 'Time this setting was last changed.';

CREATE TABLE lockstep.policy (
  id bigserial PRIMARY KEY,
  name text NOT NULL UNIQUE,
  enabled boolean NOT NULL DEFAULT true,
  command_tag text,
  database_name text,
  role_name text,
  schema_name text,
  object_name text,
  min_score int,
  action text NOT NULL CHECK (action IN ('allow', 'warn', 'block', 'require_approval')),
  reason text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE lockstep.policy IS 'Ordered local policy rules for SQL command risk decisions.';
COMMENT ON COLUMN lockstep.policy.command_tag IS 'Optional PostgreSQL command tag, for example DROP TABLE.';
COMMENT ON COLUMN lockstep.policy.min_score IS 'Optional minimum score required for this rule to match.';
COMMENT ON COLUMN lockstep.policy.action IS 'Policy action: allow, warn, block, or require_approval.';

CREATE TABLE lockstep.object_tags (
  id bigserial PRIMARY KEY,
  database_name text NOT NULL DEFAULT current_database(),
  schema_name text NOT NULL,
  object_name text NOT NULL,
  tag text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (database_name, schema_name, object_name, tag)
);

COMMENT ON TABLE lockstep.object_tags IS 'Local labels for database objects such as pii, critical, prod, financial, or auth.';

CREATE TABLE lockstep.protected_tables (
  id bigserial PRIMARY KEY,
  database_name text NOT NULL DEFAULT current_database(),
  schema_name text NOT NULL,
  table_name text NOT NULL,
  enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (database_name, schema_name, table_name)
);

COMMENT ON TABLE lockstep.protected_tables IS 'Tables with pg_lockstep DML triggers installed for local DELETE protection.';
COMMENT ON COLUMN lockstep.protected_tables.enabled IS 'Whether pg_lockstep should evaluate protected-table DML events.';

CREATE TABLE lockstep.approvals (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  command_fingerprint text NOT NULL,
  command_tag text NOT NULL,
  requested_by text NOT NULL,
  approved_by text,
  database_name text NOT NULL,
  reason text,
  ticket text,
  status text NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'used', 'expired')),
  token text,
  requested_at timestamptz NOT NULL DEFAULT now(),
  approved_at timestamptz,
  expires_at timestamptz NOT NULL,
  used_at timestamptz
);

COMMENT ON TABLE lockstep.approvals IS 'Single-use local approval records for commands that require clearance.';
COMMENT ON COLUMN lockstep.approvals.token IS 'Server-side approval token. Tokens are local and single-use.';

CREATE INDEX approvals_lookup_idx
  ON lockstep.approvals (command_fingerprint, token, status, expires_at);

CREATE TABLE lockstep.audit_log (
  id bigserial PRIMARY KEY,
  event_id text NOT NULL UNIQUE,
  ts timestamptz NOT NULL DEFAULT now(),
  database_name text NOT NULL,
  session_user_name text NOT NULL,
  current_user_name text NOT NULL,
  client_addr inet,
  application_name text,
  command_tag text NOT NULL,
  object_identity text,
  risk text NOT NULL,
  score int NOT NULL,
  action text NOT NULL,
  reasons text[] NOT NULL,
  command_fingerprint text NOT NULL,
  approved_by text,
  approval_id uuid,
  event jsonb NOT NULL
);

COMMENT ON TABLE lockstep.audit_log IS 'Structured JSON audit trail for pg_lockstep decisions.';
COMMENT ON COLUMN lockstep.audit_log.event IS 'Full JSON event emitted by lockstep.';

INSERT INTO lockstep.settings (key, value) VALUES
  ('mode', '"observe"'::jsonb),
  ('notify_enabled', 'true'::jsonb),
  ('min_notify_risk', '"warn"'::jsonb),
  ('require_ticket_for_approval', 'false'::jsonb),
  ('token_ttl_minutes', '10'::jsonb),
  ('blocked_alerts_dblink_enabled', 'false'::jsonb),
  ('blocked_alerts_dblink_conninfo', '""'::jsonb),
  ('trusted_alert_tokens_enabled', 'false'::jsonb)
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now();

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
ON CONFLICT (name) DO NOTHING;

CREATE OR REPLACE FUNCTION lockstep._setting_text(setting_key text, default_value text)
RETURNS text
LANGUAGE sql
STABLE
AS $$
  SELECT COALESCE(
    (SELECT trim(both '"' from value::text) FROM lockstep.settings WHERE key = setting_key),
    default_value
  );
$$;

COMMENT ON FUNCTION lockstep._setting_text(text, text) IS 'Internal helper returning a text setting value with a fallback.';

CREATE OR REPLACE FUNCTION lockstep._setting_bool(setting_key text, default_value boolean)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
  SELECT COALESCE(
    (SELECT value::text::boolean FROM lockstep.settings WHERE key = setting_key),
    default_value
  );
$$;

COMMENT ON FUNCTION lockstep._setting_bool(text, boolean) IS 'Internal helper returning a boolean setting value with a fallback.';

CREATE OR REPLACE FUNCTION lockstep._setting_int(setting_key text, default_value int)
RETURNS int
LANGUAGE sql
STABLE
AS $$
  SELECT COALESCE(
    (SELECT value::text::int FROM lockstep.settings WHERE key = setting_key),
    default_value
  );
$$;

COMMENT ON FUNCTION lockstep._setting_int(text, int) IS 'Internal helper returning an integer setting value with a fallback.';

CREATE OR REPLACE FUNCTION lockstep._risk_rank(risk text)
RETURNS int
LANGUAGE sql
IMMUTABLE
AS $$
  SELECT CASE risk
    WHEN 'safe' THEN 1
    WHEN 'notice' THEN 2
    WHEN 'warn' THEN 3
    WHEN 'high' THEN 4
    WHEN 'critical' THEN 5
    ELSE 0
  END;
$$;

COMMENT ON FUNCTION lockstep._risk_rank(text) IS 'Internal helper for comparing risk levels.';

CREATE OR REPLACE FUNCTION lockstep._fingerprint(command_tag text, object_identity text DEFAULT NULL)
RETURNS text
LANGUAGE sql
STABLE
AS $$
  SELECT 'sha256:' || encode(
    digest(
      current_database() || '|' || upper(coalesce(command_tag, '')) || '|' || coalesce(object_identity, ''),
      'sha256'
    ),
    'hex'
  );
$$;

COMMENT ON FUNCTION lockstep._fingerprint(text, text) IS 'Internal deterministic fingerprint for an approval-scoped command.';

CREATE OR REPLACE FUNCTION lockstep.set_mode(mode text)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  IF mode NOT IN ('observe', 'warn', 'enforce', 'lockdown') THEN
    RAISE EXCEPTION 'invalid pg_lockstep mode: %', mode
      USING HINT = 'Use observe, warn, enforce, or lockdown.';
  END IF;

  INSERT INTO lockstep.settings (key, value, updated_at)
  VALUES ('mode', to_jsonb(mode), now())
  ON CONFLICT (key) DO UPDATE
    SET value = EXCLUDED.value, updated_at = now();
END;
$$;

COMMENT ON FUNCTION lockstep.set_mode(text) IS 'Set pg_lockstep mode to observe, warn, enforce, or lockdown.';

CREATE OR REPLACE FUNCTION lockstep.get_mode()
RETURNS text
LANGUAGE sql
STABLE
AS $$
  SELECT lockstep._setting_text('mode', 'observe');
$$;

COMMENT ON FUNCTION lockstep.get_mode() IS 'Return the current pg_lockstep mode.';

CREATE OR REPLACE FUNCTION lockstep.enable(mode text DEFAULT 'observe')
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  PERFORM lockstep.set_mode(mode);
  ALTER EVENT TRIGGER pg_lockstep_ddl_command_start ENABLE;
END;
$$;

COMMENT ON FUNCTION lockstep.enable(text) IS 'Enable the pg_lockstep DDL event trigger and set the requested mode.';

CREATE OR REPLACE FUNCTION lockstep.disable()
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  PERFORM lockstep.set_mode('observe');
  ALTER EVENT TRIGGER pg_lockstep_ddl_command_start DISABLE;
END;
$$;

COMMENT ON FUNCTION lockstep.disable() IS 'Disable the pg_lockstep DDL event trigger and return mode to observe.';

CREATE OR REPLACE FUNCTION lockstep.tag_object(target_schema text, target_object text, target_tag text)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  INSERT INTO lockstep.object_tags (database_name, schema_name, object_name, tag)
  VALUES (current_database(), target_schema, target_object, lower(target_tag))
  ON CONFLICT (database_name, schema_name, object_name, tag) DO NOTHING;
END;
$$;

COMMENT ON FUNCTION lockstep.tag_object(text, text, text) IS 'Attach a local risk tag to a database object.';

CREATE OR REPLACE FUNCTION lockstep.untag_object(target_schema text, target_object text, target_tag text)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  DELETE FROM lockstep.object_tags
  WHERE database_name = current_database()
    AND schema_name = target_schema
    AND object_name = target_object
    AND tag = lower(target_tag);
END;
$$;

COMMENT ON FUNCTION lockstep.untag_object(text, text, text) IS 'Remove a local risk tag from a database object.';

CREATE OR REPLACE FUNCTION lockstep.evaluate_command(command_tag text, object_identity text DEFAULT NULL)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
  normalized_tag text := upper(coalesce(command_tag, ''));
  db_name text := current_database();
  app_name text := current_setting('application_name', true);
  score int := 10;
  risk text := 'safe';
  action text := 'allow';
  reasons text[] := ARRAY[]::text[];
  matched_policy record;
  has_pii boolean := false;
  has_critical boolean := false;
  object_schema text;
  parsed_object_name text;
BEGIN
  score := CASE normalized_tag
    WHEN 'DROP DATABASE' THEN 100
    WHEN 'DROP SCHEMA' THEN 95
    WHEN 'DROP TABLE' THEN 95
    WHEN 'TRUNCATE' THEN 90
    WHEN 'TRUNCATE TABLE' THEN 90
    WHEN 'ALTER ROLE' THEN 90
    WHEN 'CREATE ROLE' THEN 75
    WHEN 'GRANT' THEN 75
    WHEN 'REVOKE' THEN 70
    WHEN 'CREATE EXTENSION' THEN 80
    WHEN 'DROP EXTENSION' THEN 85
    WHEN 'ALTER TABLE' THEN 85
    WHEN 'DELETE' THEN 90
    WHEN 'CREATE TABLE' THEN 20
    WHEN 'CREATE INDEX' THEN 10
    ELSE 10
  END;

  IF normalized_tag LIKE 'DROP %' OR normalized_tag IN ('TRUNCATE', 'TRUNCATE TABLE') THEN
    reasons := array_append(reasons, 'destructive DDL');
  ELSIF normalized_tag = 'DELETE' THEN
    reasons := array_append(reasons, 'destructive DML');
  ELSIF normalized_tag = 'ALTER TABLE' THEN
    reasons := array_append(reasons, 'ALTER TABLE can be destructive');
  ELSIF normalized_tag IN ('ALTER ROLE', 'CREATE ROLE', 'GRANT', 'REVOKE') THEN
    reasons := array_append(reasons, 'privilege administration');
  ELSIF normalized_tag LIKE '%EXTENSION' THEN
    reasons := array_append(reasons, 'extension changes database behavior');
  ELSE
    reasons := array_append(reasons, 'baseline command score');
  END IF;

  IF db_name ~* '(prod|production|live)' THEN
    score := score + 10;
    reasons := array_append(reasons, 'production-like database');
  END IF;

  IF current_user IN ('postgres', 'rds_superuser', 'cloudsqlsuperuser') THEN
    score := score + 5;
    reasons := array_append(reasons, 'superuser-like role');
  END IF;

  IF app_name ILIKE '%psql%' THEN
    score := score + 3;
    reasons := array_append(reasons, 'interactive psql session');
  END IF;

  IF object_identity IS NOT NULL AND position('.' in object_identity) > 0 THEN
    object_schema := split_part(object_identity, '.', 1);
    parsed_object_name := split_part(object_identity, '.', 2);

    SELECT EXISTS (
      SELECT 1 FROM lockstep.object_tags
      WHERE database_name = db_name
        AND schema_name = object_schema
        AND object_name = parsed_object_name
        AND tag = 'pii'
    ) INTO has_pii;

    SELECT EXISTS (
      SELECT 1 FROM lockstep.object_tags
      WHERE database_name = db_name
        AND schema_name = object_schema
        AND object_name = parsed_object_name
        AND tag = 'critical'
    ) INTO has_critical;
  END IF;

  IF has_pii THEN
    score := score + 10;
    reasons := array_append(reasons, 'object tagged pii');
  END IF;

  IF has_critical THEN
    score := score + 10;
    reasons := array_append(reasons, 'object tagged critical');
  END IF;

  score := least(score, 100);

  risk := CASE
    WHEN score <= 19 THEN 'safe'
    WHEN score <= 39 THEN 'notice'
    WHEN score <= 69 THEN 'warn'
    WHEN score <= 89 THEN 'high'
    ELSE 'critical'
  END;

  IF risk IN ('high', 'critical') THEN
    action := 'warn';
  END IF;

  SELECT p.*
    INTO matched_policy
  FROM lockstep.policy p
  WHERE p.enabled
    AND (p.command_tag IS NULL OR upper(p.command_tag) = normalized_tag)
    AND (p.database_name IS NULL OR p.database_name = db_name)
    AND (p.role_name IS NULL OR p.role_name = current_user)
    AND (p.min_score IS NULL OR score >= p.min_score)
  ORDER BY
    (p.command_tag IS NOT NULL)::int DESC,
    (p.database_name IS NOT NULL)::int DESC,
    (p.role_name IS NOT NULL)::int DESC,
    (p.min_score IS NOT NULL)::int DESC,
    p.id ASC
  LIMIT 1;

  IF matched_policy.id IS NOT NULL THEN
    action := matched_policy.action;
    reasons := array_append(reasons, matched_policy.reason || ' by policy');
  END IF;

  RETURN jsonb_build_object(
    'risk', risk,
    'score', score,
    'action', action,
    'reasons', to_jsonb(reasons),
    'command_fingerprint', lockstep._fingerprint(normalized_tag, object_identity)
  );
END;
$$;

COMMENT ON FUNCTION lockstep.evaluate_command(text, text) IS 'Evaluate a command tag and optional object identity into a local risk decision.';

CREATE OR REPLACE FUNCTION lockstep.request_approval(
  command_tag text,
  object_identity text,
  reason text DEFAULT NULL,
  ticket text DEFAULT NULL
)
RETURNS uuid
LANGUAGE plpgsql
AS $$
DECLARE
  decision jsonb;
  approval_id uuid;
  require_ticket boolean := lockstep._setting_bool('require_ticket_for_approval', false);
  ttl int := lockstep._setting_int('token_ttl_minutes', 10);
BEGIN
  IF require_ticket AND nullif(ticket, '') IS NULL THEN
    RAISE EXCEPTION 'pg_lockstep approval ticket is required';
  END IF;

  decision := lockstep.evaluate_command(command_tag, object_identity);

  INSERT INTO lockstep.approvals (
    command_fingerprint,
    command_tag,
    requested_by,
    database_name,
    reason,
    ticket,
    status,
    expires_at
  )
  VALUES (
    decision->>'command_fingerprint',
    upper(command_tag),
    current_user,
    current_database(),
    reason,
    ticket,
    'pending',
    now() + make_interval(mins => ttl)
  )
  RETURNING id INTO approval_id;

  RETURN approval_id;
END;
$$;

COMMENT ON FUNCTION lockstep.request_approval(text, text, text, text) IS 'Create a pending local approval request for a command.';

CREATE OR REPLACE FUNCTION lockstep.approve(
  approval_id uuid,
  approved_by text,
  ttl_minutes int DEFAULT NULL
)
RETURNS text
LANGUAGE plpgsql
AS $$
DECLARE
  approval_token text;
  effective_ttl int := COALESCE(ttl_minutes, lockstep._setting_int('token_ttl_minutes', 10));
BEGIN
  approval_token := encode(gen_random_bytes(24), 'base64');

  UPDATE lockstep.approvals
  SET status = 'approved',
      approved_by = approve.approved_by,
      token = approval_token,
      approved_at = now(),
      expires_at = now() + make_interval(mins => effective_ttl)
  WHERE id = approval_id
    AND status = 'pending'
  RETURNING token INTO approval_token;

  IF approval_token IS NULL THEN
    RAISE EXCEPTION 'pg_lockstep approval not found or not pending: %', approval_id;
  END IF;

  RETURN approval_token;
END;
$$;

COMMENT ON FUNCTION lockstep.approve(uuid, text, int) IS 'Approve a pending request and return a single-use local token.';

CREATE OR REPLACE FUNCTION lockstep.reject(
  approval_id uuid,
  rejected_by text,
  reason text DEFAULT NULL
)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  UPDATE lockstep.approvals
  SET status = 'rejected',
      approved_by = reject.rejected_by,
      reason = COALESCE(reject.reason, approvals.reason),
      approved_at = now()
  WHERE id = approval_id
    AND status = 'pending';

  IF NOT FOUND THEN
    RAISE EXCEPTION 'pg_lockstep approval not found or not pending: %', approval_id;
  END IF;
END;
$$;

COMMENT ON FUNCTION lockstep.reject(uuid, text, text) IS 'Reject a pending local approval request.';

CREATE OR REPLACE FUNCTION lockstep.consume_approval(command_fingerprint text, token text)
RETURNS uuid
LANGUAGE plpgsql
AS $$
DECLARE
  approval_id uuid;
BEGIN
  UPDATE lockstep.approvals
  SET status = 'used',
      used_at = now()
  WHERE id = (
    SELECT a.id
    FROM lockstep.approvals a
    WHERE a.command_fingerprint = consume_approval.command_fingerprint
      AND a.token = consume_approval.token
      AND a.status = 'approved'
      AND a.expires_at > now()
    ORDER BY a.approved_at ASC
    LIMIT 1
    FOR UPDATE
  )
  RETURNING id INTO approval_id;

  RETURN approval_id;
END;
$$;

COMMENT ON FUNCTION lockstep.consume_approval(text, text) IS 'Consume a matching unexpired single-use approval token.';

CREATE OR REPLACE FUNCTION lockstep.current_events(limit_count int DEFAULT 50)
RETURNS SETOF lockstep.audit_log
LANGUAGE sql
STABLE
AS $$
  SELECT *
  FROM lockstep.audit_log
  ORDER BY id DESC
  LIMIT greatest(0, limit_count);
$$;

COMMENT ON FUNCTION lockstep.current_events(int) IS 'Return recent pg_lockstep audit events.';

CREATE OR REPLACE FUNCTION lockstep.configure_blocked_alerts(
  use_dblink boolean DEFAULT true,
  conninfo text DEFAULT NULL,
  trusted_approval_tokens boolean DEFAULT false
)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
  effective_conninfo text := COALESCE(conninfo, 'dbname=' || current_database());
BEGIN
  INSERT INTO lockstep.settings (key, value, updated_at)
  VALUES
    ('blocked_alerts_dblink_enabled', to_jsonb(use_dblink), now()),
    ('blocked_alerts_dblink_conninfo', to_jsonb(effective_conninfo), now()),
    ('trusted_alert_tokens_enabled', to_jsonb(trusted_approval_tokens), now())
  ON CONFLICT (key) DO UPDATE
    SET value = EXCLUDED.value, updated_at = now();
END;
$$;

COMMENT ON FUNCTION lockstep.configure_blocked_alerts(boolean, text, boolean) IS 'Configure optional out-of-transaction blocked-event NOTIFY delivery via local dblink.';

CREATE OR REPLACE FUNCTION lockstep._emit_notify_via_dblink(event_doc jsonb)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
  conninfo text := lockstep._setting_text('blocked_alerts_dblink_conninfo', '');
  command text;
  result text;
  alert_doc jsonb := event_doc || jsonb_build_object(
    'delivery', jsonb_build_object(
      'method', 'dblink_notify',
      'transactional', false
    )
  );
  trusted_tokens_enabled boolean := lockstep._setting_bool('trusted_alert_tokens_enabled', false);
  approval_id uuid;
  approval_token text;
  token_ttl int := lockstep._setting_int('token_ttl_minutes', 10);
  expires_at timestamptz;
BEGIN
  IF conninfo IS NULL OR conninfo = '' THEN
    conninfo := 'dbname=' || current_database();
  END IF;

  IF to_regprocedure('dblink_exec(text,text)') IS NULL THEN
    RAISE LOG 'pg_lockstep blocked alert could not be delivered: dblink is not installed in database %', current_database();
    RETURN;
  END IF;

  IF trusted_tokens_enabled AND event_doc->>'action' = 'require_approval' THEN
    approval_id := gen_random_uuid();
    approval_token := encode(gen_random_bytes(24), 'base64');
    expires_at := clock_timestamp() + make_interval(mins => token_ttl);

    alert_doc := alert_doc || jsonb_build_object(
      'trusted_approval', jsonb_build_object(
        'approval_id', approval_id,
        'token', approval_token,
        'expires_at', expires_at,
        'use_sql', format('SET pg_lockstep.approval_token = %L;', approval_token),
        'warning', 'Sensitive single-use approval token. Share only in trusted operational channels.'
      )
    );

    command := format(
      'DO $pg_lockstep_dblink$ BEGIN
         INSERT INTO lockstep.approvals (
           id,
           command_fingerprint,
           command_tag,
           requested_by,
           approved_by,
           database_name,
           reason,
           ticket,
           status,
           token,
           requested_at,
           approved_at,
           expires_at
         )
         VALUES (
           %L::uuid,
           %L,
           %L,
           %L,
           %L,
           %L,
           %L,
           %L,
           ''approved'',
           %L,
           clock_timestamp(),
           clock_timestamp(),
           %L::timestamptz
         );
         PERFORM pg_notify(%L, %L);
       END $pg_lockstep_dblink$;',
      approval_id::text,
      event_doc->>'fingerprint',
      event_doc->>'command_tag',
      event_doc->>'current_user',
      'pg_lockstep_trusted_alert',
      event_doc->>'database',
      'Auto-generated approval token for trusted alert channel',
      event_doc->>'event_id',
      approval_token,
      expires_at::text,
      'pg_lockstep_events',
      alert_doc::text
    );
  ELSE
    command := format(
      'DO $pg_lockstep_dblink$ BEGIN PERFORM pg_notify(%L, %L); END $pg_lockstep_dblink$;',
      'pg_lockstep_events',
      alert_doc::text
    );
  END IF;

  BEGIN
    EXECUTE 'SELECT dblink_exec($1, $2)'
      INTO result
      USING conninfo, command;
  EXCEPTION
    WHEN OTHERS THEN
      RAISE LOG 'pg_lockstep blocked alert delivery via dblink failed: %', SQLERRM;
  END;
END;
$$;

COMMENT ON FUNCTION lockstep._emit_notify_via_dblink(jsonb) IS 'Internal helper that emits blocked-event NOTIFY through a separate local dblink transaction.';

CREATE OR REPLACE FUNCTION lockstep._emit_notify(event_doc jsonb, durable boolean DEFAULT false)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
  notify_enabled boolean := lockstep._setting_bool('notify_enabled', true);
  min_notify_risk text := lockstep._setting_text('min_notify_risk', 'warn');
  risk text := event_doc->>'risk';
  action text := event_doc->>'action';
BEGIN
  IF NOT notify_enabled THEN
    RETURN;
  END IF;

  IF action NOT IN ('warn', 'block', 'require_approval') THEN
    RETURN;
  END IF;

  IF lockstep._risk_rank(risk) < lockstep._risk_rank(min_notify_risk) THEN
    RETURN;
  END IF;

  IF durable AND lockstep._setting_bool('blocked_alerts_dblink_enabled', false) THEN
    PERFORM lockstep._emit_notify_via_dblink(event_doc);
  ELSE
    PERFORM pg_notify('pg_lockstep_events', event_doc::text);
  END IF;
END;
$$;

COMMENT ON FUNCTION lockstep._emit_notify(jsonb, boolean) IS 'Internal helper that emits pg_lockstep NOTIFY events transactionally or through optional durable dblink delivery.';

CREATE OR REPLACE FUNCTION lockstep.protect_table(target_schema text, target_table text)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
  target_regclass regclass;
BEGIN
  SELECT to_regclass(format('%I.%I', target_schema, target_table)) INTO target_regclass;

  IF target_regclass IS NULL THEN
    RAISE EXCEPTION 'pg_lockstep cannot protect missing table %.%', target_schema, target_table;
  END IF;

  INSERT INTO lockstep.protected_tables (database_name, schema_name, table_name, enabled)
  VALUES (current_database(), target_schema, target_table, true)
  ON CONFLICT (database_name, schema_name, table_name) DO UPDATE
    SET enabled = true;

  EXECUTE format(
    'DROP TRIGGER IF EXISTS pg_lockstep_before_delete ON %I.%I',
    target_schema,
    target_table
  );

  EXECUTE format(
    'CREATE TRIGGER pg_lockstep_before_delete BEFORE DELETE ON %I.%I FOR EACH STATEMENT EXECUTE FUNCTION lockstep.on_before_delete()',
    target_schema,
    target_table
  );
END;
$$;

COMMENT ON FUNCTION lockstep.protect_table(text, text) IS 'Install pg_lockstep DELETE protection on one table.';

CREATE OR REPLACE FUNCTION lockstep.unprotect_table(target_schema text, target_table text)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  UPDATE lockstep.protected_tables
  SET enabled = false
  WHERE database_name = current_database()
    AND protected_tables.schema_name = target_schema
    AND protected_tables.table_name = target_table;

  EXECUTE format(
    'DROP TRIGGER IF EXISTS pg_lockstep_before_delete ON %I.%I',
    target_schema,
    target_table
  );
END;
$$;

COMMENT ON FUNCTION lockstep.unprotect_table(text, text) IS 'Remove pg_lockstep DELETE protection from one table.';

CREATE OR REPLACE FUNCTION lockstep.protect_all_tables(target_schema text DEFAULT 'public')
RETURNS int
LANGUAGE plpgsql
AS $$
DECLARE
  table_record record;
  protected_count int := 0;
BEGIN
  FOR table_record IN
    SELECT c.relname AS table_name
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = target_schema
      AND c.relkind IN ('r', 'p')
  LOOP
    PERFORM lockstep.protect_table(target_schema, table_record.table_name);
    protected_count := protected_count + 1;
  END LOOP;

  RETURN protected_count;
END;
$$;

COMMENT ON FUNCTION lockstep.protect_all_tables(text) IS 'Install pg_lockstep DELETE protection on all ordinary and partitioned tables in a schema.';

CREATE OR REPLACE FUNCTION lockstep.on_before_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  current_query text;
  object_identity text := format('%I.%I', TG_TABLE_SCHEMA, TG_TABLE_NAME);
  decision jsonb;
  event_doc jsonb;
  event_id text;
  now_ts timestamptz := clock_timestamp();
  mode text := lockstep.get_mode();
  risk text;
  score int;
  action text;
  reasons text[];
  fingerprint text;
  approval_token text;
  approval_id uuid;
  approved_by text;
  effective_action text;
  is_protected boolean;
BEGIN
  SELECT p.enabled
  INTO is_protected
  FROM lockstep.protected_tables p
  WHERE p.database_name = current_database()
    AND p.schema_name = TG_TABLE_SCHEMA
    AND p.table_name = TG_TABLE_NAME;

  IF NOT COALESCE(is_protected, false) THEN
    RETURN NULL;
  END IF;

  SELECT a.query
  INTO current_query
  FROM pg_stat_activity a
  WHERE a.pid = pg_backend_pid();

  IF current_query IS NULL OR current_query !~* '\mdelete\M' THEN
    RETURN NULL;
  END IF;

  IF current_query ~* '\mwhere\M' THEN
    RETURN NULL;
  END IF;

  decision := lockstep.evaluate_command('DELETE', object_identity);
  risk := decision->>'risk';
  score := (decision->>'score')::int;
  action := decision->>'action';
  reasons := ARRAY(SELECT jsonb_array_elements_text(decision->'reasons'));
  reasons := array_append(reasons, 'unqualified DELETE on protected table');
  fingerprint := decision->>'command_fingerprint';
  effective_action := action;

  IF mode = 'lockdown' AND risk IN ('high', 'critical') AND action = 'allow' THEN
    effective_action := 'require_approval';
    reasons := array_append(reasons, 'lockdown requires approval for high-risk DML');
  END IF;

  IF mode IN ('enforce', 'lockdown') AND effective_action = 'require_approval' THEN
    approval_token := current_setting('pg_lockstep.approval_token', true);
    IF approval_token IS NOT NULL AND approval_token <> '' THEN
      approval_id := lockstep.consume_approval(fingerprint, approval_token);
      IF approval_id IS NOT NULL THEN
        SELECT a.approved_by INTO approved_by
        FROM lockstep.approvals a
        WHERE a.id = approval_id;
        effective_action := 'allow';
        reasons := array_append(reasons, 'valid local approval token consumed');
      ELSE
        reasons := array_append(reasons, 'approval token was provided but did not match this command fingerprint');
      END IF;
    END IF;
  END IF;

  event_id := 'pg_lockstep_' ||
    to_char(now_ts AT TIME ZONE 'UTC', 'YYYYMMDDHH24MISSUS') ||
    '_' ||
    encode(gen_random_bytes(6), 'hex');

  event_doc := jsonb_build_object(
    'event_id', event_id,
    'ts', now_ts,
    'database', current_database(),
    'session_user', session_user,
    'current_user', current_user,
    'client_addr', inet_client_addr(),
    'application_name', current_setting('application_name', true),
    'command_tag', 'DELETE',
    'object_identity', object_identity,
    'risk', risk,
    'score', score,
    'action', effective_action,
    'reasons', to_jsonb(reasons),
    'fingerprint', fingerprint,
    'mode', mode
  );

  IF approval_id IS NOT NULL THEN
    event_doc := event_doc ||
      jsonb_build_object('approval_id', approval_id, 'approved_by', approved_by);
  END IF;

  INSERT INTO lockstep.audit_log (
    event_id,
    ts,
    database_name,
    session_user_name,
    current_user_name,
    client_addr,
    application_name,
    command_tag,
    object_identity,
    risk,
    score,
    action,
    reasons,
    command_fingerprint,
    approved_by,
    approval_id,
    event
  )
  VALUES (
    event_id,
    now_ts,
    current_database(),
    session_user,
    current_user,
    inet_client_addr(),
    current_setting('application_name', true),
    'DELETE',
    object_identity,
    risk,
    score,
    effective_action,
    reasons,
    fingerprint,
    approved_by,
    approval_id,
    event_doc
  );

  PERFORM lockstep._emit_notify(
    event_doc,
    mode IN ('enforce', 'lockdown') AND effective_action IN ('block', 'require_approval')
  );

  IF mode IN ('enforce', 'lockdown') AND effective_action IN ('block', 'require_approval') THEN
    RAISE EXCEPTION 'pg_lockstep blocked command'
      USING DETAIL = event_doc::text,
            HINT = format(
              'Run SELECT lockstep.request_approval(%L, %L, %L, %L); then SELECT lockstep.approve(<approval_id>, current_user); then SET pg_lockstep.approval_token to the returned token, not the approval UUID.',
              'DELETE',
              object_identity,
              'reason',
              'ticket'
            );
  END IF;

  RETURN NULL;
END;
$$;

COMMENT ON FUNCTION lockstep.on_before_delete() IS 'Table trigger entrypoint that audits and optionally blocks unqualified DELETE on protected tables.';

CREATE OR REPLACE FUNCTION lockstep.self_test()
RETURNS jsonb
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
  trigger_exists boolean;
  policy_count bigint;
  audit_count bigint;
  protected_table_count bigint;
BEGIN
  SELECT EXISTS (
    SELECT 1
    FROM pg_event_trigger
    WHERE evtname = 'pg_lockstep_ddl_command_start'
  ) INTO trigger_exists;

  SELECT count(*) INTO policy_count FROM lockstep.policy WHERE enabled;
  SELECT count(*) INTO audit_count FROM lockstep.audit_log;
  SELECT count(*) INTO protected_table_count FROM lockstep.protected_tables WHERE enabled;

  RETURN jsonb_build_object(
    'mode', lockstep.get_mode(),
    'trigger_exists', trigger_exists,
    'notify_enabled', lockstep._setting_bool('notify_enabled', true),
    'policy_count', policy_count,
    'audit_count', audit_count,
    'protected_table_count', protected_table_count
  );
END;
$$;

COMMENT ON FUNCTION lockstep.self_test() IS 'Return basic pg_lockstep health information.';

CREATE OR REPLACE FUNCTION lockstep.doctor()
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
  findings jsonb := '[]'::jsonb;
  recommendations jsonb := '[]'::jsonb;
  limitations jsonb := '[]'::jsonb;
  summary_actions jsonb := '[]'::jsonb;
  status text := 'ok';
  mode text := lockstep.get_mode();
  extension_version text;
  db_owner record;
  current_role_rec record;
  session_role_rec record;
  postgres_role_rec record;
  login_superuser_count int := 0;
  createdb_login_count int := 0;
  event_trigger_enabled text;
  suggested_owner text;
  remediation_sql text;
  critical_count int := 0;
  warning_count int := 0;
BEGIN
  SELECT e.extversion
  INTO extension_version
  FROM pg_extension e
  WHERE e.extname = 'pg_lockstep';

  SELECT d.datname,
         r.rolname,
         r.rolcanlogin,
         r.rolsuper
  INTO db_owner
  FROM pg_database d
  JOIN pg_roles r ON r.oid = d.datdba
  WHERE d.datname = current_database();

  SELECT r.rolname, r.rolcanlogin, r.rolsuper, r.rolcreatedb
  INTO current_role_rec
  FROM pg_roles r
  WHERE r.rolname = current_user;

  SELECT r.rolname, r.rolcanlogin, r.rolsuper, r.rolcreatedb
  INTO session_role_rec
  FROM pg_roles r
  WHERE r.rolname = session_user;

  SELECT r.rolname, r.rolcanlogin, r.rolsuper, r.rolcreatedb
  INTO postgres_role_rec
  FROM pg_roles r
  WHERE r.rolname = 'postgres';

  SELECT count(*)
  INTO login_superuser_count
  FROM pg_roles r
  WHERE r.rolsuper
    AND r.rolcanlogin;

  SELECT count(*)
  INTO createdb_login_count
  FROM pg_roles r
  WHERE r.rolcreatedb
    AND r.rolcanlogin
    AND NOT r.rolsuper;

  SELECT e.evtenabled
  INTO event_trigger_enabled
  FROM pg_event_trigger e
  WHERE e.evtname = 'pg_lockstep_ddl_command_start';

  limitations := limitations || jsonb_build_array(jsonb_build_object(
    'id', 'EVENT_TRIGGER_SCOPE_LIMITATION',
    'title', 'Current release SQL/event-trigger mode is database-local',
    'detail', 'This pg_lockstep release can protect many database-local DDL operations, but it cannot reliably intercept shared-object or cluster-level commands such as DROP DATABASE, CREATE DATABASE, ALTER SYSTEM, tablespace changes, or all role changes.',
    'recommendation', 'Use least privilege now. For cluster-level interception, plan native hook mode with ProcessUtility_hook and shared_preload_libraries.',
    'confidence', 'high'
  ));

  findings := findings || jsonb_build_array(jsonb_build_object(
    'id', 'EVENT_TRIGGER_SCOPE_LIMITATION',
    'severity', 'warn',
    'title', 'This release cannot protect cluster-level commands',
    'detail', 'Event triggers are database-local and do not reliably fire for shared-object or cluster-level commands such as DROP DATABASE.',
    'why_it_matters', 'A PostgreSQL superuser can connect to another database and drop this database without pg_lockstep seeing the command.',
    'recommendation', 'Use least privilege and restrict superuser access. Native hook mode with ProcessUtility_hook and shared_preload_libraries is needed for cluster-level interception.',
    'sql', NULL,
    'confidence', 'high'
  ));

  summary_actions := summary_actions || jsonb_build_array(
    'Do not rely on this release for DROP DATABASE, CREATE DATABASE, ALTER SYSTEM, role, or tablespace interception; use least privilege now and plan native hook mode for cluster-level enforcement.'
  );

  recommendations := recommendations || jsonb_build_array(jsonb_build_object(
    'id', 'NATIVE_HOOK_MODE_FOR_CLUSTER_COMMANDS',
    'title', 'Plan cluster-level enforcement',
    'detail', 'Use ProcessUtility_hook loaded through shared_preload_libraries to intercept DROP DATABASE, CREATE DATABASE, ALTER SYSTEM, role, tablespace, and other shared-object commands before execution.'
  ));

  IF event_trigger_enabled IS DISTINCT FROM 'O' THEN
    findings := findings || jsonb_build_array(jsonb_build_object(
      'id', 'EVENT_TRIGGER_DISABLED',
      'severity', 'critical',
      'title', 'pg_lockstep event trigger is not enabled',
      'detail', 'The pg_lockstep DDL event trigger is missing or disabled in this database.',
      'why_it_matters', 'Database-local DDL protection depends on this event trigger firing.',
      'recommendation', 'Run SELECT lockstep.enable(''enforce''); after validating policy in observe mode.',
      'sql', 'SELECT lockstep.enable(''enforce'');',
      'confidence', 'high'
    ));
    summary_actions := summary_actions || jsonb_build_array(
      'Enable the pg_lockstep event trigger in this database after validating policy.'
    );
  END IF;

  IF mode IN ('observe', 'warn') THEN
    findings := findings || jsonb_build_array(jsonb_build_object(
      'id', 'NON_ENFORCING_MODE',
      'severity', 'warn',
      'title', 'pg_lockstep is not in an enforcing mode',
      'detail', format('Current mode is %s. This mode audits or warns but does not block commands.', mode),
      'why_it_matters', 'Dangerous database-local commands can still execute in observe or warn mode.',
      'recommendation', 'Use observe for rollout, then switch to enforce when policy has been validated.',
      'sql', 'SELECT lockstep.enable(''enforce'');',
      'confidence', 'high'
    ));
    summary_actions := summary_actions || jsonb_build_array(
      format('Move pg_lockstep from %s mode to enforce mode when rollout validation is complete.', mode)
    );
  END IF;

  suggested_owner := regexp_replace(current_database(), '[^a-zA-Z0-9_]', '_', 'g') || '_owner';
  remediation_sql := format(
    'CREATE ROLE %I NOLOGIN; ALTER DATABASE %I OWNER TO %I;',
    suggested_owner,
    current_database(),
    suggested_owner
  );

  IF db_owner.rolcanlogin THEN
    findings := findings || jsonb_build_array(jsonb_build_object(
      'id', 'DATABASE_OWNED_BY_LOGIN_ROLE',
      'severity', 'critical',
      'title', 'Current database is owned by a login role',
      'detail', format('Database %I is owned by role %I, which can login.', current_database(), db_owner.rolname),
      'why_it_matters', 'A login owner role increases blast radius if credentials are compromised.',
      'recommendation', 'Use a dedicated NOLOGIN owner role and grant application privileges separately.',
      'sql', remediation_sql,
      'confidence', 'high'
    ));
  END IF;

  IF db_owner.rolsuper THEN
    findings := findings || jsonb_build_array(jsonb_build_object(
      'id', 'DATABASE_OWNED_BY_SUPERUSER',
      'severity', 'critical',
      'title', 'Current database is owned by a superuser',
      'detail', format('Database %I is owned by superuser role %I.', current_database(), db_owner.rolname),
      'why_it_matters', 'Superusers can bypass pg_lockstep, disable event triggers, and perform cluster-level operations.',
      'recommendation', 'Move database ownership to a dedicated NOLOGIN non-superuser owner role.',
      'sql', remediation_sql,
      'confidence', 'high'
    ));
  END IF;

  IF db_owner.rolname = 'postgres' THEN
    findings := findings || jsonb_build_array(jsonb_build_object(
      'id', 'DATABASE_OWNED_BY_POSTGRES',
      'severity', 'critical',
      'title', 'Current database is owned by postgres',
      'detail', format('Database %I is owned by the postgres role.', current_database()),
      'why_it_matters', 'The postgres role is commonly a PostgreSQL superuser and emergency administrative identity.',
      'recommendation', 'Use a dedicated NOLOGIN owner role instead of postgres.',
      'sql', remediation_sql,
      'confidence', 'high'
    ));
  END IF;

  IF COALESCE(db_owner.rolcanlogin, false)
     OR COALESCE(db_owner.rolsuper, false)
     OR db_owner.rolname = 'postgres' THEN
    summary_actions := summary_actions || jsonb_build_array(
      format('Move database ownership to a dedicated NOLOGIN role: %s', remediation_sql)
    );
  END IF;

  IF COALESCE(current_role_rec.rolsuper, false) THEN
    findings := findings || jsonb_build_array(jsonb_build_object(
      'id', 'CURRENT_USER_IS_SUPERUSER',
      'severity', 'critical',
      'title', 'Current user is a superuser',
      'detail', format('Current user %I is a PostgreSQL superuser.', current_user),
      'why_it_matters', 'A PostgreSQL superuser can bypass pg_lockstep and can disable database-local controls.',
      'recommendation', 'Operate through least-privilege roles. Reserve superuser access for emergency administrative workflows.',
      'sql', NULL,
      'confidence', 'high'
    ));
    summary_actions := summary_actions || jsonb_build_array(
      'Run application and migration work through least-privilege roles instead of a PostgreSQL superuser.'
    );
  END IF;

  IF COALESCE(session_role_rec.rolsuper, false) AND session_user <> current_user THEN
    findings := findings || jsonb_build_array(jsonb_build_object(
      'id', 'SESSION_USER_IS_SUPERUSER',
      'severity', 'critical',
      'title', 'Session user is a superuser',
      'detail', format('Session user %I is a PostgreSQL superuser.', session_user),
      'why_it_matters', 'SET ROLE does not remove the underlying power of a superuser-authenticated session.',
      'recommendation', 'Authenticate as a least-privilege login role instead of starting from a superuser session.',
      'sql', NULL,
      'confidence', 'high'
    ));
  END IF;

  IF postgres_role_rec.rolname IS NOT NULL AND postgres_role_rec.rolcanlogin THEN
    findings := findings || jsonb_build_array(jsonb_build_object(
      'id', 'REMOTE_POSTGRES_LOGIN_POSSIBLE',
      'severity', 'critical',
      'title', 'postgres superuser login is enabled',
      'detail', 'The postgres role can login. pg_lockstep cannot verify pg_hba.conf from inside ordinary SQL, so remote exposure is unknown.',
      'why_it_matters', 'A PostgreSQL superuser can bypass pg_lockstep and drop databases from another database.',
      'recommendation', 'Restrict postgres in pg_hba.conf and require emergency administrative access through OS, bastion, or audited operational controls.',
      'sql', 'ALTER ROLE postgres NOLOGIN;',
      'confidence', 'medium'
    ));
    summary_actions := summary_actions || jsonb_build_array(
      'Review and restrict postgres login paths in pg_hba.conf and operational access controls.'
    );
  END IF;

  IF login_superuser_count > 0 THEN
    findings := findings || jsonb_build_array(jsonb_build_object(
      'id', 'LOGIN_SUPERUSER_ROLES_PRESENT',
      'severity', 'critical',
      'title', 'Login-capable superuser roles exist',
      'detail', format('%s login-capable superuser role(s) exist in this cluster.', login_superuser_count),
      'why_it_matters', 'Any login-capable superuser can bypass pg_lockstep protections.',
      'recommendation', 'Minimize login-capable superusers and require emergency administrative controls.',
      'sql', 'SELECT rolname FROM pg_roles WHERE rolsuper AND rolcanlogin;',
      'confidence', 'high'
    ));
    summary_actions := summary_actions || jsonb_build_array(
      'Minimize login-capable superuser roles and document emergency access controls.'
    );
  END IF;

  IF createdb_login_count > 0 THEN
    findings := findings || jsonb_build_array(jsonb_build_object(
      'id', 'LOGIN_CREATEDB_ROLES_PRESENT',
      'severity', 'warn',
      'title', 'Login roles with CREATEDB exist',
      'detail', format('%s non-superuser login role(s) have CREATEDB.', createdb_login_count),
      'why_it_matters', 'CREATEDB roles can create databases and may own databases outside the protected database-local extension boundary.',
      'recommendation', 'Grant CREATEDB sparingly and prefer administrative workflows with review.',
      'sql', 'SELECT rolname FROM pg_roles WHERE rolcreatedb AND rolcanlogin AND NOT rolsuper;',
      'confidence', 'high'
    ));
  END IF;

  recommendations := recommendations || jsonb_build_array(jsonb_build_object(
    'id', 'USE_NOLOGIN_DATABASE_OWNER',
    'title', 'Use a NOLOGIN database owner',
    'detail', 'Own databases with dedicated NOLOGIN roles and grant application access to separate login roles.',
    'sql', remediation_sql
  ));

  recommendations := recommendations || jsonb_build_array(jsonb_build_object(
    'id', 'RESTRICT_SUPERUSER_ACCESS',
    'title', 'Restrict superuser login paths',
    'detail', 'Review pg_hba.conf, OS access, bastion controls, and operational policy for postgres and other superuser roles.',
    'sql', 'SELECT rolname FROM pg_roles WHERE rolsuper AND rolcanlogin;'
  ));

  SELECT count(*) FILTER (WHERE item->>'severity' = 'critical'),
         count(*) FILTER (WHERE item->>'severity' = 'warn')
  INTO critical_count, warning_count
  FROM jsonb_array_elements(findings) AS item;

  IF jsonb_path_exists(findings, '$[*] ? (@.severity == "critical")') THEN
    status := 'critical';
  ELSIF jsonb_path_exists(findings, '$[*] ? (@.severity == "warn")') THEN
    status := 'warn';
  ELSE
    status := 'ok';
  END IF;

  RETURN jsonb_build_object(
    'overall_status', status,
    'checked_at', clock_timestamp(),
    'database_name', current_database(),
    'current_user', current_user,
    'session_user', session_user,
    'server_version', version(),
    'pg_lockstep_mode', mode,
    'pg_lockstep_version', extension_version,
    'sql_namespace', 'lockstep',
    'summary', jsonb_build_object(
      'headline', CASE status
        WHEN 'critical' THEN 'Critical PostgreSQL posture risks require attention before relying on pg_lockstep enforcement.'
        WHEN 'warn' THEN 'PostgreSQL posture warnings require review before relying on pg_lockstep enforcement.'
        ELSE 'No critical posture issues were detected by SQL-visible checks.'
      END,
      'release_scope', format(
        'pg_lockstep %s is running in SQL/event-trigger mode for database-local enforcement.',
        COALESCE(extension_version, 'unknown')
      ),
      'fix_now', summary_actions,
      'finding_counts', jsonb_build_object(
        'critical', critical_count,
        'warn', warning_count,
        'total', jsonb_array_length(findings)
      ),
      'operator_note', 'Detailed findings, recommendations, limitations, confidence, and remediation SQL follow in this report.'
    ),
    'findings', findings,
    'recommendations', recommendations,
    'limitations', limitations
  );
END;
$$;

COMMENT ON FUNCTION lockstep.doctor() IS 'Return pg_lockstep posture diagnostics and current release protection limitations as JSONB.';

CREATE OR REPLACE FUNCTION lockstep.on_ddl_command_start()
RETURNS event_trigger
LANGUAGE plpgsql
AS $$
DECLARE
  decision jsonb;
  event_doc jsonb;
  event_id text;
  now_ts timestamptz := clock_timestamp();
  mode text := lockstep.get_mode();
  object_identity text := NULL;
  risk text;
  score int;
  action text;
  reasons text[];
  fingerprint text;
  approval_token text;
  approval_id uuid;
  approved_by text;
  effective_action text;
BEGIN
  IF tg_tag IS NULL OR tg_tag IN ('CREATE EVENT TRIGGER', 'ALTER EVENT TRIGGER', 'DROP EVENT TRIGGER') THEN
    RETURN;
  END IF;

  decision := lockstep.evaluate_command(tg_tag, object_identity);
  risk := decision->>'risk';
  score := (decision->>'score')::int;
  action := decision->>'action';
  reasons := ARRAY(SELECT jsonb_array_elements_text(decision->'reasons'));
  fingerprint := decision->>'command_fingerprint';
  effective_action := action;

  IF mode = 'lockdown' AND risk IN ('high', 'critical') AND action = 'allow' THEN
    effective_action := 'require_approval';
    reasons := array_append(reasons, 'lockdown requires approval for high-risk DDL');
  END IF;

  IF mode IN ('enforce', 'lockdown') AND effective_action = 'require_approval' THEN
    approval_token := current_setting('pg_lockstep.approval_token', true);
    IF approval_token IS NOT NULL AND approval_token <> '' THEN
      approval_id := lockstep.consume_approval(fingerprint, approval_token);
      IF approval_id IS NOT NULL THEN
        SELECT a.approved_by INTO approved_by
        FROM lockstep.approvals a
        WHERE a.id = approval_id;
        effective_action := 'allow';
        reasons := array_append(reasons, 'valid local approval token consumed');
      ELSE
        reasons := array_append(reasons, 'approval token was provided but did not match this command fingerprint');
      END IF;
    END IF;
  END IF;

  event_id := 'pg_lockstep_' ||
    to_char(now_ts AT TIME ZONE 'UTC', 'YYYYMMDDHH24MISSUS') ||
    '_' ||
    encode(gen_random_bytes(6), 'hex');

  event_doc := jsonb_build_object(
    'event_id', event_id,
    'ts', now_ts,
    'database', current_database(),
    'session_user', session_user,
    'current_user', current_user,
    'client_addr', inet_client_addr(),
    'application_name', current_setting('application_name', true),
    'command_tag', tg_tag,
    'object_identity', object_identity,
    'risk', risk,
    'score', score,
    'action', effective_action,
    'reasons', to_jsonb(reasons),
    'fingerprint', fingerprint,
    'mode', mode
  );

  IF approval_id IS NOT NULL THEN
    event_doc := event_doc ||
      jsonb_build_object('approval_id', approval_id, 'approved_by', approved_by);
  END IF;

  INSERT INTO lockstep.audit_log (
    event_id,
    ts,
    database_name,
    session_user_name,
    current_user_name,
    client_addr,
    application_name,
    command_tag,
    object_identity,
    risk,
    score,
    action,
    reasons,
    command_fingerprint,
    approved_by,
    approval_id,
    event
  )
  VALUES (
    event_id,
    now_ts,
    current_database(),
    session_user,
    current_user,
    inet_client_addr(),
    current_setting('application_name', true),
    tg_tag,
    object_identity,
    risk,
    score,
    effective_action,
    reasons,
    fingerprint,
    approved_by,
    approval_id,
    event_doc
  );

  PERFORM lockstep._emit_notify(
    event_doc,
    mode IN ('enforce', 'lockdown') AND effective_action IN ('block', 'require_approval')
  );

  IF mode IN ('enforce', 'lockdown') AND effective_action IN ('block', 'require_approval') THEN
    RAISE EXCEPTION 'pg_lockstep blocked command'
      USING DETAIL = event_doc::text,
            HINT = format(
              'Run SELECT lockstep.request_approval(%L, NULL, %L, %L); then SELECT lockstep.approve(<approval_id>, current_user); then SET pg_lockstep.approval_token to the returned token, not the approval UUID.',
              tg_tag,
              'reason',
              'ticket'
            );
  END IF;
END;
$$;

COMMENT ON FUNCTION lockstep.on_ddl_command_start() IS 'Event trigger entrypoint that audits, notifies, and optionally blocks DDL.';

CREATE EVENT TRIGGER pg_lockstep_ddl_command_start
  ON ddl_command_start
  EXECUTE FUNCTION lockstep.on_ddl_command_start();

ALTER EVENT TRIGGER pg_lockstep_ddl_command_start DISABLE;
