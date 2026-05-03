INSERT INTO lockstep.settings (key, value) VALUES
  ('blocked_alerts_dblink_enabled', 'false'::jsonb),
  ('blocked_alerts_dblink_conninfo', '""'::jsonb),
  ('trusted_alert_tokens_enabled', 'false'::jsonb)
ON CONFLICT (key) DO NOTHING;

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
