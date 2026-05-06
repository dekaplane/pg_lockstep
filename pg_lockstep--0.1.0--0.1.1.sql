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
