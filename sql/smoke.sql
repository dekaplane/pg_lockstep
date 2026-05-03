-- pg_lockstep smoke demo.
--
-- Expected behavior:
-- 1. Extension installs.
-- 2. Observe mode audits DROP TABLE but allows it.
-- 3. Enforce mode blocks DROP TABLE without an approval token.
-- 4. A single-use token allows the matching command once.

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_lockstep;

SELECT lockstep.enable('observe');

SELECT lockstep.doctor() ? 'overall_status' AS doctor_has_status;

DROP TABLE IF EXISTS lockstep_smoke_users;
CREATE TABLE lockstep_smoke_users (
  id bigserial PRIMARY KEY,
  email text NOT NULL
);

DROP TABLE lockstep_smoke_users;

SELECT command_tag, risk, action
FROM lockstep.current_events(10)
WHERE command_tag = 'DROP TABLE'
ORDER BY id DESC
LIMIT 1;

SELECT lockstep.enable('enforce');

CREATE TABLE lockstep_smoke_users (
  id bigserial PRIMARY KEY,
  email text NOT NULL
);

SELECT lockstep.protect_table('public', 'lockstep_smoke_users');

DO $$
BEGIN
  BEGIN
    ALTER TABLE lockstep_smoke_users ADD COLUMN blocked_marker text;
    RAISE EXCEPTION 'ALTER TABLE unexpectedly succeeded without approval';
  EXCEPTION
    WHEN OTHERS THEN
      IF SQLERRM <> 'pg_lockstep blocked command' THEN
        RAISE;
      END IF;
  END;
END;
$$;

SELECT lockstep.request_approval('ALTER TABLE', NULL, 'smoke alter approval', 'SMOKE-ALTER') AS alter_approval_id
\gset

SELECT lockstep.approve(:'alter_approval_id', current_user) AS alter_approval_token
\gset

SET pg_lockstep.approval_token = :'alter_approval_token';

ALTER TABLE lockstep_smoke_users ADD COLUMN approved_marker text;

DO $$
BEGIN
  BEGIN
    DROP TABLE lockstep_smoke_users;
    RAISE EXCEPTION 'DROP TABLE unexpectedly succeeded without approval';
  EXCEPTION
    WHEN OTHERS THEN
      IF SQLERRM <> 'pg_lockstep blocked command' THEN
        RAISE;
      END IF;
  END;
END;
$$;

SELECT lockstep.request_approval('DROP TABLE', NULL, 'smoke test approval', 'SMOKE-1') AS approval_id
\gset

SELECT lockstep.approve(:'approval_id', current_user) AS approval_token
\gset

SET pg_lockstep.approval_token = :'approval_token';

DROP TABLE lockstep_smoke_users;

SELECT command_tag, risk, action, approval_id IS NOT NULL AS used_approval
FROM lockstep.current_events(10)
WHERE command_tag = 'DROP TABLE'
ORDER BY id DESC
LIMIT 1;

CREATE TABLE lockstep_smoke_delete_users (
  id bigserial PRIMARY KEY,
  email text NOT NULL
);

SELECT lockstep.protect_table('public', 'lockstep_smoke_delete_users');

DO $$
BEGIN
  BEGIN
    DELETE FROM lockstep_smoke_delete_users;
    RAISE EXCEPTION 'DELETE unexpectedly succeeded without approval';
  EXCEPTION
    WHEN OTHERS THEN
      IF SQLERRM <> 'pg_lockstep blocked command' THEN
        RAISE;
      END IF;
  END;
END;
$$;

SELECT lockstep.request_approval('DELETE', 'public.lockstep_smoke_delete_users', 'smoke delete approval', 'SMOKE-2') AS delete_approval_id
\gset

SELECT lockstep.approve(:'delete_approval_id', current_user) AS delete_approval_token
\gset

SET pg_lockstep.approval_token = :'delete_approval_token';

DELETE FROM lockstep_smoke_delete_users;

SELECT lockstep.disable();

DROP TABLE lockstep_smoke_delete_users;
