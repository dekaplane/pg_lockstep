CREATE EXTENSION pgcrypto;
CREATE EXTENSION pg_lockstep;
SELECT lockstep.enable('observe');
SELECT lockstep.doctor() ? 'overall_status' AS doctor_has_status;
CREATE TABLE lockstep_regress_users (id int PRIMARY KEY);
DROP TABLE lockstep_regress_users;
SELECT command_tag, action IN ('allow', 'require_approval') AS audited
FROM lockstep.current_events(5)
WHERE command_tag = 'DROP TABLE'
ORDER BY id DESC
LIMIT 1;
SELECT lockstep.enable('enforce');
CREATE TABLE lockstep_regress_users (id int PRIMARY KEY);
SELECT lockstep.protect_table('public', 'lockstep_regress_users');
DO $$
BEGIN
  BEGIN
    ALTER TABLE lockstep_regress_users ADD COLUMN blocked_marker text;
    RAISE EXCEPTION 'unexpected alter success';
  EXCEPTION WHEN OTHERS THEN
    IF SQLERRM <> 'pg_lockstep blocked command' THEN
      RAISE;
    END IF;
  END;
END;
$$;
SELECT lockstep.request_approval('ALTER TABLE', NULL, 'regress alter', 'REGRESS-ALTER') AS alter_approval_id \gset
SELECT lockstep.approve(:'alter_approval_id', current_user) AS alter_approval_token \gset
SET pg_lockstep.approval_token = :'alter_approval_token';
ALTER TABLE lockstep_regress_users ADD COLUMN approved_marker text;
DO $$
BEGIN
  BEGIN
    DROP TABLE lockstep_regress_users;
    RAISE EXCEPTION 'unexpected success';
  EXCEPTION WHEN OTHERS THEN
    IF SQLERRM <> 'pg_lockstep blocked command' THEN
      RAISE;
    END IF;
  END;
END;
$$;
SELECT lockstep.request_approval('DROP TABLE', NULL, 'regress', 'REGRESS-1') AS approval_id \gset
SELECT lockstep.approve(:'approval_id', current_user) AS approval_token \gset
SET pg_lockstep.approval_token = :'approval_token';
DROP TABLE lockstep_regress_users;
SELECT action, approval_id IS NOT NULL AS used_approval
FROM lockstep.current_events(5)
WHERE command_tag = 'DROP TABLE'
ORDER BY id DESC
LIMIT 1;
CREATE TABLE lockstep_regress_delete_users (id int PRIMARY KEY);
SELECT lockstep.protect_table('public', 'lockstep_regress_delete_users');
DO $$
BEGIN
  BEGIN
    DELETE FROM lockstep_regress_delete_users;
    RAISE EXCEPTION 'unexpected delete success';
  EXCEPTION WHEN OTHERS THEN
    IF SQLERRM <> 'pg_lockstep blocked command' THEN
      RAISE;
    END IF;
  END;
END;
$$;
SELECT lockstep.request_approval('DELETE', 'public.lockstep_regress_delete_users', 'regress delete', 'REGRESS-2') AS delete_approval_id \gset
SELECT lockstep.approve(:'delete_approval_id', current_user) AS delete_approval_token \gset
SET pg_lockstep.approval_token = :'delete_approval_token';
DELETE FROM lockstep_regress_delete_users;
SELECT lockstep.disable();
DROP TABLE lockstep_regress_delete_users;
