INSERT INTO lockstep.policy (
  name,
  database_name,
  min_score,
  action,
  reason
) VALUES
  ('strict_prod_high_risk_requires_approval', current_database(), 70, 'require_approval', 'strict production policy'),
  ('strict_prod_warn_medium_risk', current_database(), 40, 'warn', 'strict production policy')
ON CONFLICT (name) DO UPDATE
SET database_name = EXCLUDED.database_name,
    min_score = EXCLUDED.min_score,
    action = EXCLUDED.action,
    reason = EXCLUDED.reason,
    enabled = true;
