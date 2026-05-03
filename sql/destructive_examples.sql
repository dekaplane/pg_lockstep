-- Intentionally dangerous examples for local demos only.
-- Run against a disposable database.

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_lockstep;

SELECT lockstep.enable('observe');

CREATE TABLE IF NOT EXISTS demo_users (
  id bigserial PRIMARY KEY,
  email text NOT NULL
);

SELECT lockstep.tag_object('public', 'demo_users', 'pii');

DROP TABLE demo_users;

SELECT event->>'command_tag' AS command_tag,
       event->>'risk' AS risk,
       event->>'action' AS action,
       event->'reasons' AS reasons
FROM lockstep.current_events(5);

SELECT lockstep.enable('enforce');

CREATE TABLE demo_users (
  id bigserial PRIMARY KEY,
  email text NOT NULL
);

-- This should fail in enforce mode:
DROP TABLE demo_users;
