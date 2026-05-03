# pg_lockstep Relay

The relay is optional. The PostgreSQL extension enforces policy inside the database and emits local `NOTIFY pg_lockstep_events` messages for block and warn events. This process can listen for those events and forward them to Slack.

The extension never calls Slack or any external API.

## Run

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r relay/requirements.txt
python relay/pg_lockstep_relay.py --dsn postgresql://postgres:postgres@localhost:5432/postgres
```

## Optional Slack

Set both variables to enable Slack forwarding:

```sh
export PG_LOCKSTEP_SLACK_BOT_TOKEN=xoxb-...
export PG_LOCKSTEP_SLACK_CHANNEL=C0123456789
```

If Slack fails, the relay logs the error and keeps listening. Database enforcement does not depend on this process.

## Test Slack Delivery

```sh
PG_LOCKSTEP_SLACK_BOT_TOKEN=xoxb-... \
PG_LOCKSTEP_SLACK_CHANNEL=C0123456789 \
python relay/pg_lockstep_relay.py --test-slack
```

## Important PostgreSQL Behavior

PostgreSQL delivers `NOTIFY` only when the surrounding transaction commits. If pg_lockstep blocks a command by raising an exception, PostgreSQL rolls back both the audit insert and the `NOTIFY` for that failed statement.

That means this relay will receive committed warn/observe events and explicit test notifications, but it will not receive a `NOTIFY` from a statement that pg_lockstep blocked inside the same transaction. The blocked event JSON is still present in the SQL exception `DETAIL`.
