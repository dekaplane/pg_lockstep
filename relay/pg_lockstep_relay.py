#!/usr/bin/env python3
"""Local pg_lockstep LISTEN/NOTIFY relay.

The database extension never sends network requests. This process is an
optional out-of-band alert relay that can print events or forward them to Slack.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Any

import psycopg
import requests


LOG = logging.getLogger("pg_lockstep_relay")


@dataclass
class SlackConfig:
    token: str
    channel: str


class EventDeduper:
    def __init__(self, max_size: int = 1024) -> None:
        self.max_size = max_size
        self._seen: OrderedDict[str, None] = OrderedDict()

    def seen(self, event_id: str) -> bool:
        if event_id in self._seen:
            self._seen.move_to_end(event_id)
            return True
        self._seen[event_id] = None
        if len(self._seen) > self.max_size:
            self._seen.popitem(last=False)
        return False


class RateLimiter:
    def __init__(self, max_events: int, per_seconds: float) -> None:
        self.max_events = max_events
        self.per_seconds = per_seconds
        self._timestamps: deque[float] = deque()

    def allow(self) -> bool:
        now = time.monotonic()
        while self._timestamps and now - self._timestamps[0] > self.per_seconds:
            self._timestamps.popleft()
        if len(self._timestamps) >= self.max_events:
            return False
        self._timestamps.append(now)
        return True


def slack_config_from_env() -> SlackConfig | None:
    token = os.getenv("PG_LOCKSTEP_SLACK_BOT_TOKEN")
    channel = os.getenv("PG_LOCKSTEP_SLACK_CHANNEL")
    if not token or not channel:
        return None
    return SlackConfig(token=token, channel=channel)


def slack_text(event: dict[str, Any]) -> str:
    title = event.get("title") or "pg_lockstep PostgreSQL command event"
    reasons = event.get("reasons") or []
    if isinstance(reasons, list):
        reasons_text = ", ".join(str(item) for item in reasons)
    else:
        reasons_text = str(reasons)

    fields = {
        "DB": event.get("database"),
        "Actor": event.get("current_user"),
        "Command": event.get("command_tag"),
        "Risk": event.get("risk"),
        "Score": event.get("score"),
        "Action": event.get("action"),
        "Reasons": reasons_text,
        "Fingerprint": event.get("fingerprint"),
        "Time": event.get("ts"),
    }
    trusted_approval = event.get("trusted_approval")
    if isinstance(trusted_approval, dict):
        fields.update(
            {
                "Approval ID": trusted_approval.get("approval_id"),
                "Approval Token": trusted_approval.get("token"),
                "Token Expires": trusted_approval.get("expires_at"),
                "Use SQL": trusted_approval.get("use_sql"),
            }
        )
    lines = [f"*{title}*"]
    lines.extend(f"*{key}:* {value}" for key, value in fields.items())
    return "\n".join(lines)


def send_to_slack(config: SlackConfig, event: dict[str, Any]) -> None:
    response = requests.post(
        "https://slack.com/api/chat.postMessage",
        headers={
            "Authorization": f"Bearer {config.token}",
            "Content-Type": "application/json; charset=utf-8",
        },
        json={"channel": config.channel, "text": slack_text(event)},
        timeout=10,
    )
    response.raise_for_status()
    payload = response.json()
    if not payload.get("ok"):
        raise RuntimeError(f"Slack API error: {payload}")


def handle_event(
    raw_payload: str,
    deduper: EventDeduper,
    limiter: RateLimiter,
    slack_config: SlackConfig | None,
) -> None:
    try:
        event = json.loads(raw_payload)
    except json.JSONDecodeError:
        LOG.warning("received non-JSON notification payload: %s", raw_payload)
        return

    event_id = str(event.get("event_id") or "")
    if event_id and deduper.seen(event_id):
        LOG.debug("skipping duplicate event_id=%s", event_id)
        return

    print(json.dumps(event, sort_keys=True), flush=True)

    if slack_config is None:
        return

    if not limiter.allow():
        LOG.warning("rate limited Slack event_id=%s", event_id or "<missing>")
        return

    try:
        send_to_slack(slack_config, event)
    except Exception as exc:  # noqa: BLE001 - relay should log and continue.
        LOG.warning("Slack delivery failed: %s", exc)


def run(dsn: str) -> int:
    stop = False

    def _stop(_signum: int, _frame: object) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    deduper = EventDeduper()
    limiter = RateLimiter(max_events=20, per_seconds=60)
    slack_config = slack_config_from_env()
    if slack_config is None:
        LOG.info("Slack forwarding disabled; set PG_LOCKSTEP_SLACK_BOT_TOKEN and PG_LOCKSTEP_SLACK_CHANNEL to enable it")
    else:
        LOG.info("Slack forwarding enabled for channel %s", slack_config.channel)

    LOG.info("connecting to Postgres")
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("LISTEN pg_lockstep_events")
        LOG.info("listening on pg_lockstep_events")
        while not stop:
            for notify in conn.notifies(timeout=1, stop_after=1):
                handle_event(notify.payload, deduper, limiter, slack_config)

    LOG.info("stopped")
    return 0


def run_test_slack() -> int:
    slack_config = slack_config_from_env()
    if slack_config is None:
        print(
            "Slack forwarding is not configured. Set PG_LOCKSTEP_SLACK_BOT_TOKEN "
            "and PG_LOCKSTEP_SLACK_CHANNEL.",
            file=sys.stderr,
        )
        return 2

    event = {
        "title": "pg_lockstep relay test",
        "event_id": f"pg_lockstep_relay_test_{int(time.time())}",
        "database": "relay-test",
        "current_user": "relay",
        "command_tag": "TEST",
        "risk": "warn",
        "score": 50,
        "action": "warn",
        "reasons": ["relay Slack configuration test"],
        "fingerprint": "sha256:test",
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    send_to_slack(slack_config, event)
    print("Slack test message sent", flush=True)
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Listen for pg_lockstep NOTIFY events")
    parser.add_argument("--dsn", help="PostgreSQL connection string")
    parser.add_argument("--log-level", default="INFO", help="Python logging level")
    parser.add_argument(
        "--test-slack",
        action="store_true",
        help="Send a test Slack message using env vars and exit",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    if args.test_slack:
        return run_test_slack()

    if not args.dsn:
        parser.error("--dsn is required unless --test-slack is used")

    return run(args.dsn)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
