#!/usr/bin/env python3
"""Minimal pg_lockstep CLI."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from typing import Any

try:
    import psycopg
except ModuleNotFoundError:  # pragma: no cover - exercised in minimal local envs.
    psycopg = None  # type: ignore[assignment]


def run_doctor(dsn: str) -> int:
    if psycopg is None:
        return run_doctor_with_psql(dsn)

    try:
        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT lockstep.doctor()::text")
                row = cur.fetchone()
    except psycopg.errors.UndefinedFunction:
        print(
            "pg_lockstep doctor is not installed in this database. "
            "Run CREATE EXTENSION pg_lockstep; then try again.",
            file=sys.stderr,
        )
        return 2
    except psycopg.errors.InvalidSchemaName:
        print(
            "pg_lockstep SQL schema is missing in this database. "
            "Run CREATE EXTENSION pg_lockstep; then try again.",
            file=sys.stderr,
        )
        return 2

    if row is None or row[0] is None:
        print("pg_lockstep doctor returned no result", file=sys.stderr)
        return 2

    payload: dict[str, Any] = json.loads(row[0])
    print(json.dumps(payload, indent=2, sort_keys=False))
    return 0 if payload.get("overall_status") == "ok" else 1


def run_doctor_with_psql(dsn: str) -> int:
    result = subprocess.run(
        [
            "psql",
            dsn,
            "-AtX",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            "SELECT lockstep.doctor()::text",
        ],
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        error_text = result.stderr.strip() or result.stdout.strip()
        if 'schema "lockstep" does not exist' in error_text:
            print(
                "pg_lockstep is not installed in this database. "
                "Run CREATE EXTENSION pg_lockstep; then try again.",
                file=sys.stderr,
            )
            return 2
        if "function lockstep.doctor() does not exist" in error_text:
            print(
                "pg_lockstep doctor is not installed in this database. "
                "Reinstall or upgrade pg_lockstep so lockstep.doctor() exists.",
                file=sys.stderr,
            )
            return 2
        print(error_text, file=sys.stderr)
        return result.returncode

    raw_payload = result.stdout.strip()
    if not raw_payload:
        print("pg_lockstep doctor returned no result", file=sys.stderr)
        return 2

    payload: dict[str, Any] = json.loads(raw_payload)
    print(json.dumps(payload, indent=2, sort_keys=False))
    return 0 if payload.get("overall_status") == "ok" else 1


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="pg_lockstep")
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser(
        "doctor",
        help="Run PostgreSQL posture diagnostics for pg_lockstep current release",
    )
    doctor.add_argument("--dsn", required=True, help="PostgreSQL connection string")

    args = parser.parse_args(argv)
    if args.command == "doctor":
        return run_doctor(args.dsn)

    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
