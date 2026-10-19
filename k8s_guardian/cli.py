"""Command line: ``k8s-guardian serve | once | check-policy``."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import TextIO

from pydantic import ValidationError

from .config import Settings
from .policy import load_policy


def _setup_logging(level: str, stream: TextIO) -> None:
    logging.basicConfig(level=level.upper(), format="%(asctime)s %(levelname)s %(name)s %(message)s", stream=stream)


def _serve(settings: Settings) -> int:
    import uvicorn

    from .api import create_app

    uvicorn.run(create_app(settings), host=settings.host, port=settings.port, log_level=settings.log_level.lower())
    return 0


def _once(settings: Settings) -> int:
    from .bootstrap import build_guardian

    guardian = build_guardian(settings)
    try:
        report = asyncio.run(guardian.poll_once())
    finally:
        guardian.audit.close()
    print(json.dumps(report.model_dump(mode="json"), indent=2))
    return 0 if report.ok else 1


def _check_policy(path: Path) -> int:
    policy = load_policy(path)
    print(f"policy {policy.version!r}: OK")
    print(f"  watched:  {', '.join(policy.watched_namespaces)} (ignoring {', '.join(policy.ignored_namespaces)})")
    print(f"  writable: {', '.join(policy.writable_namespaces) or '(none - observe only)'}")
    for line in policy.guidance_lines():
        print(f"  - {line}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="k8s-guardian", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("serve", help="run the API server and the background poll loop")
    sub.add_parser("once", help="run a single poll cycle, print the report as JSON, and exit")
    check = sub.add_parser("check-policy", help="validate a policy file and print what it permits")
    check.add_argument("path", type=Path)
    args = parser.parse_args(argv)

    try:
        if args.command == "check-policy":
            return _check_policy(args.path)
        settings = Settings()
    except (ValidationError, ValueError, OSError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    # `serve` logs to stdout (container convention); `once` keeps stdout clean for the JSON report.
    _setup_logging(settings.log_level, sys.stdout if args.command == "serve" else sys.stderr)
    return _serve(settings) if args.command == "serve" else _once(settings)
