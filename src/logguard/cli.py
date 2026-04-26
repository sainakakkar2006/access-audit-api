from __future__ import annotations

import argparse
import json
from pathlib import Path

from .detector import analyze_lines


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="logguard", description="Analyze SSH auth logs.")
    subcommands = parser.add_subparsers(dest="command", required=True)

    analyze = subcommands.add_parser("analyze", help="analyze an auth log file")
    analyze.add_argument("logfile", help="path to an auth.log-style file")
    analyze.add_argument("--threshold", type=int, default=5, help="failed-login threshold per IP")
    analyze.add_argument("--year", type=int, default=2026, help="year to attach to syslog timestamps")
    analyze.add_argument("--out", help="optional JSON output path")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "analyze":
        report = analyze_file(args.logfile, threshold=args.threshold, year=args.year)
    else:
        raise AssertionError(f"unknown command: {args.command}")

    payload = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(payload + "\n", encoding="utf-8")

    print(payload)
    return 0


def analyze_file(logfile: str | Path, *, threshold: int = 5, year: int = 2026) -> dict:
    path = Path(logfile)
    lines = path.read_text(encoding="utf-8").splitlines()
    return analyze_lines(lines, threshold=threshold, year=year)


if __name__ == "__main__":
    raise SystemExit(main())

