from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analyzer import analyze, load_rules
from .resolver import LiveResolver, OfflineResolver, StaticResolver


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mail-sentry", description="Analyze email files with static, explainable phishing rules.")
    parser.add_argument("input", help="Path to a .eml or .msg file")
    parser.add_argument("-o", "--output", help="Write JSON report to this path; stdout is used by default")
    parser.add_argument("--rules", help="Path to a JSON rules configuration")
    parser.add_argument("--pretty", action="store_true", help="Indent JSON output for humans")
    parser.add_argument("--check-spf", action="store_true", help="Evaluate SPF for the client your gateway received the message from (uses live DNS unless --dns-records is given)")
    parser.add_argument("--dns", action="store_true", help="Allow live DNS lookups for DKIM keys and the DMARC policy")
    parser.add_argument("--dns-records", metavar="PATH", help="Answer DNS questions from a JSON record snapshot instead of the network")
    return parser


def build_resolver(args: argparse.Namespace):
    if args.dns_records:
        return StaticResolver.from_file(args.dns_records)
    if args.dns or args.check_spf:
        return LiveResolver()
    return OfflineResolver()


def main() -> int:
    args = build_parser().parse_args()
    try:
        path = Path(args.input)
        report = analyze(path, load_rules(args.rules), resolver=build_resolver(args), check_spf=args.check_spf)
        rendered = json.dumps(report, indent=2 if args.pretty else None, ensure_ascii=False) + "\n"
        if args.output:
            Path(args.output).write_text(rendered, encoding="utf-8")
        else:
            # Reports carry decoded Unicode subjects and names. Do not depend
            # on the console code page, which is often not UTF-8 on Windows.
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8")
            sys.stdout.write(rendered)
        return 0
    except (OSError, ValueError) as exc:
        print(f"mail-sentry: {exc}", file=sys.stderr)
        return 2
    except (RecursionError, MemoryError, LookupError, TypeError, AttributeError, IndexError) as exc:
        # Hostile input can reach corners of the email package that raise
        # unexpected errors. Report it as an analysis failure, not a traceback.
        print(f"mail-sentry: could not analyze {args.input}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
