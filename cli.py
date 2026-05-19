#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from passaudit import load_bundled_wordlist
from passaudit import analyzer, wordlist as wl_module
from passaudit.entropy import crack_time_label

_GRADE_COLOUR = {
    "A+": "\033[92m", "A": "\033[92m",
    "B":  "\033[93m", "C": "\033[93m",
    "D":  "\033[91m", "F": "\033[91m",
}
_RESET = "\033[0m"


def _col(text: str, colour: str, on: bool) -> str:
    return f"{colour}{text}{_RESET}" if on else text


def _bar(score: int, width: int = 30, on: bool = True) -> str:
    filled = int(score / 100 * width)
    colour = "\033[92m" if score >= 75 else "\033[93m" if score >= 45 else "\033[91m"
    bar = "█" * filled + "░" * (width - filled)
    return _col(bar, colour, on)


def _render(report, colour: bool = True) -> None:
    e  = report.entropy
    hi = report.hibp
    gc = _GRADE_COLOUR.get(report.grade, "")

    print()
    print(f"  {'Password':<22} {'*' * len(report.password)}")
    print(f"  {'Length':<22} {e.length} characters")
    print(f"  {'Character pools':<22} {', '.join(e.pool_names) or 'none'} (pool size: {e.pool_size})")
    print(f"  {'Pool entropy':<22} {e.pool_bits:.1f} bits")
    print(f"  {'Shannon entropy':<22} {e.shannon_bits:.1f} bits")
    print(f"  {'Crack time (est.)':<22} {crack_time_label(e.pool_bits)}")
    print()
    print(f"  Score  {_bar(report.score, on=colour)}  "
          f"{_col(f'{report.score}/100', gc, colour)}  [{_col(report.grade, gc, colour)}]")
    print()
    print(f"  {report.verdict}")
    print()

    if hi.checked:
        status = (
            _col(f"⛔  YES — seen {hi.count:,}× in breach databases", "\033[91m", colour)
            if hi.pwned else
            _col("✅  Not found in breach databases", "\033[92m", colour)
        )
        print(f"  HIBP check       {status}")
    elif hi.error:
        print(f"  HIBP check       ⚠  Skipped ({hi.error})")
    else:
        print(f"  HIBP check       ⚠  Skipped (--no-hibp)")

    print()

    if report.findings:
        print("  Patterns detected")
        for f in report.findings:
            sev_label = "HIGH  " if f.severity >= 0.7 else "MED   " if f.severity >= 0.4 else "LOW   "
            sev_col   = "\033[91m" if f.severity >= 0.7 else "\033[93m" if f.severity >= 0.4 else "\033[37m"
            print(f"    [{_col(sev_label, sev_col, colour)}] {f.description}")
    else:
        print(f"  {_col('No common patterns detected', chr(27) + '[92m', colour)}")

    print()


def _render_json(report) -> None:
    e = report.entropy
    print(json.dumps({
        "password_masked": "*" * len(report.password),
        "length": e.length,
        "entropy": {
            "pool_bits": e.pool_bits,
            "shannon_bits": e.shannon_bits,
            "pool_size": e.pool_size,
            "pools": e.pool_names,
            "crack_time": crack_time_label(e.pool_bits),
        },
        "score": report.score,
        "grade": report.grade,
        "verdict": report.verdict,
        "hibp": {
            "checked": report.hibp.checked,
            "pwned": report.hibp.pwned,
            "count": report.hibp.count,
            "error": report.hibp.error,
        },
        "findings": [
            {
                "name": f.name,
                "description": f.description,
                "matched": f.matched,
                "severity": f.severity,
                "penalty_bits": f.penalty_bits,
            }
            for f in report.findings
        ],
    }, indent=2))


def cmd_check(args: argparse.Namespace) -> int:
    custom: set[str] = set()
    if args.wordlist:
        try:
            with open(args.wordlist, encoding="utf-8", errors="ignore") as fh:
                custom = {l.strip().lower() for l in fh if l.strip()}
            if not args.json:
                print(f"  Loaded {len(custom):,} words from {args.wordlist}")
        except OSError as exc:
            print(f"  Warning: {exc}", file=sys.stderr)

    words   = load_bundled_wordlist() | custom
    colour  = sys.stdout.isatty() and not args.no_colour
    targets = list(args.password or [])

    if args.stdin:
        targets += [l.rstrip("\n") for l in sys.stdin if l.strip()]

    if not targets:
        print("No passwords provided.", file=sys.stderr)
        return 1

    exit_code = 0
    for pw in targets:
        report = analyzer.analyse(pw, wordlist=words or None, skip_hibp=args.no_hibp)
        if args.json:
            _render_json(report)
        else:
            _render(report, colour=colour)
        if report.score < 45:
            exit_code = 2

    return exit_code


def cmd_wordlist(args: argparse.Namespace) -> int:
    candidates = wl_module.generate(
        args.words,
        include_leet=not args.no_leet,
        include_affixes=not args.no_affixes,
        include_reversed=not args.no_reverse,
        include_combinations=not args.no_combinations,
        max_combinations=args.max_combo,
    )

    written = 0
    if args.output:
        written = wl_module.write_wordlist(candidates, args.output,
                                           args.min_length, args.max_length)
        print(f"Wrote {written:,} candidates to {args.output}")
    else:
        for word in candidates:
            if args.min_length <= len(word) <= args.max_length:
                print(word)
                written += 1
        print(f"\n# Total: {written:,} candidates", file=sys.stderr)

    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="passaudit", description="Password Strength Analyzer & Auditor")
    sub = p.add_subparsers(dest="command", required=True)

    pc = sub.add_parser("check", help="Evaluate one or more passwords")
    pc.add_argument("password", nargs="*")
    pc.add_argument("--stdin",     action="store_true")
    pc.add_argument("--wordlist",  metavar="FILE")
    pc.add_argument("--no-hibp",   action="store_true")
    pc.add_argument("--json",      action="store_true")
    pc.add_argument("--no-colour", action="store_true")

    pw = sub.add_parser("wordlist", help="Generate candidate wordlist from base words")
    pw.add_argument("words", nargs="+")
    pw.add_argument("--output",          "-o", metavar="FILE")
    pw.add_argument("--no-leet",         action="store_true")
    pw.add_argument("--no-affixes",      action="store_true")
    pw.add_argument("--no-reverse",      action="store_true")
    pw.add_argument("--no-combinations", action="store_true")
    pw.add_argument("--max-combo",       type=int, default=2)
    pw.add_argument("--min-length",      type=int, default=6)
    pw.add_argument("--max-length",      type=int, default=64)

    return p


def main() -> None:
    args = build_parser().parse_args()
    sys.exit({"check": cmd_check, "wordlist": cmd_wordlist}[args.command](args))


if __name__ == "__main__":
    main()