"""Command line interface: python -m reconkit TARGET [options]"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import core

BANNER = "reconkit: only scan systems you own or have written permission to test."


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="reconkit", description="Small recon automation tool. " + BANNER)
    p.add_argument("target", help="hostname or IP address")
    p.add_argument("-p", "--ports", default="top", help="'top', or a list like 22,80,8000-8100")
    p.add_argument("-w", "--wordlist", help="subdomain wordlist (one word per line); enables subdomain brute force")
    p.add_argument("--timeout", type=float, default=1.0, help="per-port connect timeout in seconds")
    p.add_argument("--no-http", action="store_true", help="skip the HTTP probe")
    p.add_argument("--authorized", action="store_true",
                   help="confirm you have written permission to test a public target")
    p.add_argument("-o", "--out", help="write the report to this file (.md or .json)")
    return p


def run(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        ip = core.check_scope(args.target, args.authorized)
        ports = core.TOP_PORTS if args.ports == "top" else core.parse_ports(args.ports)
    except (core.ScopeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(BANNER, file=sys.stderr)
    rep = core.Report(target=args.target, ip=ip)
    open_ports = core.scan_ports(ip, ports, timeout=args.timeout)
    rep.ports = [vars(p) for p in open_ports]
    if not args.no_http:
        rep.http = [vars(core.probe_http(u)) for u in core.http_urls(args.target, open_ports)]
    if args.wordlist:
        words = [w.strip() for w in Path(args.wordlist).read_text().splitlines() if w.strip() and not w.startswith("#")]
        rep.subdomains = core.bruteforce_subdomains(args.target, words)

    text = json.dumps(rep.to_dict(), indent=2) if (args.out or "").endswith(".json") else core.to_markdown(rep)
    if args.out:
        Path(args.out).write_text(text)
        print(f"report written to {args.out}", file=sys.stderr)
    else:
        print(text)
    return 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
