# reconkit

A small recon automation tool: port scan, HTTP/security-header probing and optional subdomain brute force, with a clean Markdown or JSON report. Standard library only — no dependencies to install.

> **Scope guard built in.** Scanning a public (non-private) address requires `--authorized`, which you should only pass if you have written permission to test that target. Only test systems you own or are authorized to test.

## Why

Recon is the first phase of almost every test: map what's listening, what's running, and what's misconfigured, before anything else. This started as a handful of one-off scripts I kept rewriting for labs, so I turned it into one small tool with tests.

## Install

```bash
git clone https://github.com/thecyberfarhan/reconkit
cd reconkit
python3 -m reconkit --help
```

No pip install needed — it's pure standard library (Python 3.8+).

## Usage

```bash
# top common ports + HTTP probe, against a private lab host
python3 -m reconkit 192.168.1.10

# specific ports, write a Markdown report
python3 -m reconkit 192.168.1.10 -p 22,80,443,8000-8100 -o report.md

# JSON output, for feeding into another tool
python3 -m reconkit 192.168.1.10 -o report.json

# subdomain brute force (wordlist = one word per line)
python3 -m reconkit example.com -w wordlists/small.txt --authorized
```

```
$ python3 -m reconkit 192.168.1.10 -p 22,80,4280
reconkit: only scan systems you own or have written permission to test.
# Recon report: 192.168.1.10

Resolved address: `192.168.1.10`

## Open ports

| Port | Service | Banner |
|---|---|---|
| 22  | ssh  | SSH-2.0-OpenSSH_9.6 |
| 4280 | unknown | - |

## Web services

- http://192.168.1.10:4280: HTTP 200, title "Login :: DVWA", server `Apache/2.4.69`, missing headers: ...
```

## What it does

- **Port scan** — threaded TCP connect scan over a top-ports list or a custom range (`22,80,8000-8100`), with a short banner grab for non-HTTP ports.
- **HTTP probe** — for every web port found (and silent unknown ports), fetches the page title, `Server` header, and checks for the six standard security headers (CSP, HSTS, X-Frame-Options, etc).
- **Subdomain brute force** (optional, `-w`) — resolves `word.domain` for a wordlist, with wildcard-DNS detection so a catch-all DNS record doesn't produce hundreds of false hits.
- **Scope check** — refuses to touch a public IP unless you pass `--authorized`.

## Running the tests

```bash
python3 -m unittest discover -s tests -v
```

All tests run against a local test server — nothing reaches the network.

## Project layout

```
reconkit/
  core.py     scanning, probing and report logic
  cli.py      the python -m reconkit entry point
tests/
  test_core.py
```

## License

MIT — see [LICENSE](LICENSE).
