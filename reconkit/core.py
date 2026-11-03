"""Core recon functions. Standard library only, so it runs anywhere Python 3.8+ does."""
from __future__ import annotations

import concurrent.futures as cf
import ipaddress
import re
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict
from typing import Iterable

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521,
    2049, 3000, 3306, 3389, 5432, 5900, 5985, 6379, 8000, 8080, 8443, 8888, 9200, 27017,
]

SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap", 443: "https", 445: "smb",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs", 3000: "http-alt",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc", 5985: "winrm", 6379: "redis",
    8000: "http-alt", 8080: "http-alt", 8443: "https-alt", 8888: "http-alt", 9200: "elasticsearch",
    27017: "mongodb",
}

SECURITY_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options",
    "X-Frame-Options", "Referrer-Policy", "Permissions-Policy",
]

HTTP_PORTS = {80, 3000, 8000, 8080, 8888}
HTTPS_PORTS = {443, 8443}


class ScopeError(Exception):
    """Raised when a target is outside the allowed scope."""


def resolve(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as exc:
        raise ScopeError(f"cannot resolve {host}: {exc}") from exc


def is_private(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return addr.is_private or addr.is_loopback or addr.is_link_local


def check_scope(host: str, authorized: bool) -> str:
    """Return the IP for host. Public addresses need an explicit authorization flag."""
    ip = resolve(host)
    if not is_private(ip) and not authorized:
        raise ScopeError(
            f"{host} resolves to the public address {ip}. Only scan systems you own or have "
            "written permission to test. If you do, repeat the command with --authorized."
        )
    return ip


@dataclass
class PortResult:
    port: int
    service: str
    banner: str = ""


@dataclass
class HttpResult:
    url: str
    status: int | None = None
    title: str = ""
    server: str = ""
    missing_headers: list = field(default_factory=list)
    error: str = ""


@dataclass
class Report:
    target: str
    ip: str
    ports: list = field(default_factory=list)
    http: list = field(default_factory=list)
    subdomains: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def scan_port(ip: str, port: int, timeout: float = 1.0) -> PortResult | None:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            banner = ""
            s.settimeout(0.6)
            try:
                if port in HTTP_PORTS | HTTPS_PORTS:
                    pass
                else:
                    banner = s.recv(128).decode("latin-1", "replace").strip().splitlines()[0][:100]
            except (socket.timeout, OSError, IndexError):
                banner = ""
            return PortResult(port, SERVICE_NAMES.get(port, "unknown"), banner)
    except OSError:
        return None


def scan_ports(ip: str, ports: Iterable[int], timeout: float = 1.0, workers: int = 100) -> list:
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        found = [r for r in ex.map(lambda p: scan_port(ip, p, timeout), ports) if r]
    return sorted(found, key=lambda r: r.port)


_title_re = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def probe_http(url: str, timeout: float = 4.0) -> HttpResult:
    res = HttpResult(url=url)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # recon only: we want to see self-signed lab hosts too
    req = urllib.request.Request(url, headers={"User-Agent": "reconkit/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            res.status = r.status
            res.server = r.headers.get("Server", "").strip()
            body = r.read(65536).decode("utf-8", "replace")
            hdrs = {k.lower() for k in r.headers.keys()}
    except urllib.error.HTTPError as exc:
        res.status = exc.code
        res.server = exc.headers.get("Server", "").strip()
        body = ""
        hdrs = {k.lower() for k in exc.headers.keys()}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        res.error = str(getattr(exc, "reason", exc))
        return res
    m = _title_re.search(body)
    res.title = re.sub(r"\s+", " ", m.group(1)).strip()[:100] if m else ""
    res.missing_headers = [h for h in SECURITY_HEADERS if h.lower() not in hdrs]
    return res


def http_urls(host: str, ports: Iterable[PortResult]) -> list:
    """Candidate web URLs. Known web ports first, then silent unknown ports (many web apps sit on odd ports)."""
    urls = []
    for p in ports:
        if p.port in HTTPS_PORTS:
            urls.append(f"https://{host}" + ("" if p.port == 443 else f":{p.port}"))
        elif p.port in HTTP_PORTS:
            urls.append(f"http://{host}" + ("" if p.port == 80 else f":{p.port}"))
        elif p.service == "unknown" and not p.banner:
            urls.append(f"http://{host}:{p.port}")
    return urls


def bruteforce_subdomains(domain: str, words: Iterable[str], workers: int = 50) -> list:
    """Resolve word.domain for each word. Wildcard DNS is detected and filtered out."""
    wildcard = None
    try:
        wildcard = socket.gethostbyname(f"reconkit-nonexistent-{id(words)}.{domain}")
    except socket.gaierror:
        pass

    def lookup(w: str):
        name = f"{w}.{domain}"
        try:
            ip = socket.gethostbyname(name)
        except socket.gaierror:
            return None
        return None if ip == wildcard else (name, ip)

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        hits = [h for h in ex.map(lookup, words) if h]
    return sorted(hits)


def parse_ports(spec: str) -> list:
    out: list = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.extend(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    bad = [p for p in out if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"port out of range: {bad[0]}")
    return sorted(set(out))


def to_markdown(rep: Report) -> str:
    lines = [f"# Recon report: {rep.target}", "", f"Resolved address: `{rep.ip}`", ""]
    lines += ["## Open ports", ""]
    if rep.ports:
        lines += ["| Port | Service | Banner |", "|---|---|---|"]
        lines += [f"| {p['port']} | {p['service']} | {p['banner'] or '-'} |" for p in rep.ports]
    else:
        lines.append("No open ports found in the scanned range.")
    lines += ["", "## Web services", ""]
    if rep.http:
        for h in rep.http:
            if h["error"]:
                lines.append(f"- {h['url']}: error ({h['error']})")
                continue
            miss = ", ".join(h["missing_headers"]) or "none"
            lines.append(f"- {h['url']}: HTTP {h['status']}, title \"{h['title'] or '-'}\", "
                         f"server `{h['server'] or '-'}`, missing headers: {miss}")
    else:
        lines.append("No web services found.")
    if rep.subdomains:
        lines += ["", "## Subdomains", ""]
        lines += [f"- {n} -> {ip}" for n, ip in rep.subdomains]
    lines.append("")
    return "\n".join(lines)
