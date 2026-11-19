#!/usr/bin/env python3
"""
vulnscan.py - Mini Vulnerability Scanner
=========================================
Detects COMMON misconfigurations / weaknesses in a web application or host.
Detection only: no exploitation, no brute forcing, no destructive requests.

Checks
  Network : TCP connect scan, banner grab, risky exposed services
  Web     : security headers, info-disclosure headers, cookie flags,
            HTTP->HTTPS redirect, TLS version + certificate expiry,
            exposed sensitive files (.git, .env, backups, phpinfo ...),
            directory listing, CORS origin reflection,
            unencoded input reflection (possible XSS),
            SQL error disclosure (possible SQLi)

Usage
  pip install requests
  python vulnscan.py https://testsite.local --i-have-permission
  python vulnscan.py 192.168.1.10 --ports 1-1024 --i-have-permission
  python vulnscan.py https://testsite.local --json out.json --html out.html --i-have-permission

ONLY scan systems you own or have explicit written permission to test.
Legal practice targets: scanme.nmap.org, OWASP Juice Shop, DVWA, WebGoat.
"""
import argparse
import datetime as dt
import html
import json
import random
import re
import socket
import ssl
import string
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from urllib.parse import urlparse, urljoin, urlencode, parse_qsl, urlunparse

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    sys.exit("Missing dependency: pip install requests")

SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
COLOR = {"critical": "\033[95m", "high": "\033[91m", "medium": "\033[93m",
         "low": "\033[94m", "info": "\033[90m"}
RESET = "\033[0m"

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
                1433, 1521, 2049, 3000, 3306, 3389, 5432, 5900, 5985, 6379, 8000,
                8080, 8443, 8888, 9200, 11211, 27017]

# port -> (service, severity, advice)
RISKY_PORTS = {
    21: ("FTP", "medium", "FTP is unencrypted. Use SFTP/FTPS or close the port."),
    23: ("Telnet", "high", "Telnet is unencrypted. Replace with SSH and close the port."),
    111: ("RPCbind", "medium", "Restrict RPC to trusted networks."),
    135: ("MS-RPC", "medium", "Block at the firewall."),
    139: ("NetBIOS", "medium", "Block at the firewall."),
    445: ("SMB", "high", "Do not expose SMB to untrusted networks."),
    1433: ("MSSQL", "high", "Databases should not be internet-facing."),
    1521: ("Oracle DB", "high", "Databases should not be internet-facing."),
    2049: ("NFS", "high", "Restrict NFS exports to trusted hosts."),
    3306: ("MySQL", "high", "Databases should not be internet-facing."),
    3389: ("RDP", "high", "Put RDP behind a VPN / gateway with MFA."),
    5432: ("PostgreSQL", "high", "Databases should not be internet-facing."),
    5900: ("VNC", "high", "Tunnel VNC over SSH/VPN and require strong auth."),
    5985: ("WinRM", "medium", "Restrict WinRM to management networks."),
    6379: ("Redis", "high", "Bind to localhost and enable authentication."),
    9200: ("Elasticsearch", "high", "Enable auth and restrict network access."),
    11211: ("Memcached", "high", "Bind to localhost; exposed instances enable abuse."),
    27017: ("MongoDB", "high", "Enable auth and restrict network access."),
}

SECURITY_HEADERS = {
    "Content-Security-Policy": ("medium", "Add a CSP to limit XSS and data injection."),
    "X-Content-Type-Options": ("low", "Add 'X-Content-Type-Options: nosniff'."),
    "Referrer-Policy": ("info", "Add a Referrer-Policy such as 'strict-origin-when-cross-origin'."),
    "Permissions-Policy": ("info", "Add a Permissions-Policy to limit browser features."),
}

# (path, severity, content regex or None, description)
SENSITIVE_PATHS = [
    ("/.git/HEAD", "high", r"^ref:\s*refs/", "Git repository exposed (source code leak)"),
    ("/.env", "critical", r"^[A-Z][A-Z0-9_]*\s*=", "Environment file exposed (secrets)"),
    ("/.svn/entries", "high", r"dir|svn", "SVN metadata exposed"),
    ("/.DS_Store", "low", r"Bud1", "macOS .DS_Store file exposed"),
    ("/phpinfo.php", "medium", r"PHP Version|phpinfo\(\)", "phpinfo() page exposed"),
    ("/server-status", "medium", r"Apache Server Status", "Apache server-status exposed"),
    ("/wp-config.php.bak", "critical", r"DB_PASSWORD", "WordPress config backup exposed"),
    ("/config.php.bak", "critical", r"password|passwd|secret", "Config backup exposed"),
    ("/backup.zip", "high", None, "Backup archive exposed"),
    ("/backup.sql", "critical", None, "Database dump exposed"),
    ("/db.sql", "critical", None, "Database dump exposed"),
    ("/id_rsa", "critical", r"BEGIN (RSA|OPENSSH) PRIVATE KEY", "Private SSH key exposed"),
    ("/actuator/env", "high", r"propertySources|activeProfiles", "Spring Boot actuator exposed"),
    ("/swagger.json", "info", r"swagger|openapi", "API documentation publicly exposed"),
    ("/admin", "info", None, "Admin panel reachable (verify access control)"),
    ("/login", "info", None, "Login page found"),
]
DIR_LISTING_PATHS = ["/uploads/", "/images/", "/files/", "/backup/", "/static/", "/assets/"]

SQL_ERRORS = [
    r"you have an error in your sql syntax", r"warning: mysql", r"mysqli?_",
    r"unclosed quotation mark", r"quoted string not properly terminated",
    r"pg_query\(\)|psycopg2|postgresql.*error", r"sqlite3?\.operationalerror",
    r"ORA-\d{5}", r"microsoft ole db provider", r"odbc.*driver",
]
CANARY = 'vs7x"\'<z>'


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    detail: str = ""
    fix: str = ""


class Scanner:
    def __init__(self, args):
        self.a = args
        self.findings = []
        self._seen = set()
        self.s = requests.Session()
        self.s.headers["User-Agent"] = "vulnscan-mini/1.0 (authorized security testing)"
        self.s.verify = False  # TLS problems are reported by check_tls, not by failing

    # ---------- helpers ----------
    def add(self, sev, cat, title, detail="", fix=""):
        key = (cat, title, detail)
        if key in self._seen:
            return
        self._seen.add(key)
        f = Finding(sev, cat, title, detail, fix)
        self.findings.append(f)
        print(f"{COLOR[sev]}[{sev.upper():8}]{RESET} {cat}: {title}"
              + (f"  ({detail})" if detail else ""))

    def get(self, url, **kw):
        time.sleep(self.a.delay)
        try:
            return self.s.get(url, timeout=self.a.timeout, **kw)
        except requests.RequestException:
            return None

    # ---------- network ----------
    @staticmethod
    def parse_ports(spec):
        if spec == "common":
            return COMMON_PORTS
        ports = set()
        for part in spec.split(","):
            if "-" in part:
                lo, hi = part.split("-")
                ports.update(range(int(lo), int(hi) + 1))
            else:
                ports.add(int(part))
        return sorted(p for p in ports if 0 < p < 65536)

    def scan_ports(self, host, ports):
        print(f"\n== Port scan: {host} ({len(ports)} ports) ==")

        def probe(port):
            try:
                with socket.create_connection((host, port), timeout=self.a.timeout) as sock:
                    banner = ""
                    try:
                        sock.settimeout(1.0)
                        banner = sock.recv(128).decode(errors="ignore").strip()
                    except Exception:
                        pass
                    return port, banner
            except Exception:
                return None

        with ThreadPoolExecutor(self.a.threads) as ex:
            open_ports = [r for r in ex.map(probe, ports) if r]
        for port, banner in sorted(open_ports):
            svc, sev, fix = RISKY_PORTS.get(port, (None, "info", ""))
            title = f"Open port {port}" + (f" ({svc})" if svc else "")
            self.add(sev, "network", title, banner[:60].replace("\n", " "), fix)
            if banner and re.search(r"\d+\.\d+", banner):
                self.add("low", "network", f"Version banner on port {port}",
                         banner[:60].replace("\n", " "), "Hide or generalize service banners.")
        return [p for p, _ in open_ports]

    # ---------- web ----------
    def scan_web(self, url):
        print(f"\n== Web scan: {url} ==")
        r = self.get(url, allow_redirects=True)
        if r is None:
            self.add("info", "web", "Target unreachable", url)
            return
        p = urlparse(r.url)
        base = f"{p.scheme}://{p.netloc}"
        self.check_headers(r, p.scheme == "https")
        self.check_cookies(r)
        if p.scheme == "https":
            self.check_tls(p.hostname, p.port or 443)
            self.check_https_redirect(p)
        else:
            self.add("medium", "transport", "Site served over plain HTTP", url,
                     "Serve the site over HTTPS and redirect HTTP to HTTPS.")
        self.check_cors(base)
        self.check_paths(base)
        self.check_dir_listing(base)
        self.check_inputs(r)

    def check_headers(self, r, is_https):
        h = r.headers
        for name, (sev, fix) in SECURITY_HEADERS.items():
            if name not in h:
                self.add(sev, "headers", f"Missing {name}", fix=fix)
        if is_https and "Strict-Transport-Security" not in h:
            self.add("medium", "headers", "Missing Strict-Transport-Security",
                     fix="Add HSTS: 'max-age=31536000; includeSubDomains'.")
        csp = h.get("Content-Security-Policy", "")
        if "X-Frame-Options" not in h and "frame-ancestors" not in csp:
            self.add("low", "headers", "Clickjacking protection missing",
                     fix="Add X-Frame-Options: DENY or CSP frame-ancestors.")
        if re.search(r"unsafe-inline|unsafe-eval", csp):
            self.add("low", "headers", "Weak CSP (unsafe-inline/unsafe-eval)", csp[:80])
        for name in ("Server", "X-Powered-By", "X-AspNet-Version"):
            val = h.get(name)
            if val and re.search(r"\d", val):
                self.add("low", "disclosure", f"{name} reveals version", val,
                         "Remove or genericize version information.")

    def check_cookies(self, r):
        try:
            cookies = r.raw.headers.getlist("Set-Cookie")
        except Exception:
            return
        for c in cookies:
            name = c.split("=", 1)[0]
            low = c.lower()
            if "secure" not in low and r.url.startswith("https"):
                self.add("medium", "cookies", f"Cookie '{name}' missing Secure flag")
            if "httponly" not in low:
                self.add("medium", "cookies", f"Cookie '{name}' missing HttpOnly flag")
            if "samesite" not in low:
                self.add("low", "cookies", f"Cookie '{name}' missing SameSite attribute")

    def check_tls(self, host, port):
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=self.a.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    version, cert = ss.version(), ss.getpeercert()
        except ssl.SSLCertVerificationError as e:
            self.add("high", "tls", "Certificate validation failed", str(e.reason),
                     "Install a valid, trusted certificate that matches the hostname.")
            return
        except Exception as e:
            self.add("info", "tls", "TLS check could not complete", str(e)[:80])
            return
        if version in ("TLSv1", "TLSv1.1", "SSLv3"):
            self.add("high", "tls", f"Outdated protocol negotiated: {version}",
                     fix="Allow only TLS 1.2 and 1.3.")
        days = (ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) / 86400
        if days < 0:
            self.add("high", "tls", "Certificate expired", f"{int(-days)} days ago")
        elif days < 15:
            self.add("medium", "tls", "Certificate expires soon", f"{int(days)} days left")

    def check_https_redirect(self, p):
        if p.port not in (None, 443):
            return
        r = self.get(f"http://{p.hostname}/", allow_redirects=False)
        if r is None:
            return
        loc = r.headers.get("Location", "")
        if not (300 <= r.status_code < 400 and loc.startswith("https://")):
            self.add("medium", "transport", "HTTP does not redirect to HTTPS",
                     f"status {r.status_code}", "Redirect all HTTP traffic to HTTPS.")

    def check_cors(self, base):
        evil = "https://evil.example"
        r = self.get(base, headers={"Origin": evil})
        if r is None:
            return
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        creds = r.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        if acao == evil and creds:
            self.add("high", "cors", "CORS reflects arbitrary origin with credentials",
                     fix="Use a strict allow-list of trusted origins.")
        elif acao == evil:
            self.add("medium", "cors", "CORS reflects arbitrary origin",
                     fix="Use a strict allow-list of trusted origins.")
        elif acao == "*" and creds:
            self.add("high", "cors", "CORS wildcard with credentials")

    def check_paths(self, base):
        rnd = "".join(random.choices(string.ascii_lowercase, k=12))
        baseline = self.get(f"{base}/vs-{rnd}", allow_redirects=False)
        catch_all = baseline is not None and baseline.status_code == 200
        print("   checking exposed files ...")
        for path, sev, pattern, desc in SENSITIVE_PATHS:
            r = self.get(base + path, allow_redirects=False)
            if r is None or r.status_code != 200:
                continue
            body = r.text[:4000]
            if pattern:
                if not re.search(pattern, body, re.I | re.M):
                    continue
            else:  # no signature: avoid SPA / catch-all false positives
                if catch_all and r.text[:500] == baseline.text[:500]:
                    continue
                if "text/html" in r.headers.get("Content-Type", "") and path not in ("/admin", "/login"):
                    continue
            self.add(sev, "exposure", desc, base + path,
                     "Remove the file or block access at the web server.")
        robots = self.get(base + "/robots.txt", allow_redirects=False)
        if robots is not None and robots.status_code == 200 and "text/html" not in robots.headers.get("Content-Type", ""):
            dis = re.findall(r"(?im)^disallow:\s*(\S+)", robots.text)
            if dis:
                self.add("info", "exposure", "robots.txt lists hidden paths",
                         ", ".join(dis[:6]), "Do not rely on robots.txt to hide sensitive paths.")

    def check_dir_listing(self, base):
        for path in DIR_LISTING_PATHS:
            r = self.get(base + path, allow_redirects=False)
            if r is not None and r.status_code == 200 and re.search(r"<title>Index of /|Directory listing for", r.text, re.I):
                self.add("medium", "exposure", "Directory listing enabled", base + path,
                         "Disable autoindex / directory browsing.")

    def check_inputs(self, resp):
        urls = set()
        if urlparse(resp.url).query:
            urls.add(resp.url)
        if "html" in resp.headers.get("Content-Type", ""):
            host = urlparse(resp.url).netloc
            for href in re.findall(r'href=["\']([^"\']+\?[^"\']+)["\']', resp.text)[:40]:
                full = urljoin(resp.url, href)
                if urlparse(full).netloc == host:
                    urls.add(full)
        urls = sorted(urls)[:10]
        if not urls:
            self.add("info", "input", "No URLs with query parameters found to test")
            return
        print(f"   testing parameters on {len(urls)} URL(s) ...")
        for url in urls:
            self.test_params(url)

    def test_params(self, url):
        p = urlparse(url)
        params = parse_qsl(p.query, keep_blank_values=True)
        base_resp = self.get(url)
        for i, (k, v) in enumerate(params):
            def mutate(val):
                q = list(params)
                q[i] = (k, val)
                return urlunparse(p._replace(query=urlencode(q)))
            r = self.get(mutate(CANARY))
            if r is not None and "html" in r.headers.get("Content-Type", "") and CANARY in r.text:
                self.add("medium", "injection", f"Possible reflected XSS in '{k}'",
                         p.path or "/", "HTML-encode output and apply a strict CSP.")
            r = self.get(mutate(v + "'"))
            if r is not None:
                for sig in SQL_ERRORS:
                    if re.search(sig, r.text, re.I) and not (base_resp and re.search(sig, base_resp.text, re.I)):
                        self.add("high", "injection", f"SQL error disclosed via '{k}'",
                                 p.path or "/", "Use parameterized queries and hide DB errors.")
                        break

    # ---------- orchestration ----------
    def run(self, target):
        has_scheme = target.startswith(("http://", "https://"))
        host = urlparse(target).hostname if has_scheme else target
        if not self.a.skip_ports:
            open_ports = self.scan_ports(host, self.parse_ports(self.a.ports))
        else:
            open_ports = []
        if has_scheme:
            self.scan_web(target)
        else:
            for port, scheme in ((443, "https"), (8443, "https"), (80, "http"), (8080, "http")):
                if port in open_ports:
                    self.scan_web(f"{scheme}://{host}:{port}" if port not in (80, 443) else f"{scheme}://{host}")
                    break


# ---------- reporting ----------
def summarize(findings):
    counts = {s: 0 for s in SEV}
    for f in findings:
        counts[f.severity] += 1
    return counts


def write_json(path, target, findings):
    data = {"target": target, "scanned_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "summary": summarize(findings), "findings": [asdict(f) for f in findings]}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def write_html(path, target, findings):
    colors = {"critical": "#a21caf", "high": "#dc2626", "medium": "#d97706", "low": "#2563eb", "info": "#6b7280"}
    rows = "".join(
        f"<tr><td><b style='color:{colors[f.severity]}'>{f.severity.upper()}</b></td>"
        f"<td>{html.escape(f.category)}</td><td>{html.escape(f.title)}</td>"
        f"<td>{html.escape(f.detail)}</td><td>{html.escape(f.fix)}</td></tr>"
        for f in sorted(findings, key=lambda x: -SEV[x.severity]))
    counts = " | ".join(f"{k}: {v}" for k, v in summarize(findings).items())
    doc = f"""<!doctype html><meta charset="utf-8"><title>Scan report</title>
<style>body{{font-family:system-ui;margin:2rem;color:#111}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ddd;padding:6px 10px;text-align:left;vertical-align:top}}th{{background:#f3f4f6}}</style>
<h1>Vulnerability Scan Report</h1><p><b>Target:</b> {html.escape(target)}<br>
<b>Date:</b> {dt.datetime.now().strftime('%Y-%m-%d %H:%M')}<br><b>Summary:</b> {counts}</p>
<table><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Detail</th><th>Recommendation</th></tr>{rows}</table>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)


def main():
    ap = argparse.ArgumentParser(description="Mini vulnerability scanner (detection only).")
    ap.add_argument("target", help="URL (https://site) for web+network scan, or host/IP for network scan")
    ap.add_argument("--ports", default="common", help="'common', range '1-1024', or list '22,80,443'")
    ap.add_argument("--skip-ports", action="store_true", help="skip the TCP port scan")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--delay", type=float, default=0.2, help="seconds between HTTP requests")
    ap.add_argument("--threads", type=int, default=50)
    ap.add_argument("--json", metavar="FILE")
    ap.add_argument("--html", metavar="FILE")
    ap.add_argument("--i-have-permission", action="store_true",
                    help="confirm you are authorized to test this target")
    args = ap.parse_args()

    if not args.i_have_permission:
        sys.exit("Refusing to scan: pass --i-have-permission to confirm you own the target "
                 "or have written authorization to test it.")

    print(f"vulnscan-mini | target: {args.target} | {dt.datetime.now():%Y-%m-%d %H:%M:%S}")
    sc = Scanner(args)
    try:
        sc.run(args.target)
    except KeyboardInterrupt:
        print("\nInterrupted.")

    counts = summarize(sc.findings)
    print("\n== Summary ==\n" + "  ".join(f"{k}: {v}" for k, v in counts.items()))
    if args.json:
        write_json(args.json, args.target, sc.findings)
        print(f"JSON report: {args.json}")
    if args.html:
        write_html(args.html, args.target, sc.findings)
        print(f"HTML report: {args.html}")
    sys.exit(1 if counts["critical"] or counts["high"] else 0)


if __name__ == "__main__":
    main()