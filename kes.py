#!/usr/bin/env python3
"""
Kestrel - ethical-hacking recon toolkit
Stage 1: authorization + port scanner
Stage 2: banner grabbing, HTTP security headers, directory brute-force,
         subdomain brute-force
Stage 3: live username search across sites (Sherlock-style)
 
Only use on systems you own or have written permission to test.
Only search usernames you have a legitimate reason to look up.
 
Examples:
    python3 kes.py 127.0.0.1
    python3 kes.py scanme.nmap.org -p 1-1024 -b
    python3 kes.py scanme.nmap.org -H
    python3 kes.py scanme.nmap.org -d
    python3 kes.py nmap.org -s
    python3 kes.py scanme.nmap.org -p 1-1024 -b -H -d
    python3 kes.py -u johnsmith123
 
Flags:
    -p  ports        'common', a list (22,80,443), or a range (1-1024)
    -t  timeout       seconds to wait per port (default 1.0)
    -b  banners       grab service banners on open ports
    -H  headers       check HTTP security headers
    -d  dirs          brute-force common web paths
    -s  subdomains    brute-force common subdomains
    -u  username      search for a username across sites (live checks)
    -a  all           run every target-based check (needs a target)
"""
 
import argparse
import random
import socket
import ssl
import sys
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
 
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                993, 995, 1433, 3306, 3389, 5432, 5900, 8000, 8080, 8443]
 
PHRASE = "I HAVE PERMISSION"
LOG_FILE = "kestrel_authorization.log"
VERSION = "1.0"
 
# ANSI colors - most Linux terminals (including Kali's) support these
C_RESET = "\033[0m"
C_CYAN = "\033[96m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_DIM = "\033[2m"
C_BOLD = "\033[1m"
 
BANNER_ART = f"""{C_CYAN}
    __   __       __           __
   / /__/ /__ ___/ /________  / /
  / '_/ _  (_-</ __/ __/ -_) / /
 /_/\\_\\_,_/___/\\__/_/  \\__/_/
{C_RESET}{C_DIM}        recon toolkit v{VERSION}{C_RESET}
"""
 
TIPS = [
    "Only scan systems you own or have written permission to test.",
    "Combine flags in one run, e.g. kestrel target -b -H -d",
    "Use -u <username> to run a live cross-site username search.",
    "Treat LinkedIn/Facebook/Quora/VK results as leads to verify by hand.",
    "kestrel_authorization.log keeps a record of every confirmed scan.",
    "Use scanme.nmap.org to practice the port scanner safely.",
    "Run kestrel -h any time to see the full flag list.",
]
 
 
def print_banner():
    print(BANNER_ART)
    print(f"{C_YELLOW}[tip]{C_RESET} {random.choice(TIPS)}\n")
 
DIR_WORDLIST = [
    "admin", "login", "dashboard", "config", "backup", "backups", "uploads",
    "images", "api", "test", "dev", "staging", "old", "tmp", "private",
    ".git", ".env", ".git/config", "wp-admin", "wp-login.php", "phpmyadmin",
    "server-status", "robots.txt", "sitemap.xml", ".htaccess", "console",
    "debug", "swagger", "swagger-ui.html", "actuator", "db", "database.sql",
]
 
SUB_WORDLIST = [
    "www", "mail", "ftp", "dev", "test", "staging", "api", "admin", "portal",
    "vpn", "remote", "webmail", "ns1", "ns2", "shop", "blog", "cdn", "app",
    "secure", "beta", "git", "docs", "support", "status", "m",
]
 
SECURITY_HEADERS = {
    "Strict-Transport-Security": "Forces HTTPS on future visits (prevents downgrade attacks).",
    "Content-Security-Policy": "Restricts what scripts/resources a page may load.",
    "X-Frame-Options": "Stops the page being embedded in a hidden frame (clickjacking).",
    "X-Content-Type-Options": "Stops the browser guessing file types, which can be abused.",
    "Referrer-Policy": "Controls how much of the URL is leaked to other sites via Referer.",
}
 
 
# ---------- shared ----------
 
def confirm_authorization(target):
    print(f"{C_BOLD}Target:{C_RESET} {target}")
    print(f"{C_YELLOW}Only scan systems you own or have written permission to test.{C_RESET}")
    answer = input(f"Type '{PHRASE}' to continue: ").strip()
    if answer != PHRASE:
        print("Scan cancelled.")
        sys.exit(0)
    with open(LOG_FILE, "a") as log:
        log.write(f"{datetime.now().isoformat()} | authorization confirmed | {target}\n")
 
 
def resolve(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"Could not resolve '{target}'. Check the spelling.")
        sys.exit(1)
 
 
def parse_ports(spec):
    if spec == "common":
        return COMMON_PORTS
    ports = set()
    for part in spec.split(","):
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)
 
 
# ---------- Stage 1: port scan ----------
 
def scan_port(ip, port, timeout):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        if s.connect_ex((ip, port)) == 0:
            return port
    return None
 
 
def service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"
 
 
def run_port_scan(target, ip, ports, timeout, threads):
    print(f"\nScanning {target} ({ip}) - {len(ports)} ports")
    print(f"Started: {datetime.now():%Y-%m-%d %H:%M:%S}\n")
 
    with ThreadPoolExecutor(max_workers=threads) as pool:
        results = pool.map(lambda p: scan_port(ip, p, timeout), ports)
        open_ports = [p for p in results if p]
 
    if open_ports:
        print(f"{'PORT':<8}{'STATE':<8}SERVICE")
        for p in open_ports:
            print(f"{p:<8}{'open':<8}{service_name(p)}")
    else:
        print("No open ports found.")
    print(f"\nDone. {len(open_ports)} open port(s) out of {len(ports)} scanned.")
    return open_ports
 
 
# ---------- Stage 2a: banner grabbing ----------
 
def grab_banner(ip, port, timeout=2.0):
    """Connect, optionally say hello, and read whatever the service sends back."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            if port in (80, 8080, 8000):
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 443:
                return grab_tls_banner(ip, port, timeout)
            banner = s.recv(1024).decode(errors="ignore").strip()
            return banner.splitlines()[0] if banner else "(no banner)"
    except Exception:
        return "(no response)"
 
 
def grab_tls_banner(ip, port, timeout):
    """For HTTPS, do the TLS handshake first, then read the HTTP response."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock) as tls:
                tls.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = tls.recv(1024).decode(errors="ignore").strip()
                return banner.splitlines()[0] if banner else "(TLS, no banner)"
    except Exception:
        return "(TLS handshake only, no banner)"
 
 
def run_banner_grab(ip, open_ports):
    print("\n" + "=" * 50)
    print("BANNERS")
    print("=" * 50)
    for port in open_ports:
        banner = grab_banner(ip, port)
        print(f"{port:<8}{banner}")
 
 
# ---------- Stage 2b: HTTP security headers ----------
 
def fetch_headers(url, timeout=5.0):
    req = urllib.request.Request(url, headers={"User-Agent": "Kestrel-Recon/1.0"})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return dict(resp.headers), resp.status
    except urllib.error.HTTPError as e:
        return dict(e.headers), e.code
    except Exception as e:
        return None, str(e)
 
 
def run_header_check(target):
    print("\n" + "=" * 50)
    print("HTTP SECURITY HEADERS")
    print("=" * 50)
    for scheme in ("https", "http"):
        url = f"{scheme}://{target}/"
        headers, status = fetch_headers(url)
        if headers is None:
            print(f"{url} -> could not connect ({status})")
            continue
        print(f"\n{url} -> HTTP {status}")
        server = headers.get("Server")
        if server:
            print(f"!! Server header reveals software/version: {server}")
        for h, why in SECURITY_HEADERS.items():
            if h in headers:
                print(f"OK  {h}: present")
            else:
                print(f"!!  {h}: MISSING - {why}")
        return  # one successful scheme is enough
    print("Could not reach the target over HTTP or HTTPS.")
 
 
# ---------- Stage 2c: directory brute-force ----------
 
def check_path(base_url, path, timeout=4.0):
    url = base_url.rstrip("/") + "/" + path
    req = urllib.request.Request(url, headers={"User-Agent": "Kestrel-Recon/1.0"}, method="HEAD")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return path, resp.status
    except urllib.error.HTTPError as e:
        if e.code in (200, 301, 302, 403):
            return path, e.code
        return None
    except Exception:
        return None
 
 
def run_dir_brute(target, wordlist=None, threads=20):
    base_url = f"https://{target}"
    wordlist = wordlist or DIR_WORDLIST
    print("\n" + "=" * 50)
    print(f"DIRECTORY BRUTE-FORCE ({len(wordlist)} paths)")
    print("=" * 50)
    with ThreadPoolExecutor(max_workers=threads) as pool:
        results = pool.map(lambda p: check_path(base_url, p), wordlist)
    found = [r for r in results if r]
    if found:
        for path, status in found:
            print(f"{status:<5} {base_url}/{path}")
    else:
        print("Nothing found from this wordlist.")
    print(f"\n{len(found)} result(s) out of {len(wordlist)} tried.")
 
 
# ---------- Stage 2d: subdomain brute-force ----------
 
def check_subdomain(name, domain):
    host = f"{name}.{domain}"
    try:
        ip = socket.gethostbyname(host)
        return host, ip
    except socket.gaierror:
        return None
 
 
def run_subdomain_brute(domain, wordlist=None, threads=30):
    wordlist = wordlist or SUB_WORDLIST
    print("\n" + "=" * 50)
    print(f"SUBDOMAIN BRUTE-FORCE ({len(wordlist)} names)")
    print("=" * 50)
    with ThreadPoolExecutor(max_workers=threads) as pool:
        results = pool.map(lambda n: check_subdomain(n, domain), wordlist)
    found = [r for r in results if r]
    if found:
        for host, ip in found:
            print(f"{host:<30}{ip}")
    else:
        print("No subdomains found from this wordlist.")
    print(f"\n{len(found)} found out of {len(wordlist)} tried.")
 
 
# ---------- Stage 3: live username search ----------
# Each entry: (site name, URL with {} for the username, how to tell "not found")
# "not_found_code": an HTTP status that means the account doesn't exist
# "not_found_text": a phrase that appears on the page when the account doesn't exist
USERNAME_SITES = [
    ("GitHub",      "https://github.com/{}",            {"not_found_code": 404}),
    ("GitLab",      "https://gitlab.com/{}",             {"not_found_code": 404}),
    ("Reddit",      "https://www.reddit.com/user/{}",    {"not_found_code": 404}),
    ("Instagram",   "https://www.instagram.com/{}/",     {"not_found_code": 404}),
    ("Twitter/X",   "https://x.com/{}",                  {"not_found_code": 404}),
    ("TikTok",      "https://www.tiktok.com/@{}",        {"not_found_text": "Couldn't find this account"}),
    ("YouTube",     "https://www.youtube.com/@{}",       {"not_found_code": 404}),
    ("Twitch",      "https://www.twitch.tv/{}",          {"not_found_text": "Sorry. Unless you've got a time machine"}),
    ("Pinterest",   "https://www.pinterest.com/{}/",     {"not_found_code": 404}),
    ("Steam",       "https://steamcommunity.com/id/{}",  {"not_found_text": "The specified profile could not be found"}),
    ("Medium",      "https://medium.com/@{}",            {"not_found_code": 404}),
    ("DeviantArt",  "https://www.deviantart.com/{}",     {"not_found_text": "doesn't exist on this server"}),
    ("SoundCloud",  "https://soundcloud.com/{}",         {"not_found_code": 404}),
    ("Keybase",     "https://keybase.io/{}",              {"not_found_code": 404}),
    ("Dev.to",      "https://dev.to/{}",                 {"not_found_code": 404}),
    ("Replit",      "https://replit.com/@{}",             {"not_found_code": 404}),
    ("HackerNews",  "https://news.ycombinator.com/user?id={}", {"not_found_text": "No such user"}),
    ("Docker Hub",  "https://hub.docker.com/u/{}",        {"not_found_code": 404}),
    ("NPM",         "https://www.npmjs.com/~{}",          {"not_found_code": 404}),
    ("Telegram",    "https://t.me/{}",                    {"not_found_text": "If you have Telegram"}),
    ("Spotify",     "https://open.spotify.com/user/{}",   {"not_found_code": 404}),
    ("Snapchat",    "https://www.snapchat.com/add/{}",    {"not_found_text": "Sorry! We couldn't find"}),
    ("Vimeo",       "https://vimeo.com/{}",                {"not_found_code": 404}),
    ("Flickr",      "https://www.flickr.com/people/{}",    {"not_found_code": 404}),
    ("Behance",     "https://www.behance.net/{}",          {"not_found_text": "Page not found"}),
    ("Dribbble",    "https://dribbble.com/{}",             {"not_found_code": 404}),
    ("Patreon",     "https://www.patreon.com/{}",          {"not_found_code": 404}),
    ("Kickstarter", "https://www.kickstarter.com/profile/{}", {"not_found_code": 404}),
    ("WordPress",   "https://{}.wordpress.com",            {"not_found_code": 404}),
    ("Letterboxd",  "https://letterboxd.com/{}/",          {"not_found_code": 404}),
    ("Goodreads",   "https://www.goodreads.com/{}",        {"not_found_code": 404}),
    ("About.me",    "https://about.me/{}",                 {"not_found_code": 404}),
    ("Gravatar",    "https://en.gravatar.com/{}",          {"not_found_code": 404}),
    ("CodePen",     "https://codepen.io/{}",               {"not_found_code": 404}),
    ("ProductHunt", "https://www.producthunt.com/@{}",     {"not_found_code": 404}),
    # These sites actively block simple automated checks or always return
    # HTTP 200, so results here are much less reliable - always confirm
    # by hand before relying on them.
    ("LinkedIn",    "https://www.linkedin.com/in/{}",      {"not_found_code": 404, "unreliable": True}),
    ("Facebook",    "https://www.facebook.com/{}",         {"not_found_text": "This content isn't available", "unreliable": True}),
    ("Quora",       "https://www.quora.com/profile/{}",    {"not_found_text": "Page Not Found", "unreliable": True}),
    ("VK",          "https://vk.com/{}",                    {"not_found_text": "This page has been deleted", "unreliable": True}),
]
UNRELIABLE_SITES = {name for name, _, rule in USERNAME_SITES if rule.get("unreliable")}
 
 
def check_username_site(site_name, url_pattern, rule, username, timeout=6.0):
    """
    Actually request the profile URL and decide, from the real response,
    whether the account exists. This is a live check, not a guess.
    """
    url = url_pattern.format(username)
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (Kestrel-Recon/1.0; OSINT username check)"
    })
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            status = resp.status
            body = resp.read(4096).decode(errors="ignore") if "not_found_text" in rule else ""
    except urllib.error.HTTPError as e:
        status = e.code
        body = ""
    except Exception:
        return (site_name, url, "error - could not connect")
 
    if "not_found_code" in rule and status == rule["not_found_code"]:
        return (site_name, url, "not found")
    if "not_found_text" in rule and rule["not_found_text"].lower() in body.lower():
        return (site_name, url, "not found")
    if status == 200:
        return (site_name, url, "FOUND")
    return (site_name, url, f"unclear (HTTP {status})")
 
 
def run_username_search(username, threads=15):
    print("\n" + "=" * 50)
    print(f"USERNAME SEARCH: {username}  ({len(USERNAME_SITES)} sites, live checks)")
    print("=" * 50)
    print("Only look up usernames you have a legitimate reason to check.\n")
 
    with ThreadPoolExecutor(max_workers=threads) as pool:
        results = list(pool.map(
            lambda s: check_username_site(s[0], s[1], s[2], username),
            USERNAME_SITES
        ))
 
    found = [r for r in results if r[2] == "FOUND"]
    unclear = [r for r in results if r[2].startswith("unclear") or r[2] == "error - could not connect"]
 
    for name, url, status in results:
        if status == "FOUND":
            tag = " (verify by hand - unreliable site)" if name in UNRELIABLE_SITES else ""
            print(f"[+] {name:<12} {url}{tag}")
    if found:
        print()
    for name, url, status in results:
        if status not in ("FOUND", "not found"):
            print(f"[?] {name:<12} {status}")
 
    print(f"\nFound on {len(found)} of {len(USERNAME_SITES)} sites checked "
          f"({len(unclear)} unclear, rest not found). "
          f"Treat LinkedIn, Facebook, Quora and VK results as unconfirmed leads only.")
 
 
# ---------- main ----------
 
def main():
    parser = argparse.ArgumentParser(description="Kestrel - ethical-hacking recon toolkit")
    parser.add_argument("target", nargs="?", help="IP address, hostname, or domain")
    parser.add_argument("-p", "--ports", default="common",
                        help="'common', a list like 22,80,443, or a range like 1-1024")
    parser.add_argument("-t", "--timeout", type=float, default=1.0,
                        help="seconds to wait per port (default 1.0)")
    parser.add_argument("--threads", type=int, default=50,
                        help="how many checks to run at once (default 50)")
    parser.add_argument("-b", "--banners", action="store_true", help="grab service banners on open ports")
    parser.add_argument("-H", "--headers", action="store_true", help="check HTTP security headers")
    parser.add_argument("-d", "--dirs", action="store_true", help="brute-force common web paths")
    parser.add_argument("-s", "--subdomains", action="store_true", help="brute-force common subdomains")
    parser.add_argument("-u", "--username", help="search for a username across sites (live checks)")
    parser.add_argument("-a", "--all", action="store_true", help="run every check (needs a target)")
    args = parser.parse_args()
 
    print_banner()
 
    if args.username:
        run_username_search(args.username)
        return
 
    if not args.target:
        parser.error("a target is required unless you use --username")
 
    confirm_authorization(args.target)
    ip = resolve(args.target)
    ports = parse_ports(args.ports)
 
    open_ports = run_port_scan(args.target, ip, ports, args.timeout, args.threads)
 
    if args.banners or args.all:
        if open_ports:
            run_banner_grab(ip, open_ports)
        else:
            print("\nNo open ports to grab banners from.")
 
    if args.headers or args.all:
        run_header_check(args.target)
 
    if args.dirs or args.all:
        run_dir_brute(args.target)
 
    if args.subdomains or args.all:
        run_subdomain_brute(args.target)
 
 
if __name__ == "__main__":
    main()
