# Kestrel

A lightweight recon toolkit for ethical hacking, built in pure Python with
no external dependencies.

## What it does

| Flag | Function | Similar to |
|---|---|---|
| *(default)* | TCP port scan | `nmap` |
| `-b` | Grabs service banners on open ports | `nmap -sV` |
| `-H` | Checks HTTP security headers | `nikto` |
| `-d` | Brute-forces common web paths | `dirb` / `gobuster` |
| `-s` | Brute-forces common subdomains | `sublist3r` |
| `-u` | Live username search across ~39 sites | `sherlock` |

## Install

```bash
git clone https://github.com/<your-username>/kestrel.git
cd kestrel
chmod +x kes.py
sudo cp kes.py /usr/local/bin/kestrel
sudo chmod +x /usr/local/bin/kestrel
```

## Usage

```bash
kestrel scanme.nmap.org               # port scan, common ports
kestrel scanme.nmap.org -p 1-1024     # custom port range
kestrel scanme.nmap.org -b            # banners
kestrel example.com -H                # HTTP security headers
kestrel example.com -d                # directory brute-force
kestrel example.com -s                # subdomain brute-force
kestrel scanme.nmap.org -p 1-1024 -b -H -d   # combine checks
kestrel -u someusername               # live username search
```

## How the username search works

Sends a real HTTP request to each site's profile URL and reads the actual
response (a 404, or specific page text) to decide if the account exists —
not a guess. LinkedIn, Facebook, Quora and VK block simple automated
requests, so results from those four are flagged unreliable and should be
confirmed by hand.

## Ethics and scope

Kestrel requires typed confirmation (`I HAVE PERMISSION`) before scanning
any target, and logs every confirmed scan with a timestamp to
`kestrel_authorization.log` (excluded from the repo via `.gitignore`).

**Only scan systems you own or have explicit written permission to test.**
`scanme.nmap.org` is provided by the Nmap project for safe testing.

This tool does not include anything that attempts to log in, guess
passwords, exploit a vulnerability, or send attack traffic. It finds and
documents weaknesses; it does not act on them.

## Project background

Built as a project demonstrating recon-stage ethical hacking:
port scanning, service fingerprinting, web security auditing, and OSINT
username enumeration, with a built-in permission gate.

## License

MIT - see [LICENSE](LICENSE).
