# 2026-07-11 - TryHackMe Fundamentals

Continuing the fundamentals catch-up from 2026-07-04: shorter, concept-first writeups
from the easier TryHackMe rooms I skipped while working through the harder labs. Today
finished the nmap series and moved into web fundamentals. Same approach as the rest of
the repo, methodology and the *why* over any single box's kill chain, no flags or answers.

## Contents

- [nmap-post-port-scans.md](nmap-post-port-scans.md) *(Easy)* - What to do after finding open ports: service and version detection (`-sV`), OS fingerprinting (`-O`), the Nmap Scripting Engine (`-sC`, `--script`), the `-A` shortcut, and saving output (`-oN`/`-oG`/`-oX`/`-oA`). Closes out the nmap series.
- [walking-an-application.md](walking-an-application.md) *(Easy)* - Reviewing a web app with nothing but the browser: page source, and the Inspector, Debugger, Network, and Storage dev tools panels, and why client-side controls are not security.
- [content-discovery.md](content-discovery.md) *(Easy)* - Finding pages and files a site did not mean to expose, three ways: manual (robots.txt, sitemap.xml, headers, framework docs), OSINT (dorking, Wappalyzer, Wayback, GitHub, S3), and Gobuster (dir/dns/vhost).
- [web-server-attacks-1.md](web-server-attacks-1.md) *(Easy)* - The same misconfiguration patterns across Apache, Nginx, Node Express, and Python: version disclosure, directory listing, exposed status and debug pages, sensitive files, and missing security headers.
- [modern-web-stacks.md](modern-web-stacks.md) *(Easy)* - Fingerprinting a stack from its HTTP signals, then targeting the matching CVE: MERN prototype pollution, Next.js middleware bypass (CVE-2025-29927), Django SQLi (CVE-2021-35042), and Apache 2.4.49 path traversal to RCE (CVE-2021-41773).

## Where these are published

All five are published in reader-friendly form on the blog at <https://barrytd.github.io/>
under **Labs**. The command reference that grew out of these rooms lives at the repo root
as [`terminal-manual.md`](../../terminal-manual.md) and as the **/manual/** page on the blog.
