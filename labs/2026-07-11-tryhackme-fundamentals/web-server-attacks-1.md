---
title: "Web Server Attacks I - Misconfigurations Across Apache, Nginx, Node, and Python"
date: 2026-07-11
difficulty: Easy
category: offensive
excerpt: "Four web servers on one host, the same misconfiguration patterns on each: version disclosure, directory listing, exposed status pages, and missing security headers."
---

TryHackMe Easy offensive

# Web Server Attacks I - Misconfigurations Across Apache, Nginx, Node, and Python

Four different web servers, one machine, and the same categories of mistake on every one.
This room ran the same investigation against Apache, Python's HTTP server, Node.js
Express, and Nginx. The lesson underneath it is that default configurations favor easy
deployment over security, so version banners, directory listings, and status pages are
on by default and stay on until someone turns them off.

## Fingerprinting first

Before enumerating anything, identify the server. The `Server` header names the software
and often the version, and `X-Powered-By` names the app framework when `Server` is
generic or missing.

```bash
curl -sI http://TARGET:PORT       # headers only
curl -s http://TARGET:PORT/nope   # default 404 page, another fingerprint
```

Each server has a tell: Apache shows `Apache/2.4.x (Ubuntu)`, Python shows
`SimpleHTTP/0.6 Python/3.x`, Nginx shows `nginx/1.x`, and Express sends no `Server`
header at all but gives itself away with `X-Powered-By: Express`. Even the 404 page
differs per server, so you can fingerprint even when the header is suppressed.

## Python HTTP server

`python3 -m http.server` serves the entire working directory with no auth, no logging,
and no blocklist. It even serves dotfiles like `.env`, which Apache and Nginx would hide.
The finding is not a vulnerability, it is that the server is running where it should not
be. Check the root listing, pull any `.env` for credentials, and download any archive in
the directory, because backups often hold source or database dumps.

## Apache

Default Ubuntu Apache leaves three things worth checking:

- **Directory listing** where `Options +Indexes` is on, exposing a browsable file list at
  paths like `/files/`.
- **`/server-status`**, the `mod_status` page. It ships restricted to localhost, but a
  stray `Require all granted` in a vhost silently exposes it to everyone, leaking live
  requests and internal paths. Always check it.
- **Backup files** in the document root. Gobuster with `-x bak,txt` finds unlinked
  `.bak` copies and `.htpasswd` files, which often hold credentials or config.

## Node.js Express

Express apps run code, not static files, so the mistakes are development features left on
in production. A custom error handler leaks stack traces with internal file paths and SQL
queries. A debug route like `/api/routes` lists every endpoint, and `/api/debug/env`
dumps `process.env` with database passwords. `NODE_ENV: development` on a live server is
itself a signal it was never hardened. Static config files served to the browser
(`/static/config.js`) can leak internal hostnames and debug flags.

## Nginx

Same patterns as Apache with different directive names. `server_tokens on` (the default)
discloses the version in the header and 404 footer. `autoindex on` is Nginx's directory
listing. `stub_status` at a path like `/nginx_status` is the `mod_status` equivalent,
leaking connection metrics when it is not restricted to localhost.

## The patterns that repeat

Across all four, the same categories show up: version disclosure in headers, directory
listing, an exposed status or debug endpoint, sensitive files left reachable, and missing
security headers. None of the servers set `X-Frame-Options`, `X-Content-Type-Options`,
`Content-Security-Policy`, or `Referrer-Policy` by default. A quick audit:

```bash
for p in 80 8000 3000 8080; do echo "=== $p ==="; \
  curl -sI http://TARGET:$p/ | grep -iE "x-frame|x-content-type|content-security|referrer-policy"; done
```

Nikto automates the whole sweep: `nikto -h http://TARGET:80 -nointeractive` flags the
exposed status page, the directory indexing, backup files, and the missing headers in
about ten seconds.

## Takeaway

Studying each server in isolation hides the point: the misconfigurations are the same
everywhere because permissive defaults are the same everywhere. Fingerprint with headers,
check for directory listing and status pages, look for sensitive files, and audit the
security headers. That short checklist covers most of what a misconfigured web server
will hand you, regardless of which server it is.
