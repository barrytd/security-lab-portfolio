---
title: "Modern Web Stacks - Fingerprint the Stack, Then Target the CVE"
date: 2026-07-11
difficulty: Easy
category: offensive
excerpt: "Four stacks, four CVEs. Reading a stack from its HTTP signals so you know the attack surface before a scanner finishes running."
---

TryHackMe Easy offensive

# Modern Web Stacks - Fingerprint the Stack, Then Target the CVE

Every web stack leaks its identity through headers, cookie names, error pages, and HTML
patterns. Once you know the stack and version, you know the attack surface. This room ran
the same three-step workflow against four stacks: read the signals, confirm the version,
execute the exploit. The point is that targeted fingerprinting beats a generic scanner,
because scanners miss bugs that live in one middleware function or one deserialisation
path.

## The workflow

1. Fingerprint the stack from HTTP signals, no payloads yet.
2. Confirm the version and find the matching CVE.
3. Exploit, and understand why the vulnerable code exists.

A version banner points you at a CVE but does not prove exploitability. A server can be
back-patched while still showing an old version, or the vulnerable feature may be turned
off. So the banner narrows the search, and you confirm before exploiting. This room made
that concrete: before the Apache exploit, you check that `/cgi-bin/` returns 403, which
confirms mod_cgi is actually enabled.

## MERN (Express) - prototype pollution

Signals: `X-Powered-By: Express`, a `connect.sid` session cookie, and a plain-text
`Cannot GET /nonexistent` on an unknown route.

The bug lives in a hand-written merge function that copies JSON keys into a user object
with no filtering. Sending `{"__proto__": {"isAdmin": true}}` writes `isAdmin: true` onto
`Object.prototype` itself, not one object. The admin route checks `currentUser.isAdmin`,
finds no own property, walks the prototype chain, and finds the polluted `true`. Auth
bypass with one JSON payload.

## Next.js - middleware bypass (CVE-2025-29927)

Signals: `X-Powered-By: Next.js`, `window.__next_f` in the page source (the App Router
hydration array), `/_next/static/chunks/` asset paths.

Next.js uses an internal `x-middleware-subrequest` header to avoid running middleware
twice on recursive calls, but it never checked whether the header came from inside or
from the client. Since middleware is where most Next.js apps put their auth checks,
sending that header yourself skips the check entirely. One header, full auth bypass,
CVSS 9.1.

## Django - SQL injection (CVE-2021-35042)

Signals: `Server: WSGIServer/0.2 CPython/X.X.X`, a `csrftoken` cookie, and the
`csrfmiddlewaretoken` hidden field in POST forms, which is the near-certain tell.

The catalogue view concatenates the `order` parameter straight into an `ORDER BY`
clause. An `updatexml()` payload forces a MySQL XPath error, and with debug mode on,
Django leaks the query result in the 500 response. That extracts the version, the
database name, and anything else you can select. This is what happens when code bypasses
the ORM and builds SQL by hand.

## LAMP (Apache 2.4.49) - path traversal to RCE (CVE-2021-41773)

Signals: `Server: Apache/2.4.49 (Unix)`, the version repeated in 404 footers, and
`/cgi-bin/` returning 403 rather than 404, which means mod_cgi is enabled.

Apache 2.4.49 broke its traversal filter: `.%2e/` slips past the check, but the OS still
resolves it as `../`. Traverse to `/bin/sh`, and because `/cgi-bin/` runs CGI, Apache
executes it with your POST body as commands. Unauthenticated RCE. `curl --path-as-is` is
required so curl does not clean up the encoded dots before sending.

## Automation with Nikto

Nikto does the fingerprinting pass automatically: `nikto -h http://TARGET:PORT` reads the
headers, reports the Server banner, allowed methods, and misconfigurations in about ten
seconds. It is a fast first look across many hosts. For the Apache port it handed over the
exact version that maps to the CVE. What it does not do is find the app-level bugs, the
prototype pollution and the SQL injection needed the manual work. Nikto flags where to
look, it does not exploit.

## Takeaway

The banner is the lead, not the proof. Read the signals, confirm the version and the
required config, then exploit. Fingerprinting turns a noisy guess-and-check into a
targeted chain, and it is faster than waiting on a scanner, because you already know the
CVE before the scan finishes.
