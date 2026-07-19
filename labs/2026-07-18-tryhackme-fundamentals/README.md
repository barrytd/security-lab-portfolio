# 2026-07-18 - TryHackMe Fundamentals

Continuing the fundamentals catch-up. Two rooms today: the IIS half of the web server series
(the sequel to the 2026-07-11 web server room), and an intro to Burp Suite. Same approach as
the rest of the repo, methodology and the *why* over any single box, no flags or answers.

## Contents

- [web-server-attacks-2.md](web-server-attacks-2.md) *(Medium)* - Attacking IIS end to end: version fingerprinting from headers, 8.3 tilde short-name enumeration to leak hidden files, pulling WebDAV credentials from a backup directory, uploading an ASPX web shell over NTLM, the `SeImpersonatePrivilege` privesc path, the misconfiguration checklist (directory listing, web.config exposure, trace.axd, TRACE, privileged app pools), and automating the recon with Nmap NSE.
- [burp-suite-basics.md](burp-suite-basics.md) *(Easy)* - Intro to Burp Suite: proxying the browser with FoxyProxy, intercept vs logging, building a site map that surfaces a hidden endpoint, setting a scope to cut noise, trusting Burp's TLS certificate, and a reflected XSS that bypasses a client-side filter by editing the request in the proxy.

## Where these are published

Published in reader-friendly form on the blog at <https://barrytd.github.io/> under
**Labs**. The command reference lives at the repo root as
[`terminal-manual.md`](../../terminal-manual.md) and as the **/manual/** page on the blog.
