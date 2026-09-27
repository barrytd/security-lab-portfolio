# Vulnerability Assessment Report: Metasploitable 2

**Target:** 192.168.56.103 (Metasploitable 2)
**Scanner:** Nessus Essentials
**Scan type:** Non-credentialed network scan, common ports (credentialed follow-up below)
**Date:** 2026-09-27
**Analyst:** Robert Perez
**Environment:** Isolated VirtualBox host-only lab network

---

## Summary for the asset owner

This host runs an operating system that stopped getting security updates in 2013. A non-credentialed scan found 61 issues, including 4 critical and 3 high. The fastest way in is a VNC remote desktop service whose password is set to the word "password", which hands an attacker full control of the machine with no skill required. The recommendation is to rebuild this host on a supported OS. Until that happens, isolate it on its own network segment and block the risky ports.

---

## Scope

- One host, 192.168.56.103, on an isolated lab network.
- Non-credentialed scan. That means Nessus looked from the outside with no login to the target, so this is the attacker's view, not the full internal view.
- A credentialed scan follow-up is included at the end for a fuller inside view.

## Findings by severity

| Severity | Count |
|---|---|
| Critical | 4 |
| High | 3 |
| Medium | several |
| Low | several |
| Info | many |
| **Total** | **61** |

## Top findings

| # | Finding | Severity | CVSS | Port | What it means | Fix |
|---|---|---|---|---|---|---|
| 1 | VNC Server 'password' Password | Critical | 10.0 | 5900 | Remote desktop protected by the password "password". Anyone on the network gets full control. | Set a strong password or turn off VNC. |
| 2 | Ubuntu Linux 8.04 End of Life | Critical | 10.0 | host | OS has had no security patches since 2013. | Rebuild the host on a supported OS. |
| 3 | SSL v2 and v3 Detection | Critical | 9.8 | multiple | Obsolete encryption that can be broken. | Disable SSLv2 and v3, use TLS 1.2 or higher. |
| 4 | NFS Shares World Readable | High | 7.5 | 2049 | File shares readable by anyone on the network. | Restrict NFS exports to specific hosts. |
| 5 | rlogin Service Detection | High | 7.5 | 513 | Plaintext remote login, no encryption. | Turn off rlogin, use SSH. |
| 6 | Samba Badlock | High | 7.5 | 445 | Man-in-the-middle flaw in Samba. Harder to exploit, needs the attacker already positioned in the traffic. | Patch Samba to a fixed version. |
| 7 | Unencrypted Telnet Server | Medium | 6.5 | 23 | Plaintext remote administration. | Turn off telnet, use SSH. |

## How the findings were prioritized

Three scores drive the order:

- **CVSS**: how severe the flaw is, 0 to 10. This never changes.
- **EPSS**: the chance the flaw gets exploited in the near future.
- **VPR**: Tenable's blended score that mixes severity with observed threat activity.

The rule is to fix first what is both severe and easy to exploit, not just the highest number.

Two notes from this scan:

- The VNC password and the end-of-life OS are the real priorities. Both score 10.0 and both are simple to abuse.
- Samba Badlock scores 7.5, but its detail page shows no known exploit and high attack complexity. It ranks below the easy wins even though the number looks high. Read the finding, do not triage on one number.

## Recommendations

**Immediate**

- Set a strong VNC password or disable VNC on port 5900.
- Restrict the world-readable NFS shares to known hosts.

**Short term**

- Replace the OS with a supported version.
- Turn off telnet and the r-services (rlogin, rsh, rexec). Use SSH only.
- Disable SSLv2 and v3 across services.

**If a fix cannot happen right away (compensating controls)**

- Move the host to its own isolated network segment.
- Firewall the risky ports so only trusted admin systems can reach them.
- Increase monitoring on the host.

## Credentialed follow-up

I ran the same scan again with SSH credentials so Nessus could log into the host. Authentication passed and the count rose from 61 to 91.

With a login, Nessus read patch levels from inside the host and found issues the outside scan missed:

- Bash Remote Code Execution (Shellshock), CVSS 9.8, EPSS 1.0.
- Weak Debian OpenSSH Keys in authorized_keys, CVSS 9.8.
- Canonical Ubuntu Linux missing patches, 229 grouped items.

Takeaway: the non-credentialed scan is the attacker's outside view. The credentialed scan reads what is installed and unpatched inside the host, so it is more complete with fewer false positives. Run credentialed scans when you have access to the host.
