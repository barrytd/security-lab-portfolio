# 2026-07-04 - TryHackMe Fundamentals and Terminal Reference

A batch of shorter, concept-first writeups from working through the easier TryHackMe
fundamentals rooms in one sitting, plus a command reference built from the same material.
These are lighter than the full boot-to-root labs elsewhere in this repo: they focus on
the methodology and the *why* rather than a single box's kill chain. Grouped here so the
easy-content catch-up lives in one place.

## Contents

- [reconnaissance-fundamentals.md](reconnaissance-fundamentals.md) *(Easy)* - Passive vs active recon and where the line sits: WHOIS/RDAP, DNS TXT leaks, certificate transparency, and Shodan on the passive side; ping/TTL, traceroute, and banner grabbing on the active side.
- [nmap-basic-port-scans.md](nmap-basic-port-scans.md) *(Easy)* - The three core scans that find running services: TCP connect, SYN, and UDP, how each works at the packet level, and when to reach for it.
- [nmap-advanced-port-scans.md](nmap-advanced-port-scans.md) *(Medium)* - Odd-flag stealth scans (null, FIN, xmas) against stateless vs stateful firewalls, the ACK scan for mapping what a firewall allows, and source-hiding with spoofing, decoys, and the idle scan.
- [cleartext-protocols.md](cleartext-protocols.md) *(Easy)* - Protocols and Servers: reading FTP, SMTP, POP3, and IMAP by hand with telnet/netcat, and why cleartext authentication is already-compromised authentication.
- [protocols-and-servers-2.md](protocols-and-servers-2.md) *(Medium)* - Protocols and Servers 2: sniffing, man-in-the-middle, and password attacks against cleartext services, mapped to CIA/DAD with the defenses that shut each one down.
- [terminal-manual.md](terminal-manual.md) - A tiered command reference (Linux basics, networking/recon, scanning/enumeration, passwords/exploitation). Also published as the interactive Manual page on the blog.

## Where these are published

The five room writeups are published in beginner-friendly form on the blog at
<https://barrytd.github.io/> under **Labs**, and the terminal manual as the interactive
**/manual/** page.

No flags, cracked values, or room answers, per the repo house style. Methodology only.
