---
title: "Content Discovery - Manual, OSINT, and Gobuster"
date: 2026-07-11
difficulty: Easy
category: offensive
excerpt: "Finding the pages, files, and directories a site did not mean to expose, using conventional files, public OSINT, and automated brute forcing."
---

TryHackMe Easy offensive

# Content Discovery - Manual, OSINT, and Gobuster

Content is anything on a web server: pages, files, directories, admin panels, backups.
Content discovery is finding the parts that were never linked or meant to be public.
There are three ways to do it, and a real engagement uses all three.

## Manual discovery

Start with the files a server exposes by convention. They cost nothing and often hand
you the interesting paths directly.

- **robots.txt** lists paths the owner does not want crawlers indexing, which makes it a
  ready-made list of places worth looking. It is a guideline for bots, not a control, so
  those paths are usually still reachable.
- **sitemap.xml** lists pages the owner wants indexed, sometimes including staging pages,
  old content, or endpoints that are hard to reach by normal browsing.
- **HTTP headers** leak the stack. `curl http://TARGET -v` shows `Server` and
  `X-Powered-By`, which name the web server and framework.
- **Framework docs.** Once you know the framework, read its public documentation. It
  often lists the default admin path and default credentials. On this room that chain
  went straight from a header to `/thm-framework-login` with `admin` / `admin`.

## OSINT

These pull information the target has already put out in public.

- **Google dorking** uses search operators to surface indexed content: `site:` limits to
  a domain, `inurl:` and `intitle:` filter on the URL or title, `filetype:` finds
  specific file types.
- **Wappalyzer** identifies the technologies a site runs, often with versions, which
  feeds vulnerability lookups.
- **Wayback Machine** (web.archive.org) archives old snapshots, useful for pages that
  were removed but may still work, like old login forms or API endpoints.
- **GitHub** repos sometimes hold committed secrets. Check the commit history, not just
  current files, because secrets are often removed in a later commit but stay in history.
- **S3 buckets** follow the format `{name}.s3.amazonaws.com` and are frequently
  misconfigured to public. Try patterns like `company-assets` or `company-backup`.

## Automated discovery with Gobuster

Manual and OSINT only reach so far. Gobuster brute forces against a wordlist to find
what is not linked anywhere. It has three modes.

- **dir** brute forces directories and files: `gobuster dir -u http://TARGET -w WORDLIST`.
  Add `-x php,txt` to try extensions.
- **dns** brute forces subdomains through DNS: `gobuster dns -d example.thm -w WORDLIST`.
  Needs `-d` and `-w`.
- **vhost** brute forces virtual hosts by cycling the Host header, so it finds hosts not
  in public DNS: `gobuster vhost -u http://TARGET --domain example.thm -w WORDLIST
  --append-domain --exclude-length 250-320`.

Subdomains and vhosts matter because a vulnerability patched on the main site may still
be live on a forgotten one. `SecLists` at `/usr/share/wordlists/SecLists/` is the wordlist
collection to reach for.

## Takeaway

Run all three before touching exploitation. Manual checks give quick wins, OSINT surfaces
what the target already leaked, and Gobuster covers the breadth neither can. Everything
you find here, the directories, the admin panel, the subdomains, becomes the input for
the next stage of the test.
