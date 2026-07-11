---
title: "Walking An Application - Manual Web Review with Browser Dev Tools"
date: 2026-07-11
difficulty: Easy
category: offensive
excerpt: "A web app review using nothing but the browser. Page source, Inspector, Debugger, Network, and Storage, and why client-side controls are not security."
---

TryHackMe Easy offensive

# Walking An Application - Manual Web Review with Browser Dev Tools

Before any scanner or proxy, you can learn a lot about a web app with just the browser.
This room walks through the page source and the four dev tools panels that matter for
recon: Inspector, Debugger, Network, and Storage. The running theme is that anything the
server sends to your browser is yours to read and change.

## Page source

Right-click and View Page Source, or prefix the URL with `view-source:`. What to look
for:

- **HTML comments** (`<!-- -->`). Developers leave notes here that never render on the
  page, sometimes pointing at pages still under development.
- **Hidden links.** Anchor tags (`<a href=...>`) can point at pages not shown in the
  menu, like a staff-only area.
- **Directory listing.** If assets load from a folder like `/assets/`, browse to that
  folder directly. If listing is enabled, you see every file, including ones that were
  never meant to be public.
- **Framework and version.** A comment or asset path often names the framework and
  version. Compare it to the framework's current version. If the site is behind, the
  changelog for the newer version tells you what was fixed, which is a map to what is
  still broken on the old one.

That last point is the useful chain: an out-of-date framework plus its public changelog
tells you exactly what weakness to go looking for.

## Inspector

The Inspector shows the live DOM, not the original source, so it reflects changes made
by CSS and JavaScript. You can edit any element in place. A common demo is a paywall:
content hidden behind a floating box that is only hidden with CSS. Flip its
`display: block` to `display: none`, or just delete the element, and the content behind
it is right there. The lesson is that a client-side paywall hides content, it does not
protect it.

## Debugger

The Debugger (called Sources in Chrome) is for reading and pausing JavaScript. Minified
and obfuscated files can be reformatted with Pretty Print. The powerful part is
breakpoints: click a line number and the browser pauses execution there on the next
load. If a script removes something from the page, a breakpoint on that line stops it
from running, so whatever was going to be hidden stays visible.

## Network

The Network tab logs every request the page makes. Submit a form with it open and you
see the background AJAX request go out. Click the request to read its headers, cookies,
and the full server response. Requests you never see in the page are completely visible
here, which matters for understanding how an app talks to its backend.

## Storage

The Storage tab shows what the site keeps in your browser: local storage, session
storage, and cookies. Cookies are the interesting ones for a pentester, because they
carry session tokens. Check their security flags:

- **HttpOnly** stops JavaScript from reading the cookie, which protects the session if
  the site has an XSS bug. If this is `false`, the token is exposed to any script.
- **Secure** sends the cookie only over HTTPS.
- **SameSite** helps limit CSRF.

A session cookie without HttpOnly set is a finding worth reporting.

## Takeaway

Everything the server sends to the browser can be read and edited on the client side, so
none of it is a security control. Paywalls, hidden elements, and JavaScript that removes
content all fall to a few clicks in dev tools. The real controls have to live on the
server. Learning to read the source and the four dev tools panels is the cheapest recon
there is, and it comes before any heavier tooling.
