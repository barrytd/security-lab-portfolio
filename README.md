# Security Lab Portfolio

Entry-level security professional building hands-on offensive and defensive experience through documented labs, CTF challenges, and blue team investigations.

**[TryHackMe](https://tryhackme.com/p/bxrry)** · **[Portfolio Blog](https://barrytd.github.io)**

---

## ⚔️ Offensive Security

| Lab | Platform | Summary |
|---|---|---|
| [Guided Pentest: Infrastructure](labs/2026-05-22-tryhackme-guided-pentest-infrastructure/README.md) | TryHackMe | Full kill chain in one short room: nmap fingerprinted UnrealIRCd 3.2.8.1 on port 6667, searchsploit pointed at the CVE-2010-2075 backdoor, the Metasploit module landed a reverse shell, /etc/password.txt held the root password in plaintext, and SSH as root retrieved the flag. |
| [Guided Pentest: Web (RecruitX)](labs/2026-05-21-tryhackme-guided-pentest-web/README.md) | TryHackMe | Web app pentest against a fictional recruitment platform. Chained an IDOR on profile and API, a password-reset flow that returned the token in the response, and a file-upload extension blocklist that missed .phtml into a www-data reverse shell. |
| [Skynet](labs/2026-05-10-tryhackme-skynet/README.md) | TryHackMe | enum4linux to a valid user, anonymous SMB share leaking a custom wordlist, Hydra against SquirrelMail, SMB credentials disclosed by email, Cuppa CMS unauth RFI to www-data shell, tar wildcard injection in a root cron for root. |
| [Brooklyn Nine Nine](labs/2026-05-05-tryhackme-brooklyn-nine-nine/README.md) | TryHackMe | Two complete attack chains to the same root: anonymous FTP plus rockyou Hydra to jake plus sudo less escape, and steghide on a web image to holt plus sudo nano NOPASSWD escape. |
| [Ignite](labs/2026-05-01-tryhackme-ignite/README.md) | TryHackMe | Fuel CMS 1.4.1 unauth RCE (CVE-2018-16763) via create_function injection in the filter parameter, www-data shell, plaintext MySQL root password in database.php reused as system root. |
| [Mr Robot](labs/2026-05-01-tryhackme-mr-robot/README.md) | TryHackMe | robots.txt to a leaked wordlist, WordPress username enumeration plus Hydra brute force, theme-editor PHP reverse shell, cracked an unsalted MD5 on CrackStation, and SUID nmap !sh to root. |
| [Decryptify](labs/2026-04-29-tryhackme-decryptify/README.md) | TryHackMe | Forged invite codes by brute forcing a leaked seed constant, then padbuster against a date parameter to decrypt and re-encrypt commands for full RCE. |
| [Nessus](labs/2026-04-27-tryhackme-nessus/README.md) | TryHackMe | Configured Nessus Essentials, ran a Basic Network Scan and Web Application Tests scan, and triaged findings ranging from cleartext login.php to exposed .bak configs and missing X-Frame-Options. |
| [Overpass 2 - Hacked](labs/2026-04-23-tryhackme-overpass-2-hacked/README.md) | TryHackMe | PCAP forensics to recover a su password, cracked a deployed SSH backdoor's hash in hashcat, and .suid_bash -p to root. |
| [Overpass](labs/2026-04-22-tryhackme-overpass/README.md) | TryHackMe | Bypassed client-side auth, cracked an SSH key passphrase, and hijacked a root cron via writable /etc/hosts. |
| [Net Sec Challenge](labs/2026-04-15-tryhackme-net-sec-challenge/README.md) | TryHackMe | Network Security module capstone with Nmap, Telnet, and Hydra against six ports with a 0%-detection covert scan. |
| [Nmap Live Host Discovery](labs/2026-04-14-tryhackme-nmap-live-host-discovery/README.md) | TryHackMe | ARP, ICMP, and TCP/UDP ping-scan techniques and when each one is the right tool. |
| [HackPark](labs/2026-03-07-hackpark-blogengine-rce-scheduledtask-privesc/README.md) | TryHackMe | Hydra brute force, BlogEngine.NET RCE (CVE-2019-6714), scheduled-task SYSTEM privesc, done twice with Metasploit and manual. |
| [Steel Mountain](labs/2026-03-06-steel-mountain-hfs-rce-unquoted-service-path/README.md) | TryHackMe | Rejetto HFS RCE (CVE-2014-6287) and unquoted service path to SYSTEM, Metasploit and manual. |
| [Alfred](labs/2026-03-03-alfred-jenkins-rce-token-impersonation/README.md) | TryHackMe | Jenkins default creds to RCE, Nishang reverse shell, and SeImpersonatePrivilege token theft to SYSTEM. |
| [Linux PrivEsc](labs/2026-03-01-linux-privesc-tryhackme/README.md) | TryHackMe | 18 Linux privesc techniques including MySQL UDF, cron abuse, wildcard injection, and Dirty COW. |
| [VulnNet: Active](labs/2026-02-27-vulnnet-active-windows-privesc/README.md) | TryHackMe | Unauth Redis to Responder NTLM capture to cracked credentials to SMB share abuse to GodPotato to SYSTEM. |
| [Attacktive Directory](labs/2026-02-26-tryhackme-attacktive-directory/README.md) | TryHackMe | Full AD methodology with Kerberoasting, ASREPRoasting, BloodHound attack-path mapping. |
| [Active Directory - Full Domain Compromise](labs/2026-02-24-active-directory-full-domain-compromise/README.md) | Self-built | Built and attacked an AD lab: NTLM dump, Pass-the-Hash, PSExec to SYSTEM, krbtgt Golden Ticket. |
| [Kioptrix Level 2](labs/2026-02-22-kioptrix-level-1.1-web-to-root/README.md) | VulnHub | SQLi auth bypass to command injection to hardcoded creds to kernel privesc via sock_sendpage(). |
| [Basic Pentesting 1](labs/2026-02-21-basic-pentesting-1-wordpress-privesc/README.md) | VulnHub | WordPress credential attack to shell, then pkexec CVE-2021-4034 to root. |
| [Metasploitable 2 - Manual RCE](labs/2026-02-20-metasploitable-manual-rce-and-privesc/README.md) | VulnHub | UnrealIRCd RCE without Metasploit, sudo misconfig, credential harvesting. |
| [Metasploitable 2 - Multi-Vector](labs/2026-02-19-metasploitable-multi-vector-root/README.md) | VulnHub | Three independent vectors (vsftpd, Samba, Distcc) and SUID-nmap privesc. |
| [DVWA - Blind SQLi (High)](labs/2026-02-18-sqli-blind-high/README.md) | DVWA | Boolean-based blind SQLi extraction via Burp Intruder and response-length diffs. |
| [DVWA - SQLi, API & Sessions](labs/2026-02-17-sqli-api-session/README.md) | DVWA | UNION/boolean SQLi at elevated security, API v1/v2 exposure, predictable session IDs. |
| [DVWA - Foundational Vulns](labs/2026-02-16-foundational-vulnerabilities/README.md) | DVWA | OWASP Top 10 coverage: SQLi, XSS, CSRF, command injection, IDOR, LFI via php://filter. |

---

## 🛡️ Blue Team & Detection

| Lab | Platform | Summary |
|---|---|---|
| [Splunk 3 - BOTSv3](labs/2026-05-21-tryhackme-splunk-3/README.md) | TryHackMe | Hybrid-environment BOTSv3 investigation across AWS and endpoint telemetry: IAM enumeration and a public S3 bucket in CloudTrail, a leaked access key found in a public GitHub repo, browser-based Monero mining traced through performance counters, and a Taedonggang APT endpoint chain with a macro dropper, fake service account, and Base64 PowerShell C2. |
| [Splunk 2 - BOTSv2](labs/2026-05-12-tryhackme-splunk-2/README.md) | TryHackMe | Four-scenario BOTSv2 investigation as Alice Bluebird: insider-threat email exfil, web vulnerability scanner plus SQLi (UPDATEXML) and XSS, USB-delivered FruitFly/Quimitchin Perl malware with dynamic-DNS C2, and a Taedonggang APT chain with scheduled-task PowerShell Empire reading C2 config from a registry key. |
| [ItsyBitsy](labs/2026-05-10-tryhackme-itsybitsy/README.md) | TryHackMe | Hunted a bitsadmin user-agent in Kibana connection_logs and traced a HEAD request to pastebin.com/yTg0Ah6a, mapping the activity to MITRE ATT&CK T1197 (BITS Jobs) and T1105 (Ingress Tool Transfer). |
| [Introduction to SIEM](labs/2026-04-14-tryhackme-intro-to-siem/README.md) | TryHackMe | Triaged a cryptominer alert (cudominer.exe on HR_02), traced to a 4688 rule on *miner*, actioned as true positive. |
| [SOC Simulator - Phishing Analysis](labs/2026-03-25-tryhackme-soc-simulator-phishing-analysis/README.md) | TryHackMe | Five phishing alerts triaged in Splunk: 2 false positives, 3 true positives, 260 points and first place. |
| [Benign - LOLBIN Investigation](labs/2026-03-14-benign-lolbin-certutil-process-investigation/README.md) | TryHackMe | EventID 4688 hunt: imposter account, scheduled-task persistence, certutil.exe LOLBIN download. |
| [Investigating with Splunk](labs/2026-03-10-investigating-with-splunk-c2-backdoor-detection/README.md) | TryHackMe | Multi-host compromise, WMI backdoor creation, decoded a double-encoded PowerShell Empire C2 beacon. |

---

## 📘 Fundamentals & Reference

Shorter, concept-first writeups from the easier TryHackMe fundamentals rooms, grouped by date, alongside a command reference that spans every lab.

| Batch | Covers |
|---|---|
| [2026-07-11 TryHackMe Fundamentals](labs/2026-07-11-tryhackme-fundamentals/README.md) | Nmap post-scan detail (service/OS detection, NSE), walking an application with browser dev tools, content discovery (manual/OSINT/Gobuster), modern web stacks and their CVEs, and web server misconfigurations across Apache/Nginx/Node/Python. |
| [2026-07-04 TryHackMe Fundamentals](labs/2026-07-04-tryhackme-fundamentals/README.md) | Reconnaissance fundamentals, nmap basic and advanced port scans, and cleartext protocols (Protocols and Servers 1 and 2). |

The [Terminal Manual](terminal-manual.md) is a tiered command reference (Linux basics, networking and recon, scanning and enumeration, passwords and exploitation) that grew out of these rooms and spans the whole repo. It is also published as the interactive [Manual page](https://barrytd.github.io/manual/) on the blog.

---

## Lab → Skills Matrix

| Lab | Skills Demonstrated |
|---|---|
| Guided Pentest: Infrastructure | Full kill chain methodology (recon, exploit, post-exploit, privesc), Nmap service version detection, searchsploit version-to-CVE lookup, CVE-2010-2075 UnrealIRCd 3.2.8.1 backdoor (Metasploit + manual context), credential-at-rest discovery (/etc/password.txt), root SSH login as privesc, supply chain attack awareness |
| Guided Pentest: Web (RecruitX) | Web app pentest methodology, Nmap and Gobuster recon, IDOR (CWE-639) on profile and API endpoints, unauthenticated API enumeration, broken password reset (CWE-640 token-in-response), file upload extension blocklist bypass via .phtml (CWE-434), client-side accept-attribute bypass with DevTools, PHP web shell to netcat reverse shell, vulnerability chaining mindset |
| Skynet | enum4linux SID-to-username resolution, anonymous SMB enumeration, Hydra http-post-form against SquirrelMail, webmail-to-SMB credential pivot, Cuppa CMS RFI (Exploit-DB 25971), PHP reverse shell over RFI, tar wildcard injection (--checkpoint-action) via root cron |
| Brooklyn Nine Nine | Anonymous FTP enumeration, Hydra SSH brute force (rockyou), steghide extraction with weak passphrase, sudo shell escapes (less !sh and nano Execute Command), GTFOBins methodology, NOPASSWD audit |
| Ignite | Fuel CMS version disclosure, CVE-2018-16763 unauth RCE (create_function code injection), Exploit-DB 47138.py, reverse shell as www-data, plaintext credential discovery in framework config, password reuse privesc (MySQL root to system root) |
| Mr Robot | robots.txt disclosure, WordPress username enumeration, Hydra http-post-form brute force, theme-editor RCE (pentestmonkey PHP reverse shell), unsalted MD5 cracking (CrackStation), SUID nmap interactive-mode privesc |
| Decryptify | Predictable token brute force (mt_srand seed recovery), padding oracle attack (padbuster decrypt + forge), CBC bit-flipping, command injection via decrypted input |
| Nessus | Vulnerability scanner setup (Nessus Essentials), Basic Network Scan and Web App Tests templates, plugin triage, version fingerprinting |
| Overpass 2 - Hacked | PCAP forensics (Wireshark), reverse-shell payload recovery, offline cracking (John + hashcat mode 1710), SUID bash privesc |
| Overpass | Client-side auth bypass, SSH key cracking (ssh2john + John), cron hijacking, /etc/hosts abuse |
| Net Sec Challenge | Full-range port enumeration, banner grabbing with Telnet, Hydra FTP brute force, covert Nmap scanning |
| Nmap Live Host Discovery | ARP/ICMP/TCP/UDP host discovery, target spec expansion, privilege-driven scan behavior |
| HackPark | Hydra VIEWSTATE brute force, BlogEngine.NET RCE, scheduled-task privesc, manual Metasploit alternative |
| Steel Mountain | HFS CVE-2014-6287, unquoted service path abuse, msfvenom, Python HTTP delivery |
| Alfred | Jenkins abuse, PowerShell reverse shells (Nishang), Meterpreter, Incognito token impersonation |
| Linux PrivEsc | MySQL UDF, SUID/sudo/cron/NFS abuse, wildcard injection, Dirty COW (CVE-2016-5195) |
| VulnNet: Active | Redis abuse, Responder NTLMv2 capture, offline hash cracking, GodPotato, SMB share abuse |
| Attacktive Directory | Kerberoasting, ASREPRoasting, BloodHound, impacket toolkit |
| AD Full Domain Compromise | AD lab build, NTLM dump/crack, Pass-the-Hash, PSExec, krbtgt extraction, Golden Tickets |
| Kioptrix Level 2 | SQLi auth bypass, command injection, kernel privesc via sock_sendpage() |
| Basic Pentesting 1 | WordPress exploitation, pkexec CVE-2021-4034 compilation and exploitation |
| Metasploitable 2 (×2) | UnrealIRCd manual RCE, vsftpd/Samba/Distcc vectors, SUID nmap privesc |
| DVWA labs (×3) | Full OWASP Top 10: SQLi (UNION/blind), XSS, CSRF, LFI, command injection, IDOR, API/session flaws |
| Splunk 3 - BOTSv3 | Cloud and endpoint SIEM investigation, AWS CloudTrail analysis (IAM enumeration, PutBucketAcl / S3 public-access detection, access-key misuse), o365 audit logs, perfmon-based cryptomining detection, Symantec endpoint signatures, Sysmon process analysis, user-agent attribution, time-windowed osquery pivots, Base64 PowerShell C2 decoding |
| Splunk 2 - BOTSv2 | Multi-source SIEM pivoting (pan:traffic, stream:http/smtp/dns/ftp/tcp, osquery, Sysmon, WinRegistry), SPL chaining (stats / sort / dedup / table), Base64 / recursive-encoding decode with CyberChef, time-windowed DNS pivots for C2 discovery, VirusTotal metadata attribution, SSL issuer fingerprinting, scheduled-task PowerShell Empire detection, registry-stored C2 URL decoding |
| ItsyBitsy | Kibana / ELK Discover, anomalous user-agent hunting (bitsadmin), LOLBin and trusted-service abuse detection, MITRE ATT&CK T1197 / T1105 / T1071.001 mapping, Zeek uid pivot methodology |
| Intro to SIEM | Detection rule design, EventID 4688 analysis, alert triage (true vs false positive) |
| SOC Simulator | Splunk pivot between email/firewall logs, phishing indicator analysis, escalation decisions |
| Benign | SPL hunting, imposter account detection, LOLBIN analysis (certutil.exe), scheduled-task persistence |
| Investigating with Splunk | Sysmon/Windows event correlation, PowerShell Empire decoding, IOC defanging |

---

## Read These as Blog Posts

All of the labs above are also published as beginner-friendly, answer-free writeups on the companion site: **[barrytd.github.io](https://barrytd.github.io)**.
