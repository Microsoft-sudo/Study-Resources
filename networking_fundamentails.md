# 🌐 Networking Fundamentals — Complete In-Depth Guide
> **For Beginners | Single Read | With Examples, Diagrams & Real-World Context**

---

## 📌 Table of Contents
1. [What is a Network?](#1-what-is-a-network)
2. [Types of Networks](#2-types-of-networks)
3. [Network Topologies](#3-network-topologies)
4. [OSI Model — The 7 Layers](#4-osi-model--the-7-layers)
5. [TCP/IP Model](#5-tcpip-model)
6. [IP Addressing (IPv4)](#6-ip-addressing-ipv4)
7. [Subnetting & CIDR](#7-subnetting--cidr)
8. [IPv6](#8-ipv6)
9. [MAC Address](#9-mac-address)
10. [Protocols — The Complete Reference](#10-protocols--the-complete-reference)
11. [TCP vs UDP](#11-tcp-vs-udp)
12. [DNS — Domain Name System](#12-dns--domain-name-system)
13. [DHCP — Dynamic Host Configuration Protocol](#13-dhcp--dynamic-host-configuration-protocol)
14. [NAT — Network Address Translation](#14-nat--network-address-translation)
15. [Routing & Switching](#15-routing--switching)
16. [Firewalls, IDS & IPS](#16-firewalls-ids--ips)
17. [VPN — Virtual Private Network](#17-vpn--virtual-private-network)
18. [Wireless Networking (Wi-Fi)](#18-wireless-networking-wi-fi)
19. [Network Devices](#19-network-devices)
20. [Network Commands Cheat Sheet](#20-network-commands-cheat-sheet)
21. [Packet Flow — End to End](#21-packet-flow--end-to-end)
22. [Network Security Fundamentals](#22-network-security-fundamentals)
23. [Cloud Networking Basics](#23-cloud-networking-basics)
24. [Quick Reference Tables](#24-quick-reference-tables)

---

## 1. What is a Network?

A **network** is a collection of two or more devices (computers, phones, printers, servers) connected together to **share resources and communicate**.

```
Simple Home Network:
                        [Internet]
                             |
                         [Modem]
                             |
                         [Router]
                        /    |    \
                [PC]  [Laptop] [Phone]
```

### Why Networks Exist
- Share files and printers
- Access the internet
- Communication (email, video calls)
- Centralized data storage
- Remote access to systems

### Key Terminology

| Term | Meaning |
|------|---------|
| **Node** | Any device on a network (PC, phone, printer) |
| **Host** | A device that sends/receives data |
| **Server** | Provides services to other devices |
| **Client** | Requests services from a server |
| **Packet** | Small unit of data sent over a network |
| **Bandwidth** | Maximum data transfer rate (e.g., 100 Mbps) |
| **Latency** | Time taken for data to travel from A to B (ms) |
| **Throughput** | Actual data transfer rate achieved |
| **Protocol** | Set of rules for communication between devices |
| **Interface** | Physical or virtual network connection point (e.g., eth0, wlan0) |

---

## 2. Types of Networks

### By Size & Coverage

| Type | Full Name | Coverage | Example |
|------|-----------|----------|---------|
| **PAN** | Personal Area Network | ~10 meters | Bluetooth headphones to phone |
| **LAN** | Local Area Network | Building/campus | Office computers |
| **MAN** | Metropolitan Area Network | City-wide | City cable TV network |
| **WAN** | Wide Area Network | Country/global | The Internet |
| **WLAN** | Wireless LAN | Building (wireless) | Home Wi-Fi |
| **VPN** | Virtual Private Network | Any distance (virtual) | Secure remote work access |
| **SAN** | Storage Area Network | Data centers | High-speed disk storage |

### By Ownership

| Type | Description | Example |
|------|-------------|---------|
| **Private Network** | Owned and used by one organization | Company intranet |
| **Public Network** | Open to anyone | The Internet |
| **Extranet** | Private network extended to partners | Vendor portal |
| **Intranet** | Private internal web for a company | Company HR portal |

---

## 3. Network Topologies

**Topology** = the physical or logical arrangement of devices in a network.

### Bus Topology
```
[PC1]---[PC2]---[PC3]---[PC4]---[PC5]
         |_______Shared Cable_______|
```
- All devices share one cable
- ✅ Cheap, easy to set up
- ❌ One cable failure = entire network down
- ❌ Collisions when multiple devices transmit simultaneously

---

### Star Topology (Most Common Today)
```
        [PC1]
          |
[PC4]---[Switch]---[PC2]
          |
        [PC3]
```
- All devices connect to a central switch/hub
- ✅ One device failing doesn't affect others
- ✅ Easy to add/remove devices
- ❌ If the central switch fails, the whole network fails
- ✅ **Most home and office networks use this**

---

### Ring Topology
```
[PC1] → [PC2] → [PC3] → [PC4] → [PC1]
```
- Data travels in one direction around a ring
- ✅ No collisions (token-based access)
- ❌ One device failure can break the entire ring
- Used in: SONET/SDH fiber networks

---

### Mesh Topology
```
[PC1]---[PC2]
  |  \ /  |
  |   X   |
  |  / \  |
[PC3]---[PC4]
```
- Every device connects to every other device
- ✅ Extremely fault-tolerant
- ✅ Multiple paths for data
- ❌ Very expensive, complex wiring
- Used in: Military networks, internet backbone

---

### Hybrid Topology
A combination of two or more topologies (most real-world networks are hybrid).

```
Star (office) + Bus (connecting offices) = Hybrid
```

---

### Tree (Hierarchical) Topology
```
                [Core Switch]
               /              \
    [Dist Switch 1]      [Dist Switch 2]
     /         \             /         \
[Access SW] [Access SW] [Access SW] [Access SW]
   /|\           |           |          /|\
 PCs           PCs          PCs        PCs
```
- Used in large enterprise networks
- Three layers: Core → Distribution → Access

---

## 4. OSI Model — The 7 Layers

The **OSI (Open Systems Interconnection)** model is a conceptual framework that describes how data travels from one computer to another over a network.

> **Memory Aid:** "**P**lease **D**o **N**ot **T**hrow **S**ausage **P**izza **A**way"
> (Physical, Data Link, Network, Transport, Session, Presentation, Application)

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 7 — APPLICATION   │ HTTP, FTP, SMTP, DNS, SSH           │
├─────────────────────────────────────────────────────────────────┤
│  Layer 6 — PRESENTATION  │ SSL/TLS, JPEG, MPEG, encryption     │
├─────────────────────────────────────────────────────────────────┤
│  Layer 5 — SESSION       │ NetBIOS, RPC, session management     │
├─────────────────────────────────────────────────────────────────┤
│  Layer 4 — TRANSPORT     │ TCP, UDP — ports, segmentation       │
├─────────────────────────────────────────────────────────────────┤
│  Layer 3 — NETWORK       │ IP, ICMP, routing — logical address  │
├─────────────────────────────────────────────────────────────────┤
│  Layer 2 — DATA LINK     │ Ethernet, ARP, MAC — physical addr   │
├─────────────────────────────────────────────────────────────────┤
│  Layer 1 — PHYSICAL      │ Cables, radio waves, bits            │
└─────────────────────────────────────────────────────────────────┘
```

### Data Unit Names Per Layer

| Layer | Data Unit Name |
|-------|---------------|
| Layer 7–5 | **Data** |
| Layer 4 | **Segment** (TCP) / **Datagram** (UDP) |
| Layer 3 | **Packet** |
| Layer 2 | **Frame** |
| Layer 1 | **Bits** |

---

### Layer-by-Layer Deep Dive

#### Layer 1 — Physical
**What it does:** Transmits raw bits (0s and 1s) over a physical medium.

- Medium types: copper cable (electrical), fiber optic (light), radio waves (wireless)
- Devices: Hubs, repeaters, cables, NICs (Network Interface Cards)
- Specifications: Speed (Mbps/Gbps), connector types, voltage levels

```
Bit transmission: 01001000 01100101 01101100 → through cable → received
```

**Cable Types:**

| Cable | Max Speed | Max Distance | Use |
|-------|-----------|-------------|-----|
| Cat5e | 1 Gbps | 100m | Home networks |
| Cat6 | 10 Gbps | 55m | Office networks |
| Cat6a | 10 Gbps | 100m | Data centers |
| Fiber (SM) | 100 Gbps+ | 40km+ | ISP backbone |
| Fiber (MM) | 10 Gbps | 300m | Data centers |

---

#### Layer 2 — Data Link
**What it does:** Node-to-node delivery within the same network. Uses **MAC addresses**.

- Divided into two sub-layers:
  - **MAC** (Media Access Control) — hardware addressing, access to medium
  - **LLC** (Logical Link Control) — flow control, error checking
- Devices: Switches, bridges
- Protocols: **Ethernet**, Wi-Fi (802.11), ARP

**Frame Structure (Ethernet):**
```
┌──────────┬────────┬──────────┬──────────┬──────────┬─────┐
│Preamble  │ Dest   │  Source  │  Type/   │  Data    │ FCS │
│(8 bytes) │  MAC   │   MAC    │  Length  │(46-1500B)│(4B) │
│          │(6 bytes│(6 bytes) │  (2B)    │          │     │
└──────────┴────────┴──────────┴──────────┴──────────┴─────┘
```

**ARP (Address Resolution Protocol):**
- Resolves IP addresses → MAC addresses on local network
- "Who has IP 192.168.1.1? Tell 192.168.1.10"
- Broadcasts to all, the owner replies with its MAC

```
ARP Request:  [Broadcast] "Who has 192.168.1.1?"
ARP Reply:    [Unicast]   "I have it! My MAC is AA:BB:CC:DD:EE:FF"
```

---

#### Layer 3 — Network
**What it does:** Logical addressing and routing — moves packets between different networks.

- Devices: Routers
- Protocols: **IP** (IPv4/IPv6), **ICMP**, OSPF, BGP
- Key concept: **IP address** — logical address assigned to each device

**IP Packet Structure:**
```
┌──────────┬─────────┬───────┬──────────┬───────────┬──────────┐
│ Version  │  Header │  TTL  │ Protocol │  Source   │  Dest    │
│(IPv4=4)  │ Length  │       │ (TCP=6)  │    IP     │   IP     │
└──────────┴─────────┴───────┴──────────┴───────────┴──────────┘
```

**TTL (Time to Live):**
- Decremented by 1 at each router hop
- When TTL = 0, packet is dropped (prevents infinite loops)
- Windows default TTL: 128 | Linux default TTL: 64

**ICMP (Internet Control Message Protocol):**
- Used for network diagnostics
- `ping` uses ICMP Echo Request / Echo Reply
- `traceroute` uses ICMP Time Exceeded

---

#### Layer 4 — Transport
**What it does:** End-to-end communication, reliability, flow control, ports.

- Protocols: **TCP** (reliable) and **UDP** (fast, unreliable)
- **Ports** identify specific applications/services

**Port Ranges:**
```
0 – 1023      → Well-known ports (HTTP=80, SSH=22, FTP=21)
1024 – 49151  → Registered ports (application-specific)
49152 – 65535 → Dynamic/ephemeral ports (temporary client ports)
```

---

#### Layer 5 — Session
**What it does:** Manages sessions (connections) between applications.

- Establishes, maintains, and terminates sessions
- Handles synchronization and checkpointing
- Protocols: NetBIOS, RPC, PPTP
- Example: When you log into a website, the session layer manages your login session

---

#### Layer 6 — Presentation
**What it does:** Data translation, encryption, and compression.

- Converts data formats (e.g., EBCDIC → ASCII)
- **Encryption/Decryption:** SSL/TLS operates here
- **Compression:** JPEG, MP3, MPEG
- Example: When you visit HTTPS, this layer encrypts/decrypts the data

---

#### Layer 7 — Application
**What it does:** Interface between the network and end-user applications.

- Protocols: HTTP, HTTPS, FTP, SMTP, DNS, SSH, Telnet
- This is what users interact with directly
- Your browser, email client, file transfer apps all work at this layer

---

### OSI Model — Encapsulation & Decapsulation

When you send data, each layer **adds a header** (encapsulation):
```
Application Data → [App Header][Data]
Transport Layer  → [TCP Header][App Header][Data]   (Segment)
Network Layer    → [IP Header][TCP Header][Data]    (Packet)
Data Link Layer  → [ETH Header][IP Header][TCP][Data][ETH Trailer] (Frame)
Physical Layer   → 010110010100110... (Bits)
```

The receiver **removes headers** at each layer (decapsulation) — the reverse process.

---

## 5. TCP/IP Model

The **TCP/IP model** is the practical model used on the internet (simpler than OSI).

```
┌─────────────────────────────────────────────────┐
│   TCP/IP Layer          │   OSI Equivalent       │
├─────────────────────────────────────────────────┤
│  Application            │   Layers 5, 6, 7       │
├─────────────────────────────────────────────────┤
│  Transport              │   Layer 4              │
├─────────────────────────────────────────────────┤
│  Internet               │   Layer 3              │
├─────────────────────────────────────────────────┤
│  Network Access (Link)  │   Layers 1, 2          │
└─────────────────────────────────────────────────┘
```

---

## 6. IP Addressing (IPv4)

An **IPv4 address** is a 32-bit number written as 4 octets separated by dots.

```
192    .   168   .    1    .    1
 ↑           ↑         ↑        ↑
8 bits    8 bits    8 bits   8 bits
(0-255)  (0-255)  (0-255)  (0-255)

Binary: 11000000.10101000.00000001.00000001
```

### IP Address Classes (Classful — Legacy but important to know)

| Class | Range | Default Subnet Mask | Use |
|-------|-------|--------------------|----|
| **A** | 1.0.0.0 – 126.255.255.255 | /8 (255.0.0.0) | Large organizations |
| **B** | 128.0.0.0 – 191.255.255.255 | /16 (255.255.0.0) | Medium organizations |
| **C** | 192.0.0.0 – 223.255.255.255 | /24 (255.255.255.0) | Small networks |
| **D** | 224.0.0.0 – 239.255.255.255 | N/A | Multicast |
| **E** | 240.0.0.0 – 255.255.255.255 | N/A | Reserved/Research |

### Private IP Ranges (RFC 1918)
These are NOT routable on the internet — used inside private networks:

```
Class A Private:  10.0.0.0     –  10.255.255.255   (10.0.0.0/8)
Class B Private:  172.16.0.0   –  172.31.255.255   (172.16.0.0/12)
Class C Private:  192.168.0.0  –  192.168.255.255  (192.168.0.0/16)
```

### Special IP Addresses

| Address | Purpose |
|---------|---------|
| `127.0.0.1` | Loopback (localhost) — refers to your own machine |
| `0.0.0.0` | Unspecified / default route (all networks) |
| `255.255.255.255` | Limited broadcast (all hosts on local network) |
| `169.254.x.x` | APIPA — auto-assigned when DHCP fails |
| `x.x.x.0` | Network address (identifies the network) |
| `x.x.x.255` | Broadcast address (sends to all hosts in subnet) |

---

## 7. Subnetting & CIDR

**Subnetting** = dividing a large network into smaller sub-networks.

**Why subnet?**
- Reduce broadcast traffic
- Improve security (isolate departments)
- More efficient IP use

### Subnet Mask
A 32-bit number that separates the **network portion** from the **host portion** of an IP.

```
IP Address:    192.168.1.100
Subnet Mask:   255.255.255.0

Binary IP:     11000000.10101000.00000001.01100100
Binary Mask:   11111111.11111111.11111111.00000000
                  ↑ Network Part ↑          ↑Host↑

Network:    192.168.1.0
Host part:  .100
Broadcast:  192.168.1.255
```

### CIDR Notation (Classless Inter-Domain Routing)

CIDR uses a `/` followed by the number of network bits.

```
192.168.1.0/24  means:  subnet mask has 24 ones = 255.255.255.0
192.168.1.0/16  means:  subnet mask has 16 ones = 255.255.0.0
192.168.1.0/8   means:  subnet mask has 8 ones  = 255.0.0.0
```

### CIDR Quick Reference Table

| CIDR | Subnet Mask | # of Hosts | # of Usable Hosts |
|------|------------|-----------|------------------|
| /8   | 255.0.0.0 | 16,777,216 | 16,777,214 |
| /16  | 255.255.0.0 | 65,536 | 65,534 |
| /24  | 255.255.255.0 | 256 | 254 |
| /25  | 255.255.255.128 | 128 | 126 |
| /26  | 255.255.255.192 | 64 | 62 |
| /27  | 255.255.255.224 | 32 | 30 |
| /28  | 255.255.255.240 | 16 | 14 |
| /29  | 255.255.255.248 | 8 | 6 |
| /30  | 255.255.255.252 | 4 | 2 |
| /32  | 255.255.255.255 | 1 | 1 (host route) |

> **Usable Hosts = Total Hosts − 2** (subtract network address and broadcast address)

### Subnetting Example

**Task:** Divide 192.168.1.0/24 into 4 equal subnets.

```
Original: 192.168.1.0/24 → 256 addresses

Borrow 2 bits for subnets (2² = 4 subnets)
New prefix: /24 + 2 = /26

Subnet 1: 192.168.1.0/26   → 192.168.1.0   – 192.168.1.63
Subnet 2: 192.168.1.64/26  → 192.168.1.64  – 192.168.1.127
Subnet 3: 192.168.1.128/26 → 192.168.1.128 – 192.168.1.191
Subnet 4: 192.168.1.192/26 → 192.168.1.192 – 192.168.1.255

Each subnet has 64 addresses, 62 usable hosts
```

---

## 8. IPv6

IPv4 is running out of addresses (~4.3 billion). **IPv6** provides 340 undecillion addresses.

### IPv6 Format
- 128-bit address, written as 8 groups of 4 hex digits separated by colons

```
Full:        2001:0db8:0000:0000:0000:ff00:0042:8329
Compressed:  2001:db8::ff00:42:8329
             (consecutive zeros replaced by ::, leading zeros dropped)
```

### IPv6 Address Types

| Type | Example | Description |
|------|---------|-------------|
| **Unicast** | 2001:db8::1 | One-to-one |
| **Multicast** | ff02::1 | One-to-many |
| **Anycast** | Same as unicast format | One-to-nearest |
| **Link-Local** | fe80::/10 | Local network only (like APIPA) |
| **Loopback** | ::1 | Equivalent to 127.0.0.1 |
| **Global Unicast** | 2000::/3 | Routable on internet |

### IPv4 vs IPv6

| Feature | IPv4 | IPv6 |
|---------|------|------|
| Address size | 32-bit | 128-bit |
| Total addresses | ~4.3 billion | 340 undecillion |
| Format | Decimal (192.168.1.1) | Hex (2001:db8::1) |
| Header size | 20 bytes (min) | 40 bytes (fixed) |
| NAT needed? | Yes (address shortage) | No |
| Built-in security | Optional (IPSec) | Mandatory (IPSec) |
| Broadcast | Yes | No (uses multicast) |
| DHCP | Optional | Uses SLAAC (auto-config) |

---

## 9. MAC Address

A **MAC (Media Access Control) address** is a unique hardware identifier assigned to every NIC (Network Interface Card).

```
Format:  AA:BB:CC:DD:EE:FF  (6 bytes = 48 bits, written in hex)
Example: 00:1A:2B:3C:4D:5E

First 3 bytes: OUI (Organizationally Unique Identifier) → Manufacturer
Last 3 bytes:  Device Identifier → Unique per device
```

### MAC Address Types

| Type | Example | Description |
|------|---------|-------------|
| **Unicast** | 00:1A:2B:3C:4D:5E | Specific device |
| **Multicast** | 01:00:5E:xx:xx:xx | Group of devices |
| **Broadcast** | FF:FF:FF:FF:FF:FF | All devices on LAN |

### MAC vs IP Address

| Feature | MAC Address | IP Address |
|---------|------------|-----------|
| Layer | Layer 2 (Data Link) | Layer 3 (Network) |
| Scope | Local network only | Global (internet) |
| Assigned by | Manufacturer | Admin/DHCP |
| Permanent? | Usually (can be spoofed) | Changes (DHCP) |
| Purpose | Node-to-node delivery | End-to-end routing |

> **MAC Spoofing:** An attacker can change their MAC address to impersonate another device. `ifconfig eth0 hw ether AA:BB:CC:DD:EE:FF`

---

## 10. Protocols — The Complete Reference

### Application Layer Protocols

#### HTTP / HTTPS
```
HTTP  = HyperText Transfer Protocol  (Port 80)  — Plaintext
HTTPS = HTTP Secure                   (Port 443) — Encrypted (TLS)

HTTP Request:
  GET /index.html HTTP/1.1
  Host: www.example.com

HTTP Response:
  HTTP/1.1 200 OK
  Content-Type: text/html
  [HTML content]

HTTP Methods:
  GET     → Retrieve data
  POST    → Submit data
  PUT     → Update/replace resource
  DELETE  → Delete resource
  HEAD    → Get headers only
  PATCH   → Partial update

HTTP Status Codes:
  2xx Success:   200 OK, 201 Created, 204 No Content
  3xx Redirect:  301 Moved Permanently, 302 Found
  4xx Client:    400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found
  5xx Server:    500 Internal Server Error, 502 Bad Gateway, 503 Unavailable
```

#### FTP (File Transfer Protocol) — Port 20/21
```
Port 21: Control (commands)
Port 20: Data (file transfer)

Modes:
  Active:  Server initiates data connection back to client
  Passive: Client initiates both connections (better with firewalls)

Commands:
  USER, PASS → Login
  LIST       → List directory
  GET/RETR   → Download file
  PUT/STOR   → Upload file
  QUIT       → Disconnect

⚠️ FTP sends credentials in PLAINTEXT → use SFTP or FTPS instead
```

#### SSH (Secure Shell) — Port 22
```
SSH replaces Telnet with encryption.

Features:
  - Encrypted remote terminal access
  - Secure file transfer (SCP, SFTP)
  - Port forwarding / tunneling
  - Public key authentication

Connection: ssh username@192.168.1.1
Key-based:  ssh -i private_key.pem user@server

SSH uses asymmetric encryption for key exchange,
then symmetric encryption for the session.
```

#### Telnet — Port 23
```
⚠️ INSECURE — All data including passwords transmitted in PLAINTEXT
Still found on old routers, switches, embedded devices
Use SSH instead!

telnet 192.168.1.1
```

#### SMTP / POP3 / IMAP — Email Protocols
```
SMTP (Simple Mail Transfer Protocol) — Port 25, 465 (SSL), 587 (TLS)
  → SENDING emails (Mail Transfer Agent)

POP3 (Post Office Protocol v3) — Port 110, 995 (SSL)
  → RECEIVING emails (downloads and deletes from server)

IMAP (Internet Message Access Protocol) — Port 143, 993 (SSL)
  → RECEIVING emails (syncs with server, keeps on server)

Email flow:
Sender → [SMTP] → Mail Server → [SMTP] → Recipient's Mail Server
                                               ↓
                                Recipient ← [IMAP/POP3]
```

#### DNS — Port 53 (UDP/TCP)
*(See full DNS section below)*

#### DHCP — Port 67/68 (UDP)
*(See full DHCP section below)*

#### SNMP (Simple Network Management Protocol) — Port 161/162
```
Used for monitoring and managing network devices (routers, switches, servers)

Versions:
  SNMPv1 — Community strings in plaintext (public/private) — INSECURE
  SNMPv2c — Still plaintext — INSECURE
  SNMPv3 — Encryption + authentication — SECURE

Community Strings:
  "public" → Read-only access
  "private" → Read-write access

MIB (Management Information Base):
  Database of device information (CPU, memory, interfaces, etc.)

OID (Object Identifier):
  Unique ID for each piece of manageable info
  Example: 1.3.6.1.2.1.1.5.0 = System hostname

Security issue: Default "public" community = attacker can enumerate device!
```

#### NTP (Network Time Protocol) — Port 123
```
Synchronizes clocks across all network devices.
Critical for logs, authentication (Kerberos requires < 5 min difference), SSL certs

Stratum levels:
  Stratum 0 → Atomic clocks, GPS (reference clocks)
  Stratum 1 → Servers directly connected to Stratum 0
  Stratum 2 → Synced from Stratum 1
  ...

Attack: NTP amplification — small request, huge response → DDoS
```

#### RDP (Remote Desktop Protocol) — Port 3389
```
Microsoft protocol for remote graphical desktop access.
Used for: Remote administration, technical support

Security risks:
  - BlueKeep (CVE-2019-0708) — unauthenticated RCE
  - Brute force attacks
  - Man-in-the-Middle

Best practice: Use NLA + VPN + strong passwords + MFA
```

#### SMB (Server Message Block) — Port 445
```
Windows file/printer sharing protocol

SMB Versions:
  SMBv1 → Vulnerable to EternalBlue (MS17-010) — DISABLE!
  SMBv2 → Windows Vista+
  SMBv3 → Windows 8/2012+ with encryption

UNC Path: \\server\share\file.txt

Commands:
  net share          → list shares
  net use Z: \\server\share   → map share as drive Z
```

---

## 11. TCP vs UDP

### TCP (Transmission Control Protocol)
**Reliable, ordered, connection-oriented**

#### Three-Way Handshake (Connection Establishment)
```
Client                    Server
  |                          |
  |——— SYN (seq=100) ———→    |   "Can we connect?"
  |                          |
  |  ←—— SYN-ACK ————————   |   "Yes! (seq=200, ack=101)"
  |                          |
  |——— ACK (ack=201) ———→    |   "Great, connected!"
  |                          |
  [Data transfer begins]
```

#### Four-Way Handshake (Connection Termination)
```
Client                    Server
  |——— FIN ———————————→     |   "I'm done sending"
  |  ←—— ACK —————————      |   "OK, noted"
  |  ←—— FIN —————————      |   "I'm done too"
  |——— ACK ———————————→     |   "OK, closing"
  [Connection closed]
```

#### TCP Header
```
┌────────────┬───────────┬────────────────────────────────┐
│ Source Port│ Dest Port │  Sequence Number (32 bits)     │
├────────────┴───────────┴────────────────────────────────┤
│ Acknowledgment Number (32 bits)                         │
├─────────┬──────────┬───────────────────────────────────┤
│ Offset  │ Flags    │  Window Size                      │
│         │SYN ACK   │                                   │
│         │FIN RST   │                                   │
├─────────┴──────────┴───────────────────────────────────┤
│ Checksum          │  Urgent Pointer                     │
└───────────────────┴─────────────────────────────────────┘
```

**TCP Flags:**
```
SYN  → Synchronize (initiate connection)
ACK  → Acknowledgment (confirm receipt)
FIN  → Finish (close connection gracefully)
RST  → Reset (force close connection)
PSH  → Push (send data immediately)
URG  → Urgent (priority data)
```

### UDP (User Datagram Protocol)
**Fast, connectionless, unreliable**

```
UDP Header (only 8 bytes!):
┌────────────┬──────────┬──────────┬──────────┐
│ Source Port│ Dest Port│  Length  │ Checksum │
└────────────┴──────────┴──────────┴──────────┘
```

### TCP vs UDP Comparison

| Feature | TCP | UDP |
|---------|-----|-----|
| Connection | Connection-oriented | Connectionless |
| Reliability | Guaranteed delivery | No guarantee |
| Order | Data arrives in order | May arrive out of order |
| Speed | Slower (overhead) | Faster |
| Error checking | Yes (retransmit lost) | Basic checksum only |
| Header size | 20–60 bytes | 8 bytes |
| Flow control | Yes | No |
| Use cases | HTTP, SSH, FTP, email | DNS, video streaming, VoIP, gaming |

### When to Use Which?
```
Use TCP when:     Use UDP when:
─────────────     ────────────
Data accuracy     Speed matters
is critical       Loss is acceptable
File transfer     Real-time streaming
Email             DNS queries
Web browsing      Video calls
                  Online gaming
```

---

## 12. DNS — Domain Name System

**DNS** translates human-readable domain names into IP addresses.

```
You type:    www.google.com
DNS resolves: 142.250.195.68
Browser connects to: 142.250.195.68
```

Without DNS, you'd have to memorize IP addresses for every website!

### DNS Hierarchy
```
                           . (Root)
                          / | \
                        .com .org .net .in (TLDs)
                        /
                  google.com (Authoritative)
                  /    \
            www.google  mail.google (Subdomains)
```

### DNS Record Types

| Record | Purpose | Example |
|--------|---------|---------|
| **A** | Domain → IPv4 address | `google.com → 142.250.195.68` |
| **AAAA** | Domain → IPv6 address | `google.com → 2607:f8b0::200e` |
| **CNAME** | Alias for another domain | `www.google.com → google.com` |
| **MX** | Mail server for domain | `google.com → smtp.google.com` |
| **NS** | Nameserver for domain | `google.com → ns1.google.com` |
| **TXT** | Text info (SPF, DKIM, verification) | `v=spf1 include:google.com ~all` |
| **PTR** | IP → Domain (reverse DNS) | `142.250.195.68 → google.com` |
| **SOA** | Start of Authority (zone info) | Serial, refresh, retry, expire |
| **SRV** | Service location | `_sip._tcp.example.com` |

### DNS Resolution Process (Step by Step)

```
You type: www.example.com

Step 1: Check local DNS cache
        → Not found

Step 2: Query Recursive Resolver (your ISP/8.8.8.8)
        → "What is www.example.com?"

Step 3: Resolver queries Root Server (.)
        → "I don't know, ask .com TLD: 192.5.6.30"

Step 4: Resolver queries .com TLD Server
        → "I don't know, ask example.com NS: ns1.example.com"

Step 5: Resolver queries Authoritative NS (ns1.example.com)
        → "www.example.com = 93.184.216.34"

Step 6: Resolver caches answer and returns to you
        → Browser connects to 93.184.216.34
```

### DNS Commands
```bash
# Basic lookup
nslookup google.com
dig google.com

# Specific record type
dig google.com MX        # Mail servers
dig google.com NS        # Name servers
dig -x 8.8.8.8           # Reverse DNS lookup

# Query specific DNS server
dig @8.8.8.8 google.com

# Zone transfer (security test)
dig axfr @ns1.target.com target.com

# Flush DNS cache (Windows)
ipconfig /flushdns

# Flush DNS cache (Linux)
systemctl restart systemd-resolved
```

### DNS Security Issues

| Attack | Description |
|--------|-------------|
| **DNS Spoofing/Poisoning** | Inject false DNS entries → redirect to malicious site |
| **Zone Transfer** | Dump all DNS records if misconfigured → reveals internal structure |
| **DNS Amplification** | Small query → large response → DDoS amplification |
| **DNS Tunneling** | Encode data in DNS queries → bypass firewall |
| **DNS Hijacking** | Redirect DNS queries to attacker-controlled server |

---

## 13. DHCP — Dynamic Host Configuration Protocol

**DHCP** automatically assigns IP addresses and network settings to devices.

```
Without DHCP: You manually type IP, subnet, gateway, DNS on every device
With DHCP:    Plug in → automatically gets all settings
```

### DHCP DORA Process

```
Client                           DHCP Server
  |                                  |
  |——— DISCOVER (broadcast) ———→     |   "Anyone have an IP for me?"
  |                                  |
  | ←—— OFFER ——————————————         |   "I offer you 192.168.1.100"
  |                                  |
  |——— REQUEST (broadcast) ——→       |   "I'll take 192.168.1.100"
  |                                  |
  | ←—— ACK —————————————           |   "Confirmed! Use it for 24hrs"
  |                                  |
  [IP assigned: 192.168.1.100]
```

**D**iscover → **O**ffer → **R**equest → **A**cknowledge = **DORA**

### DHCP Lease Information
DHCP provides more than just an IP:
```
IP Address:         192.168.1.100
Subnet Mask:        255.255.255.0
Default Gateway:    192.168.1.1      (Router IP)
DNS Server:         8.8.8.8, 8.8.4.4
Lease Time:         86400 seconds (24 hours)
```

### DHCP Attack — Rogue DHCP Server
```
Attacker sets up their own DHCP server.
When victims ask for an IP, attacker's server responds first.
Attacker sets himself as the gateway → all traffic flows through attacker!
This is how DHCP-based Man-in-the-Middle attacks work.
```

---

## 14. NAT — Network Address Translation

**NAT** allows many devices with private IPs to share a single public IP.

```
Private network              Internet
                          
[192.168.1.10]    ↗          
[192.168.1.11] →  [Router]  ←→  Internet
[192.168.1.12]    ↘          (Public IP: 203.0.113.1)
[192.168.1.13]                
```

### How NAT Works
```
Internal device  192.168.1.10:5000  wants to visit  8.8.8.8:53

NAT Table entry:
  Internal IP:Port    →    Public IP:Port     →    Destination
  192.168.1.10:5000        203.0.113.1:40000       8.8.8.8:53

Outgoing: Replace 192.168.1.10:5000 with 203.0.113.1:40000
Incoming: Replace 203.0.113.1:40000 back with 192.168.1.10:5000
```

### NAT Types

| Type | Description |
|------|-------------|
| **Static NAT** | One private IP ↔ One public IP (1:1 mapping) |
| **Dynamic NAT** | Pool of public IPs shared among private IPs |
| **PAT (NAT Overload)** | Many private IPs → One public IP (uses port numbers) |
| **Port Forwarding** | Route external traffic on a specific port to internal host |

### Port Forwarding Example
```
External: 203.0.113.1:80   →   Internal: 192.168.1.100:80  (web server)
External: 203.0.113.1:22   →   Internal: 192.168.1.50:22   (SSH server)
External: 203.0.113.1:3389 →   Internal: 192.168.1.20:3389 (RDP server)
```

---

## 15. Routing & Switching

### Switching (Layer 2)

A **switch** forwards frames within a LAN using MAC addresses.

```
Switch MAC Address Table (CAM Table):
Port 1 → MAC: AA:BB:CC:DD:EE:01  (PC1)
Port 2 → MAC: AA:BB:CC:DD:EE:02  (PC2)
Port 3 → MAC: AA:BB:CC:DD:EE:03  (PC3)

When PC1 sends data to PC3:
  Switch looks up PC3's MAC → Port 3
  Forwards ONLY to Port 3 (not broadcast to all ports)
```

**Switch vs Hub:**
```
Hub:    Receives a frame → broadcasts to ALL ports (dumb)
Switch: Receives a frame → forwards to SPECIFIC port only (smart)

Hub = like shouting in a room
Switch = like whispering to a specific person
```

**VLANs (Virtual LANs):**
- Logically divide a physical switch into multiple isolated networks
- VLAN 10 = Finance dept, VLAN 20 = HR dept, VLAN 30 = IT dept
- Traffic can't cross VLANs without a router (or Layer 3 switch)

```
Physical switch split into virtual networks:
[Port 1,2,3]  → VLAN 10 (Finance)     [Isolated!]
[Port 4,5,6]  → VLAN 20 (HR)          [Isolated!]
[Port 7,8,9]  → VLAN 30 (IT)          [Isolated!]
```

**Spanning Tree Protocol (STP):**
- Prevents switching loops (packets looping forever)
- Blocks redundant paths, enables them if primary fails
- Improved versions: RSTP, MSTP

---

### Routing (Layer 3)

A **router** forwards packets between different networks using IP addresses.

```
Network A (192.168.1.0/24) ←→ [Router] ←→ Network B (192.168.2.0/24)
```

**Routing Table:**
```
Destination      Subnet Mask       Gateway         Interface
0.0.0.0          0.0.0.0           203.0.113.254   WAN (default route)
192.168.1.0      255.255.255.0     0.0.0.0         eth0 (directly connected)
192.168.2.0      255.255.255.0     192.168.1.1     eth0 (static route)
10.0.0.0         255.0.0.0         203.0.113.1     WAN
```

**Default Gateway:** The router that handles traffic for unknown destinations (the "exit door" of the network).

### Routing Protocols

| Protocol | Type | Algorithm | Use Case |
|----------|------|-----------|---------|
| **RIP** | Distance Vector | Hop count (max 15) | Small networks |
| **OSPF** | Link State | Dijkstra (shortest path) | Enterprise LANs |
| **EIGRP** | Hybrid | Diffusing Update Algorithm | Cisco networks |
| **BGP** | Path Vector | Policy-based | Internet backbone |
| **IS-IS** | Link State | Dijkstra | ISP networks |

### Static vs Dynamic Routing

```
Static Routing:
  Manually configured routes — never changes
  + Simple, predictable, secure
  - Doesn't adapt to failures, manual work for large networks

Dynamic Routing:
  Routers learn routes automatically via protocols (OSPF, BGP)
  + Adapts to failures, scalable
  - More complex, some security risk
```

### Default Route
```
ip route 0.0.0.0 0.0.0.0 192.168.1.1
               ↑
        "Send everything I don't know where to route → to 192.168.1.1"
```

---

## 16. Firewalls, IDS & IPS

### Firewall
A firewall **filters network traffic** based on rules (allow/deny).

```
Internet ←→ [Firewall] ←→ Internal Network
```

**Firewall Types:**

| Type | How it works | Example |
|------|-------------|---------|
| **Packet Filter** | Filters by IP, port, protocol | iptables basic rules |
| **Stateful** | Tracks connection state | Most modern firewalls |
| **Application/Proxy** | Inspects application data | Web proxy, WAF |
| **NGFW (Next-Gen)** | Deep Packet Inspection + IPS + App awareness | Palo Alto, Fortinet |

**iptables Examples (Linux Firewall):**
```bash
# Allow incoming SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Block specific IP
iptables -A INPUT -s 192.168.1.100 -j DROP

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Drop everything else (default deny)
iptables -A INPUT -j DROP

# List rules
iptables -L -v -n
```

**Firewall Rule Logic:**
```
Rules are evaluated TOP to BOTTOM — first match wins!

Rule 1: ALLOW  TCP port 80 from any      → Web traffic OK
Rule 2: ALLOW  TCP port 22 from 10.0.0.0/8  → SSH from internal only
Rule 3: DENY   TCP port 22 from any      → Block SSH from everywhere else
Rule 4: DENY   ALL from any              → Default deny
```

### DMZ (Demilitarized Zone)
```
Internet → [Outer Firewall] → [DMZ] → [Inner Firewall] → Internal Network
                               ↑
                          Web/Mail/DNS servers
                          (public-facing, semi-trusted)
```

### IDS vs IPS

| Feature | IDS (Intrusion Detection System) | IPS (Intrusion Prevention System) |
|---------|----------------------------------|-----------------------------------|
| Purpose | Detect attacks | Detect AND block attacks |
| Placement | Passive (monitor copy of traffic) | Inline (all traffic passes through) |
| Action | Alert/log | Block + alert/log |
| Risk | No impact on traffic | Can block legitimate traffic |
| Example | Snort (detection mode) | Snort (prevention mode), Suricata |

**Detection Methods:**
```
Signature-based:  Compare traffic to known attack patterns (like antivirus)
                  Fast, accurate for known threats
                  Misses new/unknown attacks

Anomaly-based:    Establishes baseline, alerts on deviations
                  Detects unknown threats
                  More false positives
```

---

## 17. VPN — Virtual Private Network

A **VPN** creates an encrypted tunnel between your device and a server, protecting your data.

```
Without VPN:
Your device → [Plaintext] → ISP → Internet → Destination

With VPN:
Your device → [Encrypted] → ISP → VPN Server → [Plaintext] → Destination
                                        ↑
                              ISP only sees encrypted data
                              Destination sees VPN server's IP
```

### VPN Types

| Type | Use Case | Example |
|------|---------|---------|
| **Remote Access VPN** | Employee connects to company network | Cisco AnyConnect |
| **Site-to-Site VPN** | Connect two offices securely | IPSec between routers |
| **SSL VPN** | Browser-based, no client needed | OpenVPN, Forticlient |
| **Split Tunneling** | Only company traffic via VPN, rest direct | Bandwidth optimization |

### VPN Protocols

| Protocol | Port | Encryption | Speed | Security |
|----------|------|-----------|-------|---------|
| **OpenVPN** | 1194 UDP | AES-256 | Good | Excellent |
| **WireGuard** | 51820 UDP | ChaCha20 | Excellent | Excellent |
| **IPSec/IKEv2** | 500/4500 UDP | AES | Fast | Very Good |
| **L2TP/IPSec** | 1701 UDP | AES | Moderate | Good |
| **PPTP** | 1723 TCP | MPPE | Fast | ❌ Broken |
| **SSTP** | 443 TCP | AES-256 | Good | Good |

### VPN Tunneling Concepts

```
Tunneling: Encapsulate one protocol inside another

Original Packet:
[IP Header][TCP Header][Data]

After VPN encapsulation:
[New IP Header][VPN Header][Encrypted: IP Header + TCP + Data]
                              ↑ Original packet hidden inside
```

---

## 18. Wireless Networking (Wi-Fi)

### IEEE 802.11 Standards

| Standard | Frequency | Max Speed | Range | Year |
|----------|-----------|----------|-------|------|
| 802.11b | 2.4 GHz | 11 Mbps | 35m | 1999 |
| 802.11g | 2.4 GHz | 54 Mbps | 38m | 2003 |
| 802.11n (Wi-Fi 4) | 2.4/5 GHz | 600 Mbps | 70m | 2009 |
| 802.11ac (Wi-Fi 5) | 5 GHz | 3.5 Gbps | 35m | 2013 |
| 802.11ax (Wi-Fi 6) | 2.4/5/6 GHz | 9.6 Gbps | 30m | 2019 |
| 802.11be (Wi-Fi 7) | 2.4/5/6 GHz | 46 Gbps | 30m | 2024 |

### Wi-Fi Security Protocols

| Protocol | Year | Encryption | Status |
|----------|------|-----------|--------|
| **WEP** | 1999 | RC4 (40-bit) | ❌ Completely broken — crackable in minutes |
| **WPA** | 2003 | TKIP | ❌ Weak — vulnerable |
| **WPA2** | 2004 | AES-CCMP | ✅ Strong (if long passphrase) |
| **WPA3** | 2018 | AES-256, SAE | ✅ Strongest — use this |

### Wireless Concepts

**SSID (Service Set Identifier):** The Wi-Fi network name

**BSSID:** MAC address of the access point

**Channels:**
```
2.4 GHz: 11 channels (1, 6, 11 are non-overlapping — best practice)
5 GHz: 24+ non-overlapping channels (less interference)
6 GHz: 60 channels (Wi-Fi 6E)
```

**Wireless Authentication Modes:**
```
Personal (PSK):   Shared pre-shared key — home networks
                  WPA2-Personal: password for everyone

Enterprise (802.1X): Username + password per user via RADIUS server
                     WPA2-Enterprise: corporate networks
```

### Wi-Fi Attacks

| Attack | Description | Tool |
|--------|-------------|------|
| **WEP Cracking** | Capture IVs, crack key | aircrack-ng |
| **WPA2 Handshake Capture** | Capture 4-way handshake, crack offline | aircrack-ng, hashcat |
| **PMKID Attack** | Crack WPA2 without capturing handshake | hcxdumptool + hashcat |
| **Evil Twin** | Create fake AP with same SSID | airbase-ng, hostapd-wpe |
| **Deauth Attack** | Disconnect clients (802.11 DoS) | aireplay-ng |
| **KRACK** | WPA2 key reinstallation attack | KRACK PoC |
| **Karma Attack** | Respond to any SSID probe | hostapd-wpe |

---

## 19. Network Devices

### Complete Device Reference

**Hub (Layer 1)**
```
- Repeats signal to ALL ports
- Half-duplex (can't send and receive simultaneously)
- Creates one collision domain
- OBSOLETE — replaced by switches
```

**Switch (Layer 2)**
```
- Forwards to specific port using MAC table
- Full-duplex
- Each port = separate collision domain
- Managed switches support VLANs, STP, port security
```

**Router (Layer 3)**
```
- Connects different networks
- Routes using IP addresses + routing table
- Separates broadcast domains
- NAT, firewall, DHCP capabilities
```

**Access Point (Layer 2)**
```
- Extends network wirelessly
- Bridges wireless and wired networks
- Can operate in multiple modes:
  Root/AP mode: Normal access point
  Repeater mode: Extends range
  Bridge mode: Connect two networks wirelessly
  Monitor mode: Capture all wireless traffic
```

**Firewall (Layer 3–7)**
```
- Filters traffic based on rules
- Stateful inspection
- Can be hardware or software
```

**Load Balancer**
```
- Distributes traffic across multiple servers
- Algorithms: Round-robin, least-connections, IP-hash
- Provides redundancy and scalability

           [Client] → [Load Balancer] → [Server 1]
                                      → [Server 2]
                                      → [Server 3]
```

**Proxy Server**
```
Forward Proxy:  Client → [Proxy] → Internet   (hides client)
Reverse Proxy:  Internet → [Proxy] → Servers  (hides servers, CDN)

Uses: Caching, filtering, anonymity, SSL termination
```

**IDS / IPS** *(see Section 16)*

**Modem**
```
Modulates/demodulates signal between digital (computer) and analog (phone line/cable)
Cable modem, DSL modem, fiber ONT
```

**NIC (Network Interface Card)**
```
Hardware that connects a device to the network
Has a burned-in MAC address
Supports specific speeds (1G, 10G, 25G)
```

---

## 20. Network Commands Cheat Sheet

### Windows Commands

```cmd
ipconfig                    → Show IP configuration
ipconfig /all               → Detailed — shows MAC, DNS, DHCP
ipconfig /release           → Release DHCP IP
ipconfig /renew             → Renew DHCP IP
ipconfig /flushdns          → Clear DNS cache

ping 8.8.8.8                → Test connectivity
ping -t 8.8.8.8             → Continuous ping
ping -n 10 8.8.8.8          → Ping 10 times

tracert 8.8.8.8             → Trace route (hop-by-hop)
pathping 8.8.8.8            → Tracert + ping statistics

netstat -an                 → All active connections and ports
netstat -b                  → Show process names
netstat -r                  → Routing table

nslookup google.com         → DNS lookup
nslookup -type=MX google.com → Lookup MX records

arp -a                      → Show ARP cache (IP-MAC mappings)
arp -d 192.168.1.1          → Delete ARP entry

route print                 → Show routing table
route add 10.0.0.0 mask 255.0.0.0 192.168.1.1  → Add static route

net view \\192.168.1.10     → List SMB shares
net use Z: \\server\share   → Map network drive

telnet 192.168.1.1 80       → Test port connectivity
```

### Linux Commands

```bash
# Interface info
ip addr show                → Show all interfaces and IPs
ip addr show eth0           → Specific interface
ifconfig                    → Legacy (older systems)
ip link show                → Show interface status
ip link set eth0 up/down    → Enable/disable interface

# Routing
ip route show               → Show routing table
ip route add 10.0.0.0/8 via 192.168.1.1   → Add route
route -n                    → Legacy routing table

# Connectivity
ping 8.8.8.8                → ICMP echo test
ping -c 4 8.8.8.8           → Ping 4 times
traceroute 8.8.8.8          → Trace hops to destination
mtr 8.8.8.8                 → Real-time traceroute

# DNS
nslookup google.com         → DNS lookup
dig google.com              → Detailed DNS query
dig +short google.com       → Just the IP
dig @8.8.8.8 google.com     → Use specific DNS server
host google.com             → Simple DNS lookup

# Port & connection info
netstat -tulpn              → Listening ports with process
ss -tulpn                   → Modern netstat alternative
ss -an                      → All connections

# ARP
arp -n                      → ARP table
ip neigh show               → Modern ARP table

# Packet capture
tcpdump -i eth0             → Capture all traffic
tcpdump -i eth0 port 80     → Only HTTP traffic
tcpdump -i eth0 -w file.pcap → Save to file
tcpdump -i eth0 host 8.8.8.8  → Traffic to/from IP

# Scanning (requires nmap)
nmap -sn 192.168.1.0/24     → Network host scan
nmap -p 80,443 192.168.1.1  → Specific ports
nmap -sV 192.168.1.1        → Service version detection

# Network configuration
nmcli dev status             → Network Manager status
nmcli con show               → Show connections
```

### Useful One-Liners

```bash
# Who's on my network?
nmap -sn 192.168.1.0/24

# What's listening on this machine?
ss -tulpn | grep LISTEN

# Trace where packets go
traceroute -n 8.8.8.8

# Check if port is open
nc -zv 192.168.1.1 22

# Monitor live traffic
tcpdump -i eth0 -nn

# Bandwidth test (install iperf3 on both ends)
iperf3 -s                   # on server
iperf3 -c 192.168.1.1       # on client

# Check external IP
curl ifconfig.me

# DNS lookup all record types
dig google.com ANY
```

---

## 21. Packet Flow — End to End

### Example: You visit www.google.com

```
Step 1: DNS Resolution
  Browser → check local DNS cache → not found
  OS → query DNS server (8.8.8.8)
  8.8.8.8 → responds: www.google.com = 142.250.195.68

Step 2: TCP Three-Way Handshake
  Your PC:Port 54321 → SYN → Google:Port 443
  Google:Port 443 → SYN-ACK → Your PC:Port 54321
  Your PC → ACK → Google

Step 3: TLS Handshake (because HTTPS)
  Client Hello (supported TLS versions, cipher suites)
  Server Hello (chosen TLS version, certificate)
  Client verifies certificate (trusted CA?)
  Key exchange (session keys established)
  Encrypted tunnel established

Step 4: HTTP Request (encrypted inside TLS)
  GET / HTTP/1.1
  Host: www.google.com

Step 5: Data Flows Back
  HTTP 200 OK + HTML/CSS/JS
  (encrypted through TLS)

Step 6: What happens at each OSI layer

  Application (L7):  HTTP GET request
  Presentation (L6): TLS encryption applied
  Session (L5):      Session maintained
  Transport (L4):    TCP segment, Source:54321 Dest:443
  Network (L3):      IP Packet, Src:192.168.1.10 Dst:142.250.195.68
  Data Link (L2):    Ethernet Frame, Src MAC:your PC Dst MAC:router MAC
  Physical (L1):     Bits sent over cable/Wi-Fi
```

### How Your Packet Travels

```
[Your PC] → [Switch] → [Router/Gateway] → [ISP Router] → ... → [Google Server]

At each router:
  - Strip L2 header (Ethernet frame)
  - Read L3 IP destination
  - Look up in routing table
  - Rewrite L2 header with next hop MAC
  - Forward out correct interface
```

---

## 22. Network Security Fundamentals

### CIA Triad

```
┌────────────────────────────────────────────────┐
│                                                │
│        C — CONFIDENTIALITY                     │
│        Only authorized users can see data      │
│        Defense: Encryption, access control     │
│                                                │
│        I — INTEGRITY                           │
│        Data hasn't been tampered with          │
│        Defense: Hashing, digital signatures    │
│                                                │
│        A — AVAILABILITY                        │
│        Systems are accessible when needed      │
│        Defense: Backups, redundancy, DDoS      │
│                                                │
└────────────────────────────────────────────────┘
```

### Common Network Attacks

| Attack | Description | Defense |
|--------|-------------|---------|
| **DDoS** | Flood server with traffic → unavailable | Rate limiting, CDN, scrubbing |
| **ARP Spoofing** | Poison ARP cache → MitM | Dynamic ARP Inspection (DAI) |
| **DNS Spoofing** | Fake DNS responses → redirect | DNSSEC, DNS over HTTPS |
| **VLAN Hopping** | Access VLANs you shouldn't | Disable auto trunking |
| **STP Attack** | Become root bridge → control traffic | BPDU Guard, Root Guard |
| **MAC Flooding** | Fill CAM table → switch broadcasts all | Port security |
| **IP Spoofing** | Fake source IP | Ingress filtering (BCP38) |
| **Smurf Attack** | ICMP broadcast amplification DDoS | Block directed broadcasts |
| **SYN Flood** | Half-open TCP connections exhaust server | SYN cookies |
| **MITM** | Intercept communications | Encryption, cert pinning |
| **Replay Attack** | Re-send captured valid packets | Timestamps, nonces |
| **Packet Sniffing** | Capture unencrypted traffic | Encryption everywhere |

### Encryption Basics

```
Symmetric Encryption:     Same key for encrypt/decrypt (fast)
  Examples: AES-128/256, 3DES, ChaCha20
  Use: Bulk data encryption (VPN tunnels, disk encryption)

Asymmetric Encryption:    Public key encrypts, Private key decrypts (slow)
  Examples: RSA-2048/4096, ECC, Diffie-Hellman
  Use: Key exchange, digital signatures, SSL/TLS handshake

Hashing:                  One-way function, fixed output
  Examples: MD5 (broken), SHA-1 (weak), SHA-256 (good), SHA-3
  Use: Password storage, file integrity verification
```

**Diffie-Hellman Key Exchange (How two parties agree on a secret):**
```
Alice and Bob want a shared secret without ever sending it.

1. Agree on public values: g=5, p=23
2. Alice picks secret a=6,  computes: A = 5^6 mod 23 = 8   → sends 8
3. Bob picks secret b=15, computes: B = 5^15 mod 23 = 19  → sends 19
4. Alice: secret = 19^6 mod 23 = 2
5. Bob:   secret = 8^15 mod 23 = 2
→ Both arrived at secret = 2, without transmitting it!
```

### PKI & Certificates

```
How HTTPS certificate trust works:

Root CA (Certificate Authority) — trusted by your OS/browser
  ↓ signs
Intermediate CA
  ↓ signs
Server Certificate (google.com)
  ↓
Browser verifies chain of trust → shows padlock
```

```
Certificate contains:
  - Domain name (google.com)
  - Public key
  - Issuing CA name
  - Valid from/to dates
  - Digital signature of CA
```

---

## 23. Cloud Networking Basics

### Key Cloud Networking Concepts

**VPC (Virtual Private Cloud):**
- Your own isolated network in the cloud (AWS, Azure, GCP)
- Define your own IP ranges, subnets, routing tables

**Security Groups:**
- Virtual firewall for cloud instances
- Stateful — allow rules only (default deny)

**NACLs (Network Access Control Lists):**
- Subnet-level firewall
- Stateless — need both inbound and outbound rules

### Cloud Network Architecture (AWS Example)

```
Region
└── VPC (10.0.0.0/16)
    ├── Availability Zone A
    │   ├── Public Subnet (10.0.1.0/24) ← has Internet Gateway route
    │   │   └── [Web Server] ← has Public IP, accessible from internet
    │   └── Private Subnet (10.0.2.0/24) ← no direct internet route
    │       └── [Database] ← only accessible from VPC internally
    └── Availability Zone B
        ├── Public Subnet (10.0.3.0/24)
        └── Private Subnet (10.0.4.0/24)
```

**Internet Gateway:** Allows public subnets to access the internet.

**NAT Gateway:** Allows private subnets to access the internet (outbound only).

**VPC Peering:** Connect two VPCs so they can communicate privately.

---

## 24. Quick Reference Tables

### Port Numbers — Must Know

| Port | Protocol | Service | Notes |
|------|----------|---------|-------|
| 20/21 | TCP | FTP | 20=data, 21=control |
| 22 | TCP | SSH | Encrypted remote access |
| 23 | TCP | Telnet | ❌ Insecure, plaintext |
| 25 | TCP | SMTP | Email sending |
| 53 | UDP/TCP | DNS | UDP for queries, TCP for zone transfer |
| 67/68 | UDP | DHCP | 67=server, 68=client |
| 69 | UDP | TFTP | Trivial FTP, no auth |
| 80 | TCP | HTTP | Unencrypted web |
| 110 | TCP | POP3 | Email receive (download) |
| 119 | TCP | NNTP | Newsgroups |
| 123 | UDP | NTP | Time sync |
| 135 | TCP | RPC | Windows RPC |
| 137-139 | TCP/UDP | NetBIOS | Windows name resolution |
| 143 | TCP | IMAP | Email receive (sync) |
| 161/162 | UDP | SNMP | 161=query, 162=trap |
| 389 | TCP | LDAP | Directory services |
| 443 | TCP | HTTPS | Encrypted web |
| 445 | TCP | SMB | Windows file sharing |
| 465/587 | TCP | SMTP (SSL/TLS) | Secure email send |
| 514 | UDP | Syslog | Log forwarding |
| 636 | TCP | LDAPS | LDAP over SSL |
| 993 | TCP | IMAPS | IMAP over SSL |
| 995 | TCP | POP3S | POP3 over SSL |
| 1433 | TCP | MSSQL | Microsoft SQL Server |
| 1521 | TCP | Oracle DB | Oracle database |
| 3306 | TCP | MySQL | MySQL database |
| 3389 | TCP | RDP | Remote Desktop |
| 5432 | TCP | PostgreSQL | PostgreSQL database |
| 5900 | TCP | VNC | Remote graphical desktop |
| 6379 | TCP | Redis | Redis cache |
| 8080 | TCP | HTTP-Alt | Common web proxy/alt HTTP |
| 8443 | TCP | HTTPS-Alt | Alternate HTTPS |
| 27017 | TCP | MongoDB | MongoDB database |

---

### OSI Model Quick Reference

| Layer | Number | Data Unit | Devices | Protocols |
|-------|--------|-----------|---------|-----------|
| Physical | 1 | Bits | Hub, Cable, NIC | — |
| Data Link | 2 | Frame | Switch, Bridge | Ethernet, ARP, Wi-Fi |
| Network | 3 | Packet | Router | IP, ICMP, OSPF, BGP |
| Transport | 4 | Segment/Datagram | — | TCP, UDP |
| Session | 5 | Data | — | NetBIOS, RPC |
| Presentation | 6 | Data | — | SSL/TLS, JPEG |
| Application | 7 | Data | — | HTTP, FTP, DNS, SSH |

---

### IP Classes Quick Reference

| Class | Range | Subnet | Hosts |
|-------|-------|--------|-------|
| A | 1-126 | /8 | 16M |
| B | 128-191 | /16 | 65K |
| C | 192-223 | /24 | 254 |
| D | 224-239 | — | Multicast |
| E | 240-255 | — | Reserved |

---

### Network Acronyms Glossary

| Acronym | Meaning |
|---------|---------|
| ACL | Access Control List |
| ARP | Address Resolution Protocol |
| BPDU | Bridge Protocol Data Unit |
| CDN | Content Delivery Network |
| CIDR | Classless Inter-Domain Routing |
| CSMA/CD | Carrier Sense Multiple Access / Collision Detection |
| DHCP | Dynamic Host Configuration Protocol |
| DMZ | Demilitarized Zone |
| DNS | Domain Name System |
| FTP | File Transfer Protocol |
| GRE | Generic Routing Encapsulation |
| HSRP | Hot Standby Router Protocol (Cisco) |
| HTTP | HyperText Transfer Protocol |
| ICMP | Internet Control Message Protocol |
| IMAP | Internet Message Access Protocol |
| IPS | Intrusion Prevention System |
| IPSec | Internet Protocol Security |
| LAN | Local Area Network |
| LDAP | Lightweight Directory Access Protocol |
| MAC | Media Access Control |
| MPLS | Multi-Protocol Label Switching |
| MTU | Maximum Transmission Unit |
| NAT | Network Address Translation |
| NIC | Network Interface Card |
| NTP | Network Time Protocol |
| OSPF | Open Shortest Path First |
| PKI | Public Key Infrastructure |
| POP3 | Post Office Protocol v3 |
| QoS | Quality of Service |
| RADIUS | Remote Auth Dial-In User Service |
| RDP | Remote Desktop Protocol |
| RSPAN | Remote Switched Port Analyzer |
| SMB | Server Message Block |
| SMTP | Simple Mail Transfer Protocol |
| SNMP | Simple Network Management Protocol |
| SSH | Secure Shell |
| SSID | Service Set Identifier |
| SSL | Secure Sockets Layer |
| STP | Spanning Tree Protocol |
| TCP | Transmission Control Protocol |
| TLS | Transport Layer Security |
| TTL | Time to Live |
| UDP | User Datagram Protocol |
| VLAN | Virtual LAN |
| VPN | Virtual Private Network |
| WAN | Wide Area Network |
| WPA | Wi-Fi Protected Access |

---

### Learning Path for Networking

```
Week 1-2:   OSI Model + TCP/IP + IP addressing + subnetting
Week 3-4:   Protocols: DNS, DHCP, HTTP, SSH, FTP deep dive
Week 5-6:   Routing & Switching — VLANs, STP, OSPF basics
Week 7-8:   Security: Firewalls, VPNs, wireless security
Week 9-10:  Packet analysis with Wireshark
Week 11-12: Practice labs (Cisco Packet Tracer / GNS3)

Certifications:
  CompTIA Network+  → Foundation networking cert
  CCNA (Cisco)      → Industry gold standard networking cert
  CompTIA Security+ → Security focus
```

---

> **💡 Key Insight:** Everything in networking comes down to one thing — moving data from Point A to Point B reliably and securely. Every protocol, device, and concept exists to solve some part of that challenge. Master the OSI model and IP addressing first — everything else builds on those two pillars.

---
*Networking Fundamentals Guide v1.0 | For Educational Purposes*
