# OSINT — Open Source Intelligence

A complete reference and learning roadmap covering: what OSINT is, how it's performed, the role of the dark web, how it relates to red teaming, an assessment of the OSINT Framework, and a structured path to becoming a professional practitioner.

---

## Table of Contents

1. [What Is OSINT?](#1-what-is-osint)
2. [The Intelligence Cycle](#2-the-intelligence-cycle-the-underlying-flow)
3. [Targeting an Organization — Reconnaissance Steps](#3-targeting-an-organization--reconnaissance-steps)
4. [The Role of the Dark Web in OSINT](#4-the-role-of-the-dark-web-in-osint)
5. [OSINT vs Red Teaming](#5-osint-vs-red-teaming)
6. [Is OSINT Framework Enough to Learn OSINT?](#6-is-osint-framework-enough-to-learn-osint)
7. [A Roadmap to Becoming a Professional OSINT Practitioner](#7-a-roadmap-to-becoming-a-professional-osint-practitioner)
8. [The Curated Reading List](#8-the-curated-pro-path-reading-list)
9. [12-Month Realistic Plan](#9-12-month-realistic-plan)
10. [Critical Legal & Ethical Lines](#10-critical-legal--ethical-lines)

---

## 1. What Is OSINT?

**OSINT (Open Source Intelligence)** is the discipline of collecting and analyzing **publicly available information** to produce actionable intelligence. "Publicly available" means anything that doesn't require unauthorized access: public websites, DNS records, certificates, job postings, social media, court filings, financial disclosures, breach databases, etc.

It's used by:

- **Red teams** — recon before an engagement
- **Blue teams** — threat intel & attack-surface monitoring
- **Journalists** — Bellingcat-style investigations
- **Law enforcement**
- **Due-diligence investigators** (M&A, fraud, corporate vetting)
- **Recruiters**

The core distinction: OSINT uses **only public data** and stops at *finding* — never *using* credentials or accessing systems.

---

## 2. The Intelligence Cycle (the underlying "flow")

Every OSINT engagement — organization or individual — follows the classic intelligence cycle. This is the framework to anchor on:

1. **Planning & Direction** — Define objective, scope, legal/ethical boundaries, Rules of Engagement (RoE), and your own OPSEC (how do I stay anonymous?). What's the question? What's "good enough"?
2. **Collection** — Gather raw data from public sources (passively — no direct contact with the target).
3. **Processing & Exploitation** — Clean, normalize, and structure the data (dedupe, geolocate, correlate).
4. **Analysis & Production** — Connect the dots, draw conclusions, produce a report.
5. **Dissemination** — Deliver to the stakeholder.
6. **Feedback** — Refine the requirements and loop.

> The mistake beginners make is jumping straight to collection with no plan. The cycle exists because unfocused collection produces noise, not intelligence.

---

## 3. Targeting an Organization — Reconnaissance Steps

For an **organization** target, the collection phase breaks down like this (loosely modeled on PTES / Bellingcat org recon):

### Step 1 — Define & footprint the target
- Confirm legal entity name, domains, subsidiaries, acquisitions (Crunchbase, OpenCorporates, SEC EDGAR, Companies House).
- Build an **asset list**: primary domains, brand names, products.

### Step 2 — Infrastructure / external attack surface
- **WHOIS / RDAP** — registrant history, related domains, name servers.
- **DNS enumeration** — all records (A, MX, TXT, SPF, DMARC), zone transfers.
- **Subdomain discovery** — passive (Certificate Transparency via `crt.sh`/`censys`, `amass`, `subfinder`, `shodan`) vs active (brute-force with `ffuf`).
- **Certificate Transparency** — certs reveal subdomains, internal naming, and historical infrastructure.
- **Shodan / Censys / ZoomEye / GreyNoise** — exposed services, banners, versions, open ports.
- **ASN & IP ranges** — `bgp.he.net`, `amass intel`, find the org's netblocks → sweep for hosts.
- **Cloud storage** — open S3 buckets, GCP, Azure blobs (`grayhatwarfare`, `bucket_finder`).
- **Wayback Machine** — historical content of their site (leaked URLs, old endpoints, files).

### Step 3 — Web presence & application recon
- Tech stack fingerprinting — `wappalyzer`, `whatweb`, HTTP headers.
- `robots.txt`, `sitemap.xml`, `.git/`, `.env`, backup files, `security.txt`.
- JavaScript files → often contain API endpoints, keys, internal hostnames.
- Email pattern discovery (e.g., `first.last@company.com`).

### Step 4 — People / employee recon
- **LinkedIn** (and LinkedIn-derived tools: `theHarvester`, `h8mail`, `snov.io`) → employee names, roles, team structure.
- **GitHub** — employee commits, leaked secrets/keys, internal repo names (`trufflehog`, `gitleaks`).
- **Social media** (X/Twitter, Facebook, Instagram) → for pretext building and social engineering.
- **Breached credential databases** — HaveIBeenPwned, DeHashed, breach compilation sets → credentials for spraying and password-pattern guessing.

### Step 5 — Public records & corporate intel
- Financial filings (SEC EDGAR, Companies House), press releases, patents, trademarks.
- Job postings (reveal tech stack: "experience with Kafka + K8s + Vault").
- Pastebin dumps mentioning the org (`psbdmp`, `google dorks`).

### Step 6 — Physical & wireless
- Google Earth / satellite imagery, Street View (building layout, badge readers, loading docks).
- `Wigle.net` — wireless networks at the org's locations (SSIDs, encryption).

### Step 7 — Synthesize → threat model
- Map: domains → IPs → services → tech → people → credentials → pretexts.
- Identify the highest-yield attack paths (credential reuse, exposed services, phishing pretexts).
- Document gaps and pivot points.

### Tooling starter pack (Kali)

| Category | Tools |
|---|---|
| Aggregate / harvest | `theHarvester`, `recon-ng`, `maltego`, `spiderfoot` |
| Subdomains / DNS | `amass`, `subfinder`, `assetfinder`, `dnsx`, `dnsenum` |
| Infra scanning | `nmap`, `masscan`, `shodan` CLI |
| Web recon | `whatweb`, `wappalyzer`, `ffuf`, `gobuster`, `katana`, `gau` |
| Secrets / code | `trufflehog`, `gitleaks`, `gitrob` |
| People / email | `h8mail`, `hunter.io`, LinkedIn scrapers, `GHunt` |
| Breaches | HaveIBeenPwned, DeHashed |
| OSINT dashboards | `Maltego` (graphing), `SpiderFoot` (automated), `IntelOwl` |

### Frameworks & references worth knowing
- **OSINT Framework** — osintframework.com (directory of tools by source).
- **Michael Bazzell — *Open Source Intelligence Techniques*** (the practical reference).
- **Bellingcat Online Investigation Toolkit** — investigative-journalism oriented.
- **MITRE ATT&CK / Cyber Threat Intelligence** — for framing findings.
- **Trace Labs OSINT** — search methodology for missing persons.

---

## 4. The Role of the Dark Web in OSINT

The dark web is one of the most **valuable — and most misunderstood** — sources in OSINT. It's not a single hidden marketplace; it's a layer of the internet that requires special software (Tor, I2P, Freenet) to access, where sites don't have a normal domain name and operators/users are pseudonymous. From an OSINT perspective it matters for two reasons: it's where stolen data **ends up**, and it's where threat actors **talk**.

### What the dark web provides

**1. Breached / leaked data dumps** — the single biggest OSINT use.
- Sold on markets (BreachForums successors, Genesis, etc.)
- Leaked for free to build a threat actor's reputation
- Ransom-group extortion sites (LockBit, BlackCat/ALPHV, Akira, etc.) that publish victims who don't pay

For an **organization target**, this reveals:
- Customer/employee PII, email + password pairs → credential reuse against the corporate VPN/email
- Internal documents, source code, database schemas → internal naming, architecture
- Which ransomware crew hit them, and **when** → threat intel and incident correlation

For a **personal target** (due diligence, executive vetting):
- Past breach exposure → password habits, reused passwords, leaked phone numbers, alt emails

**2. Threat-actor chatter and TTPs** — forums, Telegram channels, chat logs reveal:
- Tools, techniques, procedures — what exploit kits, loaders, or social-engineering lures are in vogue
- Targets being discussed — "who's hitting this sector next"
- Aliases and reputations — building an actor profile (preferred currencies, languages, time-zone hints from posting times, OPSEC mistakes)

**3. Markets listing stolen goods / access**
- Stolen credentials, session cookies, MFA-bypass / "OTP bots"
- Initial access brokers (IABs) selling footholds into companies by revenue, sector, country
- Stolen credit cards, identity packages, proxy/socks lists

**4. Underground services that enable attacks**
- Bulletproof hosting, cryptomixers/tumblers, drop services, cashout rails
- VPN/proxy/socks ("residential" pools) used by actors to hide egress
- Tools: stealers (RedLine, Vidar, Raccoon), ransomware-as-a-service affiliates

**5. Counter-OSINT / monitoring (defensive use)** — for blue teams and threat-intel analysts, the dark web is a monitoring surface:
- Is our org's data being sold right now?
- Are our executives or employees being targeted (doxxing)?
- Are our domains, IPs, or credentials in a fresh steal-log dump?

### How dark-web OSINT differs from surface-web OSINT

| Dimension | Surface web | Dark web |
|---|---|---|
| Access | Normal browser | Tor Browser / I2P; onion links are non-obvious |
| URLs | Stable, indexed by Google | `.onion` v3 strings, often down/moved, directory sites go stale fast |
| Search | Google, Bing | Ahmia, Torch, Haystak, Recon (often incomplete / paywalled) |
| Trust | Mostly signed TLS | PGP-signed releases, reputation scores, escrow on markets |
| OPSEC burden | Moderate | **High** — sites fingerprint, ban non-Tor, sometimes drop JS to deanonymize |
| Legality | Generally fine | Browsing is legal; **purchasing stolen goods/access is a crime** everywhere |

### The investigation flow (dark-web-specific)
1. **Define the question** — "Is our data for sale?", "Who leaked the XYZ dump?", "What TTPs is group ABC using?"
2. **Establish OPSEC** — Tor Browser in a hardened VM, no personal accounts, no JS, separate identities, never reuse surface-web identities. Consider VPN-before-Tor if your threat model needs it.
3. **Locate sources** — start from known-good indexers, not random link lists: `ahmia.fi`, `tor.taxi`/`darksearch`, `Haystak`, `Recon` (paid), known forum onion addresses from prior intel.
4. **Monitor / collect** — forums, ransom-leak sites, market listings, Telegram (technically clearnet but where most "dark" chatter now happens — don't ignore it).
5. **Correlate with surface data** — a leaked email means nothing until cross-checked against LinkedIn, breach DBs, and your asset list.
6. **Analyze** — actor profile, scope of leak, indicators of compromise (IOCs: hashes, URLs, wallets).
7. **Report** — and, for defensive work, feed detections (SOC rules, fraud, IAM password resets).

### Dark-web tools & services

| Purpose | Examples |
|---|---|
| Tor access | Tor Browser, Whonix VM, Tails |
| Onion search / index | Ahmia, Torch, Haystak, darksearch.io |
| Automated collection / monitoring | **IntelOwl**, **SpiderFoot** (dark-web modules), **Maltego** transforms, **DarkOwl**, **Flare**, **ZeroFox**, **Recorded Future** (commercial) |
| Breach-leak monitoring (defensive) | HaveIBeenPwned, **SpyCloud**, DeHashed, H8mail |
| Threat-actor & forum intel | Flashpoint, Intel 471, Kela, Recorded Future |
| Ransomware tracker | `ransomwatch`, ransomware.live, ransomlook |

> Most reliable dark-web intel is **commercial** (DarkOwl, Flashpoint, etc.) because they've already done the dangerous crawling and indexing — many teams don't self-crawl, they subscribe.

### Where the dark web fits in the org-OSINT flow
- **Step 4 (People)** — breach dumps → reused credentials, alt emails.
- **Step 2 (Infrastructure)** — stolen internal docs sometimes leak internal IP ranges and hostnames not findable externally.
- **A new step 7 (Threat intel)** — "is our org currently being targeted or extorted?" and "what actor's tradecraft should we defend against?"

> Framing: **the dark web is where the consequences of a breach become visible.** Surface-web OSINT finds *what's exposed*; dark-web OSINT finds *what's already been taken*.

---

## 5. OSINT vs Red Teaming

These get conflated because both do "recon on a target," but they are **different disciplines** with different scopes, goals, and deliverables.

### The core difference

| | **OSINT** | **Red Teaming** |
|---|---|---|
| **Goal** | Collect & analyze publicly available information to answer an intelligence question. | Simulate a real adversary to test the org's ability to detect, respond, and withstand an attack. |
| **What it produces** | Intelligence — a report, a profile, a list of findings. | An attack path + assessment of the blue team's detection & response (not just "did I get in"). |
| **Scope** | Public sources only — no unauthorized access. | Full adversary simulation — may include phishing, exploitation, physical intrusion, social engineering (all authorized in scope). |
| **Access level** | None. You never touch the target's systems. | You gain access, move laterally, persist, exfiltrate (mock), act like a real attacker. |
| **Primary metric** | Completeness/accuracy of the picture. | Did the blue team catch you, and how fast? (MTTD/MTTR) |
| **Audience** | Analysts, investigators, decision-makers. | The org's SOC / IR / leadership. |
| **Legality by default** | Generally legal (public data). | Legal only with a signed RoE/SOW — otherwise it's a crime. |

> **One-line version:** OSINT is about *knowing*; red teaming is about *doing* (an authorized imitation of the adversary).

### The relationship — red teaming *uses* OSINT

Real adversaries do recon before they attack, so a faithful red team engagement must do recon too — and that recon **is OSINT**.

```
OSINT (intelligence cycle)         Red Team (attack lifecycle)
─────────────────────             ──────────────────────────
1. Planning & Direction   ◄────►  1. Objective & scope, RoE
2. Collection            ◄────►  2. Recon / OSINT footprinting
3. Processing            ◄────►  3. Target selection, weaponization
4. Analysis              ◄────►  4. Initial access (phishing/exploit)
5. Production            ◄────►  5. C2, lateral movement, persistence
6. Dissemination          ◄────►  6. Actions on objectives, exfiltration
                                  7. Reporting + detection assessment
```

OSINT maps onto the **first ~40%** of a red team engagement — the recon and target-selection phase. The red team then *acts* on what OSINT found: a leaked credential gets sprayed, an exposed service gets exploited, an employee's LinkedIn post becomes a phishing pretext.

> OSINT is a component of red teaming, not a substitute for it. A red teamer who skips OSINT launches attacks blindly; an OSINT analyst who never attacks still produces a complete intelligence product.

### "Is OSINT compulsory for a red teamer?"

**Yes — it's a core, non-optional skill, but the depth expected is "operator-level," not "specialist-level."**

**What every red teamer *must* be able to do (compulsory):**
- Footprint the external attack surface — domains, subdomains, DNS, certs, exposed services, cloud buckets
- Enumerate people — LinkedIn / GitHub recon to build phishing pretexts and find leaked credentials
- Find leaked credentials & secrets — breach DBs, exposed `.git/`, hardcoded API keys
- Choose good targets — decide which exposure is worth attacking based on the recon picture
- Maintain OPSEC while reconning — so you don't tip off the blue team before the engagement's "live" phase

**What is *not* compulsory (specialist territory):**
- Deep investigative OSINT — geolocating a person from a photo (Bellingcat-style), tracking a threat actor across pseudonyms over months, building full corporate-ownership graphs across jurisdictions
- Dark-web infiltration / threat-actor profiling at analyst depth
- Persistent monitoring of a target's exposure over time

**In a mature team, the split:**
- Large/mature red teams often have a dedicated OSINT analyst or threat-intel cell that hands operators a "target dossier"
- Small teams / solo red teamers wear both hats and need solid OSINT themselves
- Bug bounty hunters and pentesters also rely heavily on OSINT (especially subdomain + tech-stack recon)

### The spectrum

```
OSINT  ──►  Pentesting  ──►  Red Teaming
(passive)   (find vulns)     (full adversary sim + blue-team test)
```

OSINT is the foundation all three sit on; the difference is how far past "knowing" you go, and how much authorization you need to go there.

---

## 6. Is OSINT Framework Enough to Learn OSINT?

**Short answer: No — but it's an essential reference you should bookmark alongside actual learning material.**

### What OSINT Framework *is*
It's a **tool directory**, not a course or tutorial — the *Yellow Pages* of OSINT: a big navigable tree of links to free tools and resources, organized by source type (email → breach databases, username → social media, domain → WHOIS/subdomains, IP → Shodan, image → reverse search, etc.).

Each entry gives you:
- A description of the tool
- Input → Output mapping (what you feed it, what you get back)
- OPSEC notes (what to watch out for)
- A community star rating
- Codes flagging special cases: `T` (local install), `D` (Google Dork), `R` (registration required), `M` (manual edit the URL)

### Why it's not *enough* on its own
A directory answers **"what tool exists?"** — but learning OSINT requires answers it doesn't cover:

| What you need to learn | Does OSINT Framework cover it? |
|---|---|
| Methodology / the intelligence cycle | ❌ No |
| Why and when to use a tool (decision-making) | ❌ Mostly no |
| How to chain tools (subdomain → cert → IP → service → exploit path) | ❌ No |
| Analysis & correlation (raw data → intelligence) | ❌ No |
| OPSEC holistically | ⚠️ Partial — per-tool notes only |
| Legal/ethical boundaries | ❌ No |
| Report writing & dissemination | ❌ No |
| Tool catalogue / what exists | ✅ Yes — this is its strength |
| Quick "where do I search X" lookup | ✅ Yes |

> The site gives you the **ingredients** but not the **recipe**. OSINT is a *thinking skill* — knowing which source answers which question and how to cross-correlate — not a tool-list memorization exercise.

### The other traps: link rot & quality variance
- Community-maintained, so links go stale, tools get paywalled, or get acquired/shut down
- Mixes excellent free tools with mediocre ones — the star rating helps but you still judge
- Newer tools often lag in being added

### How to *actually* use it well
1. Learn the methodology first (see Section 7).
2. When a lesson says *"for email recon, use breach databases"*, open OSINT Framework → Email → pick one → use it.
3. Build muscle memory by actually running tools, not by reading their descriptions.
4. Cross-reference: when you find a tool here, check its GitHub README and OPSEC notes before trusting it with a real target.

### What to pair it with
| Resource | Why |
|---|---|
| Michael Bazzell — *Open Source Intelligence Techniques* (book + inteltechniques.com) | The practical canon. Methodology + tool recipes. |
| Bellingcat Online Investigation Toolkit + case studies | Real investigations, real method. Free articles. |
| Trace Labs OSINT Search Party CTFs | Practice on real (consenting) missing-persons cases — best free hands-on training. |
| SANS SEC487 / SEC497 (or free equivalents) | Structured classroom method. |
| TryHackMe OSINT pathways / rooms | Guided, gamified practice — good for beginners. |
| OSINT Dojo, Sofosumo, The OSINT Curious | Keep up with the field. |
| Practice targets: Sofia Santos / gralhix / Nixintel write-ups | Self-contained puzzles to build the thinking skill. |

### Verdict
> **OSINT Framework is a necessary tool, not a sufficient teacher.** Bookmark it — every OSINT practitioner does. But if it's your *only* resource, you'll learn a list of tools, not the craft. Pair it with one methodology source (Bazzell or Bellingcat) and one practice outlet (Trace Labs or TryHackMe OSINT rooms), and you'll actually learn OSINT.

---

## 7. A Roadmap to Becoming a Professional OSINT Practitioner

OSINT is one of the rare fields where you can reach a professional level mostly through self-study + practice, because almost everything is public and the bar is *skill*, not credentials.

### Stage 0 — Mindset & Foundations (Weeks 1–3)
Internalize two things:
1. **The Intelligence Cycle** (planning → collection → processing → analysis → production → dissemination → feedback). Professionals think in this loop, not in "search and dump."
2. **Ethics & legality** — public data only; passive vs active recon; you may *find* breached credentials but never *use* them; understand GDPR, local privacy law, and RoE. This separates a professional from a vigilante.

**Read first:**
- *We Are Bellingcat* — Eliot Higgins. Origin story + mindset.
- Bellingcat's Beginner's Guide to Online Investigations (free, bellingcat.com).
- The OSINT Curious "So You Want To Do OSINT?" intro articles.

### Stage 1 — Technical Foundations (Months 1–3)
You cannot do professional OSINT without these.

| Skill | Why it matters | How to learn |
|---|---|---|
| Networking & DNS | Infrastructure OSINT is 70% DNS/WHOIS/IP analysis | Free CCNA-level networking; DNS, WHOIS, BGP/ASN, CDN, reverse DNS |
| The web & HTTP | Reading sites, JS files, headers, APIs | HTML/JS basics, browser devtools, REST APIs |
| Linux command line | Most OSINT tooling runs on Linux | Set up a Kali/Ubuntu VM; `grep`, `jq`, `curl`, `dig`, `whois` |
| Python + scripting | Automation, scraping, glue between tools | Automate the Boring Stuff; `requests`, `BeautifulSoup`, regex |
| Git | Tracking investigations, sharing scripts | GitHub basics |
| Geolocation & image analysis | Core investigative skill (Bellingcat signature) | EXIF, satellite imagery, Sun-shadow, Street View, map math |
| OPSEC | Don't deanonymize yourself or your client | Tor/Whonix, VMs, burner identities, fingerprinting risks |

**Books at this stage:**
- *Open Source Intelligence Techniques* — Michael Bazzell. THE canon. Read the methodology chapters carefully; use the tool list as a reference.
- *The Art of Invisibility* — Kevin Mitnick (OPSEC mindset).

### Stage 2 — Domain Skills (Months 3–8)
A professional picks 1–2 specializations but understands all of these.

**A. People / Individual OSINT**
- Username enumeration across platforms (Sherlock, WhatsMyName)
- Email & phone intelligence; breach correlation (HIBP, DeHashed)
- Social media profiling (X, Facebook, Instagram, TikTok, Reddit)
- Aviation, vessel, vehicle, property records

**B. Corporate / Organization OSINT**
- Business registries (OpenCorporates, SEC EDGAR, Companies House)
- Subsidiaries, M&A, beneficial ownership
- Job postings, patents, trademarks, filings → tech stack & structure
- Employee mapping (LinkedIn scraping, org charts)

**C. Infrastructure / Attack-surface OSINT**
- Subdomains, certs (crt.sh, Censys, cert transparency)
- Shodan/Censys/ZoomEye/GreyNoise for exposed services
- ASN → netblocks → host sweep; cloud bucket discovery
- This is where red-team/pentest OSINT lives

**D. Geolocation & chronolocation**
- Image-to-location (Bellingcat methodology)
- Timestamps from shadows, weather, flight paths

**E. Dark web & threat intel (if you specialize)**
- Tor navigation, onion indexing, ransomware-leak tracking
- Threat-actor profiling, TTPs, IOCs

> At each domain: use osintframework.com as the tool lookup, but learn the *method* from Bellingcat case studies and Bazzell's chapters.

### Stage 3 — Methodology & Frameworks (Ongoing)
Professionals don't improvise — they follow repeatable method:
- **The Intelligence Cycle** (already covered)
- **Bellingcat's 5-step method**: source → verify → geolocate → chronolocate → connect
- **PTES** (for OSINT feeding pentesting)
- **MITRE ATT&CK / CTI frameworks** for threat-intel alignment
- **Diamond Model / Pyramid of Pain** for threat analysis
- **Structured Analytic Techniques** (ACH, key assumptions check) — these separate "I found stuff" from "here is a defensible conclusion"

**Book:** *Psychology of Intelligence Analysis* — Richards Heuer (free CIA publication). Teaches you to think like an analyst and avoid cognitive bias.

### Stage 4 — Tooling (Build a Working Kit)
Don't memorize tools — build a kit you actually use.

| Category | Tool(s) |
|---|---|
| All-in-one / graph | **Maltego** (industry-standard graphing), **SpiderFoot** (automated) |
| Framework / CLI | **recon-ng**, **theHarvester** |
| Subdomain/DNS | **amass**, **subfinder**, **dnsx**, **assetfinder** |
| Infra | **Shodan/Censys** (pay for pro tiers — it's worth it) |
| Web recon | **gau**, **katana**, **ffuf**, **whatweb** |
| People | **Sherlock**, **WhatsMyName**, **GHunt**, **h8mail** |
| Breaches | HaveIBeenPwned API, **DeHashed** (paid) |
| Capture & evidence | **Hunchly** (paid, professional-grade capture with provenance) — worth it for real work |
| Automation | **IntelOwl**, custom Python |
| Notebooking | **Obsidian** or **CherryTree** for investigation logs |

> Get a paid **Shodan** and **Maltego CE/Pro** account early — they're how the pros work, not just enthusiasts.

### Stage 5 — Practice (This is where you actually become a professional)
Talent in OSINT comes from reps. Do all of these:
1. **Structured exercises** — Sofia Santos OSINT exercises, gralhix challenge, Nixintel write-ups. Self-contained, blogged solutions to compare against.
2. **TryHackMe OSINT rooms** + HackTheBox Sherlocks (DFIR/OSINT).
3. **Trace Labs CTFs** — real missing-persons cases (with consent). The single best free training with real stakes and portfolio material.
4. **CTFtime OSINT challenges** — DEFCON, Google CTF, NahamCon, etc.
5. **Write up every investigation** — even failures — as a blog. Public write-ups are how professionals get hired in OSINT.

> Aim to do **50+ investigations** before calling yourself competent. The volume matters.

### Stage 6 — Certifications (Optional but helpful for hiring)
- **SANS SEC487** (Open-Source Intelligence Gathering) — gold standard, expensive.
- **SANS SEC497** (Practical OSINT) — newer, hands-on.
- **OSINT Foundation certifications** (OSINTF).
- **MCSI OSINT certifications** (practical, cheaper than SANS).
- **Trace Labs "OSINT" badge** (free, recognized).
- **Mile2 C)OSINT**.

For red-team-leaning OSINT: OSCP + good OSINT practice is a strong combo.

### Stage 7 — Real-World Application & Career Entry
How professionals actually get hired in OSINT:
1. **Build a public portfolio** — a blog/GitHub with anonymized write-ups. This is the hiring signal in OSINT, more than certs.
2. **Specialize** — pick a lane: corporate due diligence, threat intel, missing persons/journalism, fraud, attack-surface for red team. Generalists struggle; specialists get hired.
3. **Contribute** — add tools to OSINT Framework, write for OSINT Curious, help in Trace Labs Discord. The OSINT community is small and reputation-based.
4. **Roles to target**:
   - Threat-intel analyst (SOC-adjacent, most entry points)
   - Attack-surface management / red-team recon specialist
   - Fraud / trust & safety
   - Due-diligence / corporate investigations (Kroll, BSI, Mintz Group)
   - Journalism (Bellingcat, BBC, NYT open-source team)
   - Private investigators with digital specialization

---

## 8. The Curated "Pro Path" Reading List

**Methodology & mindset**
1. *We Are Bellingcat* — Eliot Higgins
2. *Psychology of Intelligence Analysis* — Richards Heuer (free)
3. Bellingcat Online Investigation Toolkit + case studies

**Practical technique**
4. *Open Source Intelligence Techniques* — Michael Bazzell (read every edition update)
5. *Hiding from the Internet* — Bazzell (OPSEC/erasure — niche)

**Newsletters / ongoing (must subscribe)**
- OSINT Curious, Week in OSINT (Sector035), OSINT Dojo, Bellingcat, miyako.io

**Tools / communities**
- OSINT Framework, Bellingcat toolkit, Trace Labs Discord, OSINT Curious Discord

---

## 9. 12-Month Realistic Plan

| Months | Focus | Deliverable |
|---|---|---|
| 0–1 | Foundations + OPSEC + intelligence cycle | Notes, VM set up, 10 beginner exercises |
| 1–3 | Technical foundations (networking, Python, geolocation) | Automate a basic recon script |
| 3–6 | Domain skills A–C, Bazzell chapters, tools | 20 investigations blogged |
| 6–8 | Specialize in one lane + dark web or threat intel | A specialized tool/method you can teach |
| 8–10 | Trace Labs CTFs, write-ups, portfolio | 5+ public write-ups |
| 10–12 | Cert (SANS/MCSI/Trace Labs), job applications / freelance | Portfolio site live, applications out |

---

## 10. Critical Legal & Ethical Lines

1. **Browsing/reading the dark web is legal** in most jurisdictions. So is using Tor.
2. **Purchasing stolen data, credentials, or access is illegal** — that's not OSINT, that's trafficking in stolen property / aiding a breach. OSINT stops at *observation*.
3. **Don't engage actors** (chat, negotiate, "infiltrate") — entrapment-adjacent, dangerous, violates terms, and can blow back legally. Leave infiltration to law enforcement or contracted, authorized engagements.
4. **Don't download live malware** "to look at it" outside a proper sandbox — execute-only-in-VM, never on a host with real credentials.
5. **OPSEC is not optional.** Real-world deanonymization failures have come from: opening a doc that phones home, JS-based fingerprinting, time-zone correlation, language-style analysis, and reusing a surface-web handle.
6. **Passive vs active** — querying a public DNS record is passive; sending packets to enumerate a host is active recon that may violate terms of service or computer-fraud laws. Know which you're doing.
7. **Run OSINT inside an authorized scope** — a contracted pentest, your own org, a CTF, or a legitimate research question — and keep your OPSEC tight.

---

## The One-Line Truth

> **Professionals aren't defined by knowing the most tools — they're defined by repeatable method, evidence discipline (provenance & verification), OPSEC, and the ability to turn raw public data into a defensible conclusion someone will act on.**

Build the *thinking* first (Bellingcat + Heuer + Bazzell methodology), then the *hands* (tools + 50 investigations), then a *portfolio*. The tools on osintframework.com are the last 20% — most people over-invest there and under-invest in method.