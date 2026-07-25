# OSINT Execution Plan — Restructured for Domain Switch (OSINT Analyst / Red Teaming)

Built on top of your `OSINT.md` roadmap. That doc is theory-complete — this restructures it into what to *actually do*, in what order, cut down to what you don't already have.

---

## 0. Gap Analysis — What You Already Have vs. What's Actually New

Your `OSINT.md` Stage 0/1 assumes a beginner with zero technical foundation. You're not that. Two years of web/Android/iOS pentesting + a live Claude Code/Burp automation framework already gives you:

| Already have (skip re-learning) | Still a real gap |
|---|---|
| Linux CLI, `dig`/`whois`/`curl`/`jq`, Git | Structured *investigative* method (Bellingcat 5-step, ACH) |
| Subdomain/DNS/cert enum, Shodan-class infra recon | Individual/people OSINT: username pivoting, image/EXIF, geolocation, chronolocation |
| Python scripting, automation mindset (you already run agentic recon) | Dark web navigation OPSEC + threat-actor profiling workflow |
| `.git`/`.env`/JS-endpoint hunting, secrets scanning | Corporate/due-diligence OSINT (ownership graphs, filings, M&A) |
| OPSEC-for-testing instincts | OPSEC-for-investigator (burner identities, deanonymization defense — different threat model than pentest OPSEC) |
| Report-writing for pentest findings | Intelligence report writing (confidence levels, sourcing, Admiralty/CRAAP) |

**Consequence:** your 12-month plan compresses to roughly **4–5 months** to operator-level, because Stage 1 (Months 1–3 in your doc) is mostly a 1–2 week refresher, not a build-from-zero. Redirect that saved time into Stage 2 domain skills and volume of practice — that's where hiring signal actually comes from.

---

## 1. Restructured Timeline (Compressed)

| Weeks | Focus | Deliverable |
|---|---|---|
| 1–2 | Intelligence cycle formalized + investigator OPSEC (burner identities, Tails/Whonix, browser fingerprinting) + Bellingcat 5-step method | VM/identity setup; 3 Bellingcat case studies dissected |
| 3–6 | People/Individual OSINT domain: username enum, image forensics, geolocation/chronolocation | 10 solved Sofia Santos / Trace Labs practice puzzles, written up |
| 7–10 | Corporate/Due-diligence OSINT + Dark web methodology (defensive/threat-intel angle) | 1 mock corporate due-diligence report; dark-web monitoring workflow doc |
| 11–14 | Structured Analytic Techniques + report writing (Admiralty code, ACH, confidence levels) | Rewrite 3 earlier write-ups using ACH-formatted conclusions |
| 15–18 | Live practice: Trace Labs CTF (real case) + TryHackMe OSINT rooms + CTFtime challenges | 1 Trace Labs event completed + public write-up |
| 19–20 | Portfolio + specialization decision + applications | Portfolio live, applications to both OSINT-analyst and red-team-with-OSINT roles |

Ongoing throughout: build a small automation add-on to your existing Claude Code/Kali workflow specifically for OSINT (see §5).

---

## 2. Curated Resources — Per Domain, Practical First

### A. Methodology (do this before anything else — you already know tools, you don't yet have investigator method)
- **Bellingcat's Online Investigation Toolkit** (free, bellingcat.com) — case studies, not just theory. Read 5 full investigations end-to-end and note their sourcing chain.
- **Michael Bazzell — *Open Source Intelligence Techniques*** (latest edition) + inteltechniques.com — the practical canon; also his free podcast (*The Privacy, Security, & OSINT Show*) is a good commute-length supplement.
- **Richards Heuer — *Psychology of Intelligence Analysis*** (free CIA PDF) — short, teaches cognitive-bias defense and structured analytic techniques (ACH). This is the one book on your list that's genuinely different from anything in pentesting.

### B. People / Individual OSINT (your real skill gap)
- **Sherlock, WhatsMyName, Maigret** — username pivoting across platforms (practical, install and run against test accounts today).
- **GHunt** — Google account OSINT.
- **EXIF/geolocation drills** — GeoGuessr (informal but genuinely builds the eye), then Bellingcat's geolocation case studies for the real method (shadows, signage, architecture, flora).
- **Practice sets built for this exact skill**: Sofia Santos OSINT exercises, Nixintel write-ups, gralhix challenges — self-contained puzzles with published solutions to grade yourself against.

### C. Corporate / Due-Diligence OSINT
- OpenCorporates, SEC EDGAR, Companies House — you've listed these; actually run one full company profile end-to-end (pick a public company, build ownership/subsidiary graph, cross-reference job postings for tech stack).
- **Maltego CE** — get comfortable graphing entity relationships; this is the tool that separates "I found things" from "I built a defensible picture."

### D. Dark Web (learn the workflow, not just the theory you already wrote)
- Tails or a Whonix VM — set this up as a separate, permanent identity from your pentest VM.
- Ahmia, ransomwatch/ransomware.live for the defensive/threat-intel angle (this is the angle that gets you hired into threat-intel-adjacent OSINT roles, vs. the riskier "market monitoring" angle).
- MITRE ATT&CK + Diamond Model + Pyramid of Pain — frame what you find, don't just collect it.

### E. Certifications (verified current, July 2026)
- **SANS SEC487** — *Open-Source Intelligence Gathering and Analysis* (foundational; GIAC GOSI cert attached). Given your background, this would move fast for you — worth it primarily for the credential + GIAC line on a resume for OSINT-analyst-titled roles.
- **SANS SEC497** — *Practical Open-Source Intelligence* — newer, more hands-on, built to be accessible even for experienced practitioners; includes individual-investigation techniques (usernames, email, social media) and report writing. Good fit given your gap map above.
- **SANS SEC587** — *Advanced OSINT Gathering and Analysis* — disinformation assessment (Admiralty code, CRAAP, ACH), facial recognition, restricted-platform access. This is genuinely advanced content, worth targeting *after* SEC497, not instead of it.
- **Trace Labs OSINT badge** — free, earned through actual CTF participation — arguably higher signal for a domain-switch resume than a paid cert alone, because it's evidence of real casework.
- Budget-conscious alternative to the SANS stack: **MCSI OSINT certs** — cheaper, practical-lab-based.

### F. Practice Platforms (do these in parallel with study, not after)
- **Trace Labs Global OSINT Search Party CTF** — quarterly, fully virtual, real missing-persons cases, strictly passive recon (zero-touch rule — this matters, it's the same "observe don't act" boundary you already respect in pentesting scope). Confirmed still running actively through 2026; sign up for the next global event.
- **TryHackMe OSINT rooms** — guided, good for filling specific tool gaps fast.
- **CTFtime OSINT challenges** (DEFCON, NahamCon, Google CTF) — for adversarial/gamified reps.
- **HackTheBox Sherlocks** — DFIR-flavored, useful for the threat-intel-analyst crossover.

---

## 3. How This Maps to Your Two Target Titles

**"OSINT Analyst"** — needs the full investigative depth: people-profiling, geolocation, corporate due-diligence, dark-web threat monitoring, and *structured, defensible reporting* (§C above is where you're weakest relative to the role). Portfolio of written-up investigations matters more than certs here — hiring managers in this space look for public write-ups and Trace Labs participation over a resume line.

**"Red Teaming"** — per your own doc's Section 5 analysis, you're already close to "operator-level" OSINT compulsory skills (infra footprint, people-enum for pretexts, leaked-secret discovery) from your bug-bounty-automation work. The gap here is narrower: formalize it into a repeatable **target-dossier deliverable** (domains → people → credentials → pretexts, mapped explicitly, handed off before an engagement's "live" phase) rather than ad hoc recon. This is a natural extension of your existing Claude Code/Kali/Burp framework — worth building as a dedicated OSINT-recon subagent alongside your recon/vuln-tester/triager/librarian setup, producing a structured dossier as output.

---

## 4. Portfolio & Application Strategy

1. **Write up every practice investigation** — even failed ones — anonymized, on a blog or GitHub. This is the single highest-signal thing in OSINT hiring, more than certs.
2. **Pick one specialization to lead with** on applications: given your existing red-team/bug-bounty base, "attack-surface/red-team-recon specialist" is the shortest path; "threat-intel analyst" is the second-shortest given the dark-web/ATT&CK overlap you're building in §D.
3. **Participate publicly** — Trace Labs Discord, OSINT Curious community — small, reputation-based field; visible participation substitutes for a traditional network.
4. Target the **50-investigation mark** before calling yourself competent for interviews — track it like you'd track pentest reps.

---

## The One Adjustment to Your Own Doc's Conclusion

Your doc says "build the thinking first, then the hands, then a portfolio." Correct — but for you specifically, the "hands" are already partly built from pentesting. Spend your saved time on the **new thinking** (investigator method, structured analytic techniques) and the **new hands** (people OSINT, geolocation) — not re-deriving Linux/Python/networking you already have.
