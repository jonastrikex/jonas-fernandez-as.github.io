---
title: "The Key Is in the File — Static Extraction, XOR and the Disk-Memory Split"
description: "A Go binary on a Windows service embeds an encrypted credential and the key that decrypts it. Both are recoverable without executing the binary, using only strings, objdump, xxd and a Python one-liner. This article walks the full static extraction: how to find the symbols, how to translate virtual addresses to file offsets, why the disk and memory representations coexist, and why a cipher and a key of identical length almost always mean XOR."
date: 2026-10-23
type: "Technique · Reverse Engineering"
category: "Malware Analysis"
difficulty: "Advanced"
readingTime: 16
tags: [reverse-engineering, go-binaries, pe-format, objdump, xxd, xor, static-analysis, credential-extraction]
draft: false
---

## The premise

A compiled binary is a file on disk, but it is designed to be loaded into memory. Those two representations are not identical, and the difference between them is where most static analysis gets stuck.

When a program embeds a secret — a password, a key, a token — the secret ends up in one of the binary's sections. To read it, you need to find the address where the program stores it, translate that address from the memory layout back to the file layout, and extract the bytes at the right position. The compiler does not make this obvious: strings in Go are not raw byte arrays, they are headers pointing to the actual data, and the pointer inside the header has to be resolved through the section table before it means anything.

This article works through a concrete case: a Windows service written in Go, with an encrypted credential embedded in its `.data` section and the key that decrypts it sitting in the same section. The binary is never executed. The credential is recovered from the file alone, using `strings`, `objdump` and `xxd`, plus a three-line Python script to reverse the XOR.

Two techniques are covered in depth:

- **Static key extraction.** Finding where the cipher and the key live in the file, translating their virtual addresses to file offsets, and dumping the bytes.
- **XOR recovery from known plaintext.** When both the ciphertext and the key are known and they have the same length, the decryption is a byte-by-byte XOR — and if the plaintext is partially known, the key can be derived even without it.

The disk-memory distinction that trips people up is treated explicitly, because it is the same distinction that PE loading, RVAs, and every memory-mapping technique in Windows depends on.

## Part One — The artifact

The binary is a Windows service, statically compiled from Go. No .NET runtime, no managed code, no PDB file. It is a PE32+ executable for x86-64, with the usual Go section layout: `.text` for code, `.rdata` for read-only data, `.data` for initialized globals, and `.bss` for uninitialized ones.

The service authenticates against an internal endpoint. The credential it uses is not stored in plaintext — the developer encrypted it, presumably to avoid having it visible in `strings` output. The key is stored next to the ciphertext, in the same section, which is the first sign that the encryption is not intended to resist a motivated analyst.

For a static analyst, the flow is:

1. Find the variable names that hold the cipher and the key.
2. Find where those variables live in the file.
3. Read the encrypted bytes and the key bytes.
4. Reverse the encryption.

Each step is mechanical. None of them require running the binary. None of them require a debugger. None of them require dynamic analysis.

## Part Two — Finding the symbols

The first move is `strings`. A Go binary compiled with the default settings retains function and variable names in the symbol table, even when the binary is stripped of debug information. The names are not always human-readable, but the package and function prefixes usually are:

```bash
strings svcmon.exe | grep -i "password\|credential\|secret\|key"
```

In this case, the output revealed two things:

- A function named `main.resolveCredential` — the function that performs the decryption.
- Two global variables named `main.encSeed` and `main.rotSeed` — the ciphertext and the key, respectively.

The presence of these names is not an accident. Go embeds symbol information for runtime reflection and stack traces. Even in binaries that are "stripped" by conventional standards, the runtime metadata frequently survives.

Once the variable names are known, the next step is to find their addresses. `objdump -t` reads the PE symbol table and prints every symbol with its section, its flags, and its offset relative to the start of the section:

```bash
objdump -t svcmon.exe | grep -E "encSeed|rotSeed"
```

Output:

```
[2084](sec  3)(fl 0x00)(ty    0)(scl   2) (nx 0) 0x0000000000006820 main.encSeed
[2085](sec  3)(fl 0x00)(ty    0)(scl   2) (nx 0) 0x0000000000006840 main.rotSeed
```

Section 3 is `.data`. The offsets `0x6820` and `0x6840` are the distances from the start of the section to each variable. They are not addresses in memory — they are offsets inside a section. To convert them to addresses, you need to know where the section is loaded.

## Part Three — The disk-memory split

A PE file has two coordinate systems: the **file layout** (where bytes sit on disk) and the **memory layout** (where they sit after the loader maps them). They are not the same, and the difference is what makes address translation necessary.

`objdump -h` prints the section table with both coordinates for each section:

```bash
objdump -h svcmon.exe
```

For the `.data` section, the relevant fields are:

```
Idx Name          Size      VMA               LMA               File off  Algn
  3 .data         0000a200  00000001401b2000  00000001401b2000  001b0c00  2**4
```

Two numbers matter:

- **VMA** (Virtual Memory Address): `0x1401b2000`. This is where the section starts when the binary is loaded into memory. Every address the program uses at runtime is relative to this.
- **File Offset**: `0x1b0c00`. This is where the section starts inside the file on disk. Every byte you read with `xxd` or `dd` is at this coordinate.

The two are not equal. The file has a header, a section table, and possibly padding between sections; the memory layout is contiguous and page-aligned. The loader copies bytes from the file offset to the VMA, and adjusts all internal addresses accordingly.

The translation between the two is a subtraction followed by an addition:

```
File Offset = (VMA - Section VMA Base) + Section File Offset Base
```

The expression `(VMA - Section VMA Base)` is called the **RVA** — the Relative Virtual Address. It is the offset of the address relative to the start of its section. It is the same in both coordinate systems, because the section is copied as a unit. The RVA is the bridge.

For the variable `main.encSeed`:

1. Its offset inside `.data` is `0x6820` (from `objdump -t`).
2. Its VMA is `0x1401b2000 + 0x6820 = 0x1401b8820`.
3. Its RVA is `0x6820` — the same as its offset, because the offset from `objdump -t` is already relative to the section.

For the pointer that this variable contains (which points to the actual string data), the same translation applies, but the starting VMA is different — it is the VMA of the pointer, not the variable. That is covered in the next section.

### Why `xxd` cannot read memory

`xxd` is a file utility. It reads bytes from a file on disk at a given offset. It has no concept of a virtual address space, no access to a process's memory, and no way to resolve a pointer.

`objdump -s` is different. It reads the section table, computes where each section's bytes are in the file, and prints them in memory-address order. That is why `objdump -s -j .data` can show you bytes "at" a virtual address: it is translating internally, using the same VMA-to-file-offset math that you would do manually.

The two tools solve different problems:

- `objdump -s` is useful for reading data **within a known section**, at a known virtual address.
- `xxd` is useful for reading raw bytes **at a known file offset**, including offsets that `objdump` cannot resolve — such as data pointed to by a pointer whose target lies in a different section.

This is the point where static analysis of Go binaries diverges from static analysis of C binaries. In C, a global string is usually a contiguous array of bytes, and dumping the variable gives you the string directly. In Go, a global string is a **header**: 16 bytes consisting of an 8-byte pointer and an 8-byte length. The bytes of the string are stored elsewhere — typically in `.rdata` — and the header in `.data` points to them.

## Part Four — Reading the data

For `main.encSeed`, the variable at VMA `0x1401b8820` is not the ciphertext. It is a Go string header. The header is 16 bytes: the first 8 are the pointer to the data, the next 8 are the length.

Dumping the header with `objdump -s`:

```bash
objdump -s -j .data --start-address=0x1401b8820 --stop-address=0x1401b8830 svcmon.exe
```

Output:

```
Contents of section .data:
 1401b8820 482a1b40 01000000 0e000000 00000000  H*.@............
```

Interpreting the bytes:

- The first 8 bytes are `48 2a 1b 40 01 00 00 00`. x86-64 is little-endian, so this is the pointer `0x1401b2a48`.
- The next 8 bytes are `0e 00 00 00 00 00 00 00`. This is the length: `0x0e`, or 14 in decimal.

So the actual ciphertext lives at VMA `0x1401b2a48`, and it is 14 bytes long.

For `main.rotSeed`, the same procedure at VMA `0x1401b8840`:

```bash
objdump -s -j .data --start-address=0x1401b8840 --stop-address=0x1401b8850 svcmon.exe
```

Output:

```
Contents of section .data:
 1401b8840 582a1b40 01000000 0e000000 00000000  X*.@............
```

Pointer: `0x1401b2a58`. Length: 14 bytes.

Both strings have the same length. That is the first strong signal that the encryption is XOR.

### Translating the pointers to file offsets

The pointers `0x1401b2a48` and `0x1401b2a58` are virtual addresses. They are inside the same section (`.data`), so the translation uses the same formula:

```
File Offset = (Pointer - .data VMA Base) + .data File Offset Base
```

For the ciphertext pointer:

```
0x1401b2a48 - 0x1401b2000 = 0xa48        (RVA)
0xa48 + 0x1b0c00 = 0x1b1648               (File Offset)
```

For the key pointer:

```
0x1401b2a58 - 0x1401b2000 = 0xa58        (RVA)
0xa58 + 0x1b0c00 = 0x1b1658               (File Offset)
```

Now `xxd` can read the actual bytes at those positions:

```bash
xxd -s 0x1b1648 -l 14 svcmon.exe
xxd -s 0x1b1658 -l 14 svcmon.exe
```

Output:

```
001b1648: 6d74 fceb 4b91 fe3e a859 39c0 7d83  mt..K..>.Y9.}...
001b1658: 1a3f 8cd2 05e7 b346 9a2d 6bf8 04c1  .?.....F.-k...
```

The ciphertext is:

```
6d 74 fc eb 4b 91 fe 3e a8 59 39 c0 7d 83
```

The key is:

```
1a 3f 8c d2 05 e7 b3 46 9a 2d 6b f8 04 c1
```

Both are 14 bytes. Both were extracted statically, without executing the binary.

## Part Five — Why XOR

The pattern is common enough to be recognized on sight: a cipher and a key of identical length, both stored as raw bytes, both embedded in the binary.

XOR has properties that make it attractive for lightweight obfuscation:

- **It is symmetric.** The same operation encrypts and decrypts: `plain ^ key = cipher` and `cipher ^ key = plain`.
- **It is a byte-wise operation.** No block alignment, no padding, no IV, no mode of operation to configure.
- **It is reversible without any additional state.** Given the cipher and the key, the plaintext is a single pass over the bytes.
- **It produces no avalanche.** A single-byte change in the key produces a single-byte change in the plaintext, which makes it easy to test hypotheses about the plaintext.

The last property is also the weakness. If the analyst knows any part of the plaintext — a prefix, a suffix, a likely character — the corresponding part of the key can be derived directly: `key = plain ^ cipher`. If the whole plaintext is known, the key is recovered trivially. If the key is known, the whole plaintext is recovered trivially.

For the analyst, the sequence is:

1. If cipher and key lengths match, XOR is the first hypothesis.
2. Apply XOR byte-by-byte.
3. Check if the result looks like a readable string.
4. If it does, it is the plaintext.

No brute-force, no frequency analysis, no crib-dragging. Just a single operation.

## Part Six — The decryption

The decryption fits in three lines of Python. The interesting part is not the code — it is understanding what each line is doing at the bit level.

```python
cipher = bytes.fromhex("6d74fceb4b91fe3ea85939c07d83")
key    = bytes.fromhex("1a3f8cd205e7b3469a2d6bf804c1")

plain  = bytes(c ^ k for c, k in zip(cipher, key))
print(plain.decode("ascii", errors="replace"))
```

The critical construct is `zip(cipher, key)`. It pairs the two sequences element by element:

```
zip([c0, c1, c2], [k0, k1, k2])  →  (c0, k0), (c1, k1), (c2, k2)
```

Then `for c, k in` unpacks each pair into two variables, and `c ^ k` performs the XOR on each pair. The generator expression produces a sequence of bytes, which `bytes()` assembles into a bytes object, and `.decode("ascii")` converts to a string.

Running it:

```bash
python3 decrypt.py
wKp9NvMx2tR8yB
```

The plaintext is `wKp9NvMx2tR8yB` — the credential the service uses to authenticate.

### What XOR actually does at the bit level

To verify that the operation is correct, take one pair of bytes and walk through the eight bits:

```
cipher byte:  0x6d  =  0110 1101
key byte:     0x1a  =  0001 1010
              ─────────────────
XOR result:           0111 0111  =  0x77  =  'w'
```

Bit by bit:

| Bit position | Cipher | Key | XOR | Interpretation |
|---|---|---|---|---|
| 7 | 0 | 0 | 0 | Same → 0 |
| 6 | 1 | 0 | 1 | Different → 1 |
| 5 | 1 | 0 | 1 | Different → 1 |
| 4 | 0 | 1 | 1 | Different → 1 |
| 3 | 1 | 1 | 0 | Same → 0 |
| 2 | 1 | 0 | 1 | Different → 1 |
| 1 | 0 | 1 | 1 | Different → 1 |
| 0 | 1 | 0 | 1 | Different → 1 |

Result: `0111 0111` in binary, which is `0x77` in hexadecimal, which is the ASCII character `w`.

The rule is exactly the one everyone learns the first time they see XOR: **same → 0, different → 1**. The output is a byte, and the byte happens to be an ASCII character because the plaintext is a string.

## Part Seven — When the plaintext is partially known

The extraction above works because both the cipher and the key are in the binary. That is not always the case. Sometimes only the cipher is embedded, and the key is derived at runtime from something else — a machine ID, a user input, a hardcoded constant that has been obfuscated.

In that case, the analyst needs a different approach: **known-plaintext recovery**.

If any part of the plaintext is known — a common prefix, a password policy that requires certain characters, a likely suffix — the corresponding part of the key can be derived:

```python
known_plain = b"password"
cipher_fragment = cipher[:len(known_plain)]
recovered_key_fragment = bytes(p ^ c for p, c in zip(known_plain, cipher_fragment))
```

If the plaintext is "password" and the ciphertext starts with `0x59 0x5e 0x53 0x58 0x5d 0x5e 0x5f 0x5c`, then:

```
0x59 ^ 0x70 = 0x29
0x5e ^ 0x61 = 0x3f
...
```

The recovered key fragment is `0x29 0x3f ...`, and if the key is repeated (many XOR obfuscations use a short key XORed against a longer plaintext), the rest of the ciphertext can be decrypted immediately.

This is the same reason XOR is weak against known-plaintext attacks in cryptography: the key stream is directly recoverable from any known plaintext-ciphertext pair. In the context of binary analysis, the "known plaintext" often comes from the context of the application — a default password, a well-known header, a predictable value.

## Part Eight — The limits of static extraction

Static extraction is fast and non-invasive, but it has limits that are worth knowing before reaching for it:

**It only works when the data is reachable from the file.** If the cipher or the key is generated at runtime, or derived from something that is not in the binary, static analysis will not find it. The analyst has to move to dynamic analysis, tracing the code that builds the key.

**It requires the binary to be readable.** Some binaries are packed, encrypted, or protected by an anti-tamper mechanism. `strings` and `objdump` will return garbage, or the symbol table will be empty. Unpacking is a separate discipline that involves running the binary and dumping memory.

**It requires the section layout to be intact.** If the sections have been modified — a common tactic in malware to confuse tools — the VMA-to-file-offset translation may fail. The analyst has to fall back to manual PE parsing.

**It does not always yield the full plaintext.** If the encryption is stronger than XOR (AES, ChaCha20, custom cipher), the extracted cipher and key are not enough. The analyst needs to find the decryption routine and reproduce it, or run the binary under a debugger and dump the plaintext from memory after decryption.

None of these limits apply to the binary in this case. The cipher and the key are both in `.data`, both reachable through the symbol table, and both extracted with three commands and a one-line Python script.

## Part Nine — The disk and the memory, side by side

The confusion that catches most analysts is the relationship between the two coordinate systems. It is worth stating it plainly:

- The bytes in the file and the bytes in memory are **the same bytes**. Same size, same content, same internal structure.
- The **address** at which they live is different. The file has a file offset. The process has a virtual address.
- The **distance between two bytes** is the same in both coordinate systems, as long as both bytes are in the same section. This is why the RVA works: it is the offset relative to the section, and the section is copied as a unit.

The mental model:

```
FILE                                  MEMORY
├── header                            ├── mapped header
├── .text    @ file offset 0x800     ├── .text    @ VMA 0x140001000
├── .rdata   @ file offset 0x1a00    ├── .rdata   @ VMA 0x140002000
├── .data    @ file offset 0x1b0c00  ├── .data    @ VMA 0x1401b2000
│   ├── +0x6820  encSeed header      │   ├── +0x6820  encSeed header
│   │   └── pointer → 0x1401b2a48    │   │   └── pointer → 0x1401b2a48
│   └── +0x6840  rotSeed header      │   └── +0x6840  rotSeed header
│       └── pointer → 0x1401b2a58    │       └── pointer → 0x1401b2a58
└── ...                               └── ...
```

The pointer value `0x1401b2a48` is the same in both coordinate systems, because the loader does not relocate internal pointers — the whole section moves as a unit, so any address inside the section stays valid. That is why the RVA works: the loader does not need to change it.

What the loader *does* change is the base address of the process itself, when ASLR is on. But that is a different transformation (image base relocation), and it does not affect the relationship between file offsets and RVAs within a section.

## Takeaway

A compiled binary that stores a secret and the key to that secret in the same section is not protecting the secret. It is delaying its extraction by the amount of time it takes to run three commands.

The static extraction in this article is mechanical: find the symbols, translate the addresses, dump the bytes, reverse the XOR. Each step is a single tool and a single calculation. The only conceptual hurdle is the disk-memory distinction — and once that clicks, PE analysis becomes a matter of moving numbers between two coordinate systems that describe the same bytes.

The broader lesson is about threat modeling. XOR encryption of an embedded credential is not encryption; it is obfuscation with a known break. If the attacker is a curious analyst with `objdump` installed, the secret is already public. If the attacker is a motivated adversary with a debugger, even stronger encryption embedded in the binary is not enough — the key has to come from outside the binary, or the whole thing has to be re-derived at runtime from a source the adversary cannot access.

For the defensive counterpart — what happens when the binary is not static but running, and the analyst has to observe its behavior — see **[CAPE Sandbox — Analyzing Malware Without Becoming the Next Victim →](/research/cape-sandbox-malware-analysis)**. Dynamic analysis catches what static analysis misses: the keys derived at runtime, the network flows, the persistence mechanisms that only exist in memory.

Static analysis is the first pass. It is fast, it is safe, and it answers a surprising number of questions. But it is a first pass, not a complete answer.
