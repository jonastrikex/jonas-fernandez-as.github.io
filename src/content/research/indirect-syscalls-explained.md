---
title: "Indirect Syscalls — Why Direct Syscalls Get Caught and How to Fix It"
description: "Direct syscalls bypass ntdll hooks but leave a detectable artifact: the syscall instruction executes from memory that does not belong to ntdll.dll. This article explains the ProcessInstrumentationCallback detection mechanism, how indirect syscalls defeat it by jumping to ntdll's own syscall gadgets, and why the choice of gadget matters."
date: 2026-10-06
type: "Concept · Evasion"
category: "Evasion"
difficulty: "Advanced"
readingTime: 16
tags: [indirect-syscalls, direct-syscalls, syscall, edr-evasion, process-instrumentation-callback, ntdll, assembly, windows-internals]
---

## The premise

Userland hooks in `ntdll.dll` are the first line of defense for most EDRs. Every `Nt*` function is patched with a `jmp` to the EDR's handler, which inspects the arguments before the syscall reaches the kernel. Direct syscalls were the first answer to this: instead of calling the hooked stub, the implant re-implements the syscall in its own assembly. The EDR's hook never fires.

The problem is that direct syscalls leave a different artifact. The `syscall` instruction now executes from the implant's own image, not from `ntdll.dll`. A detection mechanism called **ProcessInstrumentationCallback** lets the kernel notify userland every time execution crosses from kernel mode back to user mode. When the callback fires, the EDR inspects the return address on the stack. If it points to a memory region that is not backed by `ntdll.dll`, the syscall is flagged.

This article explains the detection mechanism, why it catches direct syscalls, and how **indirect syscalls** solve the problem by executing the `syscall` instruction from within `ntdll.dll` itself — without ever calling the hooked stub.

## Part one — The syscall stub

Every syscall-capable function in `ntdll.dll` follows the same structure. Take `NtAllocateVirtualMemory` on a clean Windows 10 22H2:

```asm
mov r10, rcx          ; 4C 8B D1
mov eax, 0x18         ; B8 18 00 00 00    <- SSN for NtAllocateVirtualMemory
test byte ptr [7FFE0308h], 1
jnz short +5
syscall               ; 0F 05
ret                   ; C3
```

Three things matter here:

1. **`mov r10, rcx`** — the first argument is moved into `r10` because the Windows x64 syscall ABI expects the first parameter in `r10` when the `syscall` instruction executes.
2. **`mov eax, <SSN>`** — the syscall service number (SSN) is loaded into `eax`. The kernel uses this number to dispatch the call.
3. **`syscall; ret`** — the actual transition to kernel mode.

When an EDR hooks this function, it overwrites the first bytes with a `jmp` to its own handler:

```asm
ntdll!NtAllocateVirtualMemory:
    jmp <EDR_handler>      ; E9 xx xx xx xx
    ...                     ; rest of the stub, now unreachable
```

## Part two — Why direct syscalls are detectable

A direct syscall copies the stub into the implant's own assembly:

```asm
NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, 18h
    syscall
    ret
NtAllocateVirtualMemory ENDP
```

The `syscall` instruction executes from the implant's `.text` section, not from `ntdll.dll`. The EDR's hook is never called, but the syscall itself is still visible to the kernel. And the kernel can notify userland about it.

### The ProcessInstrumentationCallback

Windows has an undocumented feature called **Process Instrumentation Callback** (also "instrumentation callback" or IC). It allows a userland process to register a callback function that the kernel calls every time execution returns from kernel mode to user mode.

The registration uses `NtSetInformationProcess` with the `ProcessInstrumentationCallback` information class:

```c
NtSetInformationProcess(
    GetCurrentProcess(),
    ProcessInstrumentationCallback,   // class 40
    &callback_address,
    sizeof(callback_address)
);
```

Once registered, the kernel does the following on every kernel-to-user transition:

1. Checks if the `InstrumentationCallback` field in the process's `KPROCESS` structure is non-null.
2. If set, it **swaps the target user-mode `RIP`** (the original return address) with the callback address.
3. The original return address is placed in `R10`.
4. The callback executes in userland, with `R10` containing the address the kernel was about to return to.

An EDR registers its own callback and inspects `R10`. If the address points to a region backed by `ntdll.dll` (a `MEM_IMAGE` region whose backing file is ntdll), the syscall looks legitimate. If it points to the implant's own `.text` section — a `MEM_PRIVATE` region or an image that is not ntdll — it is flagged.

```
  USER MODE
  ────────────────────────────────────────────────────────

    ntdll.dll stub:                implant stub:
      mov r10, rcx                   mov r10, rcx
      mov eax, 18h                   mov eax, 18h
      syscall                        syscall
      ret                            ret
         │                              │
         │  return → ntdll              │  return → implant
         │                              │
         └──────────────┬───────────────┘
                        ▼
  ┌─────────────────────────────────────────────────────┐
  │  Instrumentation Callback (EDR)                     │
  │                                                     │
  │  Inspects R10 (return address):                     │
  │    → ntdll.dll       : OK                           │
  │    → implant.exe     : SUSPICIOUS                   │
  └─────────────────────────────────────────────────────┘
```

The key insight: **the EDR does not care about the syscall number**. It cares about the **return address on the stack**. If the `syscall` instruction executed from a memory region that is not `ntdll.dll`, the return address will not be in ntdll.

## Part three — The indirect syscall solution

An indirect syscall solves the problem by executing the `syscall` instruction from within `ntdll.dll` — without going through the hooked stub.

Recall the hooked stub in memory:

```asm
ntdll!NtProtectVirtualMemory:
    jmp <EDR_handler>      ; <- the hook
    ...

ntdll!NtProtectVirtualMemory+0x12:
    syscall                ; <- the real instruction, unhooked
    ret
```

The hook only replaces the first few bytes. The `syscall; ret` at offset `+0x12` is untouched. An indirect syscall does the setup itself (loads `r10` and `eax` with the right values), then `jmp`s directly to that `syscall` instruction:

```asm
NtProtectVirtualMemory PROC
    mov r10, rcx
    mov eax, 50h
    jmp [ntdll_syscall_addr]
NtProtectVirtualMemory ENDP
```

The kernel now receives the syscall with a return address pointing **inside `ntdll.dll`**. The instrumentation callback fires, inspects `R10`, sees `ntdll.dll`, and does not flag the call.

### The gadget does not have to belong to the same function

This is the subtle part. When you `jmp` to `ntdll.dll`, you do not need to jump to the `syscall` instruction of the same function you are trying to call. You can jump to **any** valid `syscall; ret` gadget inside `ntdll.dll`.

For example, if you want to call `NtProtectVirtualMemory` (SSN `0x50`), you can:

1. Load `eax` with `0x50`.
2. `jmp` to the `syscall` instruction of a completely different function — say, `NtQuerySystemTime`.

The kernel receives SSN `0x50` and dispatches `NtProtectVirtualMemory`. The return address points to `ntdll!NtQuerySystemTime+0x12` — a legitimate ntdll address. The instrumentation callback sees ntdll and does not flag.

The rule is simple: **do not use the same function's gadget**. If you are calling `NtProtectVirtualMemory`, do not jump to `NtProtectVirtualMemory+0x12`. The EDR could correlate the SSN with the gadget and flag the mismatch. Jump to a different function's gadget. The EDR sees a legitimate ntdll return address, which is all it checks.

```
  Implant assembly:              ntdll.dll gadget (any function):
    ┌────────────────────┐         ┌──────────────────────┐
    │  mov r10, rcx      │         │  NtQuerySystemTime:  │
    │  mov eax, 50h      │         │    ...               │
    │  jmp ──────────────┼────────►│  +0x12: syscall      │
    │  ret               │         │          ret         │
    └────────────────────┘         └──────────────────────┘

  Kernel receives:
    eax            = 0x50 (NtProtectVirtualMemory)
    return address = ntdll!NtQuerySystemTime+0x12

  Instrumentation Callback:
    R10 = ntdll!NtQuerySystemTime+0x12  →  ntdll.dll  →  OK
```

## Part four — The assembly, step by step

Here is what an indirect syscall stub looks like in practice. The example uses `NtProtectVirtualMemory` (a function commonly abused by implants) and `NtQuerySystemTime` (a benign function that no EDR will find suspicious as a gadget source).

### Step 1 — Resolve the gadget address

First, we need the address of the `syscall; ret` instruction inside `ntdll!NtQuerySystemTime`. In a real implementation, this address is resolved dynamically (using Hell's Gate, Halo's Gate, or a hardcoded offset for the target Windows version).

For this example, assume the address is stored in a variable:

```c
PVOID syscall_gadget = (PVOID)0x00007FFB5A2C1234;  // ntdll!NtQuerySystemTime+0x12
```

### Step 2 — The assembly stub

```asm
NtProtectVirtualMemory_Indirect PROC
    mov r10, rcx           ; First argument → r10 (Windows x64 syscall ABI)
    mov eax, 50h           ; SSN for NtProtectVirtualMemory
    jmp [syscall_gadget]   ; Jump to ntdll!NtQuerySystemTime+0x12
    ret                    ; Never reached — the gadget's `ret` handles return
NtProtectVirtualMemory_Indirect ENDP
```

Three instructions. The first two set up the syscall the same way the real stub would. The third jumps to a `syscall; ret` gadget inside ntdll.

### Step 3 — What the kernel and the EDR see

1. **Kernel:** receives SSN `0x50` and dispatches `NtProtectVirtualMemory`.
2. **Instrumentation callback:** inspects `R10`. The return address is `ntdll!NtQuerySystemTime+0x12`. It is inside `ntdll.dll`. No flag.
3. **EDR's userland hook:** never fires, because the hooked stub at `NtProtectVirtualMemory+0` was never called.

The syscall executes correctly, the arguments are passed correctly, and the detection mechanism sees a legitimate ntdll return address.

## Part five — Why the choice of gadget matters

You might be tempted to always use the same gadget (for example, always jump to `NtQuerySystemTime+0x12`). That works, but it creates a pattern. If every syscall from your implant returns to the same address in ntdll, an EDR that baselines syscall return addresses will flag the repetition.

The better approach is to **randomize the gadget** on each call. SysWhispers3, for example, enumerates all `syscall; ret` gadgets in `ntdll.dll` at startup and picks a random one for each syscall. The return address varies per call, which defeats fingerprinting based on repetition.

```c
// Conceptual: pick a random gadget for each call
PVOID pick_random_gadget() {
    int index = rand() % gadget_count;
    return gadgets[index];
}
```

This is not perfect — the return address is still inside ntdll, and an EDR with full stack-walking capability can still detect that the call chain is missing the expected `kernel32` frame. But it raises the bar significantly compared to always using the same gadget.

## Part six — Detection and limitations

### What the instrumentation callback catches

The callback catches direct syscalls. Any `syscall` instruction that executes from a memory region not backed by `ntdll.dll` produces a return address that the callback flags.

### What the callback does not catch

The callback does **not** catch indirect syscalls. The return address is inside ntdll, which is exactly what the callback expects. To catch indirect syscalls, the EDR needs additional telemetry:

- **Stack walking.** The callback only inspects the top return address (`R10`). A full stack walk reveals that the frames above ntdll do not match any legitimate call chain. Legitimate syscalls have `kernel32!VirtualProtect` (or similar) between the caller and `ntdll!NtProtectVirtualMemory`. An indirect syscall jumps from the implant directly to ntdll, so those intermediate frames are missing.
- **Intel Last Branch Record (LBR).** LBR records the last branches executed on the CPU. For an indirect syscall, the last branch is a `jmp` from the implant's `.text` to `ntdll!NtQuerySystemTime+0x12`. A legitimate syscall would show a branch from `kernel32!VirtualProtect` to `ntdll!NtProtectVirtualMemory+0` (the function entry, not `+0x12`).
- **ETW-Ti.** The kernel-mode ETW provider for threat intelligence emits syscall events directly from the kernel, bypassing userland entirely. It sees the syscall regardless of how it was invoked.

### The honest assessment

Indirect syscalls are a significant improvement over direct syscalls. They defeat the most common detection mechanism (instrumentation callbacks and simple return-address checks). They do not defeat stack walking, LBR, or ETW-Ti. Those require kernel-mode or hardware-level telemetry.

The current state of the art combines indirect syscalls with:

- **Module stomping** to place the syscall stubs inside a signed DLL (so the return address is backed by a legitimate image, not a private region).
- **Sleep obfuscation** to hide the implant when it is not executing.
- **ETW patching** to reduce kernel-level telemetry.

Indirect syscalls are a piece of the puzzle, not the whole solution.

## Part seven — References and further reading

- **Hell's Gate** (am0nsec, 2020) — the original SSN resolution technique.
- **Halo's Gate** — improved SSN resolution that handles hooked stubs.
- **SysWhispers3** — the generator that automates indirect syscall stub creation.
- **ProcessInstrumentationCallback** — Cirosec's blog series on the undocumented callback mechanism.
- **MITRE ATT&CK T1106** — Native API.

## Takeaway

Direct syscalls bypass userland hooks but leave a detectable artifact: the `syscall` instruction executes from the implant's own image. The ProcessInstrumentationCallback lets EDRs inspect the return address of every syscall and flag any that does not originate from `ntdll.dll`.

Indirect syscalls solve this by jumping to a `syscall; ret` gadget inside `ntdll.dll`. The kernel receives the syscall with a return address that points to ntdll. The callback sees ntdll and does not flag. The syscall number is still controlled by the implant, so the correct function is dispatched.

The choice of gadget matters. Using the same function's gadget creates a detectable pattern. Using a random gadget from a different function avoids the obvious correlation. But indirect syscalls are not invisible — they defeat the return-address check, not stack walking, LBR, or ETW-Ti. The modern evasion stack combines indirect syscalls with module stomping and sleep obfuscation to address the remaining detection surfaces.
