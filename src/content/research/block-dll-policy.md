---
title: "Block DLL Policy — When a Mitigation Becomes an Evasion Primitive"
description: "Windows exposes a process mitigation policy that blocks any DLL not signed by Microsoft from loading into a newly created process. It sounds like a defense, and in many contexts it is one. This article explains how the policy is enforced at the loader level, how it is applied during process creation through the attribute list mechanism, why local processes require a self-re-execution pattern, and where the approach hits a ceiling that kernel-level telemetry does not care about."
date: 2026-10-14
type: "Concept · Evasion"
category: "Evasion"
difficulty: "Advanced"
readingTime: 14
tags: [windows-internals, process-mitigation, evasion, process-creation, loader-policy, edr]
draft: false
---

## The premise

Windows allows a process to be created with a loader-level restriction: no DLL signed by anyone other than Microsoft is allowed to load. The check happens inside the image loader, not in userland, so it cannot be bypassed by patching a stub. It is a structural constraint on what the process can ever contain in memory.

For offensive tooling, the appeal is direct. If no non-Microsoft DLL can load, no userland EDR component can inject its hooks. The syscalls the implant makes execute without userland interception, because there is no userland interceptor. The entire hook-based detection model is removed from the equation by a single flag passed to `CreateProcess`.

The reality is narrower. The policy blocks unsigned DLLs, but EDR vendors ship signed DLLs. It blocks non-Microsoft binaries, but EDR vendors are, in this specific sense, Microsoft-adjacent: their userland components carry valid signatures, and their kernel drivers are registered callbacks that the policy never touches. The flag is real. Its reach has limits.

This article explains how the policy works, how it is applied during process creation, why local processes need a self-restart pattern to benefit from it, and where the actual ceiling is. It is not a technique article — there is no single command at the end. It is a breakdown of what a kernel mitigation does and does not do when it is turned against the detection stack it was meant to enable.

## Part One — The policy

`PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON` is one member of the family of process mitigation policies that Windows has accumulated since the Windows 8 era. The most well-known siblings are Data Execution Prevention (DEP), which prevents code execution from data pages, and Control Flow Guard (CFG), which restricts indirect call targets to known-valid entries. All three share a property: they are set at process creation, they apply for the lifetime of the process, and they cannot be disabled once active.

The binary signature policy is enforced by the loader inside `ntdll`. Every time an image is about to be mapped into the process — whether at process startup or via `LoadLibrary` — the loader consults the process mitigation policy. If the policy is set and the image is not signed by Microsoft, the load fails with `STATUS_INVALID_IMAGE_HASH`. There is no userland code involved in the decision. There is no callback to intercept. The check is a branch inside a kernel-adjacent path, and it either passes or it does not.

That property is why the policy is interesting. It does not require trust in a third-party component, and it does not depend on any userland monitoring stack. It is enforced by code that ships with the operating system.

## Part Two — Applying the policy at creation

The policy is not retroactive. A running process cannot be told, after the fact, that it should only ever load Microsoft-signed DLLs. The policy is read during process initialization and remains fixed. The only way to get a process with the policy is to be created with the policy.

The mechanism is the process thread attribute list. It is a variably sized structure that gets attached to an extended startup information block before `CreateProcess` is invoked. The standard `STARTUPINFO` structure does not have a field for this kind of out-of-band configuration, so Windows introduced `STARTUPINFOEXA` (and its wide-character sibling `STARTUPINFOEXW`) to carry a pointer to the attribute list.

Setting up the list requires three calls, and the first one is the least intuitive:

**Step 1 — Measure.** `InitializeProcThreadAttributeList` is invoked with a `NULL` list pointer. This is not an error path. The function does not create anything; it returns the amount of memory the list will require given the number of attributes that will be added. The size depends on how many attributes the list carries and is not fixed.

```c
SIZE_T attr_size = 0;
InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);
```

**Step 2 — Allocate and initialize.** A buffer is allocated using the size returned by the previous call. `InitializeProcThreadAttributeList` is called again, this time with the actual buffer. The list is now an empty container that can hold the requested number of attributes.

```c
LPPROC_THREAD_ATTRIBUTE_LIST attr_list =
    HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attr_size);

InitializeProcThreadAttributeList(attr_list, 1, 0, &attr_size);
```

**Step 3 — Populate.** `UpdateProcThreadAttribute` attaches an attribute to the list. Each attribute has a key (what it represents), a value pointer, and a size. For the binary signature policy, the key is `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY`, and the value is a bitmask of one or more mitigation flags ORed together.

```c
DWORD64 policy =
    PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

UpdateProcThreadAttribute(
    attr_list,
    0,
    PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
    &policy,
    sizeof(policy),
    NULL,
    NULL
);
```

Once populated, the list is attached to the `lpAttributeList` field of a `STARTUPINFOEXA`, the extended startup block is passed to `CreateProcessA`, and the `EXTENDED_STARTUPINFO_PRESENT` flag is set on `dwCreationFlags`. Without that flag, the attribute list is ignored.

```c
STARTUPINFOEXA si = { 0 };
si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
si.lpAttributeList = attr_list;
```

The kernel reads the attribute list during process initialization and applies the mitigation policy before the first user-mode instruction executes. From that moment on, the policy is active and cannot be removed.

## Part Three — Why local processes need a fork

Here is where the design forces a specific pattern. The policy can only be applied at creation. A running process cannot acquire it. So if the implant is currently executing inside a process that was created without the policy, that process cannot be retroactively protected.

The response is a self-restart pattern. The current process re-executes its own binary, passing an argument that signals to the new instance that the policy is already active. The new instance, reading that argument, does not re-execute and instead proceeds to the actual work. The chain terminates because the argument is carried forward.

```c
int main(int argc, char* argv[]) {

    if (argc == 2 && strcmp(argv[1], "__guarded__") == 0) {
        run_workload();
        return 0;
    }

    CHAR self[MAX_PATH * 2];
    GetModuleFileNameA(NULL, self, sizeof(self));

    CHAR cmd[MAX_PATH * 2 + 32];
    snprintf(cmd, sizeof(cmd), "%s __guarded__", self);

    spawn_guarded(cmd);
    return 0;
}
```

The `spawn_guarded` helper is a thin wrapper that does the attribute list setup from Part Two and then calls `CreateProcessA`. The original process exits. The new process continues, running under the policy, executing the workload path.

From the loader's point of view, the process that does the work was created with the policy from the start. Nothing that the initial process did — including loading anything that userland monitoring might have installed — carries over into the protected child.

## Part Four — The naming confusion

The original write-ups on this technique use the word "remote" to describe one of the two cases, and the word causes more confusion than it resolves. The two cases are:

- **Local:** the implant wants to protect the process it is running in. It uses the self-restart pattern from Part Three. The process that runs the workload is created by the implant itself, with the policy applied at creation.
- **Remote:** the implant wants to protect a different, already-running process — typically a target into which the implant has been injected. That target was not created by the implant and was not created with the policy.

The word "remote" here does not mean "on another machine". It means "not the process I am currently executing in". The process is on the same host. The distinction matters because the mitigation can only be applied at creation, and an existing process is by definition past creation.

The consequence is significant. If a target process was created without the policy — which is almost always the case, since the attacker did not create it — the policy cannot be applied retroactively. Only *new* processes that the target itself creates can be spawned under the policy. The target keeps whatever DLLs it loaded at startup, including any userland hooks. The evasion benefit is inherited only by the target's children.

This is why the local pattern is preferred. It guarantees that the process running the implant was created with the policy, rather than relying on a target that may or may not have it.

## Part Five — The runtime alternative and why it is worse

There is a second API that appears to achieve the same effect on a running process:

```c
PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sig = { 0 };
sig.MicrosoftSignedOnly = 1;

SetProcessMitigationPolicy(ProcessSignaturePolicy, &sig, sizeof(sig));
```

The intent is the same: only Microsoft-signed binaries should be allowed. But the timing is different, and the timing is what matters.

By the time `SetProcessMitigationPolicy` is called, the process has already loaded the DLLs it needs at startup. If a userland EDR component was among them, it is already in memory, and its hooks are already installed. The policy prevents *future* non-Microsoft DLLs from loading, but it does not evict the ones already present. Any syscall the process makes from that point still goes through the existing interception path.

The `CreateProcess`-time approach avoids this because the policy is applied before the first DLL load happens. The loader sees the policy on its first image mapping decision and never allows a non-Microsoft DLL to enter. The runtime approach applies the policy too late to matter for the DLLs that were already loaded.

## Part Six — Where the ceiling is

The policy blocks non-Microsoft-signed DLLs. It does not block Microsoft-signed DLLs, and it does not block anything about kernel mode. EDR vendors operate under both constraints: their userland components are signed, and their kernel components run as signed drivers. The policy never sees them.

When the userland hook cannot be installed, the EDR does not stop operating. It shifts to other layers:

- **Kernel callbacks.** Process and thread creation, image loads, registry operations — all of these can be monitored from a driver that was loaded before the process in question was created. The policy does not touch the driver.
- **ETW-Ti.** The kernel-mode ETW provider emits syscall events directly from kernel mode, without userland involvement. Whether the syscalls were made via a hooked stub, a direct syscall, or an indirect syscall, the kernel emits the event. The policy changes which userland binaries are loaded but does not change which syscalls reach the kernel.
- **Minifilter drivers.** File operations can be observed at the filesystem stack, below any userland component. The policy has no effect on the filesystem stack.
- **Network telemetry.** The C2 traffic still goes out. If the environment monitors egress, the policy does not hide the traffic.

The binary signature policy is a defense of the userland from unsigned DLLs. It is not a defense of the process from kernel-mode observation. EDR vendors have known this for years, which is why modern products do not rely solely on userland hooks: the policy would have removed them anyway from any hardened process, and the products need detection to survive in exactly those environments.

## Part Seven — Detection

The policy itself is a legitimate feature. Browsers, hardened system services, and security tools apply it routinely. Its presence in a process is not suspicious on its own.

The suspicious pattern is a specific combination: a process created with the binary signature policy, by a parent that is not a known hardened application, running from a user-writable directory, with no Microsoft signature on the parent. Any one of those properties has legitimate explanations. All four together do not.

Telemetry that helps:

- **Process creation with the attribute list.** EDRs that instrument `CreateProcess` can log the attributes carried by the new process. A process created with the mitigation policy is recorded as such, and the parent that created it is recorded as the creator.
- **Image load failures.** When a process created with the binary signature policy attempts to load a DLL that fails the signature check, the loader returns an error. Repeated failures against DLL names that a normal process would expect are a signal.
- **Self-re-execution.** The fork pattern produces a process that re-executes its own binary with a fixed argument. Legitimate software rarely does this. The combination of self-re-execution and a mitigation policy on the child is unusual.
- **Command-line arguments.** The stop marker (`__guarded__` in this article's example, but any fixed string in practice) appears verbatim in the child's command line. A parent that spawns a child of itself with a fixed string is easy to flag.
- **Unsigned parent, signed-only child.** A process that enforces a signature policy on its children while itself being unsigned is a contradiction worth investigating.

The general takeaway for defenders is that the block DLL policy is not a hiding technique. It is a layer-reduction technique. Detecting the pattern — self-re-execution with a mitigation flag, unsigned parent with a signed-only child — is more productive than trying to detect the mechanism itself.

## Takeaway

The binary signature policy is one of the cleaner examples of a Windows feature that reads as defensive and works as an evasion primitive in specific conditions. It blocks the loader from mapping unsigned DLLs, and the block is enforced structurally rather than by a hook, which means it cannot be bypassed by patching the loader.

Its ceiling is that signed DLLs still load, and EDR vendors ship signed DLLs. What the policy actually does is push detection up a layer: away from userland hooks, into kernel callbacks, ETW-Ti, and minifilter drivers. Those layers are active regardless of whether the policy is on.

The technique is useful as one component of a broader evasion stack — alongside indirect syscalls, module stomping, and sleep obfuscation — but it is not useful as a standalone. Understanding what it does — and what it does not — is the difference between applying it as a layer and expecting it to solve a problem it was never designed to solve.

For the detection angle on what happens when the userland hooks are removed: **[Indirect Syscalls — Why Direct Syscalls Get Caught and How to Fix It →](/research/indirect-syscalls-explained)**.
