# CMDPLUS

#### Introduction

CMDPLUS is a powerful Windows system administration toolkit designed for system administrators and educational environments. It integrates process management, privilege escalation, file operations, system repair, and more, effectively handling various system-restricted scenarios. A handy tool for IT classes.

**Version:** 26.7.5\_KERNEL\_DRIVER\_2
**License:** Apache 2.0
**Language:** VC++17 (Unicode)
**Target Platform:** Windows 7 SP1 \~ Windows 11 26H1
**Build Environment:** MSBuild + VS2026 v145 Toolset
**Code Size:** ~34,000 lines
**Open-Source DMSP:** `signature_protection_nocert.h` (no-cert version, signature verification & certificate data excluded)

#### Software Architecture

```
Core Components:

ProcessTerminator (Process Terminator)
├── COM Initializer
├── Firewall Rule Manager
├── Enhanced Process Open Functions
├── 71 Termination Methods
├── USB Storage Recovery
├── Input Device Recovery
└── Fullscreen Overlay Detection

WTSHelper (Token Helper)
├── Initialization
├── User Token Acquisition
└── Active Session ID Retrieval

AdvancedProcessCreator
├── Token-based Process Creation
└── Windows 7 Compatible Process Creation

DebugPrivilegeEnabler
└── Enable All Debug Privileges

Enhanced Protection Module
├── Watchdog Thread
├── Anti-Suspend Protection
├── Terminator Detection
├── Critical Process Marking
└── API Hook Management
```

**Self-Protection Architecture** — DMSP v5.4 (Distributed Multi-Layer Signature Protection):
> Open-source build uses `signature_protection_nocert.h` — **L1 signature verification is skipped** (no certificate data included). The remaining 10 protection layers operate normally.

| Tier | Subsystem | Core Capability |
|:---:|-----------|-----------------|
| L1 | Digital Signature Verification | Open-source: skipped (nocert) |
| L2 | Anti-Debug Detection | 13 Detection Methods with Weighted Voting |
| L3 | Process Self-Protection | PPL + BreakOnTermination + Job Object + Watchdog |
| L4 | Code Integrity | Full .text Section CRC32C Chunk Verification |
| L5 | Memory Anomaly Detection | VAD Scan + IAT Integrity Hash Verification |
| L6 | Anti-Hook | API Hook Detection (JMP/FF25/mov rax+jmp rax) |
| L7 | Thread Hiding | NtSetInformationThread Periodic Refresh |
| L8 | Kernel Anti-Debug | KUSER\_SHARED\_DATA Direct Read + Triple Cross-Validation |
| L9 | Anti-Compile-Time Patch | TriggerResponse Function Body CRC32C Verification |
| L10 | VEH Guard | VEH Linked List Integrity Detection |
| L11 | Control Flow Obfuscation | Function Pointer Encryption + Opaque Predicates + State-Machine Dispatcher |

**Dependencies:**
> Open-source (nocert) build does not require `wintrust.lib` / `crypt32.lib`; listed here for the full release build.

```cpp
advapi32.lib    // Advanced API (Registry, Tokens)
wtsapi32.lib    // Terminal Services API
wbemuuid.lib    // WMI
shell32.lib     // Shell API
wintrust.lib    // Code Signature Verification
ntdll.lib       // Native API
userenv.lib     // User Environment
crypt32.lib     // Cryptography API
setupapi.lib    // Device Installation API
cfgmgr32.lib    // Configuration Manager
```

#### Installation

1. Download the latest CMDPLUS.exe from the Releases page
2. Run the program **as Administrator** (right-click -> Run as Administrator)
3. Or build from source using MSBuild

**Build Command:**

```bash
MSBuild CMDPLUS.sln /p:Configuration=Release /p:Platform=x64 /t:Build /v:minimal
```

#### Usage

**Requirements:**

- Must run with **Administrator privileges**
- Windows 7 SP1 or later
- Some features require debug privileges

**Core Features:**

| No. | Feature | Description |
|:---:|---------|-------------|
| 1 | Kill Process | Forcefully terminate processes, supports PPL bypass |
| 2 | TrustedInstaller CMD | Open a command prompt with system highest privileges, always on top |
| 3 | Always On Top | Force a window to stay on top |
| 4 | Cancel Always On Top | Stop the always-on-top function |
| 5 | Privileged Launch | Launch programs with TrustedInstaller privileges |
| 6 | Force Delete | File dialog to delete files or folders |
| 7 | USB Unblock | Restore USB storage device functionality |
| 8 | Remove Classroom Manager | One-click removal of student classroom management software |
| 9 | Installed Program Manager | Manage registered installed program information |
| 10 | Junk Cleanup | Clean system junk files |
| 11 | Anti-Remote Control Firewall | Detect and block remote control connections |
| 12 | Port Monitoring | Persistent detection of suspicious port connections |
| 13 | Block Port Connections | Block communication on specific ports |
| 14 | System Cleanup | Immediate cleanup / Install boot-time auto-cleanup |
| 0 | Exit | Safe exit (with protection cleanup) |

**Notes:**

1. This tool directly operates low-level system components. Use with caution.
2. Some features may be blocked or flagged by security software.
3. PPL bypass and kernel-level techniques involve core system operations and carry stability risks.
4. Low-level file operations may cause irreversible data loss.
5. Test in a virtual machine environment before using in production.

#### Features

1. Multi-privilege support: Administrator, SYSTEM, and TrustedInstaller privilege levels
2. 71+ process termination methods, covering user-mode and kernel-mode techniques
3. Multi-layered self-protection mechanism against malicious termination
4. Comprehensive system recovery: Registry, policies, services, startup items, and more
5. Low-level file operations: Secure overwrite and raw disk sector operations
6. Broad compatibility: Supports all mainstream versions from Windows 7 to Windows 11

---

**Disclaimer:** This tool is distributed under the [Apache 2.0](LICENSE) open-source license and is intended for educational and research purposes only. The author assumes no responsibility for any system damage, data loss or leakage, or violation of local laws resulting from the use of this tool. By using this tool, you acknowledge and agree to assume all risks.