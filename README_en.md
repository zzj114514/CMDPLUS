# CMDPLUS

#### Introduction

CMDPLUS is a powerful Windows system administration toolkit designed for system administrators and educational environments. It integrates process management (71+ termination methods), privilege escalation (Admin/SYSTEM/TrustedInstaller), file operations, system repair, port monitoring, garbage cleanup, anti-remote-control firewall management, and more — effectively handling various system-restricted scenarios. A handy tool for IT classes.

**Version:** 26.7.7\_KERNEL\_DRIVER\_2
**License:** Apache 2.0
**Language:** VC++17 (Unicode)
**Target Platform:** Windows 7 SP1 \~ Windows 11 26H1
**Build Environment:** MSBuild + VS2026 v145 Toolset
**Code Size:** ~27,500 lines (source 1,459 KB)
**UAC Requirement:** Must run as Administrator
**Open-Source DMSP:** `signature_protection_nocert.h` (no-cert version, signature verification & certificate data excluded)

---

#### Software Architecture

```
CMDPLUS Modular Architecture:

├── Core System
│   ├── MainMenu          Entry point + menu system + main loop dispatch
│   ├── CommonDefs        Shared types/structs/utilities + Windows SDK polyfills
│   └── stubs             Linker stubs (fallback implementations)

├── Process Management
│   ├── ProcessTerminator Process terminator (71+ termination methods)
│   │   ├── Open Layer    12 OpenProcess strategies (incl. driver-based privilege escalation)
│   │   ├── Kill Layer    User-mode + kernel-mode termination techniques
│   │   └── Utils Layer   COM/Firewall/USB/Input device recovery
│   └── ProcessGuard      Process protection engine (DACL + Job Object + Watchdog)

├── Privilege & Token
│   ├── DebugPrivilegeEnabler  Debug privilege escalation (SeDebug etc., 7 privileges)
│   ├── WTSHelper              Windows Terminal Services token helper
│   └── AdvancedProcessCreator Advanced process creation (SYSTEM/TI token)

├── Network & Port
│   ├── AntiRemoteControl  Anti-remote-control firewall rule management
│   ├── PortMonitor        Real-time port connection monitoring (TCP/UDP)
│   └── PortBlocker        Windows firewall port blocking management

├── System Maintenance
│   ├── GarbageCleaner     Multi-threaded system junk file scanning & cleanup
│   └── System Recovery    Multi-dimensional restore (registry/policies/services/startup)

├── Kernel Driver Components
│   ├── PPL Driver         Remove PPL protection via RTCore64.sys
│   │                     (with HVCI detection/auto-disable + auto driver cleanup)
│   ├── PhantomKiller      Kernel-mode process termination driver (IOCTL)
│   └── RTCore64.sys       Signed legitimate driver (for hardware-level access)

├── Anti-Analysis & Bypass
│   ├── syscalls           Indirect syscall stubs (Hell's Gate / Halo's Gate)
│   │                     Bypass EDR/AV user-mode ntdll hooks
│   └── ProcessHint        Process hint table (accelerated process enumeration)

└── Self-Protection (DMSP v5.4.2)
    └── signature_protection  11-layer distributed multi-layer signature protection
```

**Self-Protection Architecture** — DMSP v5.4.2 (Distributed Multi-Layer Signature Protection):

> Open-source build uses `signature_protection_nocert.h` — **L1 signature verification is skipped** (no certificate data included). The remaining 10 protection layers operate normally.

| Tier | Subsystem | Core Capability |
|:---:|-----------|-----------------|
| L1 | Digital Signature Verification | Open-source: skipped (nocert) |
| L2 | Anti-Debug Detection | 13 Detection Methods with Weighted Voting |
| L3 | Process Self-Protection | PPL + BreakOnTermination + Job Object + Watchdog |
| L4 | Code Integrity | Full .text Section CRC32C Chunk Verification |
| L5 | Memory Anomaly Detection | VAD Scan + IAT Integrity Hash Verification |
| L6 | Anti-Hook | API Hook Detection (JMP/FF25/mov rax+jmp rax) |
| L7 | Thread Protection | NtSetInformationThread Periodic Refresh |
| L8 | Kernel Anti-Debug | KUSER\_SHARED\_DATA Direct Read + Triple Cross-Validation |
| L9 | Anti-Compile-Time Patch | TriggerResponse Function Body CRC32C Verification |
| L10 | VEH Guard | VEH Linked List Integrity Detection |
| L11 | Control Flow Obfuscation | Function Pointer Encryption + Opaque Predicates + State-Machine Dispatcher |

**Design Philosophy:**
| Principle | Description |
|-----------|-------------|
| Distribution | Verification logic scattered across multiple locations; single-point bypass ineffective |
| Redundancy | Every detection has at least one backup; cross-validation reduces false positives |
| Asymmetry | Detection points randomly distributed; attackers cannot predict when triggered |
| Graduated | Weight accumulation rather than threshold cutoff; reduces single-point influence |
| Self-Destruct | Multi-path forced exit when irreparable tampering is detected |

**Dependencies:**

> Open-source (nocert) build does not require `wintrust.lib` / `crypt32.lib`; listed here for the full release build.

```cpp
advapi32.lib    // Advanced API (Registry, Tokens)
wtsapi32.lib    // Terminal Services API
wbemuuid.lib    // WMI (Windows Management Instrumentation)
shell32.lib     // Shell API
wintrust.lib    // Code Signature Verification
ntdll.lib       // Native API
userenv.lib     // User Environment
crypt32.lib     // Cryptography API
setupapi.lib    // Device Installation API
cfgmgr32.lib    // Configuration Manager
iphlpapi.lib    // IP Helper API (Port Monitoring)
```

---

#### Installation

1. Download the latest CMDPLUS.exe from the Releases page
2. Run the program **as Administrator** (right-click -> Run as Administrator)
3. Or build from source using MSBuild

**Build Command:**

```bash
MSBuild CMDPLUS.sln /p:Configuration=Release /p:Platform=x64 /t:Build /v:minimal
```

---

#### Usage

**Requirements:**

- Must run with **Administrator privileges**
- Windows 7 SP1 or later
- Some features require debug privileges
- Kernel driver features require HVCI/VBS disabled or auto-handled

**Core Features:**

| No. | Feature | Description |
|:---:|---------|-------------|
| 1 | Kill Process | Forcefully terminate processes, supports PPL bypass (71+ methods) |
| 2 | TrustedInstaller CMD | Open command prompt with system highest privileges, always on top |
| 3 | Always On Top | Force a window to stay on top (with event hooks & topmost fighting) |
| 4 | Cancel Always On Top | Stop always-on-top and restore original window state |
| 5 | Privileged Launch | Launch programs with TrustedInstaller privileges |
| 6 | Force Delete | File dialog to delete files or folders |
| 7 | USB Unblock | Restore USB storage device functionality |
| 8 | Remove Classroom Manager | One-click removal of student classroom management software (incl. Image Hijacking cleanup) |
| 9 | Installed Program Manager | Manage registered installed program information |
| 10 | Junk Cleanup | Multi-threaded system junk file scanning & cleanup |
| 11 | Anti-Remote Control Firewall | Detect and block remote control connections |
| 12 | Port Monitoring | Persistent detection of suspicious port connections |
| 13 | Block Port Connections | Block communication on specific ports |
| 14 | System Cleanup | Immediate cleanup / Install boot-time auto-cleanup |
| 0 | Exit | Safe exit (with protection cleanup) |


**System Cleanup (Feature 14) Submenu:**

| Option | Function | Description |
|:------:|----------|-------------|
| 1 | Immediate Cleanup | Terminate all non-whitelist and non-self processes |
| 2 | Boot-time Auto-cleanup | Install startup + desktop shortcut for automatic cleanup on next boot |

**Notes:**

1. This tool directly operates low-level system components. Use with caution.
2. Some features may be blocked or flagged by security software.
3. PPL bypass and kernel-level techniques involve core system operations and carry stability risks.
4. Low-level file operations may cause irreversible data loss.
5. Kernel driver components (RTCore64.sys / PhantomKiller.sys) require HVCI disabled to load.
6. Test in a virtual machine environment before using in production.

---

#### Features

1. **Multi-privilege support**: Administrator, SYSTEM, and TrustedInstaller privilege levels
2. **71+ process termination methods**, covering user-mode and kernel-mode techniques (incl. driver-level EPROCESS privilege escalation)
3. **Multi-layered self-protection** (DMSP v5.4.2) against malicious termination
4. **Comprehensive system recovery**: Registry, policies, services, startup items, and more
5. **Low-level file operations**: Secure overwrite and raw disk sector operations
6. **Kernel driver integration**: RTCore64.sys PPL bypass + PhantomKiller.sys kernel-level termination
7. **EDR/AV evasion**: Indirect syscalls (Hell's Gate / Halo's Gate) bypass user-mode hooks
8. **Broad compatibility**: Supports all mainstream versions from Windows 7 to Windows 11
9. **Modular architecture**: Refactored from monolithic CMDPLUS.cpp to a layered module system

---

#### Project Structure

```
CMDPLUS/
├── MainMenu.cpp              Entry point + menu system + main loop
├── CommonDefs.h              Shared definitions / Windows SDK polyfills / utilities
├── ProcessTerminator.h       Process terminator class declaration
├── ProcessTerminator_Terminate.cpp  Termination + open strategy implementations (71+ methods)
├── ProcessGuard.h            Process protection engine
├── GarbageCleaner.{h,cpp}    Junk file scanning & cleanup
├── PortMonitor.{h,cpp}       Port monitoring
├── PortBlocker.{h,cpp}       Port blocking
├── AntiRemoteControl.{h,cpp} Anti-remote-control firewall
├── AdvancedProcessCreator.{h,cpp}  Advanced process creation
├── DebugPrivilegeEnabler.h   Debug privilege escalation
├── WTSHelper.h               Terminal Services token helper
├── stubs.cpp                 Linker stubs
├── ppl_driver.h              RTCore64.sys PPL bypass driver
├── PhantomKiller_bin.h       PhantomKiller.sys embedded binary
├── PhantomKiller_base64.h    PhantomKiller.sys Base64 encoding
├── RTCore64_base64.h         RTCore64.sys Base64 encoding
├── syscalls.h                Indirect syscalls
├── signature_protection.h    Full DMSP (with signature verification)
├── signature_protection_nocert.h  Open-source DMSP (no certificate)
├── CMDPLUS.vcxproj           MSBuild project file
├── README.md                 简体中文说明
├── README_en.md              English Documentation
└── CMDPLUS26.7.7_KERNEL_DRIVER_2.bat  Startup batch file
```


---

#### DMSP Protection Details

CMDPLUS embeds DMSP (Distributed Multi-Layer Signature Protection), an ~5400-line single-file C++17 header protection system, providing:

- **Static protection**: Digital signature verification, code integrity CRC32C checks, anti-compile-time patch
- **Dynamic protection**: Anti-debug detection (13 methods with weighted voting), API hook detection, memory anomaly scanning
- **Process protection**: PPL marking, BreakOnTermination, Job Object, Watchdog thread
- **Kernel protection**: KUSER_SHARED_DATA direct-read cross-validation
- **Obfuscation**: Function pointer encryption, opaque predicates, state-machine dispatcher



---

---

**Disclaimer:** This tool is distributed under the Apache 2.0 open-source license and is intended for educational and research purposes only. The author assumes no responsibility for any system damage, data loss or leakage, or violation of local laws resulting from the use of this tool. By using this tool, you acknowledge and agree to assume all risks.
