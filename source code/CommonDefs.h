#pragma once
#ifndef COMMON_DEFS_H
#define COMMON_DEFS_H

// ============================================================================
// CommonDefs.h — 共享类型、结构、函数指针与辅助工具定义
//   供 CMDPLUS.cpp 及其他模块统一引用
//   编译目标: _WIN32_WINNT=0x0601 (Windows 7), C++17
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
// winsock2.h MUST be before windows.h
#include <winsock2.h>

// Windows SDK polyfills for _WIN32_WINNT=0x0601
#ifndef PROCESS_ACTIVITY_MODERATION_CURRENT_VERSION
#define PROCESS_ACTIVITY_MODERATION_CURRENT_VERSION 0x00000001
#endif
#ifndef PROCESS_ACTIVITY_MODERATION_ENABLE
#define PROCESS_ACTIVITY_MODERATION_ENABLE 0x00000001
#endif
#ifndef PROCESS_VIRTUALIZATION_BASED_SECURITY_ENABLE
#define PROCESS_VIRTUALIZATION_BASED_SECURITY_ENABLE 0x00000001
#endif
#ifndef PROCESS_VIRTUALIZATION_BASED_SECURITY_ISOLATION
#define PROCESS_VIRTUALIZATION_BASED_SECURITY_ISOLATION 0x00000002
#endif
#pragma warning(disable:4996)

#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <imagehlp.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#include <ntstatus.h>
#include <commctrl.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <shellapi.h>

#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <functional>
#include <random>
#include <chrono>
#include <thread>
#include <atomic>
#include <algorithm>
#include <malloc.h>
#include <intrin.h>
#include <filesystem>

// ============================================================================
// 链接必要的库
// ============================================================================
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "imagehlp.lib")

// ============================================================================
// NT 基础类型定义 (Win7 SDK polyfill)
//   使用 _WINTERNL_ 守卫避免与已包含 winternl.h 的新 SDK 冲突
// ============================================================================

#ifndef _WINTERNL_
#if !defined(_NTDEF_)
typedef LONG NTSTATUS;
#endif

#ifndef NTAPI
#define NTAPI __stdcall
#endif

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PVOID ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

// ============================================================================
// PEB 结构
// ============================================================================

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PVOID Ldr;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID SparePtr1;
    PVOID SparePtr2;
    ULONG SpareLong1;
    ULONG SpareLong2;
    PVOID SpareLong3;
    PVOID SparePtr3;
    ULONG EnvironmentUpdateCount;
    PVOID* KernelCallbackTable;
    PVOID ReadOnlySharedMemoryBase;
    PVOID HotpatchInformation;
    PVOID* ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    SIZE_T HeapSegmentReserve;
    SIZE_T HeapSegmentCommit;
    SIZE_T HeapDeCommitTotalFreeThreshold;
    SIZE_T HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID* ProcessHeaps;
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;
    PVOID LoaderLock;
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubSystem;
    ULONG ImageSubSystemMajorVersion;
    ULONG ImageSubSystemMinorVersion;
    ULONG GdiHandleBuffer[34];
    ULONG PostProcessInitRoutine;
    ULONG SessionId;
} PEB, *PPEB;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

// ============================================================================
// SYSTEM_INFORMATION_CLASS 枚举
// ============================================================================

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemProcessorPerformanceInformation = 8,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemCurrentTimeZoneInformation = 44,
    SystemLookasideInformation = 45,
    SystemCrashDumpInformation = 46,
    SystemBigPoolInformation = 66,
    SystemSessionBigPoolInformation = 73,
    SystemObjectPoolInformation = 77,
    SystemFileCacheInformation = 91,
    SystemPoolTagInformation = 94,
    SystemInterruptCpuGicInformation = 101,
    SystemKernelDebuggerInformation = 118,
    SystemExceptionChainInformation = 121,
    SystemPolicyInformation = 134,
    SystemBigPoolEntryInformation = 180,
    MaxSystemInfoClass = 256
} SYSTEM_INFORMATION_CLASS;

// ============================================================================
// PROCESS_BASIC_INFORMATION
// ============================================================================

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG AffinityMask;
    LONG BasePriority;
    ULONG UniqueProcessId;
    ULONG InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

// ============================================================================
// PROCESSINFOCLECTION 枚举
// ============================================================================

typedef enum _PROCESSINFOCLECTION {
    ProcessBasicInformation,
    ProcessQuotaLimits,
    ProcessIoCounters,
    ProcessVmCounters,
    ProcessTimes,
    ProcessBasePriority,
    ProcessRaisePriority,
    ProcessDebugPort,
    ProcessExceptionPort,
    ProcessAccessToken,
    ProcessLdtInformation,
    ProcessLdtSize,
    ProcessDefaultHardErrorMode,
    ProcessIoPortHandlers,
    ProcessPooledUsageAndLimits,
    ProcessWorkingSetWatch,
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup,
    ProcessPriorityClass,
    ProcessWxeVersion,
    ProcessShadowStackInformation,
    MaxProcessInfoClass
} PROCESSINFOCLECTION;

// ============================================================================
// NT 辅助宏
// ============================================================================

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#ifndef OBJ_KERNEL_HANDLE
#define OBJ_KERNEL_HANDLE 0x00000002L
#endif

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = (r); \
    (p)->ObjectName = (n); \
    (p)->Attributes = (a); \
    (p)->SecurityDescriptor = (s); \
    (p)->SecurityQualityOfService = NULL; \
}
#endif

#endif // _WINTERNL_

// PCLIENT_ID 类型 — 某些 SDK 版本中未定义此指针类型，需手动补充
#ifndef PCLIENT_ID
#define PCLIENT_ID PCLIENT_ID
typedef struct _CLIENT_ID *PCLIENT_ID;
#endif

// ============================================================================
// 错误检查宏
// ============================================================================

#define CHECK_OPERATION(operation, error_message) \
    if (!(operation)) { \
        DWORD error = GetLastError(); \
        std::wcerr << L"错误: " << error_message << L" (错误代码: " << error << L")" << std::endl; \
        return false; \
    }

#define CHECK_OPERATION_VOID(operation, error_message) \
    if (!(operation)) { \
        DWORD error = GetLastError(); \
        std::wcerr << L"错误: " << error_message << L" (错误代码: " << error << L")" << std::endl; \
        return; \
    }

#define CHECK_HR(hr, error_message) \
    if (FAILED(hr)) { \
        std::wcerr << L"错误: " << error_message << L" (HRESULT: 0x" << std::hex << hr << std::dec << L")" << std::endl; \
        return false; \
    }

#define CHECK_HR_VOID(hr, error_message) \
    if (FAILED(hr)) { \
        std::wcerr << L"错误: " << error_message << L" (HRESULT: 0x" << std::hex << hr << std::dec << L")" << std::endl; \
        return; \
    }

// ============================================================================
// 前向声明
// ============================================================================

class ProcessTerminator;

// ============================================================================
// Windows 版本 polyfill: PROCESS_INFORMATION_CLASS 枚举值
//   仅当 SDK 未声明时 polyfill
// ============================================================================

#ifndef ProcessActivityModeration
// Win8 引入, Win7 SDK 未声明. 值 = 44
#define ProcessActivityModeration static_cast<PROCESS_INFORMATION_CLASS>(44)
#endif

#ifndef ProcessVirtualizationBasedSecurity
// Win10 引入. 值 = 61
#define ProcessVirtualizationBasedSecurity static_cast<PROCESS_INFORMATION_CLASS>(61)
#endif

// ============================================================================
// 自定义进程信息结构
// ============================================================================

typedef struct _PROCESS_ACTIVITY_MODERATION {
    DWORD Version;
    DWORD Flags;
    DWORD ExemptionTimeMs;
} PROCESS_ACTIVITY_MODERATION, * PPROCESS_ACTIVITY_MODERATION;

typedef struct _PROCESS_VIRTUALIZATION_BASED_SECURITY {
    DWORD Flags;
} PROCESS_VIRTUALIZATION_BASED_SECURITY, * PPROCESS_VIRTUALIZATION_BASED_SECURITY;

#ifndef PROCESS_VAULT_INFORMATION_DEFINED
#define PROCESS_VAULT_INFORMATION_DEFINED
typedef struct _PROCESS_VAULT_INFORMATION {
    ULONG_PTR VaultHandle;
} PROCESS_VAULT_INFORMATION, * PPROCESS_VAULT_INFORMATION;
#endif

// ============================================================================
// 内核函数指针类型 (_NtXxx)
// ============================================================================

typedef NTSTATUS(NTAPI* _NtSetInformationProcess)(
    HANDLE ProcessHandle,
    PROCESS_INFORMATION_CLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength
    );

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* _NtTerminateProcess)(
    HANDLE ProcessHandle,
    NTSTATUS ExitStatus
    );

typedef NTSTATUS(NTAPI* _RtlAdjustPrivilege)(
    ULONG Privilege,
    BOOLEAN Enable,
    BOOLEAN CurrentThread,
    PBOOLEAN Enabled
    );

typedef NTSTATUS(NTAPI* _NtSuspendProcess)(
    HANDLE ProcessHandle
    );

typedef NTSTATUS(NTAPI* _NtResumeProcess)(
    HANDLE ProcessHandle
    );

typedef NTSTATUS(NTAPI* _NtGetNextProcess)(
    HANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Flags,
    PHANDLE NewProcessHandle
    );

typedef NTSTATUS(NTAPI* _NtGetNextThread)(
    HANDLE ProcessHandle,
    HANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Flags,
    PHANDLE NewThreadHandle
    );

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESS_INFORMATION_CLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* _NtSetInformationThread)(
    HANDLE ThreadHandle,
    THREAD_INFORMATION_CLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
    );

typedef NTSTATUS(NTAPI* _NtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
    );

typedef NTSTATUS(NTAPI* _NtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
    );

typedef NTSTATUS(NTAPI* _NtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T WrittenBytes
    );

typedef NTSTATUS(NTAPI* _NtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

typedef NTSTATUS(NTAPI* _NtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
    );

typedef NTSTATUS(NTAPI* _NtClose)(
    HANDLE Handle
    );

// ============================================================================
// API 函数指针类型 (动态加载)
// ============================================================================

typedef BOOL(WINAPI* PSetProcessMitigationPolicy)(
    _In_ PROCESS_MITIGATION_POLICY MitigationPolicy,
    _In_ PVOID lpBuffer,
    _In_ SIZE_T dwLength
    );

typedef BOOL(WINAPI* PSetProcessValidCallTargets)(
    _In_ HANDLE hProcess,
    _In_ PVOID VirtualAddress,
    _In_ SIZE_T RegionSize,
    _In_ ULONG NumberOfOffsets,
    _In_ PCFG_CALL_TARGET_INFO OffsetInformation
    );

// ============================================================================
// SYSTEM_HANDLE 结构
// ============================================================================

typedef struct _SYSTEM_HANDLE {
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG NumberOfHandles;
    ULONG Reserved;
    SYSTEM_HANDLE Information[1];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

// ============================================================================
// PPL (Protected Process Light) 相关类型
// ============================================================================

typedef enum _PS_PROTECTED_TYPE {
    PsProtectedTypeNone = 0,
    PsProtectedTypeProtectedLight = 1,
    PsProtectedTypeProtected = 2
} PS_PROTECTED_TYPE;

typedef enum _PS_PROTECTED_SIGNER {
    PsProtectedSignerNone = 0,
    PsProtectedSignerAuthenticode = 1,
    PsProtectedSignerCodeGen = 2,
    PsProtectedSignerAntimalware = 3,
    PsProtectedSignerLsa = 4,
    PsProtectedSignerWindows = 5,
    PsProtectedSignerWinTcb = 6,
    PsProtectedSignerMax = 7
} PS_PROTECTED_SIGNER;

typedef struct _PS_PROTECTION {
    union {
        struct {
            UCHAR Signer : 3;
            UCHAR Type : 3;
            UCHAR Audit : 1;
            UCHAR Inherit : 1;
        };
        UCHAR Level;
    };
} PS_PROTECTION_ORIG, *PPS_PROTECTION_ORIG;

// PS_PROTECTION 结构体 (Windows 8+) - 用于 NtSetInformationProcess
typedef struct _PS_PROTECTION_V2 {
    UCHAR Type;
    UCHAR Audit;
    UCHAR Protection;
} PS_PROTECTION_V2, *PPS_PROTECTION_V2;

// ============================================================================
// 内核 API 函数指针类型
// ============================================================================

typedef struct _EPROCESS EPROCESS, *PEPROCESS;

typedef NTSTATUS(NTAPI* _PsTerminateProcess)(
    PEPROCESS Process,
    NTSTATUS ExitStatus
    );

typedef NTSTATUS(NTAPI* _PsLookupProcessByProcessId)(
    HANDLE ProcessId,
    PEPROCESS* Process
    );

typedef NTSTATUS(NTAPI* _ObDereferenceObject)(
    PVOID Object
    );

// ============================================================================
// DMSPObf 命名空间 — 反编译期补丁检测 (fragment B & D)
//   编译时常量分片, 分布在 .data / .rdata 段
// ============================================================================

namespace DMSPObf {
    // 分片 B: 在 .data 段 (可读写, 攻击者用 WriteProcessMemory 可改)
    inline volatile uint32_t g_dmspDevFragB = 0xA5A5A5A5u;
    // 分片 D: 在 .rdata 段 (通常 PE 加载后为只读, 攻击者需先 VirtualProtect)
    //   constexpr 强制编译器把它放在 .rdata, 不可写
    constexpr uint32_t g_dmspDevFragD = 0xA5A5A5A5u;
}

// ============================================================================
// 字符串转换辅助函数
// ============================================================================

inline std::string WideToMultiByte(const std::wstring& wideStr) {
    int bufferSize = WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (bufferSize == 0) return "";

    std::vector<char> buffer(bufferSize);
    WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), -1, buffer.data(), bufferSize, nullptr, nullptr);
    return std::string(buffer.data());
}

inline std::wstring MultiByteToWide(const std::string& multiByteStr) {
    int bufferSize = MultiByteToWideChar(CP_UTF8, 0, multiByteStr.c_str(), -1, nullptr, 0);
    if (bufferSize == 0) return L"";

    std::vector<wchar_t> buffer(bufferSize);
    MultiByteToWideChar(CP_UTF8, 0, multiByteStr.c_str(), -1, buffer.data(), bufferSize);
    return std::wstring(buffer.data());
}

// NarrowToWide — MultiByteToWide 的别名
inline std::wstring NarrowToWide(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    if (size_needed <= 0) return std::wstring();
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstr[0], size_needed);
    return wstr;
}

// ============================================================================
// RAII 句柄包装器
// ============================================================================

struct HandleDeleter {
    void operator()(HANDLE handle) const {
        if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
        }
    }
};

using HandlePtr = std::unique_ptr<void, HandleDeleter>;

struct ServiceHandleDeleter {
    void operator()(SC_HANDLE handle) const {
        if (handle != nullptr) {
            CloseServiceHandle(handle);
        }
    }
};

using ServiceHandlePtr = std::unique_ptr<typename std::remove_pointer<SC_HANDLE>::type, ServiceHandleDeleter>;

// ============================================================================
// WindowsException 异常类
// ============================================================================

class WindowsException : public std::runtime_error {
public:
    WindowsException(const std::string& message, DWORD errorCode = GetLastError())
        : runtime_error(message + " (Error: " + std::to_string(errorCode) + ")"), errorCode(errorCode) {
    }

    DWORD getErrorCode() const { return errorCode; }

private:
    DWORD errorCode;
};

// ============================================================================
// 辅助函数
// ============================================================================

inline void EnablePrivilege(const std::wstring& privilegeName) {
    HandlePtr hToken(nullptr);
    HANDLE rawToken;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &rawToken)) {
        throw WindowsException("OpenProcessToken failed");
    }
    hToken.reset(rawToken);

    LUID luid;
    if (!LookupPrivilegeValueW(nullptr, privilegeName.c_str(), &luid)) {
        throw WindowsException("LookupPrivilegeValue failed");
    }

    TOKEN_PRIVILEGES tp = { 0 };
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken.get(), FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
        throw WindowsException("AdjustTokenPrivilege failed");
    }
}

inline DWORD GetProcessIdByName(const std::wstring& processName) {
    HandlePtr hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (hSnapshot.get() == INVALID_HANDLE_VALUE) {
        throw WindowsException("CreateToolhelp32Snapshot failed");
    }

    PROCESSENTRY32W pe = { 0 };
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot.get(), &pe)) {
        throw WindowsException("Process32First failed");
    }

    do {
        if (_wcsicmp(pe.szExeFile, processName.c_str()) == 0) {
            return pe.th32ProcessID;
        }
    } while (Process32NextW(hSnapshot.get(), &pe));

    throw std::runtime_error("process not found: " + WideToMultiByte(processName));
}

// ============================================================================
// Windows 版本检测函数
//   使用 RtlGetVersion 获取真实版本号 (GetVersionExW 在 Win8.1+ 返回虚假值)
//   RtlGetVersion 在所有 Windows 版本 (包括 Win7) 上均可用
// ============================================================================

inline bool IsWindowsVersionOrLater(ULONG major, ULONG minor) {
    typedef NTSTATUS (NTAPI* _RtlGetVersion)(PRTL_OSVERSIONINFOW);
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;

    auto pRtlGetVersion = (_RtlGetVersion)GetProcAddress(hNtdll, "RtlGetVersion");
    if (!pRtlGetVersion) return false;

    RTL_OSVERSIONINFOEXW osvi = { 0 };
    osvi.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);
    pRtlGetVersion((PRTL_OSVERSIONINFOW)&osvi);

    return (osvi.dwMajorVersion > major) ||
           (osvi.dwMajorVersion == major && osvi.dwMinorVersion >= minor);
}

inline bool IsWindowsVistaOrLater() { return IsWindowsVersionOrLater(6, 0); }
inline bool IsWindows7OrLater()   { return IsWindowsVersionOrLater(6, 1); }
inline bool IsWindows8OrLater()   { return IsWindowsVersionOrLater(6, 2); }
inline bool IsWindows10OrLater()  { return IsWindowsVersionOrLater(10, 0); }

// ============================================================================
// WTS API 函数指针类型 (动态加载以支持 Win7)
// ============================================================================

typedef BOOL(WINAPI* PFN_WTSQueryUserToken)(ULONG, PHANDLE);
typedef BOOL(WINAPI* PFN_WTSEnumerateSessionsW)(HANDLE, DWORD, DWORD, PWTS_SESSION_INFOW*, PDWORD);
typedef void (WINAPI* PFN_WTSFreeMemory)(PVOID);
typedef BOOL(WINAPI* PFN_WTSGetActiveConsoleSessionId)(void);

// CreateProcessWithTokenW 函数指针类型 (Win7 SP1 需要 KB2533623)
typedef BOOL(WINAPI* PFN_CreateProcessWithTokenW)(
    HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR,
    LPSTARTUPINFOW, LPPROCESS_INFORMATION);

// CreateProcessAsUserW 函数指针类型 (替代方案)
typedef BOOL(WINAPI* PFN_CreateProcessAsUserW)(
    HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

// --- polyfill: FileDispositionInfoEx (Win10 1607+ RS1) ---
#ifndef FileDispositionInfoEx
// SDK 10.0.26100 在 _WIN32_WINNT=0x0601 下未声明
// 值 = 21
#define FileDispositionInfoEx ((FILE_INFO_BY_HANDLE_CLASS)21)
#endif

// --- polyfill: WINTRUST_SIGNATURE_SETTINGS (Win8+) ---
#ifndef WINTRUST_SIGNATURE_SETTINGS_DEFINED
#define WINTRUST_SIGNATURE_SETTINGS_DEFINED
typedef struct _WINTRUST_SIGNATURE_SETTINGS_ {
    DWORD cbStruct;
    DWORD dwIndex;
    DWORD dwFlags;
    DWORD cSecondarySigs;
    DWORD dwVerifiedSigIndex;
    PCERT_STRONG_SIGN_PARA pCryptoPolicy;
} WINTRUST_SIGNATURE_SETTINGS, *PWINTRUST_SIGNATURE_SETTINGS;
#endif

// --- polyfill: SetProcessInformation 函数指针 (Win8+, 动态加载) ---
using FnSetProcessInformation = BOOL(WINAPI*)(
    _In_ HANDLE hProcess,
    _In_ PROCESS_INFORMATION_CLASS ProcessInformationClass,
    _In_reads_bytes_(ProcessInformationSize) LPVOID ProcessInformation,
    _In_ DWORD ProcessInformationSize);

// --- polyfill: SetProcessMitigationPolicy 函数指针 (Win8+, 动态加载) ---
using FnSetProcessMitigationPolicy = BOOL(WINAPI*)(

    _In_ PROCESS_MITIGATION_POLICY MitigationPolicy,
    _In_ PVOID lpBuffer,
    _In_ SIZE_T dwLength);

// 强制置顶功能全局状态 (定义于 CMDPLUS.cpp，全项目共享单一实例)
extern bool g_alwaysOnTopEnabled;
extern std::thread g_alwaysOnTopThread;
extern HWND g_targetTopmostWindow;
extern std::wstring g_targetWindowClass;
extern std::wstring g_targetWindowTitle;
extern WINDOWPLACEMENT g_originalPlacement;
extern bool g_hasOriginalPlacement;
extern volatile LONG g_topmostFightMode;

// 强制置顶 — 启动/停止 (增强版定义于 CMDPLUS.cpp)
void StartAlwaysOnTop();
void StopAlwaysOnTop();

#endif // COMMON_DEFS_H
