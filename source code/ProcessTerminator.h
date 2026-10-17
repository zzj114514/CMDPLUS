#pragma once
#ifndef PROCESSTERMINATOR_H
#define PROCESSTERMINATOR_H

// ============================================================================
// ProcessTerminator.h — ProcessTerminator 类声明
//   进程终止工具类的完整声明，包含多种终止策略、嵌套 COM/Firewall 辅助类、
//   以及 Native API 函数指针的动态加载机制。
//   编译目标: _WIN32_WINNT=0x0601 (Windows 7), C++17
// ============================================================================

#include "CommonDefs.h"

#include <string>
#include <vector>
#include <set>
#include <map>
#include <memory>
#include <functional>
#include <thread>
#include <chrono>
#include <comdef.h>
#include <netfw.h>

// DMSP_VERIFY_INT / DMSP_VERIFY_FRAG 由 signature_protection.h 提供
// 该宏在编译期检测 .data 与 .rdata 段的分片完整性, 防止攻击者 patch 关键控制流
// ProcessTerminator.cpp 中会 #include "signature_protection.h"

// ============================================================================
// ProcessTerminator 类
// ============================================================================

class ProcessTerminator {
private:
    // ---- 私有辅助方法 ----
    static HANDLE OpenProcessWithMaximumAccess(DWORD pid);
    static HANDLE OpenProcessWithDuplicate(DWORD pid);
    static HANDLE OpenProcessWithDebugPrivilege(DWORD pid);
    static HANDLE OpenProcessWithNativeAPI(DWORD pid);
    static HANDLE OpenProcessWithTokenReplacement(DWORD pid);
    static HANDLE OpenProcessWithHandleEnumeration(DWORD pid);
    static HANDLE OpenProcessWithKernelExploitation(DWORD pid);
    static HANDLE OpenProcessWithDriver(DWORD pid);  // 方法7.5: 通过驱动读取 EPROCESS 提权至 SYSTEM
    static HANDLE OpenProcessWithCsrss(DWORD pid);
    static HANDLE OpenProcessWithWMI(DWORD pid);
    static HANDLE OpenProcessWithJobObject(DWORD pid);
    static HANDLE OpenProcessWithToolhelp(DWORD pid);
    static HANDLE OpenProcessWithProcessHint(DWORD pid);
    static HANDLE OpenProcessWithDebugObject(DWORD pid);
    static HANDLE OpenProcessWithRtlAdjustPrivilege(DWORD pid);
    static HANDLE OpenProcessWithThreadHijack(DWORD pid);
    static HANDLE OpenProcessWithMemoryMap(DWORD pid);
    static HANDLE OpenProcessWithNtQueryProcess(DWORD pid);
    static bool IsAccessDenied(DWORD error);
    static bool terminateByTaskManagerMethod(const std::string& processName);

    // ---- 进程隔离与阻止 ----
    static bool terminateByProcessIsolationAndBlocking(const std::string& processName);
    static PSID GetLowIntegritySid();
    static void BlockCriticalSystemTools(DWORD targetPid);
    static void BlockProcessHandleAccess(DWORD targetPid);
    static bool HasProcessAccessedTarget(DWORD checkerPid, DWORD targetPid);
    static void ApplyProcessMitigationPolicies(HANDLE hProcess);

    // ---- Native API 函数指针 (私有) ----
    static _NtQuerySystemInformation NtQuerySystemInformation;
    static _RtlAdjustPrivilege RtlAdjustPrivilege;
    static _NtResumeProcess NtResumeProcess;
    static _NtGetNextProcess NtGetNextProcess;
    static _NtGetNextThread NtGetNextThread;
    static _NtSetInformationProcess NtSetInformationProcess;
    static _NtQueryInformationProcess NtQueryInformationProcess;
    static _NtSetInformationThread NtSetInformationThread;
    static _NtCreateThreadEx NtCreateThreadEx;
    static _NtDuplicateObject NtDuplicateObject;
    static _NtClose NtClose;

    static bool IsProcessMonitoringOther(DWORD monitorPid, DWORD targetPid);
    static void SuspendProcess(HANDLE hProcess);
    static void StripProcessPrivileges(HANDLE hProcess);
    static bool GetProcessHandles(HANDLE hSnapshot, std::vector<SYSTEM_HANDLE>& handles);

    // ---- 嵌套类: COM 初始化 RAII ----
    class COMInitializer {
    public:
        COMInitializer() : initialized_(false) {
            HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
            if (SUCCEEDED(hr)) {
                initialized_ = true;
            }
        }

        ~COMInitializer() {
            if (initialized_) {
                CoUninitialize();
            }
        }

        bool IsInitialized() const { return initialized_; }

    private:
        bool initialized_;
    };

    // ---- 嵌套类: 防火墙规则管理器 (仅声明) ----
    struct FirewallRuleManager {
        static bool CreateBlockRule(const wchar_t* ruleName, const wchar_t* processPath);
        static bool DeleteFirewallRule(const wchar_t* ruleName);
    };

    // 检查文件是否有微软数字签名
    static bool ClearCriticalProcessFlag(int pid);

    // 通过Vectored Exception Handling实现权限提升
    static bool terminateByVectoredException(const std::string& processName);

    // 使用硬件断点技术
    static bool terminateByHardwareBreakpoint(const std::string& processName);

    // 通过服务检测和停止进程
    static bool terminateByServiceDetection(const std::string& processName);

    // 通过内存映射文件共享内核数据
    static bool terminateByMemoryMapping(const std::string& processName);

    // 利用进程间通信的特殊通道
    static bool terminateBySpecialIPC(const std::string& processName);

public:
    static HANDLE OpenProcessEnhanced(DWORD pid, DWORD desiredAccess = PROCESS_ALL_ACCESS);

    // ---- 获取进程的可执行文件路径 (内联) ----
    static std::wstring GetProcessPath(DWORD pid) {
        HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
        if (!hProcess) {
            return L"";
        }

        wchar_t path[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
            CloseHandle(hProcess);
            return path;
        }

        CloseHandle(hProcess);
        return L"";
    }

    // ---- 公开的Native API相关成员 ----
    static bool initNativeAPI() { return initNativeAPIImpl(); }
    static bool EnableAllPrivileges();
    static _NtTerminateProcess NtTerminateProcess;
    static _NtSuspendProcess NtSuspendProcess;
    static _NtOpenProcess NtOpenProcess;
    static _NtWriteVirtualMemory NtWriteVirtualMemory;
    static _NtAllocateVirtualMemory NtAllocateVirtualMemory;

    // ---- Native API 动态初始化 (内联, 单次初始化) ----
    static bool initNativeAPIImpl() {
        static bool initialized = false;
        if (initialized) return true;

#ifdef _WIN32
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return false;

        NtSetInformationProcess = (_NtSetInformationProcess)GetProcAddress(ntdll, "NtSetInformationProcess");
        NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
        NtTerminateProcess = (_NtTerminateProcess)GetProcAddress(ntdll, "NtTerminateProcess");
        RtlAdjustPrivilege = (_RtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
        NtSuspendProcess = (_NtSuspendProcess)GetProcAddress(ntdll, "NtSuspendProcess");
        NtResumeProcess = (_NtResumeProcess)GetProcAddress(ntdll, "NtResumeProcess");
        NtGetNextProcess = (_NtGetNextProcess)GetProcAddress(ntdll, "NtGetNextProcess");
        NtGetNextThread = (_NtGetNextThread)GetProcAddress(ntdll, "NtGetNextThread");
        NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
        NtSetInformationThread = (_NtSetInformationThread)GetProcAddress(ntdll, "NtSetInformationThread");
        NtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
        NtOpenProcess = (_NtOpenProcess)GetProcAddress(ntdll, "NtOpenProcess");
        NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(ntdll, "NtWriteVirtualMemory");
        NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
        NtDuplicateObject = (_NtDuplicateObject)GetProcAddress(ntdll, "NtDuplicateObject");
        NtClose = (_NtClose)GetProcAddress(ntdll, "NtClose");

        initialized = (NtSetInformationProcess != nullptr) &&
            (NtQuerySystemInformation != nullptr) &&
            (NtTerminateProcess != nullptr) &&
            (RtlAdjustPrivilege != nullptr) &&
            (NtSuspendProcess != nullptr) &&
            (NtResumeProcess != nullptr) &&
            (NtGetNextProcess != nullptr) &&
            (NtGetNextThread != nullptr) &&
            (NtQueryInformationProcess != nullptr) &&
            (NtSetInformationThread != nullptr) &&
            (NtCreateThreadEx != nullptr) &&
            (NtOpenProcess != nullptr) &&
            (NtWriteVirtualMemory != nullptr) &&
            (NtDuplicateObject != nullptr) &&
            (NtClose != nullptr);
#endif
        return initialized;
    }

    // ---- 带 SEH 保护的 NtQuerySystemInformation (声明, 实现在 .cpp) ----
    static NTSTATUS SafeNtQuerySystemInformation(
        SYSTEM_INFORMATION_CLASS infoClass,
        PVOID buffer,
        ULONG bufferSize,
        PULONG returnLength);

    // ---- 高危方法 - 内核级进程终止 ----
    static bool terminateByImageSignatureEnforcement(const std::string& processName);
    static bool terminateByCodeIntegrityViolation(const std::string& processName);
    static bool terminateByExtendedPolicyFramework(const std::string& processName);
    static bool terminateByMemoryPartitionCorruption(const std::string& processName);
    static bool terminateByThreadPoolInfrastructure(const std::string& processName);
    static bool terminateByExceptionChainCorruption(const std::string& processName);
    static bool terminateBySecuritySubsystemBypass(const std::string& processName);
    static bool terminateByVirtualizationInfrastructure(const std::string& processName);
    static bool terminateByKernelMemoryManipulation(const std::string& processName);
    static bool terminateByAdvancedIsolation(const std::string& processName);
    static bool terminateByPracticalRing0Call(const std::string& processName);
    static bool terminateByPhantomKiller(const std::string& processName);

    // ---- 挂起进程 (内联) ----
    static bool SuspendProcessNative(HANDLE hProcess) {
        if (!initNativeAPI() || !NtSuspendProcess) {
            return false;
        }
        NTSTATUS status = NtSuspendProcess(hProcess);
        return NT_SUCCESS(status);
    }

    // ---- 常规方法 ----
    static bool terminateByProcessName(const std::string& processName);
    static bool terminateByPID(int pid) {
#ifdef _WIN32
        try {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (hProcess == NULL) return false;

            bool result = TerminateProcess(hProcess, 0);
            CloseHandle(hProcess);
            return result;
        }
        catch (...) {
            return false;
        }
#else
        try {
            return kill(pid, SIGTERM) == 0;
        }
        catch (...) {
            return false;
        }
#endif
    }

    // ---- 新增的5种冷门方法 ----
    static bool terminateByProcessIsolationAndAPIDisruption(const std::string& processName);
    static bool terminateByProcessEnergyManagement(const std::string& processName);
    static bool terminateByProcessStateExtension(const std::string& processName);
    static bool terminateByProcessFaultTolerance(const std::string& processName);
    static bool terminateByProcessActivityModeration(const std::string& processName);
    static bool terminateByProcessVirtualizationBasedSecurity(const std::string& processName);
    static bool terminateByProcessVault(const std::string& processName);
    static bool terminateByProcessDynamicCodePolicy(const std::string& processName);
    static bool terminateByProcessControlFlowGuard(const std::string& processName);
    static bool terminateByProcessSignaturePolicy(const std::string& processName);
    static bool terminateByHandleInheritance(const std::string& processName);
    static bool terminateByMemoryZeroing(const std::string& processName);
    static bool terminateByThreadHijacking(const std::string& processName);
    static bool terminateByExceptionInjection(const std::string& processName);
    static bool terminateByMessageFlooding(const std::string& processName);
    static bool terminateByGDIExhaustion(const std::string& processName);
    static bool terminateByProcessTree(const std::string& processName);
    static bool terminateByTokenReplacement(const std::string& processName);
    static bool terminateByAPCInjection(const std::string& processName);
    static bool terminateBySystemCommand(const std::string& processName);

    // ---- 非常规方法 ----
    static bool terminateByParentChildRelationship(const std::string& processName);
    static bool terminateByResourceExhaustion(const std::string& processName);
    static bool terminateByWindowHandle(const std::string& processName);
    static bool terminateByDirectMemoryZeroing(const std::string& processName);
    static bool terminateByProcessInjection(const std::string& processName);
    static bool terminateByDebugging(const std::string& processName);
    static bool terminateByTimedKill(const std::string& processName);
    static bool terminateByPriorityManipulation(const std::string& processName);
    static bool terminateByProcessHollowing(const std::string& processName);

    // ---- 未公开API方法 ----
    static bool terminateByNativeAPI(const std::string& processName);
    static bool terminateByHandleEnumeration(const std::string& processName);
    static bool terminateByMemoryPatching(const std::string& processName);

    // ---- OB回调方法 ----
    static bool terminateByObCallbacks(const std::string& processName);
    static bool terminateByProcessObjectManipulation(const std::string& processName);
    static bool terminateBySecurityDescriptorModification(const std::string& processName);

    // ---- WMI方法 ----
    static bool terminateByWMI(const std::string& processName);

    static bool terminateByCriticalProcessFlag(const std::string& processName);
    static bool terminateByProcessIsolation(const std::string& processName);
    static bool terminateByMemoryCorruption(const std::string& processName);
    static bool terminateByHandleCloning(const std::string& processName);
    static bool terminateByDesktopIsolation(const std::string& processName);
    static bool terminateByTokenPrivilegeRemoval(const std::string& processName);
    static bool terminateByRegistryModification(const std::string& processName);
    static bool terminateByServiceControl(const std::string& processName);
    static bool terminateByCOMObjectManipulation(const std::string& processName);
    static bool terminateByNetworkIsolation(const std::string& processName);
    static bool terminateByPowerManagement(const std::string& processName);
    static bool terminateByUIAutomation(const std::string& processName);
    static bool terminateByRandomizedMethods(const std::string& processName);

    // ---- 新增未公开API方法 ----
    static bool terminateByThreadSuspension(const std::string& processName);
    static bool terminateByProcessDebugPort(const std::string& processName);
    static bool terminateByProcessHandleTable(const std::string& processName);
    static bool terminateByProcessWorkingSet(const std::string& processName);
    static bool terminateByProcessPagePriority(const std::string& processName);
    static bool terminateByProcessIoPriority(const std::string& processName);
    static bool terminateByProcessCycleTime(const std::string& processName);
    static bool terminateByProcessCookie(const std::string& processName);

    // ---- 辅助函数 ----
    static std::vector<int> getPIDsByName(const std::string& processName);
    static bool enableDebugPrivilege();
    static bool isProcessCritical(int pid);
    static bool isProcessRunning(const std::string& processName);

    // ---- 同目录保护进程检测和结束功能 ----
    static bool IsMicrosoftSigned(const std::wstring& filePath);
    static std::wstring GetProcessDirectory(DWORD pid);
    static std::wstring GetCurrentProcessDirectory();
    static std::vector<std::pair<DWORD, std::wstring>> GetProcessesInSameDirectory(const std::wstring& targetDir);
    static bool IsSystemProcessWhitelisted(const std::wstring& processName);
    static bool TerminateSameDirectoryProtectors(const std::wstring& targetProcessPath, bool useAllMethods);

    // ---- 调用所有方法 ----
    static bool terminateByAllMethods(const std::string& processName);
    static bool terminateByProcessDepletion(const std::string& processName);
    static bool terminateByProcessAttach(const std::string& processName);
    static bool terminateByProcessDetach(const std::string& processName);
    static bool terminateByProcessFault(const std::string& processName);
    static bool terminateByProcessInterlock(const std::string& processName);

    // ---- PPL绕过功能 - 64位ShellCode ----
    static bool terminateByPPLBypass(const std::string& processName);
    static bool LoadKernelShellCode(PVOID shellcode, SIZE_T size);
    static bool ExecuteKernelShellCode(DWORD targetPid);

    // ---- 多进程终止方法 ----
    static bool terminateMultipleProcesses(const std::vector<std::string>& processNames);

    // ---- USB存储恢复功能 ----
    static bool RestoreUSBStorage();
    static bool EnableUSBDevice(const std::wstring& deviceInstanceId);
    static bool ClearUSBRegistryLimits();

    // ---- 键盘鼠标恢复功能 ----
    static bool RestoreInputDevices();
    static bool UnblockInput();
    static bool UnhookGlobalInputHooks();

    // ---- 全屏覆盖检测与对抗功能 ----
    static bool DetectAndRemoveFullscreenOverlays();
    static bool DetectDXGIOverlayWindows(std::vector<HWND>& overlayWindows);
    static bool DetectGDILayeredOverlay(std::vector<HWND>& overlayWindows);
    static bool RemoveFullscreenOverlay(HWND hwnd);
    static bool IsSuspiciousOverlayWindow(HWND hwnd);
};

#endif // PROCESSTERMINATOR_H
