// ============================================================================
// MainMenu.cpp — 主入口点与菜单系统
//   从 CMDPLUS.cpp 迁移的完整主菜单、主循环、进程保护初始化、
//   DMSP 验证、权限提升以及安装信息管理功能。
//   编译目标: _WIN32_WINNT=0x0601 (Windows 7), C++17
// ============================================================================

#define WIN32_LEAN_AND_MEAN

#include "CommonDefs.h"
#include "ProcessTerminator.h"
#include "ProcessGuard.h"
#include "GarbageCleaner.h"
#include "PortMonitor.h"
#include "PortBlocker.h"
#include "AntiRemoteControl.h"
#include "AdvancedProcessCreator.h"
#include "signature_protection_nocert.h"

#include <sstream>
#include <iomanip>
#include <unordered_set>
#include <conio.h>
#include <comdef.h>
#include <aclapi.h>
#include <shlobj.h>
#include <process.h>

// ============================================================================
// 前向声明
// ============================================================================
static int MainEntry(int argc, char* argv[]);
static void Feature14Menu();
static void AutoCleanupAndExit();
static void DisableProtection();
static void AllowUserClose();
bool EnableProcessProtection(HANDLE hProcess);
static bool EnableEnhancedProtection();
static bool StartAutoVerify();

// ============================================================================
// 辅助函数
// ============================================================================
std::vector<std::string> splitString(const std::string& input, char delimiter) {
    std::vector<std::string> result;
    std::stringstream ss(input);
    std::string item;
    while (std::getline(ss, item, delimiter)) {
        item.erase(0, item.find_first_not_of(" \t\n\r\f\v"));
        item.erase(item.find_last_not_of(" \t\n\r\f\v") + 1);
        if (!item.empty()) {
            result.push_back(item);
        }
    }
    return result;
}

// ============================================================================
// 全局变量 — 窗口置顶功能
// ============================================================================
// 全局变量用于置顶功能（定义在 AdvancedProcessCreator.cpp）
extern bool g_alwaysOnTopEnabled;
bool g_hiddenMenuUnlocked = false;

// ============================================================================
// g_UnifiedSystemProcessWhitelist — 统一系统进程白名单 (大小写不敏感)
// ============================================================================
static const wchar_t* g_UnifiedSystemProcessWhitelist[] = {
    L"[System Process]", L"System", L"Secure System", L"Registry",
    L"Memory Compression", L"smss.exe", L"csrss.exe", L"wininit.exe",
    L"winlogon.exe", L"services.exe", L"lsass.exe", L"svchost.exe",
    L"dllhost.exe", L"fontdrvhost.exe",
    L"dwm.exe", L"explorer.exe", L"sihost.exe", L"taskhostw.exe",
    L"RuntimeBroker.exe", L"ShellHost.exe", L"conhost.exe", L"ctfmon.exe",
    L"LsaIso.exe", L"NgcIso.exe", L"smartscreen.exe",
    L"SearchHost.exe", L"SearchIndexer.exe", L"SearchProtocolHost.exe",
    L"SearchFilterHost.exe",
    L"WmiPrvSE.exe", L"WMIRegistrationService.exe", L"WmiApSrv.exe", L"unsecapp.exe",
    L"Widgets.exe", L"WidgetService.exe", L"UserOOBEBroker.exe",
    L"TextInputHost.exe", L"AggregatorHost.exe", L"backgroundTaskHost.exe",
    L"FileSyncHelper.exe", L"FileCoAuth.exe", L"OneDrive.exe",
    L"ImgLocalVisionModelHelper64.exe", L"WUDFHost.exe",
    L"wlanext.exe", L"NetSetupSvc.exe", L"WorkFolders.exe",
    L"SECOCL64.exe", L"SECOMN64.exe",
    L"IntelCpHDCPSvc.exe", L"igfxCUIServiceN.exe", L"igfxEMN.exe",
    L"igfxextN.exe", L"IntelGraphicsSoftware.Service.exe",
    L"IntelGraphicsSoftware.exe", L"OneApp.IGCC.WinService.exe",
    L"DisplayControlService.exe", L"DisplayControl.exe", L"PresentMonService.exe",
    L"IntelAudioService.exe", L"RstMwService.exe", L"jhi_service.exe",
    L"SurSvc.exe", L"TbtP2pShortcutService.exe", L"DSAService.exe",
    L"DSAUpdateService.exe", L"DSATray.exe", L"AppHelperCap.exe",
    L"DiagsCap.exe", L"NetworkCap.exe", L"SysInfoCap.exe",
    L"esrv.exe", L"esrv_svc.exe",
    L"RtkAudUService64.exe", L"cthelper.exe",
    L"SynTPEnhService.exe", L"SynTPEnh.exe", L"ELANFPService.exe",
    L"ChsIME.exe", L"TabTip.exe",
    L"spoolsv.exe",
    L"audiodg.exe", L"MidiSrv.exe",
    L"msedge.exe", L"msedgewebview2.exe", L"identity_helper.exe",
    L"elevation_service.exe", L"crashpad_handler.exe",
    L"vmtoolsd.exe", L"vmware-authd.exe", L"vmnetdhcp.exe",
    L"vmware-usbarbitrator64.exe", L"vmnat.exe", L"vmware-tray.exe",
    L"rundll32.exe", L"notepad.exe", L"cmd.exe", L"WindowsExplorer.exe",
    L"UsoClient.exe", L"MoUsoCoreWorker.exe", L"usocoreworker.exe",
    L"MusNotifyIcon.exe", L"TiWorker.exe", L"TrustedInstaller.exe", L"sppsvc.exe",
    L"CompatTelRunner.exe", L"dwminit.exe",
    L"dxdiag.exe",
    L"taskeng.exe", L"sdiagnhost.exe",
    L"rdpclip.exe", L"rdpinput.exe", L"RdpShell.exe",
    L"LanguageComponentsInstaller.exe",
    L"ApplicationFrameHost.exe", L"Calculator.exe",
    L"SettingSyncHost.exe", L"SystemSettings.exe",
    L"StartMenuExperienceHost.exe", L"SearchApp.exe", L"ShellExperienceHost.exe",
    L"vmms.exe", L"vmcompute.exe", L"Vmmem.exe", L"vmwp.exe",
    L"PrintDialog.exe",
    L"RecoveryDrive.exe", L"VSSVC.exe"
};
static const size_t g_WhitelistCount = sizeof(g_UnifiedSystemProcessWhitelist) / sizeof(g_UnifiedSystemProcessWhitelist[0]);

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

// ============================================================================
// DebugPrivilegeEnabler — 启用调试权限
// ============================================================================
class DebugPrivilegeEnabler {
public:
    static bool EnableAllDebugPrivileges() {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            std::cerr << "打开句柄错误：" << GetLastError() << std::endl;
            return false;
        }
        std::vector<std::wstring> privileges = {
            L"SeDebugPrivilege", L"SeSecurityPrivilege", L"SeBackupPrivilege",
            L"SeRestorePrivilege", L"SeSystemEnvironmentPrivilege",
            L"SeTakeOwnershipPrivilege", L"SeLoadDriverPrivilege"
        };
        bool allSuccess = true;
        for (const auto& priv : privileges) {
            if (!EnableSinglePrivilege(hToken, priv.c_str())) {
                allSuccess = false;
            }
        }
        CloseHandle(hToken);
        return allSuccess;
    }

private:
    static bool EnableSinglePrivilege(HANDLE hToken, LPCWSTR privilegeName) {
        LUID luid;
        if (!LookupPrivilegeValueW(nullptr, privilegeName, &luid)) {
            return false;
        }
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
            return false;
        }
        return GetLastError() != ERROR_NOT_ALL_ASSIGNED;
    }
};

// ============================================================================
// 智能识别 Edge / Chrome 路径
// ============================================================================
bool FindEdgePath(wchar_t* path, size_t pathSize) {
    const wchar_t* edgePaths[] = {
        L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
    };
    for (const wchar_t* ep : edgePaths) {
        if (wcsncmp(ep, L"%LOCALAPPDATA%", 15) == 0) {
            wchar_t expandedPath[MAX_PATH];
            ExpandEnvironmentStringsW(ep, expandedPath, MAX_PATH);
            if (GetFileAttributesW(expandedPath) != INVALID_FILE_ATTRIBUTES) {
                wcscpy_s(path, pathSize, expandedPath);
                return true;
            }
        } else {
            if (GetFileAttributesW(ep) != INVALID_FILE_ATTRIBUTES) {
                wcscpy_s(path, pathSize, ep);
                return true;
            }
        }
    }
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\msedge.exe",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t value[MAX_PATH];
        DWORD valueSize = sizeof(value);
        if (RegQueryValueExW(hKey, NULL, NULL, NULL, (LPBYTE)value, &valueSize) == ERROR_SUCCESS) {
            if (GetFileAttributesW(value) != INVALID_FILE_ATTRIBUTES) {
                wcscpy_s(path, pathSize, value);
                RegCloseKey(hKey);
                return true;
            }
        }
        RegCloseKey(hKey);
    }
    return false;
}

bool FindChromePath(wchar_t* path, size_t pathSize) {
    const wchar_t* chromePaths[] = {
        L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        L"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
        L"%LOCALAPPDATA%\\Google\\Chrome\\Application\\chrome.exe"
    };
    for (const wchar_t* cp : chromePaths) {
        if (wcsncmp(cp, L"%LOCALAPPDATA%", 15) == 0) {
            wchar_t expandedPath[MAX_PATH];
            ExpandEnvironmentStringsW(cp, expandedPath, MAX_PATH);
            if (GetFileAttributesW(expandedPath) != INVALID_FILE_ATTRIBUTES) {
                wcscpy_s(path, pathSize, expandedPath);
                return true;
            }
        } else {
            if (GetFileAttributesW(cp) != INVALID_FILE_ATTRIBUTES) {
                wcscpy_s(path, pathSize, cp);
                return true;
            }
        }
    }
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t value[MAX_PATH];
        DWORD valueSize = sizeof(value);
        if (RegQueryValueExW(hKey, NULL, NULL, NULL, (LPBYTE)value, &valueSize) == ERROR_SUCCESS) {
            if (GetFileAttributesW(value) != INVALID_FILE_ATTRIBUTES) {
                wcscpy_s(path, pathSize, value);
                RegCloseKey(hKey);
                return true;
            }
        }
        RegCloseKey(hKey);
    }
    return false;
}

// ============================================================================
// NtSetInformationProcess 函数指针
// ============================================================================
typedef NTSTATUS(NTAPI* NtSetInformationProcess_t)(HANDLE, ULONG_PTR, PVOID, ULONG);
static NtSetInformationProcess_t NtSetInformationProcessPtr = nullptr;

static bool LoadNtSetInformationProcess() {
    if (NtSetInformationProcessPtr) return true;
    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    if (hNtDll) {
        NtSetInformationProcessPtr = (NtSetInformationProcess_t)GetProcAddress(hNtDll, "NtSetInformationProcess");
        return NtSetInformationProcessPtr != nullptr;
    }
    return false;
}

// ============================================================================
// Job Object 进程保护
// ============================================================================
static bool ProtectProcessWithJobObject(HANDLE hProcess) {
    HANDLE hJob = CreateJobObjectW(NULL, NULL);
    if (!hJob) return false;

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {};
    jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli))) {
        CloseHandle(hJob);
        return false;
    }
    if (!AssignProcessToJobObject(hJob, hProcess)) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            return true;
        }
        CloseHandle(hJob);
        return false;
    }
    return true;
}

// ============================================================================
// 增强进程保护标志 / HiddenWindow / ConsoleCtrlHandler
// ============================================================================
static bool g_allowCloseByUser = false;
static HWND g_hHiddenWindow = nullptr;
static bool g_windowCloseIntercepted = false;

#define WM_CMDPLUS_TRAY (WM_APP + 100)

LRESULT CALLBACK HiddenWindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_CMDPLUS_TRAY) {
        if (lParam == WM_LBUTTONDOWN) {
            HWND hConsole = GetConsoleWindow();
            if (hConsole) {
                ShowWindow(hConsole, SW_SHOW);
                SetForegroundWindow(hConsole);
                BringWindowToTop(hConsole);
                SetFocus(hConsole);
            }
            return 0;
        }
        return 0;
    }
    if (msg == WM_CLOSE) {
        if (g_allowCloseByUser) {
            DisableProtection();
            return DefWindowProcW(hwnd, msg, wParam, lParam);
        }
        g_windowCloseIntercepted = true;
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static bool CreateHiddenCloseWindow() {
    if (g_hHiddenWindow) return true;
    HINSTANCE hInstance = GetModuleHandleW(NULL);
    WNDCLASSEXW wc = { sizeof(WNDCLASSEXW) };
    wc.lpfnWndProc = HiddenWindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"CMDPLUS_CloseGuard";
    if (!RegisterClassExW(&wc)) return false;
    g_hHiddenWindow = CreateWindowExW(0, L"CMDPLUS_CloseGuard", L"CMDPLUS",
        0, 0, 0, 0, 0, NULL, NULL, hInstance, NULL);
    return g_hHiddenWindow != NULL;
}

BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType) {
    if (dwCtrlType == CTRL_CLOSE_EVENT ||
        dwCtrlType == CTRL_LOGOFF_EVENT ||
        dwCtrlType == CTRL_SHUTDOWN_EVENT) {
        if (!g_allowCloseByUser) return TRUE;
    }
    return FALSE;
}

static bool RegisterConsoleCloseHandler() {
    return SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE) != 0;
}

void AllowUserClose() {
    g_allowCloseByUser = true;
    if (g_hHiddenWindow) {
        PostMessageW(g_hHiddenWindow, WM_CLOSE, 0, 0);
    }
}

// ============================================================================
// API HOOK — 原始函数指针
// ============================================================================
typedef void (NTAPI* ExitProcess_t)(UINT);
static ExitProcess_t OriginalExitProcess = nullptr;

typedef BOOL (WINAPI* TerminateProcess_t)(HANDLE, UINT);
static TerminateProcess_t OriginalTerminateProcess = NULL;

typedef NTSTATUS(NTAPI* NtTerminateProcess_t)(HANDLE, NTSTATUS);
static NtTerminateProcess_t NtTerminateProcessPtr = NULL;

typedef BOOL (WINAPI* PostMessageW_t)(HWND, UINT, WPARAM, LPARAM);
static PostMessageW_t OriginalPostMessageW = NULL;

void NTAPI HookedExitProcess(UINT uExitCode) {
    if (!g_allowCloseByUser) return;
    OriginalExitProcess(uExitCode);
}

BOOL WINAPI HookedTerminateProcess(HANDLE hProcess, UINT uExitCode) {
    if (hProcess == GetCurrentProcess() && !g_allowCloseByUser) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return OriginalTerminateProcess(hProcess, uExitCode);
}

NTSTATUS NTAPI HookedNtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus) {
    if (ProcessHandle == GetCurrentProcess() && !g_allowCloseByUser) {
        return 0xC0000022; // STATUS_ACCESS_DENIED
    }
    return NtTerminateProcessPtr(ProcessHandle, ExitStatus);
}

BOOL WINAPI HookedPostMessageW(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    if (Msg == WM_CLOSE && !g_allowCloseByUser) {
        HWND hConsole = GetConsoleWindow();
        if (hWnd == hConsole || hWnd == NULL) return 0;
    }
    return OriginalPostMessageW(hWnd, Msg, wParam, lParam);
}

// ============================================================================
// ProcessGuard 命名空间 — DACL + Job Object 保护
// ============================================================================
namespace ProcessGuard {

    static bool s_daclInstalled = false;
    HANDLE s_hJobObject = nullptr;
    DWORD s_selfPid = 0;

    static bool InstallProcessDACL() {
        PSID pSystemSid = nullptr, pSelfSid = nullptr, pAdminSid = nullptr;
        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
        if (!AllocateAndInitializeSid(&ntAuth, 1, SECURITY_LOCAL_SYSTEM_RID,
                0, 0, 0, 0, 0, 0, 0, &pSystemSid))
            return false;
        SID_IDENTIFIER_AUTHORITY ntAuth2 = SECURITY_NT_AUTHORITY;
        if (!AllocateAndInitializeSid(&ntAuth2, 2, SECURITY_BUILTIN_DOMAIN_RID,
                DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdminSid)) {
            FreeSid(pSystemSid);
            return false;
        }
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            FreeSid(pSystemSid); FreeSid(pAdminSid);
            return false;
        }
        DWORD tokenInfoSize = 0;
        GetTokenInformation(hToken, TokenUser, nullptr, 0, &tokenInfoSize);
        if (tokenInfoSize == 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            CloseHandle(hToken); FreeSid(pSystemSid); FreeSid(pAdminSid);
            return false;
        }
        std::vector<BYTE> tokenInfo(tokenInfoSize);
        if (!GetTokenInformation(hToken, TokenUser, tokenInfo.data(), tokenInfoSize, &tokenInfoSize)) {
            CloseHandle(hToken); FreeSid(pSystemSid); FreeSid(pAdminSid);
            return false;
        }
        CloseHandle(hToken);
        TOKEN_USER* pTokenUser = reinterpret_cast<TOKEN_USER*>(tokenInfo.data());
        pSelfSid = pTokenUser->User.Sid;

        // 构建 ACE 条目
        // SYSTEM: 完全控制
        EXPLICIT_ACCESS eaSystem = {};
        eaSystem.grfAccessPermissions = PROCESS_ALL_ACCESS;
        eaSystem.grfAccessMode = GRANT_ACCESS;
        eaSystem.grfInheritance = NO_INHERITANCE;
        eaSystem.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        eaSystem.Trustee.ptstrName = (LPTSTR)pSystemSid;

        // 自身: 完全控制
        EXPLICIT_ACCESS eaSelf = {};
        eaSelf.grfAccessPermissions = PROCESS_ALL_ACCESS;
        eaSelf.grfAccessMode = GRANT_ACCESS;
        eaSelf.grfInheritance = NO_INHERITANCE;
        eaSelf.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        eaSelf.Trustee.ptstrName = (LPTSTR)pSelfSid;

        // Administrators: 拒绝写访问和终止
        EXPLICIT_ACCESS eaAdminDeny = {};
        eaAdminDeny.grfAccessPermissions = PROCESS_CREATE_PROCESS | PROCESS_CREATE_THREAD |
            PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION |
            PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA | PROCESS_SUSPEND_RESUME |
            PROCESS_TERMINATE | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
            DELETE | WRITE_DAC | WRITE_OWNER;
        eaAdminDeny.grfAccessMode = DENY_ACCESS;
        eaAdminDeny.grfInheritance = NO_INHERITANCE;
        eaAdminDeny.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        eaAdminDeny.Trustee.ptstrName = (LPTSTR)pAdminSid;

        EXPLICIT_ACCESS eaList[] = { eaSystem, eaSelf, eaAdminDeny };

        PACL pNewDacl = nullptr;
        DWORD dwErr = SetEntriesInAclW(3, reinterpret_cast<PEXPLICIT_ACCESSW>(eaList), nullptr, &pNewDacl);
        if (dwErr != ERROR_SUCCESS) {
            FreeSid(pSystemSid); FreeSid(pAdminSid);
            return false;
        }
        SECURITY_DESCRIPTOR sd;
        InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorDacl(&sd, TRUE, pNewDacl, FALSE);

        DWORD dwRet = SetSecurityInfo(
            GetCurrentProcess(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            nullptr, nullptr, pNewDacl, nullptr);
        bool success = (dwRet == ERROR_SUCCESS);
        if (success) s_daclInstalled = true;

        LocalFree(pNewDacl);
        FreeSid(pSystemSid);
        FreeSid(pAdminSid);
        return success;
    }

    static bool RemoveProcessDACL() {
        if (!s_daclInstalled) return true;
        bool ok = SetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS;
        if (ok) s_daclInstalled = false;
        return ok;
    }

    static bool InstallJobObjectProtection() {
        if (s_hJobObject) return true;
        s_hJobObject = CreateJobObjectW(nullptr, nullptr);
        if (!s_hJobObject) return false;
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {};
        jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(s_hJobObject, JobObjectExtendedLimitInformation,
                &jeli, sizeof(jeli))) {
            CloseHandle(s_hJobObject);
            s_hJobObject = nullptr;
            return false;
        }
        if (!AssignProcessToJobObject(s_hJobObject, GetCurrentProcess())) {
            DWORD err = GetLastError();
            if (err != ERROR_ACCESS_DENIED) {
                CloseHandle(s_hJobObject);
                s_hJobObject = nullptr;
                return false;
            }
        }
        return true;
    }

    bool EnableProtection() {
        bool ok = true;
        ok &= InstallProcessDACL();
        ok &= InstallJobObjectProtection();
        return ok;
    }

    void DisableProtection() {
        RemoveProcessDACL();
        if (s_hJobObject) {
            CloseHandle(s_hJobObject);
            s_hJobObject = nullptr;
        }
    }

} // namespace ProcessGuard

// ============================================================================
// Watchdog 守护进程
// ============================================================================
static DWORD g_watchdogPid = 0;
static HANDLE g_watchdogProcess = nullptr;
static bool g_watchdogRunning = false;
static std::atomic<bool> g_watchdogExitFlag(false);
static std::atomic<int> g_watchdogRestartCount(0);
constexpr int MAX_WATCHDOG_RESTARTS = 5;

static bool IsProcessRunning(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) return false;
    DWORD exitCode = 0;
    bool running = GetExitCodeProcess(hProcess, &exitCode) && exitCode == STILL_ACTIVE;
    CloseHandle(hProcess);
    return running;
}

static DWORD WINAPI WatchdogThreadProc(LPVOID lpParam) {
    DWORD mainPid = GetCurrentProcessId();
    HANDLE hMainProcess = GetCurrentProcess();
    std::wstring selfPath;
    wchar_t path[MAX_PATH];
    if (GetModuleFileNameW(nullptr, path, MAX_PATH)) {
        selfPath = path;
    }
    while (!g_watchdogExitFlag.load()) {
        if (!IsProcessRunning(mainPid)) {
            int count = g_watchdogRestartCount.fetch_add(1);
            if (count >= MAX_WATCHDOG_RESTARTS) break;
            if (!selfPath.empty()) {
                for (int retry = 0; retry < 3; retry++) {
                    STARTUPINFOW si = { sizeof(si) };
                    si.lpDesktop = const_cast<LPWSTR>(L"Winsta0\\Default");
                    PROCESS_INFORMATION pi = {};
                    std::wstring cmdLine = L"\"" + selfPath + L"\"";
                    if (CreateProcessW(selfPath.c_str(), const_cast<LPWSTR>(cmdLine.c_str()),
                            nullptr, nullptr, FALSE,
                            CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
                            nullptr, nullptr, &si, &pi)) {
                        if (pi.hThread) CloseHandle(pi.hThread);
                        if (pi.hProcess) CloseHandle(pi.hProcess);
                        break;
                    }
                    Sleep(100);
                }
            }
            break;
        }
        Sleep(1000);
    }
    return 0;
}

static bool StartProcessWatchdog() {
    if (g_watchdogRunning) return true;
    HANDLE hThread = CreateThread(nullptr, 0, WatchdogThreadProc, nullptr, 0, nullptr);
    if (!hThread) return false;
    CloseHandle(hThread);
    g_watchdogRunning = true;
    return true;
}

static void StopProcessWatchdog() {
    if (!g_watchdogRunning) return;
    g_watchdogExitFlag.store(true);
    g_watchdogRunning = false;
}

// ============================================================================
// 反挂起保护
// ============================================================================
static std::atomic<bool> g_antiSuspendRunning(false);
static HANDLE g_antiSuspendThread = nullptr;

static DWORD WINAPI AntiSuspendThreadProc(LPVOID lpParam) {
    while (g_antiSuspendRunning.load()) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te = { sizeof(THREADENTRY32) };
            DWORD currentPid = GetCurrentProcessId();
            if (Thread32First(hSnapshot, &te)) {
                do {
                    if (te.th32OwnerProcessID == currentPid) {
                        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                        if (hThread) {
                            ResumeThread(hThread);
                            CloseHandle(hThread);
                        }
                    }
                } while (Thread32Next(hSnapshot, &te));
            }
            CloseHandle(hSnapshot);
        }
        Sleep(2000);
    }
    return 0;
}

static bool StartAntiSuspendProtection() {
    if (g_antiSuspendRunning.load()) return true;
    g_antiSuspendRunning.store(true);
    g_antiSuspendThread = CreateThread(nullptr, 0, AntiSuspendThreadProc, nullptr, 0, nullptr);
    if (!g_antiSuspendThread) {
        g_antiSuspendRunning.store(false);
        return false;
    }
    // 不要 CloseHandle，保留句柄给 StopAntiSuspendProtection 用于 WaitForSingleObject
    return true;
}

static void StopAntiSuspendProtection() {
    if (!g_antiSuspendRunning.load()) return;
    g_antiSuspendRunning.store(false);
    if (g_antiSuspendThread) {
        WaitForSingleObject(g_antiSuspendThread, 1000);
        CloseHandle(g_antiSuspendThread);
        g_antiSuspendThread = nullptr;
    }
}

// ============================================================================
// 自动验证线程
// ============================================================================
static std::atomic<bool> g_autoVerifyRunning(false);
static HANDLE g_autoVerifyThread = nullptr;

static DWORD WINAPI AutoVerifyThreadProc(LPVOID lpParam) {
    while (g_autoVerifyRunning.load()) {
        // AntiAnalysis::ForceExitIfDebugged disabled for modular build
        if (KernelAntiDebug::IsKernelDebuggingDetected()) {
            // AntiAnalysis::ForceExitIfDebugged disabled for modular build
        }
        CodeSectionGuard::RunPeriodicCodeCheck();
        IATIntegrity::RunPeriodicIATCheck();
        SecDescGuard::RunPeriodicSecDescCheck();
        FullCodeCRC::VerifyRandomChunk();
        VADMonitor::RunPeriodicVADCheck();
        for (int i = 0; i < 2300 && g_autoVerifyRunning.load(); i++) {
            Sleep(1);
        }
    }
    return 0;
}

static bool StartAutoVerify() {
    if (g_autoVerifyRunning.load()) return true;
    g_autoVerifyRunning.store(true);
    g_autoVerifyThread = CreateThread(nullptr, 0, AutoVerifyThreadProc, nullptr, 0, nullptr);
    if (!g_autoVerifyThread) {
        g_autoVerifyRunning.store(false);
        return false;
    }
    CloseHandle(g_autoVerifyThread);
    return true;
}

// ============================================================================
// InitProcessProtectionHooks — 初始化进程保护钩子
// ============================================================================
bool InitProcessProtectionHooks() {
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hKernel32) {
        OriginalExitProcess = (ExitProcess_t)GetProcAddress(hKernel32, "ExitProcess");
        OriginalTerminateProcess = (TerminateProcess_t)GetProcAddress(hKernel32, "TerminateProcess");
    }
    if (hNtdll) {
        NtTerminateProcessPtr = (NtTerminateProcess_t)GetProcAddress(hNtdll, "NtTerminateProcess");
    }
    bool hookOk = ProcessGuard::EnableProtection();
    HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
    if (hUser32) {
        OriginalPostMessageW = (PostMessageW_t)GetProcAddress(hUser32, "PostMessageW");
    }
    CreateHiddenCloseWindow();
    RegisterConsoleCloseHandler();
    return hookOk;
}

// ============================================================================
// EnableEnhancedProtection — 启用所有增强保护
// ============================================================================
static bool ProtectPEB() {
    PPEB pPeb = reinterpret_cast<PPEB>(__readgsqword(0x60));
    if (pPeb) {
        pPeb->BeingDebugged = FALSE;
        return true;
    }
    return false;
}

static bool DisableDebugPort() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;
    auto NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    auto NtSetInformationProcess = (_NtSetInformationProcess)GetProcAddress(hNtdll, "NtSetInformationProcess");
    if (!NtQueryInformationProcess || !NtSetInformationProcess) return false;
    DWORD debugPort = 0;
    NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(),
        static_cast<PROCESS_INFORMATION_CLASS>(7), &debugPort, sizeof(debugPort), nullptr);
    if (!NT_SUCCESS(status)) return false;
    if (debugPort != 0) {
        debugPort = 0;
        status = NtSetInformationProcess(GetCurrentProcess(),
            static_cast<PROCESS_INFORMATION_CLASS>(7), &debugPort, sizeof(debugPort));
        return NT_SUCCESS(status);
    }
    return true;
}

// 保护状态全局变量
static std::atomic<bool> g_antiAPCProtectionRunning(false);
static HANDLE g_antiAPCThread = nullptr;
static std::atomic<bool> g_enhancedWatchdogRunning(false);
static HANDLE g_enhancedWatchdogThread = nullptr;

static bool StartAntiAPCProtection() {
    if (g_antiAPCProtectionRunning.load()) return true;
    g_antiAPCProtectionRunning.store(true);
    return true;
}

static bool StopAntiAPCProtection() {
    if (!g_antiAPCProtectionRunning.load()) return true;
    g_antiAPCProtectionRunning.store(false);
    if (g_antiAPCThread) {
        WaitForSingleObject(g_antiAPCThread, 1000);
        CloseHandle(g_antiAPCThread);
        g_antiAPCThread = nullptr;
    }
    return true;
}

static bool StopEnhancedWatchdog() {
    if (!g_enhancedWatchdogRunning.load()) return true;
    g_enhancedWatchdogRunning.store(false);
    if (g_enhancedWatchdogThread) {
        WaitForSingleObject(g_enhancedWatchdogThread, 1000);
        CloseHandle(g_enhancedWatchdogThread);
        g_enhancedWatchdogThread = nullptr;
    }
    return true;
}

static bool SetHighIntegrityLevel() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;
    LUID luid;
    if (!LookupPrivilegeValueW(nullptr, SE_SECURITY_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(hToken);
    return true;
}

static bool EnableEnhancedProtection() {
    bool allSuccess = true;
    if (!ProtectPEB()) allSuccess = false;
    DisableDebugPort();
    if (!StartAntiSuspendProtection()) allSuccess = false;
    if (!StartProcessWatchdog()) allSuccess = false;
    if (!StartAntiAPCProtection()) allSuccess = false;
    SetHighIntegrityLevel();
    return allSuccess;
}

// ============================================================================
// EnableProcessProtection — 反结束进程保护
// ============================================================================
bool EnableProcessProtection(HANDLE hProcess) {
    if (!LoadNtSetInformationProcess() || !hProcess) return false;
    bool bMethod1Success = false, bMethod2Success = false, bJobSuccess = false;
    NTSTATUS status;

    // 方法1: PS_PROTECTION (Windows 8+)
    if (IsWindows8OrLater()) {
        PS_PROTECTION_V2 psProtection = {};
        psProtection.Type = 1;
        psProtection.Protection = 2;
        status = NtSetInformationProcessPtr(hProcess, 0x3B, &psProtection, sizeof(psProtection));
        if (NT_SUCCESS(status)) bMethod1Success = true;
    }
    // 方法2: ProcessBreakOnTermination
    BOOLEAN breakOnTermination = TRUE;
    status = NtSetInformationProcessPtr(hProcess, 0x1D, &breakOnTermination, sizeof(breakOnTermination));
    if (NT_SUCCESS(status)) bMethod2Success = true;
    // 方法3: Job Object
    bJobSuccess = ProtectProcessWithJobObject(hProcess);
    return bMethod1Success || bMethod2Success || bJobSuccess;
}

// ============================================================================
// DisableProtection — 禁用所有保护
// ============================================================================
static void DisableProtection() {
    StopEnhancedWatchdog();
    StopAntiAPCProtection();
    ProcessGuard::DisableProtection();
    StopAntiSuspendProtection();
    StopProcessWatchdog();
}

// ============================================================================
// IsRunningAsTrustedInstaller / RunAsTrustedInstaller
// ============================================================================
extern DWORD StartTrustedInstallerService();
extern void ImpersonateSystem();

bool IsRunningAsTrustedInstaller() {
    HandlePtr hToken(nullptr);
    HANDLE rawToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &rawToken))
        return false;
    hToken.reset(rawToken);
    DWORD tokenInfoLength = 0;
    GetTokenInformation(hToken.get(), TokenUser, nullptr, 0, &tokenInfoLength);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        return false;
    std::vector<BYTE> buf(tokenInfoLength);
    if (!GetTokenInformation(hToken.get(), TokenUser, buf.data(), tokenInfoLength, &tokenInfoLength))
        return false;
    TOKEN_USER* tokenUser = reinterpret_cast<TOKEN_USER*>(buf.data());
    WCHAR systemSid[SECURITY_MAX_SID_SIZE];
    DWORD sidSize = sizeof(systemSid);
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSid, &sidSize))
        return false;
    return EqualSid(tokenUser->User.Sid, systemSid);
}

void RunAsTrustedInstaller() {
    try {
        // 启用必要特权
        EnablePrivilege(SE_DEBUG_NAME);
        EnablePrivilege(SE_IMPERSONATE_NAME);

        // 模拟SYSTEM用户
        ImpersonateSystem();

        // 启动TrustedInstaller服务并获取其PID
        auto pid = StartTrustedInstallerService();

        // 获取TrustedInstaller进程句柄
        HandlePtr hTIProcess(OpenProcess(
            PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
            FALSE,
            pid));

        if (!hTIProcess) {
            throw WindowsException("OpenProcess failed (TrustedInstaller.exe)");
        }

        // 获取TrustedInstaller进程令牌
        HandlePtr hTIToken(nullptr);
        HANDLE rawTIToken;
        if (!OpenProcessToken(
            hTIProcess.get(),
            MAXIMUM_ALLOWED,
            &rawTIToken)) {
            throw WindowsException("OpenProcessToken failed (TrustedInstaller.exe)");
        }
        hTIToken.reset(rawTIToken);

        // 复制令牌
        HandlePtr hDupToken(nullptr);
        HANDLE rawDupToken;
        SECURITY_ATTRIBUTES tokenAttributes = { 0 };
        tokenAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
        tokenAttributes.lpSecurityDescriptor = nullptr;
        tokenAttributes.bInheritHandle = FALSE;

        if (!DuplicateTokenEx(
            hTIToken.get(),
            MAXIMUM_ALLOWED,
            &tokenAttributes,
            SecurityImpersonation,
            TokenImpersonation,
            &rawDupToken)) {
            throw WindowsException("DuplicateTokenEx failed (TrustedInstaller.exe)");
        }
        hDupToken.reset(rawDupToken);

        // 修复: 设置令牌的会话ID为当前用户会话ID，解决Edge等程序启动后被最小化的问题
        // TrustedInstaller进程的令牌会话ID为0，而当前用户会话通常为1
        DWORD dwCurrentSessionId = 0;
        DWORD dwCurrentProcessId = GetCurrentProcessId();
        
        // 使用ProcessIdToSessionId获取当前进程的会话ID
        if (ProcessIdToSessionId(dwCurrentProcessId, &dwCurrentSessionId)) {
            // 成功获取到当前进程的会话ID，设置到令牌
            if (!SetTokenInformation(hDupToken.get(), TokenSessionId, &dwCurrentSessionId, sizeof(dwCurrentSessionId))) {
                std::cerr << "警告: 设置令牌会话ID失败，Edge等程序可能无法正常显示" << std::endl;
            }
        } else {
            std::cerr << "警告: 获取当前会话ID失败，Edge等程序可能无法正常显示" << std::endl;
        }

        // 获取当前可执行文件路径
        WCHAR currentExePath[MAX_PATH];
        if (!GetModuleFileNameW(nullptr, currentExePath, MAX_PATH)) {
            throw WindowsException("GetModuleFileName failed");
        }

        // 构建命令行参数
        // [修复] 添加 --ti-child 标记，让子进程跳过单例互斥锁检查
        std::wstring commandLine = L"\"" + std::wstring(currentExePath) + L"\" --ti-child";

        // 获取当前进程的命令行参数
        LPWSTR cmdLine = GetCommandLineW();
        if (cmdLine) {
            // 跳过可执行文件路径部分
            if (cmdLine[0] == L'"') {
                // 可执行文件路径被引号包围
                wchar_t* endQuote = wcschr(cmdLine + 1, L'"');
                if (endQuote) {
                    commandLine += L" " + std::wstring(endQuote + 1);
                }
            }
            else {
                // 可执行文件路径没有引号
                wchar_t* space = wcschr(cmdLine, L' ');
                if (space) {
                    commandLine += L" " + std::wstring(space + 1);
                }
            }
        }

        // 创建进程
        STARTUPINFOW startupInfo = { 0 };
        startupInfo.cb = sizeof(STARTUPINFOW);
        startupInfo.lpDesktop = const_cast<LPWSTR>(L"Winsta0\\Default");

        PROCESS_INFORMATION processInfo = { 0 };

        DWORD dwLogonFlags = IsWindows7OrLater() ? LOGON_WITH_PROFILE : 0;
        
        if (!AdvancedProcessCreator::CreateProcessWithToken(
            hDupToken.get(),
            dwLogonFlags,
            nullptr,
            const_cast<LPWSTR>(commandLine.c_str()),
            CREATE_UNICODE_ENVIRONMENT,
            nullptr,
            nullptr,
            &startupInfo,
            &processInfo)) {
            throw WindowsException("CreateProcessWithToken failed (using AdvancedProcessCreator)");
        }

        // 关闭进程和线程句柄
        CloseHandle(processInfo.hProcess);
        CloseHandle(processInfo.hThread);

        // 退出当前进程
        exit(0);
    }
    catch (const std::exception& e) {
        std::cerr << "提升到TrustedInstaller权限失败: " << e.what() << std::endl;
        throw;
    }
}

// ============================================================================
// GetCommandLineArgsString
// ============================================================================
std::wstring GetCommandLineArgsString() {
    LPWSTR cmdLine = GetCommandLineW();
    std::wstring cmd(cmdLine);
    auto p = cmd.find(L"\" --service-run");
    if (p != std::wstring::npos) return cmd.substr(p + 2);
    p = cmd.find(L"--service-run");
    if (p != std::wstring::npos) {
        auto sp = cmd.find(L' ', p);
        if (sp != std::wstring::npos) return cmd.substr(sp + 1);
    }
    return L"";
}

// ============================================================================
// fgj — 防关机线程
// ============================================================================
void fgj() {
    while (1) {
        system("taskkill /f /im shutdown.exe >nul 2>&1");
    }
}

// ============================================================================
// ShowMainMenu
// ============================================================================
void ShowMainMenu() {
    std::wcout << std::endl;
    std::wcout << L"======================================================CMDPLUS======================================================" << std::endl;
    std::wcout << std::endl << std::endl;
    std::wcout << L"===========================================Ver: 26.7.7_KERNEL_DRIVER_2=============================================" << std::endl;
    std::wcout << std::endl << std::endl;
    std::wcout << L"                                           1. 结束进程" << std::endl;
    std::wcout << L"                                           2. 打开TrustedInstaller权限的CMD并置顶" << std::endl;
    std::wcout << L"                                           3. 开启强制置顶" << std::endl;
    std::wcout << L"                                           4. 取消置顶" << std::endl;
    std::wcout << L"                                           5. 以TrustedInstaller权限打开指定程序，防止最小化" << std::endl;
    std::wcout << L"                                           6. 强力删除指定文件夹" << std::endl;
    std::wcout << L"                                           7. USB解禁（恢复USB存储设备）" << std::endl;
    std::wcout << L"                                           8. 完全删除学生机房管理助手" << std::endl;
    std::wcout << L"                                           9. 安装信息管理" << std::endl;
    std::wcout << L"                                          10. 垃圾清理" << std::endl;
    std::wcout << L"                                          11. 反远程控制防火墙" << std::endl;
    std::wcout << L"                                          12. 端口监控（永久检测）" << std::endl;
    std::wcout << L"                                          13. 禁止指定端口连接" << std::endl;
    std::wcout << L"                                          14. 肃清系统" << std::endl;
    std::wcout << L"                                           0. 退出程序" << std::endl;
    std::wcout << std::endl << std::endl;
    std::wcout << L"===================================================================================================================" << std::endl;
}

// ============================================================================
// CheckZmservAndWarn
// ============================================================================
static bool CheckZmservAndWarn() {
    // Find zmserv.exe PID
    DWORD zmservPid = 0;
    {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = { sizeof(pe) };
            if (Process32FirstW(hSnap, &pe)) {
                do {
                    if (_wcsicmp(pe.szExeFile, L"zmserv.exe") == 0) {
                        zmservPid = pe.th32ProcessID;
                        break;
                    }
                } while (Process32NextW(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }
    }
    if (zmservPid != 0 && IsProcessRunning(zmservPid)) {
        std::wcout << L"\n========================================" << std::endl;
        std::wcout << L"  [警告] 检测到 zmserv.exe 正在运行!" << std::endl;
        std::wcout << L"========================================" << std::endl;
        std::wcout << L"\n  zmserv.exe 是学生机房管理助手的服务程序。" << std::endl;
        std::wcout << L"  执行此功能前需要先终止该进程。" << std::endl;
        std::wcout << L"\n  请先运行 功能8(删除学生机房管理助手) 或 功能14(肃清系统) 终止 zmserv.exe" << std::endl;
        std::wcout << L"  然后再执行此功能。" << std::endl;
        Sleep(2000);
        return false;
    }
    return true;
}

// ============================================================================
// TerminateKillers — 终结者检测
// ============================================================================
static void TerminateKillers() {
    const wchar_t* exactKillerNames[] = {
        L"taskkill.exe", L"taskmgr.exe", L"processhacker.exe",
        L"procexp.exe", L"procexp64.exe", L"cmdpluskill.exe",
        L"kill.cmdplus.exe", L"pkill.exe", L"pskill.exe", L"wmic.exe"
    };
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (pe.th32ProcessID == GetCurrentProcessId()) continue;
            std::wstring name = pe.szExeFile;
            std::wstring lowerName = name;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
            if (IsInUnifiedWhitelist(lowerName)) continue;
            bool isKiller = false;
            for (const auto& kn : exactKillerNames) {
                if (lowerName == kn) { isKiller = true; break; }
            }
            if (isKiller) {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (hProcess) {
                    TerminateProcess(hProcess, 0);
                    CloseHandle(hProcess);
                }
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
}

// ============================================================================
// HandleProcessTermination
// ============================================================================
void HandleProcessTermination() {
    DMSP_VERIFY(0x2001);
    std::string input;
    std::wcout << L"请输入要终止的进程名(多个进程用英文逗号分隔): ";
    std::cin >> input;

    std::vector<std::string> processNames;
    if (input.find(',') != std::string::npos)
        processNames = splitString(input, ',');
    else
        processNames.push_back(input);

    struct TargetProcess { DWORD pid; std::wstring name; std::wstring path; bool isSameDir; };
    std::vector<TargetProcess> targets;
    std::set<DWORD> addedPids;

    for (const auto& pn : processNames) {
        std::vector<int> pids = ProcessTerminator::getPIDsByName(pn);
        for (int pid : pids) {
            if (addedPids.find((DWORD)pid) != addedPids.end()) continue;
            addedPids.insert((DWORD)pid);
            targets.push_back({ (DWORD)pid, std::wstring(pn.begin(), pn.end()),
                                ProcessTerminator::GetProcessPath(pid), false });
        }
    }
    if (targets.empty()) {
        std::wcout << L"未找到匹配的进程" << std::endl;
        return;
    }

    std::set<std::wstring> processedDirs;
    for (const auto& t : targets) {
        if (t.path.empty()) continue;
        size_t ls = t.path.find_last_of(L"\\/");
        if (ls == std::wstring::npos) continue;
        std::wstring targetDir = t.path.substr(0, ls);
        std::wstring ndir = targetDir;
        std::transform(ndir.begin(), ndir.end(), ndir.begin(), ::towlower);
        if (processedDirs.find(ndir) != processedDirs.end()) continue;
        processedDirs.insert(ndir);
        std::wstring pn = t.path.substr(ls + 1);
        if (ProcessTerminator::IsSystemProcessWhitelisted(pn) && ProcessTerminator::IsMicrosoftSigned(t.path))
            continue;
        auto sameDir = ProcessTerminator::GetProcessesInSameDirectory(targetDir);
        for (const auto& proc : sameDir) {
            if (addedPids.find(proc.first) != addedPids.end()) continue;
            if (ProcessTerminator::IsSystemProcessWhitelisted(proc.second)) {
                std::wstring fp = targetDir + L"\\" + proc.second;
                if (ProcessTerminator::IsMicrosoftSigned(fp)) continue;
            }
            addedPids.insert(proc.first);
            targets.push_back({ proc.first, proc.second, targetDir + L"\\" + proc.second, true });
        }
    }

    std::wcout << L"\n找到以下匹配的进程:" << std::endl;
    std::wcout << L"序号  类型    映像名称                    PID    路径" << std::endl;
    std::wcout << L"====  ======  ========================  ======  ================================" << std::endl;
    for (size_t i = 0; i < targets.size(); i++) {
        std::wcout << std::left << std::setw(4) << (i + 1) << L"  "
                   << std::left << std::setw(6) << (targets[i].isSameDir ? L"关联" : L"目标") << L"  "
                   << std::left << std::setw(25) << targets[i].name
                   << std::right << std::setw(6) << targets[i].pid << L"  "
                   << targets[i].path << std::endl;
    }
    std::wcout << L"\n是否终止以上 " << targets.size() << L" 个进程? (y/n): ";
    std::string confirm;
    std::cin >> confirm;
    if (confirm != "y" && confirm != "Y") {
        std::wcout << L"已取消终止操作" << std::endl;
        return;
    }

    // 批量终止
    ProcessTerminator::initNativeAPI();
    ProcessTerminator::EnableAllPrivileges();
    for (const auto& t : targets) {
        HANDLE hProc = ProcessTerminator::OpenProcessEnhanced(t.pid, PROCESS_TERMINATE);
        if (!hProc) hProc = OpenProcess(PROCESS_TERMINATE, FALSE, t.pid);
        if (hProc) {
            bool killed = false;
            if (TerminateProcess(hProc, 0)) killed = true;
            if (!killed && ProcessTerminator::NtTerminateProcess) {
                if (NT_SUCCESS(ProcessTerminator::NtTerminateProcess(hProc, 0))) killed = true;
            }
            CloseHandle(hProc);
            if (killed) {
                std::wcout << L"[完成] " << t.name << L" (PID: " << t.pid << L") 已终止" << std::endl;
            } else {
                std::wcout << L"[失败] " << t.name << L" (PID: " << t.pid << L") 终止失败 (Error: " << GetLastError() << L")" << std::endl;
            }
        }
    }
    std::wcout << L"[完成] 进程终止操作完成" << std::endl;
}

// ============================================================================
// StartExplorerMonitor
// ============================================================================
static std::atomic<bool> g_explorerMonitorEnabled(false);

static DWORD WINAPI ExplorerMonitorThread(LPVOID lpParam) {
    // Simplified explorer monitor
    while (g_explorerMonitorEnabled.load()) {
        Sleep(5000);
    }
    return 0;
}

void StartExplorerMonitor() {
    static std::thread monitorThread;
    if (!g_explorerMonitorEnabled) {
        g_explorerMonitorEnabled = true;
        monitorThread = std::thread([]() {
            while (g_explorerMonitorEnabled.load()) Sleep(5000);
        });
        monitorThread.detach();
    }
}

void StopExplorerMonitor() {
    g_explorerMonitorEnabled = false;
}

// ============================================================================
// [功能14] AutoCleanupAndExit — 开机自启肃清
// ============================================================================
extern int RunCleanup(bool show);
extern bool EnsureDesktopShortcut();
extern bool SetAutoStartCleanup();
extern bool CheckAutoStartCleanup();

static void AutoCleanupAndExit() {
    auto clearIFEO = [](const wchar_t* exeName) {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                (std::wstring(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\") + exeName).c_str(),
                0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegDeleteKeyW(hKey, L""); RegCloseKey(hKey);
        }
        if (RegOpenKeyExW(HKEY_CURRENT_USER,
                (std::wstring(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\") + exeName).c_str(),
                0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegDeleteKeyW(hKey, L""); RegCloseKey(hKey);
        }
    };
    clearIFEO(L"tasklist.exe");
    clearIFEO(L"taskkill.exe");
    RunCleanup(false);
    EnsureDesktopShortcut();
    if (!CheckAutoStartCleanup()) SetAutoStartCleanup();
    ExitProcess(0);
}

// ============================================================================
// [功能14] Feature14Menu — 肃清菜单
// ============================================================================
static void Feature14Menu() {
    while (true) {
        std::wcout << L"\n=========== CMDPLUS 肃清系统 ===========\n";
        std::wcout << L"  1. 立即肃清所有非白名单进程\n";
        std::wcout << L"  2. 安装开机自启肃清\n";
        std::wcout << L"  0. 返回主菜单\n";
        std::wcout << L"========================================\n请选择: ";
        std::string in;
        std::cin >> in;
        int s = 0;
        try { s = std::stoi(in); } catch (...) { continue; }
        if (s == 0) return;
        if (s == 1) {
            std::wcout << L"[肃清] 开始立即肃清...\n";
            int n = RunCleanup(true);
            if (n < 0) std::wcout << L"[肃清] 进程快照失败\n";
            std::wcout << L"[肃清] 按 Enter 返回..."; std::cin.ignore(1024, L'\n'); std::cin.get();
            continue;
        }
        if (s == 2) {
            std::wcout << L"[肃清] 安装开机自启肃清...\n";
            EnsureDesktopShortcut() ? std::wcout << L"[肃清] 桌面快捷方式已创建\n" : std::wcout << L"[肃清] 桌面快捷方式创建失败\n";
            SetAutoStartCleanup() ? std::wcout << L"[肃清] 启动文件夹快捷方式已创建\n" : std::wcout << L"[肃清] 启动文件夹快捷方式创建失败\n";
            std::wcout << L"[肃清] 按 Enter 返回..."; std::cin.ignore(1024, L'\n'); std::cin.get();
            continue;
        }
    }
}

// ============================================================================
// 外部函数声明 — 功能2/3/4/5/6/8/14 (在 CMDPLUS.cpp 或其他模块中)
// ============================================================================
extern void OpenTrustedInstallerCMD();
extern void StartAlwaysOnTop();
extern void StopAlwaysOnTop();
extern void OpenAppMenu();
extern void del();

// ============================================================================
// MainEntry — 主入口 (非自动肃清模式)
// ============================================================================
static int MainEntry(int argc, char* argv[]) {
    // [DMSP v5.0] 最早时刻执行安全验证
    DMSP_EARLY_VERIFY();

    // 单例互斥锁
    const wchar_t* MUTEX_NAME = L"Global\\CMDPLUS_SINGLETON_INSTANCE";
    HANDLE hSingletonMutex = NULL;
    bool isTiChild = false;

    for (int i = 1; i < argc; i++) {
        if (_stricmp(argv[i], "--ti-child") == 0) { isTiChild = true; break; }
    }
    for (int i = 1; i < argc; i++) {
        if (_stricmp(argv[i], "--autoclean") == 0) {
            DMSP::InitializeState();
            AutoCleanupAndExit();
            return 0;
        }
    }

    if (!isTiChild) {
        hSingletonMutex = CreateMutexW(NULL, TRUE, MUTEX_NAME);
        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            if (hSingletonMutex) CloseHandle(hSingletonMutex);
            return 0;
        }
    }

    // 设置 Unicode 输出
    std::locale::global(std::locale(""));
    SetConsoleOutputCP(936);
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x0F);

    if (!DebugPrivilegeEnabler::EnableAllDebugPrivileges()) {
        std::cerr << "调试权限提升失败" << std::endl;
        return 1;
    }
    ProcessTerminator::enableDebugPrivilege();

    try {
        if (!IsRunningAsTrustedInstaller()) {
            std::wcout << L"正在提升到 TrustedInstaller 权限..." << std::endl;
            RunAsTrustedInstaller();
            return 0;
        }
        std::wcout << L"当前以TrustedInstaller权限运行" << std::endl;

        // DMSP 初始化深度验证
        DMSP_INIT_CHECK();

        // 初始化增强进程保护钩子
        InitProcessProtectionHooks();

        if (EnableProcessProtection(GetCurrentProcess())) {
            std::wcout << L"[保护] CMDPLUS反结束进程保护已开启" << std::endl;
        } else {
            std::wcout << L"[保护] CMDPLUS进程保护启用失败" << std::endl;
        }

        if (EnableEnhancedProtection()) {
            std::wcout << L"[保护] CMDPLUS增强保护已开启" << std::endl;
        } else {
            std::wcout << L"[保护] CMDPLUS增强保护部分功能启用失败" << std::endl;
        }

        StartExplorerMonitor();
    } catch (const std::exception& e) {
        std::wcerr << L"错误: " << e.what() << std::endl;
        std::wcout << L"当前以管理员权限运行" << std::endl;
        std::wcout << L"[警告] 提权失败，程序将在3秒后退出..." << std::endl;
        std::wcout << L"  请确保以管理员身份运行，并检查TrustedInstaller服务状态" << std::endl;
        Sleep(3000);
        return 1;
    }

    std::wcout << L"自动解禁功能已开启" << std::endl;
    std::thread sb(fgj);
    std::wcout << L"防关机已开启" << std::endl;

    // 启动自动验证线程
    StartAutoVerify();

    // ====================================================================
    // 主菜单循环 (lines 23441-25558)
    // ====================================================================
    while (true) {
        // 周期性运行时安全检查
        DMSP_RUNE_CHECK();

        ShowMainMenu();
        std::wcout << L"--------==>>";
        std::string input;
        std::cin >> input;

        // 隐藏菜单解锁密码: zzj
        if (input == "zzj") {
            g_hiddenMenuUnlocked = !g_hiddenMenuUnlocked;
            if (g_hiddenMenuUnlocked)
                std::wcout << L"[隐藏菜单已解锁]" << std::endl;
            else
                std::wcout << L"[隐藏菜单已锁定]" << std::endl;
            continue;
        }

        int i = 0;
        try {
            i = std::stoi(input);
        } catch (...) {
            continue;
        }

        // ====== 功能1: 结束进程 ======
        if (i == 1) {
            DMSP_VERIFY_INT(0x1001);
            if (!CheckZmservAndWarn()) continue;

            std::wcout << L"正在去除tasklist.exe映像劫持..." << std::endl;
            {
                HKEY hKey;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\tasklist.exe",
                        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
                    RegDeleteKeyW(hKey, L""); RegCloseKey(hKey);
                    std::wcout << L"[已清除] tasklist.exe 映像劫持已清除" << std::endl;
                } else {
                    std::wcout << L"[信息] tasklist.exe 无映像劫持" << std::endl;
                }
            }
            {
                HKEY hKey;
                if (RegOpenKeyExW(HKEY_CURRENT_USER,
                        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\tasklist.exe",
                        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
                    RegDeleteKeyW(hKey, L""); RegCloseKey(hKey);
                    std::wcout << L"[已清除] tasklist.exe 用户级映像劫持已清除" << std::endl;
                }
            }
            std::wcout << L"正在去除taskkill.exe映像劫持..." << std::endl;
            {
                HKEY hKey;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\taskkill.exe",
                        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
                    RegDeleteKeyW(hKey, L""); RegCloseKey(hKey);
                    std::wcout << L"[已清除] taskkill.exe 映像劫持已清除" << std::endl;
                } else {
                    std::wcout << L"[信息] taskkill.exe 无映像劫持" << std::endl;
                }
            }
            {
                HKEY hKey;
                if (RegOpenKeyExW(HKEY_CURRENT_USER,
                        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\taskkill.exe",
                        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
                    RegDeleteKeyW(hKey, L""); RegCloseKey(hKey);
                    std::wcout << L"[已清除] taskkill.exe 用户级映像劫持已清除" << std::endl;
                }
            }

            // 使用统一白名单显示可杀进程
            std::set<std::wstring> systemProcesses;
            for (size_t wi = 0; wi < g_WhitelistCount; wi++) {
                std::wstring wname = g_UnifiedSystemProcessWhitelist[wi];
                for (auto& c : wname) c = towlower(c);
                systemProcesses.insert(wname);
            }
            std::wcout << L"\n映像名称                    PID" << std::endl;
            std::wcout << L"========================= =======" << std::endl;
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
                if (Process32FirstW(hSnapshot, &pe)) {
                    do {
                        std::wstring en = pe.szExeFile;
                        for (auto& c : en) c = towlower(c);
                        if (systemProcesses.find(en) == systemProcesses.end()) {
                            std::wcout << std::left << std::setw(25) << pe.szExeFile
                                       << std::right << std::setw(6) << pe.th32ProcessID << std::endl;
                        }
                    } while (Process32NextW(hSnapshot, &pe));
                }
                CloseHandle(hSnapshot);
            }
            HandleProcessTermination();
        }

        // ====== 功能2: 打开TI CMD ======
        if (i == 2) {
            DMSP_VERIFY_INT(0x1002);
            OpenTrustedInstallerCMD();
        }

        // ====== 功能3: 强制置顶 ======
        if (i == 3) {
            DMSP_VERIFY_INT(0x1003);
            if (!CheckZmservAndWarn()) break;
            if (g_alwaysOnTopEnabled)
                std::wcout << L"强制置顶功能已经在运行中" << std::endl;
            else {
                std::wcout << L"强制置顶已启动" << std::endl;
                StartAlwaysOnTop();
            }
        }

        // ====== 功能4: 取消置顶 ======
        if (i == 4) {
            DMSP_VERIFY_INT(0x1004);
            StopAlwaysOnTop();
        }

        // ====== 功能5: TI打开程序 ======
        if (i == 5) {
            DMSP_VERIFY_INT(0x1005);
            OpenAppMenu();
        }

        // ====== 功能6: 强力删除 ======
        if (i == 6) {
            DMSP_VERIFY_INT(0x1006);
            del();
        }

        // ====== 功能7: USB解禁 ======
        if (i == 7) {
            DMSP_VERIFY_INT(0x1007);
            if (!CheckZmservAndWarn()) continue;
            std::wcout << L"正在执行USB解禁..." << std::endl;
            if (ProcessTerminator::RestoreUSBStorage())
                std::wcout << L"USB解禁成功！" << std::endl;
            else
                std::wcout << L"USB解禁失败" << std::endl;
        }

        // ====== 功能8: 删除学生机房管理助手 ======
        if (i == 8) {
            DMSP_VERIFY_INT(0x1008);
            std::wcout << L"[信息] 开始执行功能8..." << std::endl;

            // 去除映像劫持
            {
                std::wcout << L"[预处理] 正在去除映像劫持..." << std::endl;
                HKEY hKey;
                const wchar_t* ifeoPath = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
                if (RegOpenKeyW(HKEY_LOCAL_MACHINE, ifeoPath, &hKey) == ERROR_SUCCESS) {
                    wchar_t subKeyName[256];
                    DWORD index = 0;
                    DWORD nameSize = 256;
                    while (RegEnumKeyW(hKey, index, subKeyName, nameSize) == ERROR_SUCCESS) {
                        HKEY hSubKey;
                        if (RegOpenKeyW(hKey, subKeyName, &hSubKey) == ERROR_SUCCESS) {
                            wchar_t debuggerVal[MAX_PATH];
                            DWORD valSize = MAX_PATH * sizeof(wchar_t);
                            DWORD valType;
                            if (RegQueryValueExW(hSubKey, L"Debugger", NULL, &valType, (LPBYTE)debuggerVal, &valSize) == ERROR_SUCCESS) {
                                std::wstring d(debuggerVal);
                                if (d.find(L"CMDPLUS") != std::wstring::npos || d.find(L"cmdplus") != std::wstring::npos) {
                                    RegDeleteValueW(hSubKey, L"Debugger");
                                    std::wcout << L"  [清除] " << subKeyName << L" 的映像劫持" << std::endl;
                                }
                            }
                            RegCloseKey(hSubKey);
                        }
                        index++;
                        nameSize = 256;
                    }
                    RegCloseKey(hKey);
                }
                std::wcout << L"[预处理] 映像劫持处理完成" << std::endl;
            }

            std::wcout << L"=== 第一阶段：删除学生机房管理助手 ===" << std::endl;
            std::wcout << L"[检测] 正在扫描学生机房管理助手..." << std::endl;

            std::wstring targetDir;
            bool foundDir = false;
            {
                WIN32_FIND_DATAW fd;
                HANDLE hFind = FindFirstFileW(L"C:\\*", &fd);
                if (hFind != INVALID_HANDLE_VALUE) {
                    do {
                        std::wstring n = fd.cFileName;
                        if (n.length() > 1 && (n[0] == L'f' || n[0] == L'F')) {
                            bool allDigit = true;
                            for (size_t j = 1; j < n.length(); j++) {
                                if (!iswdigit(n[j])) { allDigit = false; break; }
                            }
                            if (allDigit) {
                                foundDir = true;
                                targetDir = L"C:\\" + n;
                                std::wcout << L"[发现] " << targetDir << std::endl;
                                break;
                            }
                        }
                    } while (FindNextFileW(hFind, &fd));
                    FindClose(hFind);
                }
            }
            if (!foundDir) {
                std::wcout << L"[信息] 未发现学生机房管理助手目录" << std::endl;
            }

            std::wcout << L"\n[信息] 正在挂起并结束相关进程..." << std::endl;
            {
                struct ProcInfo { DWORD pid; std::wstring name; };
                std::vector<ProcInfo> toTerminate;

                auto isSystemProcessFast = [](const std::wstring& lowerName,
                    const std::unordered_set<std::wstring>& whitelistSet,
                    const std::wstring& currentNameLower) -> bool {
                    if (whitelistSet.find(lowerName) != whitelistSet.end()) return true;
                    if (lowerName == currentNameLower) return true;
                    if (lowerName.find(L"student") != std::wstring::npos) return true;
                    if (lowerName.find(L"monitor") != std::wstring::npos) return true;
                    if (lowerName.find(L"mmpc") != std::wstring::npos) return true;
                    if (lowerName.find(L"main") != std::wstring::npos) return true;
                    if (lowerName.find(L"spider") != std::wstring::npos) return true;
                    if (lowerName.find(L"teacher") != std::wstring::npos) return true;
                    if (lowerName.find(L"easy") != std::wstring::npos) return true;
                    return false;
                };

                std::unordered_set<std::wstring> whitelistSet;
                for (size_t wi = 0; wi < g_WhitelistCount; wi++) {
                    std::wstring wn = g_UnifiedSystemProcessWhitelist[wi];
                    for (auto& c : wn) c = towlower(c);
                    whitelistSet.insert(wn);
                }
                whitelistSet.insert(L"rundll32.exe");

                wchar_t currentPath[MAX_PATH];
                std::wstring currentNameLower;
                if (GetModuleFileNameW(nullptr, currentPath, MAX_PATH)) {
                    currentNameLower = currentPath;
                    size_t pos = currentNameLower.find_last_of(L"\\/");
                    if (pos != std::wstring::npos) currentNameLower = currentNameLower.substr(pos + 1);
                    std::transform(currentNameLower.begin(), currentNameLower.end(), currentNameLower.begin(), ::towlower);
                }

                auto getPIDsByName = [](const std::wstring& pn) -> std::vector<int> {
                    std::vector<int> pids;
                    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                    if (hSnap == INVALID_HANDLE_VALUE) return pids;
                    PROCESSENTRY32W pe32 = { sizeof(PROCESSENTRY32W) };
                    if (Process32FirstW(hSnap, &pe32)) {
                        do {
                            if (_wcsicmp(pe32.szExeFile, pn.c_str()) == 0)
                                pids.push_back(pe32.th32ProcessID);
                        } while (Process32NextW(hSnap, &pe32));
                    }
                    CloseHandle(hSnap);
                    return pids;
                };

                std::vector<std::wstring> targetProcesses = { L"jfglzsn.exe", L"zmserve.exe" };
                for (const auto& pn : targetProcesses) {
                    auto pids = getPIDsByName(pn);
                    for (int pid : pids)
                        toTerminate.push_back({ (DWORD)pid, pn });
                }

                // 多线程扫描随机命名进程
                HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (hSnapshot != INVALID_HANDLE_VALUE) {
                    std::vector<PROCESSENTRY32W> allProcs;
                    PROCESSENTRY32W pe32 = { sizeof(PROCESSENTRY32W) };
                    if (Process32FirstW(hSnapshot, &pe32)) {
                        do { allProcs.push_back(pe32); } while (Process32NextW(hSnapshot, &pe32));
                    }
                    CloseHandle(hSnapshot);

                    const size_t threadCount = std::min<size_t>(4, allProcs.size());
                    std::vector<std::vector<ProcInfo>> threadResults(threadCount);
                    std::vector<std::thread> threads;
                    size_t chunkSize = allProcs.size() / threadCount;
                    for (size_t t = 0; t < threadCount; ++t) {
                        size_t start = t * chunkSize;
                        size_t end = (t == threadCount - 1) ? allProcs.size() : (t + 1) * chunkSize;
                        threads.emplace_back([&, start, end, t]() {
                            for (size_t i = start; i < end; ++i) {
                                std::wstring name(allProcs[i].szExeFile);
                                std::wstring lowerName = name;
                                std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
                                if (isSystemProcessFast(lowerName, whitelistSet, currentNameLower)) continue;
                                bool isRandomName = (name.length() >= 9 && name.length() <= 13 &&
                                    name.substr(name.length() - 4) == L".exe");
                                if (isRandomName) {
                                    size_t baseLen = name.length() - 4;
                                    std::wstring baseName = name.substr(0, baseLen);
                                    bool hasDigit = false, hasLetter = false, allValid = true;
                                    for (wchar_t c : baseName) {
                                        if (iswdigit(c)) hasDigit = true;
                                        else if (iswalpha(c)) hasLetter = true;
                                        else { allValid = false; break; }
                                    }
                                    if (allValid && (hasDigit || hasLetter))
                                        threadResults[t].push_back({ allProcs[i].th32ProcessID, name });
                                }
                            }
                        });
                    }
                    for (auto& t : threads) t.join();
                    for (auto& res : threadResults)
                        toTerminate.insert(toTerminate.end(), res.begin(), res.end());
                }

                // 挂起
                std::wcout << L"  [阶段1] 正在挂起 " << toTerminate.size() << L" 个目标进程..." << std::endl;
                ProcessTerminator::initNativeAPI();
                ProcessTerminator::EnableAllPrivileges();
                for (auto& proc : toTerminate) {
                    HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, proc.pid);
                    if (hProcess) {
                        ProcessTerminator::SuspendProcessNative(hProcess);
                        CloseHandle(hProcess);
                    }
                }
                // 终止
                std::wcout << L"  [阶段2] 正在终止所有已挂起进程..." << std::endl;
                for (auto& proc : toTerminate) {
                    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, proc.pid);
                    if (hProcess) {
                        bool term = false;
                        if (TerminateProcess(hProcess, 0)) term = true;
                        if (!term && ProcessTerminator::NtTerminateProcess) {
                            if (NT_SUCCESS(ProcessTerminator::NtTerminateProcess(hProcess, 0))) term = true;
                        }
                        CloseHandle(hProcess);
                        if (term)
                            std::wcout << L"  [完成] 进程 " << proc.name << L" (PID: " << proc.pid << L") 已终止" << std::endl;
                    }
                }
                std::wcout << L"[完成] 进程挂起与结束操作完成" << std::endl;

                // 额外检测 jfglzs 随机进程
                std::wcout << L"\n[信息] 正在检测 jfglzs 随机进程..." << std::endl;
                {
                    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                    if (hSnap != INVALID_HANDLE_VALUE) {
                        PROCESSENTRY32W pe32 = { sizeof(PROCESSENTRY32W) };
                        if (Process32FirstW(hSnap, &pe32)) {
                            do {
                                std::wstring name(pe32.szExeFile);
                                std::wstring lowerName = name;
                                std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
                                bool isJfglzs = false;
                                if (lowerName.length() >= 10 && lowerName.length() <= 14) {
                                    if (lowerName.substr(0, 6) == L"jfglzs" && lowerName.substr(lowerName.length() - 4) == L".exe") {
                                        size_t randLen = lowerName.length() - 10;
                                        if (randLen <= 4) {
                                            bool allValid = true;
                                            for (size_t i = 6; i < 6 + randLen; ++i) {
                                                if (!iswalnum(lowerName[i])) { allValid = false; break; }
                                            }
                                            if (allValid) isJfglzs = true;
                                        }
                                    }
                                }
                                if (isJfglzs) {
                                    std::wcout << L"  [发现] jfglzs 随机进程 " << name << L" (PID: " << pe32.th32ProcessID << L")" << std::endl;
                                    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                                    if (hProc) { TerminateProcess(hProc, 0); CloseHandle(hProc); }
                                }
                            } while (Process32NextW(hSnap, &pe32));
                        }
                        CloseHandle(hSnap);
                    }
                }

                // 为目标目录添加映像劫持
                if (foundDir && !targetDir.empty()) {
                    std::wcout << L"\n[信息] 正在为目标目录添加映像劫持..." << std::endl;
                    auto addIFEO = [](const std::wstring& exeName) -> bool {
                        HKEY hKey;
                        std::wstring p = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" + exeName;
                        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, p.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL) == ERROR_SUCCESS) {
                            std::wstring dv = L"cmd.exe /c exit";
                            RegSetValueExW(hKey, L"Debugger", 0, REG_SZ, (const BYTE*)dv.c_str(), (DWORD)((dv.length() + 1) * sizeof(wchar_t)));
                            RegCloseKey(hKey);
                            return true;
                        }
                        return false;
                    };
                    std::function<void(const std::wstring&, int&)> enumerateExe;
                    enumerateExe = [&addIFEO, &enumerateExe](const std::wstring& dir, int& count) {
                        std::wstring searchPath = dir + L"\\*";
                        WIN32_FIND_DATAW fd;
                        HANDLE hF = FindFirstFileW(searchPath.c_str(), &fd);
                        if (hF != INVALID_HANDLE_VALUE) {
                            do {
                                std::wstring nm = fd.cFileName;
                                if (nm == L"." || nm == L"..") continue;
                                std::wstring fp = dir + L"\\" + nm;
                                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                                    enumerateExe(fp, count);
                                else {
                                    size_t dot = nm.rfind(L'.');
                                    if (dot != std::wstring::npos) {
                                        std::wstring ext = nm.substr(dot);
                                        std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
                                        if (ext == L".exe") { if (addIFEO(nm)) ++count; }
                                    }
                                }
                            } while (FindNextFileW(hF, &fd));
                            FindClose(hF);
                        }
                    };
                    int ifeoCount = 0;
                    enumerateExe(targetDir, ifeoCount);
                    std::wcout << L"[完成] 已为 " << ifeoCount << L" 个程序添加映像劫持" << std::endl;
                }
            }

            std::wcout << L"\n[信息] 正在删除桌面快捷方式..." << std::endl;
            {
                std::wstring usersPath = L"C:\\Users";
                WIN32_FIND_DATAW fd;
                HANDLE hF = FindFirstFileW((usersPath + L"\\*").c_str(), &fd);
                if (hF != INVALID_HANDLE_VALUE) {
                    do {
                        if (fd.cFileName[0] == L'.' || !(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                        std::wstring sp = usersPath + L"\\" + fd.cFileName + L"\\Desktop\\学生机房管理助手.lnk";
                        if (DeleteFileW(sp.c_str())) std::wcout << L"  [删除] " << sp << std::endl;
                    } while (FindNextFileW(hF, &fd));
                    FindClose(hF);
                }
                std::wstring pub = L"C:\\Users\\Public\\Desktop\\学生机房管理助手.lnk";
                if (DeleteFileW(pub.c_str())) std::wcout << L"  [删除] " << pub << std::endl;
                std::wcout << L"  [完成] 桌面快捷方式清理完成" << std::endl;
            }

            std::wcout << L"\n=== 第一阶段完成 ===" << std::endl;
            std::wcout << L"\n=== 第二阶段：完全删除学生机房管理助手 ===" << std::endl;
            std::wcout << L"正在完全删除学生机房管理助手..." << std::endl;

            // [1/13] 恢复 Windows 安全中心与 Defender
            std::wcout << L"[1/13] 正在恢复Windows安全中心与Defender..." << std::endl;
            {
                HKEY hKey;
                DWORD valZero = 0, valOne = 1;

                const wchar_t* policyPaths[] = {
                    L"SOFTWARE\\Policies\\Microsoft\\Windows Defender",
                    L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
                    L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet",
                    L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Policy Manager"
                };
                const wchar_t* disableVals[] = {
                    L"DisableAntiSpyware", L"DisableAntiVirus", L"DisableRealtimeMonitoring",
                    L"DisableBehaviorMonitoring", L"DisableOnAccessProtection",
                    L"DisableScanOnRealtimeEnable", L"DisableIOAVProtection",
                    L"DisableScriptScanning", L"SubmitSamplesConsent",
                    L"SpynetReporting", L"DisableBlockAtFirstSeen",
                    L"EnableNetworkProtection", L"AllowFastStartup",
                    L"DisableEmailScanning", L"DisableCorscan"
                };
                for (const auto* pp : policyPaths) {
                    if (RegCreateKeyW(HKEY_LOCAL_MACHINE, pp, &hKey) == ERROR_SUCCESS) {
                        for (const auto* dv : disableVals)
                            RegSetValueExW(hKey, dv, 0, REG_DWORD, (const BYTE*)&valZero, sizeof(valZero));
                        RegCloseKey(hKey);
                    }
                }
                if (RegCreateKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender", &hKey) == ERROR_SUCCESS) {
                    RegDeleteValueW(hKey, L"DisableAntiSpyware");
                    RegDeleteValueW(hKey, L"DisableAntiVirus");
                    RegDeleteValueW(hKey, L"DisableRealtimeMonitoring");
                    RegDeleteValueW(hKey, L"PausedComponents");
                    RegSetValueExW(hKey, L"DisableAntiSpyware", 0, REG_DWORD, (const BYTE*)&valOne, 4);
                    RegSetValueExW(hKey, L"DisableAntiVirus", 0, REG_DWORD, (const BYTE*)&valOne, 4);
                    RegSetValueExW(hKey, L"DisableRealtimeMonitoring", 0, REG_DWORD, (const BYTE*)&valOne, 4);
                    RegCloseKey(hKey);
                }
                if (RegCreateKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection", &hKey) == ERROR_SUCCESS) {
                    RegSetValueExW(hKey, L"DisableRealtimeMonitoring", 0, REG_DWORD, (const BYTE*)&valOne, 4);
                    RegSetValueExW(hKey, L"DisableBehaviorMonitoring", 0, REG_DWORD, (const BYTE*)&valOne, 4);
                    RegSetValueExW(hKey, L"DisableOnAccessProtection", 0, REG_DWORD, (const BYTE*)&valOne, 4);
                    RegSetValueExW(hKey, L"DisableScanOnRealtimeEnable", 0, REG_DWORD, (const BYTE*)&valOne, 4);
                    RegSetValueExW(hKey, L"DisableIOAVProtection", 0, REG_DWORD, (const BYTE*)&valOne, 4);
                    RegCloseKey(hKey);
                }
                if (RegCreateKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender\\Spynet", &hKey) == ERROR_SUCCESS) {
                    RegSetValueExW(hKey, L"SpynetReporting", 0, REG_DWORD, (const BYTE*)&valOne, 4);
                    RegSetValueExW(hKey, L"DisableBlockAtFirstSeen", 0, REG_DWORD, (const BYTE*)&valOne, 4);
                    RegSetValueExW(hKey, L"SubmitSamplesConsent", 0, REG_DWORD, (const BYTE*)&valOne, 4);
                    RegCloseKey(hKey);
                }
                // 启用网络保护
                if (RegCreateKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Network Protection", &hKey) == ERROR_SUCCESS) {
                    RegSetValueExW(hKey, L"EnableNetworkProtection", 0, REG_DWORD, (const BYTE*)&valOne, 4);
                    RegCloseKey(hKey);
                }
                // 启用受控文件夹
                if (RegCreateKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Controlled Folder Access", &hKey) == ERROR_SUCCESS) {
                    RegSetValueExW(hKey, L"EnableControlledFolderAccess", 0, REG_DWORD, (const BYTE*)&valOne, 4);
                    RegCloseKey(hKey);
                }
                // 清理排除项
                auto clearExcl = [](const wchar_t* subPath) {
                    HKEY hKey;
                    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subPath, 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
                        DWORD idx = 0; wchar_t vn[1024]; DWORD vnl;
                        while (true) {
                            vnl = 1024;
                            if (RegEnumValueW(hKey, idx, vn, &vnl, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
                            RegDeleteValueW(hKey, vn);
                        }
                        RegCloseKey(hKey);
                    }
                };
                clearExcl(L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions");
                clearExcl(L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths");
                clearExcl(L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes");
                // 启用服务
                const wchar_t* svcs[] = { L"wscsvc", L"WinDefend", L"WdNisSvc", L"WdNisDrv", L"WdBoot", L"WdFilter" };
                for (const auto* svc : svcs) {
                    std::wstring cmd = std::wstring(L"sc config ") + svc + L" start= auto 2>nul";
                    _wsystem(cmd.c_str());
                    cmd = std::wstring(L"sc start ") + svc + L" 2>nul";
                    _wsystem(cmd.c_str());
                }
                // 清除 IFEO 恶意劫持
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                        0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
                    DWORD idx = 0; wchar_t skn[256]; DWORD sknl;
                    while (true) {
                        sknl = 256;
                        if (RegEnumKeyExW(hKey, idx, skn, &sknl, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
                        std::wstring kp = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\";
                        kp += skn;
                        HKEY hSub;
                        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kp.c_str(), 0, KEY_ALL_ACCESS, &hSub) == ERROR_SUCCESS) {
                            wchar_t dbg[1024]; DWORD dbl = sizeof(dbg);
                            if (RegQueryValueExW(hSub, L"Debugger", NULL, NULL, (LPBYTE)dbg, &dbl) == ERROR_SUCCESS) {
                                std::wstring ds = dbg;
                                std::transform(ds.begin(), ds.end(), ds.begin(), ::towlower);
                                if (ds.find(L"cmd") != std::wstring::npos || ds.find(L"exit") != std::wstring::npos || ds.find(L"jfglzs") != std::wstring::npos)
                                    RegDeleteValueW(hSub, L"Debugger");
                            }
                            RegCloseKey(hSub);
                        }
                        idx++;
                    }
                    RegCloseKey(hKey);
                }
                auto clearIFEO = [](const wchar_t* en) {
                    HKEY hKey;
                    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            (std::wstring(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\") + en).c_str(),
                            0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
                        RegDeleteKeyW(hKey, L""); RegCloseKey(hKey);
                    }
                    if (RegOpenKeyExW(HKEY_CURRENT_USER,
                            (std::wstring(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\") + en).c_str(),
                            0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
                        RegDeleteKeyW(hKey, L""); RegCloseKey(hKey);
                    }
                };
                clearIFEO(L"tasklist.exe");
                clearIFEO(L"taskkill.exe");
                std::wcout << L"  [完成] Windows安全中心与Defender已恢复" << std::endl;
            }

            // [2/13] 恢复安全模式
            std::wcout << L"[2/13] 正在恢复安全模式启动..." << std::endl;
            system("reg delete \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\" /f 2>nul");
            system("reg delete \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\" /f 2>nul");
            std::wcout << L"  [完成] 安全模式启动已恢复" << std::endl;

            // [3/13] 清理计划任务
            std::wcout << L"[3/13] 正在扫描并删除相关计划任务..." << std::endl;
            system("schtasks /delete /tn \"jfglzs*\" /f 2>nul");
            system("schtasks /delete /tn \"学生机房*\" /f 2>nul");
            system("schtasks /delete /tn \"JFGlzs*\" /f 2>nul");
            system("schtasks /delete /tn \"zm*\" /f 2>nul");
            std::wcout << L"  [完成] 相关计划任务已清理" << std::endl;

            // [4/13] 清理启动项
            std::wcout << L"[4/13] 正在清理非系统必须启动项..." << std::endl;
            {
                auto isSysStartup = [](const std::wstring& nl) -> bool {
                    static const wchar_t* sysItems[] = {
                        L"securityhealthsystray", L"windows defender", L"onedrive",
                        L"runtimebroker", L"searchindexer", L"ctfmon",
                        L"windows security", L"microsoft windows defender",
                        L"securityhealth", L"windowsdefender"
                    };
                    for (const auto* si : sysItems) { if (nl.find(si) != std::wstring::npos) return true; }
                    return false;
                };
                auto cleanRunKey = [&isSysStartup](HKEY root, const wchar_t* p) {
                    HKEY hKey;
                    if (RegOpenKeyExW(root, p, 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
                        DWORD idx = 0; wchar_t vn[256]; DWORD vnl;
                        while (true) {
                            vnl = 256;
                            LONG ret = RegEnumValueW(hKey, idx, vn, &vnl, NULL, NULL, NULL, NULL);
                            if (ret != ERROR_SUCCESS) break;
                            std::wstring nl = vn;
                            std::transform(nl.begin(), nl.end(), nl.begin(), ::towlower);
                            if (!isSysStartup(nl)) { RegDeleteValueW(hKey, vn); }
                            else { ++idx; }
                        }
                        RegCloseKey(hKey);
                    }
                };
                cleanRunKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run");
                cleanRunKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run");
                cleanRunKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
                cleanRunKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
                auto cleanStartupFolder = [](const std::wstring& fp) {
                    std::wstring sp = fp + L"\\*";
                    WIN32_FIND_DATAW fd;
                    HANDLE hF = FindFirstFileW(sp.c_str(), &fd);
                    if (hF != INVALID_HANDLE_VALUE) {
                        do {
                            std::wstring n = fd.cFileName;
                            if (n == L"." || n == L"..") continue;
                            std::wstring ln = n;
                            std::transform(ln.begin(), ln.end(), ln.begin(), ::towlower);
                            if (ln.find(L"security") == std::wstring::npos && ln.find(L"defender") == std::wstring::npos)
                                DeleteFileW((fp + L"\\" + n).c_str());
                        } while (FindNextFileW(hF, &fd));
                        FindClose(hF);
                    }
                };
                wchar_t startupPath[MAX_PATH];
                if (SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, 0, startupPath) == S_OK)
                    cleanStartupFolder(startupPath);
                if (SHGetFolderPathW(NULL, CSIDL_COMMON_STARTUP, NULL, 0, startupPath) == S_OK)
                    cleanStartupFolder(startupPath);
                std::wcout << L"  [完成] 非系统必须启动项已清理" << std::endl;
            }

            // [5/13] 修复 Chrome 策略
            std::wcout << L"[5/13] 正在修复Chrome浏览器策略..." << std::endl;
            {
                auto fixChrome = [](HKEY root) {
                    HKEY hKey;
                    if (RegCreateKeyW(root, L"Software\\Policies\\Google\\Chrome", &hKey) == ERROR_SUCCESS) {
                        RegDeleteValueW(hKey, L"AllowDinosaurEasterEgg");
                        RegDeleteValueW(hKey, L"AllowSurfingGame");
                        RegDeleteValueW(hKey, L"DeveloperToolsAvailability");
                        RegDeleteValueW(hKey, L"DownloadRestrictions");
                        RegDeleteValueW(hKey, L"WebWidgetAllowed");
                        RegDeleteValueW(hKey, L"SaveAs");
                        RegCloseKey(hKey);
                    }
                };
                fixChrome(HKEY_CURRENT_USER);
                fixChrome(HKEY_LOCAL_MACHINE);
                std::wcout << L"  [完成] Chrome浏览器策略已修复" << std::endl;
            }

            // [6/13] 恢复程序运行
            std::wcout << L"[6/13] 正在恢复被禁用的程序运行..." << std::endl;
            {
                HKEY hKey;
                if (RegCreateKeyW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", &hKey) == ERROR_SUCCESS) {
                    RegDeleteValueW(hKey, L"RestrictRun"); RegDeleteValueW(hKey, L"RestrictApps");
                    RegCloseKey(hKey);
                }
                RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BlockedApplications");
                system("reg delete \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\RestrictRun\" /f 2>nul");
                std::wcout << L"  [完成] 已恢复程序运行" << std::endl;
            }

            // [7/13] 恢复小游戏
            std::wcout << L"[7/13] 正在恢复扫雷、纸牌等小游戏..." << std::endl;
            {
                HKEY hKey;
                if (RegCreateKeyW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\.mine", &hKey) == ERROR_SUCCESS) { RegDeleteKeyW(hKey, L""); RegCloseKey(hKey); }
                if (RegCreateKeyW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\.sol", &hKey) == ERROR_SUCCESS) { RegDeleteKeyW(hKey, L""); RegCloseKey(hKey); }
                std::wcout << L"  [完成] 已恢复小游戏" << std::endl;
            }

            // [8/13] 清除浏览器主页
            std::wcout << L"[8/13] 正在清除浏览器主页..." << std::endl;
            {
                HKEY hKey;
                if (RegCreateKeyW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", &hKey) == ERROR_SUCCESS) {
                    RegDeleteValueW(hKey, L"Homepage"); RegDeleteValueW(hKey, L"Start Page");
                    RegSetValueExW(hKey, L"Homepage", 0, REG_SZ, (const BYTE*)L"about:blank\0", 24);
                    RegCloseKey(hKey);
                }
                if (RegCreateKeyW(HKEY_CURRENT_USER, L"Software\\Policies\\Microsoft\\Internet Explorer\\Main", &hKey) == ERROR_SUCCESS) {
                    RegDeleteValueW(hKey, L"Start Page"); RegCloseKey(hKey);
                }
                system("reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Internet Explorer\\Main\" /v \"Start Page\" /d \"about:blank\" /f 2>nul");
                std::wcout << L"  [完成] 已清除浏览器主页" << std::endl;
            }

            // [9/13] 恢复注册表编辑器
            std::wcout << L"[9/13] 正在恢复注册表编辑器..." << std::endl;
            {
                HKEY hKey;
                if (RegCreateKeyW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", &hKey) == ERROR_SUCCESS) {
                    RegDeleteValueW(hKey, L"DisableRegistryTools"); RegDeleteValueW(hKey, L"DisableRegistryTools1");
                    RegCloseKey(hKey);
                }
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
                    RegDeleteValueW(hKey, L"DisableRegistryTools"); RegCloseKey(hKey);
                }
                std::wcout << L"  [完成] 注册表编辑器已恢复" << std::endl;
            }

            // [10/13] 恢复任务管理器
            std::wcout << L"[10/13] 正在恢复任务管理器..." << std::endl;
            {
                HKEY hKey;
                if (RegCreateKeyW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", &hKey) == ERROR_SUCCESS) {
                    RegDeleteValueW(hKey, L"DisableTaskMgr"); RegCloseKey(hKey);
                }
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
                    RegDeleteValueW(hKey, L"DisableTaskMgr"); RegCloseKey(hKey);
                }
                std::wcout << L"  [完成] 任务管理器已恢复" << std::endl;
            }

            // [11/13] 恢复 CMD 和 PowerShell
            std::wcout << L"[11/13] 正在恢复CMD和PowerShell..." << std::endl;
            {
                HKEY hKey;
                if (RegCreateKeyW(HKEY_CURRENT_USER, L"Software\\Policies\\Microsoft\\Windows\\System", &hKey) == ERROR_SUCCESS) {
                    RegDeleteValueW(hKey, L"DisableCMD"); RegDeleteValueW(hKey, L"DisableCMDHidden");
                    RegCloseKey(hKey);
                }
                if (RegCreateKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\System", &hKey) == ERROR_SUCCESS) {
                    RegDeleteValueW(hKey, L"DisableCMD"); RegDeleteValueW(hKey, L"DisableCMDHidden");
                    RegCloseKey(hKey);
                }
                std::wcout << L"  [完成] CMD和PowerShell已恢复" << std::endl;
            }

            // [12/13] 清除网站访问限制
            std::wcout << L"[12/13] 正在清除网站访问限制..." << std::endl;
            {
                system("netsh advfirewall firewall delete rule name=all 2>nul");
                HKEY hKey;
                DWORD valZero = 0;
                if (RegCreateKeyW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile", &hKey) == ERROR_SUCCESS) {
                    RegSetValueExW(hKey, L"EnableFirewall", 0, REG_DWORD, (const BYTE*)&valZero, 4); RegCloseKey(hKey);
                }
                if (RegCreateKeyW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile", &hKey) == ERROR_SUCCESS) {
                    RegSetValueExW(hKey, L"EnableFirewall", 0, REG_DWORD, (const BYTE*)&valZero, 4); RegCloseKey(hKey);
                }

                system("attrib -h -r -s C:\\Windows\\System32\\drivers\\etc\\hosts 2>nul");
                FILE* hostsFile = _wfopen(L"C:\\Windows\\System32\\drivers\\etc\\hosts", L"w");
                if (hostsFile) {
                    fwprintf(hostsFile,
                        L"# Copyright (c) 1993-2009 Microsoft Corp.\n"
                        L"#\n"
                        L"# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\n"
                        L"#\n"
                        L"# localhost name resolution is handled within DNS itself.\n"
                        L"#\t127.0.0.1\tlocalhost\n"
                        L"#\t::1\t\tlocalhost\n");
                    fclose(hostsFile);
                }

                auto clearProxy = [](HKEY root, const wchar_t* p) {
                    HKEY hKey;
                    if (RegCreateKeyW(root, p, &hKey) == ERROR_SUCCESS) {
                        RegDeleteValueW(hKey, L"ProxyEnable"); RegDeleteValueW(hKey, L"ProxyServer");
                        RegDeleteValueW(hKey, L"ProxyOverride"); RegDeleteValueW(hKey, L"AutoConfigURL");
                        RegDeleteValueW(hKey, L"AutoDetect");
                        RegCloseKey(hKey);
                    }
                };
                clearProxy(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings");
                clearProxy(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings");

                // 第二轮代理清理
                { HKEY hKey = nullptr;
                if (RegCreateKeyW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", &hKey) == ERROR_SUCCESS) {
                    DWORD val = 0; RegSetValueExW(hKey, L"ProxyEnable", 0, REG_DWORD, (const BYTE*)&val, 4);
                    RegDeleteValueW(hKey, L"AutoConfigURL"); RegDeleteValueW(hKey, L"AutoDetect");
                    RegDeleteValueW(hKey, L"ProxyOverride"); RegDeleteValueW(hKey, L"ProxyServer"); RegCloseKey(hKey);
                } }
                { HKEY hKey = nullptr;
                if (RegCreateKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", &hKey) == ERROR_SUCCESS) {
                    DWORD val = 0; RegSetValueExW(hKey, L"ProxyEnable", 0, REG_DWORD, (const BYTE*)&val, 4);
                    RegDeleteValueW(hKey, L"AutoConfigURL"); RegDeleteValueW(hKey, L"AutoDetect");
                    RegDeleteValueW(hKey, L"ProxyOverride"); RegDeleteValueW(hKey, L"ProxyServer"); RegCloseKey(hKey);
                } }
                RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Pac");
                RegDeleteTreeW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Pac");

                system("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v ProxyEnable /t REG_DWORD /d 0 /f 2>nul");
                system("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v ProxyEnable /t REG_DWORD /d 0 /f 2>nul");

                // 重置 .htm/.html 文件关联，删除 Browser Helper Objects
                { HKEY hKey = nullptr;
                if (RegCreateKeyW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\.htm", &hKey) == ERROR_SUCCESS) {
                    RegDeleteKeyW(hKey, L""); RegCloseKey(hKey);
                } }
                { HKEY hKey = nullptr;
                if (RegCreateKeyW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\.html", &hKey) == ERROR_SUCCESS) {
                    RegDeleteKeyW(hKey, L""); RegCloseKey(hKey);
                } }
                { HKEY hKey = nullptr;
                if (RegCreateKeyW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", &hKey) == ERROR_SUCCESS) {
                    RegDeleteValueW(hKey, L"NoNetConnectDisconnect"); RegCloseKey(hKey);
                } }
                { HKEY hKey = nullptr;
                if (RegCreateKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", &hKey) == ERROR_SUCCESS) {
                    RegDeleteValueW(hKey, L"NoNetConnectDisconnect"); RegCloseKey(hKey);
                } }
                RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects");

                // 终止非必要进程
                { HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (hSnap != INVALID_HANDLE_VALUE) {
                    PROCESSENTRY32W pe = { sizeof(pe) };
                    if (Process32FirstW(hSnap, &pe)) do {
                        std::wstring lower = pe.szExeFile; for (auto& c : lower) c = towlower(c);
                        bool keep = (lower.find(L"chrome") != std::wstring::npos || lower.find(L"edge") != std::wstring::npos ||
                            lower.find(L"firefox") != std::wstring::npos || lower.find(L"msedge") != std::wstring::npos ||
                            lower.find(L"browser") != std::wstring::npos || lower.find(L"explorer") != std::wstring::npos ||
                            lower.find(L"cmd") != std::wstring::npos || lower.find(L"powershell") != std::wstring::npos ||
                            lower.find(L"windows") != std::wstring::npos || lower.find(L"microsoft") != std::wstring::npos ||
                            lower.find(L"system") != std::wstring::npos || lower.find(L"svchost") != std::wstring::npos ||
                            lower.find(L"cmdplus") != std::wstring::npos);
                        if (!keep) { HANDLE hp = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                            if (hp) { TerminateProcess(hp, 1); CloseHandle(hp); std::wcout << L"[结束] " << pe.szExeFile << std::endl; } }
                    } while (Process32NextW(hSnap, &pe));
                    CloseHandle(hSnap);
                } }
                Sleep(500);
                { HKEY hKey = nullptr;
                if (RegCreateKeyW(HKEY_CURRENT_USER, L"Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", &hKey) == ERROR_SUCCESS) {
                    RegDeleteValueW(hKey, L"ProxyDisable"); RegCloseKey(hKey);
                } }
                { HKEY hKey = nullptr;
                if (RegCreateKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate", &hKey) == ERROR_SUCCESS) {
                    RegDeleteValueW(hKey, L"WUServer"); RegDeleteValueW(hKey, L"WUStatusServer");
                    RegCloseKey(hKey);
                } }
                system("netsh interface portproxy reset 2>nul");
                system("netsh winhttp reset proxy 2>nul");
                system("ipconfig /flushdns 2>nul");
                system("netsh winsock reset 2>nul");
                std::wcout << L"  [完成] 网站访问限制已清除" << std::endl;
            }

            // [13/13] 恢复浏览器下载功能
            std::wcout << L"[13/13] 正在恢复浏览器下载功能..." << std::endl;
            {
                auto fixDownload = [](HKEY root, const wchar_t* sub) {
                    HKEY hKey;
                    if (RegCreateKeyW(root, sub, &hKey) == ERROR_SUCCESS) {
                        RegDeleteValueW(hKey, L"AutoOpenFileTypes");
                        RegDeleteValueW(hKey, L"DownloadRestrictions");
                        RegDeleteValueW(hKey, L"DisableDownload");
                        RegDeleteValueW(hKey, L"PromptForDownloadLocation");
                        RegDeleteValueW(hKey, L"DownloadDirectory");
                        RegCloseKey(hKey);
                    }
                };
                fixDownload(HKEY_CURRENT_USER, L"Software\\Policies\\Microsoft\\Edge");
                fixDownload(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Edge");
                fixDownload(HKEY_CURRENT_USER, L"Software\\Policies\\Google\\Chrome");
                fixDownload(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Google\\Chrome");
                std::wcout << L"  [完成] 浏览器下载功能已恢复" << std::endl;
            }

            std::wcout << L"[额外] 正在修复Edge..." << std::endl;
            {
                system("taskkill /f /im \"msedge.exe\" 2>nul");
                Sleep(500);

                auto fixEdge = [](HKEY root, const wchar_t* p) {
                    HKEY hKey;
                    if (RegCreateKeyW(root, p, &hKey) == ERROR_SUCCESS) {
                        RegDeleteValueW(hKey, L"SurfGameEnabled"); RegDeleteValueW(hKey, L"SurfingEnabled");
                        RegDeleteValueW(hKey, L"GameFeedEnabled"); RegDeleteValueW(hKey, L"BlockWebchache");
                        RegDeleteValueW(hKey, L"ConfigureBrowserUpdateSettings"); RegDeleteValueW(hKey, L"ChromeGameEnabled");
                        RegDeleteValueW(hKey, L"AllowSurfGames"); RegDeleteValueW(hKey, L"BrowserControlOfUsageProfile");
                        RegDeleteValueW(hKey, L"AllowSurfGame"); RegDeleteValueW(hKey, L"DeveloperToolsAvailability");
                        RegDeleteValueW(hKey, L"WebWidgetAllowed"); RegDeleteValueW(hKey, L"SaveAs");
                        RegCloseKey(hKey);
                    }
                };
                fixEdge(HKEY_CURRENT_USER, L"Software\\Policies\\Microsoft\\Edge");
                fixEdge(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Edge");

                // 修复 Edge\Main 下的 Playable 内容设置
                { HKEY hKey = nullptr;
                if (RegCreateKeyW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Edge\\Main", &hKey) == ERROR_SUCCESS) {
                    RegDeleteValueW(hKey, L"SurfGameEnabled"); RegDeleteValueW(hKey, L"PlayableContentAllowed");
                    RegDeleteValueW(hKey, L"PlayableContentDiscoveryAllowed"); RegCloseKey(hKey);
                } }
                { HKEY hKey = nullptr;
                if (RegCreateKeyW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Edge\\BLPolicy", &hKey) == ERROR_SUCCESS) {
                    RegDeleteValueW(hKey, L"SurfGameEnabled"); RegCloseKey(hKey);
                } }
                // 取消隐藏 Edge 用户数据
                { std::wstring userProfile = _wgetenv(L"USERPROFILE");
                if (!userProfile.empty()) {
                    std::wstring cmd = L"attrib -h -r \"" + userProfile + L"\\AppData\\Local\\Microsoft\\Edge\\User Data\" /s /d 2>nul";
                    _wsystem(cmd.c_str());
                } }

                system("reg add \"HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Edge\" /v SurfGameEnabled /t REG_DWORD /d 1 /f 2>nul");
                system("reg add \"HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Edge\" /v AllowSurfGames /t REG_DWORD /d 1 /f 2>nul");
                system("reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Edge\\Main\" /v PlayableContentAllowed /t REG_DWORD /d 1 /f 2>nul");
                system("reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Edge\\Main\" /v PlayableContentDiscoveryAllowed /t REG_DWORD /d 1 /f 2>nul");
                std::wcout << L"  [完成] Edge修复完成" << std::endl;
            }

            // ===== 以下为从 CMDPLUS.cpp 补全的修复段 =====

            std::wcout << L"[额外] 正在分析并修复异常PowerShell..." << std::endl;
            {
                HKEY hKey;

                if (RegCreateKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", &hKey) == ERROR_SUCCESS) {
                    DWORD val = 0;
                    RegSetValueExW(hKey, L"EnableLUA", 0, REG_DWORD, (const BYTE*)&val, 4);
                    RegSetValueExW(hKey, L"PromptOnSecureDesktop", 0, REG_DWORD, (const BYTE*)&val, 4);
                    RegCloseKey(hKey);
                }
                if (RegCreateKeyW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", &hKey) == ERROR_SUCCESS) {
                    RegDeleteValueW(hKey, L"NoRun"); RegDeleteValueW(hKey, L"NoFind"); RegDeleteValueW(hKey, L"NoDriveTypeAutoRun"); RegCloseKey(hKey);
                }
                if (RegCreateKeyW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", &hKey) == ERROR_SUCCESS) {
                    DWORD val = 1; RegSetValueExW(hKey, L"Hidden", 0, REG_DWORD, (const BYTE*)&val, 4);
                    RegSetValueExW(hKey, L"ShowSuperHidden", 0, REG_DWORD, (const BYTE*)&val, 4);
                    RegSetValueExW(hKey, L"HideFileExt", 0, REG_DWORD, (const BYTE*)&val, 4); RegCloseKey(hKey);
                }
                RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy Objects");
                RegDeleteTreeW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy Objects");
                if (RegCreateKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell", &hKey) == ERROR_SUCCESS) {
                    RegDeleteValueW(hKey, L"ExecutionPolicy"); RegDeleteValueW(hKey, L"EnableScripts"); RegCloseKey(hKey);
                }
                if (RegCreateKeyW(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", &hKey) == ERROR_SUCCESS) {
                    RegDeleteValueW(hKey, L"NoViewOnDrive"); RegDeleteValueW(hKey, L"RestrictToHKLM"); RegCloseKey(hKey);
                }
                system("attrib -h -r C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe 2>nul");
                system("attrib -h -r C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe 2>nul");
                system("echo y | reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\powershell.exe\" /v Path /t REG_SZ /d \"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\\" /f 2>nul");
                system("echo y | reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\powershell.exe\" /v \"\" /t REG_SZ /d \"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" /f 2>nul");
                {
                    std::wstring userProfile = _wgetenv(L"USERPROFILE");
                    if (!userProfile.empty()) {
                        std::vector<std::wstring> profilesToDelete = {
                            userProfile + L"\\Documents\\WindowsPowerShell\\Microsoft.PowerShell_profile.ps1",
                            userProfile + L"\\Documents\\PowerShell\\Microsoft.PowerShell_profile.ps1",
                            userProfile + L"\\Documents\\profile.ps1",
                            userProfile + L"\\Documents\\WindowsPowerShell\\profile.ps1",
                            userProfile + L"\\Documents\\PowerShell\\profile.ps1",
                            L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\profile.ps1",
                            L"C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\profile.ps1"
                        };
                        std::wstring allUsersProfile = _wgetenv(L"ALLUSERSPROFILE");
                        if (!allUsersProfile.empty()) profilesToDelete.push_back(allUsersProfile + L"\\WindowsPowerShell\\profile.ps1");
                        for (const auto& profilePath : profilesToDelete) {
                            DWORD attr = GetFileAttributesW(profilePath.c_str());
                            if (attr != INVALID_FILE_ATTRIBUTES) { SetFileAttributesW(profilePath.c_str(), FILE_ATTRIBUTE_NORMAL); DeleteFileW(profilePath.c_str()); }
                        }
                        auto deleteDirRecursive = [](const std::wstring& dirPath) {
                            std::wstring searchPath = dirPath + L"\\*";
                            WIN32_FIND_DATAW findData;
                            HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
                            if (hFind != INVALID_HANDLE_VALUE) {
                                do {
                                    if (wcscmp(findData.cFileName, L".") != 0 && wcscmp(findData.cFileName, L"..") != 0) {
                                        std::wstring fullPath = dirPath + L"\\" + findData.cFileName;
                                        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) RemoveDirectoryW(fullPath.c_str());
                                        else { SetFileAttributesW(fullPath.c_str(), FILE_ATTRIBUTE_NORMAL); DeleteFileW(fullPath.c_str()); }
                                    }
                                } while (FindNextFileW(hFind, &findData));
                                FindClose(hFind);
                            } RemoveDirectoryW(dirPath.c_str());
                        };
                        deleteDirRecursive(userProfile + L"\\Documents\\WindowsPowerShell");
                        deleteDirRecursive(userProfile + L"\\Documents\\PowerShell");
                    }
                }
                system("powershell -ExecutionPolicy Bypass -Command \"Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force -Confirm:$false\" 2>nul");
                system("powershell -ExecutionPolicy Bypass -Command \"Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -Confirm:$false\" 2>nul");
                std::wcout << L"  [完成] 已分析并修复PowerShell" << std::endl;
            }

            std::wcout << L"[额外] 正在恢复任务栏和开始菜单右键功能..." << std::endl;
            {
                HKEY hKey;
                auto deleteExplorerPolicies = [](HKEY hRoot, const wchar_t* subPath) {
                    HKEY hKey2; if (RegCreateKeyW(hRoot, subPath, &hKey2) != ERROR_SUCCESS) return;
                    RegDeleteValueW(hKey2, L"NoTrayContextMenu"); RegDeleteValueW(hKey2, L"NoViewContextMenu");
                    RegDeleteValueW(hKey2, L"NoDesktop"); RegDeleteValueW(hKey2, L"NoSetTaskbar");
                    RegDeleteValueW(hKey2, L"NoClose"); RegDeleteValueW(hKey2, L"NoLogoff");
                    RegDeleteValueW(hKey2, L"NoStartMenuSubFolders"); RegDeleteValueW(hKey2, L"NoStartMenuMorePrograms");
                    RegDeleteValueW(hKey2, L"NoStartMenuMFUprogramsList"); RegDeleteValueW(hKey2, L"NoStartMenuMyMusic");
                    RegDeleteValueW(hKey2, L"NoStartMenuNetworkPlaces"); RegDeleteValueW(hKey2, L"NoStartMenuPrinters");
                    RegDeleteValueW(hKey2, L"NoStartMenuRecentDocs"); RegDeleteValueW(hKey2, L"NoStartMenuSearch");
                    RegDeleteValueW(hKey2, L"NoStartMenuRun"); RegDeleteValueW(hKey2, L"NoStartMenuHelp");
                    RegDeleteValueW(hKey2, L"NoStartMenuDragDrop"); RegDeleteValueW(hKey2, L"NoStartMenuPinnedList");
                    RegDeleteValueW(hKey2, L"NoStartBanner"); RegDeleteValueW(hKey2, L"NoToolbarsOnTaskbar");
                    RegDeleteValueW(hKey2, L"NoTaskGrouping"); RegDeleteValueW(hKey2, L"NoTaskbarClock");
                    RegDeleteValueW(hKey2, L"NoTaskMgr"); RegDeleteValueW(hKey2, L"NoControlPanel");
                    RegDeleteValueW(hKey2, L"NoSetTaskbar"); RegDeleteValueW(hKey2, L"NoTrayItemsDisplay");
                    RegDeleteValueW(hKey2, L"NoContextMenu"); RegDeleteValueW(hKey2, L"NoFileMenu");
                    RegDeleteValueW(hKey2, L"NoBandCustomize"); RegDeleteValueW(hKey2, L"NoMovingBands");
                    RegDeleteValueW(hKey2, L"NoCloseDragDropBands"); RegDeleteValueW(hKey2, L"NoResolveSearch");
                    RegDeleteValueW(hKey2, L"NoResolveTrack"); RegDeleteValueW(hKey2, L"NoTaskbarContextMenu");
                    RegDeleteValueW(hKey2, L"NoStartMenuContextMenu"); RegDeleteValueW(hKey2, L"NoToolbarCustomize");
                    RegCloseKey(hKey2);
                };
                deleteExplorerPolicies(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer");
                deleteExplorerPolicies(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer");
                auto delPolicyValues = [](HKEY hRoot, const wchar_t* subPath) {
                    HKEY hKey2; if (RegOpenKeyW(hRoot, subPath, &hKey2) != ERROR_SUCCESS) return;
                    RegDeleteValueW(hKey2, L"NoTrayContextMenu"); RegDeleteValueW(hKey2, L"NoTaskbarContextMenu");
                    RegDeleteValueW(hKey2, L"NoStartMenuContextMenu"); RegDeleteValueW(hKey2, L"NoViewContextMenu");
                    RegDeleteValueW(hKey2, L"NoContextMenu"); RegDeleteValueW(hKey2, L"NoStartMenu");
                    RegDeleteValueW(hKey2, L"NoTaskbar"); RegDeleteValueW(hKey2, L"NoPinningToTaskbar");
                    RegDeleteValueW(hKey2, L"NoPinningToStartMenu"); RegDeleteValueW(hKey2, L"NoStartMenuMorePrograms");
                    RegDeleteValueW(hKey2, L"NoStartMenuSubFolders"); RegDeleteValueW(hKey2, L"HidePowerOptions");
                    RegDeleteValueW(hKey2, L"HideUserAccount"); RegDeleteValueW(hKey2, L"HideSignOut");
                    RegDeleteValueW(hKey2, L"HideSwitchUser"); RegDeleteValueW(hKey2, L"HideLock");
                    RegDeleteValueW(hKey2, L"HideSleep"); RegDeleteValueW(hKey2, L"HideHibernate");
                    RegDeleteValueW(hKey2, L"HideRestart"); RegDeleteValueW(hKey2, L"HideShutDown");
                    RegDeleteValueW(hKey2, L"DisableNotificationCenter"); RegDeleteValueW(hKey2, L"DisableControlCenter");
                    RegCloseKey(hKey2);
                };
                delPolicyValues(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer");
                delPolicyValues(HKEY_CURRENT_USER, L"Software\\Policies\\Microsoft\\Windows\\Explorer");
                // 遍历HKEY_USERS
                { HKEY hUsersKey; if (RegOpenKeyW(HKEY_USERS, NULL, &hUsersKey) == ERROR_SUCCESS) {
                    wchar_t sidName[256]; DWORD sidNameSize = 256, index = 0;
                    while (RegEnumKeyW(hUsersKey, index, sidName, sidNameSize) == ERROR_SUCCESS) {
                        if (wcslen(sidName) > 10 && wcsstr(sidName, L"_Classes") == NULL) {
                            auto cleanKey = [](const std::wstring& kp) {
                                HKEY hk; if (RegOpenKeyW(HKEY_USERS, kp.c_str(), &hk) == ERROR_SUCCESS) {
                                    RegDeleteValueW(hk, L"NoTrayContextMenu"); RegDeleteValueW(hk, L"NoViewContextMenu");
                                    RegDeleteValueW(hk, L"NoTaskbarContextMenu"); RegDeleteValueW(hk, L"NoStartMenuContextMenu");
                                    RegDeleteValueW(hk, L"NoContextMenu"); RegDeleteValueW(hk, L"NoDesktop");
                                    RegDeleteValueW(hk, L"NoSetTaskbar"); RegDeleteValueW(hk, L"NoTaskMgr");
                                    RegDeleteValueW(hk, L"NoControlPanel"); RegCloseKey(hk);
                                }
                            };
                            cleanKey(std::wstring(sidName) + L"\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer");
                            cleanKey(std::wstring(sidName) + L"\\Software\\Policies\\Microsoft\\Windows\\Explorer");
                        } index++; sidNameSize = 256;
                    } RegCloseKey(hUsersKey);
                }}
                { HKEY hDefaultKey; if (RegOpenKeyW(HKEY_USERS, L".DEFAULT\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", &hDefaultKey) == ERROR_SUCCESS) {
                    RegDeleteValueW(hDefaultKey, L"NoTrayContextMenu"); RegDeleteValueW(hDefaultKey, L"NoViewContextMenu");
                    RegDeleteValueW(hDefaultKey, L"NoTaskbarContextMenu"); RegDeleteValueW(hDefaultKey, L"NoStartMenuContextMenu");
                    RegDeleteValueW(hDefaultKey, L"NoContextMenu"); RegCloseKey(hDefaultKey);
                }}
                { HKEY hKey = nullptr;
                if (RegCreateKeyW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", &hKey) == ERROR_SUCCESS) {
                    DWORD val = 1; RegSetValueExW(hKey, L"EnableXamlStartMenu", 0, REG_DWORD, (const BYTE*)&val, 4);
                    RegSetValueExW(hKey, L"Start_TrackProgs", 0, REG_DWORD, (const BYTE*)&val, 4);
                    RegSetValueExW(hKey, L"Start_TrackDocs", 0, REG_DWORD, (const BYTE*)&val, 4);
                    RegSetValueExW(hKey, L"TaskbarGlomLevel", 0, REG_DWORD, (const BYTE*)&val, 4);
                    RegSetValueExW(hKey, L"ShowTaskViewButton", 0, REG_DWORD, (const BYTE*)&val, 4);
                    RegSetValueExW(hKey, L"ShowCortanaButton", 0, REG_DWORD, (const BYTE*)&val, 4); RegCloseKey(hKey);
                } }
                system("reg add \"HKEY_CLASSES_ROOT\\Directory\\Background\\shell\\cmd\" /ve /d \"在此处打开命令窗口\" /f 2>nul");
                system("reg add \"HKEY_CLASSES_ROOT\\Directory\\Background\\shell\\cmd\" /v ShowBasedOnVelocityId /t REG_DWORD /d 0x639bc8 /f 2>nul");

                // 清理 Shell Extensions\Blocked 黑名单
                { HKEY hKey = nullptr;
                if (RegCreateKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Blocked", &hKey) == ERROR_SUCCESS) {
                    RegDeleteValueW(hKey, L"{863D2FEE-3F9B-11D2-9F0E-006097C998F7}");
                    RegDeleteValueW(hKey, L"{000214E6-0000-0000-C000-000000000046}");
                    RegDeleteValueW(hKey, L"{000214E7-0000-0000-C000-000000000046}");
                    RegDeleteValueW(hKey, L"{000214E8-0000-0000-C000-000000000046}");
                    RegDeleteValueW(hKey, L"{000214E9-0000-0000-C000-000000000046}");
                    RegDeleteValueW(hKey, L"{4657278A-412B-11CF-842C-00AA0044C9B3}");
                    RegDeleteValueW(hKey, L"{1F4DE370-D627-11D1-BA4F-00A0C91EEDBA}");
                    RegDeleteValueW(hKey, L"{450D8FBA-AD25-11D0-98A8-0800361B1103}");
                    RegDeleteValueW(hKey, L"{2F8864B8-9BB5-4B78-906C-5E8F8F5F5F5F}");
                    RegDeleteValueW(hKey, L"{D6536473-D610-4C4B-95D8-5F5F5F5F5F5F}");
                    RegCloseKey(hKey);
                } }

                // 删除 GroupPolicy 目录缓存清除策略（最高优先级）
                _wsystem(L"rd /s /q \"C:\\Windows\\System32\\GroupPolicy\" 2>nul");
                _wsystem(L"rd /s /q \"C:\\Windows\\System32\\GroupPolicyUsers\" 2>nul");
                _wsystem(L"rd /s /q \"C:\\Windows\\System32\\GroupPolicy\\Machine\" 2>nul");
                _wsystem(L"rd /s /q \"C:\\Windows\\System32\\GroupPolicy\\User\" 2>nul");

                // 彻底删除策略键 + 恢复右键菜单 handler
                _wsystem(L"reg delete \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\" /f 2>nul");
                _wsystem(L"reg delete \"HKCU\\Software\\Policies\\Microsoft\\Windows\\Explorer\" /f 2>nul");
                _wsystem(L"reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /f 2>nul");
                _wsystem(L"reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /f 2>nul");
                _wsystem(L"reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Blocked\" /f 2>nul");
                _wsystem(L"reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Blocked\" /f 2>nul");
                _wsystem(L"reg add \"HKCR\\*\\shellex\\ContextMenuHandlers\\Open With\" /ve /d \"{09799AFB-AD67-11d1-ABCD-00C04FC30936}\" /f 2>nul");
                _wsystem(L"reg add \"HKCR\\*\\shellex\\ContextMenuHandlers\\Send To\" /ve /d \"{7BA4C740-9E81-11CF-99D3-00AA004AE837}\" /f 2>nul");
                _wsystem(L"reg add \"HKCR\\Directory\\shellex\\ContextMenuHandlers\\Copy To\" /ve /d \"{C2FBB630-2971-11D1-A18C-00C04FD75D13}\" /f 2>nul");
                _wsystem(L"reg add \"HKCR\\Directory\\shellex\\ContextMenuHandlers\\Move To\" /ve /d \"{C2FBB631-2971-11D1-A18C-00C04FD75D13}\" /f 2>nul");
                // 彻底清除 DisableTaskMgr/DisableRegistryTools/DisableCMD
                _wsystem(L"reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v DisableTaskMgr /f 2>nul");
                _wsystem(L"reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v DisableTaskMgr /f 2>nul");
                _wsystem(L"reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v DisableRegistryTools /f 2>nul");
                _wsystem(L"reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v DisableRegistryTools /f 2>nul");
                _wsystem(L"reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v DisableCMD /f 2>nul");
                _wsystem(L"reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v DisableCMD /f 2>nul");

                Sleep(3000);
                SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_FLUSHNOWAIT, NULL, NULL);
                SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)L"Environment", SMTO_ABORTIFHUNG, 5000, NULL);
                SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)L"Policy", SMTO_ABORTIFHUNG, 5000, NULL);
                Sleep(2000);
                std::wcout << L"  [完成] 任务栏和开始菜单右键功能已恢复" << std::endl;
            }

            std::wcout << L"[额外] 正在修复任务栏Explorer快捷方式..." << std::endl;
            {
                auto fixDelegate = [](const wchar_t* keyPath) {
                    HKEY hKey2; if (RegCreateKeyW(HKEY_CLASSES_ROOT, keyPath, &hKey2) == ERROR_SUCCESS) {
                        RegDeleteValueW(hKey2, NULL);
                        wchar_t clsid[] = L"{11dbb47c-a525-400b-9e80-a54615a090c0}";
                        RegSetValueExW(hKey2, L"DelegateExecute", 0, REG_SZ, (const BYTE*)clsid, sizeof(clsid));
                        RegCloseKey(hKey2);
                    }
                };
                fixDelegate(L"Folder\\shell\\open\\command");
                fixDelegate(L"Folder\\shell\\explore\\command");
                fixDelegate(L"Directory\\shell\\open\\command");
                fixDelegate(L"Drive\\shell\\open\\command");
                { HKEY hKey = nullptr;
                if (RegCreateKeyW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", &hKey) == ERROR_SUCCESS) {
                    DWORD val = 0; RegSetValueExW(hKey, L"LaunchTo", 0, REG_DWORD, (const BYTE*)&val, 4); RegCloseKey(hKey);
                } }
                auto fixIsShortcut = [](const wchar_t* clsidKey) {
                    HKEY hKey2; if (RegCreateKeyW(HKEY_CLASSES_ROOT, clsidKey, &hKey2) == ERROR_SUCCESS) {
                        RegDeleteValueW(hKey2, L"IsShortcut"); DWORD val = 1;
                        RegSetValueExW(hKey2, L"IsShortcut", 0, REG_DWORD, (const BYTE*)&val, 4); RegCloseKey(hKey2);
                    }
                };
                fixIsShortcut(L"lnkfile"); fixIsShortcut(L"piffile"); fixIsShortcut(L"InternetShortcut");
                std::wcout << L"  [完成] 任务栏Explorer快捷方式已修复" << std::endl;
            }

            std::wcout << L"[额外] 正在修复UAC设置..." << std::endl;
            {
                { HKEY hKey = nullptr;
                if (RegCreateKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", &hKey) == ERROR_SUCCESS) {
                    DWORD val = 1; RegSetValueExW(hKey, L"EnableLUA", 0, REG_DWORD, (const BYTE*)&val, 4);
                    RegSetValueExW(hKey, L"ConsentPromptBehaviorAdmin", 0, REG_DWORD, (const BYTE*)&val, 4);
                    RegSetValueExW(hKey, L"ConsentPromptBehaviorUser", 0, REG_DWORD, (const BYTE*)&val, 4);
                    val = 0; RegSetValueExW(hKey, L"PromptOnSecureDesktop", 0, REG_DWORD, (const BYTE*)&val, 4);
                    RegDeleteValueW(hKey, L"EnableUIADesktopToggle"); RegCloseKey(hKey);
                } }
                { HKEY hKey = nullptr;
                if (RegCreateKeyW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", &hKey) == ERROR_SUCCESS) {
                    RegDeleteValueW(hKey, L"EnableLUA"); RegDeleteValueW(hKey, L"ConsentPromptBehaviorAdmin");
                    RegDeleteValueW(hKey, L"ConsentPromptBehaviorUser"); RegDeleteValueW(hKey, L"PromptOnSecureDesktop");
                    RegCloseKey(hKey);
                } }
                system("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableLUA /t REG_DWORD /d 1 /f 2>nul");
                system("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 5 /f 2>nul");
                system("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v ConsentPromptBehaviorUser /t REG_DWORD /d 3 /f 2>nul");

                // 清理 SmartScreen 策略
                { HKEY hKey = nullptr;
                if (RegCreateKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer", &hKey) == ERROR_SUCCESS) {
                    RegDeleteValueW(hKey, L"NoSmartScreen"); RegCloseKey(hKey);
                } }
                { HKEY hKey = nullptr;
                if (RegCreateKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\System", &hKey) == ERROR_SUCCESS) {
                    RegDeleteValueW(hKey, L"EnableSmartScreen"); RegCloseKey(hKey);
                } }
                // 清理附件策略
                { HKEY hKey = nullptr;
                if (RegCreateKeyW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations", &hKey) == ERROR_SUCCESS) {
                    RegDeleteValueW(hKey, L"DefaultFileTypeRisk"); RegCloseKey(hKey);
                } }
                { HKEY hKey = nullptr;
                if (RegCreateKeyW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments", &hKey) == ERROR_SUCCESS) {
                    RegDeleteValueW(hKey, L"SaveZoneInformation"); RegDeleteValueW(hKey, L"HideZoneInfoOnProperties"); RegCloseKey(hKey);
                } }

                std::wcout << L"  [完成] UAC设置已修复" << std::endl;
            }

            std::wcout << L"\n=== 基础修复完成 ===" << std::endl;
            std::wcout << L"\n是否继续修复键盘映射（需要重启）？(Y/N): ";
            {
                wchar_t confirm; std::wcin >> confirm;
                if (confirm == L'Y' || confirm == L'y') {
                    std::wcout << L"\n[额外] 正在修复键盘映射和Win键..." << std::endl;
                    {
                        auto delScanCode = [](HKEY hRoot, const wchar_t* path) {
                            HKEY hk; if (RegOpenKeyW(hRoot, path, &hk) == ERROR_SUCCESS) {
                                RegDeleteValueW(hk, L"Scancode Map"); RegDeleteValueW(hk, L"Extended Scancode Map"); RegCloseKey(hk);
                            }
                        };
                        delScanCode(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout");
                        delScanCode(HKEY_CURRENT_USER, L"Keyboard Layout");
                        auto delNoWinKeys = [](HKEY hRoot, const wchar_t* path) {
                            HKEY hk; if (RegOpenKeyW(hRoot, path, &hk) == ERROR_SUCCESS) {
                                RegDeleteValueW(hk, L"NoWinKeys"); RegDeleteValueW(hk, L"NoWinMenu"); RegDeleteValueW(hk, L"NoWinSelect"); RegCloseKey(hk);
                            }
                        };
                        delNoWinKeys(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer");
                        delNoWinKeys(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer");
                        { HKEY hKey = nullptr;
                        if (RegCreateKeyW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", &hKey) == ERROR_SUCCESS) {
                            DWORD val = 1; RegSetValueExW(hKey, L"EnableXamlStartMenu", 0, REG_DWORD, (const BYTE*)&val, 4); RegCloseKey(hKey);
                        } }
                        system("reg delete \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout\" /v \"Scancode Map\" /f 2>nul");
                        system("reg delete \"HKEY_CURRENT_USER\\Keyboard Layout\" /v \"Scancode Map\" /f 2>nul");
                        system("reg delete \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout\" /v \"Extended Scancode Map\" /f 2>nul");
                        system("reg delete \"HKEY_CURRENT_USER\\Keyboard Layout\" /v \"Extended Scancode Map\" /f 2>nul");
                        // 枚举 Keyboard Layouts 所有子键删除 Scancode Map
                        { HKEY hkLayouts; if (RegOpenKeyW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Keyboard Layouts", &hkLayouts) == ERROR_SUCCESS) {
                            wchar_t subName[256]; DWORD idx = 0, nameSize = 256;
                            while (RegEnumKeyW(hkLayouts, idx, subName, nameSize) == ERROR_SUCCESS) {
                                HKEY hSub; if (RegOpenKeyW(hkLayouts, subName, &hSub) == ERROR_SUCCESS) {
                                    RegDeleteValueW(hSub, L"Scancode Map"); RegDeleteValueW(hSub, L"Extended Scancode Map"); RegCloseKey(hSub);
                                } idx++; nameSize = 256;
                            } RegCloseKey(hkLayouts);
                        } }
                        // 删除 DisableStartMenu/NoStartMenu 策略
                        { HKEY hk; if (RegOpenKeyW(HKEY_CURRENT_USER, L"Software\\Policies\\Microsoft\\Windows\\Explorer", &hk) == ERROR_SUCCESS) {
                            RegDeleteValueW(hk, L"DisableStartMenu"); RegDeleteValueW(hk, L"NoStartMenu"); RegCloseKey(hk);
                        } }
                        { HKEY hk; if (RegOpenKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer", &hk) == ERROR_SUCCESS) {
                            RegDeleteValueW(hk, L"DisableStartMenu"); RegDeleteValueW(hk, L"NoStartMenu"); RegCloseKey(hk);
                        } }
                        // 配置键盘驱动服务
                        _wsystem(L"sc config \"kbdclass\" start= demand 2>nul");
                        _wsystem(L"sc config \"kbdhid\" start= demand 2>nul");
                        std::wcout << L"  [完成] 键盘映射和Win键已修复（需要重启生效）" << std::endl;
                    }
                    std::wcout << L"\n正在更新策略..." << std::endl;
                    system("gpupdate /force 2>nul");
                    std::wcout << L"\n=== 完全删除学生机房管理助手完成 ===" << std::endl;
                    std::wcout << L"注意: 键盘映射修复需要重启后生效" << std::endl;
                    std::wcout << L"\n是否立即重启电脑？(Y/N): ";
                    wchar_t confirm2; std::wcin >> confirm2;
                    if (confirm2 == L'Y' || confirm2 == L'y') { std::wcout << L"正在重启..." << std::endl; system("shutdown /r /t 3 /f"); }
                } else { std::wcout << L"\n已跳过修复项" << std::endl; }
            }
        }

        // ====== 功能9: 安装信息管理 ======
        if (i == 9) {
            DMSP_VERIFY_INT(0x1009);
            std::wcout << L"=== 安装信息管理 ===" << std::endl;
            std::wcout << L"正在扫描已安装的程序..." << std::endl;

            std::vector<std::pair<std::wstring, std::wstring>> installedApps;

            auto scanUninstallKey = [&](HKEY hRoot, const wchar_t* subPath) {
                HKEY hKey = nullptr;
                if (RegOpenKeyExW(hRoot, subPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS) return;
                DWORD subKeyCount = 0;
                RegQueryInfoKeyW(hKey, NULL, NULL, NULL, &subKeyCount, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
                for (DWORD i = 0; i < subKeyCount; i++) {
                    wchar_t subKeyName[256] = {};
                    DWORD subKeyNameLen = 255;
                    if (RegEnumKeyExW(hKey, i, subKeyName, &subKeyNameLen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) continue;
                    HKEY hSubKey = nullptr;
                    if (RegOpenKeyExW(hKey, subKeyName, 0, KEY_READ, &hSubKey) != ERROR_SUCCESS) continue;
                    wchar_t displayName[1024] = {};
                    DWORD dnSize = sizeof(displayName) - sizeof(wchar_t);
                    if (RegQueryValueExW(hSubKey, L"DisplayName", NULL, NULL, (LPBYTE)displayName, &dnSize) == ERROR_SUCCESS) {
                        displayName[dnSize / sizeof(wchar_t) < 1023 ? dnSize / sizeof(wchar_t) : 1023] = L'\0';
                        for (DWORD k = 0; k < sizeof(displayName) / sizeof(wchar_t); k++) {
                            if (displayName[k] < 0x20 && displayName[k] != 0) displayName[k] = L'?';
                        }
                        wchar_t displayVersion[256] = {};
                        DWORD dvSize = sizeof(displayVersion) - sizeof(wchar_t);
                        RegQueryValueExW(hSubKey, L"DisplayVersion", NULL, NULL, (LPBYTE)displayVersion, &dvSize);
                        displayVersion[dvSize / sizeof(wchar_t) < 255 ? dvSize / sizeof(wchar_t) : 255] = L'\0';
                        std::wstring nameStr(displayName);
                        bool dup = false;
                        for (const auto& ex : installedApps) { if (ex.first == nameStr) { dup = true; break; } }
                        if (!dup) installedApps.push_back({ nameStr, std::wstring(displayVersion) });
                    }
                    RegCloseKey(hSubKey);
                }
                RegCloseKey(hKey);
            };

            scanUninstallKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
            scanUninstallKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
            scanUninstallKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall");

            std::wcout << L"扫描完成,共 " << installedApps.size() << L" 个程序" << std::endl;
            std::sort(installedApps.begin(), installedApps.end(),
                [](const auto& a, const auto& b) { return a.first < b.first; });
            installedApps.erase(std::unique(installedApps.begin(), installedApps.end(),
                [](const auto& a, const auto& b) { return a.first == b.first; }), installedApps.end());

            if (installedApps.empty()) {
                std::wcout << L"[信息] 未找到已安装的程序" << std::endl;
            } else {
                std::wcout << L"\n找到 " << installedApps.size() << L" 个已安装的程序：" << std::endl;
                std::wcout << L"========================================" << std::endl;
                for (size_t idx = 0; idx < installedApps.size(); idx++) {
                    wprintf(L"[%zu] %ls", (idx + 1), installedApps[idx].first.c_str());
                    if (!installedApps[idx].second.empty())
                        wprintf(L" (版本: %ls)", installedApps[idx].second.c_str());
                    wprintf(L"\n");
                    fflush(stdout);
                }

                wprintf(L"\n请输入要删除安装信息的程序编号（输入0取消）: ");
                fflush(stdout);
                int choice = 0;
                char numBuf[16] = {};
                int numIdx = 0;
                int c;
                while ((c = _getwch()) != WEOF) {
                    if (c == L'\r' || c == L'\n') break;
                    if (c >= L'0' && c <= L'9' && numIdx < 14) {
                        numBuf[numIdx++] = (char)c;
                        wprintf(L"%c", c); fflush(stdout);
                    } else if ((c == L'\b' || c == 0x7F) && numIdx > 0) {
                        numBuf[--numIdx] = '\0';
                        wprintf(L"\b \b"); fflush(stdout);
                    } else if (c == 0x03) {
                        numIdx = 0; wprintf(L"\n[取消] Ctrl+C 中断\n"); break;
                    }
                }
                wprintf(L"\n");
                if (numIdx > 0) choice = atoi(numBuf);

                if (choice > 0 && choice <= (int)installedApps.size()) {
                    std::wstring targetApp = installedApps[choice - 1].first;
                    std::wcout << L"\n[删除] 正在删除 \"" << targetApp << L"\" 的安装信息..." << std::endl;
                    int deletedCount = 0;

                    auto deleteFromUninstallKey = [&](HKEY hRoot, const wchar_t* basePath) {
                        HKEY hUninstallKey;
                        if (RegOpenKeyExW(hRoot, basePath, 0, KEY_READ | KEY_WRITE, &hUninstallKey) == ERROR_SUCCESS) {
                            std::vector<std::wstring> toDelete;
                            wchar_t subKeyName[256];
                            DWORD idx = 0;
                            DWORD nameSize = 256;
                            while (RegEnumKeyExW(hUninstallKey, idx, subKeyName, &nameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                                HKEY hSubKey;
                                if (RegOpenKeyExW(hUninstallKey, subKeyName, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                                    wchar_t dn[512];
                                    DWORD dnSize = sizeof(dn);
                                    if (RegQueryValueExW(hSubKey, L"DisplayName", NULL, NULL, (LPBYTE)dn, &dnSize) == ERROR_SUCCESS) {
                                        if (wcscmp(dn, targetApp.c_str()) == 0) toDelete.push_back(subKeyName);
                                    }
                                    RegCloseKey(hSubKey);
                                }
                                idx++;
                                nameSize = 256;
                            }
                            for (const auto& name : toDelete) {
                                if (RegDeleteKeyW(hUninstallKey, name.c_str()) == ERROR_SUCCESS) {
                                    std::wcout << L"  [删除] " << name << std::endl;
                                    deletedCount++;
                                }
                            }
                            RegCloseKey(hUninstallKey);
                        }
                    };

                    deleteFromUninstallKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
                    deleteFromUninstallKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
                    deleteFromUninstallKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall");

                    std::wcout << L"\n[完成] 已删除 " << deletedCount << L" 条安装信息" << std::endl;
                    std::wcout << L"注意: 仅删除了注册表中的安装信息，程序文件可能仍然存在" << std::endl;
                } else if (choice != 0) {
                    std::wcout << L"[错误] 无效的编号" << std::endl;
                } else {
                    std::wcout << L"[取消] 操作已取消" << std::endl;
                }
            }
        }

        // ====== 功能0: 退出程序 ======
        if (i == 0) {
            DMSP_VERIFY_INT(0x1000);
            std::wcout << L"正在清理保护机制..." << std::endl;
            DisableProtection();
            AllowUserClose();
            std::wcout << L"感谢使用，再见！" << std::endl;
            return 0;
        }

        // ====== 功能10: 垃圾清理 ======
        if (i == 10) {
            DMSP_VERIFY_INT(0x100A);
            GarbageCleaner::StartCleanup();
        }

        // ====== 功能11: 反远程控制防火墙 ======
        if (i == 11) {
            DMSP_VERIFY_INT(0x100B);
            if (!CheckZmservAndWarn()) break;
            AntiRemoteControl::ShowMenu();
        }

        // ====== 功能12: 端口监控 ======
        if (i == 12) {
            DMSP_VERIFY_INT(0x100C);
            PortMonitor::StartPortMonitoring();
        }

        // ====== 功能13: 禁止端口连接 ======
        if (i == 13) {
            DMSP_VERIFY_INT(0x100D);
            if (!CheckZmservAndWarn()) break;
            PortBlocker::ShowMenu();
        }

        // ====== 功能14: 肃清系统 ======
        if (i == 14) {
            DMSP_VERIFY_INT(0x100E);
            Feature14Menu();
        }
    }

    return 0;
}

// ============================================================================
// main — 程序入口
// ============================================================================
int main(int argc, char* argv[]) {
    __try {
        return MainEntry(argc, argv);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD exceptionCode = GetExceptionCode();
        std::wcout << L"\n========================================" << std::endl;
        std::wcout << L"       [致命错误] 程序发生崩溃!" << std::endl;
        std::wcout << L"========================================" << std::endl;
        std::wcout << L"  异常代码: 0x" << std::hex << exceptionCode << std::dec << std::endl;
        switch (exceptionCode) {
        case EXCEPTION_ACCESS_VIOLATION:
            std::wcout << L"  错误类型: 访问违规 (空指针/内存越界)" << std::endl; break;
        case EXCEPTION_STACK_OVERFLOW:
            std::wcout << L"  错误类型: 栈溢出" << std::endl; break;
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
            std::wcout << L"  错误类型: 除零错误" << std::endl; break;
        case EXCEPTION_BREAKPOINT:
            std::wcout << L"  错误类型: 断点中断 (可能被调试)" << std::endl; break;
        case EXCEPTION_ILLEGAL_INSTRUCTION:
            std::wcout << L"  错误类型: 非法指令" << std::endl; break;
        case EXCEPTION_PRIV_INSTRUCTION:
            std::wcout << L"  错误类型: 权限不足指令" << std::endl; break;
        case EXCEPTION_DATATYPE_MISALIGNMENT:
            std::wcout << L"  错误类型: 数据对齐错误" << std::endl; break;
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
            std::wcout << L"  错误类型: 数组越界" << std::endl; break;
        default:
            std::wcout << L"  错误类型: 未知异常" << std::endl; break;
        }
        std::wcout << L"\n  [注意] Watchdog守护进程将自动重启程序..." << std::endl;
        Sleep(2000);
        return exceptionCode;
    }
}
