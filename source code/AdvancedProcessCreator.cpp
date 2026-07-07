#include "CommonDefs.h"
#include "AdvancedProcessCreator.h"
#include "signature_protection_nocert.h"
#include "ProcessTerminator.h"
#include "WTSHelper.h"

// 外部函数声明
extern bool ForceSetForegroundWindow(HWND hwnd);

// ===== 全局变量 =====
bool g_alwaysOnTopEnabled = false;
std::thread g_alwaysOnTopThread;
HWND g_targetTopmostWindow = NULL;
std::wstring g_targetWindowClass;
std::wstring g_targetWindowTitle;
WINDOWPLACEMENT g_originalPlacement = { sizeof(WINDOWPLACEMENT) };
bool g_hasOriginalPlacement = false;
volatile LONG g_topmostFightMode = 0;

// ===== 工具函数 =====
// (EnablePrivilege 和 GetProcessIdByName 定义在 CommonDefs.h 中，inline)
// ===== TI服务启动 =====
DWORD StartTrustedInstallerService() {
    ServiceHandlePtr hSCManager(OpenSCManagerW(NULL, SERVICES_ACTIVE_DATABASE, GENERIC_EXECUTE));
    if (!hSCManager) throw WindowsException("OpenSCManager failed");
    ServiceHandlePtr hService(OpenServiceW(hSCManager.get(), L"TrustedInstaller", GENERIC_READ | GENERIC_EXECUTE));
    if (!hService) throw WindowsException("OpenService failed");
    SERVICE_STATUS_PROCESS statusBuffer = { 0 };
    DWORD bytesNeeded = 0;
    if (!QueryServiceStatusEx(hService.get(), SC_STATUS_PROCESS_INFO, (LPBYTE)&statusBuffer, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded))
        throw WindowsException("QueryServiceStatusEx failed");
    if (statusBuffer.dwCurrentState == SERVICE_STOPPED) {
        if (!StartServiceW(hService.get(), 0, nullptr))
            throw WindowsException("StartService failed");
    }
    const int maxWait = 30000, interval = 100;
    int waited = 0;
    while (waited < maxWait) {
        if (!QueryServiceStatusEx(hService.get(), SC_STATUS_PROCESS_INFO, (LPBYTE)&statusBuffer, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded))
            throw WindowsException("QueryServiceStatusEx failed");
        if (statusBuffer.dwCurrentState == SERVICE_RUNNING) return statusBuffer.dwProcessId;
        Sleep(interval); waited += interval;
    }
    throw WindowsException("TrustedInstaller service did not start within timeout");
}

// ===== 强制置顶相关 =====
void StopAlwaysOnTop() {
    if (!g_alwaysOnTopEnabled) { std::wcout << L"强制置顶功能未在运行" << std::endl; return; }
    g_alwaysOnTopEnabled = false;
    if (g_alwaysOnTopThread.joinable()) g_alwaysOnTopThread.join();
    g_targetTopmostWindow = NULL;
    std::wcout << L"强制置顶已关闭" << std::endl;
}

void StartAlwaysOnTop() {
    if (g_alwaysOnTopEnabled) { std::wcout << L"强制置顶功能已经在运行中" << std::endl; return; }
    g_alwaysOnTopEnabled = true;
    g_topmostFightMode = 0;
    if (!g_targetTopmostWindow || !IsWindow(g_targetTopmostWindow)) {
        g_targetTopmostWindow = GetConsoleWindow();
    }
    if (g_targetTopmostWindow && IsWindow(g_targetTopmostWindow)) {
        LONG exStyle = GetWindowLongW(g_targetTopmostWindow, GWL_EXSTYLE);
        SetWindowLongW(g_targetTopmostWindow, GWL_EXSTYLE, exStyle | WS_EX_TOPMOST);
        SetWindowPos(g_targetTopmostWindow, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE);
        ForceSetForegroundWindow(g_targetTopmostWindow);
        LONG style = GetWindowLongW(g_targetTopmostWindow, GWL_STYLE);
        SetWindowLongW(g_targetTopmostWindow, GWL_STYLE, style & ~WS_MINIMIZEBOX);
    }
    std::wcout << L"强制置顶已启动" << std::endl;
}

// ===== 打开TI权限CMD =====
void OpenTrustedInstallerCMD() {
    DMSP_VERIFY(0x2004);
    wchar_t cmdPath[MAX_PATH];
    UINT len = GetSystemDirectoryW(cmdPath, MAX_PATH);
    if (len == 0 || len > MAX_PATH - 10) {
        std::wcout << L"获取系统目录失败，错误码: " << GetLastError() << L"，尝试直接使用cmd.exe" << std::endl;
        wcscpy_s(cmdPath, L"cmd.exe");
    } else {
        wcscat_s(cmdPath, L"\\cmd.exe");
    }
    STARTUPINFOW si = { sizeof(si) };
    si.lpDesktop = const_cast<LPWSTR>(L"Winsta0\\Default");
    PROCESS_INFORMATION pi = { 0 };
    if (CreateProcessW(cmdPath, NULL, NULL, NULL, FALSE,
        CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &si, &pi)) {
        if (pi.hThread) CloseHandle(pi.hThread);
        if (pi.hProcess) CloseHandle(pi.hProcess);
        std::wcout << L"已启动CMD" << std::endl;
    } else {
        std::wcout << L"启动CMD失败，错误码: " << GetLastError() << std::endl;
    }
}

// ===== 辅助函数 =====
std::set<DWORD> GetChildProcesses(DWORD parentPid) {
    std::set<DWORD> childPids;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return childPids;
    PROCESSENTRY32W pe32 = { sizeof(pe32) };
    if (Process32FirstW(hSnapshot, &pe32)) {
        do { if (pe32.th32ParentProcessID == parentPid) childPids.insert(pe32.th32ProcessID); }
        while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot); return childPids;
}

bool SuspendProcess(DWORD processId) {
    bool success = true;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;
    THREADENTRY32 te = { sizeof(te) };
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == processId) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread) {
                    if (SuspendThread(hThread) == (DWORD)-1) success = false;
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    return success;
}

// ===== SYSTEM 令牌获取 =====
bool GetSystemTokenUsingWTS(HANDLE* phToken) {
    *phToken = nullptr;
    HANDLE hWts = WTSHelper::GetActiveUserToken();
    if (hWts) { *phToken = hWts; return true; }
    // 回退: 从 winlogon 取令牌
    DWORD pid = GetProcessIdByName(L"winlogon.exe");
    if (!pid) return false;
    HANDLE hProc = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return false;
    HANDLE hTok = nullptr;
    if (OpenProcessToken(hProc, MAXIMUM_ALLOWED, &hTok)) { *phToken = hTok; CloseHandle(hProc); return true; }
    CloseHandle(hProc); return false;
}

void ImpersonateSystemUsingWTS() {
    HANDLE hSystemToken = nullptr;
    if (!GetSystemTokenUsingWTS(&hSystemToken)) throw WindowsException("Failed to get SYSTEM token using WTS API");
    HandlePtr hToken(hSystemToken);
    if (!ImpersonateLoggedOnUser(hToken.get())) throw WindowsException("ImpersonateLoggedOnUser failed (WTS API)");
}

void ImpersonateSystemUsingWinlogon() {
    auto systemPid = GetProcessIdByName(L"winlogon.exe");
    HandlePtr hSystemProcess(OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, systemPid));
    if (!hSystemProcess) throw WindowsException("OpenProcess failed (winlogon.exe)");
    HANDLE rawSystemToken;
    if (!OpenProcessToken(hSystemProcess.get(), MAXIMUM_ALLOWED, &rawSystemToken)) throw WindowsException("OpenProcessToken failed (winlogon.exe)");
    HandlePtr hSystemToken(rawSystemToken);
    HANDLE rawDupToken;
    SECURITY_ATTRIBUTES ta = { sizeof(SECURITY_ATTRIBUTES), nullptr, FALSE };
    if (!DuplicateTokenEx(hSystemToken.get(), MAXIMUM_ALLOWED, &ta, SecurityImpersonation, TokenImpersonation, &rawDupToken))
        throw WindowsException("DuplicateTokenEx failed (winlogon.exe)");
    HandlePtr hDupToken(rawDupToken);
    if (!ImpersonateLoggedOnUser(hDupToken.get())) throw WindowsException("ImpersonateLoggedOnUser failed");
}

// ===== ImpersonateSystem =====
void ImpersonateSystem() {
    if (WTSHelper::IsAvailable() && IsWindows7OrLater()) {
        try { ImpersonateSystemUsingWTS(); return; }
        catch (const WindowsException&) {}
    }
    ImpersonateSystemUsingWinlogon();
}

// ===== 按进程ID查找窗口 =====
HWND FindTopLevelWindowByProcessId(DWORD processId, int maxRetries) {
    if (processId == 0) return NULL;
    for (int retry = 0; retry < maxRetries; retry++) {
        HWND hwnd = FindWindowExW(NULL, NULL, NULL, NULL);
        HWND bestHwnd = NULL;
        while (hwnd) {
            DWORD windowPid = 0;
            if (GetWindowThreadProcessId(hwnd, &windowPid) && windowPid == processId) {
                WINDOWPLACEMENT wp = { sizeof(wp) };
                if (GetWindowPlacement(hwnd, &wp)) {
                    if (IsWindowVisible(hwnd) && (wp.showCmd == SW_SHOWNORMAL || wp.showCmd == SW_SHOWMAXIMIZED || wp.showCmd == SW_RESTORE)) {
                        if (GetParent(hwnd) == NULL) return hwnd;
                        if (!bestHwnd) bestHwnd = hwnd;
                    }
                }
            }
            hwnd = FindWindowExW(NULL, hwnd, NULL, NULL);
        }
        if (bestHwnd) return bestHwnd;
        if (retry < maxRetries - 1) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return NULL;
}

// ===== 防最小化监控线程 =====
void PreventMinimizeThreadFunc(HWND hwnd, DWORD processId, std::atomic<bool>& running, const wchar_t* windowClass) {
    WINDOWPLACEMENT originalPlacement = { sizeof(WINDOWPLACEMENT) };
    bool hasOriginalPlacement = false;
    int restoreAttempts = 0;

    while (running) {
        if (hwnd && IsWindow(hwnd)) {
            BOOL isVisible = IsWindowVisible(hwnd);
            if (!isVisible) { ShowWindow(hwnd, SW_SHOW); std::this_thread::sleep_for(std::chrono::milliseconds(1)); }
            WINDOWPLACEMENT wp = { sizeof(wp) };
            if (GetWindowPlacement(hwnd, &wp)) {
                if (!hasOriginalPlacement && (wp.showCmd == SW_SHOWNORMAL || wp.showCmd == SW_SHOWMAXIMIZED)) {
                    originalPlacement = wp; hasOriginalPlacement = true;
                }
                if (wp.showCmd == SW_MINIMIZE || wp.showCmd == SW_SHOWMINIMIZED || wp.showCmd == SW_FORCEMINIMIZE || wp.showCmd == SW_HIDE) {
                    restoreAttempts++;
                    ShowWindow(hwnd, SW_RESTORE);
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    if (GetWindowPlacement(hwnd, &wp)) {
                        wp.showCmd = SW_SHOWNORMAL; wp.flags = 0;
                        wp.ptMinPosition.x = -1; wp.ptMinPosition.y = -1;
                        wp.ptMaxPosition.x = -1; wp.ptMaxPosition.y = -1;
                        SetWindowPlacement(hwnd, &wp);
                    }
                    if (restoreAttempts % 2 == 0) {
                        ShowWindow(hwnd, SW_SHOWMAXIMIZED);
                        std::this_thread::sleep_for(std::chrono::milliseconds(1));
                        ShowWindow(hwnd, SW_RESTORE);
                    }
                } else if (wp.showCmd == SW_SHOWMAXIMIZED) {
                    ShowWindow(hwnd, SW_RESTORE);
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    if (GetWindowPlacement(hwnd, &wp)) { wp.showCmd = SW_SHOWNORMAL; SetWindowPlacement(hwnd, &wp); }
                }
            }
            RECT rect;
            if (GetWindowRect(hwnd, &rect)) {
                int w = rect.right - rect.left, h = rect.bottom - rect.top;
                if (w > 0 && h > 0) {
                    for (int i = 0; i < 3; i++) SetWindowPos(hwnd, HWND_TOPMOST, rect.left, rect.top, w, h, SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE);
                }
            }
        } else {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
            if (!hProcess || WaitForSingleObject(hProcess, 0) == WAIT_OBJECT_0) {
                running = false; if (hProcess) CloseHandle(hProcess); break;
            }
            CloseHandle(hProcess);
            if (windowClass) {
                HWND newHwnd = FindWindowW(windowClass, nullptr);
                if (newHwnd && IsWindow(newHwnd)) { hwnd = newHwnd; restoreAttempts = 0; std::this_thread::sleep_for(std::chrono::milliseconds(10)); continue; }
            } else {
                HWND newHwnd = FindTopLevelWindowByProcessId(processId, 3);
                if (newHwnd && IsWindow(newHwnd)) { hwnd = newHwnd; restoreAttempts = 0; std::this_thread::sleep_for(std::chrono::milliseconds(10)); continue; }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}
