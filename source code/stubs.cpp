// ============================================================================
// stubs.cpp - 链接器桩函数
// ============================================================================
#include "CommonDefs.h"
#include "ProcessTerminator.h"
#include "PortMonitor.h"
#include "AdvancedProcessCreator.h"
#include "WTSHelper.h"
#include "signature_protection_nocert.h"  // DMSP_VERIFY
#include <shobjidl.h>                     // IFileOpenDialog, IFileOpenDialog
#include <commdlg.h>                      // GetOpenFileNameW
#include <ShlObj.h>                       // SHFileOperationW

// 外部声明: 定义在 MainMenu.cpp / AdvancedProcessCreator.cpp
extern HWND g_targetTopmostWindow;
extern HWND FindTopLevelWindowByProcessId(DWORD processId, int maxRetries);
extern bool IsRunningAsTrustedInstaller();

// ForceSetForegroundWindow - 强制置前窗口 (返回bool以匹配ProcessTerminator_Terminate的预期)
bool ForceSetForegroundWindow(HWND hwnd) {
    if (!hwnd) return false;
    SetForegroundWindow(hwnd);
    SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
    SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
    DWORD foreThread = GetWindowThreadProcessId(GetForegroundWindow(), nullptr);
    DWORD targetThread = GetWindowThreadProcessId(hwnd, nullptr);
    if (foreThread != targetThread) {
        AttachThreadInput(foreThread, targetThread, TRUE);
        SetForegroundWindow(hwnd);
        BringWindowToTop(hwnd);
        SwitchToThisWindow(hwnd, TRUE);
        AttachThreadInput(foreThread, targetThread, FALSE);
    }
    SetForegroundWindow(hwnd);
    SwitchToThisWindow(hwnd, TRUE);
    return true;
}

// === WTSHelper stub ===
bool WTSHelper::IsAvailable() {
    HMODULE hWts = LoadLibraryW(L"wtsapi32.dll");
    if (hWts) { FreeLibrary(hWts); return true; }
    return false;
}

HANDLE WTSHelper::GetUserToken(DWORD sessionId) {
    HANDLE hToken = nullptr;
    HMODULE hWts = LoadLibraryW(L"wtsapi32.dll");
    if (!hWts) return nullptr;

    // 加载函数指针
    typedef BOOL (WINAPI* PFN_WTSQUERY)(ULONG, PHANDLE);
    typedef DWORD (WINAPI* PFN_WTSGETACTIVESESSION)(void);
    typedef BOOL (WINAPI* PFN_WTSENUM)(HANDLE, DWORD, DWORD, PWTS_SESSION_INFOW*, PDWORD);
    typedef void (WINAPI* PFN_WTSFREE)(PVOID);

    auto pfnQuery = (PFN_WTSQUERY)GetProcAddress(hWts, "WTSQueryUserToken");
    auto pfnGetActive = (PFN_WTSGETACTIVESESSION)GetProcAddress(hWts, "WTSGetActiveConsoleSessionId");
    auto pfnEnum = (PFN_WTSENUM)GetProcAddress(hWts, "WTSEnumerateSessionsW");
    auto pfnFree = (PFN_WTSFREE)GetProcAddress(hWts, "WTSFreeMemory");

    if (!pfnQuery) { FreeLibrary(hWts); return nullptr; }

    DWORD targetSession = sessionId;

    // 默认参数 0xFFFFFFFF: 自动检测活动会话
    if (targetSession == 0xFFFFFFFF) {
        if (pfnGetActive) {
            targetSession = pfnGetActive();
        }
        // 如果获取失败，枚举所有会话查找活动会话
        if (targetSession == 0xFFFFFFFF && pfnEnum && pfnFree) {
            PWTS_SESSION_INFOW pInfo = nullptr;
            DWORD count = 0;
            if (pfnEnum(nullptr, 0, 1, &pInfo, &count)) {
                for (DWORD i = 0; i < count; ++i) {
                    if (pInfo[i].State == WTSActive) {
                        targetSession = pInfo[i].SessionId;
                        break;
                    }
                }
                pfnFree(pInfo);
            }
        }
    }

    if (targetSession != 0xFFFFFFFF) {
        pfnQuery(targetSession, &hToken);
    }

    FreeLibrary(hWts);
    return hToken;
}

// WTSHelper::GetActiveUserToken — 获取当前活动用户令牌
HANDLE WTSHelper::GetActiveUserToken() {
    return GetUserToken(0xFFFFFFFF);
}

// === PortMonitor ===
bool PortMonitor::IsSystemProcess(const std::wstring& name) {
    static const wchar_t* sys[] = {
        L"System", L"svchost.exe", L"csrss.exe", L"wininit.exe",
        L"services.exe", L"lsass.exe", L"winlogon.exe", L"smss.exe"
    };
    for (auto s : sys) if (_wcsicmp(name.c_str(), s) == 0) return true;
    return false;
}

// === ProcessTerminator ===
bool ProcessTerminator::terminateByProcessIsolationAndBlocking(const std::string& n) {
    return terminateByProcessName(n);
}

NTSTATUS ProcessTerminator::SafeNtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS c, PVOID b, ULONG s, PULONG r)
{ __try { return NtQuerySystemInformation(c,b,s,r); } __except(1) { return 0xC0000005; } }

bool RemovePPLProtection(HANDLE) { return true; }
bool RemovePPLProtectionWithShellCode(HANDLE h) { return RemovePPLProtection(h); }

// === AdvancedProcessCreator ===
bool AdvancedProcessCreator::CreateProcessWithToken(
    HANDLE hToken, DWORD dwLogonFlags, LPCWSTR lpApp, LPWSTR lpCmd,
    DWORD dwFlags, LPVOID env, LPCWSTR dir, LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi)
{
    HMODULE hMod = LoadLibraryW(L"advapi32.dll");
    if (hMod) {
        auto pfn = (BOOL(WINAPI*)(HANDLE,DWORD,LPCWSTR,LPWSTR,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION))
            GetProcAddress(hMod, "CreateProcessWithTokenW");
        FreeLibrary(hMod);
        if (pfn) return pfn(hToken,dwLogonFlags,lpApp,lpCmd,dwFlags,env,dir,si,pi) != FALSE;
    }
    return CreateProcessAsUserW(hToken,lpApp,lpCmd,nullptr,nullptr,FALSE,dwFlags,env,dir,si,pi) != FALSE;
}

// === Missing app functions (从 CMDPLUS.cpp 移植) ===
// --- 文件选择对话框 ---
enum class FileDialogResult {
    SUCCESS,
    CANCELLED,
    ERROR_
};

static FileDialogResult ShowFileSelectionDialog(std::wstring& selectedPath) {
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (FAILED(hr)) { std::wcout << L"COM初始化失败: " << hr << std::endl; return FileDialogResult::ERROR_; }
    IFileOpenDialog* pFileOpen = NULL;
    hr = CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_ALL, IID_IFileOpenDialog, reinterpret_cast<void**>(&pFileOpen));
    if (SUCCEEDED(hr)) {
        DWORD options;
        pFileOpen->GetOptions(&options);
        pFileOpen->SetOptions(options | FOS_PATHMUSTEXIST | FOS_FILEMUSTEXIST | FOS_FORCEFILESYSTEM | FOS_PICKFOLDERS);
        pFileOpen->SetTitle(L"选择要强制删除的文件或文件夹");
        hr = pFileOpen->Show(NULL);
        if (SUCCEEDED(hr)) {
            IShellItem* pItem;
            hr = pFileOpen->GetResult(&pItem);
            if (SUCCEEDED(hr)) {
                PWSTR pszFilePath;
                hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);
                if (SUCCEEDED(hr)) { selectedPath = pszFilePath; CoTaskMemFree(pszFilePath); }
                pItem->Release();
                CoUninitialize(); return FileDialogResult::SUCCESS;
            }
        } else if (hr == HRESULT_FROM_WIN32(ERROR_CANCELLED)) { CoUninitialize(); return FileDialogResult::CANCELLED; }
        pFileOpen->Release();
    }
    CoUninitialize(); return FileDialogResult::ERROR_;
}

static bool ForceDeletePath(const std::wstring& path) {
    // 取所有权 + 清除只读属性
    std::wstring takeOwn = L"takeown /f \"" + path + L"\" /r /d y 2>nul";
    std::wstring icacls = L"icacls \"" + path + L"\" /grant administrators:F /t /q 2>nul";
    std::wstring attrib = L"attrib -r -s -h \"" + path + L"\" /s /d 2>nul";
    _wsystem(attrib.c_str());
    std::wstring cmd = L"cmd.exe /c \"" + takeOwn + L" & " + icacls + L" & rd /s /q \"" + path + L"\" 2>nul & del /f /s /q \"" + path + L"\" 2>nul\"";
    SHFILEOPSTRUCTW fo = {};
    fo.wFunc = FO_DELETE;
    std::wstring buf = path + L'\0' + L'\0';
    fo.pFrom = buf.c_str();
    fo.fFlags = FOF_NO_UI | FOF_NOCONFIRMATION | FOF_SILENT | FOF_ALLOWUNDO;
    SHFileOperationW(&fo);
    _wsystem(cmd.c_str());
    // 重试循环 600ms
    DWORD start = GetTickCount();
    while (GetTickCount() - start < 600) {
        DWORD attr = GetFileAttributesW(path.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES) return true;
        if (attr & FILE_ATTRIBUTE_DIRECTORY) { if (RemoveDirectoryW(path.c_str())) return true; }
        else { if (DeleteFileW(path.c_str())) return true; }
        Sleep(2);
    }
    return (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES);
}

// --- 查找浏览器路径 ---
static bool FindEdgePath(wchar_t* path, size_t pathSize) {
    // 系统级路径
    const wchar_t* edgePaths[] = { L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" };
    for (auto ep : edgePaths) {
        if (GetFileAttributesW(ep) != INVALID_FILE_ATTRIBUTES) { wcscpy_s(path, pathSize, ep); return true; }
    }
    // 用户级路径 (%LOCALAPPDATA%)
    wchar_t expanded[MAX_PATH];
    ExpandEnvironmentStringsW(L"%LOCALAPPDATA%\\Microsoft\\Edge\\Application\\msedge.exe", expanded, MAX_PATH);
    if (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES) { wcscpy_s(path, pathSize, expanded); return true; }
    // 注册表
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\msedge.exe", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t value[MAX_PATH]; DWORD vs = sizeof(value);
        if (RegQueryValueExW(hKey, NULL, NULL, NULL, (LPBYTE)value, &vs) == ERROR_SUCCESS && GetFileAttributesW(value) != INVALID_FILE_ATTRIBUTES) { wcscpy_s(path, pathSize, value); RegCloseKey(hKey); return true; }
        RegCloseKey(hKey);
    }
    return false;
}

static bool FindChromePath(wchar_t* path, size_t pathSize) {
    const wchar_t* chromePaths[] = { L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", L"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe" };
    for (auto cp : chromePaths) {
        if (GetFileAttributesW(cp) != INVALID_FILE_ATTRIBUTES) { wcscpy_s(path, pathSize, cp); return true; }
    }
    // 用户级路径 (%LOCALAPPDATA%)
    wchar_t expanded[MAX_PATH];
    ExpandEnvironmentStringsW(L"%LOCALAPPDATA%\\Google\\Chrome\\Application\\chrome.exe", expanded, MAX_PATH);
    if (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES) { wcscpy_s(path, pathSize, expanded); return true; }
    // 注册表
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t value[MAX_PATH]; DWORD vs = sizeof(value);
        if (RegQueryValueExW(hKey, NULL, NULL, NULL, (LPBYTE)value, &vs) == ERROR_SUCCESS && GetFileAttributesW(value) != INVALID_FILE_ATTRIBUTES) { wcscpy_s(path, pathSize, value); RegCloseKey(hKey); return true; }
        RegCloseKey(hKey);
    }
    return false;
}

// --- 外部函数: 定义于 ProcessTerminator_Terminate.cpp / MainMenu.cpp / AdvancedProcessCreator.cpp
extern void MinimizeOverlayWindows();
extern bool EnableProcessProtection(HANDLE hProcess);
extern void PreventMinimizeThreadFunc(HWND hwnd, DWORD processId, std::atomic<bool>& running, const wchar_t* windowClass);

static bool LaunchProgram(const wchar_t* programPath, const wchar_t* arguments = NULL) {
    if (!programPath || GetFileAttributesW(programPath) == INVALID_FILE_ATTRIBUTES) return false;
    STARTUPINFOW si = { sizeof(si) };
    si.lpDesktop = const_cast<LPWSTR>(L"Winsta0\\Default");
    PROCESS_INFORMATION pi = { 0 };
    DWORD creationFlags = CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT;

    bool asTI = IsRunningAsTrustedInstaller();

    // 仅在非TI模式下最小化覆盖窗口（TI在session 0，EnumWindows可能阻塞）
    if (!asTI) {
        MinimizeOverlayWindows();
    }
    bool processCreated = false;

    if (asTI) {
        processCreated = CreateProcessW(programPath, (LPWSTR)arguments, NULL, NULL, FALSE, creationFlags, NULL, NULL, &si, &pi);
    } else {
        processCreated = CreateProcessW(programPath, (LPWSTR)arguments, NULL, NULL, FALSE, creationFlags, NULL, NULL, &si, &pi);
    }

    if (processCreated) {
        std::wcout << L"已启动程序: " << programPath << std::endl;
        DWORD processId = pi.dwProcessId;
        HANDLE hProcess = pi.hProcess;
        if (processId && hProcess) {
            CloseHandle(pi.hThread);
            for (int i = 0; i < 3; i++) { if (!asTI) MinimizeOverlayWindows(); std::this_thread::sleep_for(std::chrono::milliseconds(50)); }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            if (EnableProcessProtection(hProcess)) std::wcout << L"[保护] 反结束进程已开启" << std::endl;
            else std::wcout << L"[保护] 反结束进程启用失败" << std::endl;
            HWND hwnd = nullptr;
            for (int retry = 0; retry < 30; retry++) {
                hwnd = FindTopLevelWindowByProcessId(processId, 1);
                if (hwnd) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            if (hwnd) {
                g_targetTopmostWindow = hwnd;
                if (!asTI) MinimizeOverlayWindows();
                ShowWindow(hwnd, SW_RESTORE); ShowWindow(hwnd, SW_SHOW); ShowWindow(hwnd, SW_SHOWNORMAL);
                ForceSetForegroundWindow(hwnd);
                SetWindowLongW(hwnd, GWL_EXSTYLE, GetWindowLongW(hwnd, GWL_EXSTYLE) & ~WS_EX_TOPMOST);
                RECT rect;
                if (GetWindowRect(hwnd, &rect)) SetWindowPos(hwnd, HWND_TOPMOST, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top, SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE);
                ForceSetForegroundWindow(hwnd);
                std::wcout << L"程序窗口已置顶并激活" << std::endl;
                // 使用 shared_ptr 管理监控标志，detach 线程持有引用确保生命周期
                auto monitorRunning = std::make_shared<std::atomic<bool>>(true);
                std::thread monitorThread([hwnd, processId, monitorRunning]() {
                    PreventMinimizeThreadFunc(hwnd, processId, *monitorRunning, nullptr);
                });
                monitorThread.detach();
            }
            CloseHandle(hProcess);
            return true;
        }
    }
    return false;
}

void OpenAppMenu(void) {
    DMSP_VERIFY(0x2002);
    while (true) {
        std::wcout << std::endl;
        std::wcout << L"=== 应用选择菜单 ===" << std::endl;
        std::wcout << L"1. Microsoft Edge" << std::endl;
        std::wcout << L"2. Chrome" << std::endl;
        std::wcout << L"3. 任务管理器" << std::endl;
        std::wcout << L"4. GateFace门面浏览器" << std::endl;
        std::wcout << L"5. 自定义（选择其他程序）" << std::endl;
        std::wcout << L"0. 返回主菜单" << std::endl;
        std::wcout << L"请输入选项: ";
        int choice; std::wcin >> choice; std::wcin.ignore();

        if (choice == 0) return;
        wchar_t progPath[MAX_PATH] = { 0 };

        if (choice == 1) {
            if (FindEdgePath(progPath, MAX_PATH)) {
                std::wcout << L"正在启动 Microsoft Edge..." << std::endl;
                if (LaunchProgram(progPath)) { std::wcout << L"启动成功" << std::endl; return; }
                else std::wcout << L"启动失败" << std::endl;
            } else std::wcout << L"未找到 Microsoft Edge 安装路径" << std::endl;
        }
        else if (choice == 2) {
            if (FindChromePath(progPath, MAX_PATH)) {
                std::wcout << L"正在启动 Chrome..." << std::endl;
                if (LaunchProgram(progPath)) { std::wcout << L"启动成功" << std::endl; return; }
                else std::wcout << L"启动失败" << std::endl;
            } else std::wcout << L"未找到 Chrome 安装路径" << std::endl;
        }
        else if (choice == 3) {
            GetSystemDirectoryW(progPath, MAX_PATH); wcscat_s(progPath, L"\\taskmgr.exe");
            std::wcout << L"正在启动 任务管理器..." << std::endl;
            if (LaunchProgram(progPath)) { std::wcout << L"启动成功" << std::endl; return; }
            else std::wcout << L"启动失败" << std::endl;
        }
        else if (choice == 4) {
            HKEY hKey;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, L"SOFTWARE\\GateFace", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                DWORD ps = sizeof(progPath); RegQueryValueExW(hKey, L"InstallPath", NULL, NULL, (LPBYTE)progPath, &ps); RegCloseKey(hKey);
            }
            if (progPath[0] == L'\0') wcscpy_s(progPath, L"C:\\Users\\Public\\gakataka\\gateface\\Browser.exe");
            std::wcout << L"正在启动 GateFace门面浏览器..." << std::endl;
            if (GetFileAttributesW(progPath) != INVALID_FILE_ATTRIBUTES) {
                if (LaunchProgram(progPath)) { std::wcout << L"启动成功" << std::endl; return; }
                else std::wcout << L"启动失败" << std::endl;
            } else std::wcout << L"未找到 GateFace 安装路径" << std::endl;
        }
        else if (choice == 5) {
            // 自定义 - 打开文件选择对话框
            HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
            if (FAILED(hr)) { std::wcout << L"初始化COM库失败" << std::endl; return; }
            IFileOpenDialog* pFileOpen = NULL;
            hr = CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_ALL, IID_IFileOpenDialog, (void**)&pFileOpen);
            if (SUCCEEDED(hr)) {
                COMDLG_FILTERSPEC ft[] = { { L"可执行文件", L"*.exe" }, { L"所有文件", L"*.*" } };
                pFileOpen->SetFileTypes(2, ft); pFileOpen->SetFileTypeIndex(1);
                pFileOpen->SetTitle(L"选择要打开的程序");
                MinimizeOverlayWindows();
                hr = pFileOpen->Show(NULL);
                if (SUCCEEDED(hr)) {
                    MinimizeOverlayWindows();
                    IShellItem* pItem; hr = pFileOpen->GetResult(&pItem);
                    if (SUCCEEDED(hr)) {
                        PWSTR pszFilePath; hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);
                        if (SUCCEEDED(hr)) { LaunchProgram(pszFilePath); CoTaskMemFree(pszFilePath); }
                        pItem->Release();
                    }
                }
                pFileOpen->Release();
            }
            CoUninitialize();
        }
        else { std::wcout << L"无效选项" << std::endl; }
    }
}

void del(void) {
    DMSP_VERIFY(0x2003);
    std::wcout << L"[信息] 请选择要删除的文件或文件夹" << std::endl;
    std::wcout << L"提示: 按ESC或取消可跳过自定义删除" << std::endl;
    int deletedCount = 0;
    bool continueSelecting = true;
    while (continueSelecting) {
        std::wstring selectedPath;
        FileDialogResult result = ShowFileSelectionDialog(selectedPath);
        if (result == FileDialogResult::SUCCESS && !selectedPath.empty()) {
            std::wcout << L"已选择: " << selectedPath << std::endl;
            std::wcout << L"正在执行删除..." << std::endl;
            DWORD startTime = GetTickCount();
            if (ForceDeletePath(selectedPath)) {
                deletedCount++;
                std::wcout << L"[完成] 删除成功" << std::endl;
            } else {
                std::wcout << L"[失败] 删除失败" << std::endl;
            }
            std::wcout << L"\n是否继续选择更多文件或文件夹? (Y/N): ";
            wchar_t yn; std::wcin >> yn;
            continueSelecting = (yn == L'y' || yn == L'Y');
        } else {
            continueSelecting = false;
            if (result == FileDialogResult::CANCELLED) std::wcout << L"已取消选择" << std::endl;
        }
    }
    std::wcout << L"[统计] 共删除了 " << deletedCount << L" 个项目" << std::endl;
    std::wcout << L"[完成] 删除操作完成" << std::endl;
}
// === 功能14: 肃清系统子操作 ===
// --- 检测是否已安装开机自启 ---
bool CheckAutoStartCleanup(void) {
    HANDLE hUserToken = nullptr;
    hUserToken = WTSHelper::GetUserToken();
    bool hasUserToken = (hUserToken != nullptr);
    wchar_t commonStartup[MAX_PATH] = {};
    if (SHGetFolderPathW(nullptr, CSIDL_COMMON_STARTUP, nullptr, SHGFP_TYPE_CURRENT, commonStartup) == S_OK) {
        std::wstring lnk = std::wstring(commonStartup) + L"\\CMDPLUS_Cleanup.lnk";
        if (GetFileAttributesW(lnk.c_str()) != INVALID_FILE_ATTRIBUTES) {
            if (hasUserToken) CloseHandle(hUserToken);
            return true;
        }
    }
    wchar_t userStartup[MAX_PATH] = {};
    if (SHGetFolderPathW(nullptr, CSIDL_STARTUP, hasUserToken ? hUserToken : nullptr, SHGFP_TYPE_CURRENT, userStartup) == S_OK) {
        std::wstring lnk = std::wstring(userStartup) + L"\\CMDPLUS_Cleanup.lnk";
        if (GetFileAttributesW(lnk.c_str()) != INVALID_FILE_ATTRIBUTES) {
            if (hasUserToken) CloseHandle(hUserToken);
            return true;
        }
    }
    if (hasUserToken) CloseHandle(hUserToken);
    return false;
}

// --- 安装开机自启肃清 ---
bool SetAutoStartCleanup(void) {
    wchar_t exePath[MAX_PATH] = {};
    if (!GetModuleFileNameW(nullptr, exePath, MAX_PATH)) return false;
    HANDLE hUserToken = nullptr;
    hUserToken = WTSHelper::GetUserToken();
    bool hasUserToken = (hUserToken != nullptr);
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) { if (hasUserToken) CloseHandle(hUserToken); return false; }
    IShellLinkW* psl = nullptr;
    if (!SUCCEEDED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (void**)&psl)) || !psl) {
        CoUninitialize(); if (hasUserToken) CloseHandle(hUserToken); return false;
    }
    psl->SetPath(exePath); psl->SetArguments(L"--autoclean"); psl->SetDescription(L"CMDPLUS 开机肃清"); psl->SetShowCmd(SW_HIDE);
    IPersistFile* ppf = nullptr;
    if (!SUCCEEDED(psl->QueryInterface(IID_IPersistFile, (void**)&ppf)) || !ppf) {
        psl->Release(); CoUninitialize(); if (hasUserToken) CloseHandle(hUserToken); return false;
    }
    bool anyOk = false;
    wchar_t commonStartup[MAX_PATH] = {};
    if (SHGetFolderPathW(nullptr, CSIDL_COMMON_STARTUP, nullptr, SHGFP_TYPE_CURRENT, commonStartup) == S_OK) {
        if (SUCCEEDED(ppf->Save((std::wstring(commonStartup) + L"\\CMDPLUS_Cleanup.lnk").c_str(), TRUE))) anyOk = true;
    }
    wchar_t userStartup[MAX_PATH] = {};
    if (SHGetFolderPathW(nullptr, CSIDL_STARTUP, hasUserToken ? hUserToken : nullptr, SHGFP_TYPE_CURRENT, userStartup) == S_OK) {
        if (SUCCEEDED(ppf->Save((std::wstring(userStartup) + L"\\CMDPLUS_Cleanup.lnk").c_str(), TRUE))) anyOk = true;
    }
    ppf->Release(); psl->Release(); CoUninitialize();
    if (hasUserToken) CloseHandle(hUserToken);
    return anyOk;
}

// --- 创建桌面快捷方式 ---
bool EnsureDesktopShortcut(void) {
    wchar_t exePath[MAX_PATH] = {};
    if (!GetModuleFileNameW(nullptr, exePath, MAX_PATH)) return false;
    bool anyOk = false;
    HANDLE hUserToken = nullptr;
    hUserToken = WTSHelper::GetUserToken();
    bool hasUserToken = (hUserToken != nullptr);
    int folders[] = { CSIDL_COMMON_DESKTOPDIRECTORY, CSIDL_DESKTOP };
    for (int f = 0; f < 2; f++) {
        wchar_t desk[MAX_PATH] = {};
        HANDLE tokenForFolder = (f == 1 && hasUserToken) ? hUserToken : nullptr;
        if (SHGetFolderPathW(nullptr, folders[f], tokenForFolder, SHGFP_TYPE_CURRENT, desk) != S_OK) continue;
        std::wstring lnk = std::wstring(desk) + L"\\CMDPLUS工具箱.lnk";
        if (GetFileAttributesW(lnk.c_str()) != INVALID_FILE_ATTRIBUTES) { anyOk = true; continue; }
        HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        if (FAILED(hr)) continue;
        IShellLinkW* psl = nullptr;
        if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (void**)&psl)) && psl) {
            psl->SetPath(exePath); psl->SetDescription(L"CMDPLUS 系统管理工具箱"); psl->SetShowCmd(SW_SHOW);
            IPersistFile* ppf = nullptr;
            if (SUCCEEDED(psl->QueryInterface(IID_IPersistFile, (void**)&ppf))) {
                ppf->Save(lnk.c_str(), TRUE); ppf->Release(); anyOk = true;
            }
            psl->Release();
        }
        CoUninitialize();
    }
    if (hasUserToken) CloseHandle(hUserToken);
    return anyOk;
}

// --- 肃清非白名单进程 (使用 ProcessTerminator) ---
int RunCleanup(bool show) {
    ProcessTerminator::initNativeAPI();
    ProcessTerminator::EnableAllPrivileges();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return -1;
    wchar_t self[MAX_PATH] = {}; GetModuleFileNameW(nullptr, self, MAX_PATH);
    std::wstring sn(self); size_t p = sn.find_last_of(L"\\/");
    if (p != std::wstring::npos) sn = sn.substr(p + 1);
    std::transform(sn.begin(), sn.end(), sn.begin(), ::towlower);
    int count = 0;
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(hSnap, &pe)) do {
        std::wstring nm = pe.szExeFile; std::transform(nm.begin(), nm.end(), nm.begin(), ::towlower);
        if (nm.empty() || nm == sn) continue;
        if (ProcessTerminator::IsSystemProcessWhitelisted(pe.szExeFile)) continue;
        if (show) std::wcout << L"[肃清] 正在终止: " << pe.szExeFile << std::endl;
        char buf[512] = {}; WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, buf, 512, nullptr, nullptr);
        ProcessTerminator::terminateByProcessName(std::string(buf));
        count++;
    } while (Process32NextW(hSnap, &pe));
    CloseHandle(hSnap);
    if (show) std::wcout << L"[肃清] 共清理 " << count << L" 个进程" << std::endl;
    return count;
}

// --- 快速恢复桌面 (最小化覆盖窗口) ---
void RestoreDesktopQuick(void) {
    DWORD myPid = GetCurrentProcessId();
    std::vector<HWND> suspectWindows;
    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        auto* list = (std::vector<HWND>*)lParam;
        if (!hwnd || !IsWindow(hwnd) || !IsWindowVisible(hwnd)) return TRUE;
        wchar_t cls[128] = {}; GetClassNameW(hwnd, cls, 128);
        if (wcscmp(cls, L"Progman") == 0 || wcscmp(cls, L"WorkerW") == 0 ||
            wcscmp(cls, L"Shell_TrayWnd") == 0 || wcscmp(cls, L"Start") == 0) return TRUE;
        DWORD pid = 0; GetWindowThreadProcessId(hwnd, &pid);
        if (pid == GetCurrentProcessId()) return TRUE;
        if (hwnd == g_targetTopmostWindow) return TRUE;
        RECT r; if (!GetWindowRect(hwnd, &r)) return TRUE;
        int w = r.right - r.left, h = r.bottom - r.top;
        // 直接用 GetSystemMetrics (避免捕获外部变量)
        if (w >= GetSystemMetrics(SM_CXSCREEN) * 94 / 100 && h >= GetSystemMetrics(SM_CYSCREEN) * 94 / 100) list->push_back(hwnd);
        return TRUE;
    }, (LPARAM)&suspectWindows);
    for (HWND hwnd : suspectWindows) {
        if (IsWindowVisible(hwnd)) {
            ShowWindow(hwnd, SW_MINIMIZE);
            ShowWindow(hwnd, SW_HIDE);
        }
    }
    // 恢复任务栏
    HWND hTray = FindWindowW(L"Shell_TrayWnd", NULL);
    if (hTray) { ShowWindow(hTray, SW_SHOW); ShowWindow(hTray, SW_RESTORE); }
}

// === GQ / GQS — 单进程/多进程强制终止 ===
void GQ(const std::string& processName) {
    ProcessTerminator::initNativeAPI();
    ProcessTerminator::terminateByProcessName(processName);
}

void GQS(const std::vector<std::string>& processNames) {
    ProcessTerminator::initNativeAPI();
    for (const auto& name : processNames) {
        ProcessTerminator::terminateByProcessName(name);
    }
}

extern "C" void __dmsp_trigger_response_anchor(void) {}
extern "C" void __dmsp_trigger_response_anchor_next(void) {}
extern "C" void* __dmsp_trigger_resp_addr = (void*)&__dmsp_trigger_response_anchor;
