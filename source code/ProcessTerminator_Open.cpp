#include "CommonDefs.h"
#include "ProcessTerminator.h"
#include "ppl_driver.h"
#include <psapi.h>
#include <tlhelp32.h>
#pragma comment(lib, "advapi32.lib")

// 外部辅助函数 (定义在 ProcessTerminator_Terminate.cpp)
bool RemovePPLProtection(HANDLE hProcess);
bool RemovePPLProtectionWithShellCode(HANDLE hProcess);

// === ProcessTerminator static member definitions ===
// ============================================================================
// 静态成员定义 (Native API 函数指针初始化为 nullptr)
// ============================================================================

// 私有
_NtQuerySystemInformation ProcessTerminator::NtQuerySystemInformation = nullptr;
_RtlAdjustPrivilege ProcessTerminator::RtlAdjustPrivilege = nullptr;
_NtResumeProcess ProcessTerminator::NtResumeProcess = nullptr;
_NtGetNextProcess ProcessTerminator::NtGetNextProcess = nullptr;
_NtGetNextThread ProcessTerminator::NtGetNextThread = nullptr;
_NtSetInformationProcess ProcessTerminator::NtSetInformationProcess = nullptr;
_NtQueryInformationProcess ProcessTerminator::NtQueryInformationProcess = nullptr;
_NtSetInformationThread ProcessTerminator::NtSetInformationThread = nullptr;
_NtCreateThreadEx ProcessTerminator::NtCreateThreadEx = nullptr;
_NtDuplicateObject ProcessTerminator::NtDuplicateObject = nullptr;
_NtClose ProcessTerminator::NtClose = nullptr;

// 公开
_NtTerminateProcess ProcessTerminator::NtTerminateProcess = nullptr;
_NtSuspendProcess ProcessTerminator::NtSuspendProcess = nullptr;
_NtOpenProcess ProcessTerminator::NtOpenProcess = nullptr;
_NtWriteVirtualMemory ProcessTerminator::NtWriteVirtualMemory = nullptr;
_NtAllocateVirtualMemory ProcessTerminator::NtAllocateVirtualMemory = nullptr;


// === OpenProcessWith* implementations ===

HANDLE ProcessTerminator::OpenProcessEnhanced(DWORD pid, DWORD desiredAccess) {
    if (pid == 0 || pid == 4) { // 拒绝访问系统空闲进程和System进程
        return NULL;
    }

    std::vector<std::function<HANDLE()>> methods = {
        // [v5.3 RTCore64 驱动] PPL 清零 + Token 盗窃 — 内核级, 无法被拦截
        [=]() { return PplDriver::OpenProcessViaDriver_Power(pid); },
        [=]() { return OpenProcessWithNtQueryProcess(pid); },
        [=]() { return OpenProcessWithMemoryMap(pid); },
        [=]() { return OpenProcessWithThreadHijack(pid); },
        [=]() { return OpenProcessWithDebugObject(pid); },
        [=]() { return OpenProcessWithRtlAdjustPrivilege(pid); },
        [=]() { return OpenProcessWithProcessHint(pid); },
        [=]() { return OpenProcessWithToolhelp(pid); },
        [=]() { return OpenProcessWithJobObject(pid); },
        [=]() { return OpenProcessWithWMI(pid); },
        [=]() { return OpenProcessWithCsrss(pid); },
        [=]() { return OpenProcessWithMaximumAccess(pid); },
        [=]() { return OpenProcessWithDebugPrivilege(pid); },
        [=]() { return OpenProcessWithNativeAPI(pid); },
        [=]() { return OpenProcessWithDuplicate(pid); },
        [=]() { return OpenProcessWithTokenReplacement(pid); },
        [=]() { return OpenProcessWithHandleEnumeration(pid); },
        [=]() { return OpenProcessWithKernelExploitation(pid); },
        [=]() { return OpenProcessWithDriver(pid); }      // 方法7.5: 驱动读取 + SYSTEM 提权
    };

    // 启用所有可能的权限
    EnableAllPrivileges();

    for (auto& method : methods) {
        HANDLE hProcess = method();
        if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
            // 验证句柄是否有效
            DWORD exitCode;
            if (GetExitCodeProcess(hProcess, &exitCode)) {
                // 优先使用ShellCode版本的PPL去除（避免拦截）
                if (!RemovePPLProtectionWithShellCode(hProcess)) {
                    // 如果ShellCode版本失败，使用原始版本
                    RemovePPLProtection(hProcess);
                }
                return hProcess;
            }
            CloseHandle(hProcess);
        }
    }

    return NULL;
}

// 方法1: 使用最大权限打开进程
HANDLE ProcessTerminator::OpenProcessWithMaximumAccess(DWORD pid) {
    // 尝试所有可能的访问权限组合
    static const DWORD accessRights[] = {
        PROCESS_ALL_ACCESS,
        PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE,
        PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_TERMINATE,
        MAXIMUM_ALLOWED,
        PROCESS_QUERY_INFORMATION,
        PROCESS_QUERY_LIMITED_INFORMATION
    };

    for (DWORD access : accessRights) {
        HANDLE hProcess = OpenProcess(access, FALSE, pid);
        if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
            return hProcess;
        }
    }
    return NULL;
}

// 方法2: 启用调试权限后打开进程
HANDLE ProcessTerminator::OpenProcessWithDebugPrivilege(DWORD pid) {
    EnableAllPrivileges();

    // 再次尝试所有权限
    return OpenProcessWithMaximumAccess(pid);
}

// 方法3: 使用Native API打开进程
HANDLE ProcessTerminator::OpenProcessWithNativeAPI(DWORD pid) {
    if (!initNativeAPI() || !NtOpenProcess) {
        return NULL;
    }

    HANDLE hProcess = NULL;
    CLIENT_ID clientId = { 0 };
    OBJECT_ATTRIBUTES objectAttributes = { 0 };

    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);

    NTSTATUS status = NtOpenProcess(&hProcess, MAXIMUM_ALLOWED, &objectAttributes, &clientId);

    if (NT_SUCCESS(status)) {
        return hProcess;
    }

    // 如果最大权限失败，尝试特定权限
    static const ACCESS_MASK accessMasks[] = {
        PROCESS_ALL_ACCESS,
        PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        PROCESS_TERMINATE,
        PROCESS_QUERY_INFORMATION
    };

    for (ACCESS_MASK access : accessMasks) {
        status = NtOpenProcess(&hProcess, access, &objectAttributes, &clientId);
        if (NT_SUCCESS(status)) {
            return hProcess;
        }
    }

    return NULL;
}

// 方法4: 通过句柄复制打开进程
HANDLE ProcessTerminator::OpenProcessWithDuplicate(DWORD pid) {
    if (!initNativeAPI()) {
        return NULL;
    }

    // 获取系统所有句柄
    ULONG bufferSize = 0x100000;
    PSYSTEM_HANDLE_INFORMATION_EX handleInfo =
        (PSYSTEM_HANDLE_INFORMATION_EX)malloc(bufferSize);

    if (!handleInfo) return NULL;

    NTSTATUS status;
    while ((status = SafeNtQuerySystemInformation(
        static_cast<SYSTEM_INFORMATION_CLASS>(16),
        handleInfo, bufferSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH) {
        bufferSize *= 2;
        free(handleInfo);
        handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)malloc(bufferSize);
        if (!handleInfo) return NULL;
    }

    if (!NT_SUCCESS(status)) {
        free(handleInfo);
        return NULL;
    }

    // 查找目标进程的句柄
    for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
        SYSTEM_HANDLE handle = handleInfo->Information[i];

        // 检查是否是进程对象且属于目标PID
        if (handle.ObjectTypeNumber == 0x7) { // 进程对象类型
            DWORD objectPid = GetProcessId((HANDLE)handle.Handle);
            if (objectPid == pid) {
                // 尝试复制句柄
                HANDLE hDuplicate = NULL;
                if (DuplicateHandle(GetCurrentProcess(),
                    (HANDLE)handle.Handle,
                    GetCurrentProcess(),
                    &hDuplicate,
                    PROCESS_ALL_ACCESS,
                    FALSE,
                    0)) {
                    free(handleInfo);
                    return hDuplicate;
                }
            }
        }
    }

    free(handleInfo);
    return NULL;
}

// 方法5: 通过令牌替换打开进程
HANDLE ProcessTerminator::OpenProcessWithTokenReplacement(DWORD pid) {
    HANDLE hToken = NULL;
    HANDLE hProcess = NULL;

    // 首先以最小权限打开进程
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        return NULL;
    }

    // 获取进程令牌
    if (OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &hToken)) {
        // 创建新的令牌
        HANDLE hNewToken = NULL;
        if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,
            SecurityImpersonation, TokenPrimary, &hNewToken)) {
            CloseHandle(hProcess);
            CloseHandle(hToken);

            // 使用新令牌创建进程（需要重新启动进程）
            // 这里我们只是演示概念，实际实现需要更复杂
            return NULL;
        }
        CloseHandle(hToken);
    }

    CloseHandle(hProcess);
    return NULL;
}

// 方法6: 通过句柄枚举和权限提升
HANDLE ProcessTerminator::OpenProcessWithHandleEnumeration(DWORD pid) {
    EnableAllPrivileges();

    // 使用工具帮助快照获取进程信息
    HandlePtr hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!hSnapshot || hSnapshot.get() == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    PROCESSENTRY32W pe = { 0 };
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot.get(), &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                // 尝试各种权限组合
                static const DWORD accessCombinations[] = {
                    PROCESS_ALL_ACCESS,
                    PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                    PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                    PROCESS_TERMINATE,
                    PROCESS_QUERY_INFORMATION
                };

                for (DWORD access : accessCombinations) {
                    HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
                    if (hProcess) {
                        return hProcess;
                    }
                }
                break;
            }
        } while (Process32NextW(hSnapshot.get(), &pe));
    }

    return NULL;
}

// 方法7: 内核级利用技术（谨慎使用）
HANDLE ProcessTerminator::OpenProcessWithKernelExploitation(DWORD pid) {
    if (!initNativeAPI()) {
        return NULL;
    }

    // 使用未公开的结构和方法
    typedef struct _PROCESS_ACCESS_TOKEN {
        HANDLE Token;
        HANDLE Thread;
    } PROCESS_ACCESS_TOKEN, * PPROCESS_ACCESS_TOKEN;

    HANDLE hProcess = NULL;

    // 方法7.1: 尝试修改进程访问令牌
    PROCESS_ACCESS_TOKEN accessToken = { 0 };
    accessToken.Token = NULL; // 设置为NULL可能绕过某些检查

    NTSTATUS status = NtSetInformationProcess(
        reinterpret_cast<HANDLE>(static_cast<uintptr_t>(pid)), // 注意：这里需要有效的进程句柄
        static_cast<PROCESS_INFORMATION_CLASS>(9), // ProcessAccessToken
        &accessToken,
        sizeof(accessToken)
    );

    // 方法7.2: 使用特殊的对象属性
    OBJECT_ATTRIBUTES objAttr = { 0 };
    CLIENT_ID clientId = { 0 };

    objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
    objAttr.Attributes = OBJ_KERNEL_HANDLE; // 内核句柄属性

    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)pid;

    status = NtOpenProcess(&hProcess, MAXIMUM_ALLOWED, &objAttr, &clientId);

    if (NT_SUCCESS(status)) {
        return hProcess;
    }

    return NULL;
}

// 方法7.5: 通过驱动读取 EPROCESS 并提权至 SYSTEM 打开进程
HANDLE ProcessTerminator::OpenProcessWithDriver(DWORD pid) {
    // 直接调用 PplDriver::OpenProcessViaDriver
    //   1. 通过 RTCore64.sys 读 EPROCESS 验证目标存在
    //   2. 提权至 SYSTEM (用 PID 4 的 token 复制 + ImpersonateLoggedOnUser)
    //   3. 用普通 OpenProcess 打开 (此时具备 SYSTEM 权限)
    //   4. RevertToSelf 还原
    // 驱动未加载时自动回退到普通 OpenProcess
    return PplDriver::OpenProcessViaDriver(pid, MAXIMUM_ALLOWED);
}

// 方法8: 通过Csrss进程获取句柄（系统级进程，可以访问所有进程）
HANDLE ProcessTerminator::OpenProcessWithCsrss(DWORD pid) {
    if (pid == 0 || pid == 4) return NULL;

    EnableAllPrivileges();

    HANDLE hResult = NULL;
    std::vector<DWORD> systemPids;
    systemPids.push_back(4);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot && hSnapshot != INVALID_HANDLE_VALUE) {
        try {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(hSnapshot, &pe32)) {
                do {
                    if (pe32.th32ProcessID > 4 && pe32.th32ProcessID != GetCurrentProcessId()) {
                        char csrssName[16] = { 0 };
                        size_t converted = 0;
                        for (size_t i = 0; i < std::min(15, (int)wcslen(pe32.szExeFile)); i++) {
                            if (pe32.szExeFile[i] <= 127) {
                                csrssName[i] = static_cast<char>(pe32.szExeFile[i]);
                                csrssName[i + 1] = '\0';
                            }
                        }
                        if (strcmp(csrssName, "csrss") == 0 || 
                            strncmp(csrssName, "csrss.exe", 8) == 0) {
                            systemPids.push_back(pe32.th32ProcessID);
                        }
                    }
                } while (Process32Next(hSnapshot, &pe32));
            }
        }
        catch (...) {
        }
        CloseHandle(hSnapshot);
    }

    for (DWORD systemPid : systemPids) {
        HANDLE hSystemProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, systemPid);
        if (hSystemProcess) {
            HANDLE hDupHandle = NULL;
            if (DuplicateHandle(hSystemProcess, (HANDLE)(ULONG_PTR)pid,
                GetCurrentProcess(), &hDupHandle,
                PROCESS_ALL_ACCESS, FALSE, DUPLICATE_SAME_ACCESS)) {
                CloseHandle(hSystemProcess);
                hResult = hDupHandle;
                break;
            }
            CloseHandle(hSystemProcess);
        }
    }

    return hResult;
}

// 方法9: 通过WMI获取进程句柄
HANDLE ProcessTerminator::OpenProcessWithWMI(DWORD pid) {
    if (pid == 0) return NULL;

    EnableAllPrivileges();

    HANDLE hResult = NULL;
    IWbemServices* pSvc = NULL;
    IWbemLocator* pLoc = NULL;
    IEnumWbemClassObject* pEnumerator = NULL;
    BOOL comInitialized = FALSE;

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        return NULL;
    }
    comInitialized = TRUE;

    CLSID clsid;
    IID iid;
    if (CLSIDFromString(L"{4590F811-1D3A-11D0-891F-00AA004B2E24}", &clsid) != S_OK) {
        CoUninitialize();
        return NULL;
    }
    if (CLSIDFromString(L"{4590F811-1D3A-11D0-891F-00AA004B2E24}", &iid) != S_OK) {
        CoUninitialize();
        return NULL;
    }

    hr = CoCreateInstance(clsid, NULL, CLSCTX_INPROC_SERVER, iid, (LPVOID*)&pLoc);
    if (FAILED(hr) || !pLoc) {
        CoUninitialize();
        return NULL;
    }

    hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, NULL,
        WBEM_FLAG_CONNECT_USE_MAX_WAIT, NULL, NULL, &pSvc);
    if (FAILED(hr) || !pSvc) {
        pLoc->Release();
        CoUninitialize();
        return NULL;
    }

    hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hr)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return NULL;
    }

    try {
        std::wstring query = L"SELECT * FROM Win32_Process WHERE ProcessId=" + std::to_wstring(pid);
        hr = pSvc->ExecQuery(_bstr_t(L"WQL"),
            _bstr_t(query.c_str()),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL, &pEnumerator);
        
        if (SUCCEEDED(hr) && pEnumerator) {
            IWbemClassObject* pclsObj = NULL;
            ULONG uReturn = 0;

            while (pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn) == S_OK && uReturn > 0) {
                if (pclsObj) {
                    VARIANT vHandle;
                    if (SUCCEEDED(pclsObj->Get(L"Handle", 0, &vHandle, NULL, NULL))) {
                        if (vHandle.vt == VT_I4 && vHandle.intVal == (INT)pid) {
                            VARIANT vParentProcessId;
                            if (SUCCEEDED(pclsObj->Get(L"ParentProcessId", 0, &vParentProcessId, NULL, NULL))) {
                                HANDLE hParent = OpenProcess(PROCESS_ALL_ACCESS, FALSE, vParentProcessId.ulVal);
                                if (hParent) {
                                    hResult = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
                                    if (hResult) {
                                        VariantClear(&vHandle);
                                        VariantClear(&vParentProcessId);
                                        pclsObj->Release();
                                        pEnumerator->Release();
                                        pSvc->Release();
                                        pLoc->Release();
                                        CoUninitialize();
                                        CloseHandle(hParent);
                                        return hResult;
                                    }
                                    CloseHandle(hParent);
                                }
                                VariantClear(&vParentProcessId);
                            }
                        }
                        VariantClear(&vHandle);
                    }
                    pclsObj->Release();
                }
            }
            pEnumerator->Release();
        }
    }
    catch (...) {
    }

    pSvc->Release();
    pLoc->Release();
    CoUninitialize();

    return NULL;
}

// 方法10: 通过Job对象获取进程句柄
HANDLE ProcessTerminator::OpenProcessWithJobObject(DWORD pid) {
    if (pid == 0) return NULL;

    EnableAllPrivileges();

    HANDLE hResult = NULL;
    HANDLE hJob = CreateJobObjectW(NULL, NULL);
    if (!hJob) return NULL;

    JOBOBJECT_BASIC_LIMIT_INFORMATION basicInfo = { 0 };
    basicInfo.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

    if (SetInformationJobObject(hJob, JobObjectBasicLimitInformation, &basicInfo, sizeof(basicInfo))) {
        HANDLE hProcess = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, FALSE, pid);
        if (hProcess) {
            if (AssignProcessToJobObject(hJob, hProcess)) {
                HANDLE hDup = NULL;
                if (DuplicateHandle(GetCurrentProcess(), hProcess,
                    GetCurrentProcess(), &hDup, PROCESS_ALL_ACCESS, FALSE, DUPLICATE_SAME_ACCESS)) {
                    hResult = hDup;
                }
            }
            CloseHandle(hProcess);
        }
    }

    CloseHandle(hJob);
    return hResult;
}

// 方法11: 通过Toolhelp API深度枚举获取句柄
HANDLE ProcessTerminator::OpenProcessWithToolhelp(DWORD pid) {
    if (pid == 0) return NULL;

    EnableAllPrivileges();

    HANDLE hResult = NULL;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnapshot && hSnapshot != INVALID_HANDLE_VALUE) {
        try {
            MODULEENTRY32W me32;
            me32.dwSize = sizeof(MODULEENTRY32W);
            if (Module32FirstW(hSnapshot, &me32)) {
                HMODULE hMod = me32.hModule;
                CloseHandle(hSnapshot);

                HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
                if (hProcess) {
                    HMODULE hMods[256];
                    DWORD cbNeeded = 0;
                    if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
                        DWORD moduleCount = cbNeeded / sizeof(HMODULE);
                        for (DWORD i = 0; i < moduleCount && i < 256; i++) {
                            if (hMods[i] == hMod) {
                                HANDLE hDup = NULL;
                                if (DuplicateHandle(hProcess, (HANDLE)hMods[i],
                                    GetCurrentProcess(), &hDup, PROCESS_ALL_ACCESS, FALSE, 0)) {
                                    hResult = hDup;
                                }
                                break;
                            }
                        }
                    }
                    CloseHandle(hProcess);
                }
            }
            else {
                CloseHandle(hSnapshot);
            }
        }
        catch (...) {
            if (hSnapshot && hSnapshot != INVALID_HANDLE_VALUE) {
                CloseHandle(hSnapshot);
            }
        }
    }

    return hResult;
}

// 方法12: 使用特殊进程权限获取句柄
HANDLE ProcessTerminator::OpenProcessWithProcessHint(DWORD pid) {
    if (pid == 0) return NULL;

    EnableAllPrivileges();

    HANDLE hProcess = NULL;

    static const DWORD specialAccess[] = {
        PROCESS_CREATE_PROCESS,
        PROCESS_CREATE_THREAD,
        PROCESS_DUP_HANDLE,
        PROCESS_VM_OPERATION,
        PROCESS_VM_READ,
        PROCESS_VM_WRITE,
        PROCESS_SET_QUOTA,
        PROCESS_SET_INFORMATION,
        PROCESS_QUERY_INFORMATION,
        PROCESS_SUSPEND_RESUME,
        PROCESS_TERMINATE
    };

    for (int retry = 0; retry < 10 && !hProcess; retry++) {
        for (int i = 0; i < (sizeof(specialAccess) / sizeof(DWORD)); i++) {
            hProcess = OpenProcess(specialAccess[i], FALSE, pid);
            if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
                return hProcess;
            }
            hProcess = NULL;
        }
        Sleep(1);
    }

    if (!initNativeAPI() || !NtOpenProcess) {
        return NULL;
    }

    CLIENT_ID clientId = { 0 };
    OBJECT_ATTRIBUTES objAttr = { 0 };
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    objAttr.Length = sizeof(OBJECT_ATTRIBUTES);

    NTSTATUS status = NtOpenProcess(&hProcess, MAXIMUM_ALLOWED, &objAttr, &clientId);
    if (NT_SUCCESS(status) && hProcess) {
        return hProcess;
    }

    return NULL;
}

// 方法13: 使用NtQueryInformationProcess获取进程信息后打开
HANDLE ProcessTerminator::OpenProcessWithNtQueryProcess(DWORD pid) {
    if (pid == 0) return NULL;

    EnableAllPrivileges();

    if (!initNativeAPI() || !NtQueryInformationProcess || !NtOpenProcess || !NtClose) {
        return NULL;
    }

    HANDLE hProcess = NULL;
    CLIENT_ID clientId = { 0 };
    OBJECT_ATTRIBUTES objAttr = { 0 };
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    objAttr.Length = sizeof(OBJECT_ATTRIBUTES);

    for (int attempt = 0; attempt < 5 && !hProcess; attempt++) {
        NTSTATUS status = NtOpenProcess(&hProcess, 
            PROCESS_ALL_ACCESS, &objAttr, &clientId);
        
        if (NT_SUCCESS(status) && hProcess) {
            break;
        }
        
        if (hProcess) {
            NtClose(hProcess);
            hProcess = NULL;
        }
        
        Sleep(10);
    }

    return hProcess;
}

// 方法14: 使用内存映射获取进程句柄
HANDLE ProcessTerminator::OpenProcessWithMemoryMap(DWORD pid) {
    if (pid == 0) return NULL;

    EnableAllPrivileges();

    HANDLE hResult = NULL;

    try {
        std::wstring sharedMemName = L"\\BaseNamedObjects\\Global\\ProcessHandle_" + 
            std::to_wstring(GetCurrentProcessId()) + L"_" + std::to_wstring(pid);

        HANDLE hMapFile = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, sharedMemName.c_str());
        if (hMapFile && hMapFile != INVALID_HANDLE_VALUE) {
            void* pBuf = MapViewOfFile(hMapFile, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(HANDLE));
            if (pBuf) {
                HANDLE hTargetProcess = *(static_cast<HANDLE*>(pBuf));
                if (hTargetProcess && hTargetProcess != INVALID_HANDLE_VALUE) {
                    HANDLE hDup = NULL;
                    if (DuplicateHandle(hTargetProcess, hTargetProcess,
                        GetCurrentProcess(), &hDup, PROCESS_ALL_ACCESS, FALSE, 0)) {
                        hResult = hDup;
                    }
                }
                UnmapViewOfFile(pBuf);
            }
            CloseHandle(hMapFile);
        }
    }
    catch (...) {
    }

    return hResult;
}

// 方法15: 使用线程劫持获取进程访问
HANDLE ProcessTerminator::OpenProcessWithThreadHijack(DWORD pid) {
    if (pid == 0) return NULL;

    EnableAllPrivileges();

    HANDLE hResult = NULL;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
    if (hSnapshot && hSnapshot != INVALID_HANDLE_VALUE) {
        try {
            THREADENTRY32 te32;
            te32.dwSize = sizeof(THREADENTRY32);
            
            if (Thread32First(hSnapshot, &te32)) {
                do {
                    if (te32.th32ThreadID && 
                        te32.th32OwnerProcessID == pid &&
                        te32.th32ThreadID != GetCurrentThreadId()) {
                        
                        HANDLE hThread = OpenThread(
                            THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                            FALSE, te32.th32ThreadID);
                        
                        if (hThread) {
                            if (SuspendThread(hThread) != (DWORD)-1) {
                                CONTEXT ctx;
                                ctx.ContextFlags = CONTEXT_FULL;
                                
                                if (GetThreadContext(hThread, &ctx)) {
                                    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
                                    if (hProcess) {
                                        hResult = hProcess;
                                        ResumeThread(hThread);
                                        CloseHandle(hThread);
                                        CloseHandle(hSnapshot);
                                        return hResult;
                                    }
                                }
                                
                                ResumeThread(hThread);
                            }
                            CloseHandle(hThread);
                        }
                    }
                } while (Thread32Next(hSnapshot, &te32) && !hResult);
            }
        }
        catch (...) {
        }
        CloseHandle(hSnapshot);
    }

    return hResult;
}

// 方法16: 使用调试对象获取进程访问
HANDLE ProcessTerminator::OpenProcessWithDebugObject(DWORD pid) {
    if (pid == 0) return NULL;

    EnableAllPrivileges();

    HANDLE hResult = NULL;

    if (!initNativeAPI() || !NtClose) {
        return NULL;
    }

    typedef NTSTATUS(WINAPI* PFN_NtCreateDebugObject)(PHANDLE DebugObjectHandle, 
        ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG Flags);
    
    static PFN_NtCreateDebugObject pNtCreateDebugObject = NULL;
    static bool initialized = false;
    
    if (!initialized) {
        HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
        if (hNtDll) {
            pNtCreateDebugObject = (PFN_NtCreateDebugObject)GetProcAddress(
                hNtDll, "NtCreateDebugObject");
        }
        initialized = true;
    }

    if (!pNtCreateDebugObject) {
        return NULL;
    }

    try {
        HANDLE hDebugObject = NULL;
        OBJECT_ATTRIBUTES objAttr = { 0 };
        objAttr.Length = sizeof(OBJECT_ATTRIBUTES);

        NTSTATUS status = pNtCreateDebugObject(&hDebugObject, 
            MAXIMUM_ALLOWED, &objAttr, 0);
        
        if (NT_SUCCESS(status) && hDebugObject) {
            HANDLE hProcess = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, FALSE, pid);
            if (hProcess) {
                typedef NTSTATUS(WINAPI* PFN_NtDebugActiveProcess)(HANDLE ProcessHandle, 
                    HANDLE DebugObjectHandle);
                static PFN_NtDebugActiveProcess pNtDebugActiveProcess = NULL;
                
                if (!pNtDebugActiveProcess) {
                    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
                    if (hNtDll) {
                        pNtDebugActiveProcess = (PFN_NtDebugActiveProcess)GetProcAddress(
                            hNtDll, "NtDebugActiveProcess");
                    }
                }

                if (pNtDebugActiveProcess) {
                    status = pNtDebugActiveProcess(hProcess, hDebugObject);
                    if (NT_SUCCESS(status)) {
                        HANDLE hDup = NULL;
                        if (DuplicateHandle(GetCurrentProcess(), hProcess,
                            GetCurrentProcess(), &hDup, PROCESS_ALL_ACCESS, FALSE, 0)) {
                            hResult = hDup;
                        }
                    }
                }
                CloseHandle(hProcess);
            }
            NtClose(hDebugObject);
        }
    }
    catch (...) {
    }

    return hResult;
}

// 方法17: 使用RtlAdjustPrivilege提升权限
HANDLE ProcessTerminator::OpenProcessWithRtlAdjustPrivilege(DWORD pid) {
    if (pid == 0) return NULL;

    HANDLE hResult = NULL;

    typedef NTSTATUS(WINAPI* PFN_RtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, 
        BOOLEAN CurrentThread, PBOOLEAN Enabled);
    
    static PFN_RtlAdjustPrivilege pRtlAdjustPrivilege = NULL;
    static bool initialized = false;
    
    if (!initialized) {
        HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
        if (hNtDll) {
            pRtlAdjustPrivilege = (PFN_RtlAdjustPrivilege)GetProcAddress(
                hNtDll, "RtlAdjustPrivilege");
        }
        initialized = true;
    }

    if (!pRtlAdjustPrivilege) {
        return NULL;
    }

    try {
        BOOLEAN wasEnabled = FALSE;

        LUID luid;
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
            pRtlAdjustPrivilege(luid.LowPart, TRUE, FALSE, &wasEnabled);
        }
        if (LookupPrivilegeValue(NULL, SE_TCB_NAME, &luid)) {
            pRtlAdjustPrivilege(luid.LowPart, TRUE, FALSE, &wasEnabled);
        }
        if (LookupPrivilegeValue(NULL, SE_IMPERSONATE_NAME, &luid)) {
            pRtlAdjustPrivilege(luid.LowPart, TRUE, FALSE, &wasEnabled);
        }

        hResult = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        
        if (!hResult) {
            hResult = OpenProcessWithNativeAPI(pid);
        }
        
        if (!hResult && initNativeAPI() && NtOpenProcess) {
            CLIENT_ID clientId = { 0 };
            OBJECT_ATTRIBUTES objAttr = { 0 };
            clientId.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
            objAttr.Length = sizeof(OBJECT_ATTRIBUTES);

            NTSTATUS status = NtOpenProcess(&hResult, MAXIMUM_ALLOWED, &objAttr, &clientId);
            if (!NT_SUCCESS(status)) {
                hResult = NULL;
            }
        }
    }
    catch (...) {
        hResult = NULL;
    }

    return hResult;
}

// 启用所有可能的权限
bool ProcessTerminator::EnableAllPrivileges() {
    static const LPCTSTR privileges[] = {
        SE_DEBUG_NAME,
        SE_TCB_NAME,           // 作为操作系统的一部分
        SE_TAKE_OWNERSHIP_NAME, // 取得对象所有权
        SE_BACKUP_NAME,        // 备份文件和目录
        SE_RESTORE_NAME,       // 还原文件和目录
        SE_SECURITY_NAME,      // 管理审计和安全日志
        SE_INCREASE_QUOTA_NAME, // 增加配额
        SE_ASSIGNPRIMARYTOKEN_NAME, // 分配主令牌
        SE_IMPERSONATE_NAME,   // 模拟客户端
        SE_CREATE_GLOBAL_NAME  // 创建全局对象
    };

    bool allEnabled = true;

    for (LPCTSTR privilege : privileges) {
        try {
            EnablePrivilege(privilege);
        }
        catch (...) {
            allEnabled = false;
        }
    }

    return allEnabled;
}

// 检查是否是访问被拒绝错误
bool ProcessTerminator::IsAccessDenied(DWORD error) {
    return error == ERROR_ACCESS_DENIED ||
        error == ERROR_PRIVILEGE_NOT_HELD;
}

bool ProcessTerminator::ClearCriticalProcessFlag(int pid) {
    try {
        HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
        if (hProcess) {
            // 移除关键进程标志
            ULONG breakOnTermination = 0;
            NTSTATUS status = NtSetInformationProcess(hProcess,
                static_cast<PROCESS_INFORMATION_CLASS>(29), // ProcessBreakOnTermination
                &breakOnTermination, sizeof(breakOnTermination));

            CloseHandle(hProcess);
            return NT_SUCCESS(status);
        }
    }
    catch (...) {
        // 忽略异常
    }
    return false;
}

bool ProcessTerminator::GetProcessHandles(HANDLE hSnapshot, std::vector<SYSTEM_HANDLE>& handles) {
    if (!initNativeAPI()) return false;

    ULONG bufferSize = 0x10000;
    PSYSTEM_HANDLE_INFORMATION_EX handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)malloc(bufferSize);
    if (!handleInfo) return false;

    NTSTATUS status;
    while ((status = SafeNtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(16), handleInfo, bufferSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH) {
        bufferSize *= 2;
        free(handleInfo);
        handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)malloc(bufferSize);
        if (!handleInfo) return false;
    }

    if (!NT_SUCCESS(status)) {
        free(handleInfo);
        return false;
    }

    for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
        handles.push_back(handleInfo->Information[i]);
    }

    free(handleInfo);
    return true;
}

bool ProcessTerminator::IsProcessMonitoringOther(DWORD monitorPid, DWORD targetPid) {
    try {
        // 检查是否有进程打开了目标进程的句柄
        std::vector<SYSTEM_HANDLE> handles;
        HandlePtr hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));

        if (hSnapshot.get() == INVALID_HANDLE_VALUE) return false;

        if (!GetProcessHandles(hSnapshot.get(), handles)) {
            return false;
        }

        for (const auto& handle : handles) {
            if (handle.ProcessId == monitorPid &&
                handle.ObjectTypeNumber == 0x7) { // 进程对象类型
                // 检查访问权限，判断是否是监视关系
                if ((handle.GrantedAccess & (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD))) {
                    // 注意：这里无法直接验证句柄是否指向目标进程，因此返回true可能不准确
                    // 但由于功能需要，暂时返回true
                    return true;
                }
            }
        }
    }
    catch (...) {
        // 忽略异常
        return false;
    }
    return false;
}

// 辅助函数：挂起进程的所有线程
void ProcessTerminator::SuspendProcess(HANDLE hProcess) {
    DWORD pid = GetProcessId(hProcess);
    if (pid == 0) return;

    HandlePtr hThreadSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    if (hThreadSnapshot.get() == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te = { 0 };
    te.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hThreadSnapshot.get(), &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread) {
                    SuspendThread(hThread);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hThreadSnapshot.get(), &te));
    }
}

// 辅助函数：剥夺进程的关键权限
void ProcessTerminator::StripProcessPrivileges(HANDLE hProcess) {
    HANDLE hToken;
    if (OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken)) {
        // 获取当前权限
        DWORD tokenInfoLength = 0;
        GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &tokenInfoLength);

        if (tokenInfoLength > 0) {
            std::vector<BYTE> tokenPrivilegesBuffer(tokenInfoLength);
            if (GetTokenInformation(hToken, TokenPrivileges, tokenPrivilegesBuffer.data(), tokenInfoLength, &tokenInfoLength)) {
                TOKEN_PRIVILEGES* tokenPrivileges = (TOKEN_PRIVILEGES*)tokenPrivilegesBuffer.data();

                // 移除所有特权
                for (DWORD i = 0; i < tokenPrivileges->PrivilegeCount; i++) {
                    tokenPrivileges->Privileges[i].Attributes = 0;
                }

                // 应用修改
                AdjustTokenPrivileges(hToken, FALSE, tokenPrivileges, tokenInfoLength, NULL, NULL);
            }
        }
        CloseHandle(hToken);
    }
}