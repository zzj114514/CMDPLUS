#pragma once
#ifndef DEBUG_PRIVILEGE_ENABLER_H
#define DEBUG_PRIVILEGE_ENABLER_H

// ============================================================================
// DebugPrivilegeEnabler.h — 调试权限提升工具类
//   编译目标: _WIN32_WINNT=0x0601 (Windows 7), C++17
// ============================================================================

#include "CommonDefs.h"
#include <string>
#include <vector>
#include <set>
#include <map>

// ============================================================================
// DebugPrivilegeEnabler — 启用当前进程的调试与系统级权限
//
// 原理:
//   通过 OpenProcessToken → LookupPrivilegeValueW → AdjustTokenPrivileges
//   链式调用, 为当前进程令牌启用一组高权限 (SeDebugPrivilege 等).
//
// 用法:
//   bool ok = DebugPrivilegeEnabler::EnableAllDebugPrivileges();
//
// 注意:
//   - 必须以管理员权限运行 (或至少拥有 SeDebugPrivilege 的潜在能力)
//   - 不保证所有权限都能启用 (部分受组策略或令牌限制)
// ============================================================================

class DebugPrivilegeEnabler {
public:
    // ---- 主要入口点 ----
    // 启用所有预定义的调试及系统级权限
    static inline bool EnableAllDebugPrivileges() {
        HANDLE hToken = nullptr;

        // 获取当前进程令牌
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            std::cerr << "打开句柄错误：" << GetLastError() << std::endl;
            return false;
        }

        // 定义需要启用的权限列表
        std::vector<std::wstring> privileges = {
            L"SeDebugPrivilege",                 // 调试权限
            L"SeSecurityPrivilege",              // 安全管理权限
            L"SeBackupPrivilege",                // 备份权限
            L"SeRestorePrivilege",               // 恢复权限
            L"SeSystemEnvironmentPrivilege",     // 系统环境权限
            L"SeTakeOwnershipPrivilege",         // 取得所有权权限
            L"SeLoadDriverPrivilege"             // 加载驱动权限
        };

        bool allSuccess = true;

        for (const auto& privilege : privileges) {
            if (!EnableSinglePrivilege(hToken, privilege.c_str())) {
                std::wcerr << L"提升权限失败：" << privilege << std::endl;
                allSuccess = false;
            }
        }

        CloseHandle(hToken);
        return allSuccess;
    }

private:
    // ---- 启用单个权限（内部辅助）----
    static inline bool EnableSinglePrivilege(HANDLE hToken, LPCWSTR privilegeName) {
        LUID luid;

        // 查找权限的 LUID
        if (!LookupPrivilegeValueW(nullptr, privilegeName, &luid)) {
            std::wcerr << L"错误" << privilegeName << GetLastError() << std::endl;
            return false;
        }

        // 设置令牌权限
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        // 调整令牌权限
        if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES),
            nullptr, nullptr)) {
            return false;
        }

        // 检查 AdjustTokenPrivileges 的最终错误状态
        if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
            return false;
        }

        return true;
    }
};

#endif // DEBUG_PRIVILEGE_ENABLER_H
