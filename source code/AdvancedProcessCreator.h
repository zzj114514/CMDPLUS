#pragma once
#ifndef ADVANCEDPROCESSCREATOR_H
#define ADVANCEDPROCESSCREATOR_H

#include "CommonDefs.h"
#include <string>
#include <vector>

// AdvancedProcessCreator — 高级进程创建工具
// 完整实现在 AdvancedProcessCreator.cpp
struct AdvancedProcessCreator {

    // 使用令牌创建进程 (CreateProcessAsUserW 封装)
    static bool CreateProcessWithToken(
        HANDLE hToken,
        DWORD dwLogonFlags,
        LPCWSTR lpApplicationName,
        LPWSTR lpCommandLine,
        DWORD dwCreationFlags,
        LPVOID lpEnvironment,
        LPCWSTR lpCurrentDirectory,
        LPSTARTUPINFOW lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation
    );

    // 使用 SYSTEM 令牌创建进程
    static bool CreateProcessAsSystem(
        const std::wstring& cmdline,
        bool waitForExit = false
    );

    // 使用 WTS API 获取 SYSTEM 令牌
    static bool GetSystemTokenUsingWTS(HANDLE* phToken);
    // 使用 TrustedInstaller 令牌创建进程

    // 使用 TrustedInstaller 令牌创建进程
    static bool CreateProcessAsTrustedInstaller(
        const std::wstring& cmdline,
        bool waitForExit = false
    );
};

#endif // ADVANCEDPROCESSCREATOR_H
