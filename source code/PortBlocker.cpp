#include "CommonDefs.h"
#include "PortBlocker.h"
#include "signature_protection_nocert.h"
#include <conio.h>

// ============================================================================
// PortBlocker — 端口阻止管理
//   通过 Windows 防火墙 (netsh advfirewall) 添加/删除端口阻止规则
//   支持 TCP/UDP 单端口、端口范围阻止与解除
// ============================================================================

// --------------------------------------------------------------------------
// private: 批量命令执行
// --------------------------------------------------------------------------
void PortBlocker::ExecuteBatchCommands(const std::vector<std::wstring>& commands) {
    DMSP_VERIFY(0x2007);  // 批量命令执行子函数 - 二级验证
    if (commands.empty()) return;

    std::wstring batchContent = L"@echo off\r\n";
    for (const auto& cmd : commands) {
        batchContent += cmd + L"\r\n";
    }

    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);

    SYSTEMTIME st;
    GetLocalTime(&st);
    std::wstring batchFile = std::wstring(tempPath) + L"CMDPLUS_PB_" +
                std::to_wstring(st.wYear) + std::to_wstring(st.wMonth) +
                std::to_wstring(st.wDay) + std::to_wstring(st.wHour) +
                std::to_wstring(st.wMinute) + std::to_wstring(st.wSecond) +
                std::to_wstring(st.wMilliseconds) + L".bat";

    FILE* f = _wfopen(batchFile.c_str(), L"w");
    if (!f) return;

    fwprintf(f, L"%s", batchContent.c_str());
    fclose(f);

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi;

    std::wstring cmdLine = L"cmd.exe /c \"" + batchFile + L"\" >nul 2>&1";

    if (CreateProcessW(NULL, &cmdLine[0], NULL, NULL, FALSE,
                     CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    _wremove(batchFile.c_str());
}

// --------------------------------------------------------------------------
// private: 阻止单个 TCP 端口（入站 + 出站）
// --------------------------------------------------------------------------
void PortBlocker::BlockPortTCP(DWORD port) {
    std::wstring ruleNameIn = GetRulePrefix() + L"TCP_IN_" + std::to_wstring(port);
    std::wstring ruleNameOut = GetRulePrefix() + L"TCP_OUT_" + std::to_wstring(port);

    bool blockedIn = false;
    bool blockedOut = false;

    if (!IsRuleExists(ruleNameIn)) {
        std::wstring cmd = L"netsh advfirewall firewall add rule name=\"" + ruleNameIn +
                          L"\" dir=in action=block protocol=TCP localport=" +
                          std::to_wstring(port) + L" >nul 2>&1";

        if (_wsystem(cmd.c_str()) == 0) {
            blockedIn = true;
        }
    } else {
        std::wcout << L"  [已存在] TCP端口 " << port << L" 入站规则已存在" << std::endl;
        blockedIn = true;
    }

    if (!IsRuleExists(ruleNameOut)) {
        std::wstring cmd = L"netsh advfirewall firewall add rule name=\"" + ruleNameOut +
                          L"\" dir=out action=block protocol=TCP localport=" +
                          std::to_wstring(port) + L" >nul 2>&1";

        if (_wsystem(cmd.c_str()) == 0) {
            blockedOut = true;
        }
    } else {
        std::wcout << L"  [已存在] TCP端口 " << port << L" 出站规则已存在" << std::endl;
        blockedOut = true;
    }

    if (blockedIn && blockedOut) {
        std::wcout << L"  [成功] 已阻止TCP端口 " << port << L" 的入站和出站连接" << std::endl;
    } else if (blockedIn) {
        std::wcout << L"  [部分成功] 仅阻止了TCP端口 " << port << L" 的入站连接" << std::endl;
    } else if (blockedOut) {
        std::wcout << L"  [部分成功] 仅阻止了TCP端口 " << port << L" 的出站连接" << std::endl;
    } else {
        std::wcout << L"  [失败] 无法阻止TCP端口 " << port << std::endl;
    }
}

// --------------------------------------------------------------------------
// private: 阻止单个 UDP 端口（入站 + 出站）
// --------------------------------------------------------------------------
void PortBlocker::BlockPortUDP(DWORD port) {
    std::wstring ruleNameIn = GetRulePrefix() + L"UDP_IN_" + std::to_wstring(port);
    std::wstring ruleNameOut = GetRulePrefix() + L"UDP_OUT_" + std::to_wstring(port);

    bool blockedIn = false;
    bool blockedOut = false;

    if (!IsRuleExists(ruleNameIn)) {
        std::wstring cmd = L"netsh advfirewall firewall add rule name=\"" + ruleNameIn +
                          L"\" dir=in action=block protocol=UDP localport=" +
                          std::to_wstring(port) + L" >nul 2>&1";

        if (_wsystem(cmd.c_str()) == 0) {
            blockedIn = true;
        }
    } else {
        std::wcout << L"  [已存在] UDP端口 " << port << L" 入站规则已存在" << std::endl;
        blockedIn = true;
    }

    if (!IsRuleExists(ruleNameOut)) {
        std::wstring cmd = L"netsh advfirewall firewall add rule name=\"" + ruleNameOut +
                          L"\" dir=out action=block protocol=UDP localport=" +
                          std::to_wstring(port) + L" >nul 2>&1";

        if (_wsystem(cmd.c_str()) == 0) {
            blockedOut = true;
        }
    } else {
        std::wcout << L"  [已存在] UDP端口 " << port << L" 出站规则已存在" << std::endl;
        blockedOut = true;
    }

    if (blockedIn && blockedOut) {
        std::wcout << L"  [成功] 已阻止UDP端口 " << port << L" 的入站和出站连接" << std::endl;
    } else if (blockedIn) {
        std::wcout << L"  [部分成功] 仅阻止了UDP端口 " << port << L" 的入站连接" << std::endl;
    } else if (blockedOut) {
        std::wcout << L"  [部分成功] 仅阻止了UDP端口 " << port << L" 的出站连接" << std::endl;
    } else {
        std::wcout << L"  [失败] 无法阻止UDP端口 " << port << std::endl;
    }
}

// --------------------------------------------------------------------------
// private: 解除单个 TCP 端口的阻止
// --------------------------------------------------------------------------
void PortBlocker::UnBlockPortTCP(DWORD port) {
    DeleteRule(GetRulePrefix() + L"TCP_IN_" + std::to_wstring(port));
    DeleteRule(GetRulePrefix() + L"TCP_OUT_" + std::to_wstring(port));
    std::wcout << L"  [完成] 已解除TCP端口 " << port << L" 的所有阻止规则（入站+出站）" << std::endl;
}

// --------------------------------------------------------------------------
// private: 解除单个 UDP 端口的阻止
// --------------------------------------------------------------------------
void PortBlocker::UnBlockPortUDP(DWORD port) {
    DeleteRule(GetRulePrefix() + L"UDP_IN_" + std::to_wstring(port));
    DeleteRule(GetRulePrefix() + L"UDP_OUT_" + std::to_wstring(port));
    std::wcout << L"  [完成] 已解除UDP端口 " << port << L" 的所有阻止规则（入站+出站）" << std::endl;
}

// --------------------------------------------------------------------------
// public: 主菜单
// --------------------------------------------------------------------------
void PortBlocker::ShowMenu() {
    while (true) {
        std::wcout << L"\n========================================" << std::endl;
        std::wcout << L"       端口阻止管理" << std::endl;
        std::wcout << L"========================================" << std::endl;
        std::wcout << L"  1. 阻止单个端口（TCP+UDP）" << std::endl;
        std::wcout << L"  2. 阻止端口范围" << std::endl;
        std::wcout << L"  3. 仅阻止TCP端口" << std::endl;
        std::wcout << L"  4. 仅阻止UDP端口" << std::endl;
        std::wcout << L"  5. 解除端口阻止" << std::endl;
        std::wcout << L"  6. 查看当前阻止的端口列表" << std::endl;
        std::wcout << L"  7. 清除所有端口阻止规则" << std::endl;
        std::wcout << L"  0. 返回主菜单" << std::endl;
        std::wcout << L"\n请选择操作: ";

        int choice;
        std::wcin >> choice;
        std::wcin.ignore();

        switch (choice) {
        case 1:
            BlockSinglePort();
            break;
        case 2:
            BlockPortRange();
            break;
        case 3:
            BlockTCPPortOnly();
            break;
        case 4:
            BlockUDPPortOnly();
            break;
        case 5:
            UnblockPort();
            break;
        case 6:
            ShowBlockedPorts();
            break;
        case 7:
            ClearAllRules();
            break;
        case 0:
            return;
        default:
            std::wcout << L"[错误] 无效选择" << std::endl;
            break;
        }
    }
}

// --------------------------------------------------------------------------
// public: 阻止单个端口（TCP + UDP）
// --------------------------------------------------------------------------
void PortBlocker::BlockSinglePort() {
    std::wcout << L"\n请输入要阻止的端口号: ";
    DWORD port;
    std::wcin >> port;
    std::wcin.ignore();

    if (port < 1 || port > 65535) {
        std::wcout << L"[错误] 无效的端口号 (1-65535)" << std::endl;
        return;
    }

    std::wcout << L"\n正在阻止端口 " << port << L"..." << std::endl;
    BlockPortTCP(port);
    BlockPortUDP(port);
}

// --------------------------------------------------------------------------
// public: 阻止端口范围
// --------------------------------------------------------------------------
void PortBlocker::BlockPortRange() {
    std::wcout << L"\n请输入起始端口号: ";
    DWORD startPort, endPort;
    std::wcin >> startPort;
    std::wcin.ignore();

    std::wcout << L"请输入结束端口号: ";
    std::wcin >> endPort;
    std::wcin.ignore();

    if (startPort < 1 || endPort > 65535 || startPort > endPort) {
        std::wcout << L"[错误] 无效的端口范围 (1-65535)" << std::endl;
        return;
    }

    std::wcout << L"\n正在阻止端口范围 " << startPort << L"-" << endPort << L"..." << std::endl;

    std::vector<std::wstring> commands;

    for (DWORD port = startPort; port <= endPort; port++) {
        commands.push_back(L"netsh advfirewall firewall add rule name=\"" + GetRulePrefix() + L"TCP_IN_" + std::to_wstring(port) +
                          L"\" dir=in action=block protocol=TCP localport=" + std::to_wstring(port));
        commands.push_back(L"netsh advfirewall firewall add rule name=\"" + GetRulePrefix() + L"TCP_OUT_" + std::to_wstring(port) +
                          L"\" dir=out action=block protocol=TCP localport=" + std::to_wstring(port));
        commands.push_back(L"netsh advfirewall firewall add rule name=\"" + GetRulePrefix() + L"UDP_IN_" + std::to_wstring(port) +
                          L"\" dir=in action=block protocol=UDP localport=" + std::to_wstring(port));
        commands.push_back(L"netsh advfirewall firewall add rule name=\"" + GetRulePrefix() + L"UDP_OUT_" + std::to_wstring(port) +
                          L"\" dir=out action=block protocol=UDP localport=" + std::to_wstring(port));
    }

    DWORD startTime = GetTickCount();
    ExecuteBatchCommands(commands);
    DWORD elapsed = GetTickCount() - startTime;

    int count = (endPort - startPort + 1);
    std::wcout << L"\n[完成] 共阻止了 " << count << L" 个端口 (" << elapsed << L"ms)" << std::endl;
}

// --------------------------------------------------------------------------
// public: 仅阻止 TCP 端口
// --------------------------------------------------------------------------
void PortBlocker::BlockTCPPortOnly() {
    std::wcout << L"\n请输入要阻止的TCP端口号: ";
    DWORD port;
    std::wcin >> port;
    std::wcin.ignore();

    if (port < 1 || port > 65535) {
        std::wcout << L"[错误] 无效的端口号 (1-65535)" << std::endl;
        return;
    }

    BlockPortTCP(port);
}

// --------------------------------------------------------------------------
// public: 仅阻止 UDP 端口
// --------------------------------------------------------------------------
void PortBlocker::BlockUDPPortOnly() {
    std::wcout << L"\n请输入要阻止的UDP端口号: ";
    DWORD port;
    std::wcin >> port;
    std::wcin.ignore();

    if (port < 1 || port > 65535) {
        std::wcout << L"[错误] 无效的端口号 (1-65535)" << std::endl;
        return;
    }

    BlockPortUDP(port);
}

// --------------------------------------------------------------------------
// public: 解除端口阻止（TCP + UDP）
// --------------------------------------------------------------------------
void PortBlocker::UnblockPort() {
    std::wcout << L"\n请输入要解除阻止的端口号: ";
    DWORD port;
    std::wcin >> port;
    std::wcin.ignore();

    if (port < 1 || port > 65535) {
        std::wcout << L"[错误] 无效的端口号 (1-65535)" << std::endl;
        return;
    }

    UnBlockPortTCP(port);
    UnBlockPortUDP(port);
}

// --------------------------------------------------------------------------
// public: 查看当前阻止的端口列表
// --------------------------------------------------------------------------
void PortBlocker::ShowBlockedPorts() {
    std::wcout << L"\n========================================" << std::endl;
    std::wcout << L"       当前阻止的端口列表" << std::endl;
    std::wcout << L"========================================" << std::endl;

    FILE* pipe = _wpopen(L"netsh advfirewall firewall show rule name=all", L"r");
    if (!pipe) {
        std::wcout << L"[错误] 无法获取防火墙规则列表" << std::endl;
        return;
    }

    wchar_t buffer[1024];
    bool foundAny = false;

    while (fgetws(buffer, sizeof(buffer) / sizeof(wchar_t), pipe)) {
        std::wstring line(buffer);

        if (line.find(GetRulePrefix()) != std::wstring::npos) {
            foundAny = true;

            size_t pos = line.find(L"规则名称:");
            if (pos == std::wstring::npos) continue;

            size_t nameStart = line.find_first_not_of(L" \t", pos + wcslen(L"规则名称:"));
            if (nameStart == std::wstring::npos) continue;

            size_t nameEnd = line.find_last_not_of(L" \t\r\n");
            if (nameEnd == std::wstring::npos) continue;

            std::wstring ruleName = line.substr(nameStart, nameEnd - nameStart + 1);

            if (ruleName.find(GetRulePrefix()) == 0 &&
                ruleName.length() > GetRulePrefix().length()) {

                std::wstring portInfo = ruleName.substr(GetRulePrefix().length());

                std::wcout << L"  " << ruleName << std::endl;
            }
        }
    }

    _pclose(pipe);

    if (!foundAny) {
        std::wcout << L"  [信息] 当前没有阻止任何端口" << std::endl;
    }
}

// --------------------------------------------------------------------------
// public: 清除所有端口阻止规则
// --------------------------------------------------------------------------
void PortBlocker::ClearAllRules() {
    std::wcout << L"\n确定要清除所有端口阻止规则吗？(y/n): ";
    wchar_t confirm;
    std::wcin >> confirm;
    std::wcin.ignore();

    if (confirm == L'y' || confirm == L'Y') {
        FILE* pipe = _wpopen(L"netsh advfirewall firewall show rule name=all", L"r");
        if (!pipe) {
            std::wcout << L"[错误] 无法获取防火墙规则列表" << std::endl;
            return;
        }

        wchar_t buffer[1024];
        int deletedCount = 0;

        while (fgetws(buffer, sizeof(buffer) / sizeof(wchar_t), pipe)) {
            std::wstring line(buffer);

            if (line.find(GetRulePrefix()) != std::wstring::npos) {
                size_t pos = line.find(L"规则名称:");
                if (pos == std::wstring::npos) continue;

                size_t nameStart = line.find_first_not_of(L" \t", pos + wcslen(L"规则名称:"));
                if (nameStart == std::wstring::npos) continue;

                size_t nameEnd = line.find_last_not_of(L" \t\r\n");
                if (nameEnd == std::wstring::npos) continue;

                std::wstring ruleName = line.substr(nameStart, nameEnd - nameStart + 1);

                if (ruleName.find(GetRulePrefix()) == 0) {
                    DeleteRule(ruleName);
                    deletedCount++;
                }
            }
        }

        _pclose(pipe);

        std::wcout << L"\n[完成] 已清除 " << deletedCount << L" 个端口阻止规则" << std::endl;
    } else {
        std::wcout << L"[取消] 操作已取消" << std::endl;
    }
}
