#pragma once
#ifndef PORT_BLOCKER_H
#define PORT_BLOCKER_H

#include "CommonDefs.h"
#include <string>
#include <vector>
#include <set>
#include <map>

// ============================================================================
// PortBlocker — 端口阻止管理
//   通过 Windows 防火墙 (netsh advfirewall) 添加/删除端口阻止规则
//   支持 TCP/UDP 单端口、端口范围阻止与解除
// ============================================================================

class PortBlocker {
private:
    // --- 内联简单辅助方法 ---

    static std::wstring GetRulePrefix() {
        return L"CMDPLUS_PORT_BLOCK_";
    }

    static bool IsRuleExists(const std::wstring& ruleName) {
        std::wstring cmd = L"netsh advfirewall firewall show rule name=\"" +
                           ruleName + L"\" >nul 2>&1";
        return _wsystem(cmd.c_str()) == 0;
    }

    static void DeleteRule(const std::wstring& ruleName) {
        if (!IsRuleExists(ruleName)) return;
        std::wstring cmd = L"netsh advfirewall firewall delete rule name=\"" +
                           ruleName + L"\" >nul 2>&1";
        _wsystem(cmd.c_str());
    }

    // --- 复杂方法（仅声明，实现在 .cpp） ---

    static void ExecuteBatchCommands(const std::vector<std::wstring>& commands);

    static void BlockPortTCP(DWORD port);
    static void BlockPortUDP(DWORD port);
    static void UnBlockPortTCP(DWORD port);
    static void UnBlockPortUDP(DWORD port);

public:
    static void ShowMenu();

    static void BlockSinglePort();
    static void BlockPortRange();
    static void BlockTCPPortOnly();
    static void BlockUDPPortOnly();
    static void UnblockPort();
    static void ShowBlockedPorts();
    static void ClearAllRules();
};

#endif // PORT_BLOCKER_H
