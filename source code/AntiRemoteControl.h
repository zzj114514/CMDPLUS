#pragma once
#ifndef ANTI_REMOTE_CONTROL_H
#define ANTI_REMOTE_CONTROL_H

// ============================================================================
// AntiRemoteControl.h — 反远程控制防火墙规则管理类
//   编译目标: _WIN32_WINNT=0x0601 (Windows 7), C++17
//
// 原理:
//   通过 netsh advfirewall 命令行工具配置 Windows 防火墙规则,
//   默认阻止所有入站/出站连接, 仅放行 HTTP/HTTPS/DNS/DHCP 等基本网络服务.
//
// 用法:
//   AntiRemoteControl::EnableAntiRemoteControl();   // 启用保护
//   AntiRemoteControl::DisableAntiRemoteControl();  // 恢复默认
//   AntiRemoteControl::ShowStatus();                // 查看状态
//   AntiRemoteControl::ShowMenu();                  // 交互式菜单
// ============================================================================

#include "CommonDefs.h"
#include <string>
#include <vector>
#include <set>

// ============================================================================
// AntiRemoteControl — 防火墙规则管理
// ============================================================================

class AntiRemoteControl {
private:
    // ---- 防火墙规则名称前缀 ----
    static inline std::wstring GetFirewallRulePrefix() {
        return L"CMDPLUS_ANTI_REMOTE_";
    }

    // ---- 检查防火墙规则是否存在 ----
    static inline bool IsFirewallRuleExists(const std::wstring& ruleName) {
        std::wstring cmd = L"netsh advfirewall firewall show rule name=\"" + ruleName + L"\" >nul 2>&1";
        return _wsystem(cmd.c_str()) == 0;
    }

    // ---- 删除单条防火墙规则 ----
    static inline void DeleteFirewallRule(const std::wstring& ruleName) {
        if (!IsFirewallRuleExists(ruleName)) {
            return;
        }
        std::wstring cmd = L"netsh advfirewall firewall delete rule name=\"" + ruleName + L"\" >nul 2>&1";
        _wsystem(cmd.c_str());
    }

    // ---- 删除所有防火墙规则 ----
    static inline void DeleteAllRules() {
        _wsystem(L"netsh advfirewall firewall delete rule name=all >nul 2>&1");
        std::wcout << L"  [完成] 已重置防火墙规则" << std::endl;
    }

    // ---- 批量执行防火墙命令 (创建临时批处理文件静默执行) ----
    static void ExecuteFirewallCommands(const std::vector<std::wstring>& commands);

public:
    // ---- 启用反远程控制规则 ----
    // 设置默认阻止 + 白名单放行 (HTTP/HTTPS/DNS/DHCP/游戏等)
    static void EnableAntiRemoteControl();

    // ---- 禁用反远程控制规则, 恢复默认入站/出站允许 ----
    static void DisableAntiRemoteControl();

    // ---- 显示当前防火墙规则状态 ----
    static void ShowStatus();

    // ---- 交互式选择菜单 ----
    static void ShowMenu();
};

#endif // ANTI_REMOTE_CONTROL_H
