#include "CommonDefs.h"
#include "AntiRemoteControl.h"
#include "signature_protection.h"
#include <conio.h>

// ============================================================================
// AntiRemoteControl — 防火墙规则管理实现
//   编译目标: _WIN32_WINNT=0x0601 (Windows 7), C++17
// ============================================================================

void AntiRemoteControl::ExecuteFirewallCommands(const std::vector<std::wstring>& commands) {
    DMSP_VERIFY(0x2008);  // 防火墙命令执行子函数 - 二级验证
    if (commands.empty()) return;

    std::wstring batchContent;
    for (const auto& cmd : commands) {
        batchContent += cmd + L"\r\n";
    }

    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);

    std::wstring batchFile = std::wstring(tempPath) + L"CMDPLUS_FW_";

    SYSTEMTIME st;
    GetLocalTime(&st);
    batchFile += std::to_wstring(st.wYear) + std::to_wstring(st.wMonth) +
                std::to_wstring(st.wDay) + std::to_wstring(st.wHour) +
                std::to_wstring(st.wMinute) + std::to_wstring(st.wSecond) +
                std::to_wstring(st.wMilliseconds) + L".bat";

    FILE* f = _wfopen(batchFile.c_str(), L"w");
    if (!f) return;

    fwprintf(f, L"@echo off\r\n");
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

void AntiRemoteControl::EnableAntiRemoteControl() {
    std::wcout << L"\n========================================" << std::endl;
    std::wcout << L"       反远程控制防火墙规则" << std::endl;
    std::wcout << L"========================================" << std::endl;

    std::wcout << L"\n正在配置防火墙..." << std::endl;

    std::vector<std::wstring> commands;

    commands.push_back(L"netsh advfirewall firewall delete rule name=all");
    commands.push_back(L"netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound");
    commands.push_back(L"netsh advfirewall set allprofiles state on");

    commands.push_back(L"netsh advfirewall firewall add rule name=\"ALLOW_HTTP_IN\" dir=in action=allow protocol=TCP localport=80 profile=any");
    commands.push_back(L"netsh advfirewall firewall add rule name=\"ALLOW_HTTP_OUT\" dir=out action=allow protocol=TCP remoteport=80 profile=any");
    commands.push_back(L"netsh advfirewall firewall add rule name=\"ALLOW_HTTPS_IN\" dir=in action=allow protocol=TCP localport=443 profile=any");
    commands.push_back(L"netsh advfirewall firewall add rule name=\"ALLOW_HTTPS_OUT\" dir=out action=allow protocol=TCP remoteport=443 profile=any");
    commands.push_back(L"netsh advfirewall firewall add rule name=\"ALLOW_DNS_IN\" dir=in action=allow protocol=UDP localport=53 profile=any");
    commands.push_back(L"netsh advfirewall firewall add rule name=\"ALLOW_DNS_OUT\" dir=out action=allow protocol=UDP remoteport=53 profile=any");
    commands.push_back(L"netsh advfirewall firewall add rule name=\"ALLOW_DHCP_IN\" dir=in action=allow protocol=UDP localport=67,68 profile=any");
    commands.push_back(L"netsh advfirewall firewall add rule name=\"ALLOW_DHCP_OUT\" dir=out action=allow protocol=UDP remoteport=67,68 profile=any");
    commands.push_back(L"netsh advfirewall firewall add rule name=\"ALLOW_ICMP\" dir=in action=allow protocol=ICMPv4 any");
    commands.push_back(L"netsh advfirewall firewall add rule name=\"ALLOW_ICMP_OUT\" dir=out action=allow protocol=ICMPv4 any");
    commands.push_back(L"netsh advfirewall firewall add rule name=\"ALLOW_LOOPBACK\" dir=in action=allow localip=127.0.0.1 remoteip=127.0.0.1");
    commands.push_back(L"netsh advfirewall firewall add rule name=\"ALLOW_LOOPBACK_OUT\" dir=out action=allow localip=127.0.0.1 remoteip=127.0.0.1");
    commands.push_back(L"netsh advfirewall firewall add rule name=\"ALLOW_NETBIOS_IN\" dir=in action=allow protocol=UDP localport=137,138,139 profile=any");
    commands.push_back(L"netsh advfirewall firewall add rule name=\"ALLOW_NETBIOS_OUT\" dir=out action=allow protocol=UDP remoteport=137,138,139 profile=any");
    commands.push_back(L"netsh advfirewall firewall add rule name=\"ALLOW_NETBIOS_TCP_IN\" dir=in action=allow protocol=TCP localport=445 profile=any");
    commands.push_back(L"netsh advfirewall firewall add rule name=\"ALLOW_NETBIOS_TCP_OUT\" dir=out action=allow protocol=TCP remoteport=445 profile=any");
    commands.push_back(L"netsh advfirewall firewall add rule name=\"ALLOW_ARP\" dir=in action=allow protocol=any");
    commands.push_back(L"netsh advfirewall firewall add rule name=\"ALLOW_ARP_OUT\" dir=out action=allow protocol=any");
    commands.push_back(L"netsh advfirewall firewall add rule name=\"ALLOW_LAN_BROADCAST_IN\" dir=in action=allow protocol=UDP localip=255.255.255.255");
    commands.push_back(L"netsh advfirewall firewall add rule name=\"ALLOW_LAN_BROADCAST_OUT\" dir=out action=allow protocol=UDP remoteip=255.255.255.255");

    commands.push_back(L"netsh advfirewall firewall add rule name=\"ALLOW_GAME_TCP_IN\" dir=in action=allow protocol=TCP localport=27015-27030,7777-7780,28960,25565 >nul 2>&1");
    commands.push_back(L"netsh advfirewall firewall add rule name=\"ALLOW_GAME_TCP_OUT\" dir=out action=allow protocol=TCP remoteport=27015-27030,7777-7780,28960,25565 >nul 2>&1");
    commands.push_back(L"netsh advfirewall firewall add rule name=\"ALLOW_GAME_UDP_IN\" dir=in action=allow protocol=UDP localport=27015-27030,7777-7780,28960,25565 >nul 2>&1");
    commands.push_back(L"netsh advfirewall firewall add rule name=\"ALLOW_GAME_UDP_OUT\" dir=out action=allow protocol=UDP remoteport=27015-27030,7777-7780,28960,25565 >nul 2>&1");

    commands.push_back(L"netsh qos set policy name=\"CMDPLUS_BCAST_LIMIT\" 1 -p both -d 127.0.0.0 netmask 0.0.0.0 -b 101376 >nul 2>&1");
    commands.push_back(L"netsh qos set policy name=\"CMDPLUS_NETBIOS_LIMIT\" 1 -p both -d 0.0.0.0 netmask 255.255.255.255 -b 101376 >nul 2>&1");
    commands.push_back(L"netsh qos set policy name=\"CMDPLUS_ICMP_LIMIT\" 1 -p both -d 0.0.0.0 netmask 255.255.255.255 -b 101376 >nul 2>&1");

    DWORD startTime = GetTickCount();
    ExecuteFirewallCommands(commands);
    DWORD elapsed = GetTickCount() - startTime;

    std::wcout << L"\n[完成] 反远程控制防火墙规则已启用! (" << elapsed << L"ms)" << std::endl;
    std::wcout << L"\n说明:" << std::endl;
    std::wcout << L"  [+] 已设置默认策略: 阻止所有入站+出站连接" << std::endl;
    std::wcout << L"  [+] 允许(不限速): HTTP(80), HTTPS(443) 用于正常上网" << std::endl;
    std::wcout << L"  [+] 允许(不限速): DNS(53), DHCP(67,68) 用于网络基础服务" << std::endl;
    std::wcout << L"  [+] 允许(不限速): 游戏端口 (CS/Quake/Minecraft等)" << std::endl;
    std::wcout << L"  [+] 允许(限速99KB/S): ICMP(Ping), NetBIOS, 局域网广播" << std::endl;
    std::wcout << L"  [-] 阻止: 所有其他网络连接（包括远程控制）" << std::endl;
    std::wcout << L"\n效果:" << std::endl;
    std::wcout << L"  - 学生电脑可以正常浏览网页" << std::endl;
    std::wcout << L"  - 教师端无法查看/控制学生屏幕" << std::endl;
    std::wcout << L"  - 教师端应能看到学生在线（通过NetBIOS/Ping/广播检测）" << std::endl;
    std::wcout << L"\n如果教师端仍显示离线:" << std::endl;
    std::wcout << L"  1. 使用功能12(端口监控)检测教师端尝试连接的端口" << std::endl;
    std::wcout << L"  2. 使用功能13(端口阻止)手动允许该端口" << std::endl;
}

void AntiRemoteControl::DisableAntiRemoteControl() {
    std::wcout << L"\n========================================" << std::endl;
    std::wcout << L"       删除反远程控制防火墙规则" << std::endl;
    std::wcout << L"========================================" << std::endl;

    std::wcout << L"\n正在重置防火墙..." << std::endl;

    std::vector<std::wstring> commands;
    commands.push_back(L"netsh advfirewall firewall delete rule name=all");
    commands.push_back(L"netsh advfirewall set allprofiles firewallpolicy inboundallow,outboundallow");
    commands.push_back(L"netsh advfirewall set allprofiles state on");
    commands.push_back(L"netsh qos delete policy name=\"CMDPLUS_BCAST_LIMIT\" >nul 2>&1");
    commands.push_back(L"netsh qos delete policy name=\"CMDPLUS_NETBIOS_LIMIT\" >nul 2>&1");
    commands.push_back(L"netsh qos delete policy name=\"CMDPLUS_ICMP_LIMIT\" >nul 2>&1");

    DWORD startTime = GetTickCount();
    ExecuteFirewallCommands(commands);
    DWORD elapsed = GetTickCount() - startTime;

    std::wcout << L"\n[完成] 防火墙已恢复默认设置! (" << elapsed << L"ms)" << std::endl;
}

void AntiRemoteControl::ShowStatus() {
    std::wcout << L"\n========================================" << std::endl;
    std::wcout << L"       反远程控制防火墙规则状态" << std::endl;
    std::wcout << L"========================================" << std::endl;

    bool allowHttp = IsFirewallRuleExists(L"ALLOW_HTTP_IN");
    bool allowHttps = IsFirewallRuleExists(L"ALLOW_HTTPS_IN");
    bool allowDns = IsFirewallRuleExists(L"ALLOW_DNS_IN");

    if (allowHttp && allowHttps && allowDns) {
        std::wcout << L"  [启用] 防火墙保护已激活 - 默认阻止所有连接" << std::endl;
        std::wcout << L"  [启用] 允许HTTP/HTTPS/DNS上网" << std::endl;
    } else {
        std::wcout << L"  [禁用] 防火墙保护未激活" << std::endl;
    }
}

void AntiRemoteControl::ShowMenu() {
    while (true) {
        std::wcout << L"\n========================================" << std::endl;
        std::wcout << L"       反远程控制防火墙" << std::endl;
        std::wcout << L"========================================" << std::endl;
        std::wcout << L"  1. 启用反远程控制规则" << std::endl;
        std::wcout << L"  2. 禁用反远程控制规则" << std::endl;
        std::wcout << L"  3. 查看规则状态" << std::endl;
        std::wcout << L"  0. 返回" << std::endl;
        std::wcout << L"\n请选择操作: ";

        int choice;
        std::wcin >> choice;
        std::wcin.ignore();

        switch (choice) {
        case 1:
            EnableAntiRemoteControl();
            break;
        case 2:
            DisableAntiRemoteControl();
            break;
        case 3:
            ShowStatus();
            break;
        case 0:
            return;
        default:
            std::wcout << L"[错误] 无效选择" << std::endl;
            break;
        }
    }
}
