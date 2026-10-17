#include "CommonDefs.h"
#include "PortMonitor.h"
#include "signature_protection.h"
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <conio.h>
#include <cstdio>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

extern bool IsInUnifiedWhitelist(const std::wstring& processName);

// ============================================================================
// PortMonitor 方法实现
// ============================================================================

std::wstring PortMonitor::GetProcessNameByPID(DWORD pid) {
    if (pid == 0) return L"System Idle Process";
    if (pid == 4) return L"System";

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return L"Unknown";

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                CloseHandle(hSnapshot);
                return std::wstring(pe.szExeFile);
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return L"Unknown";
}

void PortMonitor::GetTCPConnections(std::vector<ConnectionInfo>& connections) {
    DWORD size = 0;
    GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

    if (size == 0) return;

    PMIB_TCPTABLE_OWNER_PID tcpTable = (PMIB_TCPTABLE_OWNER_PID) new char[size];

    if (GetExtendedTcpTable(tcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
            ConnectionInfo info;
            info.pid = tcpTable->table[i].dwOwningPid;
            info.localPort = ntohs((USHORT)(tcpTable->table[i].dwLocalPort));
            info.remotePort = ntohs((USHORT)(tcpTable->table[i].dwRemotePort));
            info.localAddr = tcpTable->table[i].dwLocalAddr;
            info.remoteAddr = tcpTable->table[i].dwRemoteAddr;
            info.state = tcpTable->table[i].dwState;
            info.isTCP = true;
            connections.push_back(info);
        }
    }
    delete[] (char*)tcpTable;
}

void PortMonitor::GetUDPListeners(std::vector<ConnectionInfo>& listeners) {
    DWORD size = 0;
    GetExtendedUdpTable(NULL, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);

    if (size == 0) return;

    PMIB_UDPTABLE_OWNER_PID udpTable = (PMIB_UDPTABLE_OWNER_PID) new char[size];

    if (GetExtendedUdpTable(udpTable, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        for (DWORD i = 0; i < udpTable->dwNumEntries; i++) {
            ConnectionInfo info;
            info.pid = udpTable->table[i].dwOwningPid;
            info.localPort = ntohs((USHORT)(udpTable->table[i].dwLocalPort));
            info.localAddr = udpTable->table[i].dwLocalAddr;
            info.remotePort = 0;
            info.remoteAddr = 0;
            info.state = -1;
            info.isTCP = false;
            listeners.push_back(info);
        }
    }
    delete[] (char*)udpTable;
}

void PortMonitor::StartPortMonitoring() {
    DMSP_VERIFY(0x2006);  // 端口监控子函数 - 二级验证
    bool showSystem = false;
    int scanCount = 0;

    HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hCon, &csbi);
    SHORT headerEndRow = csbi.dwCursorPosition.Y;

    std::wcout << L"\n========================================" << std::endl;
    std::wcout << L"       端口监控（实时检测）" << std::endl;
    std::wcout << L"========================================" << std::endl;
    std::wcout << L"  S=切换系统进程  Q=退出\n" << std::endl;

    // 上一次的连接快照，用于检测新连接
    std::set<std::wstring> prevKeys;

    // 历史记录：所有曾经出现过的连接（用于显示已断开的连接）
    struct HistoryEntry {
        std::wstring display;     // 显示文本
        std::wstring sortKey;     // 排序键
        DWORD pid;                // 进程ID
        std::wstring procName;    // 进程名
    };
    std::map<std::wstring, HistoryEntry> historyMap;

    while (true) {
        if (_kbhit()) {
            int ch = _getch();
            if (ch == 's' || ch == 'S') { showSystem = !showSystem; }
            else if (ch == 'q' || ch == 'Q' || ch == 27) {
                std::wcout << L"\n[退出] 端口监控已停止" << std::endl;
                return;
            }
        }

        scanCount++;
        SYSTEMTIME st;
        GetLocalTime(&st);

        struct ConnLine {
            std::wstring display;
            std::wstring sortKey;
            bool isNew;
        };
        std::vector<ConnLine> activeLines;
        std::set<std::wstring> currKeys;

        auto makeLine = [&](const ConnectionInfo& c, const wchar_t* stateStr) -> ConnLine {
            std::wstring procName = GetProcessNameByPID(c.pid);
            if (!showSystem && IsSystemProcess(procName)) { return {L"", L"", false}; }

            std::wstring lIp = FormatIP(c.localAddr);
            std::wstring rIp = FormatIP(c.remoteAddr);

            std::wstring key = rIp + L":" + std::to_wstring(c.remotePort) + L"|"
                               + lIp + L":" + std::to_wstring(c.localPort) + L"|"
                               + procName;
            currKeys.insert(key);

            bool isNew = (prevKeys.find(key) == prevKeys.end());

            // 构建显示行: 源->目标  状态  进程 PID
            wchar_t line[256];
            if (c.isTCP && c.remoteAddr != 0) {
                swprintf(line, 256, L"%-15s:%-5u -> %-15s:%-5u %-8s %-12s %5u",
                    lIp.c_str(), c.localPort,
                    rIp.c_str(), c.remotePort,
                    stateStr, procName.c_str(), c.pid);
            } else {
                swprintf(line, 256, L"%-15s:%-5u [LISTENING]          %-8s %-12s %5u",
                    lIp.c_str(), c.localPort,
                    stateStr, procName.c_str(), c.pid);
            }

            std::wstring sk = lIp + L":" + std::to_wstring(c.localPort) + L"->" +
                               rIp + L":" + std::to_wstring(c.remotePort ? c.remotePort : 0);

            HistoryEntry he;
            he.display = line;
            he.sortKey = sk;
            he.pid = c.pid;
            he.procName = procName;
            historyMap[key] = he;

            return {line, sk, isNew};
        };

        std::vector<ConnectionInfo> allConn;
        GetTCPConnections(allConn);
        GetUDPListeners(allConn);

        for (const auto& c : allConn) {
            if (c.state == MIB_TCP_STATE_TIME_WAIT) continue;
            if (c.localAddr == 0x0100007F || c.remoteAddr == 0x0100007F) continue;
            if (c.localAddr == 0 && c.remoteAddr == 0) continue;

            ConnLine cl;
            if (c.isTCP) {
                cl = makeLine(c, GetStateString(c.state).c_str());
                if (cl.display.empty()) continue;
                if (IsActiveState(c.state))
                    activeLines.push_back(cl);
            } else {
                cl = makeLine(c, L"UDP");
                if (!cl.display.empty())
                    activeLines.push_back(cl);
            }
        }

        // 已失效：历史中存在但本轮不活跃的连接
        std::vector<ConnLine> expiredLines;
        for (auto& kv : historyMap) {
            if (currKeys.find(kv.first) == currKeys.end()) {
                expiredLines.push_back({kv.second.display, kv.second.sortKey, false});
            }
        }

        // 排序
        auto sortByRemote = [](const ConnLine& a, const ConnLine& b) {
            return a.sortKey < b.sortKey;
        };
        std::sort(activeLines.begin(), activeLines.end(), sortByRemote);
        std::sort(expiredLines.begin(), expiredLines.end(), sortByRemote);

        // 部分清屏
        GetConsoleScreenBufferInfo(hCon, &csbi);
        if (headerEndRow > csbi.srWindow.Bottom) headerEndRow = csbi.srWindow.Bottom;
        COORD pos = { 0, headerEndRow };
        SetConsoleCursorPosition(hCon, pos);
        DWORD written;
        DWORD cellCount = csbi.dwSize.X * (csbi.srWindow.Bottom + 1 - headerEndRow);
        FillConsoleOutputCharacterW(hCon, L' ', cellCount, pos, &written);
        SetConsoleCursorPosition(hCon, pos);

        // ---- 标题 ----
        wchar_t timeBuf[24];
        swprintf(timeBuf, 24, L"%02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);
        std::wcout << L" CMDPLUS PortMonitor  |  #" << scanCount
                   << L"  " << timeBuf
                   << L"  sys:" << (showSystem ? L"ON" : L"OFF") << std::endl;
        std::wcout << L"-" << std::wstring(78, '-') << std::endl;
        std::wcout << L" [ACTIVE] " << activeLines.size() << L" connections" << std::endl;
        std::wcout << L" SourceIP:Port  -> DestIP:Port         State  Process       PID" << std::endl;
        std::wcout << L"-" << std::wstring(78, '-') << std::endl;
        std::wcout << L"-" << std::wstring(78, '-') << std::endl;
        std::wcout << L"-" << std::wstring(78, '-') << std::endl;

        if (activeLines.empty()) {
            std::wcout << L" (none)" << std::endl;
        } else {
            for (auto& cl : activeLines) {
                if (cl.isNew)
                    std::wcout << L"*";
                else
                    std::wcout << L" ";
                std::wcout << cl.display << std::endl;
            }
        }

        std::wcout << L"-" << std::wstring(78, '-') << std::endl;
        std::wcout << L" [EXPIRED] " << expiredLines.size() << L" connections" << std::endl;
        std::wcout << L"-" << std::wstring(78, '-') << std::endl;

        if (expiredLines.empty()) {
            std::wcout << L" (none)" << std::endl;
        } else {
            for (auto& cl : expiredLines) {
                std::wcout << L"  " << cl.display << std::endl;
            }
        }

        std::wcout << L"-" << std::wstring(78, '-') << std::endl;
        std::wcout << L" *=new  S=toggle sys  Q=quit" << std::endl;

        prevKeys.swap(currKeys);
        Sleep(1000);
    }
}
