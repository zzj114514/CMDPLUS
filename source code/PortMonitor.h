#pragma once
#ifndef PORT_MONITOR_H
#define PORT_MONITOR_H

#include "CommonDefs.h"
#include <string>
#include <vector>
#include <set>
#include <map>
#include <thread>
#include <atomic>
#include <iphlpapi.h>

// MIB_TCP_STATE 常量 (来自 tcpmib.h)
#ifndef MIB_TCP_STATE_CLOSED
#define MIB_TCP_STATE_CLOSED     1
#define MIB_TCP_STATE_LISTEN     2
#define MIB_TCP_STATE_SYN_SENT   3
#define MIB_TCP_STATE_SYN_RCVD   4
#define MIB_TCP_STATE_ESTAB      5
#define MIB_TCP_STATE_FIN_WAIT1  6
#define MIB_TCP_STATE_FIN_WAIT2  7
#define MIB_TCP_STATE_CLOSE_WAIT 8
#define MIB_TCP_STATE_CLOSING    9
#define MIB_TCP_STATE_LAST_ACK   10
#define MIB_TCP_STATE_TIME_WAIT  11
#endif

// ============================================================================
// PortMonitor — 实时检测网络连接和监听端口
//   使用 GetExtendedTcpTable / GetExtendedUdpTable 轮询当前连接
//   显示活跃连接与已失效连接，支持过滤系统进程
// ============================================================================

class PortMonitor {
private:
    struct ConnectionInfo {
        DWORD pid;
        DWORD localPort;
        DWORD remotePort;
        ULONG localAddr;
        ULONG remoteAddr;
        int state;
        bool isTCP;
    };

    // --- 内联简单辅助方法 ---

    // IsSystemProcess: 声明分离，实现在 PortMonitor.cpp 中
    static bool IsSystemProcess(const std::wstring& name);

    static bool IsActiveState(int state) {
        switch (state) {
            case MIB_TCP_STATE_LISTEN:
            case MIB_TCP_STATE_SYN_SENT:
            case MIB_TCP_STATE_SYN_RCVD:
            case MIB_TCP_STATE_ESTAB:
            case MIB_TCP_STATE_FIN_WAIT1:
            case MIB_TCP_STATE_FIN_WAIT2:
            case MIB_TCP_STATE_CLOSE_WAIT:
            case MIB_TCP_STATE_CLOSING:
            case MIB_TCP_STATE_LAST_ACK:
                return true;
            default:
                return false;
        }
    }

    static std::wstring FormatIP(ULONG addr) {
        if (addr == 0) return L"*";
        return std::to_wstring((addr & 0xFF)) + L"." +
               std::to_wstring((addr >> 8) & 0xFF) + L"." +
               std::to_wstring((addr >> 16) & 0xFF) + L"." +
               std::to_wstring((addr >> 24) & 0xFF);
    }

    static std::wstring GetStateString(int state) {
        if (state == -1) return L"LISTEN";
        switch (state) {
            case MIB_TCP_STATE_CLOSED:     return L"CLOSED";
            case MIB_TCP_STATE_LISTEN:     return L"LISTEN";
            case MIB_TCP_STATE_SYN_SENT:   return L"SYN_SENT";
            case MIB_TCP_STATE_SYN_RCVD:   return L"SYN_RCVD";
            case MIB_TCP_STATE_ESTAB:      return L"ESTABLISHED";
            case MIB_TCP_STATE_FIN_WAIT1:  return L"FIN_WAIT1";
            case MIB_TCP_STATE_FIN_WAIT2:  return L"FIN_WAIT2";
            case MIB_TCP_STATE_CLOSE_WAIT: return L"CLOSE_WAIT";
            case MIB_TCP_STATE_CLOSING:    return L"CLOSING";
            case MIB_TCP_STATE_LAST_ACK:   return L"LAST_ACK";
            case MIB_TCP_STATE_TIME_WAIT:  return L"TIME_WAIT";
            case MIB_TCP_STATE_DELETE_TCB: return L"DELETE_TCB";
            default: return L"UNKNOWN";
        }
    }

    // --- 复杂方法（仅声明，实现在 .cpp） ---

    static std::wstring GetProcessNameByPID(DWORD pid);
    static void GetTCPConnections(std::vector<ConnectionInfo>& connections);
    static void GetUDPListeners(std::vector<ConnectionInfo>& listeners);

public:
    static void StartPortMonitoring();
};

#endif // PORT_MONITOR_H
