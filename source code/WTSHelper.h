#pragma once
#ifndef WTSHELPER_H
#define WTSHELPER_H

#include "CommonDefs.h"

// WTSHelper — Windows Terminal Services 辅助工具
struct WTSHelper {
    static bool IsAvailable();
    static HANDLE GetUserToken(DWORD sessionId = 0xFFFFFFFF);
    static HANDLE GetSystemTokenUsingWTS();
    static HANDLE GetActiveUserToken();
};

#endif
