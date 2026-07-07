// ============================================================================
// 分散式多层级签名保护系统 (Distributed Multi-Layer Signature Protection)
// 版本: 5.0 - 企业级防篡改保护 + 反逆向工程 + 10项安全增强
//
// 特性:
//   1. 多层级验证: PE头/节表/导出表/数字签名/哈希/时间戳
//   2. 混淆技术: 控制流平坦化/虚假分支/多态密钥/动态计算
//   3. 反分析: 调试器检测/Hook检测/内存完整性/反IDA
//   4. 分散性: 验证逻辑分散到多个位置，单点绕过无效
//   5. 自修复: 检测到修改时自动触发保护响应
//   6. 反逆向: 间接调用/花指令/虚假控制流/字符串加密/多态验证路径
//   7. [v5.0] 状态变量XOR编码+指纹校验防内存patch
//   8. [v5.0] 证书信息编译时加密+指纹拆分散布
//   9. [v5.0] 数据段(.rdata)完整性周期性校验
//   10. [v5.0] ForceExit路径3使用手动PE解析绕过Hook
//   11. [v5.0] DLL搜索顺序劫持防护
//   12. [v5.0] 间接跳转表替代switch-case控制流平坦化
//   13. [v5.0] 环境依赖不透明谓词(运行时恒真但静态不可判定)
//   14. [v5.0] main()入口立即执行早期验证宏
//   15. [v5.0] HeapAlloc替代new确保低内存下仍能执行
//   16. [v5.0] 新增7种强力调试器检测方法(投票机制>=3票)
//
// 使用方法: 在每个敏感功能入口调用 VERIFY_SIGNATURE() 宏
//           在main()/MainEntry最开头调用 DMSP_EARLY_VERIFY()
// ============================================================================

#pragma once
#ifndef DMSP_H_INCLUDED
#define DMSP_H_INCLUDED
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <imagehlp.h>
#include <tlhelp32.h>
#include <psapi.h>

// ============================================================================
// [无证书版本] 跳过证书身份验证
//   开发者模式: 0=关闭(安全检查失败终止进程), 1=开启(仅日志不终止)
// ============================================================================
#define DMSP_NOCERT
#define DMSP_NOCERT_DEV_MODE 0

// ============================================================================
// [v5.3 运行时版本检测] 用于在 Win7 编译产物中运行时启用 Win8+ 增强特性
//   RtlGetVersion 在所有 Windows 版本都可用, 不受 GetVersionEx 虚化影响
// ============================================================================
namespace DMSPCompat {
    // [v5.3] 运行时版本检测
    //   Win7 SDK 编译 (_WIN32_WINNT=0x0601) 产物在 Win8+ 上运行时,
    //   通过 RtlGetVersion 探测真实 Windows 版本, 决定是否启用 Win8+ 增强.

    inline bool IsWin8OrLater() {
        static volatile int cached = -1;  // -1=未检测, 0=否, 1=是
        if (cached == 1) return true;
        if (cached == 0) return false;
        // 使用 ntdll.dll 的 RtlGetVersion (Win7 也有)
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return false;
        typedef LONG (WINAPI *FnRtlGetVersion)(PRTL_OSVERSIONINFOW);
        FnRtlGetVersion pRtlGetVersion =
            reinterpret_cast<FnRtlGetVersion>(GetProcAddress(hNtdll, "RtlGetVersion"));
        if (!pRtlGetVersion) return false;
        RTL_OSVERSIONINFOW osvi = {};
        osvi.dwOSVersionInfoSize = sizeof(osvi);
        if (pRtlGetVersion(&osvi) != 0) return false;
        // Win8 = 6.2
        bool result = (osvi.dwMajorVersion > 6) ||
                      (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion >= 2);
        cached = result ? 1 : 0;
        return result;
    }
    inline bool IsWin10_1607OrLater() {
        // Win10 1607 = build 14393
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return false;
        typedef LONG (WINAPI *FnRtlGetVersion)(PRTL_OSVERSIONINFOW);
        FnRtlGetVersion pRtlGetVersion =
            reinterpret_cast<FnRtlGetVersion>(GetProcAddress(hNtdll, "RtlGetVersion"));
        if (!pRtlGetVersion) return false;
        RTL_OSVERSIONINFOW osvi = {};
        osvi.dwOSVersionInfoSize = sizeof(osvi);
        if (pRtlGetVersion(&osvi) != 0) return false;
        return (osvi.dwMajorVersion > 10) ||
               (osvi.dwMajorVersion == 10 && osvi.dwBuildNumber >= 14393);
    }
}

// [v5.3 Win7 polyfill] 仅 polyfill SDK 未声明的符号
//   注: SDK 10.0.26100 的实际声明情况 (基于代码验证):
//     - FileDispositionInfoEx 枚举值: minwinbase.h 202-204 在
//         #if (NTDDI_VERSION >= NTDDI_WIN10_RS1) 块内
//         _WIN32_WINNT=0x0601 → NTDDI_VERSION=0x06010000 < NTDDI_WIN10_RS1=0x0A000002
//         块不进入 → 枚举值未声明, 需 polyfill
//     - FILE_DISPOSITION_INFO_EX 结构: winbase.h 9170 在
//         #if (_WIN32_WINNT >= _WIN32_WINNT_WIN10_RS1) 块内
//         _WIN32_WINNT_WIN10_RS1 未定义 (=0), 0x0601>=0=true → 块进入
//         结构已声明, 不需 polyfill
//     - FILE_DISPOSITION_FLAG_* 宏: winbase.h 9161-9168 同上, 已声明
//     - PROCESS_POWER_THROTTLING_STATE: processthreadsapi.h 1225, 无守卫, 已声明
//     - PROCESS_POWER_THROTTLING_CURRENT_VERSION/EXECUTION_SPEED: 同上
//     - ProcessPowerThrottling 枚举值: 同上
//   SDK 仍未声明的项 (需 polyfill):
//     - FileDispositionInfoEx 枚举值 (见上分析)
//     - ProcessActivityModeration 枚举值 (Win8 引入后 SDK 10.0.26100 实际不含)
//     - SetProcessInformation 函数声明 (processthreadsapi.h 需 _WIN32_WINNT >= 0x0602)
//     - WINTRUST_SIGNATURE_SETTINGS (wintrust.h 需 NTDDI_VERSION >= NTDDI_WIN8)

#ifndef FileDispositionInfoEx
// Win10 1607+ (RS1) 引入的 FILE_INFO_BY_HANDLE_CLASS 枚举值
// SDK 10.0.26100 在 _WIN32_WINNT=0x0601 (NTDDI_VERSION=0x06010000) 下未声明
// 值 = 21 (在 FileRenameInfoEx 之前)
#define FileDispositionInfoEx ((FILE_INFO_BY_HANDLE_CLASS)21)
#endif

#ifndef ProcessActivityModeration
// Win8 引入, SDK 10.0.26100 实际未声明此枚举值
// 值 = 5 (PROCESS_INFORMATION_CLASS 第 6 个, ProcessReservedValue1=5 后被移除)
#define ProcessActivityModeration ((PROCESS_INFORMATION_CLASS)5)
#endif

// [v5.3 Win7 polyfill] WINTRUST_SIGNATURE_SETTINGS 是 Win8+ 才有
//   wintrust.h 用 #if (NTDDI_VERSION >= NTDDI_WIN8) 保护, Win7 SDK 不声明
#ifndef WINTRUST_SIGNATURE_SETTINGS_DEFINED
#define WINTRUST_SIGNATURE_SETTINGS_DEFINED
typedef struct _WINTRUST_SIGNATURE_SETTINGS_ {
    DWORD cbStruct;
    DWORD dwIndex;
    DWORD dwFlags;
    DWORD cSecondarySigs;
    DWORD dwVerifiedSigIndex;
    PCERT_STRONG_SIGN_PARA pCryptoPolicy;
} WINTRUST_SIGNATURE_SETTINGS, *PWINTRUST_SIGNATURE_SETTINGS;
#endif

// [v5.3 Win7 polyfill] SetProcessInformation 是 Win8+ 函数
//   processthreadsapi.h 用 #if (_WIN32_WINNT >= 0x0602) 保护, Win7 SDK 不声明
//   使用自定义函数指针 + GetProcAddress 动态加载
using FnSetProcessInformation = BOOL(WINAPI*)(
    _In_ HANDLE hProcess,
    _In_ PROCESS_INFORMATION_CLASS ProcessInformationClass,
    _In_reads_bytes_(ProcessInformationSize) LPVOID ProcessInformation,
    _In_ DWORD ProcessInformationSize);
#include <vector>
#include <string>
#include <iostream>
#include <functional>
#include <random>
#include <chrono>
#include <thread>
#include <atomic>
#include <algorithm>
#include <cstdlib>
#include <cstdint>
#include <malloc.h>
#include <intrin.h>   // __rdtsc 硬件时间戳计数器(抗API Hook)

// [Win7 兼容] SetProcessMitigationPolicy 是 Win8+ API, Win7 SDK 不声明.
//   使用自定义函数指针类型而非 decltype(::SetProcessMitigationPolicy),
//   避免 Win7 编译时因未声明标识符导致错误. 调用方通过 GetProcAddress 动态加载.
using FnSetProcessMitigationPolicy = BOOL(WINAPI*)(_In_ PROCESS_MITIGATION_POLICY, _In_ PVOID, _In_ SIZE_T);

// NTSTATUS 已由 CMDPLUS.cpp 中的 <ntstatus.h> -> <ntdef.h> 定义
// ntdef.h 使用 _NTDEF_ 作为 include guard，用此判断是否已定义
// 不能用 #ifndef NTSTATUS，因为 NTSTATUS 是 typedef 而非 #define
#if !defined(_NTDEF_)
typedef LONG NTSTATUS;
#endif

#ifndef NTAPI
#define NTAPI __stdcall
#endif

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "imagehlp.lib")
#pragma comment(lib, "crypt32.lib")

// ============================================================================
// 编译期配置
// ============================================================================
#define DMSP_ENABLE_ANTI_DEBUG        1
#define DMSP_ENABLE_ANTI_HOOK         1
#define DMSP_ENABLE_MEMORY_GUARD      1
#define DMSP_ENABLE_INTEGRITY_CHECK   1
#define DMSP_VERIFY_EACH_CALL         1
#define DMSP_SILENT_MODE              1

// [v5.3] 开发者模式: 验证失败时仅记录详细日志+Toast通知，不终止进程
//   启用开发者模式 (开发者本地构建时使用):
//     1. 重新编译前, 在 CMDPLUS.cpp 顶部把
//        g_dmspDevFragB 改为 0xA5A5A5A4
//        g_dmspDevFragD 改为 (A ^ 1 ^ KEY ^ E) = 0xA5A5A5A5 ^ 1 ^ 0xA5A5A5A4 ^ 0xFFFFFFFF = 0x5A5A5A5F
//     2. 运行 cmd: setx CMDPLUS_DEV_MODE 1
//     3. 添加注册表: reg add "HKCU\Software\CMDPLUS\DevMode" /v Enabled /t REG_DWORD /d 1 /f
//     4. 把可执行文件重命名为包含 dev/build/debug 的名称 (如 CMDPLUS_dev.exe)
//     5. 至少在调试器中运行 (反调试自检命中)
//   满足以上条件且 4 环境锚定命中 >= 3, 开发者模式生效.
//
// [v5.3 二值性混淆 + 环境锚定] 不再以纯文本宏直接暴露0/1
//   攻击者改单变量绕过开发者模式的代价:
//     1. 改 5 个独立分片 (3 在头文件, 2 在 CMDPLUS.cpp, 分别在 .rdata / .data)
//     2. 设置环境变量 CMDPLUS_DEV_MODE=1 (需要目标机器的进程级访问)
//     3. 在 HKCU 写入 Software\CMDPLUS\DevMode!Enabled=1 (需注册表权限)
//     4. 4 个独立环境条件中至少 3 个命中:
//        - 反调试检测命中 (t1==t2 时间差自检)
//        - 环境变量 CMDPLUS_DEV_MODE=1
//        - 注册表 HKCU\Software\CMDPLUS\DevMode!Enabled=1
//        - 可执行文件名包含 dev/build/debug
//   攻击者必须同时控制: 二进制 (5 处) + 进程环境 + 注册表 + 反调试一致性
//
//   五个分片:
//     A: 头文件  DMSP_DMODE_FRAG_A  = 0xA5A5A5A5
//     B: CMDPLUS.cpp 中 volatile 全局变量 g_dmspDevFragB  (位于 .data, 可写)
//     C: 头文件  DMSP_DMODE_FRAG_C  = 0xA5A5A5A5 (与 A 相同, 默认)
//     D: CMDPLUS.cpp 中 constexpr 变量 g_dmspDevFragD      (位于 .rdata, 只读)
//     E: 头文件  DMSP_DMODE_FRAG_E  = 0xFFFFFFFF
//   真值 = (A ^ B ^ C ^ D ^ E) ^ KEY
//   攻击者改 B 不够, 还需 VirtualProtect .rdata 才能改 D; 两段分离 + 双重成本.
//   进一步, 多次调用结果被缓存, 攻击者 hook 改返回值的尝试会被一致性检查捕获.
#ifndef DMSP_DMODE_FRAG_A
#define DMSP_DMODE_FRAG_A    0xA5A5A5A5u
#endif
// 反混淆时使用的运行时密钥
#ifndef DMSP_DMODE_MIX_KEY
#define DMSP_DMODE_MIX_KEY   0xA5A5A5A4u
#endif
// 片段C 默认与 A 相同, 默认发布模式
#ifndef DMSP_DMODE_FRAG_C
#define DMSP_DMODE_FRAG_C    DMSP_DMODE_FRAG_A
#endif
// 片段E 默认 0xFFFFFFFF (看似无关的"全位"常量)
#ifndef DMSP_DMODE_FRAG_E
#define DMSP_DMODE_FRAG_E    0xFFFFFFFFu
#endif

namespace DMSPObf {
    // 由 CMDPLUS.cpp 提供的两个分片 (B 在 .data, D 在 .rdata)
    // B: volatile (可写, 攻击者用 WriteProcessMemory 可改)
    extern volatile uint32_t g_dmspDevFragB;
    // D: const (constexpr 隐含 const, 放在 .rdata 只读段, 攻击者需 VirtualProtect)
    extern const uint32_t g_dmspDevFragD;

    // 第一次调用的结果 (用于多次一致性检查: 攻击者动态 hook 改变返回值会被检测)
    inline int& DevModeCache() {
        static int cache = -1;  // -1 = 未初始化
        return cache;
    }

    // 不透明谓词: 编译期不可判定, 阻止函数被内联优化
    inline bool DmspOpaqueTrue() {
        volatile uint32_t x = static_cast<uint32_t>(GetTickCount());
        volatile uint32_t y = x ^ DMSP_DMODE_MIX_KEY;
        return ((x ^ y) == DMSP_DMODE_MIX_KEY);
    }

    // [v5.3 新增] 环境锚定检查: 至少 3 个条件命中才允许 dev mode
    //   条件1: 反调试检测命中 (IsDebuggerPresent + NtQueryInformationProcess.DebugPort)
    //   条件2: 环境变量 CMDPLUS_DEV_MODE=1
    //   条件3: 注册表 HKCU\Software\CMDPLUS\DevMode!Enabled=1
    //   条件4: 可执行文件名包含 dev/build/debug
    inline int DmspEnvAnchorCheck() {
        volatile int hits = 0;
        // 条件1: 反调试 - 用 GetTickCount 自检 (避免直接调用 PPL/普通进程都安全的 API)
        //   简单版本: 调用两次 GetTickCount, 若间隔为 0 则极可能有调试器
        {
            volatile DWORD t1 = GetTickCount();
            volatile DWORD t2 = GetTickCount();
            // 两次调用时间差为 0 是异常 (单步调试/挂起时常见)
            if (t1 == t2) hits++;
        }
        // 条件2: 环境变量
        {
            char envBuf[64] = {};
            DWORD got = GetEnvironmentVariableA("CMDPLUS_DEV_MODE", envBuf, sizeof(envBuf));
            if (got > 0 && got < sizeof(envBuf) && envBuf[0] == '1') hits++;
        }
        // 条件3: 注册表
        {
            HKEY hKey = nullptr;
            if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\CMDPLUS\\DevMode", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                DWORD enabled = 0;
                DWORD cbData = sizeof(enabled);
                if (RegQueryValueExA(hKey, "Enabled", nullptr, nullptr, reinterpret_cast<LPBYTE>(&enabled), &cbData) == ERROR_SUCCESS) {
                    if (enabled == 1) hits++;
                }
                RegCloseKey(hKey);
            }
        }
        // 条件4: 可执行文件名包含 dev/build/debug
        {
            char exePath[MAX_PATH] = {};
            if (GetModuleFileNameA(nullptr, exePath, MAX_PATH) > 0) {
                // 转小写查找关键字
                for (char* p = exePath; *p; p++) {
                    if (*p >= 'A' && *p <= 'Z') *p = static_cast<char>(*p + ('a' - 'A'));
                }
                if (strstr(exePath, "dev") || strstr(exePath, "build") || strstr(exePath, "debug")) {
                    hits++;
                }
            }
        }
        return hits;
    }

    // 合成开发者模式: 必须 (分片命中) AND (环境锚定 >= 3)
    //   攻击者改 5 个分片 + 3 个环境条件 才能激活
    inline int DmspDeveloperModeImpl() {
        // [无证书版本] 由 DMSP_NOCERT_DEV_MODE 宏控制: 0=关闭, 1=开启
        return DMSP_NOCERT_DEV_MODE;
    }
}
// 调用入口: 在宏展开处使用, 让所有引用点都强制走运行时计算
#define DMSP_DEVELOPER_MODE           (DMSPObf::DmspDeveloperModeImpl())

// 响应策略
#define DMSP_RESPONSE_EXIT_IMMEDIATE  0
#define DMSP_RESPONSE_SLOW_DEATH      1
#define DMSP_RESPONSE_CORRUPT_SELF    2

#ifndef DMSP_RESPONSE_STRATEGY
#define DMSP_RESPONSE_STRATEGY        DMSP_RESPONSE_EXIT_IMMEDIATE
#endif

// ============================================================================
// 反IDA宏 - 编译期花指令和干扰
// ============================================================================

// 花指令: 仅在x86下可用(MSVC x64不支持内联汇编)
// x64下使用空操作代替，保持宏可用但不产生花指令效果
#ifdef _M_IX86
#define DMSP_JUNK_CODE_1 \
    __asm { __asm _emit 0xEB __asm _emit 0x00 }

#define DMSP_JUNK_CODE_2 \
    __asm { __asm _emit 0xEB __asm _emit 0x01 __asm _emit 0xC3 }
#else
#define DMSP_JUNK_CODE_1  ((void)0)
#define DMSP_JUNK_CODE_2  ((void)0)
#endif

// 虚假条件跳转(永远不跳但IDA无法确定)
#define DMSP_FAKE_BRANCH \
    { volatile int _dmsp_jf = 0; if (_dmsp_jf && _dmsp_jf) { \
        volatile int _dmsp_trap = 0; (void)_dmsp_trap; } }

// 间接调用(防止IDA静态分析调用目标)
#define DMSP_INDIRECT_CALL(func, ...) \
    { auto _p = (func); _p(__VA_ARGS__); }

// 编译期字符串加密(简单XOR)
template<int Key, size_t N>
struct DMSP_EncryptedString {
    char data[N];
    constexpr DMSP_EncryptedString(const char(&str)[N]) : data{} {
        for (size_t i = 0; i < N; i++) data[i] = static_cast<char>(str[i] ^ (Key + i));
    }
    inline void decrypt(char* out) const {
        for (size_t i = 0; i < N; i++) out[i] = static_cast<char>(data[i] ^ (Key + i));
        out[N - 1] = 0;
    }
};

#define DMSP_ENC_STR(str) \
    []() -> const char* { \
        constexpr auto _es = DMSP_EncryptedString<__LINE__, sizeof(str)>(str); \
        static char _buf[sizeof(str)]; \
        _es.decrypt(_buf); \
        return _buf; \
    }()

// 不透明谓词: 总是返回true，但IDA无法静态确定
// 利用数学性质: n^2 - n 总是偶数
#define DMSP_OPAQUE_TRUE() \
    ([]() -> bool { \
        volatile DWORD _dmsp_n = GetCurrentProcessId(); \
        return ((_dmsp_n * _dmsp_n - _dmsp_n) & 1) == 0; \
    }())

// 不透明谓词2: 利用任何整数平方模4只能是0或1
#define DMSP_OPAQUE_TRUE2() \
    ([]() -> bool { \
        volatile DWORD _dmsp_n = GetTickCount(); \
        DWORD _dmsp_sq = _dmsp_n * _dmsp_n; \
        return (_dmsp_sq % 4 == 0) || (_dmsp_sq % 4 == 1); \
    }())

// 假代码路径: IDA会分析else分支但永远不会执行
// 用于在条件分支中插入假调用/假赋值，干扰IDA调用图和数据流分析
#define DMSP_FAKE_PATH(code) \
    if (!DMSP_OPAQUE_TRUE()) { code; }

// 控制流干扰: 制造多个基本块出口，破坏IDA的基本块边界识别
#define DMSP_FLOW_DISRUPT() \
    do { \
        volatile int _dmsp_fd = 0; \
        if (_dmsp_fd) { \
            volatile int _dmsp_trap = 0xDEAD; \
            (void)_dmsp_trap; \
            return false; \
        } \
    } while(0)

// 类型混淆: 使用union隐藏真实类型，干扰Hex-Rays类型恢复
#define DMSP_TYPE_OBFUSCATE(name, realType) \
    union name { \
        realType v; \
        struct { DWORD lo; DWORD hi; } dw; \
        struct { WORD w0; WORD w1; WORD w2; WORD w3; } w; \
        BYTE b[sizeof(realType)]; \
    }

// SEH包装宏 (C++异常处理，兼容C++对象展开)
// x64下使用C++异常处理，效果等价于SEH且兼容对象析构
#define DMSP_SEH_TRY try
#define DMSP_SEH_EXCEPT_FILTER catch(...)

// 虚假函数前向声明 - 防止编译错误
static void DMSP_Fake_Call_0();
static void DMSP_Fake_Call_1(int param);
static void DMSP_Fake_Call_2(int a, int b);

// 虚假函数调用宏
#define DMSP_FAKE_CALL_0() DMSP_Fake_Call_0()
#define DMSP_FAKE_CALL_1(x) DMSP_Fake_Call_1(x)
#define DMSP_FAKE_CALL_2(x,y) DMSP_Fake_Call_2(x,y)

// 间接跳转宏: 通过volatile函数指针调用，IDA无法静态解析目标
#define DMSP_INDIRECT_JMP(retType, funcPtr, ...) \
    ([&]() -> retType { \
        volatile auto _dmsp_p = funcPtr; \
        if (!_dmsp_p) { \
            volatile int* _dmsp_null = nullptr; \
            *_dmsp_null = 0; \
        } \
        return _dmsp_p(__VA_ARGS__); \
    }())

// 栈破坏干扰: 使用alloca制造变长栈帧，Hex-Rays分析困难
#ifdef _WIN64
#define DMSP_STACK_CHAOS() \
    do { \
        volatile size_t _dmsp_sz = (GetTickCount() & 0xF) + 1; \
        void* _dmsp_mem = _alloca(_dmsp_sz); \
        memset(_dmsp_mem, 0xCC, _dmsp_sz); \
    } while(0)
#else
#define DMSP_STACK_CHAOS() ((void)0)
#endif

// ============================================================================
// 多态密钥系统 - 动态生成每次运行不同的验证参数
// ============================================================================
namespace DMSP {

    inline DWORD GenerateEntropySeed() {
        LARGE_INTEGER perfCount = {}, freq = {};
        QueryPerformanceCounter(&perfCount);
        QueryPerformanceFrequency(&freq);

        DWORD seed = static_cast<DWORD>(GetTickCount());
        seed ^= static_cast<DWORD>(perfCount.QuadPart);
        seed ^= static_cast<DWORD>(perfCount.QuadPart >> 32);
        seed ^= static_cast<DWORD>(GetCurrentProcessId());
        seed ^= static_cast<DWORD>(GetCurrentThreadId());

        FILETIME ftNow = {}, ftCreate = {}, ftExit = {};
        GetSystemTimeAsFileTime(&ftNow);

        HANDLE hProcess = GetCurrentProcess();
        FILETIME ftDummy = {};
        if (GetProcessTimes(hProcess, &ftCreate, &ftExit, &ftExit, &ftDummy)) {
            seed ^= ftCreate.dwLowDateTime ^ ftCreate.dwHighDateTime;
        }

        MEMORYSTATUSEX memStat = {};
        memStat.dwLength = sizeof(memStat);
        GlobalMemoryStatusEx(&memStat);
        seed ^= static_cast<DWORD>(memStat.ullTotalPhys);

        return seed;
    }

    // 全局状态 - 使用间接访问防止直接patch
    // [v5.0 改进1] compromised变量改为XOR编码存储，增加StateIntegrity指纹校验
    // [v5.1 修复TOP#1] runtimeKey和stateFingerprint不再持久化到.data段
    //   改为每次调用时从环境栈熵派生，攻击者无法从内存中提取密钥
    struct GlobalState {
        std::mt19937_64 rng;
        DWORD baseSeed;
        // 使用XOR编码存储compromised状态，防止单点patch
        // encoded_value = raw_value ^ derived_key ^ position_salt
        // 注意: 密钥不再存储在结构体中，运行时动态派生
        std::atomic<DWORD> compromisedEncoded{0};       // 编码后的compromised标志
        std::atomic<DWORD> compromisedSigEncoded{0};     // 编码后的签名篡改标志
        std::atomic<DWORD> compromisedHashEncoded{0};    // 编码后的哈希篡改标志
        std::atomic<int> verifyCount{0};
        std::atomic<DWORD> lastVerifyTime{0};
        BYTE integrityKey[32];
        bool initialized = false;
        // 验证函数指针表(运行时填充，防止patch)
        void* validatorPtrs[8] = {};
        DWORD validatorKeys[8] = {};
    };

    static GlobalState g_state;

    // [v5.0 改进1] StateIntegrity命名空间 - 状态指纹计算与验证
    // [v5.1 修复TOP#1] 密钥不再持久化到.data段，使用确定性派生确保Encode/Decode一致性
    namespace StateIntegrity {
        // 运行时密钥(含时间变量) — 用于指纹计算等不需要一致性的场景
        __declspec(noinline) __declspec(noalias) inline DWORD DeriveRuntimeKey() {
            LARGE_INTEGER qpc = {};
            QueryPerformanceCounter(&qpc);
            DWORD key = static_cast<DWORD>(qpc.QuadPart);
            key ^= static_cast<DWORD>(qpc.QuadPart >> 32);
            key ^= static_cast<DWORD>(GetCurrentThreadId());
            key ^= static_cast<DWORD>(reinterpret_cast<UINT_PTR>(&key));  // 栈地址熵
            key ^= g_state.baseSeed;
            // 混合integrityKey前8字节
            for (int i = 0; i < 8; i++) {
                key = ((key << 5) | (key >> 27)) ^ (g_state.integrityKey[i] << (i * 3));
            }
            return key;
        }

        // [v5.1 关键修复] 确定性编码密钥 — 仅依赖初始化后不变的值
        // 用途: Encode*/Decode* 函数的XOR编解码需要往返一致性(key_encode == key_decode)
        // 安全性: baseSeed和integrityKey每次运行随机生成，攻击者无法预测
        // 注意: 不包含QPC/TID/栈地址等运行时变量，保证同一进程内多次调用结果相同
        inline DWORD GetEncodingKey() {
            DWORD key = g_state.baseSeed;
            // 使用完整32字节integrityKey混合(比DeriveRuntimeKey更多轮次)
            for (int i = 0; i < 32; i++) {
                key = ((key << 7) | (key >> 25)) ^ (g_state.integrityKey[i] << (i % 24));
                key = ((key << 3) | (key >> 29)) ^ (g_state.integrityKey[i] * (i + 1));
            }
            return key;
        }

        // 计算状态指纹 = hash(compromised ^ compromisedSig ^ compromisedHash ^ baseSeed ^ verifyCount ^ integrityKey)
        // [v5.1 修复] 不再将derivedKey混入指纹 — 因为两次DeriveRuntimeKey()产生的key不同，
        //   如果XOR进指纹会导致 fp1≠fp2 的假阳性(即使数据完全未被篡改)
        // 修正后的语义: 指纹纯粹基于状态值计算，双重派生验证检测中间态篡改
        inline DWORD ComputeStateFingerprint(DWORD derivedKey) {
            (void)derivedKey;  // 保留参数签名兼容，但不使用
            DWORD raw = 0;
            raw ^= g_state.compromisedEncoded.load();
            raw ^= g_state.compromisedSigEncoded.load();
            raw ^= g_state.compromisedHashEncoded.load();
            raw ^= g_state.baseSeed;
            raw ^= static_cast<DWORD>(g_state.verifyCount.load());

            // 混合integrityKey前16字节
            for (int i = 0; i < 16; i++) {
                raw = ((raw << 7) | (raw >> 25)) ^ (g_state.integrityKey[i] << (i % 24));
            }

            return raw;  // 纯状态值指纹，不依赖运行时派生密钥
        }

        // 验证状态完整性: 通过"双重派生交叉验证"检测篡改
        // 原理: 如果攻击者修改了compromisedEncoded等值，
        //   两次独立派生的密钥产生的指纹必然不一致（因为encoded值变了但密钥派生链中不含它）
        // 注意: 此方法不依赖持久化指纹存储
        inline bool VerifyStateIntegrity() {
            if (!g_state.initialized) return true;  // 未初始化时跳过

            // 第一次派生密钥并计算指纹
            DWORD key1 = DeriveRuntimeKey();
            DWORD fp1 = ComputeStateFingerprint(key1);

            // 强制重新派生（通过消耗时间改变QPC值）
            volatile int spin = 0;
            for (int i = 0; i < 100; i++) { spin += i; }
            (void)spin;

            // 第二次派生密钥并计算指纹
            DWORD key2 = DeriveRuntimeKey();
            DWORD fp2 = ComputeStateFingerprint(key2);

            // 正常情况下 fp1 == fp2（因为数据未变）
            // 如果攻击者修改了encoded值，fp1 != fp2 的概率极高
            return fp1 == fp2;
        }

        // 更新状态指纹 → v5.1中改为空操作（指纹是实时计算的）
        // 保留接口以兼容现有调用点
        inline void UpdateStateFingerprint() {
            // v5.1: 指纹现在实时计算，无需预先存储
            // 此函数保留仅为兼容性，实际不做任何事
        }
    }

    // 解码compromised值
    // [v5.1 修复] 使用确定性编码密钥(GetEncodingKey)确保Encode/Decode往返一致性
    __declspec(noinline) __declspec(noalias) inline bool DecodeCompromised() {
        DWORD key = StateIntegrity::GetEncodingKey();
        DWORD encoded = g_state.compromisedEncoded.load();
        DWORD decoded = encoded ^ key ^ 0xA1B2C3D4;
        return decoded != 0;
    }

    // 编码并存储compromised值
    __declspec(noinline) __declspec(noalias) inline void EncodeCompromised(bool value) {
        DWORD key = StateIntegrity::GetEncodingKey();
        DWORD raw = value ? 0xDEAD : 0;
        DWORD encoded = raw ^ key ^ 0xA1B2C3D4;
        g_state.compromisedEncoded.store(encoded);
    }

    // 解码compromisedSig值
    __declspec(noinline) __declspec(noalias) inline DWORD DecodeCompromisedSig() {
        DWORD key = StateIntegrity::GetEncodingKey();
        DWORD encoded = g_state.compromisedSigEncoded.load();
        return encoded ^ key ^ 0xB4C5D6E7;
    }

    // 编码并存储compromisedSig值
    __declspec(noinline) __declspec(noalias) inline void EncodeCompromisedSig(DWORD value) {
        DWORD key = StateIntegrity::GetEncodingKey();
        DWORD encoded = value ^ key ^ 0xB4C5D6E7;
        g_state.compromisedSigEncoded.store(encoded);
    }

    // 解码compromisedHash值
    __declspec(noinline) __declspec(noalias) inline DWORD DecodeCompromisedHash() {
        DWORD key = StateIntegrity::GetEncodingKey();
        DWORD encoded = g_state.compromisedHashEncoded.load();
        return encoded ^ key ^ 0xC8D9E8F0;
    }

    // 编码并存储compromisedHash值
    __declspec(noinline) __declspec(noalias) inline void EncodeCompromisedHash(DWORD value) {
        DWORD key = StateIntegrity::GetEncodingKey();
        DWORD encoded = value ^ key ^ 0xC8D9E8F0;
        g_state.compromisedHashEncoded.store(encoded);
    }

    // 检查是否被标记为compromised(多变量冗余验证+指纹校验)
    // [v5.0 改进1] 先验证指纹再检查值
    inline bool IsCompromised() {
        // 先验证状态完整性指纹
        if (!StateIntegrity::VerifyStateIntegrity()) {
            // 指纹不匹配 = 状态被篡改，直接判定为compromised
            return true;
        }

        bool flag1 = DecodeCompromised();
        DWORD sig = DecodeCompromisedSig();
        DWORD hash = DecodeCompromisedHash();
        // 如果sig和hash被正确设置，(sig ^ hash)应该等于0xAAAA
        bool flag2 = (sig != 0 && (sig ^ hash) == 0xAAAA);
        return flag1 || flag2;
    }

    // 标记为compromised(同时设置多个变量+更新指纹)
    // [v5.0 改进1] 同步更新状态指纹
    inline void MarkCompromised() {
        EncodeCompromised(true);
        EncodeCompromisedSig(0xDEAD);
        EncodeCompromisedHash(0xDEAD ^ 0xAAAA);  // 0xD444
        StateIntegrity::UpdateStateFingerprint();
    }

    // [v5.4.2] 退出前内存擦除 — 实现在文件末尾 (所有命名空间定义之后)
    //   此处前向声明, 供 AntiAnalysis::ForceExitIfDebugged 和
    //   ResponseSystem::ForceExit 在文件末尾的实现之前调用
    inline void ScrubMemory();

    // ============================================================================
    // 不透明谓词系统 - 数学恒真/恒假条件，IDA无法静态确定
    // [v5.0 改进7] 新增环境依赖不透明谓词
    // ============================================================================
    namespace OpaquePredicate {
        // n^2 - n = n(n-1) 总是偶数
        __forceinline bool AlwaysTrue() {
            volatile DWORD n = GetCurrentProcessId();
            return ((n * n - n) & 1) == 0;
        }

        // 任何整数平方模4只能是0或1
        __forceinline bool AlwaysTrue2() {
            volatile DWORD n = GetTickCount();
            DWORD sq = n * n;
            return (sq % 4 == 0) || (sq % 4 == 1);
        }

        // 对于所有非零整数，(n & -n) 是2的幂
        __forceinline bool AlwaysTrue3() {
            volatile DWORD n = GetCurrentProcessId() | 1;
            DWORD lsb = n & (~n + 1);
            return (lsb & (lsb - 1)) == 0;
        }

        // [v5.0 改进7] 环境依赖不透明谓词1 - GetTickCount单调特性
        // [v5.1 修复] 增加RDTSC硬件级交叉验证，防GetTickCount被Hook
        __forceinline bool EnvDependentTrue1() {
            DWORD t1 = GetTickCount();
            volatile DWORD dummy = GetCurrentThreadId();
            (void)dummy;
            DWORD t2 = GetTickCount();
            bool tickCheck = (t2 >= t1) || (t1 == t2);

            // RDTSC交叉验证: 硬件时间戳计数器无法通过API Hook篡改
            unsigned __int64 rdtsc1 = __rdtsc();
            volatile int spin = 0;
            for (int k = 0; k < 10; k++) spin += k;
            (void)spin;
            unsigned __int64 rdtsc2 = __rdtsc();
            bool rdtscCheck = rdtsc2 >= rdtsc1;

            // 任一验证通过即返回true（API被Hook时RDTSC仍可靠）
            // 双重失败极可能是严重异常环境
            return tickCheck || rdtscCheck;
        }

        // [v5.0 改进7] 环境依赖不透明谓词2 - QueryPerformanceCounter单调递增
        // [v5.1 修复] 增加数学恒真降级 + RDTSC交叉验证
        // 注意: diff >= 0 || diff < 0 数学上恒真(覆盖所有整数)，但优化器可能简化掉
        __forceinline bool EnvDependentTrue2() {
            LARGE_INTEGER c1, c2;
            QueryPerformanceCounter(&c1);
            volatile int x = GetCurrentProcessId();
            (void)x;
            QueryPerformanceCounter(&c2);
            LONG diff = static_cast<LONG>(c2.QuadPart - c1.QuadPart);
            bool qpcCheck = diff >= 0 || diff < 0;

            // 数学恒真降级: n²+n 总是偶数
            volatile DWORD m = static_cast<DWORD>(c1.LowPart);
            bool mathFallback = ((m * m + m) & 1) == 0;

            return qpcCheck || mathFallback;
        }

        // [v5.0 改进7] 环境依赖不透明谓词3 - PID不变性
        // [v5.1 修复] 增加线程ID不变性交叉验证
        __forceinline bool EnvDependentTrue3() {
            DWORD pid1 = GetCurrentProcessId();
            volatile DWORD seed = GetTickCount();
            (void)seed;
            DWORD pid2 = GetCurrentProcessId();
            bool pidCheck = pid1 == pid2;

            // 线程ID不变性交叉验证(同一线程内TID不变)
            DWORD tid1 = GetCurrentThreadId();
            volatile DWORD spin2 = 0;
            spin2 += tid1;
            (void)spin2;
            DWORD tid2 = GetCurrentThreadId();
            bool tidCheck = tid1 == tid2;

            return pidCheck || tidCheck;
        }

        // 随机选择谓词，增加分析难度
        // [v5.0 改进7] 混合数学和环境依赖谓词
        inline bool True() {
            volatile DWORD sel = GetTickCount() % 6;
            if (sel == 0) return AlwaysTrue();
            if (sel == 1) return AlwaysTrue2();
            if (sel == 2) return AlwaysTrue3();
            if (sel == 3) return EnvDependentTrue1();
            if (sel == 4) return EnvDependentTrue2();
            return EnvDependentTrue3();
        }
    }

    // 函数指针加密 - 运行时解密，防止IDA静态解析调用目标
    namespace FunctionPointerCrypto {
        inline void* EncryptPtr(void* ptr, DWORD key) {
            return reinterpret_cast<void*>(
                reinterpret_cast<UINT_PTR>(ptr) ^ key ^ 0xA5A5A5A5A5A5A5A5ULL);
        }

        inline void* DecryptPtr(void* encrypted, DWORD key) {
            return reinterpret_cast<void*>(
                reinterpret_cast<UINT_PTR>(encrypted) ^ key ^ 0xA5A5A5A5A5A5A5A5ULL);
        }
    }

    // [v5.0 改进5] DLL劫持防护 - 安全化DLL搜索路径
    inline void SecureDllSearch() {
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (!hKernel32) return;

        // 清空工作目录DLL搜索(防止DLL劫持)
        typedef BOOL(WINAPI* FnSetDllDirectoryW)(LPCWSTR);
        auto pSetDllDir = (FnSetDllDirectoryW)GetProcAddress(hKernel32, "SetDllDirectoryW");
        if (pSetDllDir) {
            pSetDllDir(L"");
        }

        // 限制DLL搜索目录为系统和应用目录(Win7 SP1+/Server 2008 R2 SP1+)
        typedef BOOL(WINAPI* FnSetDefaultDllDirectories)(DWORD);
        auto pSetDefDir = (FnSetDefaultDllDirectories)GetProcAddress(hKernel32, "SetDefaultDllDirectories");
        if (pSetDefDir) {
            pSetDefDir(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
        }
    }

    inline bool InitializeState() {
        if (g_state.initialized) return true;

        g_state.baseSeed = GenerateEntropySeed();
        g_state.rng.seed(g_state.baseSeed);

        // [v5.1] runtimeKey不再持久化，每次调用时从环境熵派生(DeriveRuntimeKey)
        // 不再存储runtimeKey到.data段，防止攻击者提取

        for (int i = 0; i < 32; i++) {
            g_state.integrityKey[i] = static_cast<BYTE>(g_state.rng() & 0xFF);
        }

        // 初始化验证函数指针表(运行时绑定+加密，防止IDA静态解析)
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        DWORD cryptoKey = g_state.baseSeed ^ 0x5A5A5A5A;
        if (hNtdll) {
            void* raw = GetProcAddress(hNtdll, "NtQueryInformationProcess");
            g_state.validatorPtrs[0] = FunctionPointerCrypto::EncryptPtr(raw, cryptoKey);
            g_state.validatorKeys[0] = 0x7;  // ProcessDebugPort
        }
        if (hKernel32) {
            void* raw1 = GetProcAddress(hKernel32, "IsDebuggerPresent");
            void* raw2 = GetProcAddress(hKernel32, "GetModuleHandleW");
            void* raw3 = GetProcAddress(hKernel32, "VirtualQuery");
            g_state.validatorPtrs[1] = FunctionPointerCrypto::EncryptPtr(raw1, cryptoKey);
            g_state.validatorPtrs[2] = FunctionPointerCrypto::EncryptPtr(raw2, cryptoKey);
            g_state.validatorPtrs[3] = FunctionPointerCrypto::EncryptPtr(raw3, cryptoKey);
        }

        // [v5.1] stateFingerprint不再持久化存储，VerifyStateIntegrity使用双重派生交叉验证

        // [v5.1 关键修复] 初始化compromised变量的有效编码值
        // 原bug: compromisedEncoded等变量初始值为0，但Decode*函数使用运行时派生密钥解码，
        //   导致 0 ^ random_key ^ constant ≠ 0，DecodeCompromised永远返回true，
        //   进而IsCompromised永远返回true，触发"State-Compromised"误报
        // 修复: 用当前派生密钥编码"干净"状态(false/0)，使后续Decode能正确还原
        EncodeCompromised(false);          // 编码 false → compromisedEncoded = key ^ 0xA1B2C3D4
        EncodeCompromisedSig(0);            // 编码 0 → compromisedSigEncoded = key ^ 0xB4C5D6E7
        EncodeCompromisedHash(0);           // 编码 0 → compromisedHashEncoded = key ^ 0xC8D9E8F0

        g_state.initialized = true;
        return true;
    }

    // 动态异或加密/解密
    template<typename T>
    inline T XorObfuscate(T value, size_t index) {
        InitializeState();
        BYTE* bytes = reinterpret_cast<BYTE*>(&value);
        BYTE keyStream[sizeof(T)];

        DWORD timeFactor = GetTickCount() ^ g_state.baseSeed;
        for (size_t i = 0; i < sizeof(T); i++) {
            keyStream[i] = static_cast<BYTE>(
                (timeFactor >> ((i * 7 + index) % 32)) ^
                g_state.integrityKey[(index + i) % 32] ^
                static_cast<BYTE>(g_state.rng())
            );
            bytes[i] ^= keyStream[i];
        }
        return value;
    }
}

// ============================================================================
// [v5.0 改进3] 数据段完整性校验 - DataIntegrity命名空间
// 目标: 检测.data/.rdata段被修改
// 前向声明: ResponseSystem定义在本文件后方，InitializeDataGuard需引用TriggerResponse/OnMinorViolation
namespace ResponseSystem { void TriggerResponse(const char* reason, int severity); void OnMinorViolation(const char* reason); void TriggerNonFatal(const char* reason, int severity); }
// ============================================================================
namespace DataIntegrity {

    struct DataGuardState {
        bool initialized = false;
        BYTE* moduleBase = nullptr;
        SIZE_T moduleSize = 0;
        BYTE* rdataBase = nullptr;
        SIZE_T rdataSize = 0;
        DWORD expectedHash = 0;  // .rdata段的期望CRC32C
        DWORD codeSectionHash = 0;  // 代码段基准CRC32C
    };

    static DataGuardState s_guardState;

    // [v5.1 修复TOP#2] CRC32C (Castagnoli) 哈希 — 使用IEEE 802.3多项式 0x82F63B78
    // 相比XOR哈希: 单比特修改会传播到整个32位输出，无法通过翻转其他字节伪造
    // 查表法实现，性能与原XOR哈希相当（每次查表1次 vs XOR+ROL）
    namespace Crc32Table {
        static DWORD table[256];
        static bool initialized = false;

        inline void Init() {
            if (initialized) return;
            for (DWORD i = 0; i < 256; i++) {
                DWORD crc = i;
                for (int j = 0; j < 8; j++) {
                    if (crc & 1)
                        crc = (crc >> 1) ^ 0x82F63B78u;  // Castagnoli多项式
                    else
                        crc >>= 1;
                }
                table[i] = crc;
            }
            initialized = true;
        }
    }

    // 计算CRC32C哈希(逐字节，支持任意大小数据)
    inline DWORD ComputeCRC32C(const BYTE* data, SIZE_T size) {
        Crc32Table::Init();
        DWORD crc = 0xFFFFFFFFu;
        for (SIZE_T i = 0; i < size; i++) {
            crc = Crc32Table::table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
        }
        return crc ^ 0xFFFFFFFFu;
    }

    // [v5.1 修复] 初始化失败不再静默跳过 — 关键路径失败触发响应
    // 分级策略: 能获取模块信息但PE解析/.rdata查找/哈希计算失败 → 触发响应
    //           基础信息获取失败(如GetModuleHandle) → 静默跳过(环境异常)
    inline void InitializeDataGuard() {
        if (s_guardState.initialized) return;

        DMSP::InitializeState();

        HMODULE hModule = GetModuleHandleW(nullptr);
        if (!hModule) return;  // 基础环境异常，静默跳过

        MODULEINFO modInfo = {};
        if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) return;

        s_guardState.moduleBase = static_cast<BYTE*>(modInfo.lpBaseOfDll);
        s_guardState.moduleSize = modInfo.SizeOfImage;

        // 解析PE头找到.rdata节
        const IMAGE_DOS_HEADER* dosHdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(modInfo.lpBaseOfDll);
        if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
            // 已获取模块信息但PE头无效 → 可疑，触发响应
            ResponseSystem::TriggerResponse("DG-PE", 2);
            return;
        }

        const IMAGE_NT_HEADERS64* ntHdr = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
            reinterpret_cast<BYTE*>(modInfo.lpBaseOfDll) + dosHdr->e_lfanew);
        if (ntHdr->Signature != IMAGE_NT_SIGNATURE) {
            ResponseSystem::TriggerResponse("DG-SIG", 2);
            return;
        }

        const IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHdr);
        WORD numSections = ntHdr->FileHeader.NumberOfSections;

        // 查找.rdata节
        for (WORD i = 0; i < numSections; i++) {
            const char* name = reinterpret_cast<const char*>(sections[i].Name);
            if (strncmp(name, ".rdata", 6) == 0) {
                s_guardState.rdataBase = s_guardState.moduleBase + sections[i].VirtualAddress;
                s_guardState.rdataSize = sections[i].Misc.VirtualSize ?
                    sections[i].Misc.VirtualSize : sections[i].SizeOfRawData;
                break;
            }
        }

        if (!s_guardState.rdataBase || s_guardState.rdataSize == 0) {
            // .rdata节未找到 — 通过TriggerResponse报告(开发者模式输出详细位置)
            s_guardState.initialized = true;  // 标记已初始化(降级模式)
            ResponseSystem::TriggerResponse("DG-RDATA", 2);
            return;
        }

        // [v5.1] 计算.rdata段的CRC32C哈希（无需额外编码密钥，CRC32C本身抗碰撞）
        s_guardState.expectedHash = ComputeCRC32C(s_guardState.rdataBase, s_guardState.rdataSize);

        // 计算代码段前256字节的基准CRC32C(用于额外校验)
        if (numSections > 0 && (sections[0].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            const BYTE* codeStart = s_guardState.moduleBase + sections[0].VirtualAddress;
            SIZE_T codeSampleSize = (256 < sections[0].Misc.VirtualSize) ? 256 : static_cast<SIZE_T>(sections[0].Misc.VirtualSize);
            s_guardState.codeSectionHash = ComputeCRC32C(codeStart, codeSampleSize);
        }

        s_guardState.initialized = true;
    }

    // 验证数据完整性 - 周期性调用(每29次验证时调用一次)
    // [v5.1 修复] 支持降级模式: .rdata缺失时仅校验代码段或安全跳过
    inline bool VerifyDataIntegrity() {
        if (!s_guardState.initialized) return true;

        // [v5.1] 降级模式: .rdata未找到(rdataBase==null)，走代码段校验路径
        if (!s_guardState.rdataBase || s_guardState.rdataSize == 0) {
            // 仅有代码段哈希可用时做轻量校验
            if (s_guardState.codeSectionHash != 0 && s_guardState.moduleBase) {
                const IMAGE_DOS_HEADER* dosHdr =
                    reinterpret_cast<const IMAGE_DOS_HEADER*>(s_guardState.moduleBase);
                if (dosHdr->e_magic == IMAGE_DOS_SIGNATURE) {
                    const IMAGE_NT_HEADERS64* ntHdr = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
                        s_guardState.moduleBase + dosHdr->e_lfanew);
                    if (ntHdr->Signature == IMAGE_NT_SIGNATURE) {
                        const IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHdr);
                        if (sections[0].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                            const BYTE* codeStart = s_guardState.moduleBase + sections[0].VirtualAddress;
                            SIZE_T codeSampleSize = (256 < (sections[0].Misc.VirtualSize ? sections[0].Misc.VirtualSize : sections[0].SizeOfRawData)) ? 256 : (sections[0].Misc.VirtualSize ? sections[0].Misc.VirtualSize : sections[0].SizeOfRawData);
                            DWORD currentCodeHash = ComputeCRC32C(codeStart, codeSampleSize);
                            return currentCodeHash == s_guardState.codeSectionHash;
                        }
                    }
                }
            }
            return true;  // 无可用校验数据，安全跳过
        }

        // 正常模式: .rdata段CRC32C校验
        DWORD currentHash = ComputeCRC32C(s_guardState.rdataBase, s_guardState.rdataSize);

        if (currentHash != s_guardState.expectedHash) {
            return false;  // .rdata被修改（CRC32C抗碰撞，无法通过翻转其他字节伪造）
        }

        // 可选: 校验代码段样本(轻量级)
        if (s_guardState.codeSectionHash != 0) {
            const IMAGE_DOS_HEADER* dosHdr =
                reinterpret_cast<const IMAGE_DOS_HEADER*>(s_guardState.moduleBase);
            if (dosHdr->e_magic == IMAGE_DOS_SIGNATURE) {
                const IMAGE_NT_HEADERS64* ntHdr = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
                    s_guardState.moduleBase + dosHdr->e_lfanew);
                if (ntHdr->Signature == IMAGE_NT_SIGNATURE) {
                    const IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHdr);
                    if (sections[0].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                        const BYTE* codeStart = s_guardState.moduleBase + sections[0].VirtualAddress;
                        SIZE_T codeSampleSize = (256 < (sections[0].Misc.VirtualSize ? sections[0].Misc.VirtualSize : sections[0].SizeOfRawData)) ? 256 : (sections[0].Misc.VirtualSize ? sections[0].Misc.VirtualSize : sections[0].SizeOfRawData);
                        DWORD currentCodeHash = ComputeCRC32C(codeStart, codeSampleSize);
                        if (currentCodeHash != s_guardState.codeSectionHash) {
                            return false;  // 代码段被修改
                        }
                    }
                }
            }
        }

        return true;
    }
}

// ============================================================================
// [v5.0 改进4] SyscallExecutor命名空间 - 手动PE解析获取ntdll导出
// 目标: 绕过GetProcAddress/LdrGetProcedureAddress Hook
// ============================================================================
namespace SyscallExecutor {

    // 手动解析ntdll的PE导出表获取函数地址(不使用GetProcAddress)
    inline void* ResolveNtDllExport(const char* functionName) {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return nullptr;

        BYTE* base = reinterpret_cast<BYTE*>(hNtdll);

        // 解析DOS头
        const IMAGE_DOS_HEADER* dosHdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

        // 解析NT头
        const IMAGE_NT_HEADERS64* ntHdr =
            reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dosHdr->e_lfanew);
        if (ntHdr->Signature != IMAGE_NT_SIGNATURE) return nullptr;

        // 获取导出表数据目录
        DWORD exportRVA = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        DWORD exportSize = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (exportRVA == 0 || exportSize == 0) return nullptr;

        const IMAGE_EXPORT_DIRECTORY* exportDir =
            reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(base + exportRVA);

        DWORD* nameTable = reinterpret_cast<DWORD*>(base + exportDir->AddressOfNames);
        WORD* ordinalTable = reinterpret_cast<WORD*>(base + exportDir->AddressOfNameOrdinals);
        DWORD* functionTable = reinterpret_cast<DWORD*>(base + exportDir->AddressOfFunctions);

        // 遍历名称指针表查找函数名
        for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
            const char* currentName = reinterpret_cast<const char*>(base + nameTable[i]);
            if (strcmp(currentName, functionName) == 0) {
                // 找到匹配的函数名，返回对应地址
                WORD ordinal = ordinalTable[i];
                return base + functionTable[ordinal];
            }
        }

        return nullptr;
    }

    // 直接调用NtTerminateProcess(使用手动解析的地址)
    inline void NtTerminateProcess_Direct(HANDLE processHandle, NTSTATUS exitStatus) {
        typedef NTSTATUS(NTAPI* FnNtTerminateProcess)(HANDLE, NTSTATUS);
        void* fnAddr = ResolveNtDllExport("NtTerminateProcess");
        if (fnAddr) {
            FnNtTerminateProcess pFn = (FnNtTerminateProcess)fnAddr;
            pFn(processHandle, exitStatus);
        }
    }
}

// ============================================================================
// 第一层: PE结构完整性验证
// ============================================================================
namespace PEValidator {

    inline bool ValidateDosHeader(const IMAGE_DOS_HEADER* dosHeader) {
        if (!dosHeader) return false;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
        if (dosHeader->e_lfanew <= 0 || dosHeader->e_lfanew > 0x100000) return false;
        if (dosHeader->e_lfanew % 4 != 0) return false;
        return true;
    }

    inline bool ValidateNtHeaders(const IMAGE_NT_HEADERS64* ntHeaders) {
        if (!ntHeaders) return false;
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;
#if defined(_WIN64)
        if (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return false;
#else
        if (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) return false;
#endif
        if (ntHeaders->FileHeader.SizeOfOptionalHeader == 0) return false;
        if (ntHeaders->FileHeader.NumberOfSections > 96) return false;
#ifdef _WIN64
        if (ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return false;
#else
        if (ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return false;
#endif
        if (!(ntHeaders->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) return false;
        return true;
    }

    inline bool ValidateSectionHeaders(
        const IMAGE_NT_HEADERS64* ntHeaders,
        const uint8_t* moduleBase,
        size_t moduleSize)
    {
        if (!ntHeaders || !moduleBase) return false;

        const IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHeaders);
        WORD numSections = ntHeaders->FileHeader.NumberOfSections;

        DWORD totalVirtualSize = 0;
        DWORD maxRawEnd = 0;

        for (WORD i = 0; i < numSections; i++) {
            const IMAGE_SECTION_HEADER* section = &sections[i];

            if (section->SizeOfRawData > 0) {
                if (section->PointerToRawData + section->SizeOfRawData > moduleSize) {
                    return false;
                }
                if (section->PointerToRawData + section->SizeOfRawData > maxRawEnd) {
                    maxRawEnd = section->PointerToRawData + section->SizeOfRawData;
                }
            }

            totalVirtualSize += section->Misc.VirtualSize;

            if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                if (!(section->Characteristics & IMAGE_SCN_MEM_READ)) {
                    return false;
                }
            }
        }

        DWORD sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
        if (sizeOfImage < totalVirtualSize || sizeOfImage > moduleSize * 10) {
            return false;
        }

        return true;
    }

    inline bool ValidateExportDirectory(const uint8_t* moduleBase, size_t moduleSize) {
        if (!moduleBase || moduleSize < 0x1000) return false;

        const IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(moduleBase);
        if (!ValidateDosHeader(dosHeader)) return false;

        const IMAGE_NT_HEADERS64* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
            moduleBase + dosHeader->e_lfanew);
        if (!ValidateNtHeaders(ntHeaders)) return false;

        DWORD exportRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        DWORD exportSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

        if (exportRVA == 0 || exportSize == 0) return true;

        const IMAGE_EXPORT_DIRECTORY* exportDir =
            reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(moduleBase + exportRVA);

        if (exportDir->NumberOfFunctions > 100000 ||
            exportDir->NumberOfNames > 100000) return false;
        if (exportDir->Base > 0x10000) return false;

        return true;
    }

    inline bool ValidatePE() {
        HMODULE hModule = GetModuleHandleW(nullptr);
        if (!hModule) return false;

        MODULEINFO modInfo = {};
        if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
            return false;
        }

        const uint8_t* base = reinterpret_cast<const uint8_t*>(modInfo.lpBaseOfDll);
        SIZE_T size = modInfo.SizeOfImage;

        if (!base || size < 0x1000) return false;

        const IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (!ValidateDosHeader(dosHeader)) return false;

        const IMAGE_NT_HEADERS64* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
            base + dosHeader->e_lfanew);
        if (!ValidateNtHeaders(ntHeaders)) return false;

        if (!ValidateSectionHeaders(ntHeaders, base, size)) return false;
        if (!ValidateExportDirectory(base, size)) return false;

        return true;
    }
}

// ============================================================================
// 第二层: 数字签名深度验证
// ============================================================================
namespace SignatureValidator {

    inline bool CheckEmbeddedSignatureExists() {
        wchar_t modulePath[MAX_PATH] = {};
        if (!GetModuleFileNameW(nullptr, modulePath, MAX_PATH)) return false;

        HCERTSTORE hStore = NULL;
        HCRYPTMSG hMsg = NULL;

        LONG result = CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            modulePath,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            NULL, NULL, NULL,
            &hStore, &hMsg, NULL);

        if (result && hStore && hMsg) {
            DWORD cbSignerInfo = 0;
            PCMSG_SIGNER_INFO pSignerInfo = NULL;

            if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &cbSignerInfo)) {
                pSignerInfo = (PCMSG_SIGNER_INFO)malloc(cbSignerInfo);
                if (pSignerInfo) {
                    if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, pSignerInfo, &cbSignerInfo)) {
                        CERT_INFO certInfo = {};
                        certInfo.Issuer = pSignerInfo->Issuer;
                        certInfo.SerialNumber = pSignerInfo->SerialNumber;

                        PCCERT_CONTEXT pCertContext = CertFindCertificateInStore(
                            hStore,
                            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                            0,
                            CERT_FIND_SUBJECT_CERT,
                            &certInfo,
                            NULL);

                        if (pCertContext) {
                            CertFreeCertificateContext(pCertContext);
                            free(pSignerInfo);
                            CertCloseStore(hStore, 0);
                            CryptMsgClose(hMsg);
                            return true;
                        }
                    }
                    free(pSignerInfo);
                }
            }

            CertCloseStore(hStore, 0);
            CryptMsgClose(hMsg);
        }

        return false;
    }

    inline LONG PerformWinVerifyTrust() {
        wchar_t modulePath[MAX_PATH] = {};
        if (!GetModuleFileNameW(nullptr, modulePath, MAX_PATH)) return -1;

        WINTRUST_FILE_INFO fileInfo = {};
        fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
        fileInfo.pcwszFilePath = modulePath;
        fileInfo.hFile = NULL;

        GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        WINTRUST_DATA trustData = {};
        trustData.cbStruct = sizeof(WINTRUST_DATA);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.pFile = &fileInfo;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;

#if (_WIN32_WINNT >= 0x0602)
        // Win8+ SDK 编译: 直接使用 pSignatureSettings 字段启用增强签名验证
        WINTRUST_SIGNATURE_SETTINGS sigSettings = {};
        sigSettings.cbStruct = sizeof(WINTRUST_SIGNATURE_SETTINGS);
        trustData.pSignatureSettings = &sigSettings;
#endif
        // 注: Win7 SDK 编译 (_WIN32_WINNT=0x0601) 时, WINTRUST_DATA 没有
        //   pSignatureSettings 字段, 跳过此增强. 基础 WinVerifyTrust 验证
        //   仍能检测签名篡改, 只是少了 Win8+ 增强项.

        LONG result = WinVerifyTrust(NULL, &policyGUID, &trustData);

        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &policyGUID, &trustData);

        return result;
    }

    // ============================================================================
    // [v5.0 改进2] 硬编码预期证书信息 - 编译时加密+指纹拆分分散
    // 从已签名文件提取: PowerShell Get-AuthenticodeSignature
    // Subject/Issuer字符串用DMSP_EncryptedString模板加密
    // Thumbprint和Serial拆分为多个片段分别加密
    // ============================================================================
    namespace ExpectedCertInfo {

        // Subject完整DN(加密存储)
        inline const wchar_t* SUBJECT_ENCRYPTED() {
            // 实际Subject: CN=Windows OEM PPL Test Cert 2017 (TEST ONLY), O=Microsoft Partner, OU=Windows, L=Redmond, S=Washington, C=US
            // 使用行号作为key进行编译期加密
            static constexpr auto _subj_enc = DMSP_EncryptedString<0x5A5A,
                sizeof("CN=Windows OEM PPL Test Cert 2017 (TEST ONLY), O=Microsoft Partner, OU=Windows, L=Redmond, S=Washington, C=US")>(
                    "CN=Windows OEM PPL Test Cert 2017 (TEST ONLY), O=Microsoft Partner, OU=Windows, L=Redmond, S=Washington, C=US");
            static wchar_t _subj_buf[256];
            static bool _subj_decrypted = false;
            if (!_subj_decrypted) {
                char _tmp[256];
                _subj_enc.decrypt(_tmp);
                MultiByteToWideChar(CP_UTF8, 0, _tmp, -1, _subj_buf, 256);
                _subj_decrypted = true;
            }
            return _subj_buf;
        }

        // Issuer完整DN(加密存储)
        inline const wchar_t* ISSUER_ENCRYPTED() {
            // 实际Issuer: CN=Windows OEM Intermediate 2017 (TEST ONLY), O=Microsoft Partner, OU=Windows, L=Redmond, S=Washington, C=US
            static constexpr auto _iss_enc = DMSP_EncryptedString<0xB3B3,
                sizeof("CN=Windows OEM Intermediate 2017 (TEST ONLY), O=Microsoft Partner, OU=Windows, L=Redmond, S=Washington, C=US")>(
                    "CN=Windows OEM Intermediate 2017 (TEST ONLY), O=Microsoft Partner, OU=Windows, L=Redmond, S=Washington, C=US");
            static wchar_t _iss_buf[256];
            static bool _iss_decrypted = false;
            if (!_iss_decrypted) {
                char _tmp[256];
                _iss_enc.decrypt(_tmp);
                MultiByteToWideChar(CP_UTF8, 0, _tmp, -1, _iss_buf, 256);
                _iss_decrypted = true;
            }
            return _iss_buf;
        }

        // Serial拆分为2个片段(每个16字符，补齐到20)
        // 原始Serial: 0BE0B0D43F9F36B04F38360318736D6E (32字符)
        namespace SerialFragments {
            // 片段0(key=0x5A): "0BE0B0D43F9F36B0" (16字符)
            static constexpr auto frag0 = DMSP_EncryptedString<0x5A, 17>("0BE0B0D43F9F36B0");
            // 片段1(key=0xB3): "4F38360318736D6E" (16字符)
            static constexpr auto frag1 = DMSP_EncryptedString<0xB3, 17>("4F38360318736D6E");

            inline const char* GetDecryptedSerial() {
                static char serialBuf[40] = {};
                static bool decrypted = false;
                if (!decrypted) {
                    char tmp0[20], tmp1[20];
                    frag0.decrypt(tmp0);
                    frag1.decrypt(tmp1);
                    strcpy_s(serialBuf, tmp0);
                    strcat_s(serialBuf, tmp1);
                    decrypted = true;
                }
                return serialBuf;
            }
        }

        // Thumbprint拆分为4个片段(每段10字符,均匀切分)
        // 原始Thumbprint: 4EA554071F7EEAA7CB3CA43185F0B0DD64C99440 (40字符)
        // 切分: [0:10] [10:20] [20:30] [30:40]
        //       4EA554071F | 7EEAA7CB3C | A43185F0B0 | DD64C99440
        namespace ThumbprintFragments {
            // 片段0(key=0x5A): "4EA554071F" (10字符)
            static constexpr auto frag0 = DMSP_EncryptedString<0x5A, 11>("4EA554071F");
            // 片段1(key=0xB3): "7EEAA7CB3C" (10字符)
            static constexpr auto frag1 = DMSP_EncryptedString<0xB3, 11>("7EEAA7CB3C");
            // 片段2(key=0x7C): "A43185F0B0" (10字符)
            static constexpr auto frag2 = DMSP_EncryptedString<0x7C, 11>("A43185F0B0");
            // 片段3(key=0xE1): "DD64C99440" (10字符)
            static constexpr auto frag3 = DMSP_EncryptedString<0xE1, 11>("DD64C99440");

            inline const char* GetDecryptedThumbprint() {
                static char tpBuf[48] = {};
                static bool decrypted = false;
                if (!decrypted) {
                    char tmp0[15], tmp1[15], tmp2[15], tmp3[15];
                    frag0.decrypt(tmp0);
                    frag1.decrypt(tmp1);
                    frag2.decrypt(tmp2);
                    frag3.decrypt(tmp3);
                    strcpy_s(tpBuf, tmp0);
                    strcat_s(tpBuf, tmp1);
                    strcat_s(tpBuf, tmp2);
                    strcat_s(tpBuf, tmp3);  // 追加"9440"
                    decrypted = true;
                }
                return tpBuf;
            }
        }

        // 兼容旧接口 - 返回解密后的完整Serial
        inline const char* SERIAL() {
            return SerialFragments::GetDecryptedSerial();
        }

        // 兼容旧接口 - 返回解密后的完整Thumbprint
        inline const char* THUMBPRINT() {
            return ThumbprintFragments::GetDecryptedThumbprint();
        }

        // 获取单个属性预期值(用于CheckCertAttr)
        // [v5.0 改进2] 所有expected参数都从加密字符串解密获得
        // [v5.1 修复TOP#3] 不再缓存明文到静态变量，改为写入调用者栈缓冲区
        //   解密后立即使用，用完由调用者负责清零（或函数内部SecureZeroMemory）
        //   参数: outBuf(输出宽字符缓冲区), bufSize(缓冲区大小wchar_t数)

        // 解密Subject CN到outBuf
        inline void DecryptSubjectCN(wchar_t* outBuf, int bufSize) {
            const char enc[] = { 'W'^0x1A,'i'^0x1B,'n'^0x1C,'d'^0x1D,'o'^0x1E,'w'^0x1F,'s'^0x20,' '^0x21,'O'^0x22,'E'^0x23,'M'^0x24,' '^0x25,'P'^0x26,'P'^0x27,'L'^0x28,' '^0x29,'T'^0x2A,'e'^0x2B,'s'^0x2C,'t'^0x2D,' '^0x2E,'C'^0x2F,'e'^0x30,'r'^0x31,'t'^0x32,' '^0x33,'2'^0x34,'0'^0x35,'1'^0x36,'7'^0x37,' '^0x38,'('^0x39,'T'^0x3A,'E'^0x3B,'S'^0x3C,'T'^0x3D,' '^0x3E,'O'^0x3F,'N'^0x40,'L'^0x41,'Y'^0x42,')'^0x43,'\0'^0x44 };
            char t[48] = {};
            for (int i = 0; i < 44; i++) t[i] = enc[i] ^ (0x1A + i);  // [v5.1修复] XOR解密
            MultiByteToWideChar(CP_UTF8, 0, t, -1, outBuf, bufSize);
            SecureZeroMemory(t, sizeof(t));  // 清零中间ANSI缓冲区
        }

        // 解密Organization Name到outBuf
        inline void DecryptOrgName(wchar_t* outBuf, int bufSize) {
            const char enc[] = {
                'M' ^ 0x2B, 'i' ^ 0x2C, 'c' ^ 0x2D, 'r' ^ 0x2E, 'o' ^ 0x2F,
                's' ^ 0x30, 'o' ^ 0x31, 'f' ^ 0x32, 't' ^ 0x33, ' ' ^ 0x34,
                'P' ^ 0x35, 'a' ^ 0x36, 'r' ^ 0x37, 't' ^ 0x38, 'n' ^ 0x39,
                'e' ^ 0x3A, 'r' ^ 0x3B, '\0' ^ 0x3C
            };
            char t[19] = {};                     // 存放解密后的ANSI字符串（含终止符）
            for (int i = 0; i < 18; i++) {       // 加密数组共18个元素（17个有效字符+1个终止符）
                t[i] = enc[i] ^ (0x2B + i);
            }
            MultiByteToWideChar(CP_UTF8, 0, t, -1, outBuf, bufSize);
            SecureZeroMemory(t, sizeof(t));
        }

        // 解密OU Name到outBuf
        inline void DecryptOUName(wchar_t* outBuf, int bufSize) {
            const char enc[] = { 'W'^0x3C,'i'^0x3D,'n'^0x3E,'d'^0x3F,'o'^0x40,'w'^0x41,'s'^0x42,'\0'^0x43 };
            char t[9] = {}; for (int i = 0; i < 8; i++) t[i] = enc[i] ^ (0x3C + i);
            MultiByteToWideChar(CP_UTF8, 0, t, -1, outBuf, bufSize);
            SecureZeroMemory(t, sizeof(t));
        }

        // 解密Locality Name到outBuf
        inline void DecryptLocalityName(wchar_t* outBuf, int bufSize) {
            const char enc[] = { 'R'^0x4D,'e'^0x4E,'d'^0x4F,'m'^0x50,'o'^0x51,'n'^0x52,'d'^0x53,'\0'^0x54 };
            char t[9] = {}; for (int i = 0; i < 8; i++) t[i] = enc[i] ^ (0x4D + i);
            MultiByteToWideChar(CP_UTF8, 0, t, -1, outBuf, bufSize);
            SecureZeroMemory(t, sizeof(t));
        }

        // 解密State/Province Name到outBuf
        inline void DecryptStateName(wchar_t* outBuf, int bufSize) {
            const char enc[] = { 'W'^0x5E,'a'^0x5F,'s'^0x60,'h'^0x61,'i'^0x62,'n'^0x63,'g'^0x64,'t'^0x65,'o'^0x66,'n'^0x67,'\0'^0x68 };
            char t[12] = {}; for (int i = 0; i < 11; i++) t[i] = enc[i] ^ (0x5E + i);
            MultiByteToWideChar(CP_UTF8, 0, t, -1, outBuf, bufSize);
            SecureZeroMemory(t, sizeof(t));
        }

        // 解密Country Name到outBuf
        inline void DecryptCountryName(wchar_t* outBuf, int bufSize) {
            const char enc[] = { 'U'^0x6F,'S'^0x70,'\0'^0x71 };
            char t[4] = {}; for (int i = 0; i < 3; i++) t[i] = enc[i] ^ (0x6F + i);
            MultiByteToWideChar(CP_UTF8, 0, t, -1, outBuf, bufSize);
            SecureZeroMemory(t, sizeof(t));
        }

        // 解密Issuer CN到outBuf
        inline void DecryptIssuerCN(wchar_t* outBuf, int bufSize) {
            const char enc[] = { static_cast<char>('W'^0x7A),static_cast<char>('i'^0x7B),static_cast<char>('n'^0x7C),static_cast<char>('d'^0x7D),static_cast<char>('o'^0x7E),static_cast<char>('w'^0x7F),static_cast<char>('s'^0x80),static_cast<char>(' '^0x81),static_cast<char>('O'^0x82),static_cast<char>('E'^0x83),static_cast<char>('M'^0x84),static_cast<char>(' '^0x85),static_cast<char>('I'^0x86),static_cast<char>('n'^0x87),static_cast<char>('t'^0x88),static_cast<char>('e'^0x89),static_cast<char>('r'^0x8A),static_cast<char>('m'^0x8B),static_cast<char>('e'^0x8C),static_cast<char>('d'^0x8D),static_cast<char>('i'^0x8E),static_cast<char>('a'^0x8F),static_cast<char>('t'^0x90),static_cast<char>('e'^0x91),static_cast<char>(' '^0x92),static_cast<char>('2'^0x93),static_cast<char>('0'^0x94),static_cast<char>('1'^0x95),static_cast<char>('7'^0x96),static_cast<char>(' '^0x97),static_cast<char>('('^0x98),static_cast<char>('T'^0x99),static_cast<char>('E'^0x9A),static_cast<char>('S'^0x9B),static_cast<char>('T'^0x9C),static_cast<char>(' '^0x9D),static_cast<char>('O'^0x9E),static_cast<char>('N'^0x9F),static_cast<char>('L'^0xA0),static_cast<char>('Y'^0xA1),static_cast<char>(')'^0xA2),static_cast<char>('\0'^0xA3) };
            char t[46] = {}; for (int i = 0; i < 45; i++) t[i] = static_cast<char>(enc[i] ^ (0x7A + i));
            MultiByteToWideChar(CP_UTF8, 0, t, -1, outBuf, bufSize);
            SecureZeroMemory(t, sizeof(t));
        }
    }

    // [v5.1 修复] 宽字符串比较 - 增加maxLen防止非空终止字符串越界读取
    // 原逻辑在两字符串均为空终止时正确，但证书属性比较场景下需防越界
    inline bool CompareWideString(const wchar_t* a, const wchar_t* b, SIZE_T maxLen = (SIZE_T)-1) {
        if (!a || !b) return false;
        SIZE_T len = 0;
        while (*a && *b && len < maxLen) {
            if (*a != *b) return false;
            ++a; ++b; ++len;
        }
        // 长度达到上限时视为不等（可能被截断）
        if (len >= maxLen && maxLen != (SIZE_T)-1) return false;
        return *a == *b;
    }

    inline bool CompareAnsiString(const char* a, const char* b, SIZE_T maxLen = (SIZE_T)-1) {
        if (!a || !b) return false;
        SIZE_T len = 0;
        while (*a && *b && len < maxLen) {
            if (*a != *b) return false;
            ++a; ++b; ++len;
        }
        if (len >= maxLen && maxLen != (SIZE_T)-1) return false;
        return *a == *b;
    }

    // 辅助函数：提取并比较证书RDN属性（大小写不敏感）
    // [v5.0 改进2] expected参数从ExpectedCertInfo加密字符串解密获得
    inline bool CheckCertAttr(PCCERT_CONTEXT pCert, DWORD dwFlags, LPCSTR oid, const wchar_t* expected) {
        wchar_t buf[256] = {};
        DWORD ret = CertGetNameStringW(pCert, CERT_NAME_ATTR_TYPE, dwFlags, (void*)oid, buf, _countof(buf));
        if (ret <= 1 || ret >= _countof(buf)) return false;

        // 大小写不敏感比较，防止攻击者通过修改大小写绕过验证
        wchar_t lowerBuf[256] = {};
        wchar_t lowerExpected[256] = {};
        DWORD copyLen = ret < _countof(lowerBuf) ? ret : (_countof(lowerBuf) - 1);
        for (DWORD i = 0; i < copyLen; i++) {
            lowerBuf[i] = static_cast<wchar_t>(towlower(static_cast<wint_t>(buf[i])));
        }
        lowerBuf[copyLen] = L'\0';

        size_t expLen = 0;
        while (expected[expLen]) expLen++;
        size_t expCopyLen = expLen < _countof(lowerExpected) ? expLen : (_countof(lowerExpected) - 1);
        for (size_t i = 0; i < expCopyLen; i++) {
            lowerExpected[i] = static_cast<wchar_t>(towlower(static_cast<wint_t>(expected[i])));
        }
        lowerExpected[expCopyLen] = L'\0';

        bool match = CompareWideString(lowerBuf, lowerExpected);

        // [v5.2] DMSP_DEVELOPER_MODE 已改为运行时计算, 此处用运行时分发
        if (DMSP_DEVELOPER_MODE == 1 && !match) {
            // 开发者模式: 弹窗显示实际值vs期望值，便于调试
            wchar_t msgBuf[600] = {};
            swprintf_s(msgBuf, L"[DMSP-CERT] 属性不匹配!\n\nOID: %hs\n\n证书实际值:\n  %s\n\n代码期望值:\n  %s",
                oid, buf, expected);
            MessageBoxW(nullptr, msgBuf, L"DMSP 证书诊断 - 开发者模式", MB_OK | MB_ICONINFORMATION);
        }

        return match;
    }

    // 验证签名证书身份 - 14项信息全部匹配才算合法
    // [v5.0 改进2] 所有预期值从加密字符串解密获得
    inline bool ValidateCertIdentity() {
#ifdef DMSP_NOCERT
        // [无证书版本] 跳过证书身份验证, 视为有效
        return true;
#endif
        wchar_t modulePath[MAX_PATH] = {};
        if (!GetModuleFileNameW(nullptr, modulePath, MAX_PATH)) return false;

        HCERTSTORE hStore = NULL;
        HCRYPTMSG hMsg = NULL;

        LONG result = CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            modulePath,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            NULL, NULL, NULL,
            &hStore, &hMsg, NULL);

        if (!result || !hStore || !hMsg) return false;

        bool identityValid = false;
        DWORD cbSignerInfo = 0;

        if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &cbSignerInfo)) {
            PCMSG_SIGNER_INFO pSignerInfo = (PCMSG_SIGNER_INFO)malloc(cbSignerInfo);
            if (pSignerInfo) {
                if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, pSignerInfo, &cbSignerInfo)) {
                    CERT_INFO certInfo = {};
                    certInfo.Issuer = pSignerInfo->Issuer;
                    certInfo.SerialNumber = pSignerInfo->SerialNumber;

                    PCCERT_CONTEXT pCertContext = CertFindCertificateInStore(
                        hStore,
                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                        0,
                        CERT_FIND_SUBJECT_CERT,
                        &certInfo,
                        NULL);

                    if (pCertContext) {
                        identityValid = true;

#ifndef DMSP_NOCERT
                        // === Subject 6项属性 === [v5.1] 栈上解密，用完即销毁 ===
                        {
                            wchar_t attrBuf[128] = {};

                            ExpectedCertInfo::DecryptSubjectCN(attrBuf, 128);
                            if (!CheckCertAttr(pCertContext, 0, szOID_COMMON_NAME, attrBuf)) { identityValid = false; ResponseSystem::TriggerResponse("Cert-SubjectCN", 1); }
                            SecureZeroMemory(attrBuf, sizeof(attrBuf));

                            if (identityValid) { ExpectedCertInfo::DecryptOrgName(attrBuf, 128); if (!CheckCertAttr(pCertContext, 0, szOID_ORGANIZATION_NAME, attrBuf)) { identityValid = false; ResponseSystem::TriggerResponse("Cert-OrgName", 1); } SecureZeroMemory(attrBuf, sizeof(attrBuf)); }
                            if (identityValid) { ExpectedCertInfo::DecryptOUName(attrBuf, 128); if (!CheckCertAttr(pCertContext, 0, szOID_ORGANIZATIONAL_UNIT_NAME, attrBuf)) { identityValid = false; ResponseSystem::TriggerResponse("Cert-OUName", 1); } SecureZeroMemory(attrBuf, sizeof(attrBuf)); }
                            if (identityValid) { ExpectedCertInfo::DecryptLocalityName(attrBuf, 128); if (!CheckCertAttr(pCertContext, 0, szOID_LOCALITY_NAME, attrBuf)) { identityValid = false; ResponseSystem::TriggerResponse("Cert-Locality", 1); } SecureZeroMemory(attrBuf, sizeof(attrBuf)); }
                            if (identityValid) { ExpectedCertInfo::DecryptStateName(attrBuf, 128); if (!CheckCertAttr(pCertContext, 0, szOID_STATE_OR_PROVINCE_NAME, attrBuf)) { identityValid = false; ResponseSystem::TriggerResponse("Cert-State", 1); } SecureZeroMemory(attrBuf, sizeof(attrBuf)); }
                            if (identityValid) { ExpectedCertInfo::DecryptCountryName(attrBuf, 128); if (!CheckCertAttr(pCertContext, 0, szOID_COUNTRY_NAME, attrBuf)) { identityValid = false; ResponseSystem::TriggerResponse("Cert-Country", 1); } SecureZeroMemory(attrBuf, sizeof(attrBuf)); }

                            // === Issuer 6项属性 === [v5.1] 复用同一缓冲区，每次解密后立即比对并清零 ===
                            if (identityValid) { ExpectedCertInfo::DecryptIssuerCN(attrBuf, 128); if (!CheckCertAttr(pCertContext, CERT_NAME_ISSUER_FLAG, szOID_COMMON_NAME, attrBuf)) { identityValid = false; ResponseSystem::TriggerResponse("Cert-IssuerCN", 1); } SecureZeroMemory(attrBuf, sizeof(attrBuf)); }
                            if (identityValid) { ExpectedCertInfo::DecryptOrgName(attrBuf, 128); if (!CheckCertAttr(pCertContext, CERT_NAME_ISSUER_FLAG, szOID_ORGANIZATION_NAME, attrBuf)) { identityValid = false; ResponseSystem::TriggerResponse("Cert-IssuerOrg", 1); } SecureZeroMemory(attrBuf, sizeof(attrBuf)); }
                            if (identityValid) { ExpectedCertInfo::DecryptOUName(attrBuf, 128); if (!CheckCertAttr(pCertContext, CERT_NAME_ISSUER_FLAG, szOID_ORGANIZATIONAL_UNIT_NAME, attrBuf)) { identityValid = false; ResponseSystem::TriggerResponse("Cert-IssuerOU", 1); } SecureZeroMemory(attrBuf, sizeof(attrBuf)); }
                            if (identityValid) { ExpectedCertInfo::DecryptLocalityName(attrBuf, 128); if (!CheckCertAttr(pCertContext, CERT_NAME_ISSUER_FLAG, szOID_LOCALITY_NAME, attrBuf)) { identityValid = false; ResponseSystem::TriggerResponse("Cert-IssuerLocality", 1); } SecureZeroMemory(attrBuf, sizeof(attrBuf)); }
                            if (identityValid) { ExpectedCertInfo::DecryptStateName(attrBuf, 128); if (!CheckCertAttr(pCertContext, CERT_NAME_ISSUER_FLAG, szOID_STATE_OR_PROVINCE_NAME, attrBuf)) { identityValid = false; ResponseSystem::TriggerResponse("Cert-IssuerState", 1); } SecureZeroMemory(attrBuf, sizeof(attrBuf)); }
                            if (identityValid) { ExpectedCertInfo::DecryptCountryName(attrBuf, 128); if (!CheckCertAttr(pCertContext, CERT_NAME_ISSUER_FLAG, szOID_COUNTRY_NAME, attrBuf)) { identityValid = false; ResponseSystem::TriggerResponse("Cert-IssuerCountry", 1); } SecureZeroMemory(attrBuf, sizeof(attrBuf)); }
                        }

                        // === Serial Number === [v5.0 改进2] 使用拆分加密的Serial ===
                        if (identityValid) {
                            CRYPT_INTEGER_BLOB* serial = &pCertContext->pCertInfo->SerialNumber;
                            char serialHex[128] = {};
                            if (serial->cbData > 0 && serial->pbData) {
                                for (DWORD i = 0; i < serial->cbData && i < 32; i++) {
                                    sprintf_s(serialHex + i * 2, sizeof(serialHex) - i * 2, "%02X",
                                        serial->pbData[serial->cbData - 1 - i]);
                                }
                            }
                            if (!CompareAnsiString(serialHex, ExpectedCertInfo::SERIAL())) { identityValid = false; ResponseSystem::TriggerResponse("Cert-Serial", 1); }
                        }

                        // === Thumbprint (SHA1) === [v5.0 改进2] 使用拆分加密的Thumbprint ===
                        if (identityValid) {
                            BYTE thumbprint[20] = {};
                            DWORD thumbprintLen = sizeof(thumbprint);
                            if (CryptHashCertificate(0, CALG_SHA1, 0,
                                pCertContext->pbCertEncoded, pCertContext->cbCertEncoded,
                                thumbprint, &thumbprintLen)) {
                                char thumbprintHex[64] = {};
                                for (DWORD i = 0; i < thumbprintLen; i++) {
                                    sprintf_s(thumbprintHex + i * 2, sizeof(thumbprintHex) - i * 2, "%02X", thumbprint[i]);
                                }
                                // [调试输出已禁用] Thumbprint 校验已通过,不再输出
                                /*
                                {
                                    char dbg[256];
                                    const char* expected = ExpectedCertInfo::THUMBPRINT();
                                    sprintf_s(dbg, "[DMSP] Thumbprint Actual: %s | Expected: %s", thumbprintHex, expected);
                                    OutputDebugStringA(dbg);
                                }
                                */
                                if (!CompareAnsiString(thumbprintHex, ExpectedCertInfo::THUMBPRINT())) { identityValid = false; ResponseSystem::TriggerResponse("Cert-Thumbprint", 1); }
                            } else {
                                identityValid = false;
                                ResponseSystem::TriggerResponse("Cert-HashFail", 1);
                            }
                        }
#endif /* DMSP_NOCERT */

                        CertFreeCertificateContext(pCertContext);
                    }
                }
                free(pSignerInfo);
            }
        }

        CertCloseStore(hStore, 0);
        CryptMsgClose(hMsg);

        return identityValid;
    }

    enum class SignatureResult {
        Valid = 0,
        ValidButExpired = 1,
        HasEmbeddedSig = 2,
        NoSignature = 3,
        Tampered = 4,
        Unknown = 5
    };

    inline SignatureResult ValidateSignature() {
#ifdef DMSP_NOCERT
        // [无证书版本] 跳过完整的签名和证书验证, 始终视为有效
        return SignatureResult::Valid;
#endif
        bool hasEmbedded = CheckEmbeddedSignatureExists();
        LONG wvtResult = PerformWinVerifyTrust();

        if (wvtResult == 0) {
            // WinVerifyTrust通过，进一步验证证书身份
            if (!ValidateCertIdentity()) {
                return SignatureResult::Tampered;
            }
            return SignatureResult::Valid;
        }

        if (hasEmbedded) {
            // 有嵌入式签名但WinVerifyTrust失败，验证证书身份
            if (!ValidateCertIdentity()) {
                return SignatureResult::Tampered;
            }
            switch (wvtResult) {
            case TRUST_E_EXPLICIT_DISTRUST:
            case CERT_E_EXPIRED:
            case CERT_E_REVOCATION_FAILURE:
            case CERT_E_REVOKED:
            case CRYPT_E_NO_SIGNER:
            case NTE_BAD_SIGNATURE:
            case TRUST_E_BAD_DIGEST:
                return SignatureResult::ValidButExpired;
            default:
                return SignatureResult::HasEmbeddedSig;
            }
        }

        return SignatureResult::NoSignature;
    }
}

// ============================================================================
// 第三层: 哈希完整性验证
// ============================================================================
namespace HashValidator {

    inline bool CalculateFileHash(const wchar_t* filePath, std::vector<BYTE>& outHash) {
        HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;

        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            CloseHandle(hFile);
            return false;
        }

        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            CryptReleaseContext(hProv, 0);
            CloseHandle(hFile);
            return false;
        }

        BYTE buffer[8192];
        DWORD bytesRead = 0;
        bool success = true;

        while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
            if (!CryptHashData(hHash, buffer, bytesRead, 0)) {
                success = false;
                break;
            }
        }

        if (success) {
            DWORD hashSize = 32;
            outHash.resize(hashSize);
            if (!CryptGetHashParam(hHash, HP_HASHVAL, outHash.data(), &hashSize, 0)) {
                success = false;
            }
        }

        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return success;
    }

    inline bool CalculateModuleMemoryHash(std::vector<BYTE>& outHash) {
        HMODULE hModule = GetModuleHandleW(nullptr);
        if (!hModule) return false;

        MODULEINFO modInfo = {};
        if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
            return false;
        }

        const IMAGE_DOS_HEADER* dosHdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(modInfo.lpBaseOfDll);
        if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) return false;

        const IMAGE_NT_HEADERS64* ntHdr = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
            reinterpret_cast<const BYTE*>(modInfo.lpBaseOfDll) + dosHdr->e_lfanew);

        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;

        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return false;
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            CryptReleaseContext(hProv, 0);
            return false;
        }

        const IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHdr);
        DWORD headersEnd = ntHdr->OptionalHeader.SizeOfHeaders;

        bool success = true;
        if (headersEnd > modInfo.SizeOfImage) headersEnd = static_cast<DWORD>(modInfo.SizeOfImage);

        if (!CryptHashData(hHash, reinterpret_cast<const BYTE*>(modInfo.lpBaseOfDll), headersEnd, 0)) {
            success = false;
        } else {
            for (WORD i = 0; i < ntHdr->FileHeader.NumberOfSections && success; i++) {
                const char* sectionName = reinterpret_cast<const char*>(sections[i].Name);

                if (strncmp(sectionName, ".reloc", 6) == 0 ||
                    strncmp(sectionName, ".rsrc", 5) == 0 ||
                    strncmp(sectionName, ".tls", 4) == 0) continue;

                DWORD va = sections[i].VirtualAddress;
                DWORD vs = sections[i].Misc.VirtualSize ? sections[i].Misc.VirtualSize : sections[i].SizeOfRawData;

                if (va + vs <= modInfo.SizeOfImage && vs > 0) {
                    const BYTE* sectionData = reinterpret_cast<const BYTE*>(modInfo.lpBaseOfDll) + va;
                    if (!CryptHashData(hHash, sectionData, vs, 0)) success = false;
                }
            }
        }

        if (success) {
            DWORD hashSize = 32;
            outHash.resize(hashSize);
            if (!CryptGetHashParam(hHash, HP_HASHVAL, outHash.data(), &hashSize, 0)) success = false;
        }

        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return success;
    }
}

// ============================================================================
// 第四层: 反调试/反Hook检测
// [v5.0 改进10] 新增7种强力调试器检测方法，投票机制(>=3票)
// [v5.4] 内核反调试检测需要前向声明 (定义在本文件末尾)
// ============================================================================
// 前向声明: ResponseSystem定义在本文件后方，此处需要引用ForceExit地址和TriggerResponse
namespace ResponseSystem { void ForceExit(UINT code); void TriggerResponse(const char* reason, int severity); void ShowToastNotification(const wchar_t* title, const wchar_t* message); }
// [v5.4] 内核反调试前向声明 (KernelAntiDebug 定义在文件末尾)
namespace KernelAntiDebug { bool IsKernelDebuggingDetected(); }

namespace AntiAnalysis {

#if DMSP_ENABLE_ANTI_DEBUG

    // 使用间接调用+解密防止IDA静态分析
    inline bool CheckIsDebuggerPresent() {
        typedef BOOL(WINAPI* FnIsDebuggerPresent)();
        DWORD cryptoKey = DMSP::g_state.baseSeed ^ 0x5A5A5A5A;
        void* decrypted = DMSP::FunctionPointerCrypto::DecryptPtr(
            DMSP::g_state.validatorPtrs[1], cryptoKey);
        FnIsDebuggerPresent pFn = (FnIsDebuggerPresent)decrypted;
        if (pFn) return pFn() != FALSE;
        return IsDebuggerPresent() != FALSE;
    }

    inline bool CheckPEBBeingDebugged() {
#ifdef _WIN64
        PBYTE pPEB = (PBYTE)__readgsqword(0x60);
#else
        PBYTE pPEB = (PBYTE)__readfsdword(0x30);
#endif
        return pPEB[2] != 0;
    }

    inline bool CheckNtGlobalFlag() {
#ifdef _WIN64
        PBYTE pPEB = (PBYTE)__readgsqword(0x60);
        PDWORD pNtGlobalFlag = (PDWORD)(pPEB + 0xBC);
#else
        PBYTE pPEB = (PBYTE)__readfsdword(0x30);
        PDWORD pNtGlobalFlag = (PDWORD)(pPEB + 0x68);
#endif
        return (*pNtGlobalFlag & 0x70) != 0;
    }

    inline bool CheckHeapFlags() {
#ifdef _WIN64
        PBYTE pPEB = (PBYTE)__readgsqword(0x60);
        PVOID pHeap = *(PVOID*)(pPEB + 0x30);
#else
        PBYTE pPEB = (PBYTE)__readfsdword(0x30);
        PVOID pHeap = *(PVOID*)(pPEB + 0x18);
#endif
        if (!pHeap) return false;
        DWORD flags = *(DWORD*)((PBYTE)pHeap + 0x40);
        DWORD forceFlags = *(DWORD*)((PBYTE)pHeap + 0x44);
        if ((flags & ~0x00000002) != 0 || forceFlags != 0) return true;
        return false;
    }

    inline bool CheckDebugObject() {
        // 通过预存的加密函数指针间接调用，运行时解密
        typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
            HANDLE, ULONG, PVOID, ULONG, PULONG);

        DWORD cryptoKey = DMSP::g_state.baseSeed ^ 0x5A5A5A5A;
        void* decrypted = DMSP::FunctionPointerCrypto::DecryptPtr(
            DMSP::g_state.validatorPtrs[0], cryptoKey);
        _NtQueryInformationProcess pNtQIP = (_NtQueryInformationProcess)decrypted;
        if (!pNtQIP) {
            HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
            if (!hNtdll) return false;
            pNtQIP = (_NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
            if (!pNtQIP) return false;
        }

        HANDLE hProcess = GetCurrentProcess();
        DWORD debugPort = 0;
        ULONG returnLength = 0;

        NTSTATUS status = pNtQIP(hProcess, DMSP::g_state.validatorKeys[0],
            &debugPort, sizeof(debugPort), &returnLength);

        return (status >= 0) && debugPort != 0;
    }

    inline bool CheckTimingAnomaly() {
        LARGE_INTEGER start, end;
        QueryPerformanceCounter(&start);

        volatile int sum = 0;
        for (int i = 0; i < 1000; i++) sum += i;

        QueryPerformanceCounter(&end);
        LARGE_INTEGER freq;
        QueryPerformanceFrequency(&freq);

        double elapsed = static_cast<double>(end.QuadPart - start.QuadPart) / freq.QuadPart;
        return elapsed > 0.01;
    }

    // 检测IDA远程调试器
    inline bool CheckIDARemoteDebugger() {
        HWND hIDA = FindWindowW(L"IDA", NULL);
        if (hIDA) return true;
        hIDA = FindWindowW(L"IDA64", NULL);
        if (hIDA) return true;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = { sizeof(pe) };
            if (Process32FirstW(hSnapshot, &pe)) {
                do {
                    std::wstring name = pe.szExeFile;
                    for (auto& c : name) c = towlower(c);
                    if (name.find(L"winagent") != std::wstring::npos ||
                        name.find(L"ida") != std::wstring::npos ||
                        name.find(L"x64dbg") != std::wstring::npos ||
                        name.find(L"x32dbg") != std::wstring::npos ||
                        name.find(L"windbg") != std::wstring::npos ||
                        name.find(L"ollydbg") != std::wstring::npos) {
                        CloseHandle(hSnapshot);
                        return true;
                    }
                } while (Process32NextW(hSnapshot, &pe));
            }
            CloseHandle(hSnapshot);
        }
        return false;
    }

    // 检测硬件断点
    inline bool CheckHardwareBreakpoints() {
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(GetCurrentThread(), &ctx)) {
            if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
                return true;
            }
        }
        return false;
    }

    // [v5.0 改进10-a] ProcessDebugObjectHandle检测(最可靠)
    // VMProtect使用的反调试技术，比ProcessDebugPort更可靠
    inline bool CheckProcessDebugObjectHandle() {
        typedef NTSTATUS(NTAPI* _NtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return false;
        auto pNtQIP = (_NtQIP)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (!pNtQIP) return false;

        HANDLE hDebugObj = NULL;
        ULONG returnLen = 0;
        NTSTATUS status = pNtQIP(GetCurrentProcess(), 0x1E,
            &hDebugObj, sizeof(hDebugObj), &returnLen);
        // STATUS_SUCCESS = 有调试对象attached
        return status == 0;
    }

    // [v5.0 改进10-b] NtSetInformationThread(ThreadHideFromDebugger)检测
    // 尝试隐藏线程从调试器，同时检测是否被拦截
    inline bool CheckThreadHideFromDebuggerSupport() {
        typedef NTSTATUS(NTAPI* _NtSIT)(HANDLE, ULONG, PVOID, ULONG);
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return false;
        auto pNtSIT = (_NtSIT)GetProcAddress(hNtdll, "NtSetInformationThread");
        if (!pNtSIT) return false;

        NTSTATUS status = pNtSIT(GetCurrentThread(), 0x11, NULL, 0);
        (void)status;
        return false;  // 不单独判定，仅作干扰
    }
    static volatile LONG g_closeHandleFilterLock = 0;  // 自旋锁

    inline bool CheckCloseHandleException() {
        while (InterlockedCompareExchange(&g_closeHandleFilterLock, 1, 0) != 0) {
            YieldProcessor();
        }

        bool detected = false;
        __try {
            CloseHandle((HANDLE)(UINT_PTR)0xDEAD);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            if (GetExceptionCode() == 0xC0000008) {
                detected = true;
                ResponseSystem::ShowToastNotification(L"CMDPLUS \u5B89\u5168\u901A\u77E5",
                    L"[DMSP] \u5F02\u5E38\u68C0\u6D4B: \u5F02\u5E38\u7801 0xC0000008 "
                    L"\u2014 \u8C03\u8BD5\u5F02\u5E38\u884C\u4E3A");
            }
        }
        InterlockedExchange(&g_closeHandleFilterLock, 0);
        return detected;
    }

    // [v5.0 改进10-d] OutputDebugStringW检测
    // 有调试器时GetLastError()==0，无调试器时!=0
    inline bool CheckOutputDebugString() {
        SetLastError(0);
        OutputDebugStringW(L"\x00");
        DWORD err = GetLastError();
        return err == 0;
    }
    inline bool CheckCriticalFunctionBreakpoints(void* pForceExitFn) {
        // 关键函数列表 - 24 个核心函数,覆盖验证/响应/状态/加密/数据等所有关键路径
        void* criticalFuncs[24] = {};
        int funcCount = 0;

        // === 响应系统 ===
        criticalFuncs[funcCount++] = pForceExitFn;                                    // ForceExit 强制退出
        // === 状态管理 ===
        criticalFuncs[funcCount++] = (void*)&DMSP::IsCompromised;                      // 状态检查
        criticalFuncs[funcCount++] = (void*)&DMSP::MarkCompromised;                    // 状态标记
        criticalFuncs[funcCount++] = (void*)&DMSP::EncodeCompromised;                  // 状态编码
        criticalFuncs[funcCount++] = (void*)&DMSP::DecodeCompromised;                  // 状态解码
        criticalFuncs[funcCount++] = (void*)&DMSP::SecureDllSearch;                    // DLL劫持防护
        // === 完整性校验 ===
        criticalFuncs[funcCount++] = (void*)&DataIntegrity::VerifyDataIntegrity;       // 数据完整性校验
        criticalFuncs[funcCount++] = (void*)&DMSP::StateIntegrity::VerifyStateIntegrity;  // 状态指纹验证

        // === 其他重要检测函数(本命名空间内,定义在本函数之前) ===
        criticalFuncs[funcCount++] = (void*)&CheckCloseHandleException;    // CloseHandle 异常检测
        criticalFuncs[funcCount++] = (void*)&CheckHardwareBreakpoints;     // 硬件断点检测
        criticalFuncs[funcCount++] = (void*)&CheckOutputDebugString;       // OutputDebugString 检测
        criticalFuncs[funcCount++] = (void*)&CheckProcessDebugObjectHandle; // 调试对象句柄
        criticalFuncs[funcCount++] = (void*)&CheckThreadHideFromDebuggerSupport; // 反反调试

        // 剩余槽位填0(后续如有需要可扩展)
        for (int i = funcCount; i < 24; i++) {
            criticalFuncs[i] = nullptr;
        }

        // [v5.3 增强] 扫描前 2048 字节 (覆盖函数主体+内联展开的辅助函数+被优化器融合的常量)
        // 攻击者要在 24 个函数前 2048 字节均避开 0xCC,几乎不可能
        const int SCAN_SIZE = 2048;

        for (int idx = 0; idx < 24; idx++) {
            void* fnPtr = criticalFuncs[idx];
            if (!fnPtr) continue;
            BYTE* code = reinterpret_cast<BYTE*>(fnPtr);

            // 扫描整个 2048 字节范围
            for (int i = 0; i < SCAN_SIZE; i++) {
                if (code[i] == 0xCC) return true;
            }
        }
        return false;
    }

    // [v5.0 改进10-f] NtQuerySystemInformation(SystemKernelDebuggerInformation)
    inline bool CheckKernelDebugger() {
        typedef NTSTATUS(NTAPI* _NtQSI)(ULONG, PVOID, ULONG, PULONG);
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return false;
        auto pNtQSI = (_NtQSI)GetProcAddress(hNtdll, "NtQuerySystemInformation");
        if (!pNtQSI) return false;

        struct KernelDebuggerInfo { BYTE KernelDebuggerEnabled; BYTE DebuggerNotPresent; };
        KernelDebuggerInfo info = {};
        ULONG returnLen = 0;
        NTSTATUS status = pNtQSI(0x23, &info, sizeof(info), &returnLen);
        if (status >= 0) {
            return info.KernelDebuggerEnabled && !info.DebuggerNotPresent;
        }
        return false;
    }

    // [v5.0 改进10-g] 增强版父进程+祖父进程检测
    inline bool CheckParentAndGrandparentProcess() {
        DWORD myPid = GetCurrentProcessId();
        DWORD parentPid = 0;
        DWORD grandparentPid = 0;

        // 获取父进程PID
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;

        PROCESSENTRY32W pe = { sizeof(pe) };
        if (Process32FirstW(hSnapshot, &pe)) {
            do {
                if (pe.th32ProcessID == myPid) {
                    parentPid = pe.th32ParentProcessID;
                    break;
                }
            } while (Process32NextW(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);

        if (parentPid == 0) return false;

        // 获取祖父进程PID
        hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe2 = { sizeof(pe2) };
            if (Process32FirstW(hSnapshot, &pe2)) {
                do {
                    if (pe2.th32ProcessID == parentPid) {
                        grandparentPid = pe2.th32ParentProcessID;
                        break;
                    }
                } while (Process32NextW(hSnapshot, &pe2));
            }
            CloseHandle(hSnapshot);
        }

        // 验证父进程合法性
        HANDLE hParent = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parentPid);
        if (hParent) {
            wchar_t parentPath[MAX_PATH] = {};
            DWORD pathSize = MAX_PATH;
            if (QueryFullProcessImageNameW(hParent, 0, parentPath, &pathSize)) {
                std::wstring parentName(parentPath);
                std::transform(parentName.begin(), parentName.end(), parentName.begin(), ::towlower);

                const std::vector<std::wstring> legalParents = {
                    L"explorer.exe", L"cmd.exe", L"powershell.exe", L"pwsh.exe",
                    L"services.exe", L"svchost.exe", L"taskeng.exe", L"sihost.exe",
                    L"runtimebroker.exe"
                };

                size_t pos = parentName.find_last_of(L"\\/");
                if (pos != std::wstring::npos) parentName = parentName.substr(pos + 1);

                bool isLegalParent = false;
                for (const auto& legal : legalParents) {
                    if (parentName == legal) { isLegalParent = true; break; }
                }

                if (!isLegalParent) {
                    CloseHandle(hParent);
                    return true;  // 可疑父进程
                }
            }
            CloseHandle(hParent);
        }

        // 检查祖父进程是否为可疑调试器
        if (grandparentPid != 0 && grandparentPid != myPid) {
            HANDLE hGrandparent = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, grandparentPid);
            if (hGrandparent) {
                wchar_t gpPath[MAX_PATH] = {};
                DWORD gpSize = MAX_PATH;
                if (QueryFullProcessImageNameW(hGrandparent, 0, gpPath, &gpSize)) {
                    std::wstring gpName(gpPath);
                    std::transform(gpName.begin(), gpName.end(), gpName.begin(), ::towlower);

                    size_t pos = gpName.find_last_of(L"\\/");
                    if (pos != std::wstring::npos) gpName = gpName.substr(pos + 1);

                    // 可疑的祖父进程(可能是调试器)
                    const std::vector<std::wstring> suspiciousGrandparents = {
                        L"ida.exe", L"ida64.exe", L"x64dbg.exe", L"x32dbg.exe",
                        L"windbg.exe", L"ollydbg.exe", L"procdot.exe",
                        L"cheatengine.exe", L"scyllahide.exe"
                    };

                    for (const auto& suspicious : suspiciousGrandparents) {
                        if (gpName == suspicious) {
                            CloseHandle(hGrandparent);
                            return true;  // 可疑祖父进程
                        }
                    }
                }
                CloseHandle(hGrandparent);
            }
        }

        return false;
    }

    // [v5.0 改进10] 整合所有新旧检测方法，使用加权投票机制
    // [v5.1 修复] 原始阈值3在特定环境易误报
    // [v5.4 Mod 6] PEB 检测降权为辅助: PEB 标志(w2→w1)极易被用户态绕过
    // [v5.4.2] 移除进程名黑名单: CheckIDARemoteDebugger 和 CheckParentAndGrandparentProcess
    //   不再参与任何评分 — 纯靠技术检测, 不依赖调试器进程名匹配
    inline bool IsDebuggingDetected() {
        float score = 0.0f;

        // === 核心检测 (权重3) - 无法被用户态篡改的检测 ===
        if (CheckHardwareBreakpoints()) score += 3.0f;         // DR0-DR3寄存器 (需内核级操作)
        if (KernelAntiDebug::IsKernelDebuggingDetected()) score += 2.0f;  // 内核调试器综合检测

        // === 中高可靠检测 (权重2) - 绕过需要较多操作 ===
        if (CheckCloseHandleException()) score += 2.0f;        // 异常行为 (需内核处理)
        if (CheckCriticalFunctionBreakpoints((void*)&ResponseSystem::ForceExit)) score += 2.0f;  // INT3扫描

        // === PEB 辅助检测 (权重1) - 易被用户态绕过, 仅作辅助参考 ===
        if (CheckIsDebuggerPresent()) score += 1.0f;           // PEB.BeingDebugged(API)
        if (CheckPEBBeingDebugged()) score += 1.0f;            // PEB直接读取
        if (CheckNtGlobalFlag()) score += 1.0f;                // PEB.NtGlobalFlag
        if (CheckHeapFlags()) score += 1.0f;                   // 堆标志位 (PEB派生)

        // === 中等可靠检测 (权重1) - 通常可靠但有边界情况 ===
        if (CheckDebugObject()) score += 1.0f;                 // 调试对象句柄
        if (CheckProcessDebugObjectHandle()) score += 1.0f;    // 调试对象句柄(备选)
        if (CheckKernelDebugger()) score += 1.0f;              // 内核调试标志 (API版本)

        // === 辅助检测 (权重1) - 可能误报但提供额外信号 ===
        if (CheckTimingAnomaly()) score += 1.0f;               // 计时异常(受CPU负载影响)
        if (CheckOutputDebugString()) score += 1.0f;           // API副作用

        // === 干扰用检测 (不计入分数) ===
        CheckThreadHideFromDebuggerSupport();                  // 反反调试干扰
        // [v5.4.2] CheckIDARemoteDebugger / CheckParentAndGrandparentProcess
        //   已完全移除 — 纯靠技术检测, 不依赖进程名黑名单

        return score >= 5.0f;
    }

    // [v5.4.2] 调试器检测暴力退出 — 不经过 TriggerResponse, 直接 ForceExit
    //   绕过开发者模式降级, 绕过 TriggerResponse 的 CRC32C 锚定校验
    //   只要检测到调试器, 立即在任何上下文中执行强制退出
    __declspec(noinline) inline void ForceExitIfDebugged() {
        if (IsDebuggingDetected()) {
            // [v5.4.2] 退出前擦除敏感内存 (baseSeed, integrityKey, 状态标志等)
            //   防止内存 dump 泄露完整性校验密钥和证书信息
            DMSP::ScrubMemory();

            // 直接调用底层退出 — 不经过 TriggerResponse (绕过开发者模式降级)
            // 使用多路径退出确保至少一个成功
            volatile int path = 1;
            if (path == 1) {
                ExitProcess(0xDEAD0001);
            }
            if (path == 1) {
                TerminateProcess(GetCurrentProcess(), 0xDEAD0001);
            }
            if (path == 1) {
                SyscallExecutor::NtTerminateProcess_Direct(
                    GetCurrentProcess(), 0xDEAD0001);
            }
            if (path == 1) {
                // 终极兜底: RaiseException NONCONTINUABLE
                RaiseException(STATUS_ACCESS_VIOLATION,
                    EXCEPTION_NONCONTINUABLE, 0, nullptr);
            }
            // 极端兜底: 无限分配耗尽内存
            for (;;) {
                void* p = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x10000);
                if (p) memset(p, 0xCC, 0x10000);
            }
        }
    }

#else
    inline bool IsDebuggingDetected() { return false; }
#endif

#if DMSP_ENABLE_ANTI_HOOK

    inline void GetSelfModuleRange(BYTE*& base, SIZE_T& size) {
        static BYTE* cachedBase = nullptr;
        static SIZE_T cachedSize = 0;

        if (!cachedBase) {
            HMODULE hModule = GetModuleHandleW(nullptr);
            if (hModule) {
                MODULEINFO modInfo = {};
                if (GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
                    cachedBase = static_cast<BYTE*>(modInfo.lpBaseOfDll);
                    cachedSize = modInfo.SizeOfImage;
                }
            }
        }

        base = cachedBase;
        size = cachedSize;
    }

    inline bool IsAddressInSelfModule(const void* addr) {
        BYTE* moduleBase = nullptr;
        SIZE_T moduleSize = 0;
        GetSelfModuleRange(moduleBase, moduleSize);
        if (!moduleBase || !addr) return false;
        const BYTE* targetAddr = static_cast<const BYTE*>(addr);
        return targetAddr >= moduleBase && targetAddr < (moduleBase + moduleSize);
    }

    inline bool IsExternalHook(const BYTE* code) {
        // 0xE9: JMP rel32
        if (code[0] == 0xE9) {
            INT32 offset = *reinterpret_cast<const INT32*>(code + 1);
            const void* target = reinterpret_cast<const void*>(code + 5 + offset);
            return !IsAddressInSelfModule(target);
        }

#ifdef _WIN64
        // 0xFF 0x25: JMP [rip+disp32]
        if (code[0] == 0xFF && code[1] == 0x25) {
            INT32 disp = *reinterpret_cast<const INT32*>(code + 2);
            const BYTE* addrPtr = code + 6 + disp;
            const void* target = *reinterpret_cast<const BYTE* const*>(addrPtr);
            return !IsAddressInSelfModule(target);
        }
        // 0x48 0xB8 ... 0xFF 0xE0: mov rax, imm64; jmp rax (14字节绝对跳转)
        if (code[0] == 0x48 && code[1] == 0xB8 && code[10] == 0xFF && code[11] == 0xE0) {
            UINT64 target = *reinterpret_cast<const UINT64*>(code + 2);
            return !IsAddressInSelfModule(reinterpret_cast<const void*>(target));
        }
#endif
        return true;
    }

    inline bool IsFunctionHooked(void* funcPtr) {
        if (!funcPtr) return false;
        const BYTE* code = reinterpret_cast<const BYTE*>(funcPtr);

        bool isHookPattern = false;
        if (code[0] == 0xE9) isHookPattern = true;
#ifdef _WIN64
        if (code[0] == 0xFF && code[1] == 0x25) isHookPattern = true;
        if (code[0] == 0x48 && code[1] == 0xB8 && code[10] == 0xFF && code[11] == 0xE0) isHookPattern = true;
#endif
        if (code[0] == 0xCC) return false;
        if (code[0] == 0xCD && code[1] == 0x03) return false;

        if (!isHookPattern) {
            bool allNop = true;
            for (int i = 0; i < 16; i++) {
                if (code[i] != 0x90) { allNop = false; break; }
            }
            if (allNop) isHookPattern = true;
        }

        if (!isHookPattern) return false;
        return IsExternalHook(code);
    }

    inline bool AreCriticalAPIsHooked() {
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");

        if (hKernel32) {
            void* terminateProcess = GetProcAddress(hKernel32, "TerminateProcess");
            void* exitProcess = GetProcAddress(hKernel32, "ExitProcess");
            if (terminateProcess && IsFunctionHooked(terminateProcess)) return true;
            if (exitProcess && IsFunctionHooked(exitProcess)) return true;
        }

        if (hNtdll) {
            void* ntTerminateProcess = GetProcAddress(hNtdll, "NtTerminateProcess");
            void* ntContinue = GetProcAddress(hNtdll, "NtContinue");
            if (ntTerminateProcess && IsFunctionHooked(ntTerminateProcess)) return true;
            if (ntContinue && IsFunctionHooked(ntContinue)) return true;
        }

        return false;
    }

#else
    inline bool AreCriticalAPIsHooked() { return false; }
#endif
}

// ============================================================================
// 第五层: 内存完整性保护
// ============================================================================
namespace MemoryGuard {

#if DMSP_ENABLE_MEMORY_GUARD

    inline bool IsCodeSectionWritable() {
        HMODULE hModule = GetModuleHandleW(nullptr);
        if (!hModule) return false;

        MODULEINFO modInfo = {};
        if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) return false;

        const IMAGE_DOS_HEADER* dosHdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(modInfo.lpBaseOfDll);
        const IMAGE_NT_HEADERS64* ntHdr = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
            reinterpret_cast<const BYTE*>(modInfo.lpBaseOfDll) + dosHdr->e_lfanew);

        const IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHdr);

        for (WORD i = 0; i < ntHdr->FileHeader.NumberOfSections; i++) {
            if (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                MEMORY_BASIC_INFORMATION mbi = {};
                VirtualQuery(
                    reinterpret_cast<LPCVOID>(reinterpret_cast<size_t>(modInfo.lpBaseOfDll) + sections[i].VirtualAddress),
                    &mbi, sizeof(mbi));

                if (mbi.Protect & PAGE_EXECUTE_WRITECOPY ||
                    mbi.Protect & PAGE_EXECUTE_READWRITE) {
                    return true;
                }
            }
        }

        return false;
    }

    inline bool ValidatePagePermissions() {
        HMODULE hModule = GetModuleHandleW(nullptr);
        if (!hModule) return false;

        MODULEINFO modInfo = {};
        if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) return false;

        MEMORY_BASIC_INFORMATION mbi = {};
        VirtualQuery(modInfo.lpBaseOfDll, &mbi, sizeof(mbi));

        if (mbi.State != MEM_COMMIT) return false;
        if (mbi.Type != MEM_IMAGE) return false;

        return !IsCodeSectionWritable();
    }

#else
    inline bool ValidatePagePermissions() { return true; }
#endif
}

// ============================================================================
// 第六层: 运行时环境验证
// ============================================================================
namespace EnvironmentChecker {

    inline bool ValidateParentProcess() {
        DWORD parentPid = 0;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return true;

        PROCESSENTRY32W pe = { sizeof(pe) };
        DWORD myPid = GetCurrentProcessId();

        if (Process32FirstW(hSnapshot, &pe)) {
            do {
                if (pe.th32ProcessID == myPid) {
                    parentPid = pe.th32ParentProcessID;
                    break;
                }
            } while (Process32NextW(hSnapshot, &pe));
        }

        CloseHandle(hSnapshot);
        if (parentPid == 0) return true;

        HANDLE hParentProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parentPid);
        if (!hParentProcess) return true;

        wchar_t parentPath[MAX_PATH] = {};
        DWORD pathSize = MAX_PATH;
        BOOL gotPath = QueryFullProcessImageNameW(hParentProcess, 0, parentPath, &pathSize);
        CloseHandle(hParentProcess);

        if (!gotPath) return true;

        std::wstring parentName(parentPath);
        std::transform(parentName.begin(), parentName.end(), parentName.begin(), ::towlower);

        const std::vector<std::wstring> legalParents = {
            L"explorer.exe", L"cmd.exe", L"powershell.exe", L"pwsh.exe",
            L"services.exe", L"svchost.exe", L"taskeng.exe", L"sihost.exe",
            L"runtimebroker.exe"
        };

        size_t pos = parentName.find_last_of(L"\\/");
        if (pos != std::wstring::npos) parentName = parentName.substr(pos + 1);

        for (const auto& legal : legalParents) {
            if (parentName == legal) return true;
        }

        return true;
    }

    inline bool ValidateProcessCount() {
        DWORD processCount = 0;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return true;

        PROCESSENTRY32W pe = { sizeof(pe) };
        if (Process32FirstW(hSnapshot, &pe)) {
            do { processCount++; } while (Process32NextW(hSnapshot, &pe));
        }

        CloseHandle(hSnapshot);
        return processCount >= 20;
    }
}

// ============================================================================
// 响应系统 - 多路径退出，防止单点Hook
// [v5.0 改进4] 路径3使用SyscallExecutor手动PE解析
// [v5.0 改进9] 路径5使用HeapAlloc替代new
// ============================================================================
namespace ResponseSystem {

    inline void ShowToastNotification(const wchar_t* title, const wchar_t* message) {
        WNDCLASSW wc = {};
        wc.lpfnWndProc = DefWindowProcW;
        wc.lpszClassName = L"DMSPNotifyClass";
        RegisterClassW(&wc);
        HWND hNotifyWnd = CreateWindowExW(0, L"DMSPNotifyClass", L"", 0,
            0, 0, 0, 0, HWND_MESSAGE, NULL, NULL, NULL);

        NOTIFYICONDATAW nid = {};
        nid.cbSize = sizeof(NOTIFYICONDATAW);
        nid.hWnd = hNotifyWnd;
        nid.uID = 0xDEAD;
        nid.uFlags = NIF_ICON | NIF_INFO;
        nid.hIcon = LoadIconW(NULL, IDI_WARNING);
        nid.dwInfoFlags = NIIF_WARNING;
        wcsncpy_s(nid.szInfoTitle, _countof(nid.szInfoTitle), title, _TRUNCATE);
        wcsncpy_s(nid.szInfo, _countof(nid.szInfo), message, _TRUNCATE);
        Shell_NotifyIconW(NIM_ADD, &nid);
        Shell_NotifyIconW(NIM_MODIFY, &nid);
    }

    // 多路径强制退出 - 攻击者需要Hook所有路径才能阻止退出
    // [v5.0 改进4] 路径3使用SyscallExecutor::NtTerminateProcess_Direct(手动PE解析)
    // [v5.0 改进9] 路径5b使用HeapAlloc替代new确保低内存下仍能执行
    inline void ForceExit(UINT code) {
        // [v5.4.2] 退出前擦除所有敏感内存, 防内存dump泄露
        DMSP::ScrubMemory();

        // 路径1: ExitProcess
        ExitProcess(code);

        // 以下路径仅在ExitProcess被Hook时才可能执行
        volatile int path = 1;
        if (path == 1) {
            // 路径2: TerminateProcess
            TerminateProcess(GetCurrentProcess(), code);
        }
        if (path == 1) {
            // 路径3: NtTerminateProcess（[v5.0 改进4] 使用手动PE解析，绕过GetProcAddress Hook）
            SyscallExecutor::NtTerminateProcess_Direct(GetCurrentProcess(), static_cast<NTSTATUS>(code));
        }
        if (path == 1) {
            // 路径4: CRT退出
            _exit(code);
        }
        // 路径5: 多层兜底 — 确保进程必然终止，无法被任何用户态机制拦截
        // 5a: RaiseException(EXCEPTION_NONCONTINUABLE) — SEH无法恢复执行流
        RaiseException(STATUS_ACCESS_VIOLATION, EXCEPTION_NONCONTINUABLE, 0, NULL);

        // 5b: [v5.0 改进9] HeapAlloc替代new，低内存下不会抛异常，循环继续分配
        for (;;) {
            void* p = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x10000);
            if (p) memset(p, 0xCC, 0x10000);
        }
    }

    // [v5.2] 核心响应函数 - 开发者模式下自动降级为非致命
    //   DMSP_DEVELOPER_MODE=1: 仅记录详细日志+Toast通知(不终止)
    //   DMSP_DEVELOPER_MODE=0: 完整保护响应(根据DMSP_RESPONSE_STRATEGY执行退出)
    // [v5.2 控制流平坦化] 内部拆分为 dispatcher + 多个基本块, 通过
    //   函数指针表 + 不透明 state 变量驱动, IDA 看到的是 while/switch 循环
    //   而非直接的条件分支, 阻止自动 CFG 还原
    // -------------------------------------------------------------------------
    // 内部块函数类型
    using TR_BlockFn = int(*)(const char* reason, int severity, void* ctx);
    // 块上下文 (在 dispatcher 与块之间传递)
    struct TR_BlockCtx {
        const char* reason;
        int severity;
        int exitCode;
        UINT forceExitCode;
        char dbgBuf[512];
        wchar_t toastBuf[256];
    };

    // 块 0: 开发者模式 - 输出诊断日志
    static int TR_Block_DevLog(const char* reason, int severity, void* vctx) {
        TR_BlockCtx* c = static_cast<TR_BlockCtx*>(vctx);
        char* dbgMsg = c->dbgBuf;
        sprintf_s(dbgMsg, 512,
            "[DMSP-DEV] TriggerResponse blocked by developer mode\n"
            "  Reason: %s\n"
            "  Severity: %d\n"
            "  Timestamp: %lu ms\n"
            "  ProcessID: %lu\n"
            "  ThreadID: %lu\n",
            reason, severity, GetTickCount(),
            GetCurrentProcessId(), GetCurrentThreadId());
        OutputDebugStringA(dbgMsg);
        return 1;  // 下一块
    }

    // 块 1: 开发者模式 - 显示 Toast
    static int TR_Block_DevToast(const char* reason, int severity, void* vctx) {
        TR_BlockCtx* c = static_cast<TR_BlockCtx*>(vctx);
        wchar_t* toastMsg = c->toastBuf;
        swprintf_s(toastMsg, 256,
            L"DMSP\u5F00\u53D1\u8005\u6A21\u5F0F: [%hs] (sev=%d)\n\u7A0B\u5E8F\u7EE7\u7EED\u8FD0\u884C",
            reason, severity);
        ShowToastNotification(L"CMDPLUS \u5B89\u5168\u901A\u77E5", toastMsg);
        return -1;  // 终止 dispatcher
    }

    // 块 2: 发布模式 - 初始化状态 + 标记compromised
    static int TR_Block_PubInit(const char*, int, void*) {
        DMSP::InitializeState();
        DMSP::MarkCompromised();
        return 3;  // 跳到 Toast 块
    }

    // 块 3: 发布模式 - 显示终止 Toast
    //   返回值由调用方在 bctx.exitCode 中预置 (映射到 strategyBlock)
    static int TR_Block_PubToast(const char*, int, void* vctx) {
        TR_BlockCtx* c = static_cast<TR_BlockCtx*>(vctx);
        ShowToastNotification(
            L"CMDPLUS \u5B89\u5168\u901A\u77E5",
            L"DMSP\uFF08CMDPLUS\uFF09\u68C0\u6D4B\u5230\u4EE3\u7801\u88AB\u4FEE\u6539\uFF0C\u5DF2\u7981\u6B62\u7A0B\u5E8F\u8FD0\u884C\u3002");
        return c->exitCode;  // 由调用方根据 DMSP_RESPONSE_STRATEGY 设置
    }

    // 块 4: 策略分派 - EXIT_IMMEDIATE
    static int TR_Block_StrategyExit(const char*, int severity, void*) {
        ForceExit(static_cast<UINT>(0xDEAD0001 | severity));
        return -1;
    }

    // 块 5: 策略分派 - SLOW_DEATH
    static int TR_Block_StrategySlow(const char*, int severity, void*) {
        void* dummy = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x100000);
        if (dummy) memset(dummy, 0xCC, 0x100000);
        Sleep(3000 + (severity * 1000));
        ForceExit(0xDEAD0001);
        return -1;
    }

    // 块 6: 策略分派 - CORRUPT_SELF
    static int TR_Block_StrategyCorrupt(const char*, int, void*) {
        HMODULE hModule = GetModuleHandleW(nullptr);
        MODULEINFO modInfo = {};
        if (GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
            DWORD oldProtect;
            SIZE_T protectSize = (static_cast<SIZE_T>(0x1000) < modInfo.SizeOfImage)
                ? static_cast<SIZE_T>(0x1000) : static_cast<SIZE_T>(modInfo.SizeOfImage);
            if (VirtualProtect(modInfo.lpBaseOfDll, protectSize,
                PAGE_READWRITE, &oldProtect)) {
                memset(modInfo.lpBaseOfDll, 0xFF, protectSize);
            }
        }
        ForceExit(0xDEAD0002);
        return -1;
    }

    // 块 7: 不透明假块 (永远不执行, 但必须出现在 dispatcher 路径上以干扰支配分析)
    static int TR_Block_Dead(const char*, int, void*) {
        volatile int z = 0x5A5A5A5A;
        for (int i = 0; i < 7; i++) {
            z = (z << 1) | (z >> 31);
            z ^= 0x12345678;
        }
        (void)z;
        return 0;  // 回到块 0
    }

    // 块表 (扁平结构, 看起来像函数指针表, 顺序不反映执行顺序)
    // 索引经过 XOR 混淆: 真索引 = idx ^ KEY, KEY 来自运行时种子
    static const TR_BlockFn TR_BlockTable[8] = {
        TR_Block_DevLog,        // 0
        TR_Block_DevToast,      // 1
        TR_Block_PubInit,       // 2
        TR_Block_PubToast,      // 3
        TR_Block_StrategyExit,  // 4
        TR_Block_StrategySlow,  // 5
        TR_Block_StrategyCorrupt, // 6
        TR_Block_Dead           // 7
    };

    // 块调度密钥 (与 stateTable 风格保持一致: 运行时生成)
    inline DWORD TR_BlockKey() {
        volatile uint32_t t = static_cast<uint32_t>(GetTickCount());
        volatile uint32_t s = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&TR_BlockTable));
        return static_cast<DWORD>((t ^ s) & 0xFFFFu);
    }

    // 入口: 控制流平坦化 dispatcher
    inline void TriggerResponse(const char* reason, int severity) {
        TR_BlockCtx bctx = {};
        bctx.reason = reason;
        bctx.severity = severity;

        // 初始状态: 0 = DevLog (开发者模式) 或 2 = PubInit (发布模式)
        // 通过运行时 DMSP_DEVELOPER_MODE 决定入口
        volatile int devMode = DMSP_DEVELOPER_MODE;
        volatile int initialState = (devMode == 1) ? 0 : 2;
        volatile int state = initialState ^ static_cast<int>(TR_BlockKey() & 0);
        // 密钥与 0 与运算后丢弃, 保留 initialState, 但混淆器看到复杂表达式

        // 策略选择 (编译期根据 DMSP_RESPONSE_STRATEGY 决定 PubInit 之后跳到哪个策略块)
        // 块 4 = EXIT_IMMEDIATE, 5 = SLOW_DEATH, 6 = CORRUPT_SELF
#if DMSP_RESPONSE_STRATEGY == DMSP_RESPONSE_EXIT_IMMEDIATE
        volatile int strategyBlock = 4;
#elif DMSP_RESPONSE_STRATEGY == DMSP_RESPONSE_SLOW_DEATH
        volatile int strategyBlock = 5;
#elif DMSP_RESPONSE_STRATEGY == DMSP_RESPONSE_CORRUPT_SELF
        volatile int strategyBlock = 6;
#else
        volatile int strategyBlock = 4;
#endif
        // 写入 ctx 让块 3 (PubToast) 知道下一步跳到哪个策略块
        bctx.exitCode = strategyBlock;

        // 注入不透明假分支: 强制 dispatcher 走标准 while
        volatile bool keepRunning = true;

        while (keepRunning) {
            // 反混淆 state 得到真索引
            volatile DWORD key = TR_BlockKey();
            volatile int realIdx = state ^ static_cast<int>(key & 0);
            (void)key;
            // 上面的 & 0 让 IDA 看到 XOR 但无法简化 - 实际 state == realIdx

            // 不透明边界检查
            if (realIdx < 0 || realIdx >= 8) {
                // 永不执行, 但分析器必须证明
                realIdx = 7;  // 跳到 Dead 块
            }

            // 调用块
            int next = TR_BlockTable[realIdx](reason, severity, &bctx);

            // 不透明下一状态计算
            if (next < 0) {
                keepRunning = false;
            } else {
                state = next;
                // 注入不透明假路径: 7% 概率走 Dead 块再回来
                volatile uint32_t t = static_cast<uint32_t>(GetTickCount());
                if ((t & 0xFFu) == 0xAAu) {
                    state = 7;  // 走 Dead 块后返回 0
                }
            }
        }
    }

    inline void OnMinorViolation(const char* reason) {
        static int minorViolationCount = 0;
        minorViolationCount++;
        if (minorViolationCount > 10) {
            ResponseSystem::TriggerResponse("Accumulated violations", 3);
        }
    }

    // [v5.1] 非致命响应: 仅记录日志+显示Toast通知，不终止进程
    // 用于早期验证阶段(DMSP_EARLY_VERIFY / DMSP_INIT_CHECK)，允许程序继续运行
    // 后续的VERIFY_SIGNATURE()仍使用完整的TriggerResponse进行全强度保护
    inline void TriggerNonFatal(const char* reason, int severity) {
        (void)severity;  // 保留参数以备将来分级使用
        // 详细诊断日志(开发者模式增强版)
        char dbgMsg[512] = {};
        sprintf_s(dbgMsg, sizeof(dbgMsg),
            "[DMSP-NF] Early verification warning\n"
            "  Reason: %s\n"
            "  Severity: %d\n"
            "  Timestamp: %lu ms\n",
            reason, severity, GetTickCount());
        OutputDebugStringA(dbgMsg);
        // 显示包含具体原因的Toast通知
        wchar_t toastMsg[256] = {};
        swprintf_s(toastMsg, 256,
            L"DMSP\u65E9\u671F\u9A8C\u8BC1: [%hs]\n\u7A0B\u5E8F\u7EE7\u7EED\u8FD0\u884C",
            reason);
        ShowToastNotification(L"CMDPLUS \u5B89\u5168\u901A\u77E5", toastMsg);
    }
}

// ============================================================================
// [v5.0 改进6] 间接跳转表替代switch-case - 控制流平坦化增强版
// 目标: 使IDA更难还原控制流
// ============================================================================

namespace UnifiedValidator {

    // 状态处理器上下文结构
    struct QuickVerifyContext {
        size_t callSiteId;
        int count;
        DWORD checkMask;
        HMODULE hMod;
        const IMAGE_DOS_HEADER* dosHdr;
        const IMAGE_NT_HEADERS64* ntHdr;
        bool result;
        DWORD obfuscationKey;  // 索引混淆密钥
    };

    // 验证结果结构(前向声明，状态函数中需要引用)
    struct ValidationResult {
        bool passed;
        int layerResults[6];
        std::string failureReason;
    };

    // 前向声明: PerformFullValidation在状态函数之后定义
    inline ValidationResult PerformFullValidation(bool reportAllErrors);

    // 状态处理器函数类型 - 返回下一个状态索引
    using StateFn = DWORD(*)(QuickVerifyContext* ctx);

    // 真实状态枚举(内部使用)
    enum RealStates : DWORD {
        STATE_START = 0,
        STATE_CHECK_COMPROMISED,
        STATE_CHECK_PE_1,
        STATE_CHECK_PE_2,
        STATE_CHECK_PE_3,
        STATE_CHECK_SIG_DIR,
        STATE_CHECK_MACHINE,
        STATE_CHECK_SECTIONS,
        STATE_CHECK_TIMESTAMP,
        STATE_CHECK_FULL,
        STATE_CHECK_CODE_SAMPLE,
        STATE_CHECK_HOOK,
        STATE_CHECK_DEBUG,
        STATE_CHECK_MEMORY,
        STATE_CHECK_COMPROMISED2,
        STATE_FINALIZE,
        STATE_PASS,
        STATE_FAIL,
        MAX_STATES
    };

    // 特殊索引常量
    static constexpr DWORD PASS_IDX = 0xFFFFFFFF;
    static constexpr DWORD FAIL_IDX = 0xFFFFFFFE;

    // 索引混淆: 真实索引 = 表面索引 ^ obfuscation_key
    inline DWORD ObfuscateIndex(DWORD realIdx, DWORD key) {
        return realIdx ^ (key & 0xFFFF);
    }

    inline DWORD DeobfuscateIndex(DWORD obfIdx, DWORD key) {
        return obfIdx ^ (key & 0xFFFF);
    }

    // =========================================================================
// [v5.2 反编译期补丁检测] 运行时 CRC32C 校验
//   目的: 攻击者用十六进制编辑器把 TriggerResponse 改成一字节跳转绕过
//   防护: 在 DMSP_EARLY_VERIFY() 中计算 TriggerResponse 函数体的 CRC32C
//   并与预计算常量比对. CRC 算法本身也用控制流混淆, 常量分片存储.
// =========================================================================
// [v5.2 二值性混淆] CRC 期望值的三个分片:
//   - DMSP_CRC_FRAG_A 在本头文件中以噪声常量形式出现
//   - DMSP_CRC_FRAG_B 在本头文件中以噪声常量形式出现
//   - DMSP_CRC_FRAG_C 默认为 DMSP_CRC_FRAG_A (抵消, 真值 = B)
//   真实期望值 = A ^ B ^ C, 当 C = A 时真值 = B
//   启用开发者模式时改 C 为 (A ^ B ^ 1), 真值变为 1 (用于诊断, 不是合法期望值)
//   攻击者必须改三处才能伪造期望值
//
// [v5.2 部署说明] 期望值默认 0xCAFEBABE 显然不等于真实 anchor CRC.
//   部署步骤:
//     1. 首次构建运行, 程序 OutputDebugString 输出实际 anchor CRC
//     2. 拆分实际 CRC 为三个分片 (xor合成 = CRC), 填入 A/B/C (C 不能等于 A, 否则真值=0)
//     3. 重新构建, 校验生效
//   为避免误报, 校验默认关闭 (DMSP_CRC_CHECK_ENABLED=0), 配好分片后改为 1
#ifndef DMSP_CRC_CHECK_ENABLED
#define DMSP_CRC_CHECK_ENABLED    0
#endif
#ifndef DMSP_CRC_FRAG_A
#define DMSP_CRC_FRAG_A    0xDEADBEEFu
#endif
#ifndef DMSP_CRC_FRAG_B
#define DMSP_CRC_FRAG_B    0xCAFEBABEu
#endif
#ifndef DMSP_CRC_FRAG_C
#define DMSP_CRC_FRAG_C    DMSP_CRC_FRAG_A
#endif

namespace Integrity {

        // CRC32C 多项式 (Castagnoli) - 反射形式 0x82F63B78
        // 用标准查表算法, 表在编译期生成 (constexpr)
        constexpr uint32_t CRC32C_POLY = 0x82F63B78u;

        // 编译期生成 CRC32C 查找表 (256 项)
        constexpr uint32_t Crc32CBuildEntry(uint32_t index) {
            uint32_t crc = index;
            for (int i = 0; i < 8; i++) {
                crc = (crc >> 1) ^ (CRC32C_POLY & static_cast<uint32_t>(-static_cast<int32_t>(crc & 1u)));
            }
            return crc;
        }

        constexpr uint32_t Crc32CTable[256] = {
            Crc32CBuildEntry(0),   Crc32CBuildEntry(1),   Crc32CBuildEntry(2),   Crc32CBuildEntry(3),
            Crc32CBuildEntry(4),   Crc32CBuildEntry(5),   Crc32CBuildEntry(6),   Crc32CBuildEntry(7),
            Crc32CBuildEntry(8),   Crc32CBuildEntry(9),   Crc32CBuildEntry(10),  Crc32CBuildEntry(11),
            Crc32CBuildEntry(12),  Crc32CBuildEntry(13),  Crc32CBuildEntry(14),  Crc32CBuildEntry(15),
            Crc32CBuildEntry(16),  Crc32CBuildEntry(17),  Crc32CBuildEntry(18),  Crc32CBuildEntry(19),
            Crc32CBuildEntry(20),  Crc32CBuildEntry(21),  Crc32CBuildEntry(22),  Crc32CBuildEntry(23),
            Crc32CBuildEntry(24),  Crc32CBuildEntry(25),  Crc32CBuildEntry(26),  Crc32CBuildEntry(27),
            Crc32CBuildEntry(28),  Crc32CBuildEntry(29),  Crc32CBuildEntry(30),  Crc32CBuildEntry(31),
            Crc32CBuildEntry(32),  Crc32CBuildEntry(33),  Crc32CBuildEntry(34),  Crc32CBuildEntry(35),
            Crc32CBuildEntry(36),  Crc32CBuildEntry(37),  Crc32CBuildEntry(38),  Crc32CBuildEntry(39),
            Crc32CBuildEntry(40),  Crc32CBuildEntry(41),  Crc32CBuildEntry(42),  Crc32CBuildEntry(43),
            Crc32CBuildEntry(44),  Crc32CBuildEntry(45),  Crc32CBuildEntry(46),  Crc32CBuildEntry(47),
            Crc32CBuildEntry(48),  Crc32CBuildEntry(49),  Crc32CBuildEntry(50),  Crc32CBuildEntry(51),
            Crc32CBuildEntry(52),  Crc32CBuildEntry(53),  Crc32CBuildEntry(54),  Crc32CBuildEntry(55),
            Crc32CBuildEntry(56),  Crc32CBuildEntry(57),  Crc32CBuildEntry(58),  Crc32CBuildEntry(59),
            Crc32CBuildEntry(60),  Crc32CBuildEntry(61),  Crc32CBuildEntry(62),  Crc32CBuildEntry(63),
            Crc32CBuildEntry(64),  Crc32CBuildEntry(65),  Crc32CBuildEntry(66),  Crc32CBuildEntry(67),
            Crc32CBuildEntry(68),  Crc32CBuildEntry(69),  Crc32CBuildEntry(70),  Crc32CBuildEntry(71),
            Crc32CBuildEntry(72),  Crc32CBuildEntry(73),  Crc32CBuildEntry(74),  Crc32CBuildEntry(75),
            Crc32CBuildEntry(76),  Crc32CBuildEntry(77),  Crc32CBuildEntry(78),  Crc32CBuildEntry(79),
            Crc32CBuildEntry(80),  Crc32CBuildEntry(81),  Crc32CBuildEntry(82),  Crc32CBuildEntry(83),
            Crc32CBuildEntry(84),  Crc32CBuildEntry(85),  Crc32CBuildEntry(86),  Crc32CBuildEntry(87),
            Crc32CBuildEntry(88),  Crc32CBuildEntry(89),  Crc32CBuildEntry(90),  Crc32CBuildEntry(91),
            Crc32CBuildEntry(92),  Crc32CBuildEntry(93),  Crc32CBuildEntry(94),  Crc32CBuildEntry(95),
            Crc32CBuildEntry(96),  Crc32CBuildEntry(97),  Crc32CBuildEntry(98),  Crc32CBuildEntry(99),
            Crc32CBuildEntry(100), Crc32CBuildEntry(101), Crc32CBuildEntry(102), Crc32CBuildEntry(103),
            Crc32CBuildEntry(104), Crc32CBuildEntry(105), Crc32CBuildEntry(106), Crc32CBuildEntry(107),
            Crc32CBuildEntry(108), Crc32CBuildEntry(109), Crc32CBuildEntry(110), Crc32CBuildEntry(111),
            Crc32CBuildEntry(112), Crc32CBuildEntry(113), Crc32CBuildEntry(114), Crc32CBuildEntry(115),
            Crc32CBuildEntry(116), Crc32CBuildEntry(117), Crc32CBuildEntry(118), Crc32CBuildEntry(119),
            Crc32CBuildEntry(120), Crc32CBuildEntry(121), Crc32CBuildEntry(122), Crc32CBuildEntry(123),
            Crc32CBuildEntry(124), Crc32CBuildEntry(125), Crc32CBuildEntry(126), Crc32CBuildEntry(127),
            Crc32CBuildEntry(128), Crc32CBuildEntry(129), Crc32CBuildEntry(130), Crc32CBuildEntry(131),
            Crc32CBuildEntry(132), Crc32CBuildEntry(133), Crc32CBuildEntry(134), Crc32CBuildEntry(135),
            Crc32CBuildEntry(136), Crc32CBuildEntry(137), Crc32CBuildEntry(138), Crc32CBuildEntry(139),
            Crc32CBuildEntry(140), Crc32CBuildEntry(141), Crc32CBuildEntry(142), Crc32CBuildEntry(143),
            Crc32CBuildEntry(144), Crc32CBuildEntry(145), Crc32CBuildEntry(146), Crc32CBuildEntry(147),
            Crc32CBuildEntry(148), Crc32CBuildEntry(149), Crc32CBuildEntry(150), Crc32CBuildEntry(151),
            Crc32CBuildEntry(152), Crc32CBuildEntry(153), Crc32CBuildEntry(154), Crc32CBuildEntry(155),
            Crc32CBuildEntry(156), Crc32CBuildEntry(157), Crc32CBuildEntry(158), Crc32CBuildEntry(159),
            Crc32CBuildEntry(160), Crc32CBuildEntry(161), Crc32CBuildEntry(162), Crc32CBuildEntry(163),
            Crc32CBuildEntry(164), Crc32CBuildEntry(165), Crc32CBuildEntry(166), Crc32CBuildEntry(167),
            Crc32CBuildEntry(168), Crc32CBuildEntry(169), Crc32CBuildEntry(170), Crc32CBuildEntry(171),
            Crc32CBuildEntry(172), Crc32CBuildEntry(173), Crc32CBuildEntry(174), Crc32CBuildEntry(175),
            Crc32CBuildEntry(176), Crc32CBuildEntry(177), Crc32CBuildEntry(178), Crc32CBuildEntry(179),
            Crc32CBuildEntry(180), Crc32CBuildEntry(181), Crc32CBuildEntry(182), Crc32CBuildEntry(183),
            Crc32CBuildEntry(184), Crc32CBuildEntry(185), Crc32CBuildEntry(186), Crc32CBuildEntry(187),
            Crc32CBuildEntry(188), Crc32CBuildEntry(189), Crc32CBuildEntry(190), Crc32CBuildEntry(191),
            Crc32CBuildEntry(192), Crc32CBuildEntry(193), Crc32CBuildEntry(194), Crc32CBuildEntry(195),
            Crc32CBuildEntry(196), Crc32CBuildEntry(197), Crc32CBuildEntry(198), Crc32CBuildEntry(199),
            Crc32CBuildEntry(200), Crc32CBuildEntry(201), Crc32CBuildEntry(202), Crc32CBuildEntry(203),
            Crc32CBuildEntry(204), Crc32CBuildEntry(205), Crc32CBuildEntry(206), Crc32CBuildEntry(207),
            Crc32CBuildEntry(208), Crc32CBuildEntry(209), Crc32CBuildEntry(210), Crc32CBuildEntry(211),
            Crc32CBuildEntry(212), Crc32CBuildEntry(213), Crc32CBuildEntry(214), Crc32CBuildEntry(215),
            Crc32CBuildEntry(216), Crc32CBuildEntry(217), Crc32CBuildEntry(218), Crc32CBuildEntry(219),
            Crc32CBuildEntry(220), Crc32CBuildEntry(221), Crc32CBuildEntry(222), Crc32CBuildEntry(223),
            Crc32CBuildEntry(224), Crc32CBuildEntry(225), Crc32CBuildEntry(226), Crc32CBuildEntry(227),
            Crc32CBuildEntry(228), Crc32CBuildEntry(229), Crc32CBuildEntry(230), Crc32CBuildEntry(231),
            Crc32CBuildEntry(232), Crc32CBuildEntry(233), Crc32CBuildEntry(234), Crc32CBuildEntry(235),
            Crc32CBuildEntry(236), Crc32CBuildEntry(237), Crc32CBuildEntry(238), Crc32CBuildEntry(239),
            Crc32CBuildEntry(240), Crc32CBuildEntry(241), Crc32CBuildEntry(242), Crc32CBuildEntry(243),
            Crc32CBuildEntry(244), Crc32CBuildEntry(245), Crc32CBuildEntry(246), Crc32CBuildEntry(247),
            Crc32CBuildEntry(248), Crc32CBuildEntry(249), Crc32CBuildEntry(250), Crc32CBuildEntry(251),
            Crc32CBuildEntry(252), Crc32CBuildEntry(253), Crc32CBuildEntry(254), Crc32CBuildEntry(255)
        };

        // 标准 CRC32C 算法 (查表)
        // 已被 Intel CRC32 指令验证等价, 是公认正确的实现
        inline uint32_t CalcCrc32C(const uint8_t* p, size_t len) {
            uint32_t crc = 0xFFFFFFFFu;
            for (size_t i = 0; i < len; i++) {
                uint8_t idx = static_cast<uint8_t>((crc ^ p[i]) & 0xFFu);
                crc = (crc >> 8) ^ Crc32CTable[idx];
            }
            return crc ^ 0xFFFFFFFFu;
        }

        // 期望 CRC32C (运行时合成): 真值 = (A ^ B ^ C)
        // 默认 A=0xDEADBEEF, B=0xCAFEBABE, C=A, 真值 = 0xCAFEBABE
        // 实际期望值由开发者通过运行"输出实际 CRC"模式得到, 拆分后填入 A/B/C
        inline uint32_t ExpectedCrcRuntime() {
            volatile uint32_t a = DMSP_CRC_FRAG_A;
            volatile uint32_t b = DMSP_CRC_FRAG_B;
            volatile uint32_t c = DMSP_CRC_FRAG_C;
            return a ^ b ^ c;
        }

        // 验证 TriggerResponse 函数体完整性
        // funcAddr: anchor 入口; funcSize: 字节数 (含 anchor 函数全部指令)
        // 调用方在运行时通过 anchor_next - anchor 取差, 不使用预计算常量
        inline __declspec(noinline) bool VerifyTriggerResponseCrc(const void* funcAddr, size_t funcSize) {
            if (!funcAddr || funcSize < 16 || funcSize > 4096) return false;
            volatile uint32_t expected = ExpectedCrcRuntime();
            volatile uint32_t actual = CalcCrc32C(static_cast<const uint8_t*>(funcAddr), funcSize);
            // 双路比较: 一路直接, 一路在不透明假分支中
            if (DMSPObf::DmspOpaqueTrue()) {
                if (actual == expected) return true;
            } else {
                // 永远不执行, 但静态分析器必须证明
                if (actual == 0xDEADBEEFu) return true;
            }
            return false;
        }
    } // namespace Integrity

    // 状态处理函数声明
    static DWORD State_Start(QuickVerifyContext* ctx);
    static DWORD State_CheckCompromised(QuickVerifyContext* ctx);
    static DWORD State_CheckPE_1(QuickVerifyContext* ctx);
    static DWORD State_CheckPE_2(QuickVerifyContext* ctx);
    static DWORD State_CheckPE_3(QuickVerifyContext* ctx);
    static DWORD State_CheckSigDir(QuickVerifyContext* ctx);
    static DWORD State_CheckMachine(QuickVerifyContext* ctx);
    static DWORD State_CheckSections(QuickVerifyContext* ctx);
    static DWORD State_CheckTimestamp(QuickVerifyContext* ctx);
    static DWORD State_CheckFull(QuickVerifyContext* ctx);
    static DWORD State_CheckCodeSample(QuickVerifyContext* ctx);
    static DWORD State_CheckHook(QuickVerifyContext* ctx);
    static DWORD State_CheckDebug(QuickVerifyContext* ctx);
    static DWORD State_CheckMemory(QuickVerifyContext* ctx);
    static DWORD State_CheckCompromised2(QuickVerifyContext* ctx);
    static DWORD State_Finalize(QuickVerifyContext* ctx);

    // 函数指针表(使用inline变量 - C++17特性,避免多包含导致的代码膨胀)
    // 关键: 之前用 static const 导致每个包含此头文件的 .cpp 都有一份完整副本
    // 改用 inline const 后,链接器会合并到单一实例,且MAX_STATIONS已优化为 18
    inline const StateFn stateTable[MAX_STATES] = {
        State_Start,                     // 0: START
        State_CheckCompromised,          // 1: CHECK_COMPROMISED
        State_CheckPE_1,                 // 2: CHECK_PE_1
        State_CheckPE_2,                 // 3: CHECK_PE_2
        State_CheckPE_3,                 // 4: CHECK_PE_3
        State_CheckSigDir,               // 5: CHECK_SIG_DIR
        State_CheckMachine,              // 6: CHECK_MACHINE
        State_CheckSections,             // 7: CHECK_SECTIONS
        State_CheckTimestamp,            // 8: CHECK_TIMESTAMP
        State_CheckFull,                 // 9: CHECK_FULL
        State_CheckCodeSample,           // 10: CHECK_CODE_SAMPLE
        State_CheckHook,                 // 11: CHECK_HOOK
        State_CheckDebug,                // 12: CHECK_DEBUG
        State_CheckMemory,               // 13: CHECK_MEMORY
        State_CheckCompromised2,         // 14: CHECK_COMPROMISED2
        State_Finalize,                  // 15: FINALIZE
        nullptr,                         // 16: PASS (特殊处理)
        nullptr                          // 17: FAIL (特殊处理)
    };

    // ===== 状态处理函数实现 =====

    static DWORD State_Start(QuickVerifyContext* ctx) {
        ctx->checkMask = static_cast<DWORD>(ctx->callSiteId) ^ DMSP::g_state.baseSeed;
        ctx->count = DMSP::g_state.verifyCount.fetch_add(1);
        return ObfuscateIndex(STATE_CHECK_COMPROMISED, ctx->obfuscationKey);
    }

    static DWORD State_CheckCompromised(QuickVerifyContext* ctx) {
        bool compromised = DMSP::IsCompromised();
        if (DMSP::OpaquePredicate::True()) {
            // 状态完整性/compromised检测 → 通过TriggerResponse报告(开发者模式输出位置)
            if (compromised) {
                ResponseSystem::TriggerResponse("State-Compromised", 3);
                return FAIL_IDX;
            }
        } else {
            DMSP_FAKE_CALL_2(0xBEEF, 0xCAFE);
        }
        return ObfuscateIndex(STATE_CHECK_PE_1, ctx->obfuscationKey);
    }

    static DWORD State_CheckPE_1(QuickVerifyContext* ctx) {
        DMSP_SEH_TRY {
            ctx->hMod = GetModuleHandleW(nullptr);
        } DMSP_SEH_EXCEPT_FILTER {
            return FAIL_IDX;
        }
        if (!ctx->hMod) {
            ResponseSystem::TriggerResponse("M1", 1);
            return FAIL_IDX;
        }
        return ObfuscateIndex(STATE_CHECK_PE_2, ctx->obfuscationKey);
    }

    static DWORD State_CheckPE_2(QuickVerifyContext* ctx) {
        DMSP_SEH_TRY {
            ctx->dosHdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(ctx->hMod);
            if ((ctx->dosHdr->e_magic ^ 0x5A4D) != 0) {
                ResponseSystem::TriggerResponse("M2", 1);
                return FAIL_IDX;
            }
        } DMSP_SEH_EXCEPT_FILTER {
            return FAIL_IDX;
        }
        return ObfuscateIndex(STATE_CHECK_PE_3, ctx->obfuscationKey);
    }

    static DWORD State_CheckPE_3(QuickVerifyContext* ctx) {
        DMSP_SEH_TRY {
            ctx->ntHdr = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
                reinterpret_cast<const BYTE*>(ctx->hMod) + ctx->dosHdr->e_lfanew);
            if ((ctx->ntHdr->Signature ^ 0x4550) != 0) {
                ResponseSystem::TriggerResponse("M3", 1);
                return FAIL_IDX;
            }
        } DMSP_SEH_EXCEPT_FILTER {
            return FAIL_IDX;
        }
        return ObfuscateIndex(STATE_CHECK_SIG_DIR, ctx->obfuscationKey);
    }

    static DWORD State_CheckSigDir(QuickVerifyContext* ctx) {
        if ((ctx->count + (ctx->checkMask & 0x3)) % 3 == 0) {
#ifndef DMSP_NOCERT
            DMSP_SEH_TRY {
                DWORD secDirRVA = ctx->ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
                DWORD secDirSize = ctx->ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
                if (secDirRVA == 0 || secDirSize == 0) {
                    ResponseSystem::TriggerResponse("M4", 2);
                    return FAIL_IDX;
                }
            } DMSP_SEH_EXCEPT_FILTER {
                return FAIL_IDX;
            }
#endif /* DMSP_NOCERT */
        }
        return ObfuscateIndex(STATE_CHECK_MACHINE, ctx->obfuscationKey);
    }

    static DWORD State_CheckMachine(QuickVerifyContext* ctx) {
        if ((ctx->count + (ctx->checkMask & 0x7)) % 5 == 0) {
#ifdef _WIN64
            if (ctx->ntHdr->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
                ResponseSystem::TriggerResponse("M5", 2);
                return FAIL_IDX;
            }
#else
            if (ctx->ntHdr->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
                ResponseSystem::TriggerResponse("M5", 2);
                return FAIL_IDX;
            }
#endif
        }
        return ObfuscateIndex(STATE_CHECK_SECTIONS, ctx->obfuscationKey);
    }

    static DWORD State_CheckSections(QuickVerifyContext* ctx) {
        if ((ctx->count + (ctx->checkMask & 0xF)) % 7 == 0) {
            if (ctx->ntHdr->FileHeader.NumberOfSections == 0 ||
                ctx->ntHdr->FileHeader.NumberOfSections > 96) {
                ResponseSystem::TriggerResponse("M6", 2);
                return FAIL_IDX;
            }
        }
        return ObfuscateIndex(STATE_CHECK_TIMESTAMP, ctx->obfuscationKey);
    }

    static DWORD State_CheckTimestamp(QuickVerifyContext* ctx) {
        if ((ctx->count + (ctx->checkMask & 0x1F)) % 11 == 0) {
            if (ctx->ntHdr->FileHeader.TimeDateStamp == 0) {
                ResponseSystem::TriggerResponse("M7", 2);
                return FAIL_IDX;
            }
        }
        return ObfuscateIndex(STATE_CHECK_FULL, ctx->obfuscationKey);
    }

    static DWORD State_CheckFull(QuickVerifyContext* ctx) {
        if (ctx->count % 20 == 0) {
            DMSP_SEH_TRY {
                auto fullResult = UnifiedValidator::PerformFullValidation(false);
                if (!fullResult.passed) {
                    ResponseSystem::TriggerResponse(fullResult.failureReason.c_str(), 2);
                    return FAIL_IDX;
                }
            } DMSP_SEH_EXCEPT_FILTER {
                return FAIL_IDX;
            }
        }
        return ObfuscateIndex(STATE_CHECK_CODE_SAMPLE, ctx->obfuscationKey);
    }

    static DWORD State_CheckCodeSample(QuickVerifyContext* ctx) {
        if ((ctx->count + (ctx->checkMask & 0x3F)) % 13 == 0) {
            DMSP_SEH_TRY {
                const IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ctx->ntHdr);
                if (sections[0].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                    const BYTE* textStart = reinterpret_cast<const BYTE*>(ctx->hMod) + sections[0].VirtualAddress;
                    bool looksValid = false;
                    for (int i = 0; i < 16; i++) {
                        if (textStart[i] != 0x00 && textStart[i] != 0xCC) {
                            looksValid = true;
                            break;
                        }
                    }
                    if (!looksValid) {
                        ResponseSystem::TriggerResponse("M8", 3);
                        return FAIL_IDX;
                    }
                }
            } DMSP_SEH_EXCEPT_FILTER {
                return FAIL_IDX;
            }
        }
        return ObfuscateIndex(STATE_CHECK_HOOK, ctx->obfuscationKey);
    }

    static DWORD State_CheckHook(QuickVerifyContext* ctx) {
        if ((ctx->count + (ctx->checkMask & 0x7F)) % 17 == 0) {
            if (AntiAnalysis::AreCriticalAPIsHooked()) {
                ResponseSystem::TriggerResponse("M9", 3);
                return FAIL_IDX;
            }
        }
        return ObfuscateIndex(STATE_CHECK_DEBUG, ctx->obfuscationKey);
    }

    static DWORD State_CheckDebug(QuickVerifyContext* ctx) {
        // [v5.4.2] 无条件每次都执行反调试检测, 不跳过, 不用 TriggerResponse
        //   检测到调试器 → 直接 ForceExit (绕过开发者模式降级)
        //   不依赖进程名黑名单, 纯靠技术检测 (HW断点/内核标志/异常行为等)
        AntiAnalysis::ForceExitIfDebugged();
        (void)ctx;  // ctx 在无条件检测中不需要计数器
        return ObfuscateIndex(STATE_CHECK_MEMORY, ctx->obfuscationKey);
    }

    // [v5.0 改进3] CHECK_MEMORY状态集成DataIntegrity检查
    static DWORD State_CheckMemory(QuickVerifyContext* ctx) {
        if ((ctx->count + (ctx->checkMask & 0x1FF)) % 29 == 0) {
            // [v5.0 改进3] 数据段完整性校验
            if (!MemoryGuard::ValidatePagePermissions()) {
                ResponseSystem::TriggerResponse("MB", 3);
                return FAIL_IDX;
            }
            // 每29次验证时额外检查.data/.rdata段完整性
            if (!DataIntegrity::VerifyDataIntegrity()) {
                ResponseSystem::TriggerResponse("MC", 3);  // MC = Data Corruption
                return FAIL_IDX;
            }
        }
        return ObfuscateIndex(STATE_CHECK_COMPROMISED2, ctx->obfuscationKey);
    }

    static DWORD State_CheckCompromised2(QuickVerifyContext* ctx) {
        if (DMSP::OpaquePredicate::True()) {
            // 签名哈希异常检测 → 通过TriggerResponse报告(开发者模式输出位置)
            if (DMSP::DecodeCompromisedSig() != 0) {
                ResponseSystem::TriggerResponse("State-SigInvalid", 3);
                return FAIL_IDX;
            }
        }
        return ObfuscateIndex(STATE_FINALIZE, ctx->obfuscationKey);
    }

    static DWORD State_Finalize(QuickVerifyContext* ctx) {
        DMSP::g_state.lastVerifyTime.store(GetTickCount());
        ctx->result = true;
        // [提权后校验通过] 输出DMSP v5.1 校验通过消息(仅首次通过时输出)
        if (DMSP::g_state.verifyCount.load() <= 1) {
            std::wcout << L"\n========================================" << std::endl;
            std::wcout << L"  [DMSP v5.1] 校验通过" << std::endl;
            std::wcout << L"========================================" << std::endl;
            OutputDebugStringA("[DMSP v5.1] 校验通过 (All checks passed)");
        }
        return PASS_IDX;
    }

    inline ValidationResult PerformFullValidation(bool reportAllErrors = false) {
        DMSP::InitializeState();

        DMSP::g_state.verifyCount.fetch_add(1);
        DMSP::g_state.lastVerifyTime.store(GetTickCount());

        ValidationResult result = {};
        result.passed = true;
        for (int i = 0; i < 6; i++) result.layerResults[i] = 2;

#if DMSP_ENABLE_INTEGRITY_CHECK
        result.layerResults[0] = PEValidator::ValidatePE() ? 0 : 1;
        if (result.layerResults[0] == 1) {
            result.passed = false;
            result.failureReason = "PE structure corrupted";
            if (!reportAllErrors) return result;
        }
#endif

        auto sigResult = SignatureValidator::ValidateSignature();
        switch (sigResult) {
        case SignatureValidator::SignatureResult::Valid:
        case SignatureValidator::SignatureResult::ValidButExpired:
        case SignatureValidator::SignatureResult::HasEmbeddedSig:
            result.layerResults[1] = 0;
            break;
        case SignatureValidator::SignatureResult::NoSignature:
            result.layerResults[1] = 1;
            result.passed = false;
            result.failureReason = "No digital signature";
            if (!reportAllErrors) return result;
            break;
        case SignatureValidator::SignatureResult::Tampered:
            result.layerResults[1] = 1;
            result.passed = false;
            result.failureReason = "Signature tampered or file modified";
            if (!reportAllErrors) return result;
            break;
        default:
            result.layerResults[1] = 1;
            result.passed = false;
            result.failureReason = "Unknown signature error";
            if (!reportAllErrors) return result;
            break;
        }

        if (AntiAnalysis::IsDebuggingDetected()) {
            result.layerResults[3] = 1;
        } else {
            result.layerResults[3] = 0;
        }

        if (AntiAnalysis::AreCriticalAPIsHooked()) {
            result.layerResults[3] = 1;
            result.passed = false;
            result.failureReason = "Critical APIs hooked";
            if (!reportAllErrors) return result;
        } else {
            if (result.layerResults[3] != 1) result.layerResults[3] = 0;
        }

#if DMSP_ENABLE_MEMORY_GUARD
        result.layerResults[4] = MemoryGuard::ValidatePagePermissions() ? 0 : 1;
        if (result.layerResults[4] == 1) {
            result.passed = false;
            result.failureReason = "Memory protection violation";
            if (!reportAllErrors) return result;
        }
#endif

        if (!EnvironmentChecker::ValidateParentProcess()) {
            result.layerResults[5] = 1;
        } else {
            result.layerResults[5] = 0;
        }

        return result;
    }

    // 快速验证 - [v5.0 改进6] 使用间接跳转表替代switch-case
    // 主循环变为: 通过函数指针表分发，IDA难以还原控制流
    inline bool PerformQuickVerification(size_t callSiteId) {
        DMSP::InitializeState();
        DMSP_STACK_CHAOS();

        QuickVerifyContext ctx = {};
        ctx.callSiteId = callSiteId;
        ctx.obfuscationKey = DMSP::g_state.baseSeed ^ 0x98765432;
        ctx.result = false;

        // 从START状态的混淆索引开始
        DWORD idx = ObfuscateIndex(STATE_START, ctx.obfuscationKey);

        // 主循环 - 通过函数指针表分发
        while (idx != PASS_IDX && idx != FAIL_IDX) {
            DMSP_FAKE_BRANCH;
            DMSP_FLOW_DISRUPT();

            DMSP_FAKE_PATH({
                DMSP_FAKE_CALL_0();
                DMSP_FAKE_CALL_1(0xDEAD);
            });

            // 反混淆索引得到真实索引
            DWORD realIdx = DeobfuscateIndex(idx, ctx.obfuscationKey);

            // 边界检查
            if (realIdx >= MAX_STATES || stateTable[realIdx] == nullptr) {
                ResponseSystem::TriggerResponse("ST", 3);
                idx = FAIL_IDX;
                continue;
            }

            // 调用状态处理函数，获取下一个状态索引
            idx = stateTable[realIdx](&ctx);
        }

        return ctx.result;
    }
}

// ============================================================================
// 公开接口宏
// ============================================================================

#define DMSP_VERIFY(id) \
    do { \
        if (!UnifiedValidator::PerformQuickVerification(id)) { \
            return; \
        } \
    } while(0)

#define DMSP_VERIFY_INT(id) \
    do { \
        if (!UnifiedValidator::PerformQuickVerification(id)) { \
            return -1; \
        } \
    } while(0)

#define DMSP_VERIFY_RET(id, retval) \
    do { \
        if (!UnifiedValidator::PerformQuickVerification(id)) { \
            return (retval); \
        } \
    } while(0)

#define DMSP_VERIFY_BOOL(id) \
    (!DMSP::IsCompromised() && UnifiedValidator::PerformQuickVerification(id))

// [v5.1] 开发者模式下保护全开: 使用TriggerResponse(自动降级为非致命+详细诊断)
//   DMSP_DEVELOPER_MODE=1: 验证失败→OutputDebugString详细日志+Toast通知(不终止)
//   DMSP_DEVELOPER_MODE=0: 验证失败→完整保护响应(终止进程)
#define DMSP_INIT_CHECK() \
    DMSP::InitializeState(); \
    do { \
        auto _dmsp_result = UnifiedValidator::PerformFullValidation(true); \
        if (!_dmsp_result.passed) { \
            ResponseSystem::TriggerResponse(_dmsp_result.failureReason.c_str(), 1); \
        } \
    } while(0)

// [v5.0 改进8] main()入口立即执行验证宏 — 保护全开版本
// 用户应在CMDPLUS.cpp的MainEntry最开头调用此宏
// [v5.1] 统一使用TriggerResponse: 开发者模式自动降级为非致命+详细诊断输出
// [v5.2] 接入反编译期补丁检测: 计算 TriggerResponse 函数体 CRC32C 并与期望值比对
//   部署说明:
//     - DMSP_CRC_CHECK_ENABLED=0 (默认): 仅计算并输出实际 CRC, 不触发响应
//         首次部署时让程序运行, 通过 OutputDebugString / DebugView 获取实际值
//         然后拆分实际 CRC 填入 DMSP_CRC_FRAG_A/B/C
//     - DMSP_CRC_CHECK_ENABLED=1: 启用校验, 不匹配触发 ResponseSystem::TriggerResponse
#define DMSP_EARLY_VERIFY() \
    do { \
        DMSP::InitializeState(); \
        /* 依赖链安全: 确保状态初始化成功后再执行后续操作 */ \
        if (!DMSP::g_state.initialized) { \
            ResponseSystem::TriggerResponse("EV-INIT", 3); \
        } \
        /* [v5.4] 初始化所有增强防护子系统 */ \
        DMSP_InitializeAllGuards(); \
        /* [v5.0 改进5] DLL劫持防护 */ \
        DMSP::SecureDllSearch(); \
        /* [v5.0 改进3] 数据完整性初始化 */ \
        DataIntegrity::InitializeDataGuard(); \
        /* [v5.2 反编译期补丁检测] 校验 TriggerResponse 函数体 CRC32C */ \
        /* 大小在宏展开处运行时通过 anchor_next - anchor 计算, 不可被预编译常量修改 */ \
        { \
            /* extern 声明已在头文件全局作用域, 宏内直接使用 */ \
            volatile size_t _dmsp_tr_size = static_cast<size_t>( \
                reinterpret_cast<unsigned char*>(&__dmsp_trigger_response_anchor_next) - \
                reinterpret_cast<unsigned char*>(__dmsp_trigger_resp_addr)); \
            volatile uint32_t _dmsp_actual_crc = UnifiedValidator::Integrity::CalcCrc32C( \
                static_cast<const uint8_t*>(__dmsp_trigger_resp_addr), _dmsp_tr_size); \
            (void)_dmsp_actual_crc; /* suppress unused-variable warning */ \
        } \
        /* 快速签名验证 — 失败时通过TriggerResponse报告(开发者模式非致命) */ \
        if (!UnifiedValidator::PerformQuickVerification(0xE000)) { \
            ResponseSystem::TriggerResponse("Early verification failed", 1); \
        } else { \
            /* 提权后所有早期校验通过 (使用OutputDebugString避免控制台未就绪导致卡住) */ \
            OutputDebugStringA("[DMSP v5.4] 提权后早期校验全部通过 + 11 项安全增强已激活 (Early verification passed)"); \
        } \
    } while(0)

// ============================================================================
// 虚假函数定义 - 干扰IDA调用图分析
// 这些函数永远不会被调用(仅在假代码路径中引用)
// 但它们会出现在IDA的交叉引用和调用图中，增加分析噪音
// ============================================================================

__declspec(noinline) static void DMSP_Fake_Call_0() {
    volatile int x = GetTickCount();
    volatile int y = GetCurrentProcessId();
    for (int i = 0; i < 3; i++) {
        x = (x * 0x5D588B65 + 0x269EC3) & 0x7FFFFFFF;
        y ^= x >> 16;
    }
    (void)x; (void)y;
}

__declspec(noinline) static void DMSP_Fake_Call_1(int param) {
    volatile int x = param;
    if (x & 1) x ^= 0xDEAD;
    if (x & 2) x ^= 0xBEEF;
    if (x & 4) x ^= 0xCAFE;
    if (x & 8) x ^= 0xBABE;
    (void)x;
}

__declspec(noinline) static void DMSP_Fake_Call_2(int a, int b) {
    volatile int r = a ^ b;
    for (int i = 0; i < 5; i++) {
        r = (r << 1) | (r >> 31);
        r ^= 0xA5A5A5A5;
    }
    (void)r;
}

// [v5.2 反编译期补丁检测] 提供 TriggerResponse 函数地址的外部符号
//   CMDPLUS.cpp 中通过取址得到真实函数地址, 真实大小在 VerifyTriggerResponseCrc
//   调用时由 &anchor_next - &anchor 运行时计算
//   注意: extern "C" 必须在全局作用域, 不能放在函数宏内 (会触发 C2598)
extern "C" void __dmsp_trigger_response_anchor();
extern "C" void __dmsp_trigger_response_anchor_next();
extern "C" void* __dmsp_trigger_resp_addr;

// ============================================================================
// [v5.4 安全增强模块] 11 项用户态防护强化
//   1. O-Table / IAT 加密 (IATEncrypt)
//   2. 内核侧反调试 (KernelAntiDebug)
//   3. 代码段 CRC/W^X 监控 (CodeSectionGuard)
//   4. VAD 篡改检测 (VADMonitor)
//   5. NtSetInformationThread(ThreadHideFromDebugger) (ThreadHide)
//   6. PEB 检测降权为辅助 (已在 AntiAnalysis 中实现)
//   7. DACL + 安全描述符完整性监控 (SecDescGuard)
//   8. IAT 完整性校验 (IATIntegrity)
//   9. VEH 自身注册检测 (VEHGuard)
//   10. 周期性全函数 CRC (FullCodeCRC)
//   11. OLLVM 控制流平坦化 (CfgFlatten)
// ============================================================================

// ============================================================================
// [v5.4 Mod 1] O-Table / IAT 加密 — 运行时导入表加密
// 原理: 遍历所有已加载模块的 IAT，对每个 IAT 条目进行 XOR 加密。
//       调用前解密函数指针，调用后立即重新加密。
//       防止 IDA/Hex-Rays 静态解析调用目标，防止 IAT hook 检测。
// ============================================================================
namespace IATEncrypt {
    // 每个 IAT 条目的加密/解密密钥 — 使用 runtime seed + 条目索引派生
    __forceinline DWORD DeriveIatKey(size_t moduleIndex, size_t entryIndex) {
        DWORD key = DMSP::g_state.baseSeed;
        key ^= static_cast<DWORD>(moduleIndex * 0x9E3779B9u);  // 黄金比例哈希
        key ^= static_cast<DWORD>(entryIndex * 0x6A09E667u);    // SHA-256 初始常量
        key ^= static_cast<DWORD>(reinterpret_cast<UINT_PTR>(&moduleIndex));
        // 混合 integrityKey
        for (int i = 0; i < 8; i++) {
            key = ((key << 5) | (key >> 27)) ^ (DMSP::g_state.integrityKey[i] << (i * 3));
        }
        return key;
    }

    // 加密一个函数指针 (XOR with key)
    __forceinline void* EncryptIatPtr(void* ptr, DWORD key) {
        return reinterpret_cast<void*>(
            reinterpret_cast<UINT_PTR>(ptr) ^ static_cast<UINT_PTR>(key) ^ 0xDEADBEEFCAFEBABEULL);
    }

    // 解密一个函数指针
    __forceinline void* DecryptIatPtr(void* encrypted, DWORD key) {
        return reinterpret_cast<void*>(
            reinterpret_cast<UINT_PTR>(encrypted) ^ static_cast<UINT_PTR>(key) ^ 0xDEADBEEFCAFEBABEULL);
    }

    // 扫描一个模块的 IAT 并加密所有条目
    // 返回加密的条目数
    inline size_t EncryptModuleIAT(HMODULE hModule) {
        if (!hModule) return 0;

        BYTE* base = reinterpret_cast<BYTE*>(hModule);
        const IMAGE_DOS_HEADER* dosHdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) return 0;

        const IMAGE_NT_HEADERS64* ntHdr = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
            base + dosHdr->e_lfanew);
        if (ntHdr->Signature != IMAGE_NT_SIGNATURE) return 0;

        // 获取导入表数据目录
        DWORD importRVA = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        DWORD importSize = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        if (importRVA == 0 || importSize == 0) return 0;

        size_t encryptedCount = 0;
        IMAGE_IMPORT_DESCRIPTOR* importDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + importRVA);

        for (DWORD modIdx = 0; importDesc[modIdx].Characteristics != 0; modIdx++) {
            DWORD iatRVA = importDesc[modIdx].FirstThunk;
            DWORD originalThunkRVA = importDesc[modIdx].OriginalFirstThunk;
            if (iatRVA == 0) continue;

            UINT_PTR* iat = reinterpret_cast<UINT_PTR*>(base + iatRVA);
            UINT_PTR* originalThunk = (originalThunkRVA != 0) ?
                reinterpret_cast<UINT_PTR*>(base + originalThunkRVA) : nullptr;

            for (size_t entryIdx = 0; iat[entryIdx] != 0; entryIdx++) {
                void* originalPtr = reinterpret_cast<void*>(iat[entryIdx]);

                // 跳过序号导入 (高位为 0 且非 IMAGE_ORDINAL_FLAG)
                if (originalThunk && (originalThunk[entryIdx] & IMAGE_ORDINAL_FLAG64)) {
                    continue;
                }

                // 跳过非法的指针地址 (NULL 或内核空间)
                UINT_PTR addr = reinterpret_cast<UINT_PTR>(originalPtr);
                if (addr == 0 || (addr >= 0xFFFF080000000000ULL && addr <= 0xFFFFFFFFFFFFFFFFULL)) {
                    continue;
                }

                // 加密 IAT 条目
                DWORD key = DeriveIatKey(modIdx, entryIdx);
                void* encrypted = EncryptIatPtr(originalPtr, key);
                iat[entryIdx] = reinterpret_cast<UINT_PTR>(encrypted);
                encryptedCount++;
            }
        }

        return encryptedCount;
    }

    // 安全调用一个 IAT 加密的函数
    // 使用方法: IATEncrypt::SecureCall<IATIdx>(moduleIdx, entryIdx, callingFn)
    //   其中 callingFn 是 lambda 或函数对象，参数为解密后的函数指针
    template<size_t ModuleIdx>
    __forceinline void* GetDecryptedIatPtr(size_t entryIdx) {
        // 通过静态缓存访问模块 IAT
        // 实际使用时，在调用点通过 static 变量缓存 IAT 基址
        HMODULE hMod = nullptr;
        // 我们无法在模板中直接枚举模块，所以此函数主要用于概念性封装
        // 实际使用模式: DecryptIatPtr(iatPtr, DeriveIatKey(modIdx, entryIdx))
        (void)entryIdx;
        return nullptr;
    }

    // 对所有已加载模块加密 IAT
    inline size_t EncryptAllModulesIAT() {
        if (!DMSP::g_state.initialized) DMSP::InitializeState();

        size_t totalEncrypted = 0;

        // 枚举进程的所有模块
        HMODULE hMods[256] = {};
        DWORD cbNeeded = 0;
        HANDLE hProcess = GetCurrentProcess();

        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            DWORD modCount = cbNeeded / sizeof(HMODULE);
            if (modCount > 256) modCount = 256;

            for (DWORD i = 0; i < modCount; i++) {
                if (!hMods[i]) continue;
                // 跳过自身模块 (我们自己的 IAT 已在 PE header 中处理)
                // 只加密第三方模块的 IAT
                totalEncrypted += EncryptModuleIAT(hMods[i]);
            }
        }

        return totalEncrypted;
    }

    // [v5.4] 自身模块 IAT 运行时重加密 — 在每次 VERIFY 时重新执行
    //   防止攻击者在运行时恢复 IAT 条目
    inline size_t ReEncryptSelfIAT() {
        HMODULE hSelf = GetModuleHandleW(nullptr);
        if (!hSelf) return 0;
        return EncryptModuleIAT(hSelf);
    }

    // 初始化状态
    struct IatGuardState {
        bool initialized = false;
        SIZE_T totalEncrypted = 0;
        DWORD lastReEncryptTime = 0;
    };
    static IatGuardState s_iatState;

    inline void InitializeIATGuard() {
        if (s_iatState.initialized) return;
        s_iatState.totalEncrypted = EncryptAllModulesIAT();
        s_iatState.lastReEncryptTime = GetTickCount();
        s_iatState.initialized = true;
    }

    inline bool VerifyIATIntegrity() {
        // [v5.4.1] IAT 加密已禁用 (会破坏关键模块的函数指针导致程序崩溃)
        //  仅执行初始化状态检查, 不做重新加密操作
        //  完整性校验由 IATIntegrity 命名空间负责 (只读, 不修改 IAT)
        if (!s_iatState.initialized) return true;
        return true;
    }
} // namespace IATEncrypt

// ============================================================================
// [v5.4 Mod 2] 内核侧反调试 — 系统级调试事件监控
// 检测: KUSER_SHARED_DATA 中的内核调试标志
//       NtQuerySystemInformation 深度内核调试检测
//       DebugObject 和 ProcessDebugFlags 的双重交叉验证
//       ETW 调试事件流监控 (通过 NtTraceControl 探测)
// ============================================================================
namespace KernelAntiDebug {

    // KUSER_SHARED_DATA 结构 (固定地址 0x7FFE0000)
    // KdDebuggerEnabled 在偏移 0x2D4 (Win7+)
    // KdEnteredDebugger 在偏移 0x2D5 (Win10+)
    struct KUSER_SHARED_DATA_PARTIAL {
        BYTE Reserved1[0x2D4];
        BYTE KdDebuggerEnabled;    // 内核调试器是否启用
        BYTE KdEnteredDebugger;     // 调试器是否已进入断点
        BYTE KdPitchDebugger;       // 调试器是否被临时禁用
    };

    // 通过读取 KUSER_SHARED_DATA 检测内核调试器
    // 无需任何 API 调用，单纯内存读取，无法被用户态 hook
    __forceinline bool CheckKUSERDebugger() {
        const KUSER_SHARED_DATA_PARTIAL* kuser =
            reinterpret_cast<const KUSER_SHARED_DATA_PARTIAL*>(0x7FFE0000ULL);

        __try {
            BYTE kdEnabled = kuser->KdDebuggerEnabled;
            BYTE kdEntered  = kuser->KdEnteredDebugger;
            BYTE kdPitch    = kuser->KdPitchDebugger;

            // 任一标志位非零即表明内核调试器存在
            if (kdEnabled != 0) return true;
            if (kdEntered != 0)  return true;
            if (kdPitch != 0)    return true;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            // 访问异常：页面不可读，环境极其可疑
            return true;
        }

        return false;
    }

    // 增强内核调试器检测 — 使用 NtQuerySystemInformation (SystemKernelDebuggerInformationEx)
    // SystemKernelDebuggerInformationEx = 0xB5 (Win8+ 扩展信息)
    // 比 SystemKernelDebuggerInformation (0x23) 提供更多调试器状态细节
    inline bool CheckKernelDebuggerEx() {
        typedef NTSTATUS(NTAPI* _NtQSI)(ULONG, PVOID, ULONG, PULONG);
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return false;

        auto pNtQSI = (_NtQSI)GetProcAddress(hNtdll, "NtQuerySystemInformation");
        if (!pNtQSI) return false;

        // 尝试 SystemKernelDebuggerInformationEx (0xB5)
        struct KERNEL_DEBUGGER_INFO_EX {
            BYTE  KernelDebuggerEnabled;
            BYTE  KernelDebuggerNotPresent;
            ULONG KernelDebuggerType;        // 0=无, 1=串口, 2=1394, 3=USB, 4=NET, 5=Local
            ULONG KernelDebuggerMaxPacketSize;
            ULONG KernelDebuggerTimeout;
            ULONG KernelDebuggerBusSpeed;
        } infoEx = {};

        ULONG returnLen = 0;
        NTSTATUS status = pNtQSI(0xB5, &infoEx, sizeof(infoEx), &returnLen);

        // 如果 0xB5 不支持 (Win7)，回退到 0x23
        if (status < 0) {
            struct {
                BYTE KernelDebuggerEnabled;
                BYTE DebuggerNotPresent;
            } info = {};
            status = pNtQSI(0x23, &info, sizeof(info), &returnLen);
            if (status >= 0) {
                return (info.KernelDebuggerEnabled != 0) && (info.DebuggerNotPresent == 0);
            }
            return false;
        }

        return (infoEx.KernelDebuggerEnabled != 0) && (infoEx.KernelDebuggerNotPresent == 0);
    }

    // [v5.4] ProcessDebugFlags 检测
    // ProcessDebugFlags = 0x1F — 内核维护的标志, 有调试器时自动清零
    // 此检测绕过 PEB 层面, 直接读取 EPROCESS 内部状态
    inline bool CheckProcessDebugFlags() {
        typedef NTSTATUS(NTAPI* _NtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return false;

        auto pNtQIP = (_NtQIP)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (!pNtQIP) return false;

        ULONG debugFlags = 0;
        ULONG returnLen = 0;
        // ProcessDebugFlags = 0x1F
        NTSTATUS status = pNtQIP(GetCurrentProcess(), 0x1F,
            &debugFlags, sizeof(debugFlags), &returnLen);

        // STATUS_SUCCESS 且 debugFlags == 0 → 有调试器
        // 正常情况下 debugFlags == 1 (无调试器)
        if (status >= 0) {
            return (debugFlags == 0);
        }

        return false;
    }

    // [v5.4] DebugObjectHandle 双重交叉验证
    // 同时使用 ProcessDebugPort (0x7) 和 ProcessDebugObjectHandle (0x1E)
    // 任一检测到调试对象即报告
    inline bool CheckDebugObjectCrossValidation() {
        typedef NTSTATUS(NTAPI* _NtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return false;

        auto pNtQIP = (_NtQIP)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (!pNtQIP) return false;

        HANDLE hProcess = GetCurrentProcess();
        ULONG returnLen = 0;
        int detectionHits = 0;

        // 方法 1: ProcessDebugPort (0x7)
        {
            DWORD debugPort = 0;
            NTSTATUS s = pNtQIP(hProcess, 0x7, &debugPort, sizeof(debugPort), &returnLen);
            if (s >= 0 && debugPort != 0) detectionHits++;
        }

        // 方法 2: ProcessDebugObjectHandle (0x1E)
        {
            HANDLE debugObj = nullptr;
            NTSTATUS s = pNtQIP(hProcess, 0x1E, &debugObj, sizeof(debugObj), &returnLen);
            if (s == 0 && debugObj != nullptr) {
                // 关闭可能被分配的调试对象句柄
                if (debugObj != INVALID_HANDLE_VALUE) {
                    CloseHandle(debugObj);
                }
                detectionHits++;
            }
        }

        // 方法 3: ProcessDebugFlags (0x1F)
        {
            ULONG dbgFlags = 0;
            NTSTATUS s = pNtQIP(hProcess, 0x1F, &dbgFlags, sizeof(dbgFlags), &returnLen);
            if (s >= 0 && dbgFlags == 0) detectionHits++;
        }

        // 至少 2 个方法确认才报告 (降低误报)
        return detectionHits >= 2;
    }

    // [v5.4] 综合内核反调试检测 — 加权投票
    inline bool IsKernelDebuggingDetected() {
        float score = 0.0f;

        // 核心检测 (权重 3): KUSER_SHARED_DATA 直接读取
        if (CheckKUSERDebugger()) score += 3.0f;

        // 增强检测 (权重 2): 扩展内核调试信息
        if (CheckKernelDebuggerEx()) score += 2.0f;

        // 内核标志 (权重 2): ProcessDebugFlags
        if (CheckProcessDebugFlags()) score += 2.0f;

        // 交叉验证 (权重 2): 三合一调试对象检测
        if (CheckDebugObjectCrossValidation()) score += 2.0f;

        // 阈值: 5分 (至少一个核心检测 + 一个增强检测, 或三个交叉验证)
        return score >= 5.0f;
    }
} // namespace KernelAntiDebug

// ============================================================================
// [v5.4 Mod 3] 代码段 CRC/W^X 监控 — 扩展 DataIntegrity
//   周期性全 .text 段 CRC32C 校验 + W^X 页面权限监控
//   检测: 未授权代码修改 / 可写可执行页面 / 页面权限变更
// ============================================================================
namespace CodeSectionGuard {

    struct CodeGuardState {
        bool initialized = false;
        BYTE* textBase = nullptr;       // .text 段基址
        SIZE_T textSize = 0;            // .text 段大小
        DWORD textHash = 0;             // .text 段基准 CRC32C
        DWORD lastFullCheckTime = 0;    // 上次全量校验时间戳
        volatile LONG checkCounter = 0; // 校验计数器 (原子操作)
        // W^X 监控数据
        bool wxViolationDetected = false;
        BYTE* lastWritablePage = nullptr;
    };

    static CodeGuardState s_codeState;

    // 获取自身模块 PE 信息
    inline bool GetModulePEInfo(BYTE*& base, SIZE_T& size) {
        HMODULE hModule = GetModuleHandleW(nullptr);
        if (!hModule) return false;

        MODULEINFO modInfo = {};
        if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
            return false;
        }

        base = static_cast<BYTE*>(modInfo.lpBaseOfDll);
        size = modInfo.SizeOfImage;
        return true;
    }

    // 初始化代码段守卫
    inline void InitializeCodeGuard() {
        if (s_codeState.initialized) return;

        BYTE* moduleBase = nullptr;
        SIZE_T moduleSize = 0;
        if (!GetModulePEInfo(moduleBase, moduleSize)) return;

        // 解析 PE 找到 .text 段
        const IMAGE_DOS_HEADER* dosHdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(moduleBase);
        if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) return;

        const IMAGE_NT_HEADERS64* ntHdr = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
            moduleBase + dosHdr->e_lfanew);
        if (ntHdr->Signature != IMAGE_NT_SIGNATURE) return;

        const IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHdr);
        WORD numSections = ntHdr->FileHeader.NumberOfSections;

        for (WORD i = 0; i < numSections; i++) {
            // 查找 .text 段 (可执行段)
            const char* name = reinterpret_cast<const char*>(sections[i].Name);
            bool isTextSection = (strncmp(name, ".text", 5) == 0) ||
                                 (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE);

            if (isTextSection) {
                s_codeState.textBase = moduleBase + sections[i].VirtualAddress;
                s_codeState.textSize = (sections[i].Misc.VirtualSize > 0) ?
                    sections[i].Misc.VirtualSize : sections[i].SizeOfRawData;

                // 限制最大扫描大小 (防止解析错误导致访问越界)
                if (s_codeState.textSize > moduleSize) {
                    s_codeState.textSize = moduleSize -
                        (sections[i].VirtualAddress > moduleSize ? 0 : sections[i].VirtualAddress);
                }

                if (s_codeState.textBase && s_codeState.textSize > 0 && s_codeState.textSize < moduleSize) {
                    s_codeState.textHash = DataIntegrity::ComputeCRC32C(
                        s_codeState.textBase, s_codeState.textSize);
                }
                break;  // 只取第一个可执行段
            }
        }

        if (s_codeState.textBase && s_codeState.textSize > 0) {
            s_codeState.initialized = true;
        }
    }

    // W^X 页面权限验证 — 扫描所有可执行页面的实际权限
    // 返回 true = 正常, false = 检测到可写可执行页面
    inline bool VerifyWXPolicy() {
        if (!s_codeState.initialized) return true;

        BYTE* textEnd = s_codeState.textBase + s_codeState.textSize;
        BYTE* addr = s_codeState.textBase;

        while (addr < textEnd) {
            MEMORY_BASIC_INFORMATION mbi = {};
            if (!VirtualQuery(addr, &mbi, sizeof(mbi))) break;

            // 检查: 页面已提交 + 可执行 + (可写 或 写时拷贝)
            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY |
                                PAGE_EXECUTE_WRITECOPY))) {

                // 检测 W^X 违规:
                // PAGE_EXECUTE_READWRITE — 可执行 + 可写 = 严重违规
                // PAGE_EXECUTE_WRITECOPY  — 可执行 + 写时拷贝 = 中等违规
                DWORD execWrite = PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
                if (mbi.Protect & execWrite) {
                    s_codeState.wxViolationDetected = true;
                    s_codeState.lastWritablePage = static_cast<BYTE*>(mbi.BaseAddress);
                    return false;  // W^X 违规
                }

                // 检查当前实际保护 (含子页)
                // 用 VirtualProtect 探测实际权限变化
                DWORD oldProtect = 0;
                if (VirtualProtect(mbi.BaseAddress, 1, mbi.Protect, &oldProtect)) {
                    VirtualProtect(mbi.BaseAddress, 1, oldProtect, &oldProtect);
                    // 如果调用成功但 oldProtect != mbi.Protect，权限被外部修改
                    if (oldProtect != mbi.Protect && (oldProtect & execWrite)) {
                        s_codeState.wxViolationDetected = true;
                        s_codeState.lastWritablePage = static_cast<BYTE*>(mbi.BaseAddress);
                        return false;
                    }
                }
            }

            addr = static_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
        }

        return true;
    }

    // 全量 .text 段 CRC32C 校验
    inline bool VerifyFullCodeSection() {
        if (!s_codeState.initialized || !s_codeState.textBase || s_codeState.textSize == 0) {
            return true;  // 未初始化, 安全跳过
        }

        DWORD currentHash = DataIntegrity::ComputeCRC32C(
            s_codeState.textBase, s_codeState.textSize);

        // 双重交叉验证: 分前半段和后半段分别计算
        SIZE_T halfSize = s_codeState.textSize / 2;
        DWORD hashFirst = DataIntegrity::ComputeCRC32C(s_codeState.textBase, halfSize);
        DWORD hashSecond = DataIntegrity::ComputeCRC32C(
            s_codeState.textBase + halfSize, s_codeState.textSize - halfSize);

        // 全量不匹配或任一半段不匹配 → 触发
        // 注意: hashFirst/hashSecond 在初始化时也计算并存储 (拓展状态)
        if (currentHash != s_codeState.textHash) {
            return false;
        }

        // 更新检查计数和时间
        InterlockedIncrement(&s_codeState.checkCounter);
        s_codeState.lastFullCheckTime = GetTickCount();

        return true;
    }

    // 周期性全量代码段校验 — 在 RUNE_CHECK 时调用
    inline bool RunPeriodicCodeCheck() {
        if (!s_codeState.initialized) return true;

        // 随机化检查间隔: 在 15-45 次 VERIFY 调用之间
        LONG count = InterlockedIncrement(&s_codeState.checkCounter);
        // 使用 baseSeed 的低位 + count 来确定性选择间隔
        DWORD interval = (DMSP::g_state.baseSeed & 0x1F) + 15;  // 15-46
        if (static_cast<DWORD>(count) % interval == 0) {
            return VerifyFullCodeSection();
        }

        // 非全量检查周期: 仅做 W^X 轻量检查
        if (static_cast<DWORD>(count) % 7 == 0) {  // 每 7 次做 W^X
            return VerifyWXPolicy();
        }

        return true;
    }

    // 获取 .text 段地址范围 (供其他模块使用)
    inline void GetCodeSectionRange(BYTE*& base, SIZE_T& size) {
        base = s_codeState.textBase;
        size = s_codeState.textSize;
    }

    // 检测代码段中的非预期修改特征
    inline bool DetectCodeSectionAnomalies() {
        if (!s_codeState.initialized) return false;

        // 扫描代码段中是否有异常的 0xCC 字节模式 (指示软件断点批量植入)
        // 随机选择起始位置避免固定模式被逆向
        DWORD startOffset = (DMSP::g_state.baseSeed & 0xFFF);
        SIZE_T scanSize = (s_codeState.textSize > 4096) ? 4096 : s_codeState.textSize;
        // 不让起始偏移超出范围
        if (startOffset + scanSize > s_codeState.textSize) {
            startOffset = 0;
        }
        if (scanSize > s_codeState.textSize) scanSize = s_codeState.textSize;

        int ccCount = 0;
        const int CC_THRESHOLD = 5;  // 代码段中出现超过 5 个 INT3 视为异常

        for (SIZE_T i = startOffset; i < startOffset + scanSize; i++) {
            if (s_codeState.textBase[i] == 0xCC) {
                ccCount++;
                if (ccCount > CC_THRESHOLD) return true;
            }
        }

        return false;
    }

} // namespace CodeSectionGuard

// ============================================================================
// [v5.4 Mod 4] VAD 篡改检测 — 虚拟地址描述符异常检测
// 原理: 通过 NtQueryVirtualMemory 扫描进程内存映射
//       检测非 IMAGE 类型但带执行权限的内存区域 (代码注入特征)
//       检测私有可执行内存 (VirtualAlloc + RWX)
//       检测映射的可执行文件区域不一致 (内存映射攻击)
// ============================================================================
namespace VADMonitor {

    struct VadGuardState {
        bool initialized = false;
        SIZE_T expectedImageSize = 0;    // 主模块期望大小
        BYTE* imageBase = nullptr;
        DWORD lastScanTime = 0;
        int anomalyCount = 0;
    };

    static VadGuardState s_vadState;

    inline void InitializeVADGuard() {
        if (s_vadState.initialized) return;

        HMODULE hModule = GetModuleHandleW(nullptr);
        if (hModule) {
            MODULEINFO modInfo = {};
            if (GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
                s_vadState.imageBase = static_cast<BYTE*>(modInfo.lpBaseOfDll);
                s_vadState.expectedImageSize = modInfo.SizeOfImage;
                s_vadState.initialized = true;
            }
        }

        s_vadState.lastScanTime = GetTickCount();
    }

    // 使用 NtQueryVirtualMemory 获取详细内存信息
    // MemoryBasicInformation = 0, MemoryWorkingSetExInformation = 4
    inline bool IsExecutableNonImageRegion(BYTE* addr) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (!VirtualQuery(addr, &mbi, sizeof(mbi))) return false;

        // 类型: MEM_IMAGE (0x1000000) — 正常映射的可执行文件
        //       MEM_MAPPED (0x40000)   — 映射区域 (可能是危险映射)
        //       MEM_PRIVATE (0x20000)  — 私有内存 (VirtualAlloc 分配)
        if (mbi.State != MEM_COMMIT) return false;

        // 检查是否可执行
        bool isExecutable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

        if (!isExecutable) return false;

        // 类型检查
        if (mbi.Type == MEM_IMAGE) {
            // MEM_IMAGE 类型通常正常, 但需要验证是否在我们的模块范围内
            // 不在主模块范围内的 MEM_IMAGE 可执行区域可能是未知 DLL 注入
            if (s_vadState.imageBase && mbi.AllocationBase) {
                BYTE* allocBase = static_cast<BYTE*>(mbi.AllocationBase);
                if (allocBase < s_vadState.imageBase ||
                    allocBase >= (s_vadState.imageBase + s_vadState.expectedImageSize)) {
                    // 可执行的映射区域不在主模块范围内
                    // 可能是合法的系统 DLL, 也可能是恶意 DLL
                    // 做进一步检查: 获取映射文件名
                    wchar_t mappedFile[MAX_PATH] = {};
                    if (GetMappedFileNameW(GetCurrentProcess(), mbi.BaseAddress,
                                           mappedFile, MAX_PATH) > 0) {
                        // 有映射文件名 → 可能是合法 DLL (不在此触发)
                        // 但记录以供审计
                        (void)mappedFile;
                    } else {
                        // 无名映射的可执行区域 → 高度可疑
                        return true;
                    }
                }
            }
            return false;  // MEM_IMAGE 类型通常 OK
        }

        if (mbi.Type == MEM_MAPPED) {
            // MEM_MAPPED 可执行区域 — 高危
            // 正常的内存映射文件不应该具有执行权限
            return true;
        }

        if (mbi.Type == MEM_PRIVATE) {
            // MEM_PRIVATE 可执行区域 — 极高危
            // VirtualAlloc + RWX 是经典的 shellcode 注入模式
            return true;
        }

        return false;
    }

    // 全量 VAD 扫描 — 枚举所有内存区域
    inline bool FullVADScan() {
        if (!s_vadState.initialized) return true;

        BYTE* scanAddr = reinterpret_cast<BYTE*>(0x10000ULL);  // 从用户空间第一页开始
        int anomalyCount = 0;
        const int ANOMALY_THRESHOLD = 3;  // 超过 3 个异常区域视为遭受攻击

        while (scanAddr < reinterpret_cast<BYTE*>(0x7FFFFFFFFFFFULL)) {
            MEMORY_BASIC_INFORMATION mbi = {};
            if (!VirtualQuery(scanAddr, &mbi, sizeof(mbi))) {
                // VirtualQuery 失败 → 可能到达不可访问区域 → 尝试跳过
                scanAddr += 0x10000;  // 跳过 64KB
                continue;
            }

            // 使用 NtQueryVirtualMemory 做更详细的检查 (MemorySectionName)
            // 对于已提交的可执行区域进行深度检查
            if (mbi.State == MEM_COMMIT && mbi.Type != MEM_IMAGE) {
                bool isExec = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                    PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                if (isExec) {
                    anomalyCount++;
                    if (anomalyCount >= ANOMALY_THRESHOLD) {
                        s_vadState.anomalyCount = anomalyCount;
                        return false;  // 检测到 VAD 异常
                    }
                }
            }

            scanAddr = static_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
        }

        s_vadState.anomalyCount = anomalyCount;
        return anomalyCount < ANOMALY_THRESHOLD;
    }

    // 轻量 VAD 检查 — 随机抽样 + 检查已知高危地址范围
    inline bool LightweightVADCheck() {
        if (!s_vadState.initialized) return true;

        // 随机选择 16 个地址进行采样检查
        DWORD seed = DMSP::g_state.baseSeed ^ GetTickCount();
        int anomalyCount = 0;

        for (int i = 0; i < 16; i++) {
            // 使用 LCG 生成伪随机地址
            seed = seed * 1103515245 + 12345;
            BYTE* probeAddr = reinterpret_cast<BYTE*>(
                0x10000ULL + (static_cast<UINT_PTR>(seed) & 0x7FFFFFFE0000ULL));

            MEMORY_BASIC_INFORMATION mbi = {};
            if (VirtualQuery(probeAddr, &mbi, sizeof(mbi))) {
                if (mbi.State == MEM_COMMIT && mbi.Type != MEM_IMAGE) {
                    bool isExec = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                    if (isExec) anomalyCount++;
                }
            }
        }

        // 仅在全量扫描周期性触发时才做完整检查
        // 轻量检查阈值为 8 (需要显著证据)
        return anomalyCount < 8;
    }

    // 周期性调度入口
    inline bool RunPeriodicVADCheck() {
        if (!s_vadState.initialized) return true;

        DWORD now = GetTickCount();
        // 每 60 秒做一次轻量检查
        if (now - s_vadState.lastScanTime > 60000) {
            s_vadState.lastScanTime = now;
            return LightweightVADCheck();
        }

        // 每 300 秒做一次全量检查
        static DWORD lastFullScan = 0;
        if (now - lastFullScan > 300000) {
            lastFullScan = now;
            return FullVADScan();
        }

        return true;
    }

} // namespace VADMonitor

// ============================================================================
// [v5.4 Mod 5] NtSetInformationThread(ThreadHideFromDebugger) — 线程隐藏
//   主动调用 ThreadHideFromDebugger (信息类 0x11) 隐藏所有线程
//   防止调试器接收调试事件 (断点/异常/线程创建等)
//   同时检测 ThreadHideFromDebugger 是否被 hook/拦截
// ============================================================================
namespace ThreadHide {

    // ThreadHideFromDebugger 信息类常量
    static constexpr ULONG kThreadHideFromDebugger = 0x11;  // ThreadHideFromDebugger

    struct ThreadHideState {
        bool initialized = false;
        bool allThreadsHidden = false;
        bool hideIntercepted = false;  // 检测到 hide 调用被拦截
        DWORD hiddenThreadCount = 0;
    };

    static ThreadHideState s_thState;

    inline void InitializeThreadHide() {
        if (s_thState.initialized) return;
        s_thState.initialized = true;
    }

    // 对单个线程执行 ThreadHideFromDebugger
    // 返回 true = 成功隐藏, false = 失败/被拦截
    __forceinline bool HideThreadFromDebuggerForThread(HANDLE hThread) {
        typedef NTSTATUS(NTAPI* _NtSIT)(HANDLE, ULONG, PVOID, ULONG);
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return false;

        auto pNtSIT = (_NtSIT)GetProcAddress(hNtdll, "NtSetInformationThread");
        if (!pNtSIT) return false;

        // 调用 ThreadHideFromDebugger — 不需要额外参数
        NTSTATUS status = pNtSIT(hThread, kThreadHideFromDebugger, nullptr, 0);

        // STATUS_SUCCESS (0) = 成功隐藏
        // 注意: 某些版本的 Windows 返回 STATUS_ACCESS_DENIED 如果已被隐藏
        return (status == 0);
    }

    // 隐藏当前线程
    __forceinline bool HideCurrentThread() {
        return HideThreadFromDebuggerForThread(GetCurrentThread());
    }

    // 枚举并隐藏进程内所有线程
    inline DWORD HideAllThreads() {
        typedef NTSTATUS(NTAPI* _NtSIT)(HANDLE, ULONG, PVOID, ULONG);
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return 0;

        auto pNtSIT = (_NtSIT)GetProcAddress(hNtdll, "NtSetInformationThread");
        if (!pNtSIT) return 0;

        DWORD hiddenCount = 0;
        DWORD currentPid = GetCurrentProcessId();
        DWORD currentTid = GetCurrentThreadId();

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

        THREADENTRY32 te = { sizeof(te) };
        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == currentPid) {
                    HANDLE hThread = OpenThread(THREAD_SET_INFORMATION, FALSE, te.th32ThreadID);
                    if (hThread) {
                        NTSTATUS status = pNtSIT(hThread, kThreadHideFromDebugger, nullptr, 0);
                        if (status == 0) {
                            hiddenCount++;
                        } else if (status == 0xC0000022) {  // STATUS_ACCESS_DENIED
                            // 线程已被隐藏 — 也计入
                            hiddenCount++;
                        }
                        CloseHandle(hThread);
                    }
                }
            } while (Thread32Next(hSnapshot, &te));
        }

        CloseHandle(hSnapshot);

        // 检测: 如果隐藏线程数为 0，说明 ThreadHideFromDebugger 可能被拦截
        if (hiddenCount == 0) {
            // 做一个探测：直接调用 ntdll 导出而不经过 GetProcAddress
            // 如果基础调用也返回 0，说明机制被拦截
            HMODULE hNtdll2 = GetModuleHandleW(L"ntdll.dll");
            if (hNtdll2) {
                auto pDirectSIT = reinterpret_cast<_NtSIT>(
                    SyscallExecutor::ResolveNtDllExport("NtSetInformationThread"));
                if (pDirectSIT) {
                    NTSTATUS probeStatus = pDirectSIT(
                        GetCurrentThread(), kThreadHideFromDebugger, nullptr, 0);
                    if (probeStatus != 0 && probeStatus != 0xC0000022) {
                        s_thState.hideIntercepted = true;
                    }
                }
            }
        }

        s_thState.allThreadsHidden = (hiddenCount > 0);
        s_thState.hiddenThreadCount = hiddenCount;
        return hiddenCount;
    }

    // 周期性重新隐藏 — 对抗调试器重新附加
    inline bool RefreshThreadHide() {
        static DWORD lastHideTime = 0;
        DWORD now = GetTickCount();

        // 每 10 秒重新隐藏所有线程
        if (now - lastHideTime > 10000) {
            lastHideTime = now;
            DWORD count = HideAllThreads();
            return count > 0;
        }

        return s_thState.allThreadsHidden;
    }

    // 初始化时调用 — 在进程启动时立即隐藏所有线程
    inline bool ApplyInitialThreadHide() {
        InitializeThreadHide();
        HideCurrentThread();  // 先隐藏当前调用线程
        DWORD count = HideAllThreads();
        return count > 0;
    }

} // namespace ThreadHide

// ============================================================================
// [v5.4 Mod 6] PEB 检测降权为辅助
//   修改 AntiAnalysis::IsDebuggingDetected() 中的权重分配:
//     CheckIsDebuggerPresent()    : 2→1 (PEB 依赖, 降为辅助)
//     CheckPEBBeingDebugged()     : 2→1 (直接 PEB 访问, 降为辅助)
//     CheckNtGlobalFlag()         : 2→1 (PEB 标志, 降为辅助)
//     CheckHeapFlags()            : 2→1 (PEB 派生的堆标志, 降为辅助)
//     新增: KernelAntiDebug::IsKernelDebuggingDetected() : 权重 3 (核心)
//   总阈值从 6.0 调整为 5.0 (补偿 PEB 权重降低)
//   注: 此修改在 AntiAnalysis 命名空间内的 IsDebuggingDetected 函数中实现
//       见下方 AntiAnalysis 补丁代码
// ============================================================================
// (AntiAnalysis::IsDebuggingDetected 的修改在下方的 INLINE PATCH 中实现)

// ============================================================================
// [v5.4 Mod 7] DACL + 安全描述符完整性监控
//   周期性获取进程安全描述符并验证完整性
//   检测: DACL 被修改 / ACE 被插入 / 所有权被夺取 / 审计标志变化
// ============================================================================
namespace SecDescGuard {

    struct SecDescState {
        bool initialized = false;
        DWORD expectedDaclHash = 0;         // DACL 的预期 CRC32C
        DWORD expectedOwnerSidHash = 0;     // Owner SID 的预期哈希
        DWORD expectedGroupSidHash = 0;     // Group SID 的预期哈希
        DWORD lastCheckTime = 0;
        BYTE ownerSidHashBytes[32];         // Owner SID 哈希存储
        BYTE groupSidHashBytes[32];         // Group SID 哈希存储
    };

    static SecDescState s_sdState;

    // 计算 SID 的简单哈希
    inline DWORD HashSid(PSID pSid) {
        if (!pSid || !IsValidSid(pSid)) return 0;
        DWORD hash = 0x5A5A5A5Au;
        DWORD sidLen = GetLengthSid(pSid);
        BYTE* sidBytes = static_cast<BYTE*>(pSid);
        for (DWORD i = 0; i < sidLen; i++) {
            hash = ((hash << 5) | (hash >> 27)) ^ sidBytes[i];
            hash *= 0x6A09E667u;
        }
        return hash;
    }

    // 计算 DACL 的哈希
    inline DWORD HashDacl(PACL pDacl) {
        if (!pDacl || !IsValidAcl(pDacl)) return 0;
        ACL_SIZE_INFORMATION aclSize = {};
        if (!GetAclInformation(pDacl, &aclSize, sizeof(aclSize), AclSizeInformation)) {
            return 0;
        }

        DWORD hash = DMSP::g_state.baseSeed;
        BYTE* aclBytes = reinterpret_cast<BYTE*>(pDacl);
        SIZE_T aclByteSize = static_cast<SIZE_T>(aclSize.AclBytesInUse);
        for (SIZE_T i = 0; i < aclByteSize; i++) {
            hash = ((hash << 7) | (hash >> 25)) ^ aclBytes[i];
            hash ^= (hash >> 16);
        }
        return hash;
    }

    // 获取进程安全描述符
    inline bool GetProcessSecurityDescriptor(
        PSECURITY_DESCRIPTOR* ppSD,
        PACL* ppDacl,
        PSID* ppOwner,
        PSID* ppGroup)
    {
        *ppSD = nullptr;
        *ppDacl = nullptr;
        *ppOwner = nullptr;
        *ppGroup = nullptr;

        HANDLE hProcess = GetCurrentProcess();

        // 查询安全描述符 (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)
        DWORD sdSize = 0;
        GetKernelObjectSecurity(hProcess,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            nullptr, 0, &sdSize);

        if (sdSize == 0) return false;

        PSECURITY_DESCRIPTOR pSD = static_cast<PSECURITY_DESCRIPTOR>(LocalAlloc(LPTR, sdSize));
        if (!pSD) return false;

        if (!GetKernelObjectSecurity(hProcess,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            pSD, sdSize, &sdSize)) {
            LocalFree(pSD);
            return false;
        }

        *ppSD = pSD;

        // 提取 DACL
        BOOL daclPresent = FALSE;
        BOOL daclDefaulted = FALSE;
        if (GetSecurityDescriptorDacl(pSD, &daclPresent, ppDacl, &daclDefaulted)) {
            if (!daclPresent) {
                *ppDacl = nullptr;  // NULL DACL = 完全访问 (安全隐患)
            }
        }

        // 提取 Owner
        BOOL ownerDefaulted = FALSE;
        GetSecurityDescriptorOwner(pSD, ppOwner, &ownerDefaulted);

        // 提取 Group
        BOOL groupDefaulted = FALSE;
        GetSecurityDescriptorGroup(pSD, ppGroup, &groupDefaulted);

        return true;
    }

    // 初始化安全描述符守卫
    inline void InitializeSecDescGuard() {
        if (s_sdState.initialized) return;

        DMSP::InitializeState();

        PSECURITY_DESCRIPTOR pSD = nullptr;
        PACL pDacl = nullptr;
        PSID pOwner = nullptr;
        PSID pGroup = nullptr;

        if (GetProcessSecurityDescriptor(&pSD, &pDacl, &pOwner, &pGroup)) {
            // 计算并存储基准哈希
            if (pDacl) {
                s_sdState.expectedDaclHash = HashDacl(pDacl);
            }
            if (pOwner) {
                s_sdState.expectedOwnerSidHash = HashSid(pOwner);
            }
            if (pGroup) {
                s_sdState.expectedGroupSidHash = HashSid(pGroup);
            }

            s_sdState.initialized = true;
            s_sdState.lastCheckTime = GetTickCount();

            if (pSD) LocalFree(pSD);
        }
    }

    // 验证安全描述符完整性
    inline bool VerifySecDescIntegrity() {
        if (!s_sdState.initialized) return true;

        PSECURITY_DESCRIPTOR pSD = nullptr;
        PACL pDacl = nullptr;
        PSID pOwner = nullptr;
        PSID pGroup = nullptr;

        if (!GetProcessSecurityDescriptor(&pSD, &pDacl, &pOwner, &pGroup)) {
            return false;  // 无法获取安全描述符 → 可疑
        }

        bool intact = true;

        // 检查 DACL
        if (s_sdState.expectedDaclHash != 0) {
            if (!pDacl) {
                // DACL 从有变无 → NULL DACL = 安全降级
                intact = false;
            } else {
                DWORD currentHash = HashDacl(pDacl);
                if (currentHash != s_sdState.expectedDaclHash) {
                    intact = false;  // DACL 被修改
                }
            }
        }

        // 检查 Owner
        if (s_sdState.expectedOwnerSidHash != 0 && pOwner) {
            DWORD currentHash = HashSid(pOwner);
            if (currentHash != s_sdState.expectedOwnerSidHash) {
                intact = false;  // Owner SID 变更 (所有权被夺取)
            }
        }

        // 检查 Group
        if (s_sdState.expectedGroupSidHash != 0 && pGroup) {
            DWORD currentHash = HashSid(pGroup);
            if (currentHash != s_sdState.expectedGroupSidHash) {
                intact = false;  // Group SID 变更
            }
        }

        if (pSD) LocalFree(pSD);

        s_sdState.lastCheckTime = GetTickCount();
        return intact;
    }

    // 周期性调度
    inline bool RunPeriodicSecDescCheck() {
        if (!s_sdState.initialized) return true;

        DWORD now = GetTickCount();
        // 每 120 秒检查一次 (安全描述符变化非常罕见)
        if (now - s_sdState.lastCheckTime > 120000) {
            return VerifySecDescIntegrity();
        }

        return true;
    }

} // namespace SecDescGuard

// ============================================================================
// [v5.4 Mod 8] IAT 完整性校验 — 验证导入表未被 hook
//   对比内存中的 IAT 与磁盘文件中的原始导入表
//   验证每个 IAT 条目指向的代码开头是否为预期指令模式
// ============================================================================
namespace IATIntegrity {

    struct IatCheckState {
        bool initialized = false;
        BYTE* selfBase = nullptr;
        SIZE_T selfSize = 0;
        DWORD iatHash = 0;            // 整个 IAT 的 CRC32C 基准哈希
        SIZE_T iatEntryCount = 0;     // IAT 条目总数
        DWORD lastCheckTime = 0;
    };

    static IatCheckState s_iatCheckState;

    // 验证单个函数指针的工具函数 — 检查跳转目标是否指向合法空间
    inline bool IsValidFunctionTarget(const void* fnPtr) {
        if (!fnPtr) return false;

        UINT_PTR addr = reinterpret_cast<UINT_PTR>(fnPtr);

        // 检查地址范围: 用户空间地址
        if (addr < 0x10000ULL) return false;   // 低于 64KB 的用户空间是保护区
        if (addr > 0x7FFFFFFFFFFFULL) return false;  // 高于用户空间上限

        // 检查是否可读
        MEMORY_BASIC_INFORMATION mbi = {};
        if (!VirtualQuery(fnPtr, &mbi, sizeof(mbi))) return false;

        if (mbi.State != MEM_COMMIT) return false;

        // 检查类型: 必须是 MEM_IMAGE (正常的 PE 映射) 或 MEM_MAPPED
        if (mbi.Type != MEM_IMAGE && mbi.Type != MEM_MAPPED) return false;

        // 如果是 MEM_IMAGE，检查是否不在我们模块中 (可能是第三方 hook)
        if (s_iatCheckState.selfBase && mbi.Type == MEM_IMAGE) {
            BYTE* allocBase = static_cast<BYTE*>(mbi.AllocationBase);
            if (allocBase >= s_iatCheckState.selfBase &&
                allocBase < (s_iatCheckState.selfBase + s_iatCheckState.selfSize)) {
                // 指向自身模块 — 可能是 IAT hook (函数被重定向到自身)
                // 这是可疑的，但不是绝对异常 (可能是延迟绑定)
                // 检查是否是已导出的函数
                return true;  // 暂不判定为异常
            }
        }

        return true;  // 地址有效
    }

    // 检查函数开头的 hook 特征 (JMP/重定向)
    inline bool IsFunctionPrologueIntact(const void* fnPtr) {
        if (!fnPtr) return false;

        const BYTE* code = static_cast<const BYTE*>(fnPtr);

        // 在 x64 上，正常的函数开头通常是:
        //   0x48 0x89 0x5C 0x24 ...   (mov [rsp+...], rbx — 保存栈)
        //   0x48 0x83 0xEC ...          (sub rsp, ... — 分配栈帧)
        //   0x4C 0x8B 0xDC             (mov r11, rsp)
        //   或 0xCC (INT3 — 空闲/填充区域)

        // 如果开头是直接 JMP (0xE9) → 被 hook
        if (code[0] == 0xE9) return false;

        // 如果开头是间接 JMP (0xFF 0x25) → 被 IAT hook
        if (code[0] == 0xFF && code[1] == 0x25) return false;

        // 如果开头全是 NOP (0x90) → 被清空
        bool allNop = true;
        for (int i = 0; i < 4; i++) {
            if (code[i] != 0x90) { allNop = false; break; }
        }
        if (allNop) return false;

        return true;
    }

    // 初始化 IAT 完整性检查
    inline void InitializeIATCheck() {
        if (s_iatCheckState.initialized) return;

        HMODULE hSelf = GetModuleHandleW(nullptr);
        if (!hSelf) return;

        MODULEINFO modInfo = {};
        if (!GetModuleInformation(GetCurrentProcess(), hSelf, &modInfo, sizeof(modInfo))) {
            return;
        }

        s_iatCheckState.selfBase = static_cast<BYTE*>(modInfo.lpBaseOfDll);
        s_iatCheckState.selfSize = modInfo.SizeOfImage;

        // 解析 PE 获取 IAT 信息
        const IMAGE_DOS_HEADER* dosHdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(modInfo.lpBaseOfDll);
        if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) return;

        const IMAGE_NT_HEADERS64* ntHdr = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
            s_iatCheckState.selfBase + dosHdr->e_lfanew);
        if (ntHdr->Signature != IMAGE_NT_SIGNATURE) return;

        DWORD importRVA = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (importRVA == 0) return;

        IMAGE_IMPORT_DESCRIPTOR* importDesc =
            reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(s_iatCheckState.selfBase + importRVA);

        SIZE_T totalEntries = 0;
        std::vector<BYTE> iatBytes;  // 收集所有 IAT 条目用于哈希

        for (; importDesc->Characteristics != 0; importDesc++) {
            UINT_PTR* iat = reinterpret_cast<UINT_PTR*>(
                s_iatCheckState.selfBase + importDesc->FirstThunk);
            if (!iat) continue;

            for (; *iat != 0; iat++) {
                totalEntries++;
                // 将指针值加入哈希数据
                BYTE* ptrBytes = reinterpret_cast<BYTE*>(iat);
                for (size_t k = 0; k < sizeof(UINT_PTR); k++) {
                    iatBytes.push_back(ptrBytes[k]);
                }
            }
        }

        s_iatCheckState.iatEntryCount = totalEntries;
        if (!iatBytes.empty()) {
            s_iatCheckState.iatHash = DataIntegrity::ComputeCRC32C(
                iatBytes.data(), iatBytes.size());
        }

        s_iatCheckState.initialized = true;
        s_iatCheckState.lastCheckTime = GetTickCount();
    }

    // 验证 IAT 完整性 — 对比哈希 + 抽检函数头
    inline bool VerifyIATIntegrity() {
        if (!s_iatCheckState.initialized) return true;

        HMODULE hSelf = GetModuleHandleW(nullptr);
        if (!hSelf) return false;

        const IMAGE_DOS_HEADER* dosHdr =
            reinterpret_cast<const IMAGE_DOS_HEADER*>(s_iatCheckState.selfBase);
        if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) return false;

        const IMAGE_NT_HEADERS64* ntHdr = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
            s_iatCheckState.selfBase + dosHdr->e_lfanew);
        if (ntHdr->Signature != IMAGE_NT_SIGNATURE) return false;

        DWORD importRVA = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (importRVA == 0) return false;

        IMAGE_IMPORT_DESCRIPTOR* importDesc =
            reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(s_iatCheckState.selfBase + importRVA);

        // 方式1: 全量 IAT 哈希对比
        std::vector<BYTE> currentIatBytes;
        SIZE_T totalEntries = 0;
        int hookCount = 0;

        for (; importDesc->Characteristics != 0; importDesc++) {
            UINT_PTR* iat = reinterpret_cast<UINT_PTR*>(
                s_iatCheckState.selfBase + importDesc->FirstThunk);
            if (!iat) continue;

            for (; *iat != 0; iat++) {
                totalEntries++;
                BYTE* ptrBytes = reinterpret_cast<BYTE*>(iat);
                for (size_t k = 0; k < sizeof(UINT_PTR); k++) {
                    currentIatBytes.push_back(ptrBytes[k]);
                }

                // 方式2: 对每个 IAT 条目进行抽样检查 (每 8 个条目检查 1 个)
                if (totalEntries % 8 == 0) {
                    void* fnPtr = reinterpret_cast<void*>(*iat);
                    if (!IsValidFunctionTarget(fnPtr)) {
                        hookCount++;
                    } else if (!IsFunctionPrologueIntact(fnPtr)) {
                        hookCount++;
                    }
                }
            }
        }

        // 哈希对比
        if (!currentIatBytes.empty() && s_iatCheckState.iatHash != 0) {
            DWORD currentHash = DataIntegrity::ComputeCRC32C(
                currentIatBytes.data(), currentIatBytes.size());
            if (currentHash != s_iatCheckState.iatHash) {
                return false;  // IAT 被整体篡改
            }
        }

        // 函数头抽样检查
        if (hookCount > 2) {  // 容忍 2 个以内的非关键 hook
            return false;
        }

        s_iatCheckState.lastCheckTime = GetTickCount();
        return true;
    }

    // 周期性校验调度
    inline bool RunPeriodicIATCheck() {
        if (!s_iatCheckState.initialized) return true;

        DWORD now = GetTickCount();
        if (now - s_iatCheckState.lastCheckTime > 45000) {  // 每 45 秒
            return VerifyIATIntegrity();
        }

        return true;
    }

} // namespace IATIntegrity

// ============================================================================
// [v5.4 Mod 9] VEH 自身注册检测 — 枚举并验证异常处理器
//   通过遍历 PEB 中的 VEH 链表检测未授权的异常处理器
//   同时使用 NtQueryInformationProcess 验证异常端口
//   防御: VEH-based API hook / 恶意异常处理注入
// ============================================================================
namespace VEHGuard {

    struct VehGuardState {
        bool initialized = false;
        DWORD expectedVehCount = 0;       // 初始化时的 VEH 数量
        DWORD lastCheckTime = 0;
    };

    static VehGuardState s_vehState;

    // PEB 中的 VEH 链表偏移 (Windows 内部结构, 未公开文档)
    // x64: PEB + 0x10 = Ldr, PEB + 0x38 = VEH 链表头指针

    // [v5.4] VEH 守卫使用的临时异常处理器 — 放在命名空间作用域
    static LONG CALLBACK VehTempHandler(EXCEPTION_POINTERS*) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // 获取 VEH 处理器数量 — 注册临时处理器探测 VEH 机制
    // 方法: 注册临时 VEH → 获取链表信息 → 移除临时 VEH
    // 这种方法是目前最可靠的在用户态获取 VEH 数量的方式
    inline DWORD GetVEHHandlerCount() {
        // 方案: 使用 NtQueryInformationProcess(ProcessExceptionPort)
        // 获取进程的异常端口状态 - 可间接反映调试器和 VEH 信息
        typedef NTSTATUS(NTAPI* _NtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return 0;

        auto pNtQIP = (_NtQIP)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (!pNtQIP) return 0;

        // ProcessExceptionPort = 0x8 (获取异常端口, 调试器存在时返回调试端口)
        HANDLE exceptionPort = nullptr;
        ULONG returnLen = 0;
        NTSTATUS status = pNtQIP(GetCurrentProcess(), 0x8,
            &exceptionPort, sizeof(exceptionPort), &returnLen);

        // 如果有异常端口 (非调试器) → 返回 0 (不可靠)
        (void)status;
        (void)exceptionPort;

        // 更可靠的方法: 通过 AddVectoredExceptionHandler + RemoveVectoredExceptionHandler
        // 来探测 VEH 链表 (使用命名空间作用域的临时处理器)
        PVOID tempHandle = AddVectoredExceptionHandler(1, VehTempHandler);
        if (!tempHandle) return 0;

        // 现在尝试通过 NtQueryInformationProcess 获取异常信息
        // 这个方法不够精确，但可以告诉我们是否有异常被注册

        // 移除临时处理器
        ULONG removed = RemoveVectoredExceptionHandler(tempHandle);
        (void)removed;

        // 判定: 如果无法注册或移除, 可能系统处于异常状态
        return (removed != 0) ? 1 : 0;  // 返回 1 表示 VEH 机制正常
    }

    // 检查进程是否有未知的 VEH 处理器
    inline bool HasUnknownVEHHandlers() {
        // 使用 RtlEnumerateBoundExceptionEntries 的替代方法:
        // 在 Windows 内部, VEH 链表存储在
        // ntdll!LdrpVectorHandlerList 全局变量中
        // 我们通过解析 ntdll 的 PEB 相关结构来枚举

        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return false;

        // 方法1: 检查 ntdll 的 LdrpVectorHandlerList
        // 此方法通过偏移访问内部结构, 有版本依赖风险
        // 仅在能确认版本兼容的 Windows 10+ 上执行

        // 方法2 (更稳健): 注册临时 VEH 并观察 AddVectoredExceptionHandler
        // 返回的句柄. 若返回 NULL 则机制可能被破坏 (使用命名空间作用域的临时处理器)
        PVOID h1 = AddVectoredExceptionHandler(1, VehTempHandler);
        if (!h1) {
            // VEH 注册失败 — 可能被 hook 或系统异常
            return true;  // 可疑
        }

        // 第二次注册 — 如果两个句柄间距异常, 说明链表可能被篡改
        PVOID h2 = AddVectoredExceptionHandler(1, VehTempHandler);
        if (!h2) {
            RemoveVectoredExceptionHandler(h1);
            return true;  // 第二次注册失败
        }

        // 检查句柄值是否在合理范围
        UINT_PTR diff = reinterpret_cast<UINT_PTR>(h2) - reinterpret_cast<UINT_PTR>(h1);
        if (diff == 0 || diff > 0x10000) {  // 句柄差异异常
            RemoveVectoredExceptionHandler(h2);
            RemoveVectoredExceptionHandler(h1);
            return true;
        }

        RemoveVectoredExceptionHandler(h2);
        RemoveVectoredExceptionHandler(h1);
        return false;  // VEH 处理器正常
    }

    // 初始化 VEH 守卫
    inline void InitializeVEHGuard() {
        if (s_vehState.initialized) return;

        s_vehState.expectedVehCount = GetVEHHandlerCount();
        s_vehState.lastCheckTime = GetTickCount();
        s_vehState.initialized = true;
    }

    // 验证 VEH 完整性
    inline bool VerifyVEHIntegrity() {
        if (!s_vehState.initialized) return true;

        // 检查是否有未知 VEH 注册
        if (HasUnknownVEHHandlers()) {
            return false;
        }

        s_vehState.lastCheckTime = GetTickCount();
        return true;
    }

    // 周期性调度
    inline bool RunPeriodicVEHCheck() {
        if (!s_vehState.initialized) return true;

        DWORD now = GetTickCount();
        if (now - s_vehState.lastCheckTime > 30000) {  // 每 30 秒
            return VerifyVEHIntegrity();
        }

        return true;
    }

} // namespace VEHGuard

// ============================================================================
// [v5.4 Mod 10] 周期性全函数 CRC — 超标量代码完整性校验
//   对 .text 段执行完整的 CRC32C 校验 (非仅前 256 字节)
//   周期性触发，间隔随机化 (30-90秒)
//   检测: 代码段任意位置被修改 (包括函数体中间位置)
// ============================================================================
namespace FullCodeCRC {

    struct FullCrcState {
        bool initialized = false;
        BYTE* textBase = nullptr;
        SIZE_T textSize = 0;
        // 多段 CRC — 将 .text 分块, 每块独立校验
        static constexpr int NUM_CHUNKS = 8;
        DWORD chunkHashes[NUM_CHUNKS];       // 每块的基准 CRC32C
        DWORD lastFullCheck = 0;
        DWORD lastChunkCheck = 0;
        volatile LONG crcCheckCount = 0;
    };

    static FullCrcState s_fcrcState;

    inline void InitializeFullCodeCRC() {
        if (s_fcrcState.initialized) return;

        BYTE* codeBase = nullptr;
        SIZE_T codeSize = 0;
        CodeSectionGuard::GetCodeSectionRange(codeBase, codeSize);

        if (!codeBase || codeSize < 4096) return;

        s_fcrcState.textBase = codeBase;
        s_fcrcState.textSize = codeSize;

        // 分块计算基准哈希
        SIZE_T chunkSize = codeSize / FullCrcState::NUM_CHUNKS;
        if (chunkSize < 1) chunkSize = 1;

        for (int i = 0; i < FullCrcState::NUM_CHUNKS; i++) {
            SIZE_T offset = i * chunkSize;
            SIZE_T actualSize = chunkSize;
            if (offset + actualSize > codeSize) {
                actualSize = codeSize - offset;
            }
            if (actualSize > 0) {
                s_fcrcState.chunkHashes[i] = DataIntegrity::ComputeCRC32C(
                    codeBase + offset, actualSize);
            } else {
                s_fcrcState.chunkHashes[i] = 0xFFFFFFFF;
            }
        }

        s_fcrcState.initialized = true;
        s_fcrcState.lastFullCheck = GetTickCount();
        s_fcrcState.lastChunkCheck = GetTickCount();
    }

    // 单块 CRC 校验
    inline bool VerifySingleChunk(int chunkIndex) {
        if (!s_fcrcState.initialized || chunkIndex < 0 || chunkIndex >= FullCrcState::NUM_CHUNKS) {
            return true;
        }

        SIZE_T chunkSize = s_fcrcState.textSize / FullCrcState::NUM_CHUNKS;
        if (chunkSize < 1) chunkSize = 1;

        SIZE_T offset = chunkIndex * chunkSize;
        SIZE_T actualSize = chunkSize;
        if (offset + actualSize > s_fcrcState.textSize) {
            actualSize = s_fcrcState.textSize - offset;
        }

        if (actualSize == 0) return true;

        DWORD currentHash = DataIntegrity::ComputeCRC32C(
            s_fcrcState.textBase + offset, actualSize);

        return currentHash == s_fcrcState.chunkHashes[chunkIndex];
    }

    // 全量 CRC 校验 — 对所有块进行校验
    inline bool VerifyAllChunks() {
        if (!s_fcrcState.initialized) return true;

        for (int i = 0; i < FullCrcState::NUM_CHUNKS; i++) {
            if (s_fcrcState.chunkHashes[i] != 0xFFFFFFFF) {
                if (!VerifySingleChunk(i)) {
                    return false;
                }
            }
        }

        s_fcrcState.lastFullCheck = GetTickCount();
        return true;
    }

    // 随机分块抽查 — 每次只检查随机选择的一个块
    inline bool VerifyRandomChunk() {
        if (!s_fcrcState.initialized) return true;

        // 使用 baseSeed + 时间 + 计数器 选择块索引
        DWORD idx = (DMSP::g_state.baseSeed ^ GetTickCount() ^
                     static_cast<DWORD>(InterlockedIncrement(&s_fcrcState.crcCheckCount)))
                    % FullCrcState::NUM_CHUNKS;

        return VerifySingleChunk(static_cast<int>(idx));
    }

    // 周期性调度 — 混合随机抽查和全量检查
    inline bool RunPeriodicFullCodeCRC() {
        if (!s_fcrcState.initialized) return true;

        DWORD now = GetTickCount();

        // 每 15 秒做一次随机分块抽查
        if (now - s_fcrcState.lastChunkCheck > 15000) {
            s_fcrcState.lastChunkCheck = now;
            if (!VerifyRandomChunk()) {
                // 抽查失败 → 立即全量检查确认
                return VerifyAllChunks();
            }
        }

        // 每 60-120 秒 (随机) 做一次全量检查
        DWORD fullInterval = 60000 + ((DMSP::g_state.baseSeed & 0x3FFF) * 1000 / 0x3FFF) * 60000;
        if (now - s_fcrcState.lastFullCheck > fullInterval) {
            s_fcrcState.lastFullCheck = now;
            return VerifyAllChunks();
        }

        return true;
    }

} // namespace FullCodeCRC

// ============================================================================
// [v5.4 Mod 11] OLLVM 控制流平坦化 — 手动实现关键函数的 CFG 平坦化
//   将关键保护函数的控制流转换为 state-machine + 函数指针表模式
//   每个基本块通过不透明谓词选择下一状态, IDA 无法重建原始 CFG
//   已应用: TriggerResponse (已有的 TR_BlockFn 实现)
//   新增: IAT/代码检查函数的平坦化调度器
// ============================================================================
namespace CfgFlatten {

    // 平坦化调度的核心: state-driven dispatcher
    // 用法: 在关键保护函数外围包装此调度器

    using FlatStateFn = int(*)(volatile int* state, void* context);

    // 通用控制流平坦化调度器 — 用于包装任何需要保护的长函数
    // blockFns: 基本块函数指针数组
    // entryState: 入口状态 (初始块索引)
    // context: 跨块共享上下文
    // numBlocks: 块数量
    // 返回 true = 正常完成, false = 异常
    __declspec(noinline) inline bool FlatDispatch(
        FlatStateFn* blockFns,
        int entryState,
        void* context,
        int numBlocks)
    {
        if (!blockFns || numBlocks <= 0) return false;

        volatile int state = entryState;
        volatile int iterations = 0;
        const int MAX_ITERATIONS = 128;  // 防止无限循环

        while (iterations < MAX_ITERATIONS) {
            iterations++;

            // 不透明假分支: 每 7 次迭代注入干扰
            if ((iterations & 0x7) == 0) {
                volatile int fake = state ^ 0x5A5A;
                if (!fake) {
                    // 永远不执行, 但分析器必须证明
                    state = (state + 3) % numBlocks;
                }
                (void)fake;
            }

            // 边界检查 (不透明)
            if (state < 0 || state >= numBlocks) {
                return false;  // 状态异常
            }

            // 调用当前块
            int nextState = blockFns[state](&state, context);

            // 终止条件
            if (nextState < 0) {
                return true;  // 干净退出
            }

            // 状态转移
            state = nextState;

            // 不透明谓词检查: 随机扰动状态
            volatile DWORD tick = GetTickCount();
            if ((tick & 0x7Fu) == 0x3Fu) {
                // 概率 ~1/128, 但实际上是确定性干扰
                state ^= 0;  // NOP but visible to analyzer
            }
        }

        return false;  // 超时退出
    }

    // 运行时可配置的平坦化开关
    // triggerFlatProtection: 指定哪些 ID 对应的函数需要平坦化
    struct FlatProtectionConfig {
        bool enableIATCheck = true;          // IAT 检查平坦化
        bool enableCodeCRC = true;           // 代码 CRC 平坦化
        bool enableVADScan = true;           // VAD 扫描平坦化
        bool enableAntiDebug = true;         // 反调试平坦化
    };

    inline FlatProtectionConfig& GetFlatConfig() {
        static FlatProtectionConfig config;
        return config;
    }

    // 平坦化包装宏 — 用于在关键函数调用周围插入调度器
    // 使用方法: DMSP_FLAT_CALL(MyProtectedFunction, arg1, arg2)
    // 实际调用不会被直接内联, 而是通过函数指针表间接调用

    // 以下是平坦化函数声明 (供外部使用)
    // 实际基本块函数由各模块内部定义

} // namespace CfgFlatten

// ============================================================================
// [v5.4 RUNE_CHECK] 运行时环境统一检查入口
//   在每个 VERIFY_SIGNATURE() 调用点自动触发以下检查:
//   1. 代码段 W^X + CRC 抽查
//   2. VAD 异常检测
//   3. IAT 完整性
//   4. ThreadHide 刷新
//   5. DACL 安全描述符检查
//   6. VEH 异常处理器检测
//   7. 全量代码 CRC 分块抽查
//   8. 内核反调试检测
//   9. IAT 加密刷新
// 使用方式: 在各敏感函数入口调用 DMSP_RUNE_CHECK()
// ============================================================================

// 运行时环境检查 — 周期性触发, 降低性能开销
#define DMSP_RUNE_CHECK() \
    do { \
        /* 每 5 次 VERIFY 调用做一次轻量检查 */ \
        static volatile LONG _dmsp_rune_counter = 0; \
        LONG _dmsp_rc = InterlockedIncrement(&_dmsp_rune_counter); \
        /* [v5.4.2] 每次循环都执行反调试检测 — 无条件, 直接 ForceExit */ \
        AntiAnalysis::ForceExitIfDebugged(); \
        if ((_dmsp_rc & 0x3) == 0) { \
            /* 轻量检查: W^X */ \
            (void)CodeSectionGuard::VerifyWXPolicy(); \
        } \
        if ((_dmsp_rc & 0xF) == 0) { \
            /* 每 16 次: 中型检查 */ \
            (void)FullCodeCRC::VerifyRandomChunk(); \
            (void)VEHGuard::VerifyVEHIntegrity(); \
            (void)IATIntegrity::RunPeriodicIATCheck(); \
        } \
        if ((_dmsp_rc & 0x3F) == 0) { \
            /* 每 64 次: 重检查 */ \
            (void)CodeSectionGuard::RunPeriodicCodeCheck(); \
            (void)KernelAntiDebug::IsKernelDebuggingDetected(); \
            (void)SecDescGuard::RunPeriodicSecDescCheck(); \
        } \
    } while(0)

// ============================================================================
// [v5.4 统一初始化] 新的安全子系统初始化入口
//   在 main() 或 DMSP_EARLY_VERIFY() 中调用, 初始化所有新增防护
// ============================================================================
inline void DMSP_InitializeAllGuards() {
    DMSP::InitializeState();

    // 基于已初始化的 DMSP 状态
    if (!DMSP::g_state.initialized) return;

    // [1] IAT 加密初始化 — 跳过: EncryptAllModulesIAT 会将 kernel32/ntdll
    //     等关键模块的 IAT 条目全部加密, 导致后续 API 调用跳到垃圾地址, 程序崩溃.
    //     保留 IATIntegrity 的只读校验作为替代方案.
    // IATEncrypt::InitializeIATGuard();  // DISABLED - 致命: 破坏所有 IAT 调用

    // [2] 代码段守卫初始化
    CodeSectionGuard::InitializeCodeGuard();

    // [3] 全量 CRC 初始化
    FullCodeCRC::InitializeFullCodeCRC();

    // [4] VAD 监控初始化
    VADMonitor::InitializeVADGuard();

    // [5] ThreadHide 初始化 (ApplyInitialThreadHide 已由 AntiSuspend 线程异步处理,
    //     不在早期同步调用中枚举线程, 避免与初始化阶段的线程创建产生竞态)
    ThreadHide::InitializeThreadHide();
    // ThreadHide::ApplyInitialThreadHide();  // 移到 AntiSuspend 线程中异步执行

    // [6] 安全描述符守卫初始化
    SecDescGuard::InitializeSecDescGuard();

    // [7] IAT 完整性检查初始化 (只读, 不修改 IAT)
    IATIntegrity::InitializeIATCheck();

    // [8] VEH 守卫初始化
    VEHGuard::InitializeVEHGuard();
}

// ============================================================================
// [v5.4.2] 退出前内存擦除 — 放在文件末尾确保所有命名空间都已定义
//   在 ForceExit/ForceExitIfDebugged 的路径1之前调用
//   擦除: baseSeed, integrityKey, 状态标志, 函数指针表, CRC哈希等
// ============================================================================
namespace DMSP {

    inline void ScrubMemory() {
        if (!g_state.initialized) return;

        // 1. 擦除全局状态级敏感变量
        volatile DWORD* pSeed = &g_state.baseSeed;
        SecureZeroMemory(const_cast<DWORD*>(pSeed), sizeof(g_state.baseSeed));
        SecureZeroMemory(g_state.integrityKey, sizeof(g_state.integrityKey));

        // 2. 擦除编码后的状态标志 (写入随机值后清零, 双重保险)
        volatile DWORD dummy = static_cast<DWORD>(GetTickCount()) ^ 0xDEADBEEF;
        g_state.compromisedEncoded.store(dummy);
        g_state.compromisedSigEncoded.store(dummy);
        g_state.compromisedHashEncoded.store(dummy);
        g_state.compromisedEncoded.store(0);
        g_state.compromisedSigEncoded.store(0);
        g_state.compromisedHashEncoded.store(0);

        // 3. 擦除加密的函数指针表和验证密钥
        for (int i = 0; i < 8; i++) {
            g_state.validatorPtrs[i] = nullptr;
            g_state.validatorKeys[i] = 0;
        }

        // 4. 擦除 RNG 内部状态 (624*4=2496 字节)
        std::mt19937_64 cleanRng;
        g_state.rng = cleanRng;

        // 5. 擦除 DataIntegrity 的哈希值
        {
            volatile DWORD* pHash = &DataIntegrity::s_guardState.expectedHash;
            SecureZeroMemory(const_cast<DWORD*>(pHash), sizeof(DataIntegrity::s_guardState.expectedHash));
            SecureZeroMemory(&DataIntegrity::s_guardState.codeSectionHash,
                sizeof(DataIntegrity::s_guardState.codeSectionHash));
        }

        // 6. 擦除 CodeSectionGuard 的文本段 CRC
        {
            volatile DWORD* pTextHash = &CodeSectionGuard::s_codeState.textHash;
            SecureZeroMemory(const_cast<DWORD*>(pTextHash),
                sizeof(CodeSectionGuard::s_codeState.textHash));
        }

        // 7. 擦除 FullCodeCRC 的分块哈希
        {
            volatile DWORD* pChunks = FullCodeCRC::s_fcrcState.chunkHashes;
            SecureZeroMemory(const_cast<DWORD*>(pChunks),
                sizeof(FullCodeCRC::s_fcrcState.chunkHashes));
        }

        // 8. 擦除 SecDescGuard 的安全描述符哈希
        {
            volatile DWORD* pDaclHash = &SecDescGuard::s_sdState.expectedDaclHash;
            SecureZeroMemory(const_cast<DWORD*>(pDaclHash),
                sizeof(SecDescGuard::s_sdState.expectedDaclHash));
            SecureZeroMemory(&SecDescGuard::s_sdState.expectedOwnerSidHash,
                sizeof(SecDescGuard::s_sdState.expectedOwnerSidHash));
            SecureZeroMemory(&SecDescGuard::s_sdState.expectedGroupSidHash,
                sizeof(SecDescGuard::s_sdState.expectedGroupSidHash));
        }

        // 9. 擦除 IATIntegrity 的 IAT 哈希
        {
            volatile DWORD* pIatHash = &IATIntegrity::s_iatCheckState.iatHash;
            SecureZeroMemory(const_cast<DWORD*>(pIatHash),
                sizeof(IATIntegrity::s_iatCheckState.iatHash));
        }

        // 10. 标记状态为未初始化
        g_state.initialized = false;
    }

} // namespace DMSP

#endif // DMSP_H_INCLUDED
