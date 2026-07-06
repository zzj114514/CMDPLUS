# CMDPLUS

#### 介绍

CMDPLUS 是一款功能强大的 Windows 系统管理工具箱，专为系统管理员和教育环境设计。它集成了进程管理、权限提升、文件操作、系统修复等多种功能，能够有效应对各种系统限制场景，是信息课的好东西。

**版本:** 26.7.5\_KERNEL\_DRIVER\_2
**开源协议:** Apache 2.0
**开发语言:** VC++17 (Unicode)
**目标平台:** Windows 7 SP1 \~ Windows 11 26H1
**编译环境:** MSBuild + VS2026 v145生成工具
**代码规模:** 约34,000行
**开源DMSP:** `signature_protection_nocert.h` (无证书版, 不含签名验证与证书信息)

#### 软件架构

```
核心组件:

ProcessTerminator (进程终结器)
├── COM初始化器
├── 防火墙规则管理器
├── 增强进程打开函数
├── 71种终止方法实现
├── USB存储恢复
├── 输入设备恢复
└── 全屏覆盖检测

WTSHelper (令牌辅助)
├── 初始化
├── 用户令牌获取
└── 活动会话ID获取

AdvancedProcessCreator (高级进程创建)
├── 令牌创建进程
└── 兼容Windows 7的进程创建

DebugPrivilegeEnabler (权限启用)
└── 启用所有调试权限

增强保护模块
├── Watchdog线程
├── 反挂起保护
├── 终结者检测
├── Critical进程标记
└── API钩子管理
```

**自我保护架构** — DMSP v5.4 (Distributed Multi-Layer Signature Protection) 多层防护系统：
> 开源版本使用 `signature_protection_nocert.h`，**L1 签名验证已跳过**（不含证书信息），其余 10 层保护正常运行。

|  层次 | 子系统    | 核心能力                                             |
| :-: | ------ | ------------------------------------------------ |
|  L1 | 数字签名验证 | 开源版: 已跳过 (nocert)                              |
|  L2 | 反调试检测  | 13 种检测方法加权投票                                     |
|  L3 | 进程自我保护 | PPL + BreakOnTermination + Job Object + Watchdog |
|  L4 | 代码完整性  | 全量 .text 段 CRC32C 分块校验                           |
|  L5 | 内存异常检测 | VAD 扫描 + IAT 完整性哈希校验                             |
|  L6 | 反 Hook | API Hook 检测 (JMP/FF25/mov rax+jmp rax)           |
|  L7 | 线程隐藏   | NtSetInformationThread 周期性刷新                     |
|  L8 | 内核反调试  | KUSER\_SHARED\_DATA 直读 + 三合一交叉验证                 |
|  L9 | 反编译期补丁 | TriggerResponse 函数体 CRC32C 校验                    |
| L10 | VEH 守护 | VEH 链表完整性检测                                      |
| L11 | 控制流混淆  | 函数指针加密 + 不透明谓词 + state-machine dispatcher        |

**依赖库:**
> 开源版 (nocert) 无需 wintrust.lib / crypt32.lib；此处列出完整发布版依赖。

```cpp
advapi32.lib    // 高级API (注册表、令牌)
wtsapi32.lib    // 终端服务API
wbemuuid.lib    // WMI
shell32.lib     // Shell API
wintrust.lib    // 代码签名验证
ntdll.lib       // Native API
userenv.lib     // 用户环境
crypt32.lib     // 加密API
setupapi.lib    // 设备安装API
cfgmgr32.lib    // 配置管理器
```

#### 安装教程

1. 从 Release 页面下载最新版本的 CMDPLUS.exe
2. 以 **管理员身份** 运行程序（右键 → 以管理员身份运行）
3. 或者使用 MSBuild 自行编译源码

**编译命令:**

```bash
MSBuild CMDPLUS.sln /p:Configuration=Release /p:Platform=x64 /t:Build /v:minimal
```

#### 使用说明

**运行要求:**

- 必须以 **管理员权限** 运行
- Windows 7 SP1 及以上版本
- 部分功能需要启用调试权限

**核心功能一览:**

|  序号 | 功能                   | 说明                        |
| :-: | -------------------- | ------------------------- |
|  1  | 结束进程                 | 强力终止进程，支持绕过PPL保护          |
|  2  | TrustedInstaller CMD | 以系统最高权限打开命令提示符并置顶         |
|  3  | 开启强制置顶               | 强制窗口置顶，防止被覆盖              |
|  4  | 取消置顶                 | 停止窗口强制置顶功能                |
|  5  | 权限启动程序               | 以TrustedInstaller权限启动指定程序 |
|  6  | 强力删除                 | 文件选择框删除指定文件或文件夹           |
|  7  | USB解禁                | 恢复USB存储设备的正常使用            |
|  8  | 完全删除学生机房管理助手         | 一站式移除学生机房管理助手             |
|  9  | 安装信息管理               | 管理已安装程序的注册表信息             |
|  10 | 垃圾清理                 | 清理系统垃圾文件                  |
|  11 | 反远程控制防火墙             | 检测并拦截远程控制连接               |
|  12 | 端口监控                 | 永久检测可疑端口连接                |
|  13 | 禁止指定端口连接             | 阻止特定端口的通信                 |
|  14 | 肃清系统                 | 立即肃清 / 安装开机自启肃清           |
|  0  | 退出程序                 | 安全退出（含保护清理）               |

**注意事项:**

1. 此工具直接操作底层系统组件，使用时需谨慎
2. 部分功能可能被安全软件拦截或报警
3. PPL绕过和内核级技术涉及系统核心操作，存在稳定性风险
4. 底层文件操作可能导致数据不可恢复
5. 建议在虚拟机环境中测试后再用于生产环境

#### 特性

1. 多权限支持：普通管理员、SYSTEM、TrustedInstaller 三个权限级别
2. 71+种进程终止方法，涵盖用户态和内核态技术
3. 多层自我保护机制，防止被恶意终止
4. 系统全面恢复：涵盖注册表、策略、服务、启动项等多个维度
5. 底层文件操作：支持安全覆写和底层磁盘扇区操作
6. 广泛兼容性：支持 Windows 7 至 Windows 11 所有主流版本

***

**免责声明:** 本工具遵循 [Apache 2.0](LICENSE) 开源协议，仅供学习和研究目的使用。使用本工具造成的任何系统损坏、数据丢失或泄露、违反当地法律法规等，作者不承担任何责任。使用本工具即表示您已理解并同意承担所有风险。