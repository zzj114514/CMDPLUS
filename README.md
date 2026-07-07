# CMDPLUS

#### 介绍

CMDPLUS 是一款功能强大的 Windows 系统管理工具箱，专为系统管理员和教育环境设计。它集成了进程管理（71+ 种终止方法）、权限提升（Admin/SYSTEM/TrustedInstaller）、文件操作、系统修复、端口监控、垃圾清理、反远程控制等多种功能，能够有效应对各种系统限制场景，是信息课的好东西。

**版本:** 26.7.7\_KERNEL\_DRIVER\_2
**开源协议:** Apache 2.0
**开发语言:** VC++17 (Unicode)
**目标平台:** Windows 7 SP1 \~ Windows 11 26H1
**编译环境:** MSBuild + VS2026 v145 生成工具
**代码规模:** 约 27,500 行（源代码 1,459 KB）
**UAC 要求:** 必须管理员权限运行
**开源 DMSP:** `signature_protection_nocert.h`（无证书版，不含签名验证与证书信息）

---

#### 软件架构

```
CMDPLUS 模块化架构:

├── 核心系统
│   ├── MainMenu          主入口点 + 菜单系统 + 主循环调度
│   ├── CommonDefs        共享类型/结构/辅助工具 + Windows SDK 填充
│   └── stubs             链接器桩函数（WTSHelper/PortMonitor 兜底实现）

├── 进程管理
│   ├── ProcessTerminator 进程终结器（71+ 终止方法）
│   │   ├── 进程打开层    12 种 OpenProcess 策略（含驱动提权）
│   │   ├── 终止方法层    用户态 + 内核态终止技术
│   │   └── 工具层        COM/Firewall/USB/输入设备恢复
│   └── ProcessGuard      进程保护引擎（DACL + Job Object + Watchdog）

├── 权限与令牌
│   ├── DebugPrivilegeEnabler  调试权限提升（SeDebug 等 7 项权限）
│   ├── WTSHelper              Windows 终端服务令牌辅助
│   └── AdvancedProcessCreator 高级进程创建（SYSTEM/TI 令牌）

├── 网络与端口
│   ├── AntiRemoteControl  反远程控制防火墙规则管理
│   ├── PortMonitor        实时端口连接监控（TCP/UDP）
│   └── PortBlocker        Windows 防火墙端口阻止管理

├── 系统维护
│   ├── GarbageCleaner     系统垃圾文件扫描与清理（多线程）
│   └── 系统恢复           注册表/策略/服务/启动项多维恢复

├── 内核驱动组件
│   ├── PPL Driver         通过 RTCore64.sys 去除进程 PPL 保护
│   │                      （含 HVCI 检测/自动禁用 + 驱动自动清理）
│   ├── PhantomKiller      内核级进程强制终止驱动（IOCTL）
│   └── RTCore64.sys       签名的 legitimate 驱动（用于硬件级操作）

├── 反分析与绕过
│   ├── syscalls           间接系统调用（Hell's Gate / Halo's Gate）
│   │                      绕过 EDR/AV 用户态 ntdll Hook
│   └── ProcessHint        进程提示表（加速进程枚举）

└── 自我保护 (DMSP v5.4.2)
    └── signature_protection  11 层分布式多层签名保护系统
```

**自我保护架构** — DMSP v5.4.2 (Distributed Multi-Layer Signature Protection) 多层防护系统：

> 开源版本使用 `signature_protection_nocert.h`，**L1 签名验证已跳过**（不含证书信息），其余 10 层保护正常运行。

|  层次 | 子系统    | 核心能力                                             |
| :-: | ------ | ------------------------------------------------ |
|  L1 | 数字签名验证 | 开源版：已跳过 (nocert)                              |
|  L2 | 反调试检测  | 13 种检测方法加权投票                                     |
|  L3 | 进程自我保护 | PPL + BreakOnTermination + Job Object + Watchdog |
|  L4 | 代码完整性  | 全量 .text 段 CRC32C 分块校验                           |
|  L5 | 内存异常检测 | VAD 扫描 + IAT 完整性哈希校验                             |
|  L6 | 反 Hook | API Hook 检测 (JMP/FF25/mov rax+jmp rax)           |
|  L7 | 线程保护   | NtSetInformationThread 周期性刷新                     |
|  L8 | 内核反调试  | KUSER\_SHARED\_DATA 直读 + 三合一交叉验证                 |
|  L9 | 反编译期补丁 | TriggerResponse 函数体 CRC32C 校验                    |
| L10 | VEH 守护 | VEH 链表完整性检测                                      |
| L11 | 控制流混淆  | 函数指针加密 + 不透明谓词 + state-machine dispatcher        |

**设计哲学：**
| 原则 | 描述 |
|------|------|
| 分散性 | 验证逻辑分散到多个位置，单点绕过无效 |
| 冗余性 | 每个检测有至少一个备选，交叉验证降低误报 |
| 非对称性 | 检测点随机分布，攻击者无法预判何时触发 |
| 渐增性 | 权重累积而非截断判定，降低单点操纵影响 |
| 自毁性 | 检测到无法修复的篡改时，多路径强制退出 |

**依赖库：**

> 开源版 (nocert) 无需 wintrust.lib / crypt32.lib；此处列出完整发布版依赖。

```cpp
advapi32.lib    // 高级 API（注册表、令牌）
wtsapi32.lib    // 终端服务 API
wbemuuid.lib    // WMI（Windows Management Instrumentation）
shell32.lib     // Shell API
wintrust.lib    // 代码签名验证
ntdll.lib       // Native API
userenv.lib     // 用户环境
crypt32.lib     // 加密 API
setupapi.lib    // 设备安装 API
cfgmgr32.lib    // 配置管理器
iphlpapi.lib    // IP 助手 API（端口监控）
```

---

#### 安装教程

1. 从 Release 页面下载最新版本的 CMDPLUS.exe
2. 以 **管理员身份** 运行程序（右键 → 以管理员身份运行）
3. 或者使用 MSBuild 自行编译源码

**编译命令：**

```bash
MSBuild CMDPLUS.sln /p:Configuration=Release /p:Platform=x64 /t:Build /v:minimal
```

---

#### 使用说明

**运行要求：**

- 必须以 **管理员权限** 运行
- Windows 7 SP1 及以上版本
- 部分功能需要启用调试权限
- 内核驱动相关功能需要 HVCI/VBS 关闭或自动处理

**核心功能一览：**

|  序号 | 功能                   | 说明                        |
| :-: | -------------------- | ------------------------- |
|  1  | 结束进程                 | 强力终止进程，支持绕过 PPL 保护（71+ 种方法） |
|  2  | TrustedInstaller CMD | 以系统最高权限打开命令提示符并置顶         |
|  3  | 开启强制置顶               | 强制窗口置顶，包含窗口事件钩子和顶置对抗    |
|  4  | 取消置顶                 | 停止窗口强制置顶功能并恢复原始窗口状态        |
|  5  | 权限启动程序               | 以 TrustedInstaller 权限启动指定程序 |
|  6  | 强力删除                 | 文件选择框删除指定文件或文件夹           |
|  7  | USB 解禁                | 恢复 USB 存储设备的正常使用            |
|  8  | 完全删除学生机房管理助手         | 一站式移除学生机房管理助手（含映像劫持清理）    |
|  9  | 安装信息管理               | 管理已安装程序的注册表信息             |
|  10 | 垃圾清理                 | 多线程扫描并清理系统垃圾文件          |
|  11 | 反远程控制防火墙             | 检测并拦截远程控制连接               |
|  12 | 端口监控                 | 永久检测可疑端口连接                |
|  13 | 禁止指定端口连接           | 阻止特定端口的通信                 |
|  14 | 肃清系统                 | 立即肃清 / 安装开机自启肃清           |
|  0  | 退出程序                 | 安全退出（含保护清理）               |


**肃清系统（功能 14）子菜单：**

|  子选项 | 功能       | 说明                         |
| :--: | -------- | -------------------------- |
|  1   | 立即肃清    | 终止所有非白名单和非自身进程           |
|  2   | 开机自启肃清  | 安装开机自启 + 桌面快捷方式，下次启动时自动执行肃清 |

**注意事项：**

1. 此工具直接操作底层系统组件，使用时需谨慎
2. 部分功能可能被安全软件拦截或报警
3. PPL 绕过和内核级技术涉及系统核心操作，存在稳定性风险
4. 底层文件操作可能导致数据不可恢复
5. 内核驱动组件（RTCore64.sys / PhantomKiller.sys）需 HVCI 关闭方可加载
6. 建议在虚拟机环境中测试后再用于生产环境

---

#### 特性

1. **多权限支持**：管理员、SYSTEM、TrustedInstaller 三个权限级别
2. **71+ 种进程终止方法**，涵盖用户态和内核态技术（含驱动级 EPROCESS 提权）
3. **多层自我保护机制**（DMSP v5.4.2），防止被恶意终止
4. **系统全面恢复**：涵盖注册表、策略、服务、启动项等多个维度
5. **底层文件操作**：支持安全覆写和底层磁盘扇区操作
6. **内核驱动集成**：RTCore64.sys PPL 绕过 + PhantomKiller.sys 内核级终止
7. **EDR/AV 绕过**：间接系统调用（Hell's Gate / Halo's Gate）绕过用户态 Hook
8. **广泛兼容性**：支持 Windows 7 至 Windows 11 所有主流版本
9. **模块化架构**：从单体 CMDPLUS.cpp 重构为分层模块系统

---

#### 项目结构

```
CMDPLUS/
├── MainMenu.cpp              主入口 + 菜单系统 + 主循环
├── CommonDefs.h               共享定义 / Windows SDK 填充 / 工具函数
├── ProcessTerminator.h        进程终结器类声明
├── ProcessTerminator_Terminate.cpp  终止 + 打开策略实现（71+ 种方法）
├── ProcessGuard.h             进程保护引擎
├── GarbageCleaner.{h,cpp}     垃圾文件扫描清理
├── PortMonitor.{h,cpp}        端口监控
├── PortBlocker.{h,cpp}        端口阻止
├── AntiRemoteControl.{h,cpp}  反远程控制防火墙
├── AdvancedProcessCreator.{h,cpp}  高级进程创建
├── DebugPrivilegeEnabler.h    调试权限提升
├── WTSHelper.h                终端服务令牌辅助
├── stubs.cpp                  链接器桩函数
├── ppl_driver.h               RTCore64.sys PPL 绕过驱动
├── PhantomKiller_bin.h        PhantomKiller.sys 二进制嵌入
├── PhantomKiller_base64.h     PhantomKiller.sys Base64 编码
├── RTCore64_base64.h          RTCore64.sys Base64 编码
├── syscalls.h                 间接系统调用
├── signature_protection.h     完整版 DMSP（含签名验证）
├── signature_protection_nocert.h  开源版 DMSP（无证书）
├── CMDPLUS.vcxproj            MSBuild 项目文件
├── README.md                  简体中文说明
├── README_en.md               English Documentation
└── CMDPLUS26.7.7_KERNEL_DRIVER_2.bat  启动批处理文件
```

**开源仓库说明：**

- `CMDPLUS.cpp`（单体文件）及其备份副本**不包含在开源上传中**
- `BOVID/` 目录（PhantomKiller.sys 驱动源代码）**不包含在开源上传中**——PhantomKiller.sys 仅以预编译二进制形式通过 `PhantomKiller_bin.h` / `PhantomKiller_base64.h` 嵌入
- `RTCore64.sys资料/` 目录（驱动加载器及资料）**不包含在开源上传中**
- `新建文件夹/`（临时文件）**不包含在开源上传中**
- 编译产物（`x64/Release/*.exe`, `*.obj`, `*.pdb` 等）可通过 MSBuild 自行生成，**不包含在开源上传中**

---

#### DMSP 保护详解

CMDPLUS 内嵌的 DMSP（Distributed Multi-Layer Signature Protection）是一个约 5400 行的单文件 C++17 头文件保护系统，实现了以下安全能力：

- **静态防护**：数字签名验证、代码完整性 CRC32C 校验、反编译期补丁
- **动态防护**：反调试检测（13 种方法加权投票）、API Hook 检测、内存异常扫描
- **进程防护**：PPL 标记、BreakOnTermination、Job Object、Watchdog 线程
- **内核防护**：KUSER_SHARED_DATA 直读交叉验证
- **混淆技术**：函数指针加密、不透明谓词、state-machine dispatcher



---

***

**免责声明：** 本工具遵循 Apache 2.0 开源协议，仅供学习和研究目的使用。使用本工具造成的任何系统损坏、数据丢失或泄露、违反当地法律法规等，作者不承担任何责任。使用本工具即表示您已理解并同意承担所有风险。