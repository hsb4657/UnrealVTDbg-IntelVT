# 腾讯 Anti-Cheat Expert (ACE) 反作弊系统分析报告

**目标路径**: `D:\WeGameApps\rail_apps\wgprojectm(2002291)\ShadowTrackerExtra\Binaries\Win64\AntiCheatExpert`  
**游戏**: ShadowTrackerExtra (WeGame 平台, AppID 2002291)  
**分析日期**: 2026-08-06  
**ACE 版本**: 28.2.2604.951 (Base64.dll) / 1.386.2605.2163 (产品版本)  
**签名实体**: ACEVILLE PTE LTD (新加坡) / Tencent Technology (深圳) / Microsoft WHCP

---

## 一、系统架构概览

ACE (Anti-Cheat Expert) 是腾讯自研的多层反作弊系统，采用 **内核驱动 + 用户态守护进程 + AI 检测 + 云端控制** 四层纵深防御架构。

```
┌─────────────────────────────────────────────────────┐
│                   云端控制层                          │
│  CCloudControl / CPullConfigProto / 远程策略下发      │
└────────────────────────┬────────────────────────────┘
                         │ HTTPS (libcurl + OpenSSL)
┌────────────────────────▼────────────────────────────┐
│              用户态守护层 (Ring 3)                    │
│  SGuard64.exe (TGuard 框架) ← IPC → ACE-Service64   │
│  ACE-Base64.dll | ACE-IDS64 | ACE-DFS64 | ACE-CSI64 │
│  ACE-ATS64 | ACE-PBC-Game64 | ACE-Safe | ACE-SSC64  │
└────────────────────────┬────────────────────────────┘
                         │ DeviceIoControl / IOCTL
┌────────────────────────▼────────────────────────────┐
│              内核驱动层 (Ring 0)                      │
│  ACE-BASE.sys  │  ACE-CORE.sys  │  ACE-GAME.sys     │
│  ACE-SSC-DRV64.sys                                   │
└─────────────────────────────────────────────────────┘
```

---

## 二、组件清单与功能定位

### 2.1 内核驱动 (.sys)

| 文件 | 大小 | 签名 | 功能 |
|------|------|------|------|
| **ACE-BASE.sys** | 4,029 KB | Microsoft WHCP | 基础内核框架: 文件系统 Minifilter、进程通知回调、NDIS 网络过滤、注册表监控 |
| **ACE-CORE.sys** | 3,795 KB | Microsoft WHCP | 核心保护: 内存映射 (MmMapLockedPages)、进程附加 (KeStackAttachProcess)、对象引用拦截 |
| **ACE-GAME.sys** | 2,019 KB | Tencent (深圳) | 游戏专用: NMI 回调注册 (KeRegisterNmiCallback)、注册表回调 (CmRegisterCallback)、进程创建通知 |
| **ACE-SSC-DRV64.sys** | 2,485 KB | Microsoft WHCP | 服务端校验内核组件 |
| **ACE-CORE.sysa/sysa2** | 1,664/1,559 KB | — | ARM64 架构驱动 (Windows on ARM 支持) |
| **ACE-CORE.sys2/sys3** | 3,160/3,209 KB | — | x64 驱动变体 (不同 Windows 版本适配) |

**关键内核 API 调用**:
- `PsSetCreateProcessNotifyRoutineEx` — 进程创建/退出通知
- `ObRegisterCallbacks` (间接通过 ObOpenObjectByPointer) — 对象句柄操作拦截
- `FltRegisterFilter` — 文件系统 Minifilter
- `CmRegisterCallback` — 注册表操作回调
- `KeRegisterNmiCallback` / `KeDeregisterNmiCallback` — NMI 中断回调 (反调试)
- `KeRegisterBugCheckReasonCallback` — 蓝屏回调 (反 dump)
- `MmMapLockedPagesSpecifyCache` / `MmProbeAndLockProcessPages` — 跨进程内存操作
- `KeStackAttachProcess` / `KeUnstackDetachProcess` — 进程上下文切换
- `ZwQuerySystemInformation` — 系统信息枚举
- `NdisRegisterMiniportDriver` (ACE-BASE) — 网络层过滤
- `HalDispatchTable` — HAL 调度表访问 (高权限操作)
- `KeIpiGenericCall` — 多核 IPI 广播 (全局同步操作)

### 2.2 用户态核心模块 (.dll/.exe)

| 文件 | 大小 | 功能 | 关键技术 |
|------|------|------|----------|
| **ACE-Base64.dll** | 68,048 KB | 主客户端引擎 | YARA 规则引擎, OpenCV, MNN/ncnn, Lua 5.4 脚本, OpenCL GPU 计算, Rust 组件, libcurl 通信 |
| **ACE-IDS64.dll** | 4,510 KB | AI 视觉检测引擎 | ncnn 神经网络推理 (DetectionOutput, PriorBox), OpenCV 4.5.5 图像处理 |
| **ACE-DFS64.dll** | 24,683 KB | 文件系统检测 | 进程/文件枚举, 工具进程识别 |
| **ACE-CSI64.dll** | 7,764 KB | 客户端完整性 | 代码完整性校验, 内存扫描 |
| **ACE-ATS64.dll** | 8,999 KB | 反篡改扫描 | 模块完整性校验, 特征扫描 |
| **ACE-PBC-Game64.dll** | 4,250 KB | 玩家行为检测 | 行为模式分析 |
| **ACE-Safe.dll** | 8,787 KB | 进程模块扫描 | Process32/Module32 枚举, CreateRemoteThreadEx, tessafe.sys 交互 |
| **ACE-SSC64.dll** | 11,940 KB | 服务端校验 | 客户端-服务端双向验证 |
| **ACE-DRV64.dll** | 26,320 KB | 驱动交互 | Microsoft Detours 注入框架 |
| **ACE-Trace.dll** | 2,322 KB | 遥测上报 | OpenSSL + libcurl, BugTrace 事件日志 |

### 2.3 守护进程 (SGuard / TGuard 框架)

| 文件 | 版本 | 功能 |
|------|------|------|
| **SGuard64.exe** | 1.0.2508.45 | 主守护进程 (TGuard 框架) |
| **SGuardSvc64.exe** | 1.0.2508.45 | Windows 服务进程 |
| **SGuardAgent64.dll** | — | Agent 通信库 |
| **SGuardUpdate64.exe** | — | 热更新程序 |
| **ACE-Service64.exe** | 28.1.2604.232 | ACE 服务守护 |
| **ACE-Helper.exe** | 1.0.2112.1011 | 辅助/安装程序 |

**TGuard 内部架构** (从 RTTI 信息恢复):
```
TGuard::
├── Agent::CAgent              — 检测代理执行单元
├── Agent::CAgentManager       — 代理管理器
├── Control::CCloudControl     — 云端策略控制
├── Control::CLocalControl     — 本地控制逻辑
├── Executor::CExecutorCreator — 执行器工厂
├── Monitor::CEventMonitor     — 事件监控器
├── Module::CTGuardLogicServer — 逻辑服务器主模块
├── Net::CPullConfigProto      — 配置拉取协议
├── IPC::CIpcServer            — 进程间通信服务
├── IPC::CTGuardIPC            — TGuard IPC 实现
└── Common::CTickThread        — 定时心跳线程
```

---

## 三、保护机制详细分析

### 3.1 代码虚拟化保护 (TVM — Tencent Virtual Machine)

**所有核心模块均使用腾讯自研虚拟机保护 (.tvm0 段)**:

| 模块 | TVM0 段大小 | 占比 |
|------|------------|------|
| ACE-Base64.dll | 25,408 KB | 36% |
| ACE-DFS64.dll | 23,716 KB | 92% |
| ACE-ATS64.dll | 6,976 KB | 76% |
| ACE-SSC64.dll | 5,940 KB | 49% |
| ACE-CORE.sys | 3,596 KB | 93% |
| ACE-PBC-Game64.dll | 3,320 KB | 76% |
| ACE-CSI64.dll | 3,236 KB | 50% |
| ACE-BASE.sys | 2,976 KB | 72% |
| ACE-SSC-DRV64.sys | 2,296 KB | 90% |
| ACE-GAME.sys | 1,792 KB | 87% |
| SGuard64.exe | 3,160 KB | 40% |

> **结论**: ACE 的核心检测逻辑几乎全部被 TVM 虚拟化保护，静态分析极其困难。

**额外保护**: ACE-Base64.dll 和 ACE-Service64.exe 包含 `.detourc`/`.detourd` 段 (Microsoft Detours 框架)，用于 API Hook。

### 3.2 内核层检测能力

1. **进程保护** — 通过 ObRegisterCallbacks 拦截外部进程打开游戏进程句柄
2. **内存保护** — 拦截跨进程内存读写 (ReadProcessMemory/WriteProcessMemory)
3. **文件系统监控** — Minifilter 驱动监控作弊工具文件落地
4. **注册表监控** — CmRegisterCallback 检测作弊工具注册表痕迹
5. **网络过滤** — NDIS 驱动检测网络层作弊 (加速器/封包修改)
6. **反调试** — NMI 回调检测硬件断点和调试器附加
7. **反 Dump** — BugCheck 回调防止内存转储

### 3.3 用户态检测能力

1. **YARA 规则扫描** — ACE-Base64.dll 集成 libyara (支持 PE/ELF/dotnet/hash/math 模块)
2. **AI 视觉检测** — ACE-IDS64.dll 集成 ncnn 神经网络推理引擎 + OpenCV 4.5.5
   - 使用 DetectionOutput 层 → SSD/YOLO 类目标检测模型
   - 用于检测屏幕外挂 (ESP/Aimbot 覆盖层, 准星辅助等)
3. **GPU 加速扫描** — ACE-Base64.dll 引用 OpenCL (CPU/GPU 异构计算)
4. **MNN 推理** — ACE-Base64.dll 包含 MNN 框架 (移动/桌面神经网络推理)
5. **进程/模块枚举** — ACE-Safe.dll 通过 CreateToolhelp32Snapshot 枚举可疑进程和 DLL
6. **输入设备检测** — 通过 hid.dll 检测模拟输入设备 (鼠标宏/键盘宏)
7. **行为分析** — ACE-PBC-Game64.dll 分析玩家行为模式

### 3.4 配置标志 (从字符串恢复)

```
/EnableDetectServiceCallbackStack   — 启用服务回调栈检测
/KeyboardDetectionInterval          — 键盘检测间隔
/MouseDetectionInterval             — 鼠标检测间隔
/PunishInputHookIntegrity           — 惩罚输入 Hook 完整性违规
```

### 3.5 通信与云控

- **网络通信**: libcurl + OpenSSL (HTTPS), WinHTTP, WebSocket
- **云端控制**: CCloudControl 远程下发检测策略、黑名单规则
- **遥测上报**: ACE-Trace.dll 通过 BugTrace 事件收集数据上报
- **心跳**: CTickThread 定时心跳保持与服务端连接
- **热更新**: SGuardUpdate64.exe 支持组件独立更新

### 3.6 数据文件

| 文件 | 大小 | 类型 | 用途推测 |
|------|------|------|----------|
| ACE-Base.dat | 73.5 KB | 加密数据 (熵 7.98) | 配置/规则数据 |
| ACE-Helper.dat | 923.7 KB | 自定义格式 (熵 6.64) | 辅助数据/签名库 |
| ids.dat | 4,127 KB | 加密数据 (熵 7.98) | IDS 检测规则/模型权重 |
| pld.dat | 1,069 KB | ZIP 压缩包 (加密内容) | 载荷包 (模型文件 m/y) |
| w9741486220778564302 | 306 KB | 加密数据 (熵 7.98) | 运行时动态数据 |

> pld.dat 是 ZIP 格式，内含 `m` (895KB) 和 `y` (199KB) 两个加密文件，推测为 AI 检测模型的参数文件。

---

## 四、多平台支持

| 架构 | 驱动 | 说明 |
|------|------|------|
| x64 | ACE-CORE.sys, ACE-CORE.sys2, ACE-CORE.sys3 | 多版本 Windows 适配 |
| ARM64 | ACE-CORE.sysa, ACE-CORE.sysa2 | Windows on ARM 支持 |

---

## 五、技术栈汇总

| 类别 | 技术 |
|------|------|
| 编译环境 | MSVC 14.22 (VS2019), Rust (rsproxy.cn 镜像源) |
| 代码保护 | Tencent VM (TVM0), Microsoft Detours |
| AI/ML | ncnn, MNN, OpenCV 4.5.5-dev, OpenCL |
| 规则引擎 | libyara (PE/ELF/dotnet/hash/math/cuckoo 模块) |
| 脚本 | Lua 5.4 |
| 网络 | libcurl, OpenSSL, WinHTTP, WS2_32 |
| 加密 | OpenSSL (GHASH), bcrypt, crypt32, wintrust |
| 驱动框架 | WDF, NDIS, FltMgr (Minifilter) |
| IPC | 命名管道 / 共享内存 (CTGuardIPC) |

---

## 六、安全评估结论

**防护等级**: ★★★★★ (极高)

ACE 是目前国内最复杂的游戏反作弊系统之一，主要特点:

1. **纵深防御** — 内核层 (4 个驱动) + 用户层 (10+ 模块) + 云端协同
2. **AI 赋能** — 集成 ncnn/MNN 神经网络推理，用于视觉外挂检测
3. **全方位保护** — 代码虚拟化 (TVM) 使静态分析几乎不可能
4. **动态更新** — 云控策略 + 热更新机制，规则可远程实时更新
5. **多平台** — 支持 x64 和 ARM64 Windows
6. **进程隔离** — SGuard 独立守护进程 + Windows 服务，互相监控

**逆向难度**: 极高。核心检测逻辑被 TVM 虚拟化保护，关键数据文件全部加密 (熵接近 8.0)，且有内核层多重反调试机制。

---

*报告生成工具: 静态分析 (PE 解析、字符串提取、签名验证)*  
*未执行动态分析 (未运行目标程序)*
