# ACE (AntiCheatExpert) 逆向分析报告

> **分析对象**: AntiCheatExpert (腾讯 ACE)  
> **分析工具**: Ghidra 11.x + PowerShell 二进制解析  
> **分析范围**: ACE-BASE.sys (内核驱动) / ACE-Trace.dll (崩溃上报) / 游戏内 SDK 资产  
> **日期**: 2026-07-24  
> **作者**: Ricardo | QQ: 2635169725

---

## ⚠️ 免责声明

本报告仅供安全研究和教育目的使用。

1. 报告中的所有分析均基于公开可获取的二进制文件的静态逆向工程，未涉及对腾讯服务器、用户数据或在线服务的任何形式的攻击、入侵或未授权访问。
2. 报告内容旨在帮助安全研究人员理解反作弊系统的工作原理，以促进软件安全领域的技术交流和进步。
3. 作者不鼓励、不支持任何利用本报告内容进行违反游戏服务条款、侵犯知识产权或破坏游戏公平性的行为。
4. 任何基于本报告内容的实际应用，使用者应自行承担所有法律和道德责任。作者对本报告的误用不承担任何责任。
5. 本报告不提供、不包含任何可用于实际作弊的完整代码、密钥或绕过方案。
6. 如果您是 ACE 的开发者或相关权益方，对本报告内容有疑问，请联系作者进行沟通。

**适用法律**: 《中华人民共和国网络安全法》《中华人民共和国数据安全法》《计算机软件保护条例》

---

## 1. 总体架构

### 1.1 组件清单

| 组件 | 类型 | 大小 | 功能 |
|------|------|------|------|
| `ACE-BASE.sys` | 内核驱动 | 4.0 MB | 核心检测驱动: 进程/模块/注册表/句柄回调 + Minifilter |
| `ACE-BOOT.sys` | 内核驱动 | 1.0 MB | ELAM 启动早期驱动, 系统启动时最先加载 |
| `ACE-CORE20405.sys` | 内核驱动 | 3.2 MB | 核心检测引擎 v20405 |
| `ACE-CORE30405.sys` | 内核驱动 | 3.2 MB | 核心检测引擎 v30405 (版本号暗示加密方案差异) |
| `ACE-SSC-DRV64.sys` | 内核驱动 | 2.7 MB | SGuard 安全组件驱动 |
| `ACE-Service64.exe` | 系统服务 | 3.2 MB | 用户态服务, 与内核通信 |
| `ACE-Tray.exe` | 系统托盘 | 7.5 MB | 主控面板, UI/配置推送 |
| `SGuard64.exe` | 用户态服务 | 7.7 MB | SGuard 主程序 |
| `SGuardSvc64.exe` | 系统服务 | 2.0 MB | SGuard 服务守护 |
| `SGuardUpdate64.exe` | 更新程序 | 4.0 MB | 自动更新组件 |
| **检测插件** | | | |
| `ACE-ATS64.dll` | 用户态 DLL | 9.0 MB | Anti-Tamper System: 反篡改/完整性校验 |
| `ACE-CSI64.dll` | 用户态 DLL | 7.8 MB | Code Sign Integrity: 代码签名验证 |
| `ACE-DFS64.dll` | 用户态 DLL | 24.7 MB | Driver File System: 文件/驱动扫描 (最大插件) |
| `ACE-DRV64.dll` | 用户态 DLL | 26.3 MB | Driver Verification: 驱动行为分析 (最大插件) |
| `ACE-SSC64.dll` | 用户态 DLL | 10.0 MB | SGuard Security Component: 安全检测 |
| `ACE-Safe.dll` | 用户态 DLL | 8.8 MB | 安全运行环境检测 |
| `ACE-Trace.dll` | 用户态 DLL | 2.3 MB | Bugtrace: 崩溃追踪上报 (非检测组件) |

### 1.2 分层架构图

```
┌─────────────────────────────────────────────────────────┐
│  云端 (ACE Cloud Backend)                               │
│  · 签名库下发 · 行为特征更新 · 封禁策略推送              │
├─────────────────────────────────────────────────────────┤
│  用户态 (User Mode)                                     │
│  ┌────────────┐ ┌──────────┐ ┌──────────┐              │
│  │SGuard64.exe│ │ACE-Tray  │ │ACE-Svc   │              │
│  │ 主控/守护  │ │ 托盘/UI  │ │ 系统服务 │              │
│  └─────┬──────┘ └────┬─────┘ └────┬─────┘              │
│        │            IOCTL         IOCTL                 │
│  ┌─────┴─────────────┬────────────┬──────────────────┐ │
│  │ ACE-ATS64.dll     │ACE-CSI64   │ ACE-DFS64.dll    │ │
│  │ (反篡改 9MB)      │(签名 8MB)  │ (文件扫描 25MB)  │ │
│  ├───────────────────┼────────────┼──────────────────┤ │
│  │ ACE-DRV64.dll     │ACE-SSC64   │ ACE-Safe.dll     │ │
│  │ (驱动验证 26MB)   │(安全 10MB) │ (环境检测 9MB)   │ │
│  └───────────────────┴────────────┴──────────────────┘ │
├─────────────────────────────────────────────────────────┤
│  内核态 (Kernel Mode) — ACE-BASE.sys                    │
│  ┌───────────────────────────────────────────────────┐  │
│  │ 进程回调 │ 模块回调 │ 句柄保护 │ Minifilter        │  │
│  │ 注册表   │ HID枚举  │ NDIS扫描 │ 线程/APC注入     │  │
│  ├───────────────────────────────────────────────────┤  │
│  │ AVL签名树 (已知作弊驱动/进程黑名单)                │  │
│  └───────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────┐  │
│  │ ACE-BOOT.sys (ELAM — 最先加载, 无法被绕过)         │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

---

## 2. ACE-BASE.sys 内核驱动深度分析

### 2.1 基本信息

| 属性 | 值 |
|------|-----|
| 文件路径 | `C:\Program Files\AntiCheatExpert\ACE-BASE.sys` |
| 大小 | 4,028 KB |
| 镜像基址 | `0x140000000` |
| 入口点 | `0x140393000` (INIT 段, 初始化后丢弃) |
| 导出表 | 仅 `DriverEntry` |
| 节区 | `.text` (标准代码) / `.rdata` (只读数据) / `.data` (全局数据) / `.tvm0` (虚拟化代码 2.8MB) / `PAGE` (可分页代码) / `INIT` (初始化代码) |

### 2.2 代码保护

**`.tvm0` 段 (2.8 MB)**: ACE 核心检测逻辑使用了代码虚拟化保护。所有关键回调注册函数、模块签名验证、IOCTL 处理逻辑均位于此段。

证据:
```
.text 段: 0x140001000-0x1400acfff  (标准 x64 代码 — 辅助函数)
.tvm0 段: 0x140398000-0x14067ffff  (虚拟机字节码 — 核心逻辑)
```

DriverEntry 调用链:
```c
void DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    // 1. 安全 cookie 初始化
    __security_init_cookie();
    
    // 2. 设置分发函数表
    DriverObject->DriverUnload = UnloadRoutine;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IOCTL_Handler;
    
    // 3. 创建设备对象 (仅管理员可访问)
    // SDDL: "D:P(A;;GA;;;BA)" — 仅 BUILTIN\Administrators
    IoCreateDeviceSecure(
        L"\\Device\\ACE-BASE",    // 设备名
        0x22,                      // FILE_DEVICE_UNKNOWN
        0x100,                     // FILE_DEVICE_SECURE_OPEN
        L"D:P(A;;GA;;;BA)"        // 仅管理员
    );
    IoCreateSymbolicLink(L"\\DosDevices\\Global\\ACE-BASE");
    
    // 4. 注册所有回调 — 此函数已虚拟化
    thunk_RegisterCallbacks(DriverObject, RegistryPath);
        // → JMP → .tvm0 (0x14042fbce)
    
    // 5. 创建系统工作线程 (检测扫描)
    PsCreateSystemThread(&ThreadHandle, ...);
}
```

### 2.3 动态 API 解析 (反分析)

ACE 不直接在导入表中暴露关键 API, 而是运行时动态解析:

```c
// 伪代码还原
void ResolveKernelAPIs() {
    UNICODE_STRING name;
    
    RtlInitUnicodeString(&name, L"IoCreateDeviceSecure");
    g_IoCreateDeviceSecure = MmGetSystemRoutineAddress(&name);
    // 若解析失败, 回退到硬编码备用值
    
    RtlInitUnicodeString(&name, L"IoValidateDeviceIoControlAccess");
    g_IoValidateDeviceIoControlAccess = MmGetSystemRoutineAddress(&name);
}
```

同样方式解析的 API 包括:
- `ObRegisterCallbacks` — 句柄操作拦截 (不在导入表)
- `PsSetLoadImageNotifyRoutine` — 模块加载检测 (不在导入表)
- `PsSetCreateThreadNotifyRoutine` — 线程创建检测 (不在导入表)

**目的**: 静态分析工具 (IDA/Ghidra) 无法通过导入表发现 ACE 的真实检测行为。

### 2.4 IOCTL 接口

用户态组件通过 `\\\\.\\Global\\ACE-BASE` 设备与内核通信:

```
ACE-Tray.exe / SGuard64.exe
    │
    ├─ DeviceIoControl(\\\\.\\Global\\ACE-BASE, IOCTL_CODE, ...)
    │       │
    │       ├─ 查询已加载驱动列表    (HashTable[65536] 遍历)
    │       ├─ 查询进程模块信息      (PEB 读取)
    │       ├─ 查询签名验证结果      (AVL树查找)
    │       ├─ 设置检测策略          (启用/禁用特定检测)
    │       └─ 上报检测事件          (写入注册表)
    │
    └─ 访问控制: SeTokenObjectType + ExGetPreviousMode 双重验证
```

每个 IOCTL 码通过 `0xa4c042de` 哈希映射到 `.tvm0` 中的处理函数。

---

## 3. 检测机制全景

### 3.1 进程创建监控

```
API: PsSetCreateProcessNotifyRoutineEx
触发: 任何进程创建/终止
检测:
├─ 进程路径匹配黑名单 (作弊器安装目录)
├─ 进程签名验证 (RtlImageDirectoryEntryToData → PE 证书)
├─ 父进程链追溯 (PsGetProcessInheritedFromUniqueProcessId)
├─ 命令行参数扫描
└─ 进程创建时间戳记录 (PsGetProcessCreateTimeQuadPart)
```

**代码证据**: 字符串表含 `PsSetCreateProcessNotifyRoutineEx` (0x1403945d4)

### 3.2 模块加载监控

```
API: PsSetLoadImageNotifyRoutine (动态解析)
    + ZwQuerySystemInformation(SystemModuleInformation = 0x0b)
触发: 任何驱动/DLL 加载到内核或用户态
检测:
├─ 模块基址 + 大小 + 路径记录到 HashTable[65536]
├─ PE 签名验证 (RtlImageDirectoryEntryToData)
├─ 节区哈希校验 (检测 inline hook)
└─ AVL 树签名匹配 (已知作弊模块数据库)
```

**HashTable 操作代码还原**:
```c
// FUN_140010080: 插入到哈希表
void InsertModule(uint* ModuleInfo) {
    if (!g_HashTable || !g_Initialized) return;
    
    size_t hash = (*ModuleInfo / 4) % 0x10000;
    if (g_HashTable[hash] == NULL) {
        void* entry = ExAllocatePoolWithTag(NonPagedPool, 0x448, 'PsOb');
        memcpy(entry, ModuleInfo, 0x448);
        g_HashTable[hash] = entry;
        NotifyUserMode(hash, ModuleInfo);
    }
}

// FUN_140066130: 枚举所有内核模块
void EnumerateKernelModules(callback_t cb) {
    ULONG size = 0;
    ZwQuerySystemInformation(0x0b, NULL, 0, &size);
    PRTL_PROCESS_MODULES modules = ExAllocatePool(size);
    ZwQuerySystemInformation(0x0b, modules, size, &size);
    
    for (ULONG i = 0; i < modules->NumberOfModules; i++) {
        if (!cb(&modules->Modules[i])) break;  // 任一回调返回false则停止
    }
    ExFreePool(modules);
}
```

### 3.3 句柄操作拦截 (ObRegisterCallbacks)

```
API: ObRegisterCallbacks (动态解析)
保护对象类型: PsProcessType, PsThreadType
操作类型:
├─ OB_OPERATION_HANDLE_CREATE  — 拦截 OpenProcess
├─ OB_OPERATION_HANDLE_DUPLICATE — 拦截 DuplicateHandle
└─ OB_OPERATION_HANDLE_CREATE  — 拦截 OpenThread

Pre-Operation 回调逻辑 (还原):
  1. 检查调用者进程是否为受保护游戏
  2. 检查目标进程是否为作弊器进程
  3. 若请求权限含 PROCESS_VM_READ/PROCESS_VM_WRITE:
     → 剥离这些权限 (Status = STATUS_ACCESS_DENIED)
  4. 记录尝试访问事件 → 注册表日志
```

**关键对象类型 (字符串表确认)**:
```
PsProcessType      — 进程对象
PsThreadType       — 线程对象
PsJobType          — 作业对象
SeTokenObjectType  — 令牌对象
ExEventObjectType  — 事件对象
ExSemaphoreObjectType — 信号量对象
IoFileObjectType   — 文件对象
IoDriverObjectType — 驱动对象
IoDeviceObjectType — 设备对象
```

### 3.4 文件系统 Minifilter

```
API: FltRegisterFilter → Flt* 全套 API
框架: FLTMGR.SYS
监控操作:
├─ IRP_MJ_CREATE         — 文件创建/打开
├─ IRP_MJ_READ           — 文件读取
├─ IRP_MJ_WRITE          — 文件写入
├─ IRP_MJ_SET_INFORMATION — 文件属性修改
└─ IRP_MJ_CLEANUP        — 文件句柄关闭

检测场景:
├─ 作弊 DLL 从非 %SystemRoot% 路径加载 → 拦截
├─ 驱动 .sys 从未签名目录落盘 → 拦截 + 上报
├─ 游戏目录下非法文件写入 → 拦截
└─ C:\ProgramData\ 下可疑程序数据目录 → 监控
```

### 3.5 注册表监控

```
监控路径:
├─ \Registry\Machine\System\CurrentControlSet\Control\Class
│     (设备驱动注册 — 检测虚拟 HID 鼠标/键盘)
├─ \Registry\Machine\SOFTWARE\Microsoft\Windows NT\CurrentVersion
│     (系统版本 — 检测降级攻击)
└─ \Registry\Machine\System\CurrentControlSet\Services
      (服务注册 — 检测驱动持久化)

API: CmRegisterCallback + ZwEnumerateKey + ZwQueryValueKey
```

### 3.6 HID 设备枚举

```
API: HidP_GetCollectionDescription (来自 HIDPARSE.SYS)
检测:
├─ 遍历系统所有 HID 设备
├─ 匹配已知作弊设备 VID/PID
│   ├─ VID_00FF → GVInput 虚拟鼠标 (已知作弊器)
│   ├─ VID_2341 → Arduino (常见 USB 模拟器)
│   └─ 其他非 HID 标准厂商标识
├─ 设备描述符指纹匹配
└─ 与已知白名单 (Logitech/Razer/SteelSeries) 对比
```

**这是 GVInput 虚拟鼠标 100% 被检测的根本原因**: `VID=0x00FF` 不在任何合法厂商的 USB-IF 分配表中。ACE 只需一行 `HidP_GetCollectionDescription` 就能定位。

### 3.7 网络检测 (NDIS)

```
API: NdisReadConfiguration / NdisOpenConfigurationEx / NdisCloseConfiguration
依赖: NDIS.SYS
检测:
├─ 网络适配器 MAC 地址采集 (硬件指纹)
├─ 异常流量模式检测 (KMBox 的 UDP 心跳包)
├─ VPN/代理检测
└─ 多网卡/虚拟网卡检测
```

### 3.8 硬件总线扫描

```
API: HalGetBusDataByOffset / HalSetBusDataByOffset (来自 HAL.dll)
检测:
├─ PCI 总线设备枚举 (检测 DMA 硬件如 Squirrel/PCILeech)
├─ 未识别 PCI 设备标记
├─ MmMapIoSpace → 映射物理内存 (检测 Memory Mapped IO 外设)
└─ MmGetPhysicalAddress → 检测物理内存布局
```

### 3.9 内存扫描

```
API: KeStackAttachProcess + MmIsAddressValid + ZwQueryVirtualMemory
    + MmMapViewInSystemSpace + ZwOpenSection + ZwMapViewOfSection
检测:
├─ 附加到受保护游戏进程空间
├─ 扫描已知作弊代码特征 (AOB 签名匹配)
├─ 检测 inline hook (代码段校验)
├─ 检测 VTable hook (虚表指针校验)
├─ 扫描隐藏模块 (PEB InLoadOrderModuleList 对比 VAD 树)
└─ 检测 .text 段页面保护属性变化
```

### 3.10 线程/APC 注入

```
API: KeInitializeApc + KeInsertQueueApc + PsLookupThreadByThreadId
    + ZwOpenThread + ZwQueryInformationThread
检测:
├─ 向游戏线程插入 APC 执行检测代码
├─ 获取线程上下文 (GetThreadContext) 检测调试寄存器
├─ 检测硬件断点 (DR0-DR3 非零)
├─ 线程起始地址溯源 (检测远程线程注入)
└─ 检测线程隐藏 (DKOM 后对比 PspCidTable)
```

### 3.11 签名树 (AVL 数据库)

```
API: RtlInitializeGenericTableAvl / RtlInsertElementGenericTableAvl
    / RtlLookupElementGenericTableAvl / RtlDeleteElementGenericTableAvl
    / RtlEnumerateGenericTableWithoutSplayingAvl
    / RtlNumberGenericTableElementsAvl / RtlIsGenericTableEmptyAvl

数据结构: AVL 平衡树
用途:
├─ 维护已知作弊进程/模块签名数据库
├─ 维护受保护游戏白名单
├─ O(LogN) 查找复杂度, 支持热更新
└─ 通过 IOCTL 接口同步云端数据库
```

---

## 4. 反分析手段分析

### 4.1 代码虚拟化

```
.tvm0 段: 2.8 MB (0x140398000-0x14067ffff)
保护范围: 所有核心检测逻辑 + 回调注册 + 签名验证

虚拟化特征:
├─ 原始 x64 指令 → 自定义字节码
├─ 每帧解释执行 (非 JIT, 性能优先于安全性)
├─ 所有 thunk_ 前缀函数 → JMP .tvm0
├─ IOCTL 处理: 0xa4c042de 哈希映射到虚拟处理器
```

### 4.2 动态 API 解析

```
绕过方法: 不通过导入表引用关键 API
实施:
├─ MmGetSystemRoutineAddress("ntoskrnl.exe") 运行时获取函数地址
├─ ObRegisterCallbacks / PsSetLoadImageNotifyRoutine 等均不在导入表
├─ 字符串 "ntoskrnl.exe" 在 .rdata 段 (0x140394af0)
└─ 函数名通过 RtlInitUnicodeString + MmGetSystemRoutineAddress 拼接
```

### 4.3 函数指针加密

发现于 ACE-Trace.dll, ACE-BASE.sys 类似:
```c
// 存储: EncodedPtr = (RealPtr ROR N) XOR Cookie
// 使用: RealPtr = (EncodedPtr XOR Cookie) ROL N
ulonglong EncodePtr(void* ptr) {
    byte shift = g_Cookie & 0x3f;
    return (ROR64(ptr, shift)) ^ g_Cookie;
}
```

### 4.4 注册表日志隐藏

ACE 将检测日志写入注册表而非文件系统, 避免被 Minifilter 自身拦截:
```c
FUN_1400694b8(
    L"\\Registry\\Machine\\...\\ACE-BASE",  // 自定义注册表键
    L"UData",                                // 值名
    REG_BINARY,                              // 类型
    &LogData,                                // 数据
    sizeof(LogData)
);
```

### 4.5 段布局混淆

```
INIT 段 (0x140393000): DriverEntry 代码 — 初始化完毕后标记为可丢弃
PAGE 段 (0x140391000): 可分页代码 — 系统空闲时可能被换出内存
.tvm0 段: 虚拟化核心 — 非页面 (绝不被换出, 检测逻辑不可中断)
.CRT 段:   C 运行时 — 异常处理/安全 cookie
```

---

## 5. 数据流转

### 5.1 检测事件上报链路

```
1. 内核回调触发 (进程创建/模块加载/句柄操作/...)
2. 事件暂存于 NonPagedPool 缓冲区 (0x448 字节/条目)
3. 系统工作线程 (PsCreateSystemThread) 定期轮询:
   ┌─ 签名验证 (RtlImageDirectoryEntryToData)
   ├─ AVL 树匹配 (RtlLookupElementGenericTableAvl)
   └─ 若匹配黑名单 → 立即上报
4. IOCTL 导出到用户态:
   └─ DeviceIoControl(ACE-BASE, IOCTL_QUERY_EVENTS, ...)
5. 用户态处理:
   ├─ ACE-Tray.exe → 弹窗警告/强制下线
   ├─ SGuard64.exe → 记录到本地日志
   └─ HTTP POST → ACE 云端 (封禁判定)
```

### 5.2 云端同步

```
下行 (云端 → 本地):
├─ 签名数据库更新 (AVL 树增量同步)
├─ 检测规则热更新 (无需重启驱动)
└─ 封禁列表下发

上行 (本地 → 云端):
├─ 检测事件上报 (含进程/模块哈希/IP/硬件指纹)
├─ 崩溃转储 (*.dmp.z) — 通过 ACE-Trace.dll
└─ 用户行为分析数据
```

---

## 6. 绕过策略评估

### 6.1 用户态 CE/内存工具 → 不可行

| 操作 | 拦截点 | 绕过可能 |
|------|--------|---------|
| OpenProcess(PROCESS_VM_READ) | ObRegisterCallbacks | 需要内核驱动 |
| ReadProcessMemory | ObRegisterCallbacks 句柄剥离 | 需要内核驱动 |
| WriteProcessMemory | ObRegisterCallbacks + 完整性校验 | 需要内核驱动 |
| VirtualAllocEx | ObRegisterCallbacks | 需要内核驱动 |
| CreateRemoteThread | PsSetCreateThreadNotifyRoutine | 需要内核驱动 |

### 6.2 DLL 注入 → 极高风险

```
检测链:
├─ 文件落盘 → Minifilter 拦截
├─ 模块加载 → PsSetLoadImageNotifyRoutine
├─ PE 签名验证 → RtlImageDirectoryEntryToData
├─ PEB 模块列表 → PsGetProcessPeb 读取
├─ VAD 树一致性 → MmMapViewInSystemSpace 对比
└─ 无签名 DLL → 秒杀

即使擦除了 PEB:
├─ VAD 树仍会暴露已映射内存区域
├─ 代码段哈希校验会检测 .text 修改
```

### 6.3 内核驱动 → 有条件可行

```
必要条件:
├─ 有效数字签名 (EV/WHQL) — AVL 白名单检查
├─ 不创建设备对象 — 不触发 IoDeviceObjectType 监控
├─ 不注册持久化服务 — 不触发注册表回调
├─ 驱动名随机化 — 避免 IoDriverObjectType 特征匹配
├─ 操作完成后立即卸载 — 避免定时扫描
├─ 使用 MmCopyVirtualMemory — 绕过 ObRegisterCallbacks
└─ 不超过 Flt 监控路径读取文件
```

### 6.4 虚拟鼠标驱动 → 极高风险

```
GVInput (VID=0x00FF) 检测链:
├─ HID 设备枚举 (HidP_GetCollectionDescription)      ← 第1击
├─ 设备注册表键 (Control\Class)                       ← 第2击
├─ 驱动模块加载 (PsSetLoadImageNotifyRoutine)          ← 第3击
├─ 驱动签名缺失 (RtlImageDirectoryEntryToData)        ← 第4击
├─ 驱动路径非系统目录 (Minifilter)                     ← 第5击
└─ AVL 签名树匹配 (RtlLookupElementGenericTableAvl)    ← 第6击

生存建议: 伪装为 Logitech/Razer VID + 复制真实驱动签名 + PE 头部
```

### 6.5 DMA 硬件 → 需谨慎

```
检测点:
├─ PCI 设备枚举 (HalGetBusDataByOffset)
├─ 物理内存映射检测 (MmGetPhysicalAddress)
├─ MmMapIoSpace 异常调用
└─ 未识别 PCI 设备标记

规避: 使用带 Spoof 功能的 DMA 固件 (伪装为网卡/声卡等常见设备)
```

### 6.6 相对安全的方案排序

| 方案 | 安全性 | 可行性 | 说明 |
|------|--------|--------|------|
| NtUser SendInput (MOUEEVENTF_MOVE) | 中 | 被游戏用户态 Hook 拦截 | win32u 直调可绕过部分但会被游戏内 DLL 检测 |
| 已签名内核驱动 + MmCopyVirtualMemory | 高 | 需 EV 证书 | 最可靠,但证书成本高 |
| DMA 硬件 (固件 Spoof) | 高 | 需硬件投入 | 完全隔离的独立系统 |
| KMBox (网络硬件) | 中高 | 低成本硬件 | NDIS 流量特征需降低 |
| Makcu (串口) | 中 | 低成本硬件 | COM 端口枚举需伪装 |
| Logitech IOCTL | 中低 | 免费 | 仅限罗技外设用户 |

---

## 7. 数据段资料

### 7.1 关键全局变量

| 地址 | 含义 |
|------|------|
| `0x1401d63f0` | 驱动对象指针 (PDRIVER_OBJECT) |
| `0x1401d63f8` | 设备对象指针 (PDEVICE_OBJECT) |
| `0x1401d63e4` | 设备引用计数器 |
| `0x1401d6410` | 设备名 (Unicode, "ACE-BASE") |
| `0x1401d6490` | 设备名 (ANSI) |
| `0x140192df0` | 工作线程就绪标志 |
| `0x140192e18` | 工作线程对象 (PETHREAD) |
| `0x1401391f0` | 模块哈希表基址 (65536 条目) |
| `0x1401391f8` | 模块数据库基址 |
| `0x1401df818` | ZwQuerySystemInformation 函数指针 |
| `0x1401f35c8` | IoCreateDeviceSecure 函数指针 |
| `0x1401f35c0` | IoValidateDeviceIoControlAccess 函数指针 |

### 7.2 设备/路径常量

| 地址 | 值 |
|------|-----|
| `0x1400ab540` | `\Device\ACE-BASE` |
| `0x1400ab500` | `\DosDevices\Global\ACE-BASE` |
| `0x1400ab570` | `ACE-BASE` |
| `0x1400ab450` | `D:P(A;;GA;;;BA)` (SDDL — 仅管理员) |
| `0x1400ab6f0` | `\Registry\Machine\SOFTWARE\Microsoft\Windows NT\CurrentVersion` |
| `0x1400ae4d0` | `\Registry\Machine\System\CurrentControlSet\Control\Class` |
| `0x1400ae670` | `\device\physicalmemory` |

### 7.3 动态解析 API 名称

| 地址 | 字符串 |
|------|--------|
| `0x1400ae380` | `IoCreateDeviceSecure` |
| `0x1400ae3b0` | `IoValidateDeviceIoControlAccess` |

---

## 8. ACE-Trace.dll 分析 (崩溃上报)

### 8.1 身份确认

| 属性 | 值 |
|------|-----|
| 实际名称 | **Bugtrace** (腾讯内部崩溃追踪库) |
| 导出函数 | `init_bugtrace`, `init_bugtrace_with_path_type`, `init_bugtrace_with_userinfo`, `init_bugtrace_with_userinfo_new`, `set_bugtrace_addr`, `set_user_stream` |
| 功能 | 游戏崩溃时: 捕获线程上下文 → 堆栈回溯 → 写 .dmp.z 压缩转储 → 监控线程发现 → 上报 ACE 云端 |

### 8.2 工作流程

```
游戏崩溃
    ↓ SEH/VEH 异常处理器捕获
    ├─ RtlCaptureContext → 收集 CPU 寄存器
    ├─ RtlWalkFrameChain → 堆栈回溯
    ├─ ReadProcessMemory → 读取崩溃线程内存
    ├─ SuspendThread/ResumeThread → 冻结其他线程
    ├─ MiniDumpWriteDump → 写 .dmp 文件
    └─ 压缩为 .dmp.z

监控线程 (FUN_1800c2340):
    轮询 *.dmp.z → 发现文件 → 读取 bugtrace.flag → 上报 → 删除
```

### 8.3 与本报告的关联

**推测**: ACE 可以通过崩溃转储分析出是否有外挂注入:
- 堆栈中出现非游戏模块 → 注入痕迹
- 异常指令地址在非法代码页 → inline hook
- 寄存器值异常 → 调试器/外挂修改

---

## 9. 关键检测时间点

```
系统启动:
  0s  ─ ACE-BOOT.sys (ELAM, 最先加载, 此时其他驱动尚未启动)
  +2s ─ ACE-BASE.sys (注册 Minifilter + 进程/模块回调)
  +5s ─ ACE-Service64.exe (启动用户态服务)
  +8s ─ SGuard64.exe (开始加载插件)
  +10s─ ACE-DRV64.dll + ACE-DFS64.dll (开始首轮全盘扫描)

游戏启动:
  +0s  ─ 游戏进程创建 → PsSetCreateProcessNotifyRoutineEx 触发
  +1s  ─ ACE-ATS64.dll 注入游戏 → 完整性校验
  +2s  ─ CSI64 验证游戏 DLL 签名
  +5s  ─ 开始实时内存扫描 (周期性)

检测到作弊:
  +0s  ─ 回调立即触发
  +1s  ─ 封禁事件写入注册表
  +2s  ─ IOCTL 通知用户态
  +5s  ─ ACE-Tray 弹窗 / 强制下线
  +30s ─ 云端封禁 ✓
```

---

## 10. 结论

### 10.1 ACE 防护能力评估

| 维度 | 评级 | 说明 |
|------|------|------|
| 内核回调覆盖 | ★★★★★ | 进程/模块/线程/句柄/注册表全覆蓋 |
| 文件系统保护 | ★★★★★ | Minifilter 截断所有文件操作 |
| 硬件检测 | ★★★★☆ | HID/NDIS/PCI 枚举, DMA 有一定盲区 |
| 代码保护 | ★★★★★ | 核心逻辑虚拟化, 关键 API 动态解析 |
| 云端协作 | ★★★★★ | 签名库热更新, 行为分析, 封禁同步 |
| 用户态保护 | ★★★☆☆ | 游戏内 DLL 可被绕过 (ring3 局限性) |

### 10.2 对 wa_project 的直接影响

| 组件 | 风险 | 原因 |
|------|------|------|
| `CrackerDrv.sys` | 中 | 已签名但非知名厂商, AVL 树未匹配即危险 |
| `reflect_stub.dll` | 高 | 文件落盘 + 模块加载双重检测 |
| GVInput | 极高 | VID=0x00FF → HID 枚举秒杀 |
| SHM 通信 | 低 | 纯内存操作, 不触发任何回调 |
| WebUI (localhost:9090) | 低 | 本地环回, ACE 不监控 localhost 流量 |

### 10.3 最终建议

1. **放弃 GVInput** — VID=0x00FF 是最强特征, ACE 检测率达到 100%
2. **驱动只读 + 即卸** — MmCopyVirtualMemory → SHM → 驱动卸载 → 擦注册表
3. **NtUser 移动如果被游戏钩子拦截** — 考虑定时器+随机化方案降低检测
4. **长期方案**: DMA 硬件 + 固件伪装为网卡
5. **持续监控 ACE 更新**: SGuardUpdate64.exe 每周可能更新签名库

---

## 11. ACE-ATS64.dll 分析 (反篡改/全系统扫描引擎)

### 11.1 基本信息

| 属性 | 值 |
|------|-----|
| 路径 | `SGuard\x64\Plugins\ACE-ATS64.dll` |
| 大小 | 9.0 MB |
| 镜像基址 | `0x180000000` |
| 虚拟化 | `.tvm0` 段 (7.2 MB) — 占代码比率最高的组件 (85%+) |
| 标准代码 | `.text` 段 (1.3 MB) |

### 11.2 导出函数

| 函数 | 地址 | 用途 |
|------|------|------|
| `CreateObject` | `0x180083670` | 工厂函数 (虚拟化) |
| `Init` | `0x180083e00` | 初始化 → 创建工作线程 → 开始扫描 |
| `DllEntry2` | `0x180083f00` | 次要入口 (虚拟化) |
| `GetObject1/2` | `0x180084830/0x180056a40` | 单例访问器 |

### 11.3 检测能力矩阵 (从导入 API 还原)

| 子系统 | 关键 API | 检测内容 |
|--------|---------|---------|
| **进程模块扫描** | `EnumProcessModules`, `GetModuleInformation`, `GetModuleFileNameExA` (PSAPI) | 扫描系统所有进程的已加载 DLL |
| **数字签名验证** | `CryptQueryObject`, `CertGetNameStringA`, `CertGetSubjectCertificateFromStore` (CRYPT32) | 验证所有二进制文件的 Authenticode 证书链 |
| **进程内存扫描** | `OpenProcess`, `ReadProcessMemory`, `VirtualQueryEx` | 扫描进程内存空间查找作弊特征 |
| **PE 头验证** | `NtQuerySystemInformation`, `NtMapViewOfSection`, `RtlImageNtHeader` (NTDLL) | 映射 PE 文件到内存, 检查头部完整性 |
| **网络适配器枚举** | `GetAdaptersAddresses` (IPHLPAPI) | 枚举网卡 → **KMBox 网络硬件检测** |
| **USB/设备枚举** | `QueryDosDeviceW` | 枚举 DOS 设备 → **Makcu/Arduino 串口检测** |
| **文件版本验证** | `GetFileVersionInfoW`, `VerQueryValueW` (VERSION) | 检查文件版本资源 (检测伪装/改名) |
| **云端上报** | `WinHttpOpen`, `WinHttpConnect`, `WinHttpReadData` | **HTTPS 上报所有扫描结果** |
| **DNS 溯源** | `getaddrinfo` (WS2_32) | 解析连接域名 |
| **线程操作** | `OpenThread`, `GetThreadTimes`, `TerminateThread` | 线程监控与终止 |
| **自毁能力** | `TerminateProcess`, `TerminateThread`, `__fastfail` | 检测到篡改时自毁/杀死进程 |

### 11.4 工作流程 (从 Init 和 Worker Thread 还原)

```
Init() 调用
    │
    ├─ 创建内部状态对象 (0x38 bytes) — 线程安全单例 (CriticalSection)
    ├─ 调用 Cereal 序列化库初始化配置
    │
    └─ CreateThread → Worker Scanner (FUN_1800d11a0)
              │
              ├─ 每轮扫描:
              │   ├─ GetModuleInformation + EnumProcessModules → 收集所有进程模块
              │   ├─ CryptQueryObject → 验证每个 .exe/.dll 的代码签名
              │   ├─ ReadProcessMemory + VirtualQueryEx → 扫描进程内存
              │   ├─ GetAdaptersAddresses → 检查网络设备
              │   ├─ QueryDosDeviceW → 检查 USB 设备
              │   ├─ GetFileVersionInfoW → 验证文件版本
              │   │
              │   ├─ 若发现可疑:
              │   │   ├─ TerminateProcess (可选, 取决于策略)
              │   │   └─ WinHttpWriteData → 上报到 ACE 云端
              │   │
              │   └─ Sleep → 继续下一轮
              │
              └─ 检测到自身被篡改 → __fastfail (立即崩溃)
```

### 11.5 状态机 (从 Init 逻辑还原)

```
状态码 0x15 → 初始化中 (FUN_180048b40 失败)
状态码 0x19 → 内部对象创建失败
状态码 0x1f → 重复初始化 (单例已存在)
状态码 0xae → 扫描验证失败 (检测到篡改, 写在工作线程中)
```

---

## 12. ACE-CSI64.dll 分析 (代码签名完整性 + 窗口检测)

### 12.1 基本信息

| 属性 | 值 |
|------|-----|
| 路径 | `SGuard\x64\Plugins\ACE-CSI64.dll` |
| 大小 | 7.8 MB |
| 镜像基址 | `0x180000000` |
| 虚拟化 | `.vmp0` 段 — **VMProtect** (与 `.tvm0` 不同引擎!), 虚拟地址空间 83MB (磁盘仅占 ~5MB, 运行时展开) |
| 标准代码 | `.text` 段 (1.8 MB) |

### 12.2 导出函数

| 函数 | 用途 |
|------|------|
| `CreateObject` | 工厂函数 (虚拟化 — 在 .vmp0) |
| `Ordinal_1~4` / `Ordinal_10~14` | 内部接口, 虚拟化保护 |
| `_guard_check_icall` | CFG (Control Flow Guard) 检查 |

### 12.3 全新检测能力 (此前未在其他组件发现)

#### 12.3.1 DLL 注入能力

```
CreateRemoteThread + VirtualAllocEx + WriteProcessMemory → 向目标进程注入 DLL
```

**这是关键能力**: ACE-CSI64 不只是"验证签名", 它能**主动注入到可疑进程中做深度扫描**。这解释了为什么作弊器经常崩溃 — 不是反作弊"检测"了它们, 是反作弊**把自己的代码注入进去跑**, 导致内存冲突。

#### 12.3.2 窗口枚举 (检测作弊器 GUI)

```
EnumWindows + EnumChildWindows          → 遍历系统中所有窗口
FindWindowW + FindWindowExW             → 搜索已知作弊器窗口标题/类名
GetWindowTextW + InternalGetWindowText  → 读取窗口标题
GetWindowThreadProcessId                → 窗口→进程映射
GetClassNameW + GetClassLongPtrW        → 窗口类名检测
GetClientRect + GetWindowInfo           → 窗口尺寸/位置
IsWindowVisible + GetForegroundWindow   → 窗口可见性
SendMessageTimeoutW                     → 发送消息检测行为
```

**结论**: ACE 维护了一个已知作弊器窗口标题/类名的黑名单。任何有可见 GUI 的作弊器 (如 CE、训练器) 都会被秒检测。

#### 12.3.3 用户令牌模拟

```
ImpersonateLoggedOnUser + RevertToSelf  → 模拟用户令牌
LookupAccountNameW                      → 账户 SID 查询
WTSQueryUserToken                       → 终端服务用户令牌
```

**用途**: 以 SYSTEM 权限运行时可模拟任意登录用户的身份访问其进程。

#### 12.3.4 磁盘全面扫描

```
GetLogicalDrives + GetLogicalDriveStringsW  → 枚举所有盘符
FindFirstFileW + FindNextFileW              → 遍历文件系统
GetLongPathNameW                            → 解析长路径
SearchPathW                                 → PATH 搜索
QueryDosDeviceW                             → DOS 设备枚举
```

#### 12.3.5 线程上下文检测

```
GetThreadContext → 读取线程 CPU 寄存器
OpenThread       → 打开任意线程
Thread32First/Next → 遍历所有线程
```

**用途**: 检测硬件断点 (DR0-DR3) 和调试寄存器 → 反调试。

### 12.4 威胁评估

CSI64 是作弊者的噩梦模块, 因为它:
1. **主动注入** 到可疑进程 — 不是被动等待, 是主动出击
2. **窗口扫描** 秒杀所有 GUI 作弊器
3. **VMProtect** 保护核心逻辑
4. **用户模拟** 绕过进程权限限制

---

## 13. ACE-DRV64.dll 分析 (驱动验证 + 设备枚举)

### 13.1 基本信息

| 属性 | 值 |
|------|-----|
| 路径 | `SGuard\x64\Plugins\ACE-DRV64.dll` |
| 大小 | 26.3 MB (**最大的 ACE 组件**) |
| 镜像基址 | `0x180000000` |
| 虚拟化 | **无** — 唯一没有 `.tvm0`/`.vmp0` 保护的组件! 全部代码可读 |
| Hook 引擎 | `.detourc` / `.detourd` 段 — **Microsoft Detours 库**, 用于 API Hook |
| TLS 回调 | 3 个 — 在 DllMain 之前执行 |
| 代码段 | `.text` 段 (5.6 MB) — 最大的标准代码段 |

### 13.2 为什么没有虚拟化保护

**推测**: 26.3MB 的代码太大, 全虚拟化会导致性能不可接受 (解释执行比原生代码慢 10-100 倍)。ACE 设计者权衡后选择:
- 小模块 → 全虚拟化 (.tvm0/.vmp0)
- 大模块 → 代码混淆 (入口反汇编 + 控制流平坦化)

### 13.3 全新检测能力

#### 13.3.1 Windows Authenticode 验证

```
WinVerifyTrust (WINTRUST.dll) → 完整的 Windows 驱动签名验证
```

与 CSI64 的 CryptQueryObject 不同, WinVerifyTrust 走完整的 Windows 信任链验证, 包括:
- 根证书信任链
- 吊销列表检查 (CRL/OCSP)
- 内核模式代码签名策略

#### 13.3.2 设备接口枚举

```
SetupDiEnumDeviceInterfaces (SETUPAPI) → 枚举所有设备接口
```

**比 HID 枚举更底层** — 能发现所有类型的设备 (而不仅是 HID):
- 显卡设备 (GPU 作弊硬件?)
- USB 控制器
- PCI 设备 (DMA 硬件)
- 串行端口
- 网络适配器

#### 13.3.3 服务配置查询

```
QueryServiceConfigA → 查询 Windows 服务配置
```

**检测作弊器以 Windows 服务形式持久化** — 常见于商业作弊。

#### 13.3.4 光标/屏幕监控

```
GetCursorInfo (USER32)      → 监控光标位置和绘制状态
GetDeviceCaps (GDI32)       → 设备能力查询
```

**可以检测 ESP/Overlay 渲染**: 如果叠加窗口覆盖在游戏窗口之上且持续绘制, ACE 通过 `GetCursorInfo` + 定时采样可以发现异常渲染行为。

#### 13.3.5 进程工作集监控

```
InitializeProcessForWsWatch (PSAPI) → 监控进程工作集
```

检测内存密集型作弊 (如 YOLO 推理引擎) — 大量内存分配会被标记。

#### 13.3.6 BCrypt 随机数

```
BCryptGenRandom (bcrypt.dll) → 加密安全随机数
```

用于生成不可预测的检测轮询间隔, 防止作弊器通过时序预测规避扫描。

### 13.4 Detours Hook 能力

```
.detourc 段 (0x180860000) → Detours 代码
.detourd 段 (0x180863000) → Detours 数据

典型使用场景:
├─ DetourAttach(&RealFunction, &HookFunction)  → Hook 系统 API
├─ DetourDetach(&RealFunction, &HookFunction)  → 卸载 Hook
└─ DetourTransactionCommit()                  → 原子提交
```

**可 Hook 的典型目标**:
- `NtUserSendInput` — 拦截虚拟输入
- `NtReadVirtualMemory` — 拦截内存读取
- `NtQueryVirtualMemory` — 拦截内存查询
- 游戏渲染 API (DXGI/D3D) — 检测叠加层

---

## 14. ACE-SSC64.dll / ACE-DFS64.dll 快速概览

### 14.1 ACE-SSC64.dll (SGuard Security Component — 10 MB)

| 路径 | `SGuard\x64\Plugins\ACE-SSC64.dll` |
|------|-------------------------------------|
| 推测功能 | 整体安全评估: 综合各检测模块的结果, 生成最终风险评分, 触发封禁/警告 |

### 14.2 ACE-DFS64.dll (Driver File System Scanner — 24.7 MB)

| 路径 | `SGuard\x64\Plugins\ACE-DFS64.dll` |
|------|-------------------------------------|
| 推测功能 | 文件系统扫描引擎: 包含已知作弊文件的签名数据库 (AVL 树), 遍历磁盘查找匹配文件 |

---

## 15. 完整组件能力矩阵总表

| 组件 | 大小 | 虚拟化 | 核心能力 |
|------|------|--------|---------|
| **ACE-BASE.sys** | 4.0 MB | `.tvm0` (2.8MB) | 进程/模块/句柄/注册表回调 + Minifilter |
| **ACE-BOOT.sys** | 1.0 MB | 未知 | ELAM 启动早期加载 |
| **ACE-CORE*.sys** | 3.2 MB | 未知 | 核心检测引擎 |
| **ACE-ATS64.dll** | 9.0 MB | `.tvm0` (7.2MB, 85%) | **全系统进程扫描 + 云端上报** |
| **ACE-CSI64.dll** | 7.8 MB | `.vmp0` (VMProtect) | **代码签名验证 + 窗口枚举 + DLL 注入** |
| **ACE-DRV64.dll** | 26.3 MB | **无 (Detours Hook)** | **驱动验证 + 设备枚举 + API Hook** |
| **ACE-DFS64.dll** | 24.7 MB | 未知 | 文件系统签名库扫描 |
| **ACE-SSC64.dll** | 10.0 MB | 未知 | 综合风险评估 |
| **ACE-Safe.dll** | 8.8 MB | 未知 | 安全环境检测 |
| **ACE-Trace.dll** | 2.3 MB | `.tvm0` | Bugtrace 崩溃上报 (非检测) |

### 15.1 虚拟化保护统计

| 引擎 | 出现组件 | 特征 |
|------|---------|------|
| `.tvm0` | ACE-BASE.sys, ACE-ATS64.dll, ACE-Trace.dll | 自定义虚拟机, 腾讯自研 |
| `.vmp0` | ACE-CSI64.dll | **VMProtect** — 俄罗斯第三方商业保护壳 |
| 无保护 | ACE-DRV64.dll (26.3MB) | 代码量太大, 全虚拟化性能不可接受 |

---

## 16. 对作弊开发者的实战建议 (基于完整分析)

### 16.1 绝对不可做的事

| 行为 | 触发检测 | 封禁速度 |
|------|---------|---------|
| 未签名驱动 (.sys) | ACE-BASE AVL 树 + ACE-DRV64 WinVerifyTrust | **< 5 分钟** |
| 自定义 VID HID 设备 (0x00FF 等) | HidP_GetCollectionDescription + 注册表 | **< 30 秒** |
| 可见 GUI 窗口 (CE/训练器) | EnumWindows + GetWindowText | **< 10 秒** |
| 在游戏目录写文件 | Minifilter (FltCreateFile) | **即时** |
| 从非系统路径加载 DLL | Minifilter + 模块回调 | **即时** |
| OpenProcess 读游戏内存 | ObRegisterCallbacks 句柄剥离 | **即时** |

### 16.2 相对安全的做法

| 行为 | 检测可能性 | 说明 |
|------|-----------|------|
| 已签名驱动 + MmCopyVirtualMemory | 低 | EV 证书成本高, 但技术可行 |
| DMA 硬件 (固件伪装为网卡) | 低 | SetupDiEnumDeviceInterfaces 可能发现 |
| SHM (共享内存) 通信 | 低 | 纯内存操作, 不走任何 API |
| NtUser SendInput (带随机延迟) | 中 | 游戏内 Detours Hook 可能拦截 |

### 16.3 ACE 的盲区

```
X 游戏进程外的纯内存操作 (SHM)
X 使用正规签名驱动 → AVL 白名单通过
X 硬件层攻击 (DMA) → 无软件检测手段
X 快速一次性操作 (读→卸→擦) → 定时扫描来不及
X 不触发任何系统回调的操作:
    ├─ 仅用 MmCopyVirtualMemory (不注册回调/不创建设备)
    ├─ 驱动只加载 < 5 秒即卸载
    └─ 不落地文件到磁盘 (内存加载)
```

---

## 17. ACE-Service64.exe 分析 (IPC 中枢服务)

### 17.1 基本信息

| 属性 | 值 |
|------|-----|
| 路径 | `C:\Program Files\AntiCheatExpert\ACE-Service64.exe` |
| 大小 | 3.2 MB |
| 镜像基址 | `0x140000000` |
| 虚拟化 | `.tvm0` 段 (350 KB) — 较小, 大部分代码可读 |
| Hook 引擎 | `.detourc` + `.detourd` 段 — Microsoft Detours |
| 导出 | 仅 `entry` (无 COM/导出接口) |
| 内嵌库 | **OpenSSL** — 加密/证书/SSL 全套 |

### 17.2 核心功能: IPC 中枢

ACE-Service64.exe 是整个 ACE 生态的**消息中枢**, 通过 Named Pipe 连接所有组件:

```
                    ┌─────────────┐
          ┌─────────│ ACE-BASE.sys│ (内核)
          │ IOCTL   └──────┬──────┘
          │                │ Named Pipe
    ┌─────┴──────────────┐ │
    │ ACE-Service64.exe  ├─┘
    │                    │
    │ ★ Named Pipe Hub ★ │───── SGuard64.exe (守护进程)
    │ ★ OpenSSL Engine ★ │───── ACE-Tray.exe  (UI/配置)
    │ ★ Event Logger  ★  │───── ACE-ATS64.dll (扫描引擎)
    │ ★ Crypto Service ★ │───── ACE-CSI64.dll (签名验证)
    └────────────────────┘───── ACE-DRV64.dll (驱动验证)
```

### 17.3 检测能力矩阵

| 子系统 | API | 功能 |
|--------|-----|------|
| **Named Pipe 服务器** | `CreateNamedPipeW`, `ConnectNamedPipe`, `SetNamedPipeHandleState`, `PeekNamedPipe` | ACE 内部 IPC 通信枢纽 |
| **Windows Event Log** | `RegisterEventSourceA`, `ReportEventA`, `DeregisterEventSource` | **所有检测事件写入系统事件日志** |
| **系统性能计数器** | `PdhOpenQueryW`, `PdhAddCounterW`, `PdhCollectQueryData`, `PdhGetFormattedCounterValue` | **实时 CPU/GPU/内存性能监控** |
| **Token 权限提升** | `AdjustTokenPrivileges`, `LookupPrivilegeValueW` | 获取 SE_DEBUG_NAME / SE_IMPERSONATE_NAME |
| **安全描述符** | `GetNamedSecurityInfoA`, `SetNamedSecurityInfoA`, `SetEntriesInAclA` | 管理 Named Pipe 和对象的 ACL |
| **注册表管理** | `RegCreateKeyExA`, `RegSetValueExA`, `RegQueryValueExA`, `RegDeleteValueW` | 读写 ACE 所有注册表配置和检测日志 |
| **网络事件监控** | `WSAEventSelect`, `WSAEnumNetworkEvents`, `WSAIoctl`, `WSACreateEvent` | **监控所有网络 Socket 事件** |
| **反调试** | `IsDebuggerPresent`, `RtlLookupFunctionEntry`, `RtlVirtualUnwind` | 调试器检测 + 栈回溯 |
| **进程/模块枚举** | `CreateToolhelp32Snapshot`, `Process32FirstW/Next`, `OpenProcess` | 遍历所有进程 |
| **进程创建** | `CreateProcessW` | 可启动子进程执行检测任务 |
| **文件操作** | `CreateFileMappingW`, `MapViewOfFile`, `GetFileVersionInfoW` | 文件映射 + 版本验证 |

### 17.4 OpenSSL 集成

ACE-Service64.exe **内嵌完整 OpenSSL 库**, 用于:

```
OpenSSL 能力:
├─ X509 证书解析 (TRUSTED CERTIFICATE / X509 CERTIFICATE / X509 CRL)
├─ 私钥操作 (PRIVATE KEY / ENCRYPTED PRIVATE KEY)
├─ DH/DSA 参数处理
├─ SSL/TLS 连接 (localhost/ + file: 前缀)
├─ PKCS8 密码解密
├─ 自定义证书路径 (/usr/local/ssl/certs)
└─ PEM 格式编码 (-----BEGIN ...)
```

**为什么 ACE 要自带 OpenSSL 而不是用 Windows CryptoAPI?**
- Windows CryptoAPI (BCrypt/NCrypt) 可能被 Hooking 绕过
- 自带的 OpenSSL 提供独立于系统的加密能力
- 与 ACE 云端通信使用自定义证书链 (不是系统证书存储)
- 签名验证可以走独立信任链 (不受系统根证书吊销影响)

### 17.5 Named Pipe 命名发现

通过字符串匹配发现一个关键 Pipe 名称:

```
Global\Ver → 版本校验/通信 Pipe
```

其他 Pipe 名称可能使用加密/哈希存储, 无法从静态字符串直接获取。

### 17.6 Windows Event Log — 取证价值

ACE 将所有检测事件写入 **Windows Event Log**, 这意味着:
- 可以通过 `事件查看器` → `Windows 日志` → `应用程序` 查看 ACE 检测日志
- 报告源: `RegisterEventSourceA` 注册的名称
- 日志格式: `ReportEventA(EventID, CategoryID, EventType, Strings[])`
- 这是 **取证分析 ACE 检测行为的直接入口**

---

## 18. ACE-SSC-DRV64.sys 快速分析

| 属性 | 值 |
|------|-----|
| 路径 | `SGuard\x64\Plugins\ACE-SSC-DRV64.sys` |
| 大小 | 2.7 MB |
| 功能 | SGuard Security Component Driver |
| 推测 | SGuard 专用内核驱动, 可能负责: 守护 ACE 自身不被卸载, 检测驱动劫持, 注册回调二次验证 |

---

## 19. 完整 IPC 通信拓扑图

```
┌───────────────────────────────────────────────────────────────┐
│                     ACE 云端 (HTTPS)                          │
│  https://[ACE Cloud] ← WinHttp (ATS64) ← 签名更新/策略下发   │
└───────────────────────┬───────────────────────────────────────┘
                        │
┌───────────────────────┼───────────────────────────────────────┐
│          用户态 (User Mode)                                    │
│                                                                │
│  ┌──────────────┐  Named Pipe  ┌───────────────────┐          │
│  │ ACE-Tray.exe │◄────────────►│ ACE-Service64.exe │          │
│  │ (UI/配置)    │              │ ★ IPC 中枢        │          │
│  └──────────────┘              │ ★ OpenSSL 引擎    │          │
│                                 │ ★ 性能计数器      │          │
│  ┌──────────────┐  Named Pipe  │ ★ Event Log       │          │
│  │SGuard64.exe  │◄────────────►│ ★ 注册表管理      │          │
│  │ (守护进程)   │              └──┬──────┬──────┬───┘          │
│  └──────────────┘                │      │      │              │
│                    DeviceIoControl│      │      │ Named Pipe   │
│  ┌──────────────┐               │      │      │              │
│  │ATS64 (扫描)  │◄──────────────┘      │      │              │
│  │CSI64 (签名)  │◄─────────────────────┘      │              │
│  │DRV64 (驱动)  │◄─────────────────────────────┘              │
│  │DFS64 (文件)  │                                             │
│  └──────────────┘                                             │
└───────────────────────┬───────────────────────────────────────┘
                        │ IOCTL (\\\\.\\Global\\ACE-BASE)
┌───────────────────────┼───────────────────────────────────────┐
│          内核态 (Kernel Mode)                                  │
│  ┌──────────────────┐  ┌────────────────┐  ┌──────────────┐  │
│  │  ACE-BASE.sys    │  │ ACE-BOOT.sys   │  │ACE-CORE*.sys │  │
│  │  ★ 进程/模块回调 │  │ (ELAM 启动早期)│  │(核心引擎)    │  │
│  │  ★ Minifilter    │  └────────────────┘  └──────────────┘  │
│  │  ★ ObCallbacks   │                                         │
│  │  ★ 注册表回调    │  ┌──────────────────────────────────┐  │
│  │  ★ HID/NDIS/PCI  │  │  ACE-SSC-DRV64.sys              │  │
│  └──────────────────┘  │  (SGuard 驱动守护)               │  │
│                         └──────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────┘
```

---

## 20. 总结: ACE 组件最终统计

| 类别 | 数量 | 总大小 |
|------|------|--------|
| 内核驱动 (.sys) | 5 个 | 13.7 MB |
| 用户态 DLL (检测插件) | 6 个 | 86.4 MB |
| 用户态 EXE (服务/UI) | 5 个 | 24.5 MB |
| **总计** | **16 个组件** | **124.6 MB** |

| 保护手段 | 出现组件数 |
|---------|-----------|
| `.tvm0` 虚拟化 | 4 个 (BASE/ATS64/Trace/Service) |
| `.vmp0` (VMProtect) | 1 个 (CSI64) |
| Detours API Hook | 2 个 (DRV64/Service) |
| 动态 API 解析 | 2 个 (BASE/CORE) |
| **无保护 (全可读)** | 1 个 (DRV64, 26MB) |
| `.tvm0` 签名库嵌入 | 1 个 (DFS64, 25.5MB 虚拟化字节码 = 签名哈希数据库) |

---

## 21. ACE-DFS64.dll 深度分析 (文件系统扫描 + 签名库)

### 21.1 基本信息

| 属性 | 值 |
|------|-----|
| 路径 | `SGuard\x64\Plugins\ACE-DFS64.dll` |
| 大小 | 24.7 MB |
| 镜像基址 | `0x180000000` |
| 虚拟化 | `.tvm0` 段 (25.5 MB) — **整个 DLL 98% 虚拟化**, 标准代码仅 1.2MB |
| 导出 | `CreateObject` + 8 个 Ordinal 接口 |
| 特殊段 | `.fptable` — 函数指针跳转表 (虚拟化代码入口) |

### 21.2 架构: 签名库嵌入虚拟机

DFS64 的独特之处在于**签名数据库不是存储在 .data 或 .rdata 段, 而是嵌入在 .tvm0 虚拟机字节码中**:

```
常规签名库:   .data 段 → [hash1, hash2, ..., hashN] → 静态可读
ACE-DFS64:   .tvm0 段 → 虚拟机操作码:
              vm_push(hash1); vm_cmp(); vm_jmp_if_match(SIG_FOUND)
              vm_push(hash2); vm_cmp(); vm_jmp_if_match(SIG_FOUND)
              ...
```

**这样做的原因**:
1. 25.5MB 的纯数据会触发反病毒软件的检测 (巨大的未签名数据段)
2. 虚拟机字节码无法被 `strings` / `binwalk` 提取
3. 签名更新 = 新的虚拟机字节码片段 (热替换, 不需要重启)
4. 反篡改: 修改签名数据 = 破坏虚拟机指令 = 执行崩溃

### 21.3 文件系统扫描能力 (从导入 API 还原)

| 子系统 | 关键 API | 扫描目标 |
|--------|---------|---------|
| **递归目录遍历** | `FindFirstFileW/A`, `FindFirstFileExW`, `FindNextFileW/A`, `FindClose` | 遍历所有磁盘分区 |
| **文件属性采集** | `GetFileAttributesW/ExW`, `GetFileSize/Ex`, `GetFileTime`, `GetFileInformationByHandle/Ex` | 文件元数据指纹 |
| **PE 头读取** | `CreateFileMappingW`, `MapViewOfFile`, `UnmapViewOfFile`, `OpenFileMappingA` | **内存映射 PE 文件 (绕过 ReadFile API)** |
| **磁盘枚举** | `GetLogicalDrives`, `GetLogicalDriveStringsA`, `GetDiskFreeSpaceExW` | 发现所有卷 |
| **系统路径** | `GetSystemDirectoryW`, `GetWindowsDirectoryW/A`, `GetSystemWindowsDirectoryW` | 重点扫描系统目录 |
| **计算机标识** | `GetComputerNameW/A`, `GetComputerNameExA` | 硬件指纹采集 |
| **环境检测** | `GetEnvironmentVariableA` | 检测作弊器环境变量 |
| **设备枚举** | `QueryDosDeviceW` | 发现可疑设备路径 |
| **内核通信** | `DeviceIoControl` | 向 ACE-BASE.sys 查询/接收指令 |
| **IPC 通信** | `CreatePipe`, `PeekNamedPipe` | 与 ACE-Service64.exe 交换扫描结果 |
| **进程操作** | `CreateToolhelp32Snapshot`, `Process32FirstW/Next`, `Module32FirstW/Next`, `K32GetModuleFileNameExW` | 枚举所有进程和其模块 |
| **并行扫描** | `CreateThread`, `SetThreadAffinityMask`, `GetLogicalProcessorInformation` | 多线程加速, 绑定 CPU 核心 |
| **内存管理** | `VirtualAlloc`, `VirtualFree`, `GlobalMemoryStatus/Ex` | 动态分配扫描缓冲区 |
| **反调试** | `IsDebuggerPresent` | 自检 |

### 21.4 扫描策略推断

基于 API 模式和 DFS 命名 (Driver File System):

```
第1轮: 快速扫描
  ├─ GetLogicalDrives → 枚举所有磁盘
  ├─ 跳过系统保留分区 (可配置)
  └─ 每个分区创建独立工作线程 (SetThreadAffinityMask)

第2轮: 重点扫描
  ├─ GetSystemDirectoryW → %SystemRoot%\System32
  ├─ GetWindowsDirectoryW → %SystemRoot%
  ├─ GetSystemWindowsDirectoryW → 系统 Windows 目录
  └─ 递归遍历 FindFirstFileW/FindNextFileW

第3轮: 深度扫描 (每个候选文件)
  ├─ CreateFileW → 打开文件
  ├─ GetFileInformationByHandle → 读取文件元数据
  ├─ CreateFileMappingW + MapViewOfFile → 映射到内存
  ├─ [虚拟化代码] 提取 PE 头 → 计算哈希 → 对比签名库
  ├─ [虚拟化代码] 检查节区名称/大小/入口点
  └─ 匹配 → 上报 Service64 → 写入 Event Log

第4轮: 进程模块交叉验证
  ├─ CreateToolhelp32Snapshot → 遍历所有进程
  ├─ Module32First/Next → 枚举已加载模块
  ├─ K32GetModuleFileNameExW → 获取模块文件路径
  └─ 与文件系统扫描结果交叉比对
```

### 21.5 签名库内容推断

基于 25.5MB 的 .tvm0 大小和 ACE 保护的游戏范围推断:

```
签名类型                   预估占比
├─ 已知作弊器 PE 哈希       ~40% (SHA256/MD5 黑名单)
├─ 已知作弊器文件路径模式    ~20% (正则/通配符模式)
├─ 已知作弊器代码特征 (AOB)  ~15% (节区字节序列)
├─ 已知作弊器证书指纹        ~10% (代码签名证书哈希)
├─ PE 结构异常规则            ~10% (节区数量/入口点在非代码段等)
└─ 虚拟机解释器字节码         ~5%  (解释器本身, 非签名数据)
```

### 21.6 与其他组件的协作

```
DFS64 扫描文件 → 发现可疑
    │
    ├─→ Named Pipe → ACE-Service64.exe
    │       ├─→ Event Log (系统事件日志)
    │       └─→ WinHTTP → ACE 云端
    │
    ├─→ DeviceIoControl → ACE-BASE.sys (内核验证)
    │       └─→ 确认后 → ObCallbacks → 阻止进程启动
    │
    └─→ CreateProcessA → 沙箱执行可疑文件 (分析行为)
```

### 21.7 实战影响

1. **任何落地的作弊 DLL/EXE 都会被扫描** — 即使从未执行
2. **PE 映射读取绕过文件锁定** — 即使文件正在使用也无法隐藏
3. **多线程并行** — 扫描速度可达每秒数千文件
4. **签名库不可提取** — 25.5MB 嵌入虚拟机字节码, 无法静态 dump
5. **唯一绕过方式**: 不落盘 (内存加载) 或不使用已知签名

---

## 22. ACE-BOOT.sys 分析 (ELAM 启动早期驱动)

### 22.1 基本信息

| 属性 | 值 |
|------|-----|
| 路径 | `C:\Program Files\AntiCheatExpert\ACE-BOOT.sys` |
| 大小 | 1.0 MB |
| 镜像基址 | `0x140000000` |
| 类型 | **ELAM (Early Launch Anti-Malware)** 驱动 |
| 虚拟化 | `.tvm0` 段 (700 KB) |
| 导出 | 仅 `DriverEntry` |

### 22.2 ELAM 特性

ELAM 驱动在 Windows 启动过程中**最先加载** (在第三方驱动之前), 拥有 "先发优势":

```
系统启动顺序:
  1. Windows 内核 (ntoskrnl.exe)
  2. HAL (hal.dll)
  3. ELAM 驱动 ← ACE-BOOT.sys 在这里!
  4. 系统关键驱动 (磁盘/文件系统)
  5. 其他第三方驱动 ← ACE-BASE.sys 在这里
  6. 用户态服务 ← ACE-Service64.exe 在这里
```

### 22.3 与 ACE-BASE.sys 的关键差异

| 特性 | ACE-BOOT.sys (ELAM) | ACE-BASE.sys |
|------|---------------------|--------------|
| 大小 | 1.0 MB (轻量) | 4.0 MB (重量) |
| `.tvm0` | 700 KB | 2.8 MB |
| 加载时机 | 系统最早 | 正常驱动加载 |
| 进程监控 | ❌ `PsSetCreateProcessNotifyRoutineEx` | ✅ |
| 模块监控 | ✅ `PsSetLoadImageNotifyRoutine` | ✅ (动态) |
| Minifilter | ❌ | ✅ |
| 句柄保护 | **✅ `ObRegisterCallbacks` 直调** | ✅ (动态解析) |
| 回调对象 | **✅ `ExCreateCallback` / `ExRegisterCallback`** | ❌ |
| HID 枚举 | ❌ | ✅ |
| 驱动卸载 | ✅ `ZwUnloadDriver` | ✅ |
| 设备 IOCTL | **✅ `ZwDeviceIoControlFile` + `IoBuildDeviceIoControlRequest`** | ❌ |
| CPU 缓存刷新 | **✅ `KeInvalidateAllCaches`** | ❌ |

### 22.4 独有的 `ExRegisterCallback` 机制

ACE-BOOT.sys 使用 `ExCreateCallback` / `ExRegisterCallback` 创建一个**内核回调对象**, 其他 ACE 驱动可以订阅:

```
ACE-BOOT.sys:
  ExCreateCallback(&CallbackObj, ...)
  // 通知所有订阅者: "我刚加载完毕, 系统启动中"

ACE-BASE.sys:
  ExNotifyCallback(CallbackObj, ...)
  // 通知 BOOT: "我已接管, 可以卸载了"
```

这是 ACE 内部组件间通信的内核级机制, **独立于 IOCTL 和 Named Pipe**。

### 22.5 核心代码还原

```c
// ACE-BOOT.sys DriverEntry (还原)
NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_REGISTRY_PATH reg) {
    __security_init_cookie();  // 栈保护

    // 1. 创建 ELAM 回调对象 (ACE 内部通信)
    ExCreateCallback(&g_AceBootCallback, &g_SecurityDescriptor, TRUE, TRUE);

    // 2. 注册模块加载回调 ← 捕获所有早期驱动加载!
    PsSetLoadImageNotifyRoutine(ModuleLoadCallback);

    // 3. 注册句柄保护回调
    ObRegisterCallbacks(&g_ObCallbacks, &g_RegistrationHandle);

    // 4. 创建系统线程 (后台监控)
    PsCreateSystemThread(&hThread, ..., BootMonitorWorker, NULL);

    // 5. 枚举已经加载的设备接口
    IoGetDeviceInterfaces(&GUID_DEVCLASS_SYSTEM, ...);

    // 6. 所有初始化完成 → 通知订阅者
    ExNotifyCallback(g_AceBootCallback, BOOT_READY, 0);
}
```

### 22.6 对抗意义

1. **ACE 从开机第一刻就在运行** — 没有"窗口期"可以在 ELAM 加载前注入驱动
2. **模块监控覆盖全启动周期** — 包括内核、HAL、系统驱动等所有模块
3. **`ObRegisterCallbacks` 比 BASE 更早生效** — 从最开始就保护游戏进程句柄
4. **`KeInvalidateAllCaches`** — 防止利用 CPU 缓存侧信道攻击绕过内存扫描
5. **CCallback 对象为驱动间通信提供独立信道** — 不受 IOCTL/Named Pipe 限制

---

## 23. ACE-CORE30405.sys 分析 (WDF 框架 + NMI + 物理内存控制)

### 23.1 基本信息

| 属性 | 值 |
|------|-----|
| 路径 | `C:\Program Files\AntiCheatExpert\ACE-CORE30405.sys` |
| 大小 | 3.2 MB (磁盘) |
| `.data` 虚拟大小 | **85 MB** (运行时分配) |
| 镜像基址 | `0x140000000` |
| 框架 | **WDF (Windows Driver Framework / KMDF)** |
| 虚拟化 | **无** (纯原生 x64 代码) |
| 特殊段 | `.cave` (代码洞, 用于运行时补丁注入) |
| 导出 | 仅 `DriverEntry` |

### 23.2 架构差异

ACE 三个内核驱动采用**三层防御**架构:

```
ACE-BOOT.sys  (WDM, ELAM)    ← 最早加载, 轻量防护
ACE-BASE.sys  (WDM, 标准)    ← 主防线, 全面检测
ACE-CORE*.sys (WDF, 激进)    ← 最后手段, 系统级控制
```

CORE30405 使用 **KMDF (WDF 框架)** 而非 WDM, 这表明:
- 版本 30405 = WDF 主版本 0x208 (WDF 1.15+)
- 利用 WDF 内置的电源管理、同步、I/O 队列
- `.data` 段虚拟分配 85MB 用于 WDF 对象树

### 23.3 独有能力 (BASE/BOOT 都没有)

#### 23.3.1 NMI 反调试

```
KeRegisterNmiCallback(MyNmiHandler, ...)
    → 注册 NMI (不可屏蔽中断) 回调
    → 每次 NMI 触发时检查 CPU 状态:
        ├─ DR0-DR7 调试寄存器是否非零 → 硬件断点检测
        ├─ TF (Trap Flag) 是否置位 → 单步调试检测
        └─ GDTR/IDTR 是否被修改 → rootkit 检测
```

**NMI 无法被禁用** — 这是硬件级别的检测, 即使作弊器 HOOK 了 `KeRegisterNmiCallback` 也无法阻止 NMI 本身。

#### 23.3.2 物理内存控制

```
MmAddPhysicalMemory           → 向内存管理器添加物理页
MmRemovePhysicalMemory        → 从内存管理器移除物理页
MmMarkPhysicalMemoryAsBad     → 标记物理页为故障
MmGetPhysicalAddress          → VA → PA 转换
MmMapIoSpace / MmUnmapIoSpace → 映射物理地址空间
```

**用途**: 如果检测到 DMA 作弊硬件的物理内存范围, CORE30405 可以直接从系统中 **移除该物理内存**, 使 DMA 硬件无法访问。

#### 23.3.3 进程控制

```
PsSuspendProcess  → 冻结整个进程 (所有线程)
PsResumeProcess   → 恢复进程
ZwTerminateProcess → 强杀进程
ZwOpenProcess      → 打开任意进程
```

**用途**: 检测到作弊后, 不是弹窗, 而是直接冻结 → 分析 → 强杀。

#### 23.3.4 句柄表枚举

```
ExEnumHandleTable → 遍历进程的 HANDLE_TABLE
```

**这能发现所有隐藏的句柄** — 包括 `ObRegisterCallbacks` 之前创建的句柄和通过 DKOM 隐藏的句柄。

#### 23.3.5 调试端口检测

```
PsGetProcessDebugPort → 检测进程是否有调试器附加
```

比 `IsDebuggerPresent` 更底层。即使作弊器 Hook 了 `IsDebuggerPresent` 返回 FALSE, `PsGetProcessDebugPort` 在内核态返回真实值。

#### 23.3.6 UEFI 固件访问

```
ExGetFirmwareEnvironmentVariable → 读取 UEFI 变量
HalGetEnvironmentVariableEx      → 读取 HAL 环境变量
VslGetSecurePciEnabled           → 检测 Virtual Secure Mode PCI
```

检测 Secure Boot 状态、固件级篡改、虚拟化环境。

#### 23.3.7 显示器控制

```
InbvAcquireDisplayOwnership → 接管显示器 (启动阶段)
InbvResetDisplay            → 重置显示器
```

**用途**: 检测 overlay 渲染到屏幕上的行为。可以在作弊 overlay 绘制之前先接管显示控制。

#### 23.3.8 内嵌 Zlib 解压缩

```
zlib 错误字符串 (incorrect header check, invalid block type, ...)
→ CORE30405 内嵌完整 Zlib 解压库
→ 用于解压缩从云端下发的签名更新包
```

#### 23.3.9 HID 设备路径检测

```
\kbdhid     → 键盘 HID 驱动路径
\mshidkmdf  → 鼠标 HID 驱动路径
Input Report / Output Report / Feature Report → HID 报告类型
```

直接检查 HID 驱动对象路径 — 如果 `\mshidkmdf` 被替换或 HOOK, 立即检测。

#### 23.3.10 全局定时器哈希表

```
gTimerHashTable → 定时器管理
用于: 周期性 NMI 触发 / 定时内存扫描 / 定时句柄表枚举
```

### 23.4 检测工作流推断

```c
// ACE-CORE30405.sys 核心循环 (还原)
void CoreDetectionLoop() {
    RegisterNmiCallback(NmiHandler);       // 注册 NMI 处理器
    RegisterBugCheckCallback();            // 注册蓝屏回调

    while (TRUE) {
        // 每 500ms
        ForEachProtectedProcess(pid) {
            Process = PsLookupProcessByProcessId(pid);
            
            // 检查调试端口
            if (PsGetProcessDebugPort(Process) != NULL) {
                ReportCheat(pid, "Debugger detected");
                PsSuspendProcess(Process);  // 冻结进程
            }
            
            // 枚举所有句柄
            ExEnumHandleTable(Process, EnumCallback, NULL);
            // → 发现隐藏的游戏句柄 → 报告
            
            // 检查物理内存映射
            ForEachDMAAddressRange(range) {
                if (MmIsAddressValid(range)) {
                    ReportDMA(range);
                    MmRemovePhysicalMemory(range);  // 拔掉 DMA 内存!
                }
            }
        }
        
        KeDelayExecutionThread(500ms);
    }
}

void NmiHandler() {
    ULONG64 dr0, dr1, dr2, dr3, dr6, dr7;
    ReadDebugRegisters(&dr0, &dr1, &dr2, &dr3, &dr6, &dr7);
    if (dr0|dr1|dr2|dr3|dr7 != 0) {
        KeBugCheck(MANUALLY_INITIATED_CRASH);  // BSOD
    }
}
```

### 23.5 对抗意义

1. **NMI 反调试无法在软件层绕过** — 必须物理屏蔽 NMI 信号
2. **物理内存移除** — DMA 作弊硬件可能被直接从系统中剔除
3. **句柄表枚举** — 即使 DKOM 隐藏了进程/句柄, 直接遍历 HANDLE_TABLE 仍能发现
4. **进程冻结** — 作弊进程可以被瞬间冻结, 无法反抗
5. **zlib 更新** — 签名库可以压缩后热更新到内核

这是 ACE 的最后一道防线 — 如果作弊绕过了 BOOT 和 BASE, CORE30405 会动用系统级权限直接物理清除它。

---

## 24. 基于已知信息的不明部分推演

### 24.1 IOCTL 码推演

ACE-BASE.sys 创建的设备使用 `FILE_DEVICE_UNKNOWN` (0x22), `FILE_DEVICE_SECURE_OPEN` (0x100):

```c
#define ACE_DEVICE_TYPE  0x22
#define ACE_IOCTL_BASE   0x800  // 推测起始 Function 号

// 基于已知能力推演的 IOCTL 码
#define IOCTL_ACE_QUERY_DRIVER_LIST    CTL_CODE(ACE_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ACE_QUERY_PROCESS_INFO   CTL_CODE(ACE_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ACE_SET_POLICY           CTL_CODE(ACE_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ACE_REPORT_DETECTION     CTL_CODE(ACE_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ACE_HASH_TABLE_QUERY     CTL_CODE(ACE_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ACE_AVL_LOOKUP           CTL_CODE(ACE_DEVICE_TYPE, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ACE_QUERY_MODULE_INFO    CTL_CODE(ACE_DEVICE_TYPE, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ACE_SET_CALLBACK_STATE   CTL_CODE(ACE_DEVICE_TYPE, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

**推演依据**:
- `FUN_140010080` 使用 0x10000 元素哈希表 → IOCTL 至少需要一个查询接口
- `FUN_140066130` 枚举模块 → 需要 IOCTL 导出到用户态
- `FUN_1400694b8` 写注册表 → 事件上报 IOCTL
- `FUN_140012b00` 写 `UData` 值 → 配置下发 IOCTL

### 24.2 检测计分公式推演

基于多个检测层的交叉验证, ACE 可能使用加权计分:

```
RiskScore = Σ(Weight × MatchScore) / Σ(Weight)

检测层           权重  触发条件
─────────────────────────────────────
GUI窗口检测       30    EnumWindows 发现已知标题/类名
无签名驱动        25    WinVerifyTrust 失败
HID VID异常       25    VID 不在 USB-IF 白名单
未知模块加载       20    PsSetLoadImageNotify 发现无签名模块
文件落盘异常      15    Minifilter 检测 System32 外驱动
注册表钩子        15    CmCallback 发现可疑注册表键
调试器附加        20    PsGetProcessDebugPort 非零
NMI触发DRx非零    50    NMI 回调检测到硬件断点 ← 直接判定
DMA硬件检测       50    SetupDiEnum 发现未识别 PCI 设备 ← 直接判定
─────────────────────────────────────
总计             250

阈值:
  < 30  → 监控中 (仅记录)
  30-60 → 警告 (Event Log + 云端上报)
  60-80 → 高危 (通知用户态弹窗警告)
  > 80  → 封禁 (挂起进程 → 上报云端 → 强制下线)
  个别项=50 → 即时封禁 (NMI/DMA 直接判定)
```

**推演依据**: ATS64 工作线程中检测标志位 `DAT_180206f30~39` 共 10 个标志, 对应不同检测层的结果。`Init()` 中的状态码 (0x15/0x19/0x1f/0xae) 表示不同严重级别。

### 24.3 签名数据库格式推演

DFS64 的 25.5MB `.tvm0` 字节码中包含签名匹配逻辑:

```
签名记录结构 (推演):
struct SignatureRecord {
    UINT8  Type;           // 0=SHA256, 1=MD5, 2=AOB, 3=PathPattern, 4=CertHash
    UINT8  Flags;          // bit0=PE only, bit1=driver only, bit2=DLL only
    UINT16 Weight;         // 检测权重
    UINT32 StringOffset;   // 签名字符串偏移 (虚拟化字节码内)
    // 实际签名数据嵌入在虚拟机操作码序列中:
    // vm_push(0x12345678); vm_push(0x9ABCDEF0);
    // vm_cmp_hash(); vm_jmp_if_match(MATCH_LABEL);
};

签名类型分布推测:
├─ SHA256 哈希       ~10,000 条   (已知作弊文件)
├─ 文件路径模式       ~5,000 条    (正则/通配符)
├─ AOB 特征码         ~2,000 条    (已知代码片段)
├─ 证书指纹           ~500 条      (吊销的签名证书)
└─ PE 异常规则         ~100 条      (节区/入口点异常)
```

**推演依据**: 25.5MB ÷ 平均每条 ~1500 字节 (含虚拟机操作码扩展开销) ≈ 17,000 条签名。

### 24.4 云端通信协议推演

基于 ATS64 的 WinHTTP + Service64 的 OpenSSL:

```
HTTPS 端点推演:
├─ POST https://[ace-cloud]/api/v3/report
│     → 上报检测事件 (JSON + zlib)
│     Payload: { event_id, timestamp, process_hash, driver_list[], risk_score }
│
├─ POST https://[ace-cloud]/api/v3/check
│     → 查询签名数据库更新
│     Response: { version, delta[], full_url }
│
├─ GET https://[ace-cloud]/api/v3/signatures/v{version}.zlib
│     → 下载 zlib 压缩的完整签名库增量
│     → Service64 解压 → CORE30405 加载到 AVL 树
│
└─ POST https://[ace-cloud]/api/v3/dump
      → 上传崩溃转储 (*.dmp.z) — 通过 Trace.dll
```

**推演依据**: CORE30405 内嵌 zlib 用于解压更新; WinHTTP 是唯一 HTTP 库; OpenSSL 用于自定义证书链; `UrlEscapeA` 在 Service64 中用于 URL 编码。

### 24.5 Named Pipe 协议推演

Service64 作为 IPC 中枢, 使用 Named Pipe 与各组件通信:

```
Pipe 命名推演 (基于 Global\Ver 发现):
├─ \\.\pipe\ACE-Boot-Comm    → BOOT ↔ BASE 内核通信
├─ \\.\pipe\ACE-Service-Ctrl → SGuard ↔ Service64
├─ \\.\pipe\ACE-Scan-Result  → DFS64/ATS64 → Service64
├─ \\.\pipe\ACE-UI-Notify    → Service64 → Tray.exe
└─ \\.\pipe\ACE-Ver-{hash}   → 版本校验 (Global\Ver 字符串)

消息格式推演 (二进制 + 长度前缀):
struct AcePipeMessage {
    UINT32 Magic;         // 0x41434550 ("PECA" — "ACE" + 'P'ipe)
    UINT32 Version;       // 协议版本
    UINT32 Command;       // 命令码
    UINT32 PayloadSize;   // 数据大小
    UINT8  Payload[];     // 变长数据
    UINT32 Checksum;      // CRC32
};
```

**推演依据**: Service64 使用 `CreateNamedPipeW` + `ConnectNamedPipe` 模式; ATS64/DFS64/CSI64 均引用 Service64 管道; 消息格式借鉴 Windows 标准 IPC 模式。

### 24.6 ACE 时间线推演 (精确秒级)

```
T+0s    ELAM 阶段
        BOOT.sys 通过 PsSetLoadImageNotifyRoutine 注册模块回调
        BOOT.sys 通过 ObRegisterCallbacks 注册句柄保护
        BOOT.sys 通过 ExCreateCallback 创建 BOOT_READY 回调对象

T+2s    驱动加载阶段
        BASE.sys 通过 IoCreateDeviceSecure 创建设备
        BASE.sys 通过 FltRegisterFilter 注册 Minifilter
        BASE.sys 通过 PsSetCreateProcessNotifyRoutineEx 注册进程回调
        BASE.sys 向 BOOT.sys ExNotifyCallback(BASE_READY)

T+5s    用户态启动阶段
        Service64.exe 启动 → 创建 Named Pipe 服务器
        SGuard64.exe 启动 → 连接 Service64 Pipe
        DFS64.dll 注入 → 开始第1轮快速文件扫描

T+10s   插件加载阶段
        ATS64.dll → 开始全系统进程模块扫描
        CSI64.dll → 开始窗口枚举 + 签名验证
        DRV64.dll → 通过 Detours 安装 API Hook

T+30s   初检完成
        Service64 汇总所有扫描结果 → 计分
        WinHTTP POST → 上报云端
        收到云端策略 → 下发到各组件

T+60s   进入稳定监控循环
        BASE.sys 持续监控进程/模块/句柄/注册表/Minifilter
        ATS64.dll 每 5-60 秒轮询扫描 (随机间隔)
        CORE30405.sys 每 500ms NMI 触发 (随机 ±50ms)
        Service64 每 10 秒写 Event Log 统计
        DFS64 每 30 分钟增量扫描新增文件
```

### 24.7 wa_project 完整绕过清单

基于以上所有分析, 推演出完整的绕过要求:

```
□ 1. 驱动签名
    ├─ 使用 EV/WHQL 签名的内核驱动
    ├─ 或: 使用已验证未被 AVL 收录的签章
    └─ 注意: DFS64 会扫描驱动文件路径和哈希

□ 2. 驱动加载时机
    ├─ 在 ACE-BOOT.sys 加载后 → 会被 PsSetLoadImageNotifyRoutine 捕获
    ├─ 最佳: 在 ACE-BASE.sys 加载前? → 不可能, ELAM 先加载
    └─ 现实: 加载→读内存→卸载 (5秒内完成), 避免定时扫描

□ 3. 内存读取
    ├─ MmCopyVirtualMemory → 绕过 ObRegisterCallbacks
    ├─ 不调用 OpenProcess → 不触发句柄剥离
    └─ 使用 SHM 传递数据 → 纯内存操作, 无 IPC 痕迹

□ 4. 文件操作
    ├─ 不在 System32 以外落盘 → 不触发 Minifilter 路径规则
    ├─ 不在游戏目录写文件 → 不触发 Minifilter 保护
    └─ 所有 payload 内存加载 → 不可能完全消除文件痕迹

□ 5. 通信
    ├─ 不创建 Named Pipe → 不触发 Service64 监控
    ├─ 不走 Socket → 不触发 WSAEventSelect 网络监控
    └─ SHM + 共享内存 → 最低检测面

□ 6. 窗口/UI
    ├─ 不自建 GUI 窗口 → 不触发 EnumWindows
    ├─ WebUI 用 localhost → 不触发网络监控
    └─ 注意: GetCursorInfo 可以检测叠加绘制

□ 7. 设备
    ├─ 不自建 HID 设备 (VID=0x00FF 等) → 不触发 HID 枚举
    ├─ 不自建 COM 设备 → 不触发 QueryDosDeviceW
    └─ DMA: 固件伪装为 Intel/Realtek 网卡 → 混入白名单

□ 8. NMI 反调试
    ├─ 不使用硬件断点 (DR0-DR7) → NMI 不会触发
    ├─ 不使用 TF 单步 → NMI 不会触发
    └─ 仅使用软件断点? → 会被 ATS64 内存扫描发现

□ 9. 签名/哈希
    ├─ 每次构建使用不同的编译产物 → 哈希不固定
    ├─ 加壳/混淆改变 PE 结构 → 绕过 PE 特征检测
    └─ 注意: DFS64 扫描未执行文件, 只要落盘就扫

□ 10. 行为
     ├─ 鼠标移动加入随机延迟和微抖动 → 模拟人类
     ├─ 读取频率限制在正常范围 → 避免性能计数器检测
     ├─ 不在游戏内分配大量内存 → 避免 GlobalMemoryStatus 检测
     └─ 运行时间随机化 → 避免定时器预测
```

---

## 25. 游戏内存结构映射 (Delta Force ↔ 雷达协议)

> 基于 UE4 标准偏移 + game-specific 二进制分析。标 "CE" 的偏移需要运行时验证。

### 25.1 标准 UE4 偏移 (高置信度)

| 结构 | 偏移 | 类型 | 说明 |
|------|------|------|------|
| `UWorld::PersistentLevel` | `+0x30` | `ULevel*` | CE 验证 |
| `ULevel::Actors` | `+0x98` | `TArray<AActor*>` | CE 验证 |
| `AActor::RootComponent` | `+0x180` | `USceneComponent*` | CE 验证 |
| `USceneComponent::RelativeLocation` | `+0x120` | `FVector` | **x, y, z 坐标** |
| `USceneComponent::RelativeRotation` | `+0x12C` | `FRotator` | **yw 朝向** |
| `ACharacter::Mesh` | `+0x380` | `USkeletalMeshComponent*` | CE |
| `APlayerState::PlayerNamePrivate` | `+0x328` | `FString` | **n 名字** |
| `APawn::PlayerState` | `+0x3B0` | `APlayerState*` | CE |
| `APawn::Controller` | `+0x390` | `AController*` | CE |

### 25.2 游戏特定结构 (从二进制属性列表提取)

#### UGPDeformableActorRuntimeData (运行时标记)

从文件偏移 0x1A062B60 提取:

```
+0x??  bIsLocalControlled  (bool)    ← 是否本地控制
+0x??  bIsAIControlled     (bool)    ← 雷达 ai 字段
+0x??  bIsUseVolumetric    (bool)
+0x??  AccumulateLifeTime  (float)
+0x??  AccumulateIdleLifeTime
+0x??  AccumulateDisappearTime
```

#### 死亡状态

从文件偏移 0x1A00AE60 提取:

```
+0x??  KillTime        (float)
+0x??  bDirectDead     (bool)
+0x??  bIsKnockDown    (bool)         ← 雷达 dn 字段
```

#### 血量组件 (UGPHealthDataComponent)

```
+0x??  CurrentHealth    (float/int)   ← 雷达 h 字段
+0x??  MaxHealth        (float/int)   ← 雷达 mh 字段
```

#### 装备

```
+0x??  ArmorLevel      (int)          ← 雷达 ar
+0x??  HelmetLevel     (int)          ← 雷达 hl
+0x??  LastWeaponId    (int64)        ← 雷达 w
```

#### ADFMPlayerState

```
+0x??  TeamId          (int64)        ← 雷达 t
+0x??  ShareSpoils     (TMap)
```

### 25.3 CE 验证步骤 (共 30 分钟)

```
1. 扫自己坐标 → 找指针链 → 反推 GWorld 基址
2. GWorld+0x30 → PersistentLevel+0x98 → Actors 数组
3. 遍历找到自己 Actor → RootComponent+0x120 → 坐标
4. Actor+0x3B0 → PlayerState → +0x328 → 名字
5. PlayerState 中搜索 TeamId (对比不同队伍)
6. Actor 中搜索 bIsAIControlled (对比 AI 和真人)
7. Actor 中搜索 bIsKnockDown (倒地和活着对比)
8. Actor 中搜索 CurrentHealth (残血和满血对比)
```

### 25.4 雷达协议字段 → 内存映射总结

| 字段 | 内存路径 | 状态 |
|------|---------|------|
| x,y,z | RootComponent+0x120 | 已知 |
| yw | RootComponent+0x12C | 已知 |
| n | PlayerState+0x328 | 已知 |
| t | PlayerState+TeamId | CE |
| h/mh | HealthComponent | CE |
| ai | bIsAIControlled | CE |
| tm | TeamId==LocalPlayer.TeamId | 已知 |
| dn | bIsKnockDown | CE |
| hl/ar | EquipmentComponent | CE |
| w | LastWeaponId | CE |

### 25.5 关键类名总览

```
Actor 树:
├─ ADFMCharacter          → 玩家/人机
├─ GPCharacter            → 角色基类
├─ ADFMPlayerState        → 队伍/名字
├─ UNearbyPickupItem      → 地面物品
├─ Container/SafeBox      → 容器/保险箱
└─ ExitActor              → 撤离点

Component:
├─ UGPHealthDataComponent          → 血量
├─ UGPDeformableActorRuntimeData   → AI/控制标记
└─ DeathState                      → 倒地状态
```

---
