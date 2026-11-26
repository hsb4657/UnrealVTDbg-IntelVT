# 28 - KDU 能力移植与驱动装载改造

## 1. 背景

原装载链路是 `AIHelper.dll!LoadNT(path, service)`：一个黑盒导出函数，内部用 SCM 建服务再启动。
本项目驱动全部未签名（或仅测试签名），在默认策略的机器上装不进去，又没法控制失败原因，
只能在"为什么起不来"上反复猜。

参照 [KDU](https://github.com/hfiref0x/KDU)（MIT）做了一次定向移植：

- 装载/卸载内核驱动的服务操作自己实现，不再依赖 `AIHelper`；
- 增加漏驱 provider 抽象与内核内存读写；
- 增加 DSE 状态定位与临时改写；
- 增加宿主环境探测（Hyper-V/VBS/HVCI/测试签名），给 `VMXON` 失败提供归因。

`AIHelper.dll` 只保留 `outDebug` 日志通道，其余能力不再使用。

## 2. 搬运清单

| 能力 | KDU 原文件 | 本项目落点 | 说明 |
|---|---|---|---|
| 服务方式装载驱动 | `Source/Hamakaze/sup.c`<br>`supLoadDriver` / `supCreateServiceKey` | `KernelBridge/KernDrv.cpp`<br>`kern::LoadDriverImage` | 写 `ImagePath/Type/Start/ErrorControl` 后 `NtLoadDriver`，失败把 NTSTATUS 原样带出 |
| 服务卸载 | `supUnloadDriver` | `kern::DeleteDriverService` | `NtUnloadDriver` + `RegDeleteTree` |
| 漏驱 provider：RTCore64 | `Source/Hamakaze/idrv/rtcore.cpp` / `.h` | `kern::Provider::RTCore64` | 内核 VA 读 `0x80002048` / 写 `0x8000204C`，4 字节粒度 |
| 漏驱 provider：Intel NAL | `Source/Hamakaze/idrv/intel.cpp` / `.h` | `kern::Provider::Iqvw64` | `0x80862007` + `FunctionId 0x33`，任意长度 VA memmove |
| DSE 定位与改写 | `Source/Hamakaze/dsefix.cpp` | `kern::BeginDseBypass` / `EndDseBypass` | 两路定位 + 回读校验 + 写回还原 |
| 环境探测 | `Source/Hamakaze/hvdetect.cpp` | `kern::QueryHostEnv` | CPUID hypervisor 位、`DeviceGuard` 注册表、`SystemCodeIntegrityInformation` |
| 内核模块基址 | `sup.c` / `diag.cpp` | `kern::KernelModuleBase` | `EnumDeviceDrivers` + `GetDeviceDriverBaseNameW` |

## 3. 刻意没有搬运的部分

| KDU 能力 | 不搬的原因 |
|---|---|
| `drvmap.cpp` 手动映射（`-map`） | 本项目驱动用了 `ObRegisterCallbacks` 和大量未导出函数；映射进去的模块不在 `PsLoadedModuleList`，回调会被 PatchGuard 直接判定非法。KDU 自己也写了这套限制 |
| 物理页表遍历 `PwVirtualToPhysicalEx`（含 LA57） | 只有"纯物理内存"类漏驱才需要。本实现选的两个 provider 都直接支持内核 VA，用不上 |
| build 偏移表 | 没有实测值不能抄，写错一个地址就是 `0x50`。改成「导出表 + 可执行节扫描」两路构建无关的定位 |
| `-ps/-pse/-pho/-dmp` | EPROCESS/PPL 相关，与本项目调试链路无关 |
| `MmUnloadedDrivers` / `PiDDBCacheTable` 清理 | KDU 自己也不做，本项目同样不做 |

## 4. 新装载链路

```
InitializeDevice(path)
├─ kern::QueryHostEnv()                 → 打印系统/Hypervisor/VBS/HVCI/TestSign
├─ 第一轮：InstallDriverStack(path)     → 按系统默认签名策略直接装
│   ├─ LoadVT     → NtLoadDriver(VT_Driver.sys)
│   └─ Load驱动栈 → NtLoadDriver(DbgkSysWin1x.sys)
│   └─ 成功 → 直接返回，全程不碰任何漏驱
└─ 第二轮（仅第一轮失败）：
    ├─ kern::BeginDseBypass(path)
    │   ├─ OpenKernelAccess(path)
    │   │   ├─ TryOpenProvider(RTCore64)    → RTCore64.sys → \\.\RTCore64
    │   │   └─ TryOpenProvider(Iqvw64)      → iqvw64e.sys → \\.\Nal（回退）
    │   ├─ ParseCiImage()                   → ci.dll 基址 + PE 头 + 节表
    │   ├─ LocateCiOptionsByExport()        → CiInitialize 里找 C7 05 disp32 06 00 00 00
    │   ├─ LocateCiOptionsByScan()          → 兜底：扫可执行节
    │   └─ KernelWrite32(addr, 0) → 回读校验 == 0
    ├─ InstallDriverStack(path)             → 重试装载
    └─ kern::EndDseBypass()                 → 写回 0x6 + 卸载漏驱 + 删服务键
```

两点约束：
- 驱动已签名 / 测试签名已开时，第一轮就成功，**根本不会加载漏驱**，内核攻击面不扩大；
- DSE 窗口只覆盖"重试装载"这一小段，装完立刻还原，不长期保持关闭状态。

## 5. 漏驱选择

| 判据 | RTCore64 | iqvw64e / NAL |
|---|---|---|
| 装载方式 | legacy，`NtLoadDriver` 直接起 | legacy，同上 |
| 内核访问粒度 | 4 字节 | 任意长度 |
| 设备名冲突风险 | `\Device\RTCore64`，仅 Afterburner 在跑时占用 | `\Device\Nal`，Intel PROSet 可能占用 |
| 被安全软件关注度 | 中 | 高（BYOVD 头号样本） |
| 版本覆盖 | 7601 → ANY | 7601 → ANY |

结论：**RTCore64 为主，iqvw64e 为备**。

- 主的理由：体积小、无 WDF 依赖、设备名不容易被厂商官方驱动占用；
- 备的理由：4 字节粒度扫 `ci.dll` 慢（全段扫约十几万次 IOCTL），NAL 一次 memmove 解决，
  在冷门 build 上导出表路径失效、必须全段扫描时能显著缩短时间。

两者对 `ci!g_CiOptions` 的写法完全相同，切换对上层无感。

### 5.1 设备与实例归属判定

只靠"设备能不能打开"来判断占用是错的：程序自己崩溃留下的实例也会占着同一个设备名。
按下面的状态机判定：

| 状态 | 判定依据 | 处理 |
|---|---|---|
| 服务键 `RTCore64F3` / `Iqvw64eF3` 存在 | 这个名字只有本程序会创建 → 一定是自己的实例 | 卸载后重装；卸载失败则补回键并复用 |
| 键不存在、设备存在、已加载镜像路径 == 本目录文件 | 自己上次崩溃留下的孤儿 | 补建服务键，直接复用，收尾可正常卸载 |
| 键不存在、设备存在、镜像来自别的目录 | 厂商官方驱动（Afterburner / Intel PROSet） | 跳过该 provider，不动别人的驱动 |
| 键不存在、设备存在、枚举不出模块路径 | 归属未知 | 功能自检：用该 provider 读 `ci.dll` 的 DOS 头，拿到 `MZ` 才认；通过则**借用**，收尾不卸载 |

配套改动：`DeleteDriverService` 在 `NtUnloadDriver` 失败时**保留服务键**，不再无条件删键。
否则会出现「键没了、驱动还在」的黑洞状态——下次启动既不满足"键在"的重装条件，
又因为设备存在被误判为"被占用"，直接永久跳过该 provider，直到重启。

## 6. 代码位置

```
UnrealDbgDll/KernelBridge/KernDrv.h     对外接口
UnrealDbgDll/KernelBridge/KernDrv.cpp   实现
UnrealDbgDll/Init/InitNTDevice.cpp      装载流程接入点
UnrealDbgWinUI/Runtime.cpp              打包清单（新增 RTCore64.sys / iqvw64e.sys）
```

对外接口一览：

```cpp
kern::HostEnv  env  = kern::QueryHostEnv();
kern::HostEnv        // hypervisorPresent / hypervisorVendor / vbs / hvci / testSigning / build

bool  ok = kern::LoadDriverImage(L"C:\\x\\VT_Driver.sys", L"VT_Driver");
bool  del = kern::DeleteDriverService(L"VT_Driver");

bool  dse = kern::BeginDseBypass(L"C:\\x\\");   // 目录，末尾带反斜杠
void       kern::EndDseBypass();

bool  r = kern::KernelRead(va, buf, n);
bool  w = kern::KernelWrite(va, buf, n);
uintptr_t base = kern::KernelModuleBase(L"ci.dll");
```

## 7. 部署

运行目录需要两个漏驱文件（按需放置，缺失时对应 provider 自动跳过）：

| 文件 | 来源 | 校验（SHA256） |
|---|---|---|
| `RTCore64.sys` | MSI Afterburner 4.6.2（≤ build 15658） | `01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd` |
| `iqvw64e.sys` | Intel 网卡诊断组件 1.03.0.7 | `4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b` |

WinUI 的"运行时文件"页会把它们列出来，缺失显示为未就绪，但不阻断启动。
两个文件都只用于开发/测试机的驱动装载，**不要提交进仓库**（`.gitignore` 需覆盖）。

## 8. 验证

启动后日志区应出现以下序列（关键字 `[环境]` / `[DSE]` / `[漏驱]` / `[装载]`）：

```
[环境] 系统 10.0.26100 | Hypervisor=否 | VBS=关 | HVCI=关 | TestSign=开
[装载] 第一轮：按默认签名策略装载驱动栈。
（未签名机器上第一轮失败，进入第二轮）
[漏驱] provider 就绪: RTCore64 (RTCore64.sys)
[DSE] 导出表路径命中: ci!g_CiOptions=0xFFFFF801xxxxxxxx
[DSE] 已关闭驱动签名强制: ci!g_CiOptions=0xFFFFF801xxxxxxxx -> 0
[装载] 驱动已进入内核: VT_Driver
[装载] 驱动已进入内核: UnrealDevice
[DSE] 已还原 g_CiOptions=0x6
[漏驱] provider 已卸载: RTCore64F3
```

`NtLoadDriver` 失败码对照：

| NTSTATUS | 含义 | 处理 |
|---|---|---|
| `0xC0000603` / `0xC0000428` | 镜像哈希/签名被拒（黑名单或 DSE 未关） | 确认 HVCI 已关；换另一个 provider |
| `0xC000036B` | 驱动被策略阻止 | 同上，检查 SiPolicy |
| `0xC000010E` | 已加载 | 先 `DeleteDriverService` 再试 |
| `0xC0000034` | 找不到镜像 | 检查 `ImagePath` 与文件权限 |

DSE 定位于两路都失败时会打 `[DSE] 定位 g_CiOptions 失败`，
此时检查 `ci.dll` 版本是否超出 `C7 05 ...,6` 的形态，需要人工补一条定位路径。

## 9. 已知风险

1. **HVCI/VBS 必须关闭**：本项目的 `VT_Driver` 要抢 VMX root，Hyper-V 在场时 `VMXON` 必失败。
   环境探测会在日志里明确指出，但不阻断启动（避免嵌套虚拟化测试环境被误伤）。
2. **provider 文件本身就是 AV 重点关注对象**，部分安全软件会在落盘时隔离 `RTCore64.sys`，
   表现为 provider 直接跳过；日志中能看到设备打开失败/装载失败。
3. **写 `g_CiOptions` 是全局状态**：`EndDseBypass` 失败（漏驱被提前卸载等）会保持 DSE 关闭，
   日志会明确写出"还原失败"，此时应重启系统。
4. **不要用本模块 patch `.text`**：RTCore64/NAL 都是 `memcpy` 级写入，写只读代码页会直接
   `0x50`；本模块只写 `ci.dll` 的 `.data`。
5. 服务名固定为 `RTCore64F3` / `Iqvw64eF3`，不用 `RTCore64` / `Nal`，避免与厂商官方服务或
   历史残留冲突。
