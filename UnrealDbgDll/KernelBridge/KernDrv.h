#pragma once

#ifndef _KERN_DRV_H
#define _KERN_DRV_H

#include <Windows.h>
#include <string>
#include <cstdint>

// ============================================================================
//  KDU (https://github.com/hfiref0x/KDU, MIT) 能力精简移植
//
//  搬运清单（保持功能等价，去掉与本项目无关的分支）：
//    1. 服务方式装载/卸载内核驱动      <- Source/Hamakaze/sup.c
//         supLoadDriver / supUnloadDriver / supCreateServiceKey
//    2. 漏驱 provider 抽象 + 内核读写   <- Source/Hamakaze/idrv/rtcore.cpp
//                                          Source/Hamakaze/idrv/intel.cpp
//    3. DSE 状态定位与改写              <- Source/Hamakaze/dsefix.cpp
//    4. 虚拟化/代码完整性环境探测        <- Source/Hamakaze/hvdetect.cpp
//
//  刻意不搬运：
//    * drvmap.cpp   手动映射：本项目驱动用了 ObRegisterCallbacks 与大量未导出
//                   函数，不在 PsLoadedModuleList 里会被 PatchGuard 直接带走。
//    * 物理页表遍历  (PwVirtualToPhysicalEx)：只有物理内存类漏驱才需要，
//                   本实现选用的 provider 都直接支持内核虚拟地址。
//    * build 偏移表  没有可靠的实测值，抄错一个地址就是 0x50 蓝屏；改用
//                   「导出表 + 可执行节扫描」两路构建无关的定位方式。
// ============================================================================

namespace kern
{
    // 宿主环境（对应 KDU hvdetect）
    struct HostEnv
    {
        bool    hypervisorPresent = false;          // CPUID.1:ECX[31]
        wchar_t hypervisorVendor[16] = {};          // CPUID.40000000 厂商串
        bool    vbsEnabled = false;                 // 注册表 DeviceGuard
        bool    hvciEnabled = false;                // SystemCodeIntegrityInformation
        bool    testSigning = false;                // 测试签名模式
        DWORD   buildNumber = 0;
        DWORD   majorVersion = 0;
        DWORD   minorVersion = 0;
    };

    // 可用的漏驱 provider
    enum class Provider
    {
        None = 0,
        RTCore64,   // MSI Afterburner 4.6.2，内核 VA 读/写，4 字节粒度
        Iqvw64      // Intel NAL 1.03.0.7，内核 VA memmove，任意长度
    };

    // ---- 驱动服务 ----------------------------------------------------------
    bool EnableLoadDriverPrivilege();
    bool LoadDriverImage(const std::wstring& imagePath, const std::wstring& serviceName);
    bool DeleteDriverService(const std::wstring& serviceName);

    // ---- 环境探测 ----------------------------------------------------------
    HostEnv      QueryHostEnv();
    std::wstring DescribeHostEnv(const HostEnv& env);

    // ---- 内核访问 ----------------------------------------------------------
    Provider GetActiveProvider();
    const wchar_t* GetActiveProviderName();
    bool OpenKernelAccess(const std::wstring& driverDirectory);
    void CloseKernelAccess();

    bool KernelRead(uintptr_t virtualAddress, void* buffer, size_t size);
    bool KernelWrite(uintptr_t virtualAddress, const void* buffer, size_t size);
    bool KernelRead32(uintptr_t virtualAddress, uint32_t* value);
    bool KernelWrite32(uintptr_t virtualAddress, uint32_t value);

    uintptr_t KernelModuleBase(const wchar_t* moduleName);

    // ---- DSE ---------------------------------------------------------------
    // 装载漏驱 -> 定位 ci!g_CiOptions -> 写 0。成功返回 true，此后签名为强制关闭状态。
    bool      BeginDseBypass(const std::wstring& driverDirectory);
    // 写回 0x6 并卸载漏驱，可重复调用。
    void      EndDseBypass();
    uintptr_t GetCiOptionsAddress();

    // ---- 装载痕迹清理（P1） ------------------------------------------------
    // 驱动已经在内核里跑起来之后，把磁盘上那份镜像删掉。
    // 原理：NtLoadDriver 装载时内存管理器用 SEC_IMAGE 建立 section，之后的执行代码来自 section
    //       而不是文件；文件本体可以删除，已加载的驱动照常运行。
    // 作用：后续定期文件扫描（哈希库 / 路径规则 / minifilter 遍历）找不到任何落地的 .sys。
    // 注意：装载成功后调用；调用后该文件就不存在了，下次装载需要重新部署一份。
    bool HideDriverImageFile(const std::wstring& imagePath);

    // 只删注册表服务键，不碰已经加载的驱动对象。
    // 用于「驱动已运行、但不想在 Services 列表里留下可疑名字」的场景。
    // 注意：删键之后就再也无法通过 NtUnloadDriver 卸载该驱动（卸载要靠这个键找驱动对象），
    //       还需要卸载的场合不要调用。
    bool RemoveServiceKeyOnly(const std::wstring& serviceName);

    // ---- 反作弊驻留探测 ----------------------------------------------------
    // 通过 EnumDeviceDrivers 检查已知反作弊内核模块是否已经在内核里，返回命中的模块名（未命中返回空串）。
    // 用途：装载顺序决定可见性——「先装 VT 再开游戏」和「游戏已经开着再装 VT」是两个世界：
    //       反作弊驱动一旦先驻留，它会用 PsSetLoadImageNotifyRoutine 直接记录你的映像装载事件，
    //       那时再谈隐藏链表、删文件都没有意义，那一次事件已经上报了。
    std::wstring DetectResidentAntiCheat();
}

#endif // !_KERN_DRV_H
