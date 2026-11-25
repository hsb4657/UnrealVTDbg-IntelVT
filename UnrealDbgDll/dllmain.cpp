#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <iptypes.h>

#include "dllmain.h"
#include "Init/InitNTDevice.h"
#include "Channels/DispatchData.h"
#include "Globals.h"
#include "Interface/Interface.h"
#include "StartProcess.h"
#include "NetVerHelp/Help_Tou/NetworkVerHelp.h"
#include "Crypter/xorstr.hpp"
#include "../Common/Shared/HookSelection.h"

#include <atomic>
#include <mutex>

#pragma comment(lib, "iphlpapi.lib")

Logger logger("UnrealDbgDll.log");
static std::atomic<ULONG64> g_hookSelectionMask{ HOOK_SELECTION_ALL };

namespace
{
    std::mutex g_sessionMutex;
    HANDLE g_heartbeatStop = nullptr;
    HANDLE g_heartbeatThread = nullptr;
    std::atomic<bool> g_sessionActive{ false };
    std::atomic<bool> g_driversNeedCleanup{ false };
    std::atomic<bool> g_terminalHookMayHaveRun{ false };

    BOOL TryUninitializeSessionDrivers()
    {
        // A terminal PspExitThread call can outlive the state guard. We cannot
        // prove its instruction pointer has left the driver/trampoline allocations.
        // Never free those allocations merely because the callback count is zero.
        if (g_terminalHookMayHaveRun.load(std::memory_order_acquire))
        {
            logger.outDebug(L"本次会话可能运行过 PspExitThread Hook，暂不支持安全热卸载；保留驱动，请重启系统回收。");
            return FALSE;
        }
        return UnInitialize();
    }

    void JoinHeartbeat()
    {
        if (g_heartbeatStop) SetEvent(g_heartbeatStop);
        if (g_heartbeatThread)
        {
            WaitForSingleObject(g_heartbeatThread, INFINITE);
            CloseHandle(g_heartbeatThread);
            g_heartbeatThread = nullptr;
        }
        if (g_heartbeatStop) CloseHandle(g_heartbeatStop);
        g_heartbeatStop = nullptr;
    }
}

extern "C" __declspec(dllexport) BOOL __stdcall SessionActive_F3()
{
    return g_sessionActive.load(std::memory_order_acquire) ? TRUE : FALSE;
}

extern "C" __declspec(dllexport) BOOL __stdcall Shutdown_F3()
{
    std::lock_guard<std::mutex> lock(g_sessionMutex);
    g_sessionActive.store(false, std::memory_order_release);
    JoinHeartbeat(); // Never wait for threads from DllMain / under the loader lock.
    StopStartupWorkers();
    if (g_driversNeedCleanup && !TryUninitializeSessionDrivers()) return FALSE;
    g_driversNeedCleanup = false;
    return TRUE;
}

//--------------------------------------------



#define 开启验证	

#ifdef  开启验证
std::string GetMac();
bool EnsureMacCode();

string cardnum;
//心跳Key,每次心跳此值都会变
string heartbeatkey;
string token;
std::string maccode;
std::wstring macAdapterType;
std::wstring macAdapterName;

Model::PlatformType platformtypeid = Model::PlatformType::NetVer;
string encryptKey = (const char*)_xor_("29d6b27e");
string signSalt = (const char*)_xor_("5cae28fc");
Model::EncryptType encrypttypeid = Model::EncryptType::RC4;
string goodscode = (const char*)_xor_("4cd990453596e1aa");
string platformUserCode = (const char*)_xor_("86ffdabd03591bff4e958201c252fe75f0d1e74d");
string versionname = (const char*)_xor_("v6067");

std::string FormatMacAddress(const BYTE* address, ULONG length)
{
    if (address == nullptr || length != 6)
    {
        return {};
    }

    char mac[13] = {};
    sprintf_s(mac, _countof(mac), "%02X%02X%02X%02X%02X%02X",
        address[0], address[1], address[2], address[3], address[4], address[5]);
    return mac;
}

std::wstring FormatMacAddressForLog(const std::string& mac)
{
    if (mac.length() != 12)
    {
        return Common::ConvertLocalCodePageToWideString(mac);
    }

    std::wstring formattedMac;
    formattedMac.reserve(17);
    for (size_t index = 0; index < mac.length(); ++index)
    {
        if (index > 0 && index % 2 == 0)
        {
            formattedMac.push_back(L'-');
        }
        formattedMac.push_back(static_cast<wchar_t>(mac[index]));
    }

    return formattedMac;
}

void LogMultilineLocalText(const std::string& text, const wchar_t* firstLinePrefix = L"", const wchar_t* nextLinePrefix = L"")
{
    std::wstring wideText = Common::ConvertLocalCodePageToWideString(text);
    if (wideText.empty())
    {
        if (firstLinePrefix != nullptr && firstLinePrefix[0] != L'\0')
        {
            logger.outDebug(_xor_(L"%s"), firstLinePrefix);
        }
        return;
    }

    size_t lineStart = 0;
    bool isFirstLine = true;
    while (lineStart < wideText.length())
    {
        const size_t lineEnd = wideText.find(L'\n', lineStart);
        std::wstring line = wideText.substr(lineStart, lineEnd == std::wstring::npos ? std::wstring::npos : lineEnd - lineStart);
        if (!line.empty() && line.back() == L'\r')
        {
            line.pop_back();
        }

        std::wstring output;
        const wchar_t* prefix = isFirstLine ? firstLinePrefix : nextLinePrefix;
        if (prefix != nullptr)
        {
            output += prefix;
        }
        output += line;
        logger.outDebug(_xor_(L"%s"), output.c_str());

        if (lineEnd == std::wstring::npos)
        {
            break;
        }

        lineStart = lineEnd + 1;
        isFirstLine = false;
    }
}

bool IsUsableMacAdapter(const IP_ADAPTER_ADDRESSES* adapter)
{
    if (adapter == nullptr)
    {
        // 处理打开进程失败的情况
        return false;
    }

    if (adapter->OperStatus != IfOperStatusUp ||
        adapter->PhysicalAddressLength != 6 ||
        adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK ||
        adapter->IfType == IF_TYPE_TUNNEL)
    {
        // 处理打开进程失败的情况
        return false;
    }

    const BYTE zeroMac[6] = {};
    return memcmp(adapter->PhysicalAddress, zeroMac, sizeof(zeroMac)) != 0;
}

int GetMacAdapterPriority(const IP_ADAPTER_ADDRESSES* adapter)
{
    if (adapter == nullptr)
    {
        return 3;
    }

    switch (adapter->IfType)
    {
    case IF_TYPE_IEEE80211:
        return 0; // Wi-Fi first.
    case IF_TYPE_ETHERNET_CSMACD:
        return 1; // Wired Ethernet second.
    default:
        return 2; // Other usable adapters are fallback only.
    }
}

std::wstring GetMacAdapterTypeName(const IP_ADAPTER_ADDRESSES* adapter)
{
    if (adapter == nullptr)
    {
        return L"Unknown";
    }

    switch (adapter->IfType)
    {
    case IF_TYPE_IEEE80211:
        return L"Wi-Fi";
    case IF_TYPE_ETHERNET_CSMACD:
        return L"Ethernet";
    default:
        return L"Other";
    }
}

//获取机器码
std::string GetMac()
{
    ULONG bufferLength = 15 * 1024;
    constexpr ULONG flags =
        GAA_FLAG_SKIP_ANYCAST |
        GAA_FLAG_SKIP_MULTICAST |
        GAA_FLAG_SKIP_DNS_SERVER |
        GAA_FLAG_SKIP_FRIENDLY_NAME;

    for (int attempt = 0; attempt < 3; ++attempt)
    {
        std::vector<BYTE> buffer(bufferLength);
        auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        const DWORD status = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, adapters, &bufferLength);

        if (status == ERROR_BUFFER_OVERFLOW)
        {
            continue;
        }

        if (status != NO_ERROR)
        {
            logger.outDebug(_xor_(L"获取机器码失败，GetAdaptersAddresses error:%lu"), status);
            return {};
        }

        const IP_ADAPTER_ADDRESSES* selectedAdapter = nullptr;
        int selectedPriority = 3;

        for (auto* adapter = adapters; adapter != nullptr; adapter = adapter->Next)
        {
            if (IsUsableMacAdapter(adapter))
            {
                const int priority = GetMacAdapterPriority(adapter);
                if (priority < selectedPriority)
                {
                    selectedAdapter = adapter;
                    selectedPriority = priority;
                    if (selectedPriority == 0)
                    {
                        break;
                    }
                }
            }
        }

        if (selectedAdapter != nullptr)
        {
            macAdapterType = GetMacAdapterTypeName(selectedAdapter);
            macAdapterName = selectedAdapter->FriendlyName != nullptr ? selectedAdapter->FriendlyName : L"";
            return FormatMacAddress(selectedAdapter->PhysicalAddress, selectedAdapter->PhysicalAddressLength);
        }

        logger.outDebug(_xor_(L"获取机器码失败，没有可用的物理网卡。"));
        return {};
    }

    logger.outDebug(_xor_(L"获取机器码失败，网卡列表缓冲区持续不足。"));
    return {};
}

bool EnsureMacCode()
{
    if (!maccode.empty())
    {
        return true;
    }

    maccode = GetMac();
    if (maccode.empty())
    {
        logger.outDebug(_xor_(L"初始化失败,MAC拿不到"));
        return false;
    }

    if (!macAdapterName.empty())
    {
        logger.outDebug(_xor_(L"MAC(%s, %s) : %s"), macAdapterType.c_str(), macAdapterName.c_str(), FormatMacAddressForLog(maccode).c_str());
    }
    else
    {
        logger.outDebug(_xor_(L"MAC(%s) : %s"), macAdapterType.c_str(), FormatMacAddressForLog(maccode).c_str());
    }
    return true;
}

void LoginOut(string cardnumorusername)
{
#ifdef  USE_VMP
    VMProtectBegin("LoginOut");
#endif
    //构建退出登录入参
    Model::In_LoginOutArgs LoginOutArgs;
    LoginOutArgs.maccode = maccode;//必填
    LoginOutArgs.timestamp = Help::NetworkVerHelp::GetTimeStamp();//必填
    LoginOutArgs.cardnumorusername = cardnumorusername;//必填
    LoginOutArgs.token = token;//必填
    //请求接口，获取结果
    Model::Result result = Help::NetworkVerHelp::GeLoginOut(LoginOutArgs);
#ifdef  USE_VMP
    VMProtectEnd();
#endif
}
void DisableCardOrAccount(string cardnumorusername)
{
#ifdef  USE_VMP
    VMProtectBegin("DisableCardOrAccount");
#endif

    Model::In_DisableCardOrAccountArgs DisableCardOrAccountArgs;
    DisableCardOrAccountArgs.maccode = maccode;//必填
    DisableCardOrAccountArgs.timestamp = Help::NetworkVerHelp::GetTimeStamp();//必填
    DisableCardOrAccountArgs.cardnumorusername = cardnumorusername;//必填
    DisableCardOrAccountArgs.token = token;//必填
    DisableCardOrAccountArgs.disablecardoraccounttype = Model::DisableCardOrAccountType::Disable;//必填
    Model::Result result = Help::NetworkVerHelp::DisableCardOrAccount(DisableCardOrAccountArgs);
#ifdef  USE_VMP
    VMProtectEnd();
#endif
}
bool IniSoftInfo()
{
#ifdef  USE_VMP
    VMProtectBegin("IniSoftInfo");
#endif
    bool IniResult = false;

    //构建初化软件入参
    Model::In_IniSoftInfoArgs args;
    args.maccode = maccode;//必填
    args.timestamp = Help::NetworkVerHelp::GetTimeStamp();//必填
    args.requestflag = to_string(args.timestamp);//必填
    args.versionname = versionname;//必填
    //请求接口，获取结果
    Model::Result result = Help::NetworkVerHelp::GetIniSoftInfo(args, platformtypeid, encryptKey, signSalt, encrypttypeid, goodscode, platformUserCode);

    //判断版本
    if (Help::iniSoftInfoData.softInfo.newversionnum != (const char*)_xor_(""))
    {
        if (Help::iniSoftInfoData.softInfo.newversionnum != versionname)
        {
            logger.outDebug(_xor_(L"1.新版本下载地址:%s"), Common::ConvertLocalCodePageToWideString(Help::iniSoftInfoData.softInfo.networkdiskurl).c_str());
            logger.outDebug(_xor_(L"           密码：%s"), Common::ConvertLocalCodePageToWideString(Help::iniSoftInfoData.softInfo.diskpwd).c_str());

            IniResult = false;
#ifdef  USE_VMP
            VMProtectEnd();
#endif
            return IniResult;
        }
    }

    if (result.code == 0)
    {
        //网络验证平台
        //iniSoftInfoData:初始化完后的具体结果
        if (Help::iniSoftInfoData.inisoftkey != (const char*)_xor_(""))
        {
            if (Help::iniSoftInfoData.requestflag != args.requestflag)
            {
                IniResult = false;
                DisableCardOrAccount(cardnum);
                return IniResult;
            }
        }
        LogMultilineLocalText(Help::iniSoftInfoData.softInfo.notice);
        logger.outDebug(_xor_(L"----------------------------------------"));
        LogMultilineLocalText(Help::iniSoftInfoData.softInfo.basedata, _xor_(L"消息："), _xor_(L"      "));

        IniResult = true;
#ifdef  USE_VMP
        VMProtectEnd();
#endif
        return IniResult;
    }

    else
    {
        switch (result.code)
        {
        case 1003:
            logger.outDebug(_xor_(L"通信异常"));
            break;
        case 1006:
            logger.outDebug(_xor_(L"机器码_时间戳_错误"));
            break;
        default:
            LogMultilineLocalText(result.msg);
            break;
        }

        IniResult = false;
#ifdef  USE_VMP
        VMProtectEnd();
#endif
        return IniResult;
    }

}
DWORD WINAPI HeartBeat(void*)
{
    bool failed = false;
    try
    {
        while (WaitForSingleObject(g_heartbeatStop, 0) == WAIT_TIMEOUT)
        {
            Model::In_HeartBeatArgs args;
            args.maccode = maccode;
            args.timestamp = Help::NetworkVerHelp::GetTimeStamp();
            args.requestflag = to_string(args.timestamp);
            args.cardnumorusername = cardnum;
            args.token = token;
            args.heartbeatkey = heartbeatkey;
            Model::Result result = Help::NetworkVerHelp::GetHeartBeat(args);
            if (WaitForSingleObject(g_heartbeatStop, 0) != WAIT_TIMEOUT) break;
            if (result.code != 0) { failed = true; break; }
            auto reply = Help::NetworkVerHelp::ConvertHeartBeat(result.data);
            if (reply.heartbeatkey.empty() || reply.requestflag != args.requestflag)
            {
                DisableCardOrAccount(cardnum);
                failed = true;
                break;
            }
            heartbeatkey = reply.heartbeatkey;
            if (WaitForSingleObject(g_heartbeatStop, 300 * 1000) != WAIT_TIMEOUT) break;
        }
    }
    catch (...) { failed = true; }
    if (failed)
    {
        g_sessionActive.store(false, std::memory_order_release);
        logger.outDebug(L"验证心跳失败，正在停止调试会话；请重新初始化。");
        StopStartupWorkers();
        g_driversNeedCleanup = !TryUninitializeSessionDrivers();
    }
    return 0;
}
bool LoginByCard(string _CardNum)
{
#ifdef  USE_VMP
    VMProtectBegin("LoginByCardM");
#endif
    bool IsLoginOk = false;
    //构建登录入参
    Model::In_CardLoginArgs args;
    args.maccode = maccode;//必填
    args.timestamp = Help::NetworkVerHelp::GetTimeStamp();//必填
    args.requestflag = to_string(args.timestamp);//必填
    args.cardnum = _CardNum;//必填
    //请求接口，获取结果
    Model::Result result = Help::NetworkVerHelp::GetLoginByCard(args);
    Sleep(1000);

    if (result.code == 0)
    {


        Model::Out_Login LoginData = Help::NetworkVerHelp::ConvertLoginData(result.data);

        if (LoginData.requestflag != args.requestflag)
        {
            IsLoginOk = false;

            DisableCardOrAccount(_CardNum);
            LoginOut(_CardNum);
            return IsLoginOk;
        }

        token = LoginData.token;
        heartbeatkey = LoginData.heartbeatkey;
        IsLoginOk = true;
    }
    else
    {
        switch (result.code)
        {
        case 6003:
        case 6005:
            logger.outDebug(_xor_(L"温馨提示：当前时间不开放，请等待开放时间"));
            break;
        case 6002:
            logger.outDebug(_xor_(L"温馨提示：停用软件"));
            break;
        default:
            LogMultilineLocalText(result.msg, _xor_(L"温馨提示："), _xor_(L"          "));
            break;

        }
        IsLoginOk = false;

    }


#ifdef  USE_VMP
    VMProtectEnd();
#endif

    return IsLoginOk;

}

#endif



//--------------------------------------------
BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpReserved)   // reserved
{
    BOOL bRet = TRUE;


    // Perform actions based on the reason for calling.
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
    {
        break;
    }

    case DLL_THREAD_ATTACH:
        // Do thread-specific initialization.
        break;

    case DLL_THREAD_DETACH:
    {
        // Do thread-specific cleanup.
        break;
    }

    case DLL_PROCESS_DETACH:
    {
        // Perform any necessary cleanup.      
        break;
    }

    }
    return bRet;
}


void InitSymbol()
{
	g_SymbolTable = { 0 };
	HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
	g_SymbolTable.lpDbgUiRemoteBreakin = (size_t)GetProcAddress(hNtdll, "DbgUiRemoteBreakin");
	g_SymbolTable.lpDbgBreakPoint = (size_t)GetProcAddress(hNtdll, "DbgBreakPoint");
}

void DispatchSymbol()
{
	InitSymbol();

	// 将缓冲区地址传递给驱动程序
	DWORD BytesReturned = 0;
	//SendUserDataToDriver(IOCTL_DISPATCH_SYMBOL, &g_SymbolTable, sizeof(SYMBOL_TABLE), NULL, 0, &BytesReturned);
}


//Initialize
extern "C" __declspec(dllexport) BOOL __stdcall ConfigureHooks_F3(ULONG64 mask)
{
    if ((mask & ~HOOK_SELECTION_ALL) != 0)
    {
        return FALSE;
    }

    g_hookSelectionMask.store(mask, std::memory_order_release);
    return TRUE;
}

BOOL Initialize_F3(ULONG64 key)   //初始化驱动 key用户  驱动对比
{
    std::lock_guard<std::mutex> lock(g_sessionMutex);
    if (g_sessionActive.load(std::memory_order_acquire)) return TRUE;
    JoinHeartbeat();
    StopStartupWorkers();
    if (g_driversNeedCleanup && !TryUninitializeSessionDrivers()) return FALSE;
    g_driversNeedCleanup = false;

   // VMProtectBegin("Initialize_F3");
    //logger.outDebug(L"Key 十六进制数据: 0x%016llX", key);

    if (!EnsureMacCode()) {
        return false;
    }
    if (!IniSoftInfo()) {
        return false;
    }

    cardnum = (const char*)_xor_("XX-7337f05ae9b00807");

    if (!LoginByCard(cardnum)) {
        return false;
    }

	std::wstring processPath = FileSystem::GetModuleDirectory(NULL);
    //VMProtectEnd();

    g_driversNeedCleanup = true;
	if (!_Initialize(processPath.c_str()))  //加载驱动
	{
        logger.outDebug(_xor_(L"驱动初始化失败"));
        g_driversNeedCleanup = !TryUninitializeSessionDrivers();
        return FALSE;
	}

    if (!InitSymbolsTable(key))
    {
        logger.outDebug(_xor_(L"符号表初始化失败"));
        g_driversNeedCleanup = !TryUninitializeSessionDrivers();
        return FALSE;
    }

    // Failed partial installations are also pinned by the kernel before the hook
    // is published; UnInitialize checks the service result before touching VT.
    if ((g_hookSelectionMask.load(std::memory_order_acquire) & HOOK_SELECTION_PSP_EXIT_THREAD) != 0)
        g_terminalHookMayHaveRun.store(true, std::memory_order_release);

    if (!SendDebuggerDataToDriver(GetCurrentProcessId()))
    {
        logger.outDebug(_xor_(L"宿主调试器登记失败"));
        g_driversNeedCleanup = !TryUninitializeSessionDrivers();
        return FALSE;
    }

    g_heartbeatStop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_heartbeatStop)
    {
        g_driversNeedCleanup = !TryUninitializeSessionDrivers();
        return FALSE;
    }
    EnableStartupWorkers();
    g_sessionActive.store(true, std::memory_order_release);
    g_heartbeatThread = CreateThread(nullptr, 0, HeartBeat, nullptr, 0, nullptr);
    if (!g_heartbeatThread)
    {
        g_sessionActive = false;
        StopStartupWorkers();
        JoinHeartbeat();
        g_driversNeedCleanup = !TryUninitializeSessionDrivers();
        return FALSE;
    }

    logger.outDebug(_xor_(L"初始化成功"));
    return TRUE;
}


//GetFileVersion
void GetFileVersion(_In_ TCHAR* FileName, _Out_ TCHAR* VerInfo)
{
    VS_FIXEDFILEINFO* pVsInfo{};
    UINT iFileInfoSize = sizeof(VS_FIXEDFILEINFO);

    DWORD iVerInfoSize = GetFileVersionInfoSize(FileName, NULL);
    if (iVerInfoSize)
    {
        TCHAR* pBuf = new TCHAR[iVerInfoSize];
        if (pBuf)
        {
            if (GetFileVersionInfo(FileName, 0, iVerInfoSize, pBuf))
            {
                if (VerQueryValue(pBuf, _T("\\"), (LPVOID*)&pVsInfo, &iFileInfoSize))
                {
                    wsprintf(pBuf, _T("%d.%d.%d.%d"), HIWORD(pVsInfo->dwFileVersionMS), LOWORD(pVsInfo->dwFileVersionMS), HIWORD(pVsInfo->dwFileVersionLS), LOWORD(pVsInfo->dwFileVersionLS));
                    wcscpy(VerInfo, pBuf);
                }
            }
            delete[] pBuf;
        }
    }
}

BOOL InitSymbolsTable(ULONG64 key)
{
    return LoadSymbolsTable(key);
}

//加载符号表
BOOL LoadSymbolsTable(ULONG64 key)
{
   VMProtectBeginVirtualization("VMP");
    BOOL bRet;
    // 将缓冲区地址传递给驱动程序
    DWORD BytesReturned = 0;
    RING3_HOOK_CONFIGURATION hookConfiguration = { 0 };
    hookConfiguration.version = HOOK_CONFIGURATION_VERSION;
    hookConfiguration.size = sizeof(hookConfiguration);
    hookConfiguration.mask = g_hookSelectionMask.load(std::memory_order_acquire);
    bRet = SendUserDataToDriver(IOCTL_CONFIGURE_EPT_HOOKS,
        &hookConfiguration, sizeof(hookConfiguration), NULL, 0, &BytesReturned);
    if (!bRet)
    {
        logger.outDebug(_xor_(L"下发 EPT hook 选择失败"));
        VMProtectEnd();
        return FALSE;
    }

    RING3_VERIFY info = { 0 };
    info.key = key;
    DWORD dwSuccess = 520;
    bRet = SendUserDataToDriver(IOCTL_LOAD_SYMBOLS_TABLE, &info, sizeof(RING3_VERIFY), &dwSuccess, sizeof(DWORD), &BytesReturned);
    if (!bRet || dwSuccess != INIT_SYMBOLS_STATUS_SUCCESS)
    {
        logger.outDebug(L"驱动初始化失败，状态码: 0x%08lX", dwSuccess);
        VMProtectEnd();
        return FALSE;
    }
    VMProtectEnd();
    return bRet;
}
