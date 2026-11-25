#include "DllMainInternal.h"
#include "../../HookCallSet/Hooks/HookInstallRoutines.h"

namespace
{
    constexpr LONG kHookStateNotInstalled = 0;
    constexpr LONG kHookStateInstalled = 1;
    constexpr LONG kHookStateUninstalling = 2;
    constexpr LONG kHookStateInstalling = 3;
    constexpr LONG kHookStateCleanupRequired = 4;

    typedef bool (*HookInstallRoutine)();
    typedef bool (*HookUninstallRoutine)();

    struct HookStep
    {
        const char* name;
        HookInstallRoutine install;
        HookUninstallRoutine uninstall;
        bool installed;
    };

    HookStep g_HookSteps[] =
    {
        // 旧项目保留的禁用路径：TryHook_DbgUiDebugActiveProcess 是 DbgUiDebugActiveProcess -> NtDebugActiveProcess
        // -> DbgUiIssueRemoteBreakin 的更上层封装入口。
        // 为什么注释：当前安装表从 NtDebugActiveProcess 和 DbgUiIssueRemoteBreakin 两层拦截，已经覆盖关键调试附加与远程
        // break-in 行为；再开启上层 DbgUi hook 会增加重复拦截和递归风险。
        // 放开的好处：可以更早观察 Win32/DbgUi 调试附加入口，便于做 API 层审计。
        // 放开的坏处：和下层 Nt* hook 重叠，异常路径中可能重复记录、重复修改 break-in 线程。
        // 项目影响：会扩大 Hook.dll/Hook64.dll 对 ntdll 调试 API 的干预面，提升兼容性回归风险。
        // 结论：继续注释；只有在明确需要上层 API 观测时再作为单独 HookStep 加入。
        //{ "DbgUiDebugActiveProcess", TryHook_DbgUiDebugActiveProcess, TryUnHook_DbgUiDebugActiveProcess, false },
        { "DebugActiveProcess", TryHook_DebugActiveProcess, TryUnHook_DebugActiveProcess, false }, //注入？
        { "DebugActiveProcessStop", TryHook_DebugActiveProcessStop, TryUnHook_DebugActiveProcessStop, false },
        { "TerminateProcess", TryHook_TerminateProcess, TryUnHook_TerminateProcess, false },
        { "NtDebugActiveProcess", TryHook_NtDebugActiveProcess, TryUnHook_NtDebugActiveProcess, false },
        { "NtRemoveProcessDebug", TryHook_NtRemoveProcessDebug, TryUnHook_NtRemoveProcessDebug, false },
        { "NtTerminateProcess", TryHook_NtTerminateProcess, TryUnHook_NtTerminateProcess, false },
        { "DbgUiIssueRemoteBreakin", TryHook_DbgUiIssueRemoteBreakin, TryUnHook_DbgUiIssueRemoteBreakin, false },
        { "WaitForDebugEvent", TryHook_WaitForDebugEvent, TryUnHook_WaitForDebugEvent, false },
        { "ContinueDebugEvent", TryHook_ContinueDebugEvent, TryUnHook_ContinueDebugEvent, false },
        { "NtDebugContinue", TryHook_NtDebugContinue, TryUnHook_NtDebugContinue, false },
        { "OutputDebugStringA", TryHook_OutputDebugStringA, TryUnHook_OutputDebugStringA, false },
        { "OutputDebugStringW", TryHook_OutputDebugStringW, TryUnHook_OutputDebugStringW, false },
        { "SetThreadContext", TryHook_SetThreadContext, TryUnHook_SetThreadContext, false },
        { "GetThreadContext", TryHook_GetThreadContext, TryUnHook_GetThreadContext, false },
        { "NtWriteVirtualMemory", TryHook_NtWriteVirtualMemory, TryUnHook_NtWriteVirtualMemory, false },
        { "NtReadVirtualMemory", TryHook_NtReadVirtualMemory, TryUnHook_NtReadVirtualMemory, false },
        { "WriteProcessMemory", TryHook_WriteProcessMemory, TryUnHook_WriteProcessMemory, false },
        { "ReadProcessMemory", TryHook_ReadProcessMemory, TryUnHook_ReadProcessMemory, false },
        { "VirtualProtectEx", TryHook_VirtualProtectEx, TryUnHook_VirtualProtectEx, false },
    };

    bool InstallAllHooks()
    {
        for (HookStep& step : g_HookSteps)
        {
            if (!step.install())
            {
                logger.Log("安装%s钩子失败", step.name);
                return false;
            }

            step.installed = true;
        }

        return true;
    }

    bool TryUninstallHook(const char* name, HookUninstallRoutine uninstall)
    {
        if (!uninstall())
        {
            logger.Log("卸载%s钩子失败", name);
            return false;
        }

        // 调试器会高频读取断点附近字节，回填路径保持静默，避免日志拖慢步进和反汇编刷新。
        return true;
    }

    bool UninstallInstalledHooks()
    {
        bool success = true;

        // Undo only committed steps, in reverse order. Failed detachments retain
        // their records so the runtime keeps this module and can retry cleanup.
        for (size_t index = _countof(g_HookSteps); index != 0; --index)
        {
            HookStep& step = g_HookSteps[index - 1];
            if (!step.installed)
            {
                continue;
            }
            if (TryUninstallHook(step.name, step.uninstall))
            {
                step.installed = false;
            }
            else
            {
                success = false;
            }
        }

        return success;
    }
}

bool SetupHook()
{
    if (HookDllMainInternal::g_HookRuntimeStopping != 0)
    {
        logger.Log("Hook runtime is stopping, skip setup");
        return false;
    }

    const LONG previousState = InterlockedCompareExchange(
        &HookDllMainInternal::g_HookInstalled,
        kHookStateInstalling,
        kHookStateNotInstalled);
    if (previousState != kHookStateNotInstalled)
    {
        return previousState == kHookStateInstalled;
    }

    if (!InitializeDevice())
    {
        InterlockedExchange(&HookDllMainInternal::g_HookInstalled, kHookStateNotInstalled);
        logger.Log("初始化设备失败");
        return false;
    }

    if (!InstallAllHooks())
    {
        InterlockedExchange(&HookDllMainInternal::g_HookInstalled, kHookStateCleanupRequired);
        logger.Log("钩子安装失败，初始化未完成，需要回滚已安装项");
        return false;
    }

    InterlockedExchange(&HookDllMainInternal::g_HookInstalled, kHookStateInstalled);
    logger.Log("初始化成功，钩子安装完毕");
    return true;
}

bool UnHook()
{
    const LONG state = InterlockedCompareExchange(&HookDllMainInternal::g_HookInstalled, 0, 0);
    if (state == kHookStateNotInstalled)
    {
        return true;
    }
    // Setup and teardown are owned by HookRuntimeThread. Installing is also
    // accepted here to clean up the runtime's structured-exception path.
    if (state == kHookStateUninstalling ||
        InterlockedCompareExchange(&HookDllMainInternal::g_HookInstalled,
            kHookStateUninstalling, state) != state)
    {
        return false;
    }

    if (!UninstallInstalledHooks())
    {
        InterlockedExchange(&HookDllMainInternal::g_HookInstalled, kHookStateCleanupRequired);
        logger.Log("部分钩子卸载失败，保留 DLL 和驱动连接，等待再次清理");
        return false;
    }

    if (g_hGeneralDriverDevice != INVALID_HANDLE_VALUE)
    {
        CloseHandle(g_hGeneralDriverDevice);
        g_hGeneralDriverDevice = INVALID_HANDLE_VALUE;
    }

    InterlockedExchange(&HookDllMainInternal::g_HookInstalled, kHookStateNotInstalled);
    return true;
}
