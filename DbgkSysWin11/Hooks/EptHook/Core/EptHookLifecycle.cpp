#include "EptHookCommon.h"

static ULONG64 g_EptHookSelectionMask = HOOK_SELECTION_ALL;

EXTERN_C
NTSTATUS ConfigureEptHookSelection(ULONG64 mask)
{
    if ((mask & ~HOOK_SELECTION_ALL) != 0)
    {
        outFile("拒绝修改 EPT hook 选择：掩码包含未知位 0x%llX.", mask);
        return STATUS_INVALID_PARAMETER;
    }

    g_EptHookSelectionMask = mask;
    outFile("EPT hook 选择已配置：mask=0x%llX.", mask);
    return STATUS_SUCCESS;
}

EXTERN_C
VOID UnEptHook()
{
    if (!g_IsInitGlobalVariable)
    {
        outLog("跳过 EPT 取消 hook：符号或 hook 尚未初始化.");
        //是我们自己的调试器要创建线程，则直接返回不走线程回调
        return;
    }

    bool vtReady = false;
    __try
    {
        vtReady = hvgt::test_vmcall();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        vtReady = false;
    }

    if (!vtReady)
    {
        outLog("跳过 EPT 取消 hook：VT 通道不可用.");
        KeBugCheckEx(0x00020001, 0x4442474B, 1, 0, 0);
        return;
    }

    bool unhooked = false;
    __try
    {
        unhooked = hvgt::ept_unhook();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        unhooked = false;
    }

    if (unhooked)
    {
        outLog("EPT 取消 hook 成功.");

        // Removing EPT redirects does not finish callbacks already in this driver.
        // Keep original trampolines valid while DbgkUnInitialize drains those calls.
        // A subsequent initialization replaces them only after that drain completes.
        g_IsInitGlobalVariable = FALSE;
        return;
    }

    outLog("EPT 取消 hook 失败或已跳过.");
    KeBugCheckEx(0x00020001, 0x4442474B, 2, 0, 0);
}

EXTERN_C
BOOLEAN SetupEptHook()
{
    if (!g_IsInitGlobalVariable)
    {
        return FALSE;
    }

    struct HookStep
    {
        ULONG64 mask;
        const char* name;
        BOOLEAN (*install)();
    };
    // Preserve installation order: NtCreateDebugObject first, ValidateHwnd
    // first in the win32k group. Only hooks selected by the user are required.
    const HookStep steps[] =
    {
        { HOOK_SELECTION_NT_CREATE_DEBUG_OBJECT, "Hook_NtCreateDebugObject", Hook_NtCreateDebugObject },
        { HOOK_SELECTION_PSP_INSERT_PROCESS, "Hook_PspInsertProcess", Hook_PspInsertProcess },
        { HOOK_SELECTION_NT_SET_INFORMATION_DEBUG_OBJECT, "Hook_NtSetInformationDebugObject", Hook_NtSetInformationDebugObject },
        { HOOK_SELECTION_NT_REMOVE_PROCESS_DEBUG, "Hook_NtRemoveProcessDebug", Hook_NtRemoveProcessDebug },
        { HOOK_SELECTION_NT_DEBUG_ACTIVE_PROCESS, "Hook_NtDebugActiveProcess", Hook_NtDebugActiveProcess },
        { HOOK_SELECTION_NT_WAIT_FOR_DEBUG_EVENT, "Hook_NtWaitForDebugEvent", Hook_NtWaitForDebugEvent },
        { HOOK_SELECTION_NT_DEBUG_CONTINUE, "Hook_NtDebugContinue", Hook_NtDebugContinue },
        { HOOK_SELECTION_DBGK_MAP_VIEW_OF_SECTION, "Hook_DbgkMapViewOfSection", Hook_DbgkMapViewOfSection },
        { HOOK_SELECTION_DBGK_UNMAP_VIEW_OF_SECTION, "Hook_DbgkUnMapViewOfSection", Hook_DbgkUnMapViewOfSection },
        { HOOK_SELECTION_DBGK_CREATE_THREAD, "Hook_DbgkCreateThread", Hook_DbgkCreateThread },
        { HOOK_SELECTION_DBGK_EXIT_THREAD, "Hook_DbgkExitThread", Hook_DbgkExitThread },
        { HOOK_SELECTION_DBGK_EXIT_PROCESS, "Hook_DbgkExitProcess", Hook_DbgkExitProcess },
        { HOOK_SELECTION_DBGK_FORWARD_EXCEPTION, "Hook_DbgkForwardException", Hook_DbgkForwardException },
        { HOOK_SELECTION_DBGKP_QUEUE_MESSAGE, "Hook_DbgkpQueueMessage", Hook_DbgkpQueueMessage },
        { HOOK_SELECTION_PSP_EXIT_THREAD, "Hook_PspExitThread", Hook_PspExitThread },
        { HOOK_SELECTION_OBP_REFERENCE_OBJECT_BY_HANDLE_TAG, "Hook_ObpReferenceObjectByHandleWithTag", Hook_ObpReferenceObjectByHandleWithTag },
        { HOOK_SELECTION_NT_CLOSE, "Hook_NtClose", Hook_NtClose },
        { HOOK_SELECTION_NT_DUPLICATE_OBJECT, "Hook_NtDuplicateObject", Hook_NtDuplicateObject },
        { HOOK_SELECTION_DBGK_OPEN_PROCESS_DEBUG_PORT, "Hook_DbgkOpenProcessDebugPort", Hook_DbgkOpenProcessDebugPort },
        { HOOK_SELECTION_NT_QUERY_INFORMATION_PROCESS, "Hook_NtQueryInformationProcess", Hook_NtQueryInformationProcess },
        { HOOK_SELECTION_NT_SET_INFORMATION_PROCESS, "Hook_NtSetInformationProcess", Hook_NtSetInformationProcess },
        { HOOK_SELECTION_NT_QUERY_OBJECT, "Hook_NtQueryObject", Hook_NtQueryObject },
        { HOOK_SELECTION_NT_QUERY_SYSTEM_INFORMATION, "Hook_NtQuerySystemInformation", Hook_NtQuerySystemInformation },
        { HOOK_SELECTION_NT_SYSTEM_DEBUG_CONTROL, "Hook_NtSystemDebugControl", Hook_NtSystemDebugControl },
        { HOOK_SELECTION_NT_SET_INFORMATION_THREAD, "Hook_NtSetInformationThread", Hook_NtSetInformationThread },
        { HOOK_SELECTION_NT_QUERY_INFORMATION_THREAD, "Hook_NtQueryInformationThread", Hook_NtQueryInformationThread },
        { HOOK_SELECTION_NT_GET_CONTEXT_THREAD, "Hook_NtGetContextThread", Hook_NtGetContextThread },
        { HOOK_SELECTION_NT_SET_CONTEXT_THREAD, "Hook_NtSetContextThread", Hook_NtSetContextThread },
        { HOOK_SELECTION_NT_CREATE_THREAD_EX, "Hook_NtCreateThreadEx", Hook_NtCreateThreadEx },
        { HOOK_SELECTION_VALIDATE_HWND, "Hook_ValidateHwnd", Hook_ValidateHwnd },
        { HOOK_SELECTION_NT_USER_FIND_WINDOW_EX, "Hook_NtUserFindWindowEx", Hook_NtUserFindWindowEx },
        { HOOK_SELECTION_NT_USER_WINDOW_FROM_POINT, "Hook_NtUserWindowFromPoint", Hook_NtUserWindowFromPoint },
        { HOOK_SELECTION_NT_USER_SET_WINDOWS_HOOK_EX, "Hook_NtUserSetWindowsHookEx", Hook_NtUserSetWindowsHookEx },
        { HOOK_SELECTION_NT_USER_GET_CLASS_NAME, "Hook_NtUserGetClassName", Hook_NtUserGetClassName },
    };

    for (const HookStep& step : steps)
    {
        if ((g_EptHookSelectionMask & step.mask) != 0 && !step.install())
        {
            outFile("EPT hook 初始化失败: %s；回滚全部处理器上的已安装项.", step.name);
            // Include partially installed hooks on the failing CPU broadcast.
            // UnEptHook must finish before the caller releases Dbgk state.
            UnEptHook();
            return FALSE;
        }
    }
    return TRUE;
}
