#include "EptHookCommon.h"

EXTERN_C
BOOLEAN Hook_NtUserFindWindowEx()
{
    if (g_IsInitGlobalVariable)
    {
        return HookEptRoutine(Sys_NtUserFindWindowEx, NewNtUserFindWindowEx, (PVOID*)&Original_NtUserFindWindowEx, "NtUserFindWindowEx", "NtUserFindWindowEx");
    }
    return FALSE;
}

EXTERN_C
BOOLEAN Hook_ValidateHwnd()
{
    if (g_IsInitGlobalVariable)
    {
        return HookEptRoutine(Sys_ValidateHwnd, NewValidateHwnd, (PVOID*)&Original_ValidateHwnd, "ValidateHwnd", "ValidateHwnd");
    }
    return FALSE;
}

EXTERN_C
BOOLEAN Hook_NtUserWindowFromPoint()
{
    if (g_IsInitGlobalVariable)
    {
        return HookEptRoutine(Sys_NtUserWindowFromPoint, NewNtUserWindowFromPoint, (PVOID*)&Original_NtUserWindowFromPoint, "NtUserWindowFromPoint", "NtUserWindowFromPoint");
    }
    return FALSE;
}

EXTERN_C
BOOLEAN Hook_NtUserSetWindowsHookEx()
{
    if (g_IsInitGlobalVariable)
    {
        return HookEptRoutine(Sys_NtUserSetWindowsHookEx, NewNtUserSetWindowsHookEx, (PVOID*)&Original_NtUserSetWindowsHookEx, "NtUserSetWindowsHookEx", "NtUserSetWindowsHookEx");
    }
    return FALSE;
}

EXTERN_C
BOOLEAN Hook_NtUserBuildHwndList()
{
    if (g_IsInitGlobalVariable)
    {
        return HookEptRoutine(Sys_NtUserBuildHwndList, NewNtUserBuildHwndList, (PVOID*)&Original_NtUserBuildHwndList, "NtUserBuildHwndList", "NtUserBuildHwndList");
    }
    return FALSE;
}

EXTERN_C
BOOLEAN Hook_NtUserGetClassName()
{
    if (g_IsInitGlobalVariable)
    {
        return HookEptRoutine(Sys_NtUserGetClassName, NewNtUserGetClassName, (PVOID*)&Original_NtUserGetClassName, "NtUserGetClassName", "NtUserGetClassName");
    }
    return FALSE;
}
