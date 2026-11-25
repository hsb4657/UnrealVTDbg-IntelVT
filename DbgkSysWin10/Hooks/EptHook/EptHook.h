#pragma once

#ifndef _EPT_HOOK_H
#define _EPT_HOOK_H

EXTERN_C
VOID UnEptHook();

EXTERN_C
VOID DisableDbgkHotUnload();

EXTERN_C
BOOLEAN SetupEptHook();

EXTERN_C
NTSTATUS ConfigureEptHookSelection(ULONG64 mask);

EXTERN_C
BOOLEAN Hook_DbgkOpenProcessDebugPort();

EXTERN_C
BOOLEAN Hook_NtCreateDebugObject();

EXTERN_C
BOOLEAN Hook_NtSetInformationDebugObject();

EXTERN_C
BOOLEAN Hook_NtRemoveProcessDebug();

EXTERN_C
BOOLEAN Hook_NtDebugActiveProcess();

EXTERN_C
BOOLEAN Hook_NtWaitForDebugEvent();

EXTERN_C
VOID Hook_KiDispatchException();

EXTERN_C
BOOLEAN Hook_PspInsertProcess();

EXTERN_C
VOID Hook_PspInsertThread();

EXTERN_C
BOOLEAN Hook_NtDebugContinue();

EXTERN_C
BOOLEAN Hook_DbgkMapViewOfSection();

EXTERN_C
BOOLEAN Hook_DbgkUnMapViewOfSection();

EXTERN_C
BOOLEAN Hook_NtQueryInformationThread();

EXTERN_C
BOOLEAN Hook_NtSetInformationThread();

EXTERN_C
BOOLEAN Hook_NtQueryInformationProcess();

EXTERN_C
BOOLEAN Hook_NtSetInformationProcess();

EXTERN_C
BOOLEAN Hook_NtQueryObject();

EXTERN_C
BOOLEAN Hook_NtQuerySystemInformation();

EXTERN_C
BOOLEAN Hook_NtSystemDebugControl();

EXTERN_C
BOOLEAN Hook_NtClose();

EXTERN_C
BOOLEAN Hook_NtDuplicateObject();

EXTERN_C
VOID Hook_NtSuspendThread();

EXTERN_C
VOID Hook_NtResumeThread();

EXTERN_C
BOOLEAN Hook_DbgkCreateThread();

EXTERN_C
BOOLEAN Hook_DbgkExitThread();

EXTERN_C
BOOLEAN Hook_DbgkExitProcess();

EXTERN_C
BOOLEAN Hook_DbgkForwardException();

EXTERN_C
BOOLEAN Hook_DbgkpQueueMessage();

EXTERN_C
VOID Hook_KeStackAttachProcess();

EXTERN_C
VOID Hook_KiStackAttachProcess();

EXTERN_C
VOID Hook_NtProtectVirtualMemory();

EXTERN_C
VOID Hook_MiObtainReferencedVadEx();

EXTERN_C
VOID Hook_MmProtectVirtualMemory();

EXTERN_C
BOOLEAN Hook_NtQueryInformationThread();

EXTERN_C
BOOLEAN Hook_NtGetContextThread();

EXTERN_C
BOOLEAN Hook_NtSetContextThread();

EXTERN_C
VOID Hook_NtShutdownSystem();

EXTERN_C
VOID Hook_NtOpenProcess();

EXTERN_C
VOID Hook_NtReadVirtualMemory();

EXTERN_C
VOID Hook_NtWriteVirtualMemory();

EXTERN_C
VOID Hook_ObReferenceObjectByHandle();

EXTERN_C
VOID Hook_ObReferenceObjectByHandleWithTag();

EXTERN_C
BOOLEAN Hook_ObpReferenceObjectByHandleWithTag();

EXTERN_C
VOID Hook_ObfDereferenceObjectWithTag();

EXTERN_C
VOID Hook_ObfDereferenceObject();

EXTERN_C
VOID Hook_MmCopyVirtualMemory();

EXTERN_C
VOID Hook_PspCreateUserContext();

EXTERN_C
BOOLEAN Hook_PspCallThreadNotifyRoutines();

EXTERN_C
VOID Hook_NtTerminateProcess();

EXTERN_C
BOOLEAN Hook_PspExitThread();

EXTERN_C
VOID Hook_PspCreateThread();

EXTERN_C
BOOLEAN Hook_NtCreateThreadEx();

EXTERN_C
VOID Hook_PspAllocateThread();

EXTERN_C
VOID Hook_DbgkpCloseObject();


//win32k.sys
EXTERN_C
BOOLEAN Hook_NtUserFindWindowEx();

EXTERN_C
BOOLEAN Hook_ValidateHwnd();

EXTERN_C
BOOLEAN Hook_NtUserWindowFromPoint();

EXTERN_C
BOOLEAN Hook_NtUserSetWindowsHookEx();

EXTERN_C
BOOLEAN Hook_NtUserBuildHwndList();

EXTERN_C
BOOLEAN Hook_NtUserGetClassName();

// 反-反调试共享判定：虚拟调试目标（attach 路径查 g_DebugProcessList，
// create 路径查 EPROCESS->DebugPort 是否为 Hvm_DebugObject）。
BOOLEAN HvmIsVirtualDebugTargetProcess(_EPROCESS* Process, PVOID* DebugProcess);
BOOLEAN HvmIsCallerVirtualDebugTarget();
BOOLEAN HvmIsProcessHandleVirtualDebugTarget(HANDLE ProcessHandle, KPROCESSOR_MODE PreviousMode);
BOOLEAN HvmIsThreadHandleVirtualDebugTarget(HANDLE ThreadHandle, KPROCESSOR_MODE PreviousMode);

// attach/create 两条路径统一清除 PEB/线程调试痕迹（TitanHide Olly 插件同款目标）。
VOID PrepareVirtualDebugTargetProcess(_EPROCESS* Process);

#endif // !_EPT_HOOK_H
