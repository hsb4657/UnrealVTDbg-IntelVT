#pragma once

#ifndef _DBGKAPI_H
#define _DBGKAPI_H

#include "../Driver.h"
#include "../Globals.h"  // 包含调试类型定义

#define DBGK_EXCEPTIONPORT_MASK           7   //异常端口

//
// NtCreateDebugObject Flags
//
#define DBGK_KILL_PROCESS_ON_EXIT         (0x1)
#define DBGK_ALL_FLAGS                    (DBGK_KILL_PROCESS_ON_EXIT)


extern volatile LONG g_DbgkActiveRuntimeCallCount; // Active hook/debug callback count during unload drain

inline BOOLEAN DbgkIsDriverRuntimeUnloading()
{
    return InterlockedCompareExchange(&g_DbgkDriverUnloading, 0, 0) != 0;
}

class DbgkRuntimeCallGuard
{
public:
    DbgkRuntimeCallGuard()
    {
        InterlockedIncrement(&g_DbgkActiveRuntimeCallCount);
    }

    ~DbgkRuntimeCallGuard() { Release(); }

    // Terminal calls (PspExitThread) never run C++ destructors. Release the state
    // reference explicitly after the last state access and before transferring control.
    void Release()
    {
        if (active_)
        {
            active_ = false;
            InterlockedDecrement(&g_DbgkActiveRuntimeCallCount);
        }
    }

    DbgkRuntimeCallGuard(const DbgkRuntimeCallGuard&) = delete;
    DbgkRuntimeCallGuard& operator=(const DbgkRuntimeCallGuard&) = delete;
private:
    bool active_ = true;
};

#include "Api/DebugObjectCommon.h"
#include "Api/CreateDebugObject.h"
#include "Api/DebugActiveProcess.h"
#include "Api/WaitForDebugEvent.h"
#include "Api/DebugContinue.h"
#include "Api/RemoveProcessDebug.h"
#include "Api/SetInformationDebugObject.h"
#include "Api/DebugEventHandlers.h"

#endif // !_DBGKAPI_H
