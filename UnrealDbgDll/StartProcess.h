#pragma once

#ifndef _START_PROCESS_H
#define _START_PROCESS_H

void EnableStartupWorkers();
void StopStartupWorkers();

BOOL StartProcess(TCHAR* szExe, TCHAR* sPath);

//根据光标位置获取进程pid
DWORD GetProcessId_ByCursor();

//下发调试器信息给驱动
BOOL SendDebuggerDataToDriver(DWORD dwProcessId);


#endif // !_START_PROCESS_H
