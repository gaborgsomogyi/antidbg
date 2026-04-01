#include "thrmng.h"
#include "syscall.h"
#include "config.h"

HANDLE DbgCreateThread(
    const HANDLE hProcess,
    const SIZE_T dwStackSize,
    const LPTHREAD_START_ROUTINE lpStartAddress,
    const LPVOID lpParameter,
    const DWORD dwCreationFlags,
    const LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
    LPDWORD lpThreadId)
{
    HANDLE hThread = NULL;
#pragma warning (disable : 4152)
    const NTSTATUS statusCreate = DbgNtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        lpStartAddress,
        lpParameter,
        dwCreationFlags,
        0,
        dwStackSize,
        dwStackSize,
        (PPS_ATTRIBUTE_LIST)lpAttributeList);
#pragma warning (default : 4152)

    if (statusCreate < 0) {
        SetLastError(statusCreate);
        return NULL;
    }

#ifdef _DEBUG
    if (!g_dryRun)
#endif
        DbgNtSetInformationThread(hThread, ThreadHideFromDebugger, NULL, 0);

    if (lpThreadId)
        *lpThreadId = GetThreadId(hThread);

    return hThread;
}