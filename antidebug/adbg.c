#include "adbg.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

DebugCheckResult debuggerChecks[] = {

    /* =====================================================================
     * TAB 1 — Anti-Debug 1
     * ===================================================================== */

    /* IsDebuggerPresent */
    {false, "IsBeingDebugged",               .functionPtr = IsBeingDebugged},
    {false, "PEB",                           .functionPtr = CheckPEB},

    /* NtGlobalFlag */
    {false, "NtGlobalFlag",                  .functionPtr = NtGlobalFlag},

    /* HeapFlags */
    {false, "ProcessHeap_Flags",             .functionPtr = ProcessHeapFlag},

    /* HeapForceFlags */
    {false, "ProcessHeapForce_Flag",         .functionPtr = ProcessHeapForceFlag},

    /* CheckRemoteDebuggerPresent */
    {false, "IsRemoteDebuggerPresent",       .functionPtrWithProcess = IsRemoteDebuggerPresent},
    {false, "DebugPort",                     .functionPtrWithProcess = DebugPort},

    /* OutputDebugString */
    {false, "OutputDebugString",             .functionPtr = CheckOutputDebugString},

    /* NtClose */
    {false, "InvalidHandle",                 .functionPtr = CheckCloseHandle},

    /* SeDebugPrivilege */
    {false, "OpenProcess",                   .functionPtr = CheckOpenProcess},

    /* BlockInput — no test yet
       {false, "BlockInput",                 .functionPtr = CheckBlockInput},         new: api/blockinput.c */

    /* ProcessDebugFlags */
    {false, "DebugFlags",                    .functionPtrWithProcess = DebugFlags},

    /* ProcessDebugObjectHandle */
    {false, "DebugObjectHandle",             .functionPtrWithProcess = DebugObjectHandle},

    /* TerminateProcess — no test yet
       {false, "TerminateProcess",           .functionPtr = CheckTerminateProcess},   new: api/terminateproc.c */

    /* NtSetInformationThread (ThreadHideFromDebugger) — no test yet
       {false, "NtSetInformationThread",     .functionPtr = CheckSetInfoThread},      new: api/setinfthread.c */

    /* NtQueryObject */
    {false, "NtQueryObject",                 .functionPtr = CheckNtQueryObject},

    /* FindWindow */
    {false, "Window",                        .functionPtr = CheckWindow},

    /* NtOpenProcess (block opening current process) — no test yet
       {false, "NtOpenProcess",              .functionPtr = CheckNtOpenProcess},      new: object/ntopnproc.c */

    /* =====================================================================
     * TAB 2 — Anti-Debug 2
     * ===================================================================== */

    /* Process32First — no test yet
       {false, "Process32First",             .functionPtr = CheckProcess32First},     new: flags/proc32.c */

    /* Process32Next — no test yet (share impl with Process32First)
       {false, "Process32Next",              .functionPtr = CheckProcess32Next},      new: flags/proc32.c */

    /* ParentProcess */
    {false, "ParentProcesses",               .functionPtrWithProcess = ParentProcesses},

    /* GetTickCount — TimingAttacks uses GetTickCount64 and QueryPerformanceCounter */
    {false, "Timing",                        .functionPtr = TimingAttacks},

    /* TimeGetTime — no dedicated test; TimingAttacks does not call timeGetTime
       {false, "TimeGetTime",                .functionPtr = CheckTimeGetTime},        new: flags/timegtime.c */

    /* QueryPerformanceCounter — covered by Timing above (calls QueryPerformanceCounter directly) */

    /* ZwGetContextThread */
    {false, "HardwareBreakpoint",            .functionPtrWithThread = HardwareBreakpoint},
    {false, "HardwareBreakpoint2",           .functionPtrWithProcessAndThread = HardwareBreakPoint2},

    /* NtSetContextThread — no test yet
       {false, "NtSetContextThread",         .functionPtr = CheckNtSetContextThread}, new: asm/setctxthread.c */

    /* KdDebuggerNotPresent */
    {false, "KernelDebugger",               .functionPtr = KernelDebugger},

    /* KdDebuggerEnabled — covered by KernelDebugger above (checks both flags) */

    /* NtSetDebugFilterState — no test yet
       {false, "NtSetDebugFilterState",      .functionPtr = CheckDbgFilterState},    new: api/dbgfilterstate.c */

    /* ProtectDRX — no test yet
       {false, "ProtectDRX",                 .functionPtrWithThread = CheckProtectDRX}, new: memory/protectdrx.c */

    /* HideDRX — no test yet (HardwareBreakpoint checks GetContextThread path only;
       HideDRX operates via KiUserExceptionDispatcher exception context)
       {false, "HideDRX",                    .functionPtrWithThread = CheckHideDRX}, new: memory/hidedrx.c */

    /* DbgPrompt — no test yet (DBGP checks ACPI firmware tables, unrelated)
       {false, "DbgPrompt",                  .functionPtr = CheckDbgPrompt},          new: memory/dbgprompt.c */

    /* CreateThread — no test yet
       {false, "CreateThread",               .functionPtr = CheckCreateThread},       new: api/createthread.c */

    /* NtSystemDebugControl */
    {false, "NtSystemDebugControl",          .functionPtr = NtSystemDebugControl},

    /* =====================================================================
     * TAB 3 — Anti-Debug 3
     * ===================================================================== */

    /* RtlRaiseException — POPFTrapFlag raises EXCEPTION_SINGLE_STEP (0x80000004)
       via RaiseException->RtlRaiseException; plugin hook suppresses that exact code */
    {false, "POPFTrapFlag",                  .functionPtr = POPFTrapFlag},

    /* Apply Custom Patches — INI-driven; no generic test possible */

    /* =====================================================================
     * Uncovered — antidbg checks with no corresponding plugin protection
     * ===================================================================== */
    {false, "DebuggerBreak",                 .functionPtr = DebuggerBreak},
    {false, "int2D",                         .functionPtr = int2D},
    {false, "int3",                          .functionPtr = int3},
    {false, "StackSegmentRegister",          .functionPtrWithThread = StackSegmentRegister},
    {false, "PrefixHop",                     .functionPtr = PrefixHop},
    {false, "RaiseDbgControl",               .functionPtr = RaiseDbgControl},
    {false, "DuplicatedHandles",             .functionPtrWithProcess = DuplicatedHandles},
    {false, "NtSetLdtEntries",              .functionPtr = CheckNtSetLdtEntries},
    {false, "VirtualAlloc_MEM_WRITE_WATCH",  .functionPtr = WriteWatch},
    {false, "SetHandleInformation",          .functionPtr = ProtectedHandle},
    {false, "ReadOwnMemoryStack",            .functionPtr = ReadMemoryStack},
    {false, "ProcessJob",                    .functionPtr = ProcessJob},
    {false, "MemoryBreakpoint",             .functionPtrWithProcess = MemoryBreakpoint},
    {false, "PageExceptionBreakpoint",       .functionPtrWithProcess = PageExceptionBreakpoint},
    {false, "DBGP",                          .functionPtr = dbgp},
    {false, "LBR",                           .functionPtr = lbr},
};

#define NUM_DEBUG_CHECKS (sizeof(debuggerChecks) / sizeof(debuggerChecks[0]))

static bool g_activeChecks[NUM_DEBUG_CHECKS];

static void init_active_checks(void) {
    for (int i = 0; i < (int)NUM_DEBUG_CHECKS; ++i)
        g_activeChecks[i] = true;
}

static void print_usage(void) {
#ifdef _DEBUG
    printf("Usage: antidbg [-h] [-d] [-p <spec>]\n\n");
#else
    printf("Usage: antidbg [-h] [-p <spec>]\n\n");
#endif
    printf("  -h          Show this help and exit\n");
#ifdef _DEBUG
    printf("  -d          Dry run: log detections but do not terminate\n");
#endif
    printf("  -p <spec>   Run only the specified checks (default: all %d active)\n\n", (int)NUM_DEBUG_CHECKS);
    printf("  <spec> format: comma-separated indices and/or inclusive ranges\n");
    printf("    Examples:\n");
    printf("      -p 0,1,2,3     checks 0, 1, 2, 3\n");
    printf("      -p 0-2,5-6     checks 0, 1, 2, 5, 6\n");
    printf("      -p 0,2-5,7     checks 0, 2, 3, 4, 5, 7\n");
    printf("      -p -5          checks 0 through 5 (open left)\n");
    printf("      -p 5-          checks 5 through last (open right)\n\n");
    printf("  Available checks:\n");
    for (int i = 0; i < (int)NUM_DEBUG_CHECKS; ++i)
        printf("    %2d  %s\n", i, debuggerChecks[i].functionName);
}

static bool parse_protection_spec(const char* spec) {
    char buf[512];
    const size_t specLen = strlen(spec);
    if (specLen == 0 || specLen >= sizeof(buf)) {
        fprintf(stderr, "[-] Invalid -p spec (empty or too long)\n");
        return false;
    }
    memcpy(buf, spec, specLen + 1);

    // reset all to false; only enable what is specified
    for (int i = 0; i < (int)NUM_DEBUG_CHECKS; ++i)
        g_activeChecks[i] = false;

    char* ctx = NULL;
    char* token = strtok_s(buf, ",", &ctx);
    while (token != NULL) {
        char* dash = strchr(token, '-');
        if (dash != NULL) {
            // range: start-end, -end (short for 0-end), start- (short for start to last)
            *dash = '\0';
            long start, end;

            if (token[0] == '\0') {
                start = 0;
            } else {
                char* endptr = NULL;
                start = strtol(token, &endptr, 10);
                if (*endptr != '\0') {
                    fprintf(stderr, "[-] Non-numeric value in range '%s-...'\n", token);
                    return false;
                }
            }

            if (dash[1] == '\0') {
                end = (long)NUM_DEBUG_CHECKS - 1;
            } else {
                char* endptr = NULL;
                end = strtol(dash + 1, &endptr, 10);
                if (*endptr != '\0') {
                    fprintf(stderr, "[-] Non-numeric value in range '...-%s'\n", dash + 1);
                    return false;
                }
            }

            if (start > end) {
                fprintf(stderr, "[-] Inverted range %ld-%ld\n", start, end);
                return false;
            }
            if (start < 0 || end >= (long)NUM_DEBUG_CHECKS) {
                fprintf(stderr, "[-] Range %ld-%ld out of bounds (0-%d)\n", start, end, (int)NUM_DEBUG_CHECKS - 1);
                return false;
            }
            for (long i = start; i <= end; ++i)
                g_activeChecks[i] = true;
        } else {
            // single index
            char* endptr = NULL;
            const long idx = strtol(token, &endptr, 10);
            if (*endptr != '\0') {
                fprintf(stderr, "[-] Non-numeric value '%s'\n", token);
                return false;
            }
            if (idx < 0 || idx >= (long)NUM_DEBUG_CHECKS) {
                fprintf(stderr, "[-] Index %ld out of bounds (0-%d)\n", idx, (int)NUM_DEBUG_CHECKS - 1);
                return false;
            }
            g_activeChecks[idx] = true;
        }
        token = strtok_s(NULL, ",", &ctx);
    }
    return true;
}


DWORD __stdcall __adbg(LPVOID lpParam) {
    const HANDLE hProcess = (HANDLE)(lpParam);
    const HANDLE hThread = (HANDLE)(-2LL);

    while (1) {
        for (int i = 0; i < NUM_DEBUG_CHECKS; ++i) {
            if (!g_activeChecks[i]) continue;

            if (debuggerChecks[i].functionPtrWithProcess != NULL) {
                debuggerChecks[i].result = debuggerChecks[i].functionPtrWithProcess(hProcess);
            }
            else if (debuggerChecks[i].functionPtrWithThread != NULL) {
                debuggerChecks[i].result = debuggerChecks[i].functionPtrWithThread(hThread);
            }
            else if (debuggerChecks[i].functionPtrWithProcessAndThread != NULL) {
                debuggerChecks[i].result = debuggerChecks[i].functionPtrWithProcessAndThread(hProcess, hThread);
            }
            else if (debuggerChecks[i].functionPtr != NULL) {
                debuggerChecks[i].result = debuggerChecks[i].functionPtr();
            }

            if (debuggerChecks[i].result) {
#ifdef _DEBUG
                dbg_log("[!] Debugger detected in function: %s\n", debuggerChecks[i].functionName);
                if (!g_dryRun)
#endif
                    __fastfail(EXIT_SUCCESS);
            }

            // ensure our thread priority was not tampered with
            const int currentPriority = GetThreadPriority(hThread);
            if (currentPriority == THREAD_PRIORITY_ERROR_RETURN) {
            #ifdef _DEBUG
                dbg_log("[-] Failed to query thread priority. Error: %d\n", GetLastError());
            #endif
            }

            if (currentPriority != THREAD_PRIORITY_NORMAL) {
                if (!SetThreadPriority(hThread, THREAD_PRIORITY_NORMAL)) {
                #ifdef _DEBUG
                    dbg_log("[-] Failed to set thread priority. Error: %d\n", GetLastError());
                #endif
                }
            }

            const DWORD minDelayMs = 500;
            const DWORD maxDelayMs = 2000;
            DWORD randomValue = 0;

            // maybe to syscall it we would need to get a handle to the cng device and get the IOCTL code (of course will change between versions) that this sends to the driver
            const NTSTATUS status = BCryptGenRandom(
                NULL,
                (PUCHAR)&randomValue,
                sizeof(randomValue),
                BCRYPT_USE_SYSTEM_PREFERRED_RNG);

            DWORD randomDelayMs;
            if (BCRYPT_SUCCESS(status)) { // something like RtlGenRandom
                randomDelayMs = minDelayMs + (randomValue % (maxDelayMs - minDelayMs + 1));
            }
            else {
                randomDelayMs = minDelayMs;
            }

            LARGE_INTEGER delay = { 0 };
            const __int64 randomDelayMs64 = (__int64)randomDelayMs;
            const __int64 conversionFactor = 10000;
            const __int64 result = -(randomDelayMs64 * conversionFactor);

            delay.QuadPart = result;

            DbgNtDelayExecution(FALSE, &delay);
        }
        dbg_log("[*] Debugger detection end\n");
    }

    return 0;
}

void StartDebugProtection() {
    const PVOID hVeh = AddVectoredExceptionHandler(1, VectoredDebuggerCheck);
    if (!hVeh) {
        __fastfail(STATUS_ACCESS_VIOLATION);
    }

    StartAttachProtection();
    const HANDLE hProcess = (HANDLE)(-1LL);
    DbgCreateThread((HANDLE)(-1LL), 0, __adbg, (LPVOID)hProcess, 0, ((void*)0), ((void*)0));
    StartMemoryTracker(hProcess);
}

bool isProgramBeingDebugged() {
    const HANDLE hProcess = (HANDLE)(-1LL);
    const HANDLE hThread = (HANDLE)(-2LL);

    for (int i = 0; i < NUM_DEBUG_CHECKS; ++i) {
        if (!g_activeChecks[i]) continue;

        if (debuggerChecks[i].functionPtrWithProcess != NULL) {
            debuggerChecks[i].result = debuggerChecks[i].functionPtrWithProcess(hProcess);
        }
        else if (debuggerChecks[i].functionPtrWithThread != NULL) {
            debuggerChecks[i].result = debuggerChecks[i].functionPtrWithThread(hThread);
        }
        else if (debuggerChecks[i].functionPtrWithProcessAndThread != NULL) {
            debuggerChecks[i].result = debuggerChecks[i].functionPtrWithProcessAndThread(hProcess, hThread);
        }
        else if (debuggerChecks[i].functionPtr != NULL) {
            debuggerChecks[i].result = debuggerChecks[i].functionPtr();
        }

        if (debuggerChecks[i].result) {
        #ifdef _DEBUG
            printf("[!] Debugger detected in function: %s\n", debuggerChecks[i].functionName);
        #endif
            return true;
        }
    }

    DbgNtClose(hProcess);
    DbgNtClose(hThread);
    return false;
}

int main(int argc, char* argv[]) {
    init_active_checks();

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-h") == 0) {
            print_usage();
            return 0;
        }
#ifdef _DEBUG
        if (strcmp(argv[i], "-d") == 0) {
            g_dryRun = true;
            continue;
        }
#endif
        if (strcmp(argv[i], "-p") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "[-] -p requires an argument\n");
                print_usage();
                return 1;
            }
            ++i;
            if (!parse_protection_spec(argv[i])) {
                print_usage();
                return 1;
            }
        }
    }

#ifdef _DEBUG
    if (g_dryRun)
        dbg_log("[*] Dry run mode: detections will be logged but process will not terminate\n");
#endif
    dbg_log("[*] Active checks:\n");
    for (int i = 0; i < (int)NUM_DEBUG_CHECKS; ++i) {
        if (g_activeChecks[i])
            printf("    %2d  %s\n", i, debuggerChecks[i].functionName);
    }

    StartDebugProtection();
    return 0;
}
