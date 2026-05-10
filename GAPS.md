# Gap Analysis: antidbg ↔ x64dbgext

Tracks coverage parity between the x64dbgext plugin protections and the antidbg test
application. Every plugin protection should have a corresponding antidbg test, and every
antidbg test should have a corresponding plugin protection.

Legend: ✅ covered · `[ ]` not yet implemented · N/A not applicable

Check off `[ ]` items as you implement them and uncomment the matching placeholder in
`antidebug/adbg.c` (or add the new plugin protection file).

---

## Part 1 — Plugin protections → antidbg tests

Ordered by plugin tab, matching `debuggerChecks[]` index order.

### Tab 1 — Anti-Debug 1 (`-p 0-13`)

| antidbg idx | Plugin protection | antidbg test | Status | Where to implement |
|-------------|-------------------|--------------|--------|--------------------|
| 0–1 | IsDebuggerPresent | `IsBeingDebugged`, `PEB` | ✅ | — |
| 2 | NtGlobalFlag | `NtGlobalFlag` | ✅ | — |
| 3 | HeapFlags | `ProcessHeap_Flags` | ✅ | — |
| 4 | HeapForceFlags | `ProcessHeapForce_Flag` | ✅ | — |
| 5–6 | CheckRemoteDebuggerPresent | `IsRemoteDebuggerPresent`, `DebugPort` | ✅ | — |
| 7 | OutputDebugString | `OutputDebugString` | ✅ | — |
| 8 | NtClose | `InvalidHandle` | ✅ | — |
| 9 | SeDebugPrivilege | `OpenProcess` | ✅ | — |
| — | BlockInput | — | `[ ]` | New file `antidebug/api/blockinput.c`. Call `BlockInput(TRUE)`; if it returns TRUE the hook is absent and the call succeeded — that means no protection, so invert: detect by calling `BlockInput(FALSE)` and checking whether input is actually blocked. |
| 10 | ProcessDebugFlags | `DebugFlags` | ✅ | — |
| 11 | ProcessDebugObjectHandle | `DebugObjectHandle` | ✅ | — |
| — | TerminateProcess | — | `[ ]` | New file `antidebug/api/terminateproc.c`. Call `TerminateProcess(GetCurrentProcess(), 0)` — if plugin hook intercepts it and returns TRUE without terminating, execution continues; if it does not reach the next line, process terminated (no detection possible). Better approach: call with a dummy process handle and verify return value or hook behaviour. |
| — | NtSetInformationThread | — | `[ ]` | New file `antidebug/api/setinfthread.c`. Call `NtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, NULL, 0)` via syscall; without the hook this succeeds and hides the thread. Check by querying thread info afterward, or use the fact that a hooked call returns `STATUS_SUCCESS` but does NOT actually hide the thread (visible via `NtQueryInformationThread`). |
| 12 | NtQueryObject | `NtQueryObject` | ✅ | — |
| 13 | FindWindow | `Window` | ✅ | — |
| — | NtOpenProcess | — | `[ ]` | New file `antidebug/object/ntopnproc.c`. Call `NtOpenProcess` on the current process PID; without the plugin hook it succeeds (returns valid handle), with the hook it returns `STATUS_INVALID_CID`. Detect presence by expecting failure. |

### Tab 2 — Anti-Debug 2 (`-p 14-19`)

| antidbg idx | Plugin protection | antidbg test | Status | Where to implement |
|-------------|-------------------|--------------|--------|--------------------|
| — | Process32First | — | `[ ]` | New file `antidebug/flags/proc32.c`. Create a process snapshot with `CreateToolhelp32Snapshot`, walk with `Process32First`/`Process32Next`, verify the current process PID is absent. |
| — | Process32Next | — | `[ ]` | Shared impl with Process32First in `antidebug/flags/proc32.c`. |
| 14 | ParentProcess | `ParentProcesses` | ✅ | — |
| 15 | GetTickCount | `Timing` | ✅ | Note: `TimingAttacks` uses `GetTickCount64`, not the hooked `GetTickCount`. If precise hook testing is needed, add a dedicated `GetTickCount` call to `antidebug/flags/timing.c`. |
| — | TimeGetTime | — | `[ ]` | New file `antidebug/flags/timegtime.c` or extend `timing.c`. Call `timeGetTime` twice with a `Sleep` in between; if both readings are identical (counter stuck at 1 as the plugin does), detect the hook. |
| 15 | QueryPerformanceCounter | `Timing` | ✅ | Covered by `TimingAttacks` (calls `QueryPerformanceCounter` directly). |
| 16–17 | ZwGetContextThread | `HardwareBreakpoint`, `HardwareBreakpoint2` | ✅ | — |
| — | NtSetContextThread | — | `[ ]` | New file `antidebug/asm/setctxthread.c`. Set a known value in a scratch register via `NtSetContextThread`; read it back. If the plugin stripped `CONTEXT_CONTROL` the register value will not have changed. |
| 18 | KdDebuggerNotPresent | `KernelDebugger` | ✅ | — |
| 18 | KdDebuggerEnabled | `KernelDebugger` | ✅ | Covered by the same `KernelDebugger` entry (checks both `KdDebuggerEnabled` and `KdDebuggerNotPresent`). |
| — | NtSetDebugFilterState | — | `[ ]` | New file `antidebug/api/dbgfilterstate.c`. Call `NtSetDebugFilterState`; plugin hook returns `STATUS_ACCESS_DENIED`. Detect by checking return value. |
| — | ProtectDRX | — | `[ ]` | New file `antidebug/memory/protectdrx.c`. Set a hardware breakpoint via `NtSetContextThread`, trigger it, inspect Dr0–Dr3 in the VEH exception context — they should be preserved (non-zero) if the plugin is NOT protecting them (i.e. absence = detectable). |
| — | HideDRX | — | `[ ]` | New file `antidebug/memory/hidedrx.c`. Set a hardware breakpoint, trigger an exception, read Dr0–Dr3 from the `EXCEPTION_POINTERS` context in a VEH handler. With the plugin active they are zeroed; without they are non-zero. Distinct from `HardwareBreakpoint` which uses `ZwGetContextThread`, not the exception context. |
| — | DbgPrompt | — | `[ ]` | New file `antidebug/memory/dbgprompt.c`. Call `ntdll!DbgPrompt` (get proc address dynamically); without a kernel debugger this is a no-op. With the plugin hook it calls the original and then issues `INT 0x2D`. Detect by catching the resulting exception. Note: `DBGP` (index 35) checks ACPI firmware tables and is unrelated. |
| — | CreateThread | — | `[ ]` | New file `antidebug/api/createthread.c`. Call `CreateThread` with a trivial thread proc; plugin hook returns NULL. Detect by checking for NULL return. |
| 19 | NtSystemDebugControl | `NtSystemDebugControl` | ✅ | — |

### Tab 3 — Anti-Debug 3 (`-p 20`)

| antidbg idx | Plugin protection | antidbg test | Status | Notes |
|-------------|-------------------|--------------|--------|-------|
| 20 | RtlRaiseException | `POPFTrapFlag` | ✅ | `POPFTrapFlag` calls `RaiseException(EXCEPTION_TRAP_FLAG = 0x80000004)` which goes through `RtlRaiseException` internally. The plugin hook intercepts that exact exception code (`EXCEPTION_SINGLE_STEP`) and returns without raising — causing `RaiseException` to return normally and the function to return `true` (detected). |
| N/A | Apply Custom Patches | — | N/A | INI-driven binary patches; no generic antidbg test possible. |

---

## Part 2 — antidbg tests → plugin protections (uncovered)

These checks are in `debuggerChecks[]` (indices 21–36) but have no corresponding plugin
protection. Add a new protection to x64dbgext for each `[ ]` item.

| antidbg idx | antidbg test | Status | x64dbgext file to create |
|-------------|--------------|--------|--------------------------|
| 21 | `DebuggerBreak` | `[ ]` | `Protections/DebuggerBreak.cpp` |
| 22 | `int2D` | `[ ]` | `Protections/Int2D.cpp` |
| 23 | `int3` | `[ ]` | `Protections/Int3.cpp` |
| 24 | `StackSegmentRegister` | `[ ]` | `Protections/StackSegmentRegister.cpp` |
| 25 | `PrefixHop` | `[ ]` | `Protections/PrefixHop.cpp` |
| 26 | `RaiseDbgControl` | `[ ]` | Extend `Protections/RtlRaiseException.cpp`: also intercept `DBG_CONTROL_C` (0x40010005) and `DBG_RIPEXCEPTION` (0x40010007), not just `EXCEPTION_SINGLE_STEP`. |
| 27 | `DuplicatedHandles` | `[ ]` | `Protections/DuplicatedHandles.cpp` — hook `ZwSetInformationObject` for `ObjectHandleFlagInformation` with `ProtectFromClose`, or hook `DuplicateHandle` to allow duplication of protected handles. |
| 28 | `NtSetLdtEntries` | `[ ]` | `Protections/NtSetLdtEntries.cpp` — hook `NtSetLdtEntries`, return `STATUS_SUCCESS` without applying LDT changes that a debugger might rely on. |
| 29 | `VirtualAlloc_MEM_WRITE_WATCH` | `[ ]` | `Protections/WriteWatch.cpp` — hook `VirtualAlloc`; strip `MEM_WRITE_WATCH` from `AllocationType` before passing to original. |
| 30 | `SetHandleInformation` | `[ ]` | `Protections/SetHandleInformation.cpp` — hook `NtSetInformationObject` for `ObjectHandleFlagInformation`; intercept `ProtectFromClose` flag to prevent exception-based detection. |
| 31 | `ReadOwnMemoryStack` | `[ ]` | `Protections/ReadOwnMemory.cpp` — hook `NtReadVirtualMemory`; when source and target process are both the current process and the address is in the stack region, return zeroed data or `STATUS_ACCESS_DENIED`. |
| 32 | `ProcessJob` | `[ ]` | `Protections/ProcessJob.cpp` — hook `NtQueryInformationProcess` for `ProcessBasicInformation` or `IsProcessInJob`; spoof the job membership flag. |
| 33 | `MemoryBreakpoint` | `[ ]` | `Protections/MemoryBreakpoint.cpp` — hook `NtProtectVirtualMemory` or the page-guard exception path in `KiUserExceptionDispatcher` to suppress `STATUS_GUARD_PAGE_VIOLATION` when it originates from a debugger-set guard page. |
| 34 | `PageExceptionBreakpoint` | `[ ]` | `Protections/PageExceptionBreakpoint.cpp` — hook `KiUserExceptionDispatcher`; suppress or reroute page-exception events used as breakpoints. |
| 35 | `DBGP` | `[ ]` | `Protections/DBGP.cpp` — hook `EnumSystemFirmwareTables` and `GetSystemFirmwareTable`; filter out the `DBGP` ACPI table from results. |
| 36 | `LBR` | `[ ]` | `Protections/LBR.cpp` — disable Last Branch Record tracing; write to `MSR_LBR_SELECT` (0x1C8) to clear the LBR enable bit, or intercept the detection mechanism used in `lbr_btf.c`. |
