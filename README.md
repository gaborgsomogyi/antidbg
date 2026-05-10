# AntiDebugging Library for C/C++

antidbg is a PoC of a x64 user-mode anti-debugging library for Windows, designed to protect any software from debugging.

The library is:
- Very easy to use (only one function call required)
- Directly syscalled, which means that most antidebugging checks can't be hooked from user-space
- Optimized for officially supported Windows versions and AMD64 only.
- Designed for speed and minimal memory usage
- Requires Visual Studio (MSVC) on Windows x64

## Features
**__1.__** Able to bypass thread creation hooking and hide user-land threads from debuggers.

**__2.__** Able to detect debuggers with 37 different checks (indices usable with `-p`):
  - Tab 1 (0–13):
    - 0: IsBeingDebugged
    - 1: PEB
    - 2: NtGlobalFlag
    - 3: ProcessHeap_Flags
    - 4: ProcessHeapForce_Flag
    - 5: IsRemoteDebuggerPresent
    - 6: DebugPort
    - 7: OutputDebugString
    - 8: InvalidHandle
    - 9: OpenProcess
    - 10: DebugFlags
    - 11: DebugObjectHandle
    - 12: NtQueryObject
    - 13: Window
  - Tab 2 (14–19):
    - 14: ParentProcesses
    - 15: Timing
    - 16: HardwareBreakpoint
    - 17: HardwareBreakpoint2
    - 18: KernelDebugger
    - 19: NtSystemDebugControl
  - Tab 3 (20):
    - 20: POPFTrapFlag
  - Uncovered / no plugin protection yet (21–36):
    - 21: DebuggerBreak
    - 22: int2D
    - 23: int3
    - 24: StackSegmentRegister
    - 25: PrefixHop
    - 26: RaiseDbgControl
    - 27: DuplicatedHandles
    - 28: NtSetLdtEntries
    - 29: VirtualAlloc_MEM_WRITE_WATCH
    - 30: SetHandleInformation
    - 31: ReadOwnMemoryStack
    - 32: ProcessJob
    - 33: MemoryBreakpoint
    - 34: PageExceptionBreakpoint
    - 35: DBGP
    - 36: LBR

**__3.__** Able to detect unusual memory writes by other analysis tools like sandboxes.

**__4.__** Monitorization of antidebugging thread priority and self-integrity.

**__5.__** Ability to randomize the time when protection routines will run.

**__6.__** Prevention, not only detection, of debuggers from being attached.

**__7.__** Protects the software from memory injections done by debuggers.

**__8.__** Continuous tracking of virtual memory with hardware-accelerated hashing to detect software breakpoints and inline hooks.

**__9.__** Runs a special routine before your program's entrypoint even starts to detect if a debugger is attached.

**__10.__** Automatic handling of any exception in your software without interfering with other program's handlers.

## Detection Modes
> 1. Guard mode:A thread will start running in your program and continuously monitor for attached debuggers. If a debugger is detected at any time, the program will forcefully exit while preventing other programs from stopping the crash.

`Example Usage:`
```c
#include "adbg.h"

int main() {
    StartDebugProtection();

    return 0;
}
```

> 2. Single-run mode: A function that you can call at any time to detect if debuggers are attached to your process.

`Example Usage:`
```c
#include "adbg.h"

int main() {
    if (isProgramBeingDebugged()) {
        printf("Debugger detected.\n");
    }
    else {
        printf("No debugger was detected.\n");
    }

    return 0;
}
```

# Notes
The library requires Visual Studio (MSVC) on Windows x64. Other compilers and build systems are not supported.

# Legal
I am not responsible nor liable for any damage you cause through any malicious usage of this project.

License: GNU GENERAL PUBLIC LICENSE, Version 2