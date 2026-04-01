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

**__2.__** Able to detect debuggers with 36 different checks (indices usable with `-p`):
  - 0: IsBeingDebugged
  - 1: IsRemoteDebuggerPresent
  - 2: DebuggerBreak
  - 3: int2D
  - 4: int3
  - 5: StackSegmentRegister
  - 6: PrefixHop
  - 7: RaiseDbgControl
  - 8: DebugObjectHandle
  - 9: KernelDebugger
  - 10: NtGlobalFlag
  - 11: DebugFlags
  - 12: ProcessHeap_Flags
  - 13: ProcessHeapForce_Flag
  - 14: DuplicatedHandles
  - 15: ParentProcesses
  - 16: NtSetLdtEntries
  - 17: PEB
  - 18: DebugPort
  - 19: HardwareBreakpoint
  - 20: HardwareBreakpoint2
  - 21: VirtualAlloc_MEM_WRITE_WATCH
  - 22: InvalidHandle
  - 23: NtQueryObject
  - 24: OpenProcess
  - 25: SetHandleInformation
  - 26: NtSystemDebugControl
  - 27: ReadOwnMemoryStack
  - 28: ProcessJob
  - 29: POPFTrapFlag
  - 30: MemoryBreakpoint
  - 31: PageExceptionBreakpoint
  - 32: Timing
  - 33: Window
  - 34: DBGP
  - 35: LBR

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