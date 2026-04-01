#include "log.h"

#ifdef _DEBUG

#include <windows.h>
#include <stdio.h>
#include <stdarg.h>

void dbg_log(const char* fmt, ...) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    printf("[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

#endif
