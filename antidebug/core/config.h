#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _DEBUG
    extern bool g_dryRun;
#else
    #define g_dryRun false
#endif

#ifdef __cplusplus
}
#endif
