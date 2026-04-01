#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _DEBUG
    void dbg_log(const char* fmt, ...);
#endif

#ifdef __cplusplus
}
#endif
