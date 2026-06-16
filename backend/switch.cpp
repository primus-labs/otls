#include "backend/switch.h"

// FULLPORT: single Backend* phase cache (replacing the old circ+prot dual cache)
#ifndef THREADING
Backend* gc_backend_buf = nullptr;
Backend* zk_backend_buf = nullptr;
Backend* offline_gc_backend_buf = nullptr;
bool enable_offline = false;
#else
__thread Backend* gc_backend_buf = nullptr;
__thread Backend* zk_backend_buf = nullptr;
__thread Backend* offline_gc_backend_buf = nullptr;
__thread bool enable_offline = false;
#endif
