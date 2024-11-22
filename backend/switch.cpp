#include "backend/switch.h"

/* Switch between gc and izk */
#ifndef THREADING
CircuitExecution* gc_circ_buf = nullptr;
ProtocolExecution* gc_prot_buf = nullptr;
CircuitExecution* zk_circ_buf = nullptr;
ProtocolExecution* zk_prot_buf = nullptr;
CircuitExecution* offline_gc_circ_buf = nullptr;
ProtocolExecution* offline_gc_prot_buf = nullptr;
bool enable_offline = false;
#else
__thread CircuitExecution* gc_circ_buf = nullptr;
__thread ProtocolExecution* gc_prot_buf = nullptr;
__thread CircuitExecution* zk_circ_buf = nullptr;
__thread ProtocolExecution* zk_prot_buf = nullptr;
__thread CircuitExecution* offline_gc_circ_buf = nullptr;
__thread ProtocolExecution* offline_gc_prot_buf = nullptr;
__thread bool enable_offline = false;
#endif
