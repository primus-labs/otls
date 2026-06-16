#ifndef PRIMUS_BACKEND_H__
#define PRIMUS_BACKEND_H__
// FULLPORT: upstream emp merges the fork's two singletons CircuitExecution::circ_exec
// + ProtocolExecution::prot_exec into a single `emp::backend`. The original
// backend.h setup_{,offline_,online_}backend each new'd two objects (circ+prot)
// and assigned the two singletons -> now we new a single merged Backend subclass
// (see upstream_gc.h: Primus/Offline/Online {Gen,Eva}Backend) and assign the single `backend`.
#include "emp-tool/emp-tool.h"
#include "backend/upstream_gc.h"
using namespace emp;

// FULLPORT: the old tests/upper layers obtained the GC's IKNP COT via `(PrimusParty<IO>*)prot_exec->ot`.
// After the upstream merge, Gen/Eva are different types (both containing `IKNP* ot`); we expose the
// in-process active cot recorded at setup time in a uniform way, avoiding party-based casts.
// The arithmetic OT in OLE/E2F/VOPE/AEAD all use it.
inline emp::IKNP*& gc_active_cot() { static thread_local emp::IKNP* c = nullptr; return c; }
inline emp::IKNP* gc_cot() { return gc_active_cot(); }

/* Offline backend: garble the whole circuit (input-independent) */
template <typename IO>
inline Backend* setup_offline_backend(IO* io, int party) {
    backend = (party == ALICE) ? (Backend*)new otls_gc::OfflineGenBackend(io)
                               : (Backend*)new otls_gc::OfflineEvaBackend(io);
    return backend;
}

/* Online backend: evaluate with real inputs (aligned with the offline garble) */
template <typename IO>
inline Backend* setup_online_backend(IO* io, int party) {
    if (party == ALICE) {
        auto* b = new otls_gc::OnlineGenBackend(io);
        gc_active_cot() = b->ot; backend = (Backend*)b;
    } else {
        auto* b = new otls_gc::OnlineEvaBackend(io);
        gc_active_cot() = b->ot; backend = (Backend*)b;
    }
    return backend;
}

/* Single-phase backend (no offline/online split, simplest) */
template <typename IO>
inline Backend* setup_backend(IO* io, int party) {
    if (party == ALICE) {
        auto* b = new otls_gc::PrimusGenBackend(io);
        gc_active_cot() = b->ot; backend = (Backend*)b;
    } else {
        auto* b = new otls_gc::PrimusEvaBackend(io);
        gc_active_cot() = b->ot; backend = (Backend*)b;
    }
    return backend;
}

/* Sync offline information into the online backend (seed/delta/out_labels | GC/pub_values) */
using otls_gc::sync_offline_online;

inline void finalize_backend() {
    delete backend;
    backend = nullptr;
}
#endif
