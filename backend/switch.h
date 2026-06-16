#ifndef __SWITCH_H__
#define __SWITCH_H__
// FULLPORT: GC/ZK/offline phase switching under the upstream single-`emp::backend` model.
// Old model: two singletons CircuitExecution::circ_exec + ProtocolExecution::prot_exec, two pointers cached per phase.
// New model: a single `backend`, one Backend* cached per phase, switch = write the corresponding cache back into `backend`.
#include "emp-tool/emp-tool.h"
#include "backend/backend.h"
#include "emp-zk/emp-zk.h"
#include "cipher/utils.h"

using namespace emp;

// Per-phase Backend* cache (single pointer, replacing the old circ+prot dual cache)
#ifndef THREADING
extern Backend* gc_backend_buf;
extern Backend* zk_backend_buf;
extern Backend* offline_gc_backend_buf;
extern bool enable_offline;
#else
extern __thread Backend* gc_backend_buf;
extern __thread Backend* zk_backend_buf;
extern __thread Backend* offline_gc_backend_buf;
extern __thread bool enable_offline;
#endif

// setup_* has already written the newly created backend into `backend`; here we store it into the corresponding phase cache.
inline void backup_gc()      { gc_backend_buf = backend; }
inline void backup_zk()      { zk_backend_buf = backend; }
inline void backup_offline() { offline_gc_backend_buf = backend; }

inline void switch_to_zk() { backend = zk_backend_buf; }
inline void switch_to_gc() { backend = gc_backend_buf; }

// The upstream sync_zk_bool() is non-template (only flushes the ZK io); the template signature is kept for source compatibility with handshake/aead.
template <typename IO>
void sync_zk_gc() { sync_zk_bool(); }

template <typename IO>
void switch_to_online(int party) {
    sync_offline_online(offline_gc_backend_buf, gc_backend_buf, party);
    switch_to_gc();
}

// Single ZK BoolIO + single GC io (first version is single-threaded; the old multi-IO array + threads have been removed).
template <typename IO>
void setup_protocol(IO* io, BoolIO* zk_io, int party, bool ENABLE_OFFLINE_ONLINE = false) {
    init_files();
    try {
        setup_zk_bool(zk_io, party);   // upstream: backend = ZKBool{Prover,Verifier}
        backup_zk();
        if (!ENABLE_OFFLINE_ONLINE) {
            setup_backend(io, party);
            backup_gc();
        } else {
            setup_online_backend(io, party);
            backup_gc();
            setup_offline_backend(io, party);
            backup_offline();
        }
    } catch (std::exception& e) {
        // clean up already-created backends, to prevent leaks + leftover state on the anti-cheat fallback path
        if (gc_backend_buf) { delete gc_backend_buf; gc_backend_buf = nullptr; }
        if (zk_backend_buf) { delete zk_backend_buf; zk_backend_buf = nullptr; }
        if (offline_gc_backend_buf) { delete offline_gc_backend_buf; offline_gc_backend_buf = nullptr; }
        backend = nullptr;
        throw std::runtime_error(e.what());
    }
    enable_offline = ENABLE_OFFLINE_ONLINE;
}

inline void finalize_protocol() {
    delete gc_backend_buf; gc_backend_buf = nullptr;
    // FULLPORT FIX (fidelity audit): run the ZK closing SOUNDNESS checks — the
    // QuickSilver leftover AND-batch check + f2k batch check + auth_hash output-MAC
    // digest compare (error() on a cheating prover) + ferret final chi-fold — by
    // finalizing the OWNED ZK session. These live in the engine dtor (~ZKBoolProver/
    // ~ZKBoolVerifier), reached only via g_zk_owned->finalize(). Previously this fn
    // deleted ONLY the ZKBackend adapter (zk_backend_buf), leaking the real engine
    // un-finalized so the ZK proof's closing check NEVER RAN on the GC+ZK (mpctls)
    // path. Mirrors the fork's `delete zk_prot_buf` (which IS the ZKVerifier).
    if (g_zk_owned) { g_zk_owned->finalize(); delete g_zk_owned; g_zk_owned = nullptr; g_zk_engine = nullptr; }
    delete zk_backend_buf; zk_backend_buf = nullptr;   // adapter only (owns nothing else)
    if (enable_offline) { delete offline_gc_backend_buf; offline_gc_backend_buf = nullptr; }
    backend = nullptr;
    uninit_files();
}

#endif
