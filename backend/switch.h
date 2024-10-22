#ifndef __SWITCH_H__
#define __SWITCH_H__
#include "emp-tool/emp-tool.h"
#include "backend/backend.h"
#include "emp-zk/emp-zk.h"
#include "cipher/utils.h"

using namespace emp;

#ifndef THREADING
extern CircuitExecution* gc_circ_buf;
extern ProtocolExecution* gc_prot_buf;
extern CircuitExecution* zk_circ_buf;
extern ProtocolExecution* zk_prot_buf;
extern CircuitExecution* offline_gc_circ_buf;
extern ProtocolExecution* offline_gc_prot_buf;
extern bool enable_offline;
#else
extern __thread CircuitExecution* gc_circ_buf;
extern __thread ProtocolExecution* gc_prot_buf;
extern __thread CircuitExecution* zk_circ_buf;
extern __thread ProtocolExecution* zk_prot_buf;
extern __thread CircuitExecution* offline_gc_circ_buf;
extern __thread ProtocolExecution* offline_gc_prot_buf;
extern __thread bool enable_offline;
#endif

inline void reset_prot_ptr() {
    CircuitExecution::circ_exec = nullptr;
    ProtocolExecution::prot_exec = nullptr;
}

inline void delete_prot_ptr() {
    if (CircuitExecution::circ_exec != nullptr) {
        delete CircuitExecution::circ_exec;
    }
    if (ProtocolExecution::prot_exec != nullptr) {
        delete ProtocolExecution::prot_exec;
    }
    reset_prot_ptr();
}

inline void backup_gc_ptr() {
    gc_circ_buf = CircuitExecution::circ_exec;
    gc_prot_buf = ProtocolExecution::prot_exec;
}

inline void reset_gc_ptr() {
    gc_circ_buf = nullptr;
    gc_prot_buf = nullptr;
}

inline void backup_zk_ptr() {
    zk_circ_buf = CircuitExecution::circ_exec;
    zk_prot_buf = ProtocolExecution::prot_exec;
}

inline void reset_zk_ptr() {
    zk_circ_buf = nullptr;
    zk_prot_buf = nullptr;
}

inline void backup_offline_ptr() {
    offline_gc_circ_buf = CircuitExecution::circ_exec;
    offline_gc_prot_buf = ProtocolExecution::prot_exec;
}

inline void reset_offline_ptr() {
    offline_gc_circ_buf = nullptr;
    offline_gc_prot_buf = nullptr;
}

inline void safe_setup_protocol(
    std::function<void()> setupFn,
    std::function<void()> backupFn,
    std::function<void()> resetFn
) {
    FunctionWrapperV3(
        [&setupFn, &backupFn]() {
            reset_prot_ptr();
            setupFn();
            backupFn();
        },
        [&resetFn](const char* e) {
            delete_prot_ptr();
            resetFn();
            throw std::runtime_error(e);
        }
    )();

    CHECK_INITIALIZE_EXCEPTION();
}

template <typename IO>
void setup_protocol(
  IO* io, BoolIO<IO>** ios, int threads, int party, bool ENABLE_OFFLINE_ONLINE = false) {
    init_files();
    safe_setup_protocol(
        [ios, threads, party]() {
            setup_zk_bool(ios, threads, party);
        },
        backup_zk_ptr,
        reset_zk_ptr
    );

    if (!ENABLE_OFFLINE_ONLINE) {
        safe_setup_protocol(
            [io, party]() {
                setup_backend(io, party);
            },
            backup_gc_ptr,
            reset_gc_ptr
        );
    } else {
        safe_setup_protocol(
            [io, party]() {
                setup_online_backend(io, party);
            },
            backup_gc_ptr,
            reset_gc_ptr
        );

        safe_setup_protocol(
            [io, party]() {
                setup_offline_backend(io, party);
            },
            backup_offline_ptr,
            reset_offline_ptr
        );
    }
    enable_offline = ENABLE_OFFLINE_ONLINE;
}

inline void switch_to_zk() {
    CircuitExecution::circ_exec = zk_circ_buf;
    ProtocolExecution::prot_exec = zk_prot_buf;
}

template <typename IO>
void sync_zk_gc() {
    sync_zk_bool<BoolIO<IO>>();
}

inline void switch_to_gc() {
    CircuitExecution::circ_exec = gc_circ_buf;
    ProtocolExecution::prot_exec = gc_prot_buf;
}

template <typename IO>
void switch_to_online(int party) {
    auto offline = (OfflinePADOParty*)offline_gc_prot_buf;
    auto online = (PADOParty<IO>*)gc_prot_buf;

    sync_offline_online(offline, online, party);
    switch_to_gc();
}

inline void finalize_protocol() {
    delete gc_circ_buf;
    delete gc_prot_buf;
    delete zk_circ_buf;
    delete zk_prot_buf;
    if (enable_offline) {
        delete offline_gc_circ_buf;
        delete offline_gc_prot_buf; // delete in sync_offline_online
    }

    uninit_files();
}

#endif
