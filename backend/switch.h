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

inline void backup_gc_ptr() {
    gc_circ_buf = CircuitExecution::circ_exec;
    gc_prot_buf = ProtocolExecution::prot_exec;
}

inline void backup_zk_ptr() {
    zk_circ_buf = CircuitExecution::circ_exec;
    zk_prot_buf = ProtocolExecution::prot_exec;
}

inline void backup_offline_ptr() {
    offline_gc_circ_buf = CircuitExecution::circ_exec;
    offline_gc_prot_buf = ProtocolExecution::prot_exec;
}

template <typename IO>
void setup_protocol(
  IO* io, BoolIO<IO>** ios, int threads, int party, bool ENABLE_OFFLINE_ONLINE = false) {
    init_files();
    setup_zk_bool<BoolIO<IO>>(ios, threads, party);
    backup_zk_ptr();

    if (!ENABLE_OFFLINE_ONLINE) {
        setup_backend<IO>(io, party);
        backup_gc_ptr();
    } else {
        setup_online_backend(io, party);
        backup_gc_ptr();

        setup_offline_backend(io, party);
        backup_offline_ptr();
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

template <typename IO>
void switch_offline_status(int party) {
    if (party == ALICE) {
        OfflinePADOGen<IO>* gen = (OfflinePADOGen<IO>*)offline_gc_prot_buf;
        gen->switch_status();
    }
    else if (party == BOB) {
        OfflinePADOEva<IO>* eva = (OfflinePADOEva<IO>*)offline_gc_prot_buf;
        eva->switch_status();
    }
}

template <typename IO>
void switch_online_status(int party) {
    if (party == ALICE) {
        OnlinePADOGen<IO>* gen = (OnlinePADOGen<IO>*)gc_prot_buf;
        gen->switch_status();
    }
    else if (party == BOB) {
        OnlinePADOEva<IO>* eva = (OnlinePADOEva<IO>*)gc_prot_buf;
        eva->switch_status();
    }
}
inline void finalize_protocol() {
    delete gc_circ_buf;
    delete gc_prot_buf;
    delete zk_circ_buf;
    delete zk_prot_buf;
    if (enable_offline) {
        delete offline_gc_circ_buf;
        // delete offline_gc_prot_buf; // delete in sync_offline_online
    }

    uninit_files();
}

#endif
