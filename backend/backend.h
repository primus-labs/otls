#ifndef PRIMUS_BACKEND_H__
#define PRIMUS_BACKEND_H__
#include "emp-tool/emp-tool.h"
#include "backend/opt_hg_gen.h"
#include "backend/opt_hg_eva.h"
#include "backend/offline_hg_gen.h"
#include "backend/online_hg_gen.h"
#include "backend/online_hg_eva.h"
#include "backend/primus_gen.h"
#include "backend/primus_eva.h"
#include "backend/offline_primus_gen.h"
#include "backend/offline_primus_eva.h"
#include "backend/online_primus_gen.h"
#include "backend/online_primus_eva.h"
#include "backend/offline_primus_party.h"
using namespace emp;

/* Initialize the offline backend of two parties */
template <typename IO>
inline OfflinePrimusParty* setup_offline_backend(IO* io, int party) {
    if (party == ALICE) {
        OfflineHalfGateGen<IO>* t = new OfflineHalfGateGen<IO>(io);
        CircuitExecution::circ_exec = t;
        ProtocolExecution::prot_exec = new OfflinePrimusGen<IO>(io, t);
    } else {
        OfflineHalfGateEva<IO>* t = new OfflineHalfGateEva<IO>(io);
        CircuitExecution::circ_exec = t;
        ProtocolExecution::prot_exec = new OfflinePrimusEva<IO>(io, t);
    }
    return (OfflinePrimusParty*)ProtocolExecution::prot_exec;
}

/* Sync the offline information with online backend */
template <typename IO>
inline void sync_offline_online(OfflinePrimusParty* offline, PrimusParty<IO>* online, int party) {
    if (party == ALICE) {
        OfflinePrimusGen<IO>* off_gen = (OfflinePrimusGen<IO>*)offline;
        OnlinePrimusGen<IO>* on_gen = (OnlinePrimusGen<IO>*)online;
        on_gen->set_seed(off_gen->seed);
        on_gen->gc->set_delta(off_gen->gc->delta);
        on_gen->gc->out_labels = off_gen->gc->out_labels;
    } else {
        OfflinePrimusEva<IO>* off_eva = (OfflinePrimusEva<IO>*)offline;
        OnlinePrimusEva<IO>* on_eva = (OnlinePrimusEva<IO>*)online;
        on_eva->gc->GC = off_eva->gc->GC;
        on_eva->pub_values = off_eva->pub_values;
    }
}

/* Initialize the online backend */
template <typename IO>
inline PrimusParty<IO>* setup_online_backend(IO* io, int party) {
    if (party == ALICE) {
        OnlineHalfGateGen<IO>* t = new OnlineHalfGateGen<IO>();
        CircuitExecution::circ_exec = t;
        ProtocolExecution::prot_exec = new OnlinePrimusGen<IO>(io, t);
    } else {
        OnlineHalfGateEva<IO>* t = new OnlineHalfGateEva<IO>();
        CircuitExecution::circ_exec = t;
        ProtocolExecution::prot_exec = new OnlinePrimusEva<IO>(io, t);
    }
    return (PrimusParty<IO>*)ProtocolExecution::prot_exec;
}

/* Initialize the protocol backend, only online phase enabled, no offline */
template <typename IO>
inline PrimusParty<IO>* setup_backend(IO* io, int party) {
    if (party == ALICE) {
        OptHalfGateGen<IO>* t = new OptHalfGateGen<IO>(io);
        CircuitExecution::circ_exec = t;
        ProtocolExecution::prot_exec = new PrimusGen<IO>(io, t);
    } else {
        OptHalfGateEva<IO>* t = new OptHalfGateEva<IO>(io);
        CircuitExecution::circ_exec = t;
        ProtocolExecution::prot_exec = new PrimusEva<IO>(io, t);
    }
    return (PrimusParty<IO>*)ProtocolExecution::prot_exec;
}

/* Finalize the backend and delete all the pointers */
inline void finalize_backend() {
    delete CircuitExecution::circ_exec;
    delete ProtocolExecution::prot_exec;
}
#endif
