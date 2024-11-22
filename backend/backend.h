#ifndef PADO_BACKEND_H__
#define PADO_BACKEND_H__
#include "emp-tool/emp-tool.h"
#include "backend/opt_hg_gen.h"
#include "backend/opt_hg_eva.h"
#include "backend/offline_hg_gen.h"
#include "backend/online_hg_gen.h"
#include "backend/online_hg_eva.h"
#include "backend/pado_gen.h"
#include "backend/pado_eva.h"
#include "backend/offline_pado_gen.h"
#include "backend/offline_pado_eva.h"
#include "backend/online_pado_gen.h"
#include "backend/online_pado_eva.h"
#include "backend/offline_pado_party.h"
using namespace emp;

/* Initialize the offline backend of two parties */
template <typename IO>
inline OfflinePADOParty* setup_offline_backend(IO* io, int party) {
    if (party == ALICE) {
        OfflineHalfGateGen<IO>* t = new OfflineHalfGateGen<IO>(io);
        CircuitExecution::circ_exec = t;
        ProtocolExecution::prot_exec = new OfflinePADOGen<IO>(io, t);
    } else {
        OfflineHalfGateEva<IO>* t = new OfflineHalfGateEva<IO>(io);
        CircuitExecution::circ_exec = t;
        ProtocolExecution::prot_exec = new OfflinePADOEva<IO>(io, t);
    }
    return (OfflinePADOParty*)ProtocolExecution::prot_exec;
}

/* Sync the offline information with online backend */
template <typename IO>
inline void sync_offline_online(OfflinePADOParty* offline, PADOParty<IO>* online, int party) {
    if (party == ALICE) {
        OfflinePADOGen<IO>* off_gen = (OfflinePADOGen<IO>*)offline;
        OnlinePADOGen<IO>* on_gen = (OnlinePADOGen<IO>*)online;
        on_gen->set_seed(off_gen->seed);
        on_gen->gc->set_delta(off_gen->gc->delta);
        on_gen->gc->out_labels = off_gen->gc->out_labels;
    } else {
        OfflinePADOEva<IO>* off_eva = (OfflinePADOEva<IO>*)offline;
        OnlinePADOEva<IO>* on_eva = (OnlinePADOEva<IO>*)online;
        on_eva->gc->GC = off_eva->gc->GC;
        on_eva->pub_values = off_eva->pub_values;
    }
}

/* Initialize the online backend */
template <typename IO>
inline PADOParty<IO>* setup_online_backend(IO* io, int party) {
    if (party == ALICE) {
        OnlineHalfGateGen<IO>* t = new OnlineHalfGateGen<IO>();
        CircuitExecution::circ_exec = t;
        ProtocolExecution::prot_exec = new OnlinePADOGen<IO>(io, t);
    } else {
        OnlineHalfGateEva<IO>* t = new OnlineHalfGateEva<IO>();
        CircuitExecution::circ_exec = t;
        ProtocolExecution::prot_exec = new OnlinePADOEva<IO>(io, t);
    }
    return (PADOParty<IO>*)ProtocolExecution::prot_exec;
}

/* Initialize the protocol backend, only online phase enabled, no offline */
template <typename IO>
inline PADOParty<IO>* setup_backend(IO* io, int party) {
    if (party == ALICE) {
        OptHalfGateGen<IO>* t = new OptHalfGateGen<IO>(io);
        CircuitExecution::circ_exec = t;
        ProtocolExecution::prot_exec = new PADOGen<IO>(io, t);
    } else {
        OptHalfGateEva<IO>* t = new OptHalfGateEva<IO>(io);
        CircuitExecution::circ_exec = t;
        ProtocolExecution::prot_exec = new PADOEva<IO>(io, t);
    }
    return (PADOParty<IO>*)ProtocolExecution::prot_exec;
}

/* Finalize the backend and delete all the pointers */
inline void finalize_backend() {
    delete CircuitExecution::circ_exec;
    delete ProtocolExecution::prot_exec;
}
#endif
