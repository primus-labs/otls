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
    // delete offline;
}

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

// inline OfflinePADOGen* setup_offline_backend(int party) {
//     assert(party == ALICE);
//     OfflineHalfGateGen* t = new OfflineHalfGateGen();
//     CircuitExecution::circ_exec = t;
//     ProtocolExecution::prot_exec = new OfflinePADOGen(t);
//     return (OfflinePADOGen*)ProtocolExecution::prot_exec;
// }

inline void finalize_backend() {
    delete CircuitExecution::circ_exec;
    delete ProtocolExecution::prot_exec;
}

/*template<typename IO>
inline PADOParty<IO>* swap_role(int party) {
	PADOParty<IO>* p = (PADOParty<IO>*)ProtocolExecution::prot_exec;
	if(p->cur_party == party) {
		error("party misaligned!");
	}
	IKNP<IO> * old_ot = p->ot;
	IKNP<IO> * new_ot = new IKNP<IO>(old_ot->io, true);
	block k0[128], k1[128];
	bool s[128];
	if(party == ALICE) {
		auto t = new HalfGateGen<IO>(p->io);
		block_to_bool(s, t->delta);
		old_ot->recv_rot(k0, s, 128);
		new_ot->setup_send(s, k0);

		auto pro = new PADOGen<IO>(p->io, t, new_ot);
		finalize_backend();
		CircuitExecution::circ_exec = t;
		ProtocolExecution::prot_exec = pro;
	} else {
		auto t = new HalfGateEva<IO>(p->io);

		old_ot->send_rot(k0, k1, 128);
		new_ot->setup_recv(k0, k1);
		auto pro = new PADOEva<IO>(p->io, t, new_ot);
		finalize_backend();
		CircuitExecution::circ_exec = t;
		ProtocolExecution::prot_exec = pro;
	}
	return (PADOParty<IO>*)ProtocolExecution::prot_exec;
}*/
#endif
