#ifndef __SWITCH_H__
#define __SWITCH_H__
#include "emp-tool/emp-tool.h"
#include "backend/backend.h"
#include "emp-zk/emp-zk.h"

using namespace emp;

static CircuitExecution* gc_circ_buf = nullptr;
static ProtocolExecution* gc_prot_buf = nullptr;
static CircuitExecution* zk_circ_buf = nullptr;
static ProtocolExecution* zk_prot_buf = nullptr;

void backup_gc_ptr() {
    gc_circ_buf = CircuitExecution::circ_exec;
    gc_prot_buf = ProtocolExecution::prot_exec;
}

void backup_zk_ptr() {
    zk_circ_buf = CircuitExecution::circ_exec;
    zk_prot_buf = ProtocolExecution::prot_exec;
}

template <typename IO>
void setup_protocol(IO* io, BoolIO<IO>** ios, int threads, int party) {
    setup_zk_bool<BoolIO<IO>>(ios, threads, party);
    backup_zk_ptr();

    setup_backend<IO>(io, party);
    backup_gc_ptr();
}

void switch_to_zk() {
    gc_circ_buf = CircuitExecution::circ_exec;
    gc_prot_buf = ProtocolExecution::prot_exec;

    CircuitExecution::circ_exec = zk_circ_buf;
    ProtocolExecution::prot_exec = zk_prot_buf;
}

template <typename IO>
void sync_zk_gc() {
    sync_zk_bool<BoolIO<IO>>();
}

void switch_to_gc() {
    zk_circ_buf = CircuitExecution::circ_exec;
    zk_prot_buf = ProtocolExecution::prot_exec;

    CircuitExecution::circ_exec = gc_circ_buf;
    ProtocolExecution::prot_exec = gc_prot_buf;
}

void finalize_protocol() {
    delete gc_circ_buf;
    delete gc_prot_buf;
    delete zk_circ_buf;
    delete zk_prot_buf;
}

// class Switch {
//    public:
//     static CircuitExecution* gc_circ_buf;
//     static ProtocolExecution* gc_prot_buf;
//     static CircuitExecution* zk_circ_buf;
//     static ProtocolExecution* zk_prot_buf;

//     static void backup_gc() {
//         gc_circ_buf = CircuitExecution::circ_exec;
//         gc_prot_buf = ProtocolExecution::prot_exec;
//     }

//     static void switch_from_gc_to_zk() {
//         gc_circ_buf = CircuitExecution::circ_exec;
//         gc_prot_buf = ProtocolExecution::prot_exec;

//         CircuitExecution::circ_exec = zk_circ_buf;
//         ProtocolExecution::prot_exec = zk_prot_buf;
//     }

//     static void switch_from_zk_to_gc() {
//         zk_circ_buf = CircuitExecution::circ_exec;
//         zk_prot_buf = ProtocolExecution::prot_exec;

//         CircuitExecution::circ_exec = gc_circ_buf;
//         ProtocolExecution::prot_exec = gc_prot_buf;
//     }
// };
#endif