#ifndef _OFFLINE_HG_EVA_
#define _OFFLINE_HG_EVA_
#include "emp-tool/emp-tool.h"
#include "backend/bn_utils.h"
using namespace emp;

template <typename IO>
class OfflineHalfGateEva : public CircuitExecution {
   public:
    IO* io;
    int64_t gid = 0;
    int64_t gid2 = 0;
    int64_t* p_gid = nullptr;
    vector<block> GC;
    vector<block> GC2;
    vector<block>* p_GC = nullptr;
    bool server_finish = false;
    OfflineHalfGateEva(IO* io) : io(io) {
        p_gid = &gid;
        p_GC = &GC;
    }
    block public_label(bool b) override { return zero_block; }

    block and_gate(const block& a, const block& b) override {
        block table[2];
        io->recv_block(table, 2);
        p_GC->push_back(table[0]);
        p_GC->push_back(table[1]);
        (*p_gid)++;
        return zero_block;
    }
    void switch_status() {
        server_finish = !server_finish;
        if (server_finish) {
            p_gid = &gid2;
            p_GC = &GC2;
        }
        else {
            p_gid = &gid;
            p_GC = &GC;
        }
    }
    block xor_gate(const block& a, const block& b) override { return zero_block; }
    block not_gate(const block& a) override { return zero_block; }
    uint64_t num_and() override { return *p_gid; }
};

#endif
