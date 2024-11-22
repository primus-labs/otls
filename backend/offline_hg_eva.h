#ifndef _OFFLINE_HG_EVA_
#define _OFFLINE_HG_EVA_
#include "emp-tool/emp-tool.h"
#include "backend/bn_utils.h"
using namespace emp;

/* Define the offline evalutor of half-gate evaluator */
template <typename IO>
class OfflineHalfGateEva : public CircuitExecution {
   public:
    IO* io;
    int64_t gid = 0;
    vector<block> GC;
    OfflineHalfGateEva(IO* io) : io(io) {}
    block public_label(bool b) override { return zero_block; }

    block and_gate(const block& a, const block& b) override {
        block table[2];
        io->recv_block(table, 2);
        GC.push_back(table[0]);
        GC.push_back(table[1]);
        gid++;
        return zero_block;
    }
    block xor_gate(const block& a, const block& b) override { return zero_block; }
    block not_gate(const block& a) override { return zero_block; }
    uint64_t num_and() override { return gid; }
};

#endif