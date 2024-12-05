#ifndef PRIMUS_Online_HALFGATE_EVA_
#define PRIMUS_Online_HALFGATE_EVA_
#include "emp-tool/emp-tool.h"
#include "backend/bn_utils.h"
using namespace emp;

/* Define the online evalutor of half-gate evaluator */
template <typename T>
class OnlineHalfGateEva : public CircuitExecution {
   public:
    int64_t gid = 0;
    PRP prp;
    block constant[2];
    vector<block> GC;
    OnlineHalfGateEva() {
        PRG prg(fix_key);
        prg.random_block(constant, 2);
    }
    block public_label(bool b) override { return b ? constant[1] : constant[0]; }
    block and_gate(const block& a, const block& b) override {
        block out, table[2];
        table[0] = GC[gid * 2];
        table[1] = GC[gid * 2 + 1];
        garble_gate_eval_halfgates(a, b, &out, table, gid++, &prp.aes);
        return out;
    }
    block xor_gate(const block& a, const block& b) override { return a ^ b; }
    block not_gate(const block& a) override { return a; }
    uint64_t num_and() override { return gid; }
};
#endif // HALFGATE_EVA_H__
