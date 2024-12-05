#ifndef PRIMUS_OPT_HALFGATE_EVA_
#define PRIMUS_OPT_HALFGATE_EVA_
#include "emp-tool/emp-tool.h"
#include "backend/bn_utils.h"
using namespace emp;

/* Optimized half-gate evaluator process */
template <typename T>
class OptHalfGateEva : public CircuitExecution {
   public:
    int64_t gid = 0;
    PRP prp;
    T* io;
    block fix_point;
    OptHalfGateEva(T* io) : io(io) {
        PRG prg(fix_key);
        prg.random_block(&fix_point, 1);
    }
    bool is_public(const block& b, int party) { return isZero(&b) or isOne(&b); }
    block public_label(bool b) override { return b ? all_one_block : zero_block; }
    block and_gate(const block& a, const block& b) override {
        block out, table[2];
        if (isZero(&a) or isOne(&a) or isZero(&b) or isOne(&b)) {
            return _mm_and_si128(a, b);
        } else {
            io->recv_block(table, 2);
            garble_gate_eval_halfgates(a, b, &out, table, gid++, &prp.aes);
            return out;
        }
    }
    block xor_gate(const block& a, const block& b) override {
        if (isOne(&a))
            return not_gate(b);
        else if (isOne(&b))
            return not_gate(a);
        else if (isZero(&a))
            return b;
        else if (isZero(&b))
            return a;
        else {
            block res = a ^ b;
            if (isZero(&res))
                return fix_point;
            else
                return res;
        }
    }
    block not_gate(const block& a) override {
        if (isZero(&a))
            return all_one_block;
        else if (isOne(&a))
            return zero_block;
        else
            return a;
    }
    uint64_t num_and() override { return gid; }
};
#endif // HALFGATE_EVA_H__
