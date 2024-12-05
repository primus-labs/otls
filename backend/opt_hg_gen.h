#ifndef PRIMUS_OPT_HALFGATE_GEN_
#define PRIMUS_OPT_HALFGATE_GEN_
#include "emp-tool/emp-tool.h"
#include "backend/bn_utils.h"
using namespace emp;

/* Optimized half-gate garbler process */
template <typename T>
class OptHalfGateGen : public CircuitExecution {
   public:
    int64_t gid = 0;
    block delta;
    PRP prp;
    block seed;
    T* io;
    block fix_point;
    OptHalfGateGen(T* io) : io(io) {
        PRG prg(fix_key);
        prg.random_block(&fix_point, 1);
        PRG tmp;
        tmp.random_block(&seed, 1);
        block a;
        tmp.random_block(&a, 1);
        set_delta(a);
    }
    bool is_public(const block& b, int party) { return isZero(&b) or isOne(&b); }
    void set_delta(const block& _delta) {
        this->delta = _mm_or_si128(makeBlock(0L, 1L), _delta); //make_delta(_delta);
    }
    block public_label(bool b) override { return b ? all_one_block : zero_block; }
    bool isDelta(const block& b) {
        __m128i neq = b ^ delta;
        return _mm_testz_si128(neq, neq);
    }

    block and_gate(const block& a, const block& b) override {
        block out[2], table[2];
        if (isZero(&a) or isZero(&b)) {
            return zero_block;
        } else if (isOne(&a)) {
            return b;
        } else if (isOne(&b)) {
            return a;
        } else {
            garble_gate_garble_halfgates(a, a ^ delta, b, b ^ delta, &out[0], &out[1], delta,
                                         table, gid++, &prp.aes);
            io->send_block(table, 2);
            return out[0];
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
            if (isDelta(res))
                return fix_point ^ delta;
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
            return a ^ delta;
    }
    uint64_t num_and() override { return gid; }
};
#endif
