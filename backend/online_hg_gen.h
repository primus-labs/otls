#ifndef PRIMUS_Online_HALFGATE_GEN_
#define PRIMUS_Online_HALFGATE_GEN_
#include "emp-tool/emp-tool.h"
#include "backend/bn_utils.h"
using namespace emp;

/* Define the online garbler of half-gate garbler */
template <typename T>
class OnlineHalfGateGen : public CircuitExecution {
   public:
    int64_t gid = 0;
    block delta;
    PRP prp;
    block constant[2];
    vector<block> out_labels;
    OnlineHalfGateGen() {
        block tmp;
        PRG().random_block(&tmp, 1);
        set_delta(tmp);
    }
    void set_delta(const block& _delta) {
        this->delta = _mm_or_si128(makeBlock(0L, 1L), _delta);
        PRG prg(fix_key);
        prg.random_block(constant, 2);
        constant[1] ^= delta;
    }
    block public_label(bool b) override { return b ? constant[1] : constant[0]; }
    block and_gate(const block& a, const block& b) override { return out_labels[gid++]; }
    block xor_gate(const block& a, const block& b) override { return a ^ b; }
    block not_gate(const block& a) override { return a ^ delta; }
    uint64_t num_and() override { return gid; }
};
#endif
