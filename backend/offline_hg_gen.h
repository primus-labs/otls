#ifndef PRIMUS_Offline_HALFGATE_GEN_
#define PRIMUS_Offline_HALFGATE_GEN_
#include "emp-tool/emp-tool.h"
#include "backend/bn_utils.h"
using namespace emp;

/* Define the offline garbler of half-gate garbler */
template <typename IO>
class OfflineHalfGateGen : public CircuitExecution {
   public:
    IO* io;
    int64_t gid = 0;
    block delta;
    PRP prp;
    block constant[2];
    vector<block> out_labels;
    OfflineHalfGateGen(IO* io) : io(io) {
        block tmp;
        PRG().random_block(&tmp, 1);
        set_delta(tmp);
    }

    inline void set_delta(const block& _delta) {
        this->delta = _mm_or_si128(makeBlock(0L, 1L), _delta);
        PRG prg(fix_key);
        prg.random_block(constant, 2);
        constant[1] ^= delta;
    }

    block public_label(bool b) override { return b ? constant[1] : constant[0]; }

    block and_gate(const block& a, const block& b) override {
        block out[2], table[2];
        garble_gate_garble_halfgates(a, a ^ delta, b, b ^ delta, &out[0], &out[1], delta,
                                     table, gid++, &prp.aes);
        io->send_block(table, 2);
        out_labels.push_back(out[0]);
        return out[0];
    }

    block xor_gate(const block& a, const block& b) override { return a ^ b; }
    block not_gate(const block& a) override { return a ^ delta; }
    uint64_t num_and() override { return gid; }
};
#endif
