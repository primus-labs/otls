#ifndef PADO_Online_HALFGATE_GEN_
#define PADO_Online_HALFGATE_GEN_
#include "emp-tool/emp-tool.h"
#include "backend/bn_utils.h"
using namespace emp;

template <typename T>
class OnlineHalfGateGen : public CircuitExecution {
   public:
    int64_t gid = 0;
    int64_t gid2 = 0;
    int64_t* p_gid = nullptr;
    block delta;
    PRP prp;
    block constant[2];
    vector<block> out_labels;
    vector<block> out_labels2;
    vector<block>* p_out_labels = nullptr;
    bool server_finish = false;
    OnlineHalfGateGen() {
        block tmp;
        PRG().random_block(&tmp, 1);
        set_delta(tmp);

        p_gid = &gid;
        p_out_labels = &out_labels;
    }
    void set_delta(const block& _delta) {
        this->delta = _mm_or_si128(makeBlock(0L, 1L), _delta);
        PRG prg(fix_key);
        prg.random_block(constant, 2);
        constant[1] ^= delta;
    }
    block public_label(bool b) override { return b ? constant[1] : constant[0]; }
    block and_gate(const block& a, const block& b) override {
        return (*p_out_labels)[(*p_gid)++];
        // block out[2], table[2];
        // garble_gate_garble_halfgates(a, a ^ delta, b, b ^ delta, &out[0], &out[1], delta,
        //                              table, gid++, &prp.aes);
        // return out[0];
    }

    void switch_status() {
        server_finish = !server_finish;
        if (server_finish) {
            p_gid = &gid2;
            p_out_labels = &out_labels2;
        }
        else {
            p_gid = &gid;
            p_out_labels = &out_labels;
        }
    }
    block xor_gate(const block& a, const block& b) override { return a ^ b; }
    block not_gate(const block& a) override { return a ^ delta; }
    uint64_t num_and() override { return *p_gid; }
};
#endif
