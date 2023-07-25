#ifndef PADO_Online_HALFGATE_EVA_
#define PADO_Online_HALFGATE_EVA_
#include "emp-tool/emp-tool.h"
#include "backend/bn_utils.h"
using namespace emp;
template <typename T>
class OnlineHalfGateEva : public CircuitExecution {
   public:
    int64_t gid = 0;
    int64_t gid2 = 0;
    int64_t* p_gid = nullptr;
    PRP prp;
    block constant[2];
    vector<block> GC;
    vector<block> GC2;
    vector<block>* p_GC = nullptr;
    bool server_finish = false;
    OnlineHalfGateEva() {
        PRG prg(fix_key);
        prg.random_block(constant, 2);

        p_gid = &gid;
        p_GC = &GC;
    }
    block public_label(bool b) override { return b ? constant[1] : constant[0]; }
    block and_gate(const block& a, const block& b) override {
        block out, table[2];
        table[0] = (*p_GC)[(*p_gid) * 2];
        table[1] = (*p_GC)[(*p_gid) * 2 + 1];
        garble_gate_eval_halfgates(a, b, &out, table, (*p_gid)++, &prp.aes);
        return out;
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
    block xor_gate(const block& a, const block& b) override { return a ^ b; }
    block not_gate(const block& a) override { return a; }
    uint64_t num_and() override { return *p_gid; }
};
#endif // HALFGATE_EVA_H__
