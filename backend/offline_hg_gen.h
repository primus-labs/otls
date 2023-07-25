#ifndef PADO_Offline_HALFGATE_GEN_
#define PADO_Offline_HALFGATE_GEN_
#include "emp-tool/emp-tool.h"
#include "backend/bn_utils.h"
using namespace emp;

template <typename IO>
class OfflineHalfGateGen : public CircuitExecution {
   public:
    IO* io;
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
    OfflineHalfGateGen(IO* io) : io(io) {
        block tmp;
        PRG().random_block(&tmp, 1);
        set_delta(tmp);
        p_gid = &gid;
        p_out_labels = &out_labels;
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
                                     table, (*p_gid)++, &prp.aes);
        io->send_block(table, 2);
        p_out_labels->push_back(out[0]);
        return out[0];
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

// class OfflineHalfGateGen : public CircuitExecution {
//    public:
//     int64_t gid = 0;
//     block delta;
//     PRP prp;
//     block constant[2];
//     vector<block> GC;
//     OfflineHalfGateGen() {
//         block tmp;
//         PRG().random_block(&tmp, 1);
//         set_delta(tmp);
//     }
//     void set_delta(const block& _delta) {
//         this->delta = _mm_or_si128(makeBlock(0L, 1L), _delta);
//         PRG prg(fix_key);
//         prg.random_block(constant, 2);
//         constant[1] ^= delta;
//     }
//     block public_label(bool b) override { return b ? constant[1] : constant[0]; }
//     block and_gate(const block& a, const block& b) override {
//         block out[2], table[2];
//         garble_gate_garble_halfgates(a, a ^ delta, b, b ^ delta, &out[0], &out[1], delta,
//                                      table, gid++, &prp.aes);
//         GC.push_back(table[0]);
//         GC.push_back(table[1]);
//         return out[0];
//     }
//     block xor_gate(const block& a, const block& b) override { return a ^ b; }
//     block not_gate(const block& a) override { return a ^ delta; }
//     uint64_t num_and() override { return gid; }
// };
#endif
