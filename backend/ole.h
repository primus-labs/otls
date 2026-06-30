#ifndef PRIMUS_OLE_H
#define PRIMUS_OLE_H
#include "emp-ot/emp-ot.h"
#include "backend/bn_utils.h"
#include <iostream>

/* Define the OLE protocol with prime fields */
template <typename IO>
class OLE {
   public:
    IO* io;
    COT<IO>* ot;
    BN_CTX* ctx = nullptr;
    std::unique_ptr<BN_CTX, void(*)(BN_CTX*)> p_ctx;
    vector<BIGNUM*> exp;
    vector<std::shared_ptr<BIGNUM>> p_exp;
    CCRH ccrh;
    size_t bit_length;
    BIGNUM* q;
    std::unique_ptr<BIGNUM, void(*)(BIGNUM*)> p_q;
    OLE(IO* io, COT<IO>* ot, BIGNUM* q2, size_t bit_length)
        : io(io), ot(ot), bit_length(bit_length), p_ctx(nullptr, BN_CTX_free), p_q(nullptr, BN_free) {
        ctx = BN_CTX_new();
        p_ctx.reset(ctx);
        q = BN_new();
        p_q.reset(q);
        BN_copy(this->q, q2);
        exp.resize(bit_length);
        p_exp.resize(bit_length);
        for (size_t i = 0; i < bit_length; ++i) {
            exp[i] = BN_new();
            p_exp[i] = std::shared_ptr<BIGNUM>(exp[i], BN_free);
            BN_set_bit(exp[i], i);
            BN_mod(exp[i], exp[i], q, ctx);
        }
    }

    ~OLE() {
    }

    /* Compute the OLE protocol */
    // BN_new all memory before calling this function!
    void compute(vector<BIGNUM*>& out, const vector<BIGNUM*>& in) {
        assert(out.size() == in.size());
        BIGNUM *pad1 = BN_new(), *pad2 = BN_new(), *msg = BN_new(), *tmp = BN_new();
        std::unique_ptr<BIGNUM, void(*)(BIGNUM*)> p_pad1(pad1, BN_free);
        std::unique_ptr<BIGNUM, void(*)(BIGNUM*)> p_pad2(pad2, BN_free);
        std::unique_ptr<BIGNUM, void(*)(BIGNUM*)> p_msg(msg, BN_free);
        std::unique_ptr<BIGNUM, void(*)(BIGNUM*)> p_tmp(tmp, BN_free);
        block* raw = new block[out.size() * bit_length];
        std::unique_ptr<block[]> p_raw(raw);
        if (!cmpBlock(&ot->Delta, &zero_block, 1)) {
            ot->send_cot(raw, out.size() * bit_length);
            for (size_t i = 0; i < out.size(); ++i) {
                BN_zero(out[i]);
                for (size_t j = 0; j < bit_length; ++j) {
                    H(pad1, raw[i * bit_length + j], q, ctx, ccrh);
                    H(pad2, raw[i * bit_length + j] ^ ot->Delta, q, ctx, ccrh);
                    BN_add(msg, pad1, pad2);
                    BN_mod_add(msg, msg, in[i], q, ctx);

                    BN_sub(tmp, q, pad1);
                    BN_mod_mul(tmp, exp[j], tmp, q, ctx);
                    BN_mod_add(out[i], out[i], tmp, q, ctx);

                    send_bn(io, msg);
                }
                io->flush();
            }
        } else {
            bool* bits = new bool[out.size() * bit_length];
            std::unique_ptr<bool[]> p_bits(bits);
            for (size_t i = 0; i < out.size(); ++i)
                for (size_t j = 0; j < bit_length; ++j)
                    bits[i * bit_length + j] = (BN_is_bit_set(in[i], j) == 1);

            ot->recv_cot(raw, bits, out.size() * bit_length);

            for (size_t i = 0; i < out.size(); ++i) {
                BN_zero(out[i]);
                for (size_t j = 0; j < bit_length; ++j) {
                    recv_bn(io, tmp);

                    H(msg, raw[i * bit_length + j], q, ctx, ccrh);
                    if (bits[i * bit_length + j])
                        BN_sub(msg, tmp, msg);

                    BN_mod_mul(tmp, exp[j], msg, q, ctx);
                    BN_mod_add(out[i], out[i], tmp, q, ctx);
                }
            }
        }
    }
};
#endif
