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
    vector<BIGNUM*> exp;
    CCRH ccrh;
    size_t bit_length;
    BIGNUM* q;
    OLE(IO* io, COT<IO>* ot, BIGNUM* q2, size_t bit_length)
        : io(io), ot(ot), bit_length(bit_length) {
        ctx = BN_CTX_new();
        q = BN_new();
        BN_copy(this->q, q2);
        exp.resize(bit_length);
        for (size_t i = 0; i < bit_length; ++i) {
            exp[i] = BN_new();
            BN_set_bit(exp[i], i);
            BN_mod(exp[i], exp[i], q, ctx);
        }
    }

    ~OLE() {
        BN_CTX_free(ctx);
        BN_free(q);
        for (size_t i = 0; i < bit_length; ++i)
            BN_free(exp[i]);
    }

    /* Compute the OLE protocol */
    // BN_new all memory before calling this function!
    void compute(vector<BIGNUM*>& out, const vector<BIGNUM*>& in) {
        assert(out.size() == in.size());
        BIGNUM *pad1 = BN_new(), *pad2 = BN_new(), *msg = BN_new(), *tmp = BN_new();
        block* raw = new block[out.size() * bit_length];
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
            delete[] bits;
        }
        delete[] raw;
        BN_free(pad1);
        BN_free(pad2);
        BN_free(msg);
        BN_free(tmp);
    }
};
#endif
