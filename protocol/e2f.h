#ifndef _E2F_H_
#define _E2F_H_
#include "emp-tool/emp-tool.h"
#include "backend/ole.h"
#include "backend/bn_utils.h"

template <typename IO>
class E2F {
   public:
    IO* io;
    IO* io_opt;
    OLE<IO>* ole = nullptr;
    std::unique_ptr<OLE<IO>> p_ole;
    size_t bit_length;

    BIGNUM* a;
    UniqueBN p_a;
    BIGNUM* b;
    UniqueBN p_b;
    BIGNUM* c;
    UniqueBN p_c;
    BIGNUM* bp;
    UniqueBN p_bp;
    BIGNUM* cp;
    UniqueBN p_cp;
    BIGNUM* r;
    UniqueBN p_r;
    BIGNUM* r2;
    UniqueBN p_r2;

    E2F(IO* io, IO* io_opt, COT<IO>* ot, BIGNUM* q2, size_t bit_length)
        : io(io), bit_length(bit_length) {
        ole = new OLE<IO>(io, ot, q2, bit_length);
        p_ole.reset(ole);
        this->io_opt = io_opt;
        a = BN_new();
        p_a.reset(a);
        b = BN_new();
        p_b.reset(b);
        c = BN_new();
        p_c.reset(c);
        bp = BN_new();
        p_bp.reset(bp);
        cp = BN_new();
        p_cp.reset(cp);
        r = BN_new();
        p_r.reset(r);
        r2 = BN_new();
        p_r2.reset(r2);
    }

    ~E2F() {
    }

    inline void open(BIGNUM* value[], int party) {
        BIGNUM* tmp = BN_new();
        UniqueBN p_tmp(tmp);
        if (party == ALICE) {
            for (size_t i = 0; value[i] != nullptr; i++)
                send_bn(io, value[i]);
            io->flush();
            for (size_t i = 0; value[i] != nullptr; i++) {
                recv_bn(io_opt, tmp);
                BN_mod_add(value[i], value[i], tmp, ole->q, ole->ctx);
            }
        } else {
            for (size_t i = 0; value[i] != nullptr; i++)
                send_bn(io_opt, value[i]);
            io_opt->flush();
            for (size_t i = 0; value[i] != nullptr; i++) {
                recv_bn(io, tmp);
                BN_mod_add(value[i], value[i], tmp, ole->q, ole->ctx);
            }
        }
    }

    inline void open(BIGNUM* value, int party) {
        BIGNUM* vec[] = {value, nullptr};
        open(vec, party);
    }

    void compute_offline(int party) {
        BN_rand(a, bit_length, 0, 0);
        BN_mod(a, a, ole->q, ole->ctx);
        BN_rand(b, bit_length, 0, 0);
        BN_mod(b, b, ole->q, ole->ctx);
        BN_rand(bp, bit_length, 0, 0);
        BN_mod(bp, bp, ole->q, ole->ctx);
        BN_rand(r, bit_length, 0, 0);
        BN_mod(r, r, ole->q, ole->ctx);

        vector<BIGNUM*> in;
        vector<BIGNUM*> out;
        vector<UniqueBN> p_out;

        out.resize(5);
        p_out.resize(5);
        for (int i = 0; i < 5; i++) {
            out[i] = BN_new();
            p_out[i].reset(out[i]);
        }

        if (party == ALICE) {
            in.push_back(a);
            in.push_back(b);
            in.push_back(a);
            in.push_back(bp);
            in.push_back(r);
        } else {
            in.push_back(b);
            in.push_back(a);
            in.push_back(bp);
            in.push_back(a);
            in.push_back(r);
        }

        ole->compute(out, in);

        BN_mod_mul(c, a, b, ole->q, ole->ctx);
        BN_mod_add(c, c, out[0], ole->q, ole->ctx);
        BN_mod_add(c, c, out[1], ole->q, ole->ctx);

        BN_mod_mul(cp, a, bp, ole->q, ole->ctx);
        BN_mod_add(cp, cp, out[2], ole->q, ole->ctx);
        BN_mod_add(cp, cp, out[3], ole->q, ole->ctx);

        BN_mod_sqr(r2, r, ole->q, ole->ctx);
        BN_mod_add(r2, r2, out[4], ole->q, ole->ctx);
        BN_mod_add(r2, r2, out[4], ole->q, ole->ctx);

    }

    void compute_online(BIGNUM* out, const BIGNUM* x, const BIGNUM* y, int party) {
        BIGNUM* xbma = BN_new();
        UniqueBN p_xbma(xbma);
        BIGNUM* ybma = BN_new();
        UniqueBN p_ybma(ybma);

        if (party == ALICE) {
            BN_sub(xbma, ole->q, x);
            BN_sub(ybma, ole->q, y);
        } else {
            BN_copy(xbma, x);
            BN_copy(ybma, y);
        }
        BIGNUM* w = BN_new();
        UniqueBN p_w(w);
        BN_mod_sub(w, xbma, b, ole->q, ole->ctx); // epsilon1 = open(xb-xa-b)

        BIGNUM* eta = BN_new();
        UniqueBN p_eta(eta);
        BN_mod_sub(eta, ybma, bp, ole->q, ole->ctx); // epsilon2 = open(yb-ya-bp)

        BIGNUM* open_vec[] = {w, eta, nullptr};
        open(open_vec, party); // open epsilon1, epsilon2

        BN_mod_mul(w, w, a, ole->q, ole->ctx);
        BN_mod_add(w, w, c, ole->q, ole->ctx);

        open(w, party); // open w.

        if (BN_is_zero(w))
            error("w is zero, invalid!\n");

        BN_mod_mul(eta, eta, a, ole->q, ole->ctx);
        BN_mod_add(eta, eta, cp, ole->q, ole->ctx);

        BN_mod_inverse(w, w, ole->q, ole->ctx);
        BN_mod_mul(eta, w, eta, ole->q, ole->ctx);

        BN_mod_sub(eta, eta, r, ole->q, ole->ctx); // epsilon3 = open(eta-r)
        open(eta, party);                          // open epsilon3

        BN_mod_mul(out, eta, r, ole->q, ole->ctx);   // epsilon3*[r]
        BN_mod_add(out, out, out, ole->q, ole->ctx); // 2*epsilon3*[r]
        BN_mod_add(out, out, r2, ole->q, ole->ctx);  // 2epsilon3*[r] + [r^2]
        BN_mod_sub(out, out, x, ole->q, ole->ctx);   // 2epsilon3*[r] + [r^2] - [xb]-[xa]

        BN_set_word(ybma, 0);
        if (party == BOB)
            BN_mod_sqr(ybma, eta, ole->q, ole->ctx); // epsilon3^2

        // epsilon3^2 + 2epsilon3*[r] + [r^2] - [xb]-[xa]
        BN_mod_add(out, out, ybma, ole->q, ole->ctx);

    }
};

#endif
