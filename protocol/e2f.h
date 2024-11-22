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
    size_t bit_length;

    BIGNUM* a;
    BIGNUM* b;
    BIGNUM* c;
    BIGNUM* bp;
    BIGNUM* cp;
    BIGNUM* r;
    BIGNUM* r2;

    E2F(IO* io, IO* io_opt, COT<IO>* ot, BIGNUM* q2, size_t bit_length)
        : io(io), bit_length(bit_length) {
        ole = new OLE<IO>(io, ot, q2, bit_length);
        this->io_opt = io_opt;
        a = BN_new();
        b = BN_new();
        c = BN_new();
        bp = BN_new();
        cp = BN_new();
        r = BN_new();
        r2 = BN_new();
    }

    ~E2F() {
        BN_free(a);
        BN_free(b);
        BN_free(c);
        BN_free(bp);
        BN_free(cp);
        BN_free(r);
        BN_free(r2);
        if (ole != nullptr) {
            delete ole;
        }
    }

    inline void open(BIGNUM* value[], int party) {
        BIGNUM* tmp = BN_new();
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
        BN_free(tmp);
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

        out.resize(5);
        for (int i = 0; i < 5; i++) {
            out[i] = BN_new();
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

        for (int i = 0; i < 5; i++) {
            BN_free(out[i]);
        }
    }

    void compute_online(BIGNUM* out, const BIGNUM* x, const BIGNUM* y, int party) {
        BIGNUM* xbma = BN_new();
        BIGNUM* ybma = BN_new();

        if (party == ALICE) {
            BN_sub(xbma, ole->q, x);
            BN_sub(ybma, ole->q, y);
        } else {
            BN_copy(xbma, x);
            BN_copy(ybma, y);
        }
        BIGNUM* w = BN_new();
        BN_mod_sub(w, xbma, b, ole->q, ole->ctx); // epsilon1 = open(xb-xa-b)

        BIGNUM* eta = BN_new();
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

        BN_free(xbma);
        BN_free(ybma);
        BN_free(w);
        BN_free(eta);
    }
};

#endif
