#ifndef PRIMUS_VOPE_H
#define PRIMUS_VOPE_H
#include "emp-ot/emp-ot.h"
#include "backend/bn_utils.h"
#include "cipher/utils.h"
#include <iostream>
template <typename IO>
class VOPE {
   public:
    IO* io;
    COT<IO>* ot;
    CCRH ccrh;
    GaloisFieldPacking pack;
    VOPE(IO* io, COT<IO>* ot) : io(io), ot(ot) {}

    ~VOPE() {}

    void compute_recv(block* out, int length) {
        int oles = length * 2 - 1;
        block* M = new block[oles * 128];
        bool* bits = new bool[oles * 128];
        PRG prg;
        prg.random_bool(bits, oles * 128);
        ot->recv_cot(M, bits, oles * 128);
        block diff[2];
        diff[0] = zero_block;
        io->recv_data(diff + 1, sizeof(block));

        for (int i = 0; i < oles * 128; ++i) {
            M[i] = M[i] ^ diff[bits[i]];
        }

        block* U = M + oles;
        block* t1 = M + 2 * oles;
        block* t2 = M + 3 * oles;
        for (int i = 0; i < oles; ++i) {
            pack.packing(M + i, M + i * 128);
            U[i] = bool_to_block(bits + i * 128);
        }
        //M = K + U Delta
        out[0] = M[0];
        out[1] = U[0];
        for (int i = 1; i < length; ++i) {
            for (int j = 0; j <= i; ++j) {
                t1[j] = mulBlock(out[j], M[i]);
                t2[j] = mulBlock(out[j], U[i]);
            }
            out[0] = t1[0];
            for (int j = 1; j <= i; ++j)
                out[j] = t2[j - 1] ^ t1[j];
            out[i + 1] = t2[i];
            out[0] ^= M[length + i - 1];
            out[1] ^= U[length + i - 1];
        }
        delete[] M;
        delete[] bits;
    }
    void compute_send(block* out, block h, int length) {
        int oles = length * 2 - 1;
        block* K = new block[oles * 128];
        ot->send_cot(K, oles * 128);
        block diff = h ^ ot->Delta;
        io->send_data(&diff, sizeof(block));
        io->flush();
        pack.packing(out, K);
        block tmp;
        for (int i = 1; i < length; ++i) {
            pack.packing(&tmp, K + i * 128);
            *out = mulBlock(*out, tmp);
            pack.packing(&tmp, K + (i + length - 1) * 128);
            *out = *out ^ tmp;
        }
        delete[] K;
    }
};

#endif // PRIMUS_VOPE_H
