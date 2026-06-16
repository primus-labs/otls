#ifndef PRIMUS_OLE_F2K_H
#define PRIMUS_OLE_F2K_H
#include "emp-ot/emp-ot.h"
#include <iostream>
using namespace emp;  // FULLPORT: upstream emp is entirely inside namespace emp

/* Define OLE for the power-of-2 field with Block */
template <typename IO>
class OLEF2K {
   public:
    IO* io;
    COT* ot;   // FULLPORT: upstream COT is a non-template base class
    // FULLPORT: upstream GaloisFieldPacking removed the public base array (switching to an inline packing()).
    // To keep the OLE output convention bit-for-bit consistent with the fork (I3; downstream e2f/vope depend on the gfmul_reflect + X^i gadget),
    // we locally reproduce the fork's packing_base_gen here to generate the (X^0..X^127) gadget.
    block base[128];
    OLEF2K(IO* io, COT* ot) : io(io), ot(ot) { packing_base_gen(); }

    void packing_base_gen() {
        uint64_t a = 0, b = 1;
        for (int i = 0; i < 64; i += 4) {
            base[i]   = _mm_set_epi64x(a, b);
            base[i+1] = _mm_set_epi64x(a, b << 1);
            base[i+2] = _mm_set_epi64x(a, b << 2);
            base[i+3] = _mm_set_epi64x(a, b << 3);
            b <<= 4;
        }
        a = 1, b = 0;
        for (int i = 64; i < 128; i += 4) {
            base[i]   = _mm_set_epi64x(a, b);
            base[i+1] = _mm_set_epi64x(a << 1, b);
            base[i+2] = _mm_set_epi64x(a << 2, b);
            base[i+3] = _mm_set_epi64x(a << 3, b);
            a <<= 4;
        }
    }

    /* Compute the inner product of two block vectors*/
    void inner_prod(block* res, const block* a, const block* b, int sz) {
        block r = zero_block;
        block r1;
        for (int i = 0; i < sz; i++) {
            gfmul_reflect(a[i], b[i], &r1);
            r = r ^ r1;
        }
        *res = r;
    }

    /* Compute the OLE protocol with inputs in, and put the output to out */
    void compute(block* out, const block* in, int length) {
        block* raw0 = new block[length * 128];
        if (!cmpBlock(&ot->Delta, &zero_block, 1)) {
            block* raw1 = new block[length * 128];
            ot->send_rot(raw0, raw1, length * 128);
            for (int i = 0; i < length; ++i) {
                for (int j = 0; j < 128; ++j) {
                    block msg = raw0[i * 128 + j] ^ raw1[i * 128 + j] ^ in[i];
                    io->send_block(&msg, 1);
                }
                inner_prod(out + i, raw0 + i * 128, base, 128);
            }
            delete[] raw1;
        } else {
            bool* bits = new bool[length * 128];
            for (int i = 0; i < length; ++i)
                bits_to_bools(bits + i * 128, &in[i], 128);  // FULLPORT: upstream rename of block_to_bool

            ot->recv_rot(raw0, bits, length * 128);

            for (int i = 0; i < length; ++i) {
                block tmp[128];
                io->recv_block(tmp, 128);
                for (int j = 0; j < 128; ++j) {
                    if (bits[i * 128 + j])
                        raw0[i * 128 + j] ^= tmp[j];
                }
                // pack.packing(out + i, raw0 + i * 128);
                inner_prod(out + i, raw0 + i * 128, base, 128);
            }
            delete[] bits;
        }
        delete[] raw0;
    }
};
#endif
