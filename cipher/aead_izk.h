#ifndef _AEAD_IZK_
#define _AEAD_IZK_
#include "emp-tool/emp-tool.h"
#include "utils.h"

using namespace emp;
class AEAD_IZK {
   public:
    Integer expanded_key;
    Integer nonce;
    Integer H;

    AEAD_IZK(Integer& key, unsigned char* iv, size_t iv_len) {
        if (iv_len != 12) {
            error("invalid IV length!\n");
        }
        reverse(iv, iv + iv_len);
        nonce = Integer(96, iv, PUBLIC);
        Integer ONE = Integer(32, 1, PUBLIC);
        concat(nonce, &ONE, 1);

        expanded_key = computeKS(key);
        Integer H = computeH();
    }
    ~AEAD_IZK() {}

    inline Integer computeH() {
        Integer in(128, 0, PUBLIC);
        return computeAES_KS(expanded_key, in);
    }

    inline Integer inc(Integer& counter, size_t s) {
        if (counter.size() < s) {
            error("invalid length s!");
        }
        Integer msb = counter, lsb = counter;
        msb.bits.erase(msb.bits.begin(), msb.bits.begin() + s);
        lsb.bits.erase(lsb.bits.begin() + s, lsb.bits.end());
        lsb = lsb + Integer(s, 1, PUBLIC);

        concat(msb, &lsb, 1);
        return msb;
    }

    inline void gctr(Integer& res, size_t m) {
        Integer tmp(128, 0, PUBLIC);
        for (int i = 0; i < m; i++) {
            Integer content = nonce;
            tmp = computeAES_KS(expanded_key, content);

            concat(res, &tmp, 1);
            nonce = inc(nonce, 32);
        }
    }

    inline void enc_and_dec_msg(Integer& aes_ctxt, size_t bit_len) {
        size_t ctr_len = (bit_len + 128 - 1) / 128;
        gctr(aes_ctxt, 1 + ctr_len);
    }
};
#endif