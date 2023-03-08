#ifndef _AEAD_IZK_
#define _AEAD_IZK_
#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-zk.h"
#include "utils.h"
#include "aead.h"
#include "backend/checkzero.h"

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

template <typename IO>
class AEAD_Proof {
    AEAD<IO> aead;
    Integer expanded_key;
    Integer nonce;
    Integer H;

    AEAD_Proof(AEAD<IO>& aead, Integer& key, unsigned char* iv, size_t iv_len) {
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
    ~AEAD_Proof() {}

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

    void prove_encryption(
      Integer& msg, unsigned char* ctxt, size_t ctxt_len, int party, bool sec_type = false) {
        // u = 128 * ceil(ctxt_len/128) - 8*ctxt_len
        size_t u = 128 * ((ctxt_len * 8 + 128 - 1) / 128) - ctxt_len * 8;

        size_t ctr_len = (ctxt_len * 8 + 128 - 1) / 128;

        Integer Z;
        gctr(Z, 1 + ctr_len);

        Integer Z0;
        Z0.bits.insert(Z0.bits.end(), Z.bits.end() - 128, Z.bits.end());
        block z0 = integer_to_block(Z0);

        Z.bits.erase(Z.bits.end() - 128, Z.bits.end());
        Z.bits.erase(Z.bits.begin(), Z.bits.begin() + u);

        if (!sec_type) {
        } else {
        }
    }

    void prove_decryption() {}
};

// implicity homomorphic property and check zero of IT-MAC.
template <typename IO>
inline void itmac_hom_add_check(Integer& res, Integer& pre_res, int party, block blk) {
    assert(pre_res.size() == 128);
    assert(res.size() == 128);

    if (party == BOB) {
        block delta = ((ZKVerifier<IO>*)(ProtocolExecution::prot_exec))->ostriple->delta;
        for (int i = 0; i < pre_res.size(); i++) {
            block tmp = set_bit(zero_block, i);
            block tmpx = tmp & blk;
            if (cmpBlock(&tmpx, &tmp, 1))
                pre_res[i].bit = pre_res[i].bit ^ delta;
        }
    }
    check_zero<IO>(res ^ pre_res, party);
}

// implicity homomorphic property and check zero of IT-MAC.
template <typename IO>
inline void itmac_hom_add_check(
  Integer& res, Integer& pre_res, int party, const unsigned char* share, int len) {
    assert(pre_res.size() == (len * 8));
    assert(res.size() == (len * 8));
    if (party == BOB) {
        block delta = ((ZKVerifier<IO>*)(ProtocolExecution::prot_exec))->ostriple->delta;
        bool* data = new bool[len * 8];
        to_bool(data, share, len * 8);
        for (int i = 0; i < len * 8; i++) {
            if (data[i])
                pre_res[i].bit = pre_res[i].bit ^ delta;
        }
        delete[] data;
    }

    check_zero<IO>(res ^ pre_res, party);
}
#endif