/* 
    This is for the proxy model, which does not need MPC to run the handshake and record phase. 
    The proxy will keep and forward all the TLS transcripts. 
    The client will prove (with interactive zkp) to the proxy (verifier) 
    that he knows the session key (and possibly some private message) encrypted under the given ciphertexts.
*/

#ifndef _AESPROVER_
#define _AESPROVER_

#include "emp-tool/emp-tool.h"
#include "cipher/utils.h"

template <typename IO>
void setup_proxy_protocol(BoolIO<IO>** ios, int threads, int party) {
    init_files();
    setup_zk_bool<BoolIO<IO>>(ios, threads, party);
}

template <typename IO>
inline bool finalize_proxy_protocol() {
    bool res = finalize_zk_bool<IO>();
    uninit_files();
    return res;
}

/*
    The AES Prover.
*/
class AESProver {
   public:
    // This is the scheduled aes key.
    Integer expanded_key;
    Integer fixed_iv;
    Integer nonce;

    inline AESProver(Integer& key, Integer& iv) {
        assert(key.size() == 128);
        expanded_key = computeKS(key);

        assert(iv.size() == 32);
        fixed_iv = iv;
    }
    ~AESProver() {}

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
        for (size_t i = 0; i < m; i++) {
            Integer content = nonce;
            tmp = computeAES_KS(expanded_key, content);

            concat(res, &tmp, 1);
            nonce = inc(nonce, 32);
        }
    }

    inline void set_nonce(const unsigned char* iv,
                          size_t iv_len) {
        assert(iv_len == 8);

        unsigned char* riv = new unsigned char[iv_len];
        memcpy(riv, iv, iv_len);
        reverse(riv, riv + iv_len);
        Integer variable_iv(64, riv, PUBLIC);

        delete[] riv;

        Integer ONE = Integer(32, 1, PUBLIC);

        nonce = fixed_iv;
        concat(nonce, &variable_iv, 1);
        concat(nonce, &ONE, 1);
    }

    inline Integer computeCounter(const unsigned char* iv,
                                  size_t iv_len,
                                  size_t msg_len) {
        size_t u = 128 * ((msg_len * 8 + 128 - 1) / 128) - msg_len * 8;

        size_t ctr_len = (msg_len * 8 + 128 - 1) / 128;

        set_nonce(iv, iv_len);
        Integer Z;
        gctr(Z, 1 + ctr_len);

        Z.bits.erase(Z.bits.end() - 128, Z.bits.end());
        Z.bits.erase(Z.bits.begin(), Z.bits.begin() + u);
        return Z;
    }

    // This proves AES(k, nounce) xor msgs = ctxts in blocks, where msgs is public.
    // Note the length of nounces, msgs and ctxts should be the same and a multiple of 16.
    // len_bytes is a multiple of 16.
    inline bool prove_public_msgs(const unsigned char* iv,
                                  size_t iv_len,
                                  const unsigned char* msgs,
                                  const unsigned char* ctxts,
                                  size_t msg_len) {
        Integer c = computeCounter(iv, iv_len, msg_len);

        unsigned char* c_xor_m = new unsigned char[msg_len];
        for (int i = 0; i < msg_len; ++i) {
            c_xor_m[msg_len - 1 - i] = msgs[i] ^ ctxts[i];
        }

        unsigned char* expected = new unsigned char[msg_len];

        c.reveal<unsigned char>((unsigned char*)expected, PUBLIC);
        bool res = memcmp(expected, c_xor_m, msg_len) == 0;

        delete[] c_xor_m;
        delete[] expected;
        return res;
    }

    // This proves AES(k, nounces) xor msgs = ctxts in blocks, where msgs is private.
    // Note the length of nounces and ctxts should be the same and a multiple of 16.
    // The length of msgs should be a multiple of 128.
    // len_bytes is a multiple of 16.
    inline bool prove_private_msgs(const unsigned char* iv,
                                   size_t iv_len, 
                                   const Integer& msgs,
                                   const unsigned char* ctxts,
                                   size_t msg_len) {
        assert(msgs.size() == 8 * msg_len);

        Integer c = computeCounter(iv, iv_len, msg_len);

        c ^= msgs;

        unsigned char* expected = new unsigned char[msg_len];

        c.reveal<unsigned char>((unsigned char*)expected, PUBLIC);
        reverse(expected, expected + msg_len);
        bool res = memcmp(expected, ctxts, msg_len) == 0;

        delete[] expected;
        return res;
    }
};

#endif
