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

    inline AESProver(Integer& key) {
        assert(key.size() == 128);
        expanded_key = computeKS(key);
    }
    ~AESProver() {}

    // This proves AES(k, nounce) xor msgs = ctxts in blocks, where msgs is public.
    // Note the length of nounces, msgs and ctxts should be the same and a multiple of 16.
    // len_bytes is a multiple of 16.
    inline bool prove_public_msgs(const unsigned char* nounces,
                                  const unsigned char* msgs,
                                  const unsigned char* ctxts,
                                  size_t len_bytes) {
        assert(len_bytes % 16 == 0);

        unsigned char* c_xor_m = new unsigned char[len_bytes];
        for (int i = 0; i < len_bytes; ++i) {
            c_xor_m[len_bytes - 1 - i] = msgs[i] ^ ctxts[i];
        }

        Integer c;
        unsigned char* buffer = new unsigned char[16];
        for (int i = 0; i < len_bytes / 16; ++i) {
            memcpy(buffer, nounces + i * 16, 16);
            reverse(buffer, buffer + 16);
            Integer msg(128, buffer, PUBLIC);
            Integer tmp = computeAES_KS(expanded_key, msg);
            concat(c, &tmp, 1);
        }

        unsigned char* expected = new unsigned char[len_bytes];

        c.reveal<unsigned char>((unsigned char*)expected, PUBLIC);
        bool res = memcmp(expected, c_xor_m, len_bytes) == 0;

        delete[] c_xor_m;
        delete[] buffer;
        delete[] expected;
        return res;
    }

    // This proves AES(k, nounces) xor msgs = ctxts in blocks, where msgs is private.
    // Note the length of nounces and ctxts should be the same and a multiple of 16.
    // The length of msgs should be a multiple of 128.
    // len_bytes is a multiple of 16.
    inline bool prove_private_msgs(const unsigned char* nounces,
                                   const Integer& msgs,
                                   const unsigned char* ctxts,
                                   size_t len_bytes) {
        assert(len_bytes % 16 == 0);
        assert(msgs.size() = 8 * len_bytes);

        Integer c;
        unsigned char* buffer = new unsigned char[16];
        for (int i = 0; i < len_bytes / 16; ++i) {
            memcpy(buffer, nounces + i * 16, 16);
            reverse(buffer, buffer + 16);
            Integer msg(128, nounces + i, PUBLIC);
            Integer tmp = computeAES_KS(expanded_key, msg);
            concat(c, &tmp, 1);
        }

        c ^= msgs;

        unsigned char* expected = new unsigned char[len_bytes];

        c.reveal<unsigned char>((unsigned char*)expected, PUBLIC);
        reverse(expected, expected + len_bytes);
        bool res = memcmp(expected, ctxts, len_bytes) == 0;

        delete[] expected;
        delete[] buffer;
        return res;
    }
};

#endif