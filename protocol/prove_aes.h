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

// The counter blocks infomation to be proved and the length of each counter block is 16 bytes.
// `id` is the counter block index, starting from zero.
// `mask` identify the bytes to be proved in one counter block. If `mask[i]` is 1,
// then the i-th bytes should be proved
struct AESCounterInfo {
    size_t id;
    unsigned char mask[16];
};

/*
    The AES Prover.
*/
class AESProver {
   public:
    // This is the scheduled aes key.
    Integer expanded_key;
    Integer fixed_iv;
    Integer nonce;

    // `key` and `iv` are client(server) write key and iv respectively derived from master secret.
    // Note the length of `key` is 16-bytes and the length of `iv` is 4-bytes.
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

    inline void gctr_opt(vector<Integer>& res, const vector<size_t>& ids) {
        if (ids.empty()) return;

        size_t index = 0;
        for (size_t i = 0; ; i++) {
            if (i == ids[index] + 1) {
                Integer content = nonce;
                Integer tmp = computeAES_KS(expanded_key, content);
                res.push_back(tmp);

                index++;
                if (index >= ids.size()) {
                    break;
                }
            }
            nonce = inc(nonce, 32);
        }
    }

    // `iv_len` should be 8, the `iv` derived from master secret
    // will be concated with this iv to form the full iv, the 
    // length of which is 12-bytes.
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

    inline Integer computeCounter(const unsigned char* iv, size_t iv_len, size_t msg_len) {
        size_t u = 128 * ((msg_len * 8 + 128 - 1) / 128) - msg_len * 8;

        size_t ctr_len = (msg_len * 8 + 128 - 1) / 128;

        set_nonce(iv, iv_len);
        Integer Z;
        gctr(Z, 1 + ctr_len);

        Z.bits.erase(Z.bits.end() - 128, Z.bits.end());
        Z.bits.erase(Z.bits.begin(), Z.bits.begin() + u);
        return Z;
    }

    inline Integer computeCounterOpt(const vector<AESCounterInfo>& counterInfos,
                                             const unsigned char* iv,
                                             size_t iv_len) {
        vector<size_t> ids;
        for (size_t i = 0; i < counterInfos.size(); i++) {
            ids.push_back(counterInfos[i].id);
        }

        vector<Integer> counters;
        set_nonce(iv, iv_len);
        gctr_opt(counters, ids);

        Integer izk_counter;
        for (size_t i = 0; i < counterInfos.size(); i++) {
            const AESCounterInfo& c = counterInfos[i];
            const Integer& oneCounter = counters[i];
            int begin = -1;
            int j = 0;

            for (; j < 16; j++) {
                if (c.mask[j]) {
                    if (begin == -1) {
                        begin = j;
                    }
                }
                else {
                    if (begin != -1) {
                        izk_counter.bits.insert(izk_counter.bits.begin(), oneCounter.bits.end() - j * 8, oneCounter.bits.end() - begin * 8);
                        begin = -1;
                    }
                }
            }
            if (begin != -1) {
                izk_counter.bits.insert(izk_counter.bits.begin(), oneCounter.bits.end() - j * 8, oneCounter.bits.end() - begin * 8);
                begin = -1;
            }
            
        }

        return izk_counter;
    }


    // This proves AES(k, nounce) xor msgs = ctxts in blocks, where msgs is public.
    // Note the msgs and ctxts should be continuous and no block can be omitted.
    inline bool prove_public_msgs(const unsigned char* iv,
                                  size_t iv_len,
                                  const unsigned char* msgs,
                                  const unsigned char* ctxts,
                                  size_t msg_len) {
        Integer c = computeCounter(iv, iv_len, msg_len);

        unsigned char* c_xor_m = new unsigned char[msg_len];
        for (size_t i = 0; i < msg_len; ++i) {
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
    // Note the msgs and ctxts should be continuous and no block can be omitted.
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

    // This proves AES(k, nounce) xor msgs = ctxts in blocks, where msgs is public.
    // Note the msgs and ctxts can be discreate and their positions can be identified by `counterInfos`.
    inline bool prove_public_msgs_opt(const vector<AESCounterInfo>& counterInfos,
                                       const unsigned char* iv,
                                       size_t iv_len, 
                                       const unsigned char* msgs,
                                       const unsigned char* ctxts,
                                       size_t msg_len) {
        Integer c = computeCounterOpt(counterInfos, iv, iv_len);

        unsigned char* c_xor_m = new unsigned char[msg_len];
        for (size_t i = 0; i < msg_len; ++i) {
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
    // Note the msgs and ctxts can be discreate and their positions can be identified by `counterInfos`.
    inline bool prove_private_msgs_opt(const vector<AESCounterInfo>& counterInfos,
                                       const unsigned char* iv,
                                       size_t iv_len, 
                                       const Integer& msgs,
                                       const unsigned char* ctxts,
                                       size_t msg_len) {
        assert(msgs.size() == 8 * msg_len);

        Integer c = computeCounterOpt(counterInfos, iv, iv_len);

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
