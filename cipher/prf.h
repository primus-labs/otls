#ifndef _TLSPRF_H_
#define _TLSPRF_H_

#include "emp-tool/emp-tool.h"
#include "hmac_sha256.h"
#include "utils.h"

using namespace emp;

class PRF {
   public:
    PRF(){};
    ~PRF() {
        for (int i = 0; i < pub_M.size(); i++) {
            if (pub_M[i] != nullptr) {
                delete[] pub_M[i];
            }
        }
        pub_M.clear();
    };
    size_t hmac_calls_num = 0;

    // should check consistency of zk_sec_M and pub_M;
    vector<Integer> zk_sec_M;
    vector<uint32_t*> pub_M;
    size_t zk_pos = 0;

    inline void init(HMAC_SHA256& hmac, const Integer secret) {
        hmac.init(secret);
        hmac_calls_num = 0;
    }

    inline void phash(HMAC_SHA256& hmac,
                      Integer& res,
                      size_t bitlen,
                      const Integer secret,
                      const Integer seed) {
        size_t blks = bitlen / (hmac.DIGLEN * hmac.WORDLEN) + 1;
        Integer* A = new Integer[blks + 1];
        Integer* tmp = new Integer[hmac.DIGLEN];

        A[0] = seed;
        for (int i = 1; i < blks + 1; i++) {
            hmac.hmac_sha256(tmp, A[i - 1]);
            hmac_calls_num++;
            concat(A[i], tmp, hmac.DIGLEN);

            Integer As;
            concat(As, &A[i], 1);
            concat(As, &seed, 1);

            hmac.hmac_sha256(tmp, As);
            hmac_calls_num++;
            concat(res, tmp, hmac.DIGLEN);
        }

        res.bits.erase(res.bits.begin(),
                       res.bits.begin() + blks * (hmac.DIGLEN * hmac.WORDLEN) - bitlen);

        delete[] A;
        delete[] tmp;
    }

    inline void opt_phash(HMAC_SHA256& hmac,
                          Integer& res,
                          size_t bitlen,
                          const Integer secret,
                          const unsigned char* seed,
                          size_t seedlen,
                          bool reuse_in_hash_flag = false,
                          bool reuse_out_hash_flag = false,
                          bool zk_flag = false) {
        size_t blks = bitlen / (hmac.DIGLEN * hmac.WORDLEN) + 1;
        vector<unsigned char*> A;
        vector<size_t> hashlen;
        A.resize(blks + 1);
        A[0] = new unsigned char[seedlen];
        memcpy(A[0], seed, seedlen);
        hashlen.push_back(seedlen);

        Integer* tmp = new Integer[hmac.DIGLEN];
        uint32_t* tmpd = new uint32_t[hmac.DIGLEN];

        unsigned char* As = new unsigned char[32 + seedlen];
        for (int i = 1; i < blks + 1; i++) {
            hmac.opt_hmac_sha256(tmp, A[i - 1], hashlen[i - 1], reuse_in_hash_flag,
                                 reuse_out_hash_flag, zk_flag);
            hmac_calls_num++;
            A[i] = new unsigned char[32];

            Integer tmpInt;

            for (int i = 0; i < hmac.VALLEN; ++i)
                tmpInt.bits.insert(tmpInt.bits.end(), std::begin(tmp[i].bits),
                                   std::end(tmp[i].bits));

            if (!zk_flag) {
                // in the gc setting, store the revealed M values.
                tmpInt.reveal<uint32_t>((uint32_t*)tmpd, PUBLIC);

                pub_M.push_back(nullptr);
                pub_M.back() = new uint32_t[hmac.DIGLEN];
                memcpy(pub_M.back(), tmpd, hmac.DIGLEN * sizeof(uint32_t));
            } else {
                // in the zk setting, store the zk shares of M. Reuse the stored public M value.
                zk_sec_M.push_back(tmpInt);
                memcpy(tmpd, pub_M[zk_pos++], hmac.DIGLEN * sizeof(uint32_t));
            }

            for (int j = 0, k = 0; j < hmac.DIGLEN; j++, k += 4) {
                A[i][k] = (tmpd[j] >> 24);
                A[i][k + 1] = (tmpd[j] >> 16);
                A[i][k + 2] = (tmpd[j] >> 8);
                A[i][k + 3] = tmpd[j];
            }
            hashlen.push_back(32);

            memcpy(As, A[i], 32);
            memcpy(As + 32, seed, seedlen);

            hmac.opt_hmac_sha256(tmp, As, 32 + seedlen, reuse_in_hash_flag,
                                 reuse_out_hash_flag, zk_flag);
            hmac_calls_num++;
            concat(res, tmp, hmac.DIGLEN);
        }
        res.bits.erase(res.bits.begin(),
                       res.bits.begin() + blks * (hmac.DIGLEN * hmac.WORDLEN) - bitlen);

        for (int i = 0; i < blks + 1; i++) {
            delete[] A[i];
        }

        delete[] As;
        delete[] tmp;
        delete[] tmpd;
    }

    inline void compute(HMAC_SHA256& hmac,
                        Integer& res,
                        size_t bitlen,
                        const Integer secret,
                        const Integer label,
                        const Integer seed) {
        Integer label_seed;
        concat(label_seed, &label, 1);
        concat(label_seed, &seed, 1);
        phash(hmac, res, bitlen, secret, label_seed);
    }

    inline void opt_compute(HMAC_SHA256& hmac,
                            Integer& res,
                            size_t bitlen,
                            const Integer secret,
                            const unsigned char* label,
                            size_t labellen,
                            const unsigned char* seed,
                            size_t seedlen,
                            bool reuse_in_hash_flag = false,
                            bool reuse_out_hash_flag = false,
                            bool zk_flag = false) {
        unsigned char* label_seed = new unsigned char[labellen + seedlen];
        memcpy(label_seed, label, labellen);
        memcpy(label_seed + labellen, seed, seedlen);
        opt_phash(hmac, res, bitlen, secret, label_seed, labellen + seedlen,
                  reuse_in_hash_flag, reuse_out_hash_flag, zk_flag);

        delete[] label_seed;
    }

    inline size_t hmac_calls() { return hmac_calls_num; }

    template <typename IO>
    inline void prf_check(int party) {
        if (pub_M.size() != zk_sec_M.size())
            error("length of M is not consistent!\n");
        for (int i = 0; i < pub_M.size(); i++)
            check_zero<IO>(zk_sec_M[i], pub_M[i], 8, party);
    }
};

#endif