#ifndef _TLSPRF_H_
#define _TLSPRF_H_

#include "emp-tool/emp-tool.h"
#include "hmac_sha256.h"
#include "utils.h"

using namespace emp;

class PRF {
   public:
    PRF() {};
    ~PRF() {
    };
    size_t hmac_calls_num = 0;

    // should check consistency of zk_sec_M and pub_M;
    vector<Integer> zk_sec_M;
    vector<uint32_t*> pub_M;
    vector<std::shared_ptr<uint32_t>> p_pub_M;
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
        std::unique_ptr<Integer[]> p_A(A);
        Integer* tmp = new Integer[hmac.DIGLEN];
        std::unique_ptr<Integer[]> p_tmp(tmp);

        A[0] = seed;
        for (size_t i = 1; i < blks + 1; i++) {
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
        vector<std::shared_ptr<unsigned char>> p_A;
        vector<size_t> hashlen;
        A.resize(blks + 1);
        p_A.resize(blks + 1);
        A[0] = new unsigned char[seedlen];
        p_A[0].reset(A[0]);
        memcpy(A[0], seed, seedlen);
        hashlen.push_back(seedlen);

        Integer* tmp = new Integer[hmac.DIGLEN];
        std::unique_ptr<Integer[]> p_tmp(tmp);
        uint32_t* tmpd = new uint32_t[hmac.DIGLEN];
        std::unique_ptr<uint32_t[]> p_tmpd(tmpd);

        unsigned char* As = new unsigned char[32 + seedlen];
        std::unique_ptr<unsigned char[]> p_As(As);
        for (size_t i = 1; i < blks + 1; i++) {
            hmac.opt_hmac_sha256(tmp, A[i - 1], hashlen[i - 1], reuse_in_hash_flag,
                                 reuse_out_hash_flag, zk_flag);
            hmac_calls_num++;
            A[i] = new unsigned char[32];
            p_A[i].reset(A[i]);

            Integer tmpInt;
            reverse_concat(tmpInt, tmp, hmac.DIGLEN);

            if (!zk_flag) {
                // in the gc setting, store the revealed M values.
                tmpInt.reveal<uint32_t>((uint32_t*)tmpd, PUBLIC);

                pub_M.push_back(nullptr);
                pub_M.back() = new uint32_t[hmac.DIGLEN];
                p_pub_M.push_back(std::shared_ptr<uint32_t>(pub_M.back()));
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


    }

    inline void opt_rounds_phash(HMAC_SHA256& hmac,
                                 Integer& res,
                                 size_t bitlen,
                                 const Integer secret,
                                 const unsigned char* seed,
                                 size_t seedlen,
                                 bool reuse_in_hash_flag = false,
                                 bool reuse_out_hash_flag = false,
                                 bool zk_flag = false) {
        size_t blks = bitlen / (hmac.DIGLEN * hmac.WORDLEN) + 1;
        Integer* A = new Integer[blks + 1];
        std::unique_ptr<Integer[]> p_A(A);
        Integer* tmp = new Integer[hmac.DIGLEN];
        std::unique_ptr<Integer[]> p_tmp(tmp);
        unsigned char* rseed = new unsigned char[seedlen];
        std::unique_ptr<unsigned char[]> p_rseed(rseed);
        memcpy(rseed, seed, seedlen);
        reverse(rseed, rseed + seedlen);
        A[0] = Integer(8 * seedlen, rseed, ALICE);

        for (size_t i = 1; i < blks + 1; i++) {
            hmac.opt_rounds_hmac_sha256(tmp, A[i - 1], reuse_in_hash_flag,
                                        reuse_out_hash_flag);
            hmac_calls_num++;

            concat(A[i], &tmp[0], hmac.DIGLEN);

            Integer As;
            concat(As, &A[i], 1);
            concat(As, &A[0], 1);

            hmac.opt_rounds_hmac_sha256(tmp, As, reuse_in_hash_flag, reuse_out_hash_flag);
            hmac_calls_num++;
            concat(res, tmp, hmac.DIGLEN);
        }
        res.bits.erase(res.bits.begin(),
                       res.bits.begin() + blks * (hmac.DIGLEN * hmac.WORDLEN) - bitlen);

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
        std::unique_ptr<unsigned char[]> p_label_seed(label_seed);
        memcpy(label_seed, label, labellen);
        memcpy(label_seed + labellen, seed, seedlen);
        opt_phash(hmac, res, bitlen, secret, label_seed, labellen + seedlen,
                  reuse_in_hash_flag, reuse_out_hash_flag, zk_flag);

    }

    inline void opt_rounds_compute(HMAC_SHA256& hmac,
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
        std::unique_ptr<unsigned char[]> p_label_seed(label_seed);
        memcpy(label_seed, label, labellen);
        memcpy(label_seed + labellen, seed, seedlen);
        opt_rounds_phash(hmac, res, bitlen, secret, label_seed, labellen + seedlen,
                         reuse_in_hash_flag, reuse_out_hash_flag, zk_flag);
    }

    inline size_t hmac_calls() { return hmac_calls_num; }

    template <typename IO>
    inline void prf_check(int party) {
        if (pub_M.size() != zk_sec_M.size())
            error("length of M is not consistent!\n");
        for (size_t i = 0; i < pub_M.size(); i++)
            check_zero<IO>(zk_sec_M[i], pub_M[i], 8, party);
    }
};

class PRFOffline {
   public:
    PRFOffline() {};
    ~PRFOffline() {};
    size_t hmac_calls_num = 0;

    inline void init(HMAC_SHA256_Offline& hmac, const Integer secret) {
        hmac.init(secret);
        hmac_calls_num = 0;
    }

    inline void opt_phash(HMAC_SHA256_Offline& hmac,
                          Integer& res,
                          size_t bitlen,
                          const Integer secret,
                          bool reuse_in_hash_flag = false,
                          bool reuse_out_hash_flag = false) {
        size_t blks = bitlen / (hmac.DIGLEN * hmac.WORDLEN) + 1;

        Integer* tmp = new Integer[hmac.DIGLEN];
        std::unique_ptr<Integer[]> p_tmp(tmp);
        uint32_t* tmpd = new uint32_t[hmac.DIGLEN];
        std::unique_ptr<uint32_t[]> p_tmpd(tmpd);

        for (size_t i = 1; i < blks + 1; i++) {
            hmac.opt_hmac_sha256(tmp, reuse_in_hash_flag, reuse_out_hash_flag);
            hmac_calls_num++;

            // in the gc setting, store the revealed M values.
            Integer tmpInt;
            reverse_concat(tmpInt, tmp, hmac.DIGLEN);
            tmpInt.reveal<uint32_t>((uint32_t*)tmpd, PUBLIC);

            hmac.opt_hmac_sha256(tmp, reuse_in_hash_flag, reuse_out_hash_flag);
            hmac_calls_num++;
            concat(res, tmp, hmac.DIGLEN);
        }
        res.bits.erase(res.bits.begin(),
                       res.bits.begin() + blks * (hmac.DIGLEN * hmac.WORDLEN) - bitlen);

    }

    inline void opt_rounds_phash(HMAC_SHA256_Offline& hmac,
                                 Integer& res,
                                 size_t bitlen,
                                 const Integer secret,
                                 size_t seedlen,
                                 bool reuse_in_hash_flag = false,
                                 bool reuse_out_hash_flag = false) {
        size_t blks = bitlen / (hmac.DIGLEN * hmac.WORDLEN) + 1;
        Integer* A = new Integer[blks + 1];
        std::unique_ptr<Integer[]> p_A(A);
        A[0] = Integer(8 * seedlen, 0, ALICE);

        Integer* tmp = new Integer[hmac.DIGLEN];
        std::unique_ptr<Integer[]> p_tmp(tmp);

        for (size_t i = 1; i < blks + 1; i++) {
            hmac.opt_rounds_hmac_sha256(tmp, A[i - 1], reuse_in_hash_flag,
                                        reuse_out_hash_flag);
            hmac_calls_num++;

            concat(A[i], &tmp[0], hmac.VALLEN);

            Integer As;
            concat(As, &A[i], 1);
            concat(As, &A[0], 1);

            hmac.opt_rounds_hmac_sha256(tmp, As, reuse_in_hash_flag, reuse_out_hash_flag);
            hmac_calls_num++;
            concat(res, tmp, hmac.DIGLEN);
        }
        res.bits.erase(res.bits.begin(),
                       res.bits.begin() + blks * (hmac.DIGLEN * hmac.WORDLEN) - bitlen);

    }

    inline void opt_compute(HMAC_SHA256_Offline& hmac,
                            Integer& res,
                            size_t bitlen,
                            const Integer secret,
                            bool reuse_in_hash_flag = false,
                            bool reuse_out_hash_flag = false) {
        opt_phash(hmac, res, bitlen, secret, reuse_in_hash_flag, reuse_out_hash_flag);
    }
    inline void opt_rounds_compute(HMAC_SHA256_Offline& hmac,
                                   Integer& res,
                                   size_t bitlen,
                                   const Integer secret,
                                   size_t seedlen,
                                   bool reuse_in_hash_flag = false,
                                   bool reuse_out_hash_flag = false) {
        opt_rounds_phash(hmac, res, bitlen, secret, seedlen, reuse_in_hash_flag,
                         reuse_out_hash_flag);
    }
};

#endif
