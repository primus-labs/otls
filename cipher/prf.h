#ifndef _TLSPRF_H_
#define _TLSPRF_H_

#include "emp-tool/emp-tool.h"
#include "hmac_sha256.h"
#include "utils.h"

using namespace emp;

class PRF {
   public:
    PRF(){};
    ~PRF(){};
    size_t hmac_calls_num = 0;

    inline void init(HMAC_SHA256& hmac, const Integer secret) {
        hmac.init(secret);
    }

    inline void phash(HMAC_SHA256& hmac,
                      Integer& res,
                      size_t bitlen,
                      const Integer secret,
                      const Integer seed) {
        size_t blks = bitlen / (hmac.DIGLEN * hmac.WORDLEN) + 1;
        Integer* A = new Integer[blks + 1];
        Integer* res_tmp = new Integer[blks];
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
            concat(res_tmp[i - 1], tmp, hmac.DIGLEN);
        }

        concat(res, res_tmp, blks);
        res.bits.erase(
          res.bits.begin(),
          res.bits.begin() + blks * (hmac.DIGLEN * hmac.WORDLEN) - bitlen);

        delete[] A;
        delete[] tmp;
        delete[] res_tmp;
    }

    inline void opt_phash(HMAC_SHA256& hmac,
                          Integer& res,
                          size_t bitlen,
                          const Integer secret,
                          const unsigned char* seed,
                          size_t seedlen,
                          bool in_flag = false,
                          bool out_flag = false) {
        size_t blks = bitlen / (hmac.DIGLEN * hmac.WORDLEN) + 1;
        vector<unsigned char*> A;
        vector<size_t> hashlen;
        A.resize(blks + 1);
        A[0] = new unsigned char[seedlen];
        memcpy(A[0], seed, seedlen);
        hashlen.push_back(seedlen);

        Integer* tmp = new Integer[hmac.DIGLEN];
        Integer* res_tmp = new Integer[blks];
        uint32_t* tmpd = new uint32_t[hmac.DIGLEN];

        unsigned char* As = new unsigned char[32 + seedlen];
        for (int i = 1; i < blks + 1; i++) {
            hmac.opt_hmac_sha256(tmp, A[i - 1], hashlen[i - 1], in_flag,
                                  out_flag);
            hmac_calls_num++;
            A[i] = new unsigned char[32];

            Integer tmpInt;

            for (int i = 0; i < hmac.VALLEN; ++i)
                tmpInt.bits.insert(tmpInt.bits.end(), std::begin(tmp[i].bits),
                                   std::end(tmp[i].bits));
            tmpInt.reveal<uint32_t>((uint32_t*)tmpd, PUBLIC);

            for (int j = 0, k = 0; j < hmac.DIGLEN; j++, k += 4) {
                A[i][k] = (tmpd[j] >> 24);
                A[i][k + 1] = (tmpd[j] >> 16);
                A[i][k + 2] = (tmpd[j] >> 8);
                A[i][k + 3] = tmpd[j];
            }
            hashlen.push_back(32);

            memcpy(As, A[i], 32);
            memcpy(As + 32, seed, seedlen);

            hmac.opt_hmac_sha256(tmp, As, 32 + seedlen, in_flag, out_flag);
            hmac_calls_num++;
            concat(res_tmp[i - 1], tmp, hmac.DIGLEN);
        }

        concat(res, res_tmp, blks);
        res.bits.erase(
          res.bits.begin(),
          res.bits.begin() + blks * (hmac.DIGLEN * hmac.WORDLEN) - bitlen);

        for (int i = 0; i < blks + 1; i++) {
            delete[] A[i];
        }

        delete[] As;
        delete[] tmp;
        delete[] res_tmp;
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
                        bool in_flag = false,
                        bool out_flag = false) {
        unsigned char* label_seed = new unsigned char[labellen + seedlen];
        memcpy(label_seed, label, labellen);
        memcpy(label_seed + labellen, seed, seedlen);
        opt_phash(hmac, res, bitlen, secret, label_seed, labellen + seedlen,
                  in_flag, out_flag);

        delete[] label_seed;
    }

    inline size_t hmac_calls() { return hmac_calls_num; }
};

#endif