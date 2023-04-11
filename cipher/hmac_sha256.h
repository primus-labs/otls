#ifndef HMAC_SHA256_H
#define HMAC_SHA256_H

#include "emp-tool/emp-tool.h"
#include <iostream>
#include <vector>
#include <list>
#include "sha256.h"
#include "utils.h"

using namespace std;
using namespace emp;
using std::vector;

class HMAC_SHA256 : public SHA256 {
   public:
    int SHA256_call = 0;
    HMAC_SHA256(){};
    ~HMAC_SHA256(){};

    Integer o_key_pad;
    Integer i_key_pad;

    inline void init(Integer key) {
        refresh();
        SHA256_call = 0;

        Integer pad_key;

        if (key.size() > CHUNKLEN) {
            Integer* tmp = new Integer[DIGLEN];
            digest(tmp, key);
            SHA256_call++;
            concat(pad_key, tmp, DIGLEN);
            Integer ZEROS = Integer(CHUNKLEN - DIGLEN * WORDLEN, 0, PUBLIC);
            concat(pad_key, &ZEROS, 1);

            delete[] tmp;
        }
        if (key.size() <= CHUNKLEN) {
            pad_key = key;
            Integer ZEROS = Integer(CHUNKLEN - key.size(), 0, PUBLIC);
            concat(pad_key, &ZEROS, 1);
        }

        Integer hex5C = Integer(CHUNKLEN, 0x5c, PUBLIC);
        Integer hex36 = Integer(CHUNKLEN, 0x36, PUBLIC);
        Integer o_pad = Integer(CHUNKLEN, 0x5c, PUBLIC);
        Integer i_pad = Integer(CHUNKLEN, 0x36, PUBLIC);

        for (int i = 0; i < CHUNKLEN / 8 - 1; i++) {
            o_pad = (o_pad << 8) ^ hex5C;
            i_pad = (i_pad << 8) ^ hex36;
        }
        o_key_pad = pad_key ^ o_pad;
        i_key_pad = pad_key ^ i_pad;
    }

    inline void hmac_sha256(Integer* res, const Integer msg) {
        Integer i_msg = i_key_pad;
        concat(i_msg, &msg, 1);

        Integer* tmp_dig = new Integer[DIGLEN];
        digest(tmp_dig, i_msg);
        SHA256_call++;

        Integer o_msg = o_key_pad;
        concat(o_msg, tmp_dig, DIGLEN);

        digest(res, o_msg);
        SHA256_call++;

        delete[] tmp_dig;
    }

    void opt_hmac_sha256(Integer* res,
                         unsigned char* msg,
                         size_t len,
                         bool reuse_in_hash_flag = false,
                         bool reuse_out_hash_flag = false,
                         bool zk_flag = false) {
        uint32_t* dig = new uint32_t[DIGLEN];

        opt_digest(dig, i_key_pad, msg, len, reuse_in_hash_flag, zk_flag);
        SHA256_call++;
        Integer* o_msg = new Integer[DIGLEN];
        for (int i = 0; i < DIGLEN; i++) {
            o_msg[i] = Integer(32, dig[i], PUBLIC);
        }

        Integer omsg = o_key_pad;
        concat(omsg, o_msg, DIGLEN);

        digest(res, omsg, reuse_out_hash_flag);
        SHA256_call++;
        delete[] dig;
        delete[] o_msg;
    }
};

#endif
