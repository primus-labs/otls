#ifndef _IZK_H_
#define _IZK_H_
#include "emp-tool/emp-tool.h"
#include "cipher/hmac_sha256.h"
#include "cipher/aead_izk.h"
#include "cipher/prf.h"
#include "handshake.h"
#include "add.h"
#include "e2f.h"

using namespace emp;
using namespace std;

template <typename IO>
class IZK {
   public:
    HMAC_SHA256 hmac;
    PRF prf;
    BIGNUM* q;
    BN_CTX* ctx;
    EC_GROUP* group = nullptr;

    IZK(EC_GROUP* group) {
        ctx = BN_CTX_new();
        this->group = group;
        q = BN_new();
        EC_GROUP_get_curve(group, q, NULL, NULL, ctx);
    }
    ~IZK() {
        BN_CTX_free(ctx);
        BN_free(q);
    }

    inline void prove_master_and_expansion_keys(Integer& ms,
                                                Integer& key,
                                                const BIGNUM* pms_a,
                                                const BIGNUM* pms_b,
                                                const unsigned char* rc,
                                                size_t rc_len,
                                                const unsigned char* rs,
                                                size_t rs_len,
                                                int party) {
        size_t len = 32; //BN_num_bytes(pms_a);
        assert(len == BN_num_bytes(pms_b));

        unsigned char* bufa = new unsigned char[len];
        unsigned char* bufb = new unsigned char[len];
        // BN_bn2bin(pms_a, bufa);
        // reverse(bufa, bufa + len);

        memset(bufa, 11, len);

        BN_bn2bin(pms_b, bufb);
        reverse(bufb, bufb + len);

        Integer pmsa, pmsb;
        pmsa = Integer(len * 8, bufa, PUBLIC);
        pmsb = Integer(len * 8, bufb, ALICE);

        Integer pmsbits;
        addmod(pmsbits, pmsa, pmsb, q);
        size_t seed_len = rc_len + rs_len;
        unsigned char* seed = new unsigned char[seed_len];
        memcpy(seed, rc, rc_len);
        memcpy(seed + rc_len, rs, rs_len);

        prf.init(hmac, pmsbits);
        prf.opt_compute(hmac, ms, master_key_bit_length, pmsbits, master_key_label,
                        master_key_label_length, seed, seed_len, true, true);

        memcpy(seed, rs, rs_len);
        memcpy(seed + rs_len, rc, rc_len);

        prf.init(hmac, ms);
        prf.opt_compute(hmac, key, expansion_key_bit_length, ms, key_expansion_label,
                        key_expansion_label_length, seed, seed_len, true, true);

        delete[] seed;
        delete[] bufa;
        delete[] bufb;
    }

    inline void prove_compute_finished_msg(unsigned char* ufin,
                                           const Integer& ms,
                                           const unsigned char* label,
                                           size_t label_len,
                                           const unsigned char* tau,
                                           size_t tau_len) {
        Integer ufin_int;
        prf.opt_compute(hmac, ufin_int, finished_msg_bit_length, ms, label, label_len, tau,
                        tau_len, true, true);
        ufin_int.reveal<unsigned char>((unsigned char*)ufin, PUBLIC);
    }

    inline void prove_encrypt_client_finished_msg(AEAD_IZK& aead_izk_c,
                                                  Integer& ctxt,
                                                  size_t msg_len) {
        aead_izk_c.enc_and_dec_msg(ctxt, msg_len);
    }

    inline void prove_decrypt_server_finished_msg(AEAD_IZK& aead_izk_s,
                                                  Integer& msg,
                                                  size_t ctxt_len) {
        aead_izk_s.enc_and_dec_msg(msg, ctxt_len);
    }

    inline void prove_encrypt_record_msg(AEAD_IZK& aead_izk_c, Integer& ctxt, size_t msg_len) {
        aead_izk_c.enc_and_dec_msg(ctxt, msg_len);
    }

    inline void prove_decrypt_record_msg(AEAD_IZK& aead_izk_s, Integer& msg, size_t ctxt_len) {
        aead_izk_s.enc_and_dec_msg(msg, ctxt_len);
    }
};
#endif