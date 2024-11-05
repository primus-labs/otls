/* 
    This is for the proxy model, which does not need MPC to run the handshake and record phase. 
    The proxy will keep and forward all the TLS transcripts. 
    The client will prove (with interactive zkp) to the proxy (verifier) 
    that he knows the session key (and possibly some private message) encrypted under the given ciphertexts.
*/

#ifndef _PRFPROVER_
#define _PRFPROVER_

#include "emp-tool/emp-tool.h"
#include "cipher/utils.h"
#include "protocol/handshake.h"

/*
 * The PRF Prover
 */
class PRFProver {
    public:
    HMAC_SHA256 hmac;
    PRF prf;
    EC_GROUP* group = nullptr;
    BIGNUM* q;
    BN_CTX* ctx;
    bool reuse_in_hash_flag = true;
    bool reuse_out_hash_flag = true;
    bool zk_flag = false;

    PRFProver() {
        group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        q = BN_new();
        ctx = BN_CTX_new();
        EC_GROUP_get_curve(group, q, NULL, NULL, ctx);
    }
    ~PRFProver() {
        EC_GROUP_free(group);
        BN_free(q);
        BN_CTX_free(ctx);
    }

    // ALICE knows pms, which is the entire value, not a share.
    inline void prove_master_key(Integer& ms,
                                 const BIGNUM* pms,
                                 const unsigned char* rc,
                                 size_t rc_len,
                                 const unsigned char* rs,
                                 size_t rs_len,
                                 int party) {
        size_t len = BN_num_bytes(q);
        unsigned char* buf = new unsigned char[len];
        memset(buf, 0, len);

        if (party == ALICE) {
            size_t pms_len = BN_num_bytes(pms);
            BN_bn2bin(pms, buf + (len - pms_len));
            reverse(buf, buf + len);
        }
        Integer pmsbits(len * 8, buf, ALICE);

        size_t seed_len = rc_len + rs_len;
        unsigned char* seed = new unsigned char[seed_len];
        memcpy(seed, rc, rc_len);
        memcpy(seed + rc_len, rs, rs_len);

        prf.init(hmac, pmsbits);
        prf.opt_compute(hmac, ms, master_key_length * 8, pmsbits, master_key_label,
                        master_key_label_length, seed, seed_len, reuse_in_hash_flag, reuse_out_hash_flag, zk_flag);

        delete[] seed;
        delete[] buf;
    }

    // ALICE knows pms, which is the entire value, not a share.
    inline void prove_extended_master_key(Integer& ms,
                                          const BIGNUM* pms,
                                          const unsigned char* session_hash,
                                          size_t hash_len,
                                          int party) {
        size_t len = BN_num_bytes(q);
        unsigned char* buf = new unsigned char[len];
        memset(buf, 0, len);

        if (party == ALICE) {
            size_t pms_len = BN_num_bytes(pms);
            BN_bn2bin(pms, buf + (len - pms_len));
            reverse(buf, buf + len);
        }
        Integer pmsbits(len * 8, buf, ALICE);

        prf.init(hmac, pmsbits);
        prf.opt_compute(hmac, ms, extended_master_key_length * 8, pmsbits,
                        extended_master_key_label, extended_master_key_label_length,
                        session_hash, hash_len, reuse_in_hash_flag, reuse_out_hash_flag, zk_flag);

        delete[] buf;
    }

    inline void prove_expansion_keys(Integer& key_c,
                                     Integer& key_s,
                                     Integer& iv_c,
                                     Integer& iv_s,
                                     const Integer& ms,
                                     const unsigned char* rc,
                                     size_t rc_len,
                                     const unsigned char* rs,
                                     size_t rs_len,
                                     int party) {
        size_t seed_len = rc_len + rs_len;
        unsigned char* seed = new unsigned char[seed_len];
        memcpy(seed, rs, rs_len);
        memcpy(seed + rs_len, rc, rc_len);

        Integer key;
        prf.init(hmac, ms);
        prf.opt_compute(hmac, key, expansion_key_length * 8, ms, key_expansion_label,
                        key_expansion_label_length, seed, seed_len, reuse_in_hash_flag, reuse_out_hash_flag, zk_flag);

        extract_integer(key_c, key, 0, key_length * 8);
        extract_integer(key_s, key, key_length * 8, key_length * 8);

        extract_integer(iv_c, key, key_length * 8 * 2, iv_length * 8);
        extract_integer(iv_s, key, key_length * 8 * 2 + iv_length * 8, iv_length * 8);

        delete[] seed;
    }

    inline void prove_client_finished_msg(Integer& ufin,
                                          const Integer& ms,
                                          const unsigned char* tau,
                                          size_t tau_len,
                                          int party) {
        prf.opt_compute(hmac, ufin, finished_msg_length * 8, ms, client_finished_label, client_finished_label_length, tau,
                        tau_len, reuse_in_hash_flag, reuse_out_hash_flag, zk_flag);
    }

    inline void prove_server_finished_msg(Integer& ufin,
                                          const Integer& ms,
                                          const unsigned char* tau,
                                          size_t tau_len,
                                          int party) {
        prf.opt_compute(hmac, ufin, finished_msg_length * 8, ms, server_finished_label, server_finished_label_length, tau,
                        tau_len, reuse_in_hash_flag, reuse_out_hash_flag, zk_flag);
    }

};

#endif
