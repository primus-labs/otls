#ifndef _POST_RECORD_
#define _POST_RECORD_
#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-zk.h"
#include "protocol/handshake.h"
#include "protocol/aead_izk.h"
#include "protocol/record.h"

using namespace emp;

template <typename IO>
class PostRecord {
   public:
    IO* io;
    HandShake<IO>* hs = nullptr;
    AEAD<IO>* aead_c = nullptr;
    AEAD<IO>* aead_s = nullptr;
    AEAD_Proof<IO>* aead_proof_c = nullptr;
    AEAD_Proof<IO>* aead_proof_s = nullptr;
    Record<IO>* rd = nullptr;
    BIGNUM* pms;
    Integer master_key;
    Integer client_write_key;
    Integer server_write_key;
    Integer client_write_iv;
    Integer server_write_iv;
    Integer client_finished_z0;
    Integer server_finished_z0;
    int party;
    PostRecord(IO* io,
               HandShake<IO>* hs,
               AEAD<IO>* aead_c,
               AEAD<IO>* aead_s,
               Record<IO>* rd,
               int party) {
        this->io = io;
        this->aead_c = aead_c;
        this->aead_s = aead_s;
        this->hs = hs;
        this->rd = rd;
        this->party = party;
        pms = BN_new();
    }

    ~PostRecord() {
        BN_free(pms);
        if (aead_proof_c != nullptr)
            delete aead_proof_c;
        if (aead_proof_s != nullptr)
            delete aead_proof_s;
    }

    inline void reveal_pms(EC_POINT* Ts) {
        if (party == BOB) {
            send_bn(io, hs->ta_primus);
        } else {
            BIGNUM* t = BN_new();
            recv_bn(io, t);
            EC_POINT* T = EC_POINT_new(hs->group);
            EC_POINT_mul(hs->group, T, t, NULL, NULL, hs->ctx);
            // Check Ta = G^ta
            if (EC_POINT_cmp(hs->group, T, hs->Ta_client, hs->ctx))
                error("Ta is not consistent!\n");

            // Get pms
            BN_mod_add(t, t, hs->tb_client, EC_GROUP_get0_order(hs->group), hs->ctx);
            EC_POINT_mul(hs->group, T, NULL, Ts, t, hs->ctx);
            EC_POINT_get_affine_coordinates(hs->group, T, pms, NULL, hs->ctx);

            BN_free(t);
            EC_POINT_free(T);
        }
    }

    inline void prove_and_check_handshake_step1(const unsigned char* rc,
                                                size_t rc_len,
                                                const unsigned char* rs,
                                                size_t rs_len,
                                                const unsigned char* tau_c,
                                                size_t tau_c_len,
                                                const unsigned char* tau_s,
                                                size_t tau_s_len,
                                                const unsigned char* session_hash,
                                                size_t hash_len,
                                                bool is_extended_master_key = false) {
        if (is_extended_master_key) {
            hs->prove_extended_master_key(master_key, pms, session_hash, hash_len, party);
        } else {
            hs->prove_master_key(master_key, pms, rc, rc_len, rs, rs_len, party);
        }
        hs->prove_expansion_keys(client_write_key, server_write_key, client_write_iv,
                                 server_write_iv, master_key, rc, rc_len, rs, rs_len, party);

        hs->prove_client_finished_msg(master_key, client_finished_label,
                                      client_finished_label_length, tau_c, tau_c_len, party);

        hs->prove_server_finished_msg(master_key, server_finished_label,
                                      server_finished_label_length, tau_s, tau_s_len, party);

        aead_proof_c = new AEAD_Proof<IO>(aead_c, client_write_key, client_write_iv, party);
        aead_proof_s = new AEAD_Proof<IO>(aead_s, server_write_key, server_write_iv, party);
    }

    inline void prove_and_check_handshake_step2(const unsigned char* finc_ctxt,
                                                size_t finc_ctxt_len,
                                                const unsigned char* client_iv,
                                                size_t client_iv_len) {
        hs->prove_enc_dec_finished_msg(aead_proof_c, client_finished_z0, finc_ctxt,
                                       finc_ctxt_len, client_iv, client_iv_len);
    }

    inline void prove_and_check_handshake_step3(const unsigned char* fins_ctxt,
                                                size_t fins_ctxt_len,
                                                const unsigned char* server_iv,
                                                size_t server_iv_len) {
        hs->prove_enc_dec_finished_msg(aead_proof_s, server_finished_z0, fins_ctxt,
                                       fins_ctxt_len, server_iv, server_iv_len);
        hs->handshake_check(party);
    }

    inline void prove_record_client(Integer& msg,
                                    Integer& z0,
                                    const unsigned char* ctxt,
                                    size_t ctxt_len,
                                    const unsigned char* iv,
                                    size_t iv_len) {
        aead_proof_c->prove_aead(msg, z0, ctxt, ctxt_len, iv, iv_len, true);
    }

    // Note that this function should be invoke for every message from server.
    inline void prove_record_server(Integer& msg,
                                    Integer& z0,
                                    const unsigned char* ctxt,
                                    size_t ctxt_len,
                                    const unsigned char* iv,
                                    size_t iv_len) {
        aead_proof_s->prove_aead(msg, z0, ctxt, ctxt_len, iv, iv_len, true);
    }

    // Invoke this function for the last ciphertext from server.
    inline void prove_record_server_last(Integer& msg,
                                         Integer& z0,
                                         const unsigned char* ctxt,
                                         size_t ctxt_len,
                                         const unsigned char* iv,
                                         size_t iv_len) {
        aead_proof_s->prove_aead_last(msg, z0, ctxt, ctxt_len, iv, iv_len);
    }

    // 1. check encrypting client finished message (check tag)
    // 2. check decrypting server finished message (check tag)
    // 3. check encrypting record message sent to server, multiple messages.
    // 4. check decrypting record message recv from server, multiple messages.
    inline bool finalize_check(const unsigned char* finc_ctxt,
                               const unsigned char* finc_tag,
                               size_t finc_len,
                               const unsigned char* finc_aad,
                               const unsigned char* fins_ctxt,
                               const unsigned char* fins_tag,
                               size_t fins_len,
                               const unsigned char* fins_aad,
                               const vector<Integer> enc_z0s,
                               const vector<unsigned char*> enc_ctxts,
                               const vector<unsigned char*> enc_tags,
                               const vector<size_t> enc_ctxts_len,
                               const vector<unsigned char*> enc_aads,
                               size_t enc_num,
                               const vector<Integer> dec_z0s,
                               const vector<unsigned char*> dec_ctxts,
                               const vector<unsigned char*> dec_tags,
                               const vector<size_t> dec_ctxts_len,
                               const vector<unsigned char*> dec_aads,
                               size_t dec_num,
                               size_t aad_len) {
        Integer h;
        reverse_concat(h, &(aead_proof_c->H), 1);
        reverse_concat(h, &(aead_proof_s->H), 1);
        reverse_concat(h, &client_finished_z0, 1);
        reverse_concat(h, &server_finished_z0, 1);
        reverse_concat(h, enc_z0s.data(), enc_num);
        reverse_concat(h, dec_z0s.data(), dec_num);

        block* blks_h = new block[4 + enc_num + dec_num];
        h.reveal<block>((block*)blks_h, PUBLIC);

        bool res = true;
        res &=
          compare_tag(finc_tag, blks_h[0], blks_h[2], finc_ctxt, finc_len, finc_aad, aad_len);
        res &=
          compare_tag(fins_tag, blks_h[1], blks_h[3], fins_ctxt, fins_len, fins_aad, aad_len);
        for (size_t i = 0; i < enc_num; i++)
            res &= compare_tag(enc_tags[i], blks_h[0], blks_h[4 + i], enc_ctxts[i],
                               enc_ctxts_len[i], enc_aads[i], aad_len);
        for (size_t i = 0; i < dec_num; i++)
            res &= compare_tag(dec_tags[i], blks_h[1], blks_h[4 + enc_num + i], dec_ctxts[i],
                               dec_ctxts_len[i], dec_aads[i], aad_len);

        delete[] blks_h;
        return res;
    }
};
#endif
