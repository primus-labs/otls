#ifndef _HAND_SHAKE_H_
#define _HAND_SHAKE_H_
#include "emp-tool/emp-tool.h"
#include "cipher/hmac_sha256.h"
#include "cipher/aead.h"
//#include "cipher/aesgcm.h"
#include "cipher/prf.h"
#include "add.h"
#include "e2f.h"
#include "backend/switch.h"
#include "cipher/aead_izk.h"

using namespace emp;
using namespace std;

static unsigned char master_key_label[] = {"master key"};
static unsigned char key_expansion_label[] = {"key expansion"};
static unsigned char client_finished_label[] = {"client finished"};
static unsigned char server_finished_label[] = {"server finished"};

static size_t master_key_label_length = sizeof(master_key_label) - 1;
static size_t key_expansion_label_length = sizeof(key_expansion_label) - 1;
static size_t client_finished_label_length = sizeof(client_finished_label) - 1;
static size_t server_finished_label_length = sizeof(server_finished_label) - 1;

static size_t master_key_length = 384 / 8;
static size_t expansion_key_length = 448 / 8;
static const size_t finished_msg_length = 96 / 8;
static const size_t tag_length = 16;
static const size_t iv_length = 12;
static const size_t key_length = 128 / 8;

template <typename IO>
class HandShake {
   public:
    IO* io;
    HMAC_SHA256 hmac;
    PRF prf;
    E2F<IO>* e2f = nullptr;
    EC_GROUP* group = nullptr;
    BIGNUM* q;
    BN_CTX* ctx;

    BIGNUM* ta_pado;
    BIGNUM* tb_client;
    EC_POINT* Ta_client;
    EC_POINT* Ts;

    Integer zk_pms;
    BIGNUM* bn_pms;

    Integer master_key;
    Integer client_write_key;
    Integer server_write_key;

    unsigned char client_ufin[finished_msg_length];
    unsigned char server_ufin[finished_msg_length];
    unsigned char iv_oct[iv_length * 2];

    HandShake(IO* io, COT<IO>* ot, EC_GROUP* group) : io(io) {
        ctx = BN_CTX_new();
        this->group = group;
        q = BN_new();
        bn_pms = BN_new();
        ta_pado = BN_new();
        tb_client = BN_new();
        Ta_client = EC_POINT_new(this->group);
        Ts = EC_POINT_new(this->group);
        EC_GROUP_get_curve(group, q, NULL, NULL, ctx);
        e2f = new E2F<IO>(io, ot, q, BN_num_bits(q));
    }
    ~HandShake() {
        BN_CTX_free(ctx);
        BN_free(q);
        BN_free(bn_pms);
        BN_free(ta_pado);
        BN_free(tb_client);
        EC_POINT_free(Ta_client);
        EC_POINT_free(Ts);
        if (e2f != nullptr) {
            delete e2f;
        }
    }

    // The Ts value is received from the Server.
    inline void compute_pado_VA(EC_POINT* Va, const EC_POINT* Ts) {
        compute_pado_VA(Va, ta_pado, Ts);
    }

    inline void compute_pado_VA(EC_POINT* Va, BIGNUM* t, const EC_POINT* Ts) {
        // BN_rand(t, BN_num_bytes(q) * 8, 0, 0);
        // BN_mod(t, t, q, ctx);
        BN_rand_range(t, EC_GROUP_get0_order(group));

        EC_POINT* Ta = EC_POINT_new(group);
        if (!EC_POINT_mul(group, Ta, t, NULL, NULL, ctx))
            error("error in computing TA!\n");

        unsigned char buf[65];
        // Should compress the point.
        // size is 65 for secp256r1, should make it more general.
        int size = EC_POINT_point2oct(group, Ta, POINT_CONVERSION_UNCOMPRESSED, buf, 65, ctx);
        io->send_data(buf, size);
        //io->flush();

        if (!EC_POINT_mul(group, Va, NULL, Ts, t, ctx))
            error("error in computing VA!\n");

        EC_POINT_free(Ta);
    }

    // The Ts value is received from the Server.
    // The Tc value will be sent to the Server.
    inline void compute_client_VB(EC_POINT* Tc, EC_POINT* Vb, const EC_POINT* Ts) {
        BN_rand_range(tb_client, EC_GROUP_get0_order(group));
        EC_POINT* Tb = EC_POINT_new(group);
        if (!EC_POINT_mul(group, Tb, tb_client, NULL, NULL, ctx))
            error("error in computing TB!\n");

        // size is 65 for secp256r1, should make it more general.
        unsigned char buf[65];
        io->recv_data(buf, 65);

        if (!EC_POINT_oct2point(group, Ta_client, buf, 65, ctx))
            error("error in converting oct to TA\n");

        if (!EC_POINT_mul(group, Vb, NULL, Ts, tb_client, ctx))
            error("error in computing VB!\n");
        EC_POINT_add(group, Tc, Ta_client, Tb, ctx);

        EC_POINT_free(Tb);
    }

    inline void compute_client_VB(EC_POINT* Tc, EC_POINT* Vb, BIGNUM* t, const EC_POINT* Ts) {
        // BN_rand(t, BN_num_bytes(q) * 8, 0, 0);
        // BN_mod(t, t, q, ctx);
        BN_rand_range(t, EC_GROUP_get0_order(group));

        EC_POINT* Tb = EC_POINT_new(group);
        if (!EC_POINT_mul(group, Tb, t, NULL, NULL, ctx))
            error("error in computing TB!\n");

        EC_POINT* Ta = EC_POINT_new(group);

        // size is 65 for secp256r1, should make it more general.
        unsigned char buf[65];
        io->recv_data(buf, 65);

        if (!EC_POINT_oct2point(group, Ta, buf, 65, ctx))
            error("error in converting oct to TA\n");

        if (!EC_POINT_mul(group, Vb, NULL, Ts, t, ctx))
            error("error in computing VB!\n");
        EC_POINT_add(group, Tc, Ta, Tb, ctx);

        EC_POINT_free(Tb);
        EC_POINT_free(Ta);
    }

    inline void compute_pms_offline(int party) { e2f->compute_offline(party); }

    inline void compute_pms_online(BIGNUM* pms, const EC_POINT* V, int party) {
        BIGNUM* x = BN_new();
        BIGNUM* y = BN_new();

        EC_POINT_get_affine_coordinates(group, V, x, y, ctx);
        e2f->compute_online(pms, x, y, party);

        // store arithmetic shares of pms;
        BN_copy(bn_pms, pms);

        BN_free(x);
        BN_free(y);
    }

    inline void compute_master_key(const BIGNUM* pms,
                                   const unsigned char* rc,
                                   size_t rc_len,
                                   const unsigned char* rs,
                                   size_t rs_len) {
        size_t len = BN_num_bytes(pms);
        unsigned char* buf = new unsigned char[len];
        BN_bn2bin(pms, buf);
        reverse(buf, buf + len);
        Integer pmsa, pmsb;

        // commit the IT-MAC of zk_2 in addmod.
        switch_to_zk();
        zk_pms = Integer(len * 8, buf, ALICE);
        sync_zk_gc<IO>();
        switch_to_gc();

        pmsa = Integer(len * 8, buf, ALICE);
        pmsb = Integer(len * 8, buf, BOB);

        Integer pmsbits;
        addmod(pmsbits, pmsa, pmsb, q);

        size_t seed_len = rc_len + rs_len;
        unsigned char* seed = new unsigned char[seed_len];
        memcpy(seed, rc, rc_len);
        memcpy(seed + rc_len, rs, rs_len);

        prf.init(hmac, pmsbits);
        prf.opt_compute(hmac, master_key, master_key_length * 8, pmsbits, master_key_label,
                        master_key_label_length, seed, seed_len, true, true);

        delete[] seed;
        delete[] buf;
    }

    inline void compute_expansion_keys(const unsigned char* rc,
                                       size_t rc_len,
                                       const unsigned char* rs,
                                       size_t rs_len) {
        size_t seed_len = rc_len + rs_len;
        unsigned char* seed = new unsigned char[seed_len];
        memcpy(seed, rs, rs_len);
        memcpy(seed + rs_len, rc, rc_len);

        Integer key;
        prf.init(hmac, master_key);
        prf.opt_compute(hmac, key, expansion_key_length * 8, master_key, key_expansion_label,
                        key_expansion_label_length, seed, seed_len, true, true);
        Integer iv;
        iv.bits.insert(iv.bits.begin(), key.bits.begin(),
                       key.bits.begin() + iv_length * 8 * 2);
        server_write_key.bits.insert(server_write_key.bits.begin(),
                                     key.bits.begin() + 2 * iv_length * 8,
                                     key.bits.begin() + 2 * iv_length * 8 + key_length * 8);
        client_write_key.bits.insert(client_write_key.bits.begin(),
                                     key.bits.begin() + 2 * iv_length * 8 + key_length * 8,
                                     key.bits.begin() + 2 * (iv_length * 8 + key_length * 8));

        iv.reveal<unsigned char>((unsigned char*)iv_oct, PUBLIC);
        delete[] seed;
    }

    inline void compute_master_and_expansion_keys(Integer& ms,
                                                  Integer& key,
                                                  const BIGNUM* pms,
                                                  const unsigned char* rc,
                                                  size_t rc_len,
                                                  const unsigned char* rs,
                                                  size_t rs_len,
                                                  int party) {
        size_t len = BN_num_bytes(pms);
        unsigned char* buf = new unsigned char[len];
        BN_bn2bin(pms, buf);
        reverse(buf, buf + len);
        Integer pmsa, pmsb;

        // commit the IT-MAC of zk_2 in addmod.
        switch_to_zk();
        zk_pms = Integer(len * 8, buf, ALICE);
        sync_zk_gc<IO>();
        switch_to_gc();

        // if (party == ALICE) {
        //     pmsa = Integer(len * 8, buf, ALICE);
        //     pmsb = Integer(len * 8, 0, BOB);
        // } else {
        //     pmsa = Integer(len * 8, 0, ALICE);
        //     pmsb = Integer(len * 8, buf, BOB);
        // }

        pmsa = Integer(len * 8, buf, ALICE);
        pmsb = Integer(len * 8, buf, BOB);

        Integer pmsbits;
        addmod(pmsbits, pmsa, pmsb, q);

        size_t seed_len = rc_len + rs_len;
        unsigned char* seed = new unsigned char[seed_len];
        memcpy(seed, rc, rc_len);
        memcpy(seed + rc_len, rs, rs_len);

        prf.init(hmac, pmsbits);
        prf.opt_compute(hmac, ms, master_key_length * 8, pmsbits, master_key_label,
                        master_key_label_length, seed, seed_len, true, true);

        memcpy(seed, rs, rs_len);
        memcpy(seed + rs_len, rc, rc_len);

        prf.init(hmac, ms);
        prf.opt_compute(hmac, key, expansion_key_length * 8, ms, key_expansion_label,
                        key_expansion_label_length, seed, seed_len, true, true);

        delete[] buf;
        delete[] seed;
    }

    inline void compute_finished_msg(unsigned char* ufin,
                                     const Integer& ms,
                                     const unsigned char* label,
                                     size_t label_len,
                                     const unsigned char* tau,
                                     size_t tau_len) {
        Integer ufin_int;
        prf.opt_compute(hmac, ufin_int, finished_msg_length * 8, ms, label, label_len, tau,
                        tau_len, true, true);
        ufin_int.reveal<unsigned char>((unsigned char*)ufin, PUBLIC);
    }

    inline void compute_client_finished_msg(const unsigned char* label,
                                            size_t label_len,
                                            const unsigned char* tau,
                                            size_t tau_len) {
        Integer ufin_int;
        prf.opt_compute(hmac, ufin_int, finished_msg_length * 8, master_key, label, label_len,
                        tau, tau_len, true, true);
        ufin_int.reveal<unsigned char>((unsigned char*)client_ufin, PUBLIC);
    }

    inline void compute_server_finished_msg(const unsigned char* label,
                                            size_t label_len,
                                            const unsigned char* tau,
                                            size_t tau_len) {
        Integer ufin_int;
        prf.opt_compute(hmac, ufin_int, finished_msg_length * 8, master_key, label, label_len,
                        tau, tau_len, true, true);
        ufin_int.reveal<unsigned char>((unsigned char*)server_ufin, PUBLIC);
    }

    inline void encrypt_client_finished_msg(AEAD<IO>* aead_c,
                                            unsigned char* ctxt,
                                            unsigned char* tag,
                                            const unsigned char* aad,
                                            size_t aad_len,
                                            int party) {
        aead_c->encrypt(io, ctxt, tag, client_ufin, finished_msg_length, aad, aad_len, party);
    }

    inline void encrypt_client_finished_msg(AEAD<IO>& aead_c,
                                            unsigned char* ctxt,
                                            unsigned char* tag,
                                            const unsigned char* ufinc,
                                            const unsigned char* aad,
                                            size_t aad_len,
                                            int party) {
        aead_c.enc_finished_msg(io, ctxt, tag, ufinc, finished_msg_length, aad, aad_len,
                                party);
    }

    // The ufins string is computed by pado and client, need to check the equality with the decrypted string
    inline bool decrypt_and_check_server_finished_msg(AEAD<IO>* aead_s,
                                                      const unsigned char* ctxt,
                                                      const unsigned char* tag,
                                                      const unsigned char* aad,
                                                      size_t aad_len,
                                                      int party) {
        unsigned char* msg = new unsigned char[finished_msg_length];
        bool res1 =
          aead_s->decrypt(io, msg, ctxt, finished_msg_length, tag, aad, aad_len, party);

        bool res2 = (memcmp(msg, server_ufin, finished_msg_length) == 0);
        delete[] msg;
        return res1 & res2;
    }

    inline bool decrypt_and_check_server_finished_msg(AEAD<IO>& aead_s,
                                                      const unsigned char* ufins,
                                                      const unsigned char* ctxt,
                                                      const unsigned char* tag,
                                                      const unsigned char* aad,
                                                      size_t aad_len,
                                                      int party) {
        unsigned char* msg = new unsigned char[finished_msg_length];
        bool res1 = aead_s.dec_finished_msg(io, msg, ctxt, finished_msg_length, tag, aad,
                                            aad_len, party);

        bool res2 = (memcmp(msg, ufins, finished_msg_length) == 0);
        delete[] msg;

        return res1 & res2;
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

        if (party == ALICE)
            BN_mod_sub(bn_pms, pms, bn_pms, q, ctx);

        BN_bn2bin(bn_pms, buf);
        reverse(buf, buf + len);
        Integer z1(len * 8, buf, PUBLIC);

        Integer pmsbits;
        addmod(pmsbits, z1, zk_pms, q);

        size_t seed_len = rc_len + rs_len;
        unsigned char* seed = new unsigned char[seed_len];
        memcpy(seed, rc, rc_len);
        memcpy(seed + rc_len, rs, rs_len);

        prf.init(hmac, pmsbits);
        prf.opt_compute(hmac, ms, master_key_length * 8, pmsbits, master_key_label,
                        master_key_label_length, seed, seed_len, true, true, true);

        delete[] seed;
        delete[] buf;
    }

    inline void prove_expansion_keys(Integer& key_c,
                                     Integer& key_s,
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
                        key_expansion_label_length, seed, seed_len, true, true, true);
        Integer iv;
        iv.bits.insert(iv.bits.begin(), key.bits.begin(),
                       key.bits.begin() + iv_length * 8 * 2);

        key_s.bits.insert(key_s.bits.begin(), key.bits.begin() + 2 * iv_length * 8,
                          key.bits.begin() + 2 * iv_length * 8 + key_length * 8);
        key_c.bits.insert(key_c.bits.begin(),
                          key.bits.begin() + 2 * iv_length * 8 + key_length * 8,
                          key.bits.begin() + 2 * (iv_length * 8 + key_length * 8));

        check_zero<IO>(iv, iv_oct, iv_length * 2, party);

        // Integer expected_iv(iv_length * 8 * 2, iv_oct, PUBLIC);
        // Integer diff = iv ^ expected_iv;
        // check_zero<IO>(diff, party);

        delete[] seed;
    }

    inline void prove_client_finished_msg(const Integer& ms,
                                          const unsigned char* label,
                                          size_t label_len,
                                          const unsigned char* tau,
                                          size_t tau_len,
                                          int party) {
        Integer ufin;
        prf.opt_compute(hmac, ufin, finished_msg_length * 8, ms, label, label_len, tau,
                        tau_len, true, true, true);
        check_zero<IO>(ufin, client_ufin, finished_msg_length, party);
    }

    inline void prove_server_finished_msg(const Integer& ms,
                                          const unsigned char* label,
                                          size_t label_len,
                                          const unsigned char* tau,
                                          size_t tau_len,
                                          int party) {
        Integer ufin;
        prf.opt_compute(hmac, ufin, finished_msg_length * 8, ms, label, label_len, tau,
                        tau_len, true, true, true);
        check_zero<IO>(ufin, server_ufin, finished_msg_length, party);
    }

    inline void prove_enc_dec_finished_msg(AEAD_Proof<IO>* aead_proof_c,
                                           const unsigned char* ctxt) {
        // Dummy variable.
        Integer msg;
        aead_proof_c->prove_aead(msg, ctxt, finished_msg_length);
    }

    inline void handshake_check(int party) {
        prf.prf_check<IO>(party);
        hmac.sha256_check<IO>(party);
    }
};

#endif