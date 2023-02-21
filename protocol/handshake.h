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

static size_t master_key_bit_length = 384;
static size_t expansion_key_bit_length = 448;
static size_t finished_msg_bit_length = 96;
static size_t tag_byte_len = 16;

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

    Integer zkPMS_ALICE;

    HandShake(IO* io, COT<IO>* ot, EC_GROUP* group) : io(io) {
        ctx = BN_CTX_new();
        this->group = group;
        q = BN_new();
        EC_GROUP_get_curve(group, q, NULL, NULL, ctx);
        e2f = new E2F<IO>(io, ot, q, BN_num_bits(q));
    }
    ~HandShake() {
        BN_CTX_free(ctx);
        BN_free(q);
        if (e2f != nullptr) {
            delete e2f;
        }
    }

    // The Ts value is received from the Server.
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

        BN_free(x);
        BN_free(y);
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

        switch_to_zk();
        if (party == ALICE) {
            zkPMS_ALICE = Integer(len * 8, buf, ALICE);
        } else {
            zkPMS_ALICE = Integer(len * 8, 0, ALICE);
        }
        sync_zk_gc<IO>();
        switch_to_gc();

        if (party == ALICE) {
            pmsa = Integer(len * 8, buf, ALICE);
            pmsb = Integer(len * 8, 0, BOB);
        } else {
            pmsa = Integer(len * 8, 0, ALICE);
            pmsb = Integer(len * 8, buf, BOB);
        }

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
        prf.opt_compute(hmac, ufin_int, finished_msg_bit_length, ms, label, label_len, tau,
                        tau_len, true, true);
        ufin_int.reveal<unsigned char>((unsigned char*)ufin, PUBLIC);
    }

    inline void encrypt_client_finished_msg(AEAD<IO>& aead_c,
                                            unsigned char* ctxt,
                                            unsigned char* tag,
                                            const unsigned char* ufinc,
                                            const unsigned char* aad,
                                            size_t aad_len,
                                            int party) {
        aead_c.enc_finished_msg(io, ctxt, tag, ufinc, finished_msg_bit_length / 8, aad,
                                aad_len, party);
    }

    // The ufins string is computed by pado and client, need to check the equality with the decrypted string
    inline bool decrypt_and_check_server_finished_msg(AEAD<IO>& aead_s,
                                                      const unsigned char* ufins,
                                                      const unsigned char* ctxt,
                                                      const unsigned char* tag,
                                                      const unsigned char* aad,
                                                      size_t aad_len,
                                                      int party) {
        unsigned char* msg = new unsigned char[finished_msg_bit_length / 8];
        bool res1 = aead_s.dec_finished_msg(io, msg, ctxt, finished_msg_bit_length / 8, tag,
                                            aad, aad_len, party);

        bool res2 = (memcmp(msg, ufins, finished_msg_bit_length / 8) == 0);
        delete[] msg;

        return res1 & res2;
    }
};

#endif