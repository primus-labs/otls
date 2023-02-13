#include "mpc_tls.h"
#include <openssl/mpc_tls_meth.h>
#include "protocol/handshake.h"
#include "backend/backend.h"
#include <iostream>
#include "cipher/prf.h"
#include <openssl/bn.h>

using namespace std;
using namespace emp;

static EC_GROUP* g_group = nullptr;
static int g_party = -1;
static HandShake<NetIO>* g_hs = nullptr;
static NetIO* g_io = nullptr;
static IKNP<NetIO>* g_cot = nullptr;
static BN_CTX* g_ctx = nullptr;
static BIGNUM* g_q = nullptr;
static BIGNUM* g_priv_key = nullptr;
static EC_POINT* g_pub_key = nullptr;

int init_mpc(int party) {
    g_io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", 8081);
    setup_backend(g_io, party);
    auto prot = (PADOParty<NetIO>*)(ProtocolExecution::prot_exec);
    g_cot = prot->ot;

    g_party = party;

    g_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    g_hs = new HandShake<NetIO>(g_io, g_cot, g_group);
    g_ctx = g_hs->ctx;
    g_q = g_hs->q;

    g_priv_key = BN_new();
    BN_rand_range(g_priv_key, g_q);
    g_pub_key = EC_POINT_new(g_group);
    EC_POINT_mul(g_group, g_pub_key, g_priv_key, NULL, NULL, g_ctx);

    return 1;
}

EC_POINT* EC_POINT_new_mpc() {
    return EC_POINT_new(g_group);
}

void EC_POINT_free_mpc(EC_POINT* p) {
    return EC_POINT_free(p);
}

static int send_point(EC_POINT* pub_key) {
    unsigned char buf[65];
    int size = EC_POINT_point2oct(g_group, pub_key, POINT_CONVERSION_UNCOMPRESSED, buf, 65, g_ctx);
    printf("begin send point:%d\n", size);
    g_io->send_data(buf, size);
    g_io->flush();
    printf("end send point\n");
    return 1;
}

static int recv_point(EC_POINT* pub_key) {
    unsigned char buf[65];
    printf("begin recv point:%d\n", 65);
    g_io->recv_data(buf, 65);
    printf("end recv point\n");

    if (!EC_POINT_oct2point(g_group, pub_key, buf, 65, g_ctx))
        printf("error in converting oct to TA\n");
    return 1;
}

int set_priv_key_mpc(BIGNUM* priv_key) {
    BN_copy(g_priv_key, priv_key);
    EC_POINT_mul(g_group, g_pub_key, g_priv_key, NULL, NULL, g_ctx);

    return 1;
}
    
int EC_POINT_mul_mpc(EC_POINT* out, EC_POINT* pub_key) {
    if (g_party == ALICE) {
        recv_point(pub_key);
    } else {
        send_point(pub_key);
    }

    EC_POINT_mul(g_group, out, NULL, pub_key, g_priv_key, g_ctx);
    
    printf("finish ec point mul mpc\n");
    return 1;
}

int get_client_pub_key_mpc(EC_POINT* out) {
    if (g_party == ALICE) {
        send_point(g_pub_key);
    } else {
        EC_POINT* tmp = EC_POINT_new(g_group);
        recv_point(tmp);

        EC_POINT_add(g_group, out, tmp, g_pub_key, g_ctx);
        EC_POINT_free(tmp);
    }
    printf("finish get client pub key mpc\n");

    return 1;
}

int get_pms_mpc(BIGNUM *pms, EC_POINT* Z) {
    g_hs->compute_pms_offline(g_party);

    g_hs->compute_pms_online(pms, Z, g_party);
    printf("finish get pms mpc\n");
    return 1;
}
    
static Integer g_iv, g_key_c, g_key_s;
static unsigned char g_iv_oct[8];
static unsigned char g_fixed_iv_c[4];
static unsigned char g_fixed_iv_s[4];
static AESGCM<NetIO> *g_aead_c = NULL;
static AESGCM<NetIO> *g_aead_s = NULL;
static Integer* g_block_key = NULL;
static Integer* g_ms = NULL;
static Integer* g_finish_mac = NULL;
int tls1_prf_P_hash_mpc(const unsigned char* sec, size_t sec_len, const unsigned char* seed, size_t seed_len, unsigned char* out, size_t olen) {
        Integer *pmsbits;
        if (sec_len == 32) {
            char* buf = new char[sec_len];
            for (int i = 0; i < sec_len; i++) {
            buf[i] = sec[sec_len - 1 - i];
        }
        Integer pmsa, pmsb;

        if (g_party == ALICE) {
            pmsa = Integer(sec_len * 8, buf, ALICE);
            pmsb = Integer(sec_len * 8, 0, BOB);
        } else {
            pmsa = Integer(sec_len * 8, 0, ALICE);
            pmsb = Integer(sec_len * 8, buf, BOB);
        }
        
        pmsbits = new Integer();
        addmod(*pmsbits, pmsa, pmsb, g_q);
        delete []buf;
    }
    else {
        pmsbits = g_ms;
    }

    unsigned char* pms_oct = new unsigned char[1024];
    pmsbits->reveal<unsigned char>((unsigned char*)pms_oct, PUBLIC);
    printf("reveal pms[%d]:", sec_len);
    for (int i = 0; i < sec_len; i++) {
        printf("%2x ", pms_oct[sec_len - 1 - i]);
    }
    printf("\n");

    printf("reveal seed[%d]:", seed_len);
    for (int i = 0; i < seed_len; i++) {
        printf("%2x ", seed[i]);
    }
    printf("\n");

    PRF prf;
    HMAC_SHA256 hmac;
    printf("hmac diglen:%d wordlen:%d olen:%d\n", hmac.DIGLEN, hmac.WORDLEN, olen);
    Integer *ms = new Integer();
    prf.init(hmac, *pmsbits);
    prf.opt_phash(hmac, *ms, olen * 8, *pmsbits, seed, seed_len, true, true);

    if (sec_len == 32)
        g_ms = ms;
    else if (olen == 56) {
        g_block_key = ms;
        g_iv.bits.insert(g_iv.bits.begin(), ms->bits.begin() + 128, ms->bits.begin() + 128 + 32 * 2);
        g_key_s.bits.insert(g_key_s.bits.begin(), ms->bits.begin() + 128 + 2 * 32,
                            ms->bits.begin() + 128 + 2 * 32 + 128);
        g_key_c.bits.insert(g_key_c.bits.begin(), ms->bits.begin() + 128 + 2 * 32 + 128,
                            ms->bits.begin() + 128 + 2 * (32 + 128));
        g_iv.reveal<unsigned char>((unsigned char*)g_iv_oct, PUBLIC);

        for (int i = 0; i < 4; i++)
            g_fixed_iv_c[i] = g_iv_oct[4 + 4 - 1 - i];

        for (int i = 0; i < 4; i++)
            g_fixed_iv_s[i] = g_iv_oct[4 - 1 - i];

        printf("iv_c[%d]", 4);
        for (int i = 0; i < 4; i++)
            printf("%2x ", g_iv_oct[4 + 4 - 1 - i]);
        printf("\n");

        printf("iv_s[%d]", 4);
        for (int i = 0; i < 4; i++)
            printf("%2x ", g_iv_oct[4 - 1 - i]);
        printf("\n");

        unsigned char key_oct[16];
        g_key_c.reveal<unsigned char>(key_oct, PUBLIC);
        printf("key_c[%d]", 16);
        for (int i = 0; i < 16; i++)
            printf("%2x ", key_oct[16 - 1 - i]);
        printf("\n");

        g_key_s.reveal<unsigned char>(key_oct, PUBLIC);
        printf("key_s[%d]", 16);
        for (int i = 0; i < 16; i++)
            printf("%2x ", key_oct[16 - 1 - i]);
        printf("\n");
        // g_aead_c = new AESGCM<NetIO>(g_key_c, g_iv_oct + 12, 12);
        // g_aead_s = new AESGCM<NetIO>(g_key_s, g_iv_oct, 12);
    }
    else
        g_finish_mac = ms;

    unsigned char* out_oct = new unsigned char[1024];
    ms->reveal<unsigned char>((unsigned char*)out_oct, PUBLIC);
    printf("reveal out[%d]:", olen);
    for (int i = 0; i < olen; i++) {
        printf("%2x ", out_oct[olen - 1 - i]);
    }
    printf("\n");
    if (olen == 12) {
        memcpy(out, out_oct, olen);
        reverse(out, out + olen);
    }

    printf("finsih tls1 prf P hash mpc\n");

    return 1;
}

int transfer_hash_mpc(unsigned char* hash, size_t n) {
    if (g_party == ALICE) {
        g_io->recv_data(hash, n);
    }
    else {
        g_io->send_data(hash, n);
        g_io->flush();
    }
    printf("transfer hash[%d] ", n);
    for (int i = 0; i < n; i++)
        printf("%2x ", hash[i]);
    printf("\n");
    return 1;
}


int tls1_prf_master_secret_mpc(const unsigned char* sec, size_t sec_len, const unsigned char* seed, size_t seed_len, unsigned char* out, size_t olen) {
    char buf[256]; // 22 + 32
    strcpy(buf, "extended master secret");
    memcpy(buf + 22, seed, 32);

    tls1_prf_P_hash_mpc(sec, sec_len, (unsigned char*)buf, 54, out, olen);
    return 1;
}

int tls1_prf_block_key_mpc(const unsigned char* sec, size_t sec_len, const unsigned char* seed, size_t seed_len, unsigned char* out, size_t olen) {
    char buf[256]; // 13 + 32 + 32
    strcpy(buf, "key expansion");
    memcpy(buf + 13, seed, 64);

    tls1_prf_P_hash_mpc(sec, sec_len, (unsigned char*)buf, 77, out, olen);
    return 1;
}

int tls1_prf_finish_mac_mpc(const unsigned char* sec, size_t sec_len, const unsigned char* seed, size_t seed_len, unsigned char* out, size_t olen, int client) {
    char buf[256]; // 15 + 32
    strcpy(buf, client ? "client finished":"server finished");
    memcpy(buf + 15, seed, 32);

    tls1_prf_P_hash_mpc(sec, sec_len, (unsigned char*)buf, 47, out, olen);
    return 1;
}

int enc_aesgcm_mpc(unsigned char* ctxt, unsigned char* tag, const unsigned char* msg, size_t msg_len, const unsigned char* aad, size_t aad_len, const unsigned char* iv, size_t iv_len) {
    unsigned char buf[12];
    memcpy(buf, g_fixed_iv_c, 4);
    memcpy(buf + 4, iv, 8);
    // reverse(buf, buf + 12);
    // g_aead_c = new AESGCM<NetIO>(g_io, g_cot, g_key_c, buf, 12);
    g_aead_c = new AESGCM<NetIO>(g_key_c, buf, 12);
    printf("msg[%d]", msg_len);
    for (int i = 0; i < msg_len; i++)
        printf("%2x ", msg[i]);
    printf("\n");

    printf("aad[%d]", aad_len);
    for (int i = 0; i < aad_len; i++)
        printf("%2x ", aad[i]);
    printf("\n");
    g_hs->encrypt_client_finished_msg(*g_aead_c, ctxt, tag, msg, msg_len * 8, aad, aad_len, g_party);
    printf("ctxt[%d]", 16);
    for (int i = 0; i < 16; i++)
        printf("%2x ", ctxt[i]);
    printf("\n");

    printf("tag[%d]", 16);
    for (int i = 0; i < 16; i++)
        printf("%2x ", tag[i]);
    printf("\n");
    return 1;
}

int dec_aesgcm_mpc(unsigned char* msg, const unsigned char* ctxt, size_t ctxt_len, const unsigned char* tag, const unsigned char* aad, size_t aad_len, const unsigned char* iv, size_t iv_len) {
    unsigned char buf[12];
    memcpy(buf, g_fixed_iv_s, 4);
    memcpy(buf + 4, iv, 8);
    // reverse(buf, buf + 12);
    // g_aead_s = new AESGCM<NetIO>(g_io, g_cot, g_key_s, buf, 12);
    g_aead_s = new AESGCM<NetIO>(g_key_s, buf, 12);
    printf("ctxt[%d]", ctxt_len);
    for (int i = 0; i < ctxt_len; i++)
        printf("%2x ", ctxt[i]);
    printf("\n");

    printf("aad[%d]", aad_len);
    for (int i = 0; i < aad_len; i++)
        printf("%2x ", aad[i]);
    printf("\n");
    
    printf("tag[%d]", 16);
    for (int i = 0; i < 16; i++)
        printf("%2x ", tag[i]);
    printf("\n");
    bool res = g_hs->decrypt_and_check_server_finished_msg(*g_aead_s, msg, ctxt, ctxt_len * 8, tag, aad, aad_len, g_party);
    printf("msg[%d]", ctxt_len);
    for (int i = 0; i < ctxt_len; i++)
        printf("%2x ", msg[i]);
    printf("\n");

    if (!res)
        printf("bad mac\n");
    return 1;
}
