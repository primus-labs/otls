#include "mpc_tls.h"
#include <openssl/mpc_tls_meth.h>
#include "protocol/handshake.h"
#include "backend/backend.h"
#include <iostream>
#include "cipher/prf.h"
#include <openssl/bn.h>
#include "websocket_io_channel.h"
#include "emp_io_channel.h"
#include <emp-tool/emp-tool.h>

using namespace std;
using namespace emp;

static EC_GROUP* g_group = nullptr;
static int g_party = -1;
static HandShake<WebSocketIO>* g_hs = nullptr;
static WebSocketIO* g_io = nullptr;
static IKNP<WebSocketIO>* g_cot = nullptr;
static BN_CTX* g_ctx = nullptr;

static void print_mpc(const char* str, const unsigned char* data, size_t n) {
    printf("%s[%d] ", str, n);
    for (size_t i = 0; i < n; i++)
        printf("%2x ", data[i]);
    printf("\n");
}

int init_mpc(int pado) {
    OPENSSL_init_MPC_METH(get_pms_mpc,
                          tls1_prf_master_secret_mpc,
                          tls1_prf_block_key_mpc,
                          tls1_prf_finish_mac_mpc,
                          enc_aesgcm_mpc,
                          dec_aesgcm_mpc,
                          transfer_hash_mpc);

    int party = pado ? BOB: ALICE;
    g_io = new WebSocketIO(party == BOB ? nullptr : "127.0.0.1", 8081);
    printf("create websocket io ok\n");
    
    char buf[256];
    sprintf(buf, "send by %s", pado? "pado": "clnt");
    g_io->send_data(buf, strlen(buf));
    printf("send=> %s\n", buf);
    memset(buf, 0, sizeof(buf));
    g_io->recv_data(buf, 12);
    printf("recv=> %s\n", buf);

    setup_backend(g_io, party);
    printf("setup backend ok\n");
    auto prot = (PADOParty<WebSocketIO>*)(ProtocolExecution::prot_exec);
    g_cot = prot->ot;

    g_party = party;

    g_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    g_hs = new HandShake<WebSocketIO>(g_io, g_cot, g_group);
    g_ctx = g_hs->ctx;

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

static BIGNUM *g_pms = NULL;

int get_pms_mpc(EC_POINT *Tc, EC_POINT* Ts) {
    EC_POINT* V = EC_POINT_new(g_group);
    BIGNUM* t = BN_new();

    if (g_party == BOB) {
        Ts = EC_POINT_new(g_group);
        recv_point(Ts);
        g_hs->compute_pado_VA(V, t, Ts);
        EC_POINT_free(Ts);
    } else {
        send_point(Ts);
        g_hs->compute_client_VB(Tc, V, t, Ts);
    }

    g_hs->compute_pms_offline(g_party);

    g_pms = BN_new();
    g_hs->compute_pms_online(g_pms, V, g_party);

    EC_POINT_free(V);
    BN_free(t);

    printf("finish get pms mpc\n");
    return 1;
}
    
static Integer g_iv, g_key_c, g_key_s;
static unsigned char g_iv_oct[8];
static unsigned char g_fixed_iv_c[4];
static unsigned char g_fixed_iv_s[4];
static AEAD<WebSocketIO> *g_aead_c = NULL;
static AEAD<WebSocketIO> *g_aead_s = NULL;
static Integer* g_block_key = NULL;
static Integer* g_ms = NULL;
static Integer* g_finish_mac = NULL;

int transfer_hash_mpc(unsigned char* hash, size_t n) {
    if (g_party == BOB) {
        g_io->recv_data(hash, n);
    }
    else {
        g_io->send_data(hash, n);
        g_io->flush();
    }
    print_mpc("transfer hash", hash, n);
    return 1;
}


int tls1_prf_master_secret_mpc(const unsigned char* sec, size_t sec_len, const unsigned char* seed, size_t seed_len, unsigned char* out, size_t olen) {
    g_ms = new Integer();
    g_hs->compute_extended_master_secret(*g_ms, g_pms, seed, seed_len, g_party);
    return 1;
}

int tls1_prf_block_key_mpc(const unsigned char* sec, size_t sec_len, const unsigned char* rc, size_t rc_len, const unsigned char* rs, size_t rs_len, unsigned char* out, size_t olen) {
    g_block_key = new Integer();
    g_hs->compute_expansion_keys(*g_block_key, *g_ms, rc, rc_len, rs, rs_len); 
    
    g_iv.bits.insert(g_iv.bits.begin(), g_block_key->bits.begin() + 128, g_block_key->bits.begin() + 128 + 32 * 2);
    g_key_s.bits.insert(g_key_s.bits.begin(), g_block_key->bits.begin() + 128 + 2 * 32,
                        g_block_key->bits.begin() + 128 + 2 * 32 + 128);
    g_key_c.bits.insert(g_key_c.bits.begin(), g_block_key->bits.begin() + 128 + 2 * 32 + 128,
                        g_block_key->bits.begin() + 128 + 2 * (32 + 128));
    g_iv.reveal<unsigned char>((unsigned char*)g_iv_oct, PUBLIC);

    memcpy(g_fixed_iv_s, g_iv_oct, 4);
    reverse(g_fixed_iv_s, g_fixed_iv_s + 4);

    memcpy(g_fixed_iv_c, g_iv_oct + 4, 4);
    reverse(g_fixed_iv_c, g_fixed_iv_c + 4);

    return 1;
}

int tls1_prf_finish_mac_mpc(const unsigned char* sec, size_t sec_len, const unsigned char* seed, size_t seed_len, unsigned char* out, size_t olen, int client) {
    char buf[256]; // 15 + 32
    strcpy(buf, client ? "client finished":"server finished");
    printf("finish mac:%s\n", buf);
    g_hs->compute_finished_msg(out, *g_ms, (unsigned char*)buf, 15, seed, seed_len); 
    reverse(out, out + olen);

    return 1;
}

int enc_aesgcm_mpc(unsigned char* ctxt, unsigned char* tag, const unsigned char* msg, size_t msg_len, const unsigned char* aad, size_t aad_len, const unsigned char* iv, size_t iv_len, int finish) {
    unsigned char buf[12];
    memcpy(buf, g_fixed_iv_c, 4);
    memcpy(buf + 4, iv, 8);
    g_aead_c = new AEAD<WebSocketIO>(g_io, g_cot, g_key_c, buf, 12);
    // g_aead_c = new AEAD<WebSocketIO>(g_key_c, buf, 12);

    print_mpc("msg", msg, msg_len);
    print_mpc("aad", aad, aad_len);

    if (finish)
        g_hs->encrypt_client_finished_msg(*g_aead_c, ctxt, tag, msg, msg_len * 8, aad, aad_len, g_party);
    else
        g_hs->encrypt_record_msg(*g_aead_c, ctxt, tag, msg, msg_len * 8, aad, aad_len, g_party);
    
    print_mpc("ctxt", ctxt, msg_len);
    print_mpc("tag", tag, 16);

    return 1;
}

int dec_aesgcm_mpc(unsigned char* msg, const unsigned char* ctxt, size_t ctxt_len, const unsigned char* tag, const unsigned char* aad, size_t aad_len, const unsigned char* iv, size_t iv_len, int finish) {
    unsigned char buf[12];
    memcpy(buf, g_fixed_iv_s, 4);
    memcpy(buf + 4, iv, 8);
    g_aead_s = new AEAD<WebSocketIO>(g_io, g_cot, g_key_s, buf, 12);
    // g_aead_s = new AEAD<WebSocketIO>(g_key_s, buf, 12);
    
    print_mpc("ctxt", ctxt, ctxt_len);
    print_mpc("aad", aad, aad_len);
    print_mpc("tag", tag, 16);

    bool res;
    if (finish)
        res = g_hs->decrypt_and_check_server_finished_msg(*g_aead_s, msg, ctxt, ctxt_len * 8, tag, aad, aad_len, g_party);
    else
        res = g_hs->decrypt_record_msg(*g_aead_s, msg, ctxt, ctxt_len * 8, tag, aad, aad_len, g_party);

    print_mpc("msg", msg, ctxt_len);

    if (!res)
        printf("bad mac\n");
    return 1;
}
