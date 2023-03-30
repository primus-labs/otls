#include "mpc_tls.h"
#include <openssl/mpc_tls_meth.h>
#include "protocol/handshake.h"
#include "protocol/record.h"
#include "backend/backend.h"
#include <iostream>
#include "cipher/prf.h"
#include <openssl/bn.h>
#include <emp-tool/emp-tool.h>

using namespace std;
using namespace emp;

#define WEBSOCKET_IO 1

#if defined(__EMSCRIPTEN__) || defined(WEBSOCKET_IO)
#include "websocket_io_channel.h"
using PadoIO = WebSocketIO;
#else
#include "emp_io_channel.h"
using PadoIO = MyIO;
#endif

static EC_GROUP* g_group = nullptr;
static int g_party = -1;
static HandShake<PadoIO>* g_hs = nullptr;
static Record<PadoIO>* g_rd = nullptr;
static PadoIO* g_io = nullptr;
static BoolIO<PadoIO>** g_ios = nullptr;
static IKNP<PadoIO>* g_cot = nullptr;
static BN_CTX* g_ctx = nullptr;

void print_mpc(const char* str, const unsigned char* data, size_t n) {
#if DEBUG_PRINT_MPC
    printf("%s[%d] ", str, n);
    for (size_t i = 0; i < n; i++)
        printf("%2x ", data[i]);
    printf("\n");
#endif
}

void debug_print(const char* str) {
#if DEBUG_PRINT_MPC
    printf(str);
#endif
}

static void sync_send(const char* buf, int len) {
    g_io->send_data(buf, len);
#if DEBUG_PRINT_MPC
    printf("send=> %s\n", buf);
#endif
}

static void sync_recv(char* buf, int len) {
    g_io->recv_data(buf, len);
#if DEBUG_PRINT_MPC
    printf("recv=> %s\n", buf);
#endif
}

static const int threads = 1;
int init_mpc(int pado) {
    OPENSSL_init_MPC_METH(get_pms_mpc,
                          tls1_prf_master_secret_mpc,
                          tls1_prf_block_key_mpc,
                          tls1_prf_finish_mac_mpc,
                          enc_aesgcm_mpc,
                          dec_aesgcm_mpc,
                          transfer_hash_mpc, 0x3f);
    OPENSSL_init_print_meth(print_mpc, debug_print);

    int party = pado ? BOB: ALICE;
    g_io = new PadoIO(party == BOB ? nullptr : "127.0.0.1", 8081);
    g_ios = new BoolIO<PadoIO>*[threads];
    for (int i = 0; i < threads; i++)
        g_ios[i] = new BoolIO<PadoIO>(g_io, party == ALICE);
    debug_print("create websocket io ok\n");
    
    char send_buf[256];
    char recv_buf[256];
    sprintf(send_buf, "send by %s", pado? "pado": "clnt");
    memset(recv_buf, 0, sizeof(recv_buf));

    if (pado) {
        sync_recv(recv_buf, 12);
        sync_send(send_buf, 12);
    }
    else {
        sync_send(send_buf, 12);
        sync_recv(recv_buf, 12);
    }

    // setup_backend(g_io, party);
    setup_protocol<PadoIO>(g_io, g_ios, threads, party);

    debug_print("setup backend ok\n");
    auto prot = (PADOParty<PadoIO>*)(ProtocolExecution::prot_exec);
    g_cot = prot->ot;

    g_party = party;

    g_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    g_hs = new HandShake<PadoIO>(g_io, g_cot, g_group);
    g_ctx = g_hs->ctx;

    g_rd = new Record<PadoIO>();

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
	printf("point size:%d\n", size);
    g_io->send_data(buf, size);
    g_io->flush();
    return 1;
}

static int recv_point(EC_POINT* pub_key) {
    unsigned char buf[65];
    g_io->recv_data(buf, 65);

    if (!EC_POINT_oct2point(g_group, pub_key, buf, 65, g_ctx))
        printf("error in converting oct to TA\n");
    return 1;
}

static BIGNUM *g_pms = NULL;

int get_pms_mpc(EC_POINT *Tc, EC_POINT* Ts, BIGNUM* pri_key) {
    EC_POINT* V = EC_POINT_new(g_group);

    if (g_party == BOB) {
		size_t len;
		g_io->recv_data(&len, sizeof(size_t));
		unsigned char* buf = new unsigned char[len];
		g_io->recv_data(buf, len);

		BIGNUM* b = BN_new();
		BN_bin2bn(buf, len, b);
		g_hs->ta_pado = b;

        Ts = EC_POINT_new(g_group);
        recv_point(Ts);
        g_hs->compute_pado_VA(V, Ts);
        EC_POINT_free(Ts);
    } else {

    const BIGNUM* order = EC_GROUP_get0_order(g_group);
    BIGNUM* a = BN_new();
    BIGNUM* b = BN_new();
    BN_priv_rand_range(a, order);
	BN_mod_sub(b, pri_key, a, order, g_ctx);

        size_t len = BN_num_bytes(b);
        unsigned char* buf = new unsigned char[len];
        BN_bn2bin(b, buf);

		g_io->send_data(&len, sizeof(size_t));
		g_io->send_data(buf, len);

    g_hs->tb_client = a;

        send_point(Ts);
        g_hs->compute_client_VB(Tc, V, Ts);
    }

    g_hs->compute_pms_offline(g_party);

    g_pms = BN_new();
    g_hs->compute_pms_online(g_pms, V, g_party);

    EC_POINT_free(V);
    debug_print("finish get pms mpc\n");

    return 1;
}
    
static AEAD<PadoIO> *g_aead_c = NULL;
static AEAD<PadoIO> *g_aead_s = NULL;

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
    g_hs->compute_extended_master_key(g_pms, seed, seed_len);
	memcpy(out, g_hs->master_secret, 48);
	print_mpc("mmmmmmmm master secret", out, 48);
    return 1;
}

int tls1_prf_block_key_mpc(const unsigned char* sec, size_t sec_len, const unsigned char* rc, size_t rc_len, const unsigned char* rs, size_t rs_len, unsigned char* out, size_t olen) {
    g_hs->compute_expansion_keys(rc, rc_len, rs, rs_len); 
    memcpy(out, g_hs->key_block, 56);
	print_mpc("mmmmmmmm key block", out, 56);
    return 1;
}

int tls1_prf_finish_mac_mpc(const unsigned char* sec, size_t sec_len, const unsigned char* seed, size_t seed_len, unsigned char* out, size_t olen, int client) {
    char buf[256]; // 15 + 32
    strcpy(buf, client ? "client finished":"server finished");
#if DEBUG_PRINT_MPC
    printf("finish mac:%s\n", buf);
#endif
    if (client) {
        g_hs->compute_client_finished_msg(out, (unsigned char*)buf, 15, seed, seed_len);
    }
    else {
        g_hs->compute_server_finished_msg(out, (unsigned char*)buf, 15, seed, seed_len);
    }
    reverse(out, out + olen);

	print_mpc("mmmmmmmmmmmmmm finish mac", out, olen);

    return 1;
}

int enc_aesgcm_mpc(unsigned char* ctxt, unsigned char* tag, const unsigned char* msg, size_t msg_len, const unsigned char* aad, size_t aad_len, const unsigned char* iv, size_t iv_len, int finish) {
    unsigned char buf[12];
    memcpy(buf, g_hs->client_iv_oct, 4);
    memcpy(buf + 4, iv, 8);
    g_aead_c = new AEAD<PadoIO>(g_io, g_cot, g_hs->client_write_key, buf, 12);

    print_mpc("msg", msg, msg_len);
    print_mpc("aad", aad, aad_len);
    print_mpc("iv", buf, 12);
    Integer c_key = g_hs->client_write_key;
    unsigned char ckey[16];
    c_key.reveal<unsigned char>(ckey, PUBLIC);
    reverse(ckey, ckey + 16);
    print_mpc("key", ckey, 16);

    if (finish)
        g_hs->encrypt_client_finished_msg(*g_aead_c, ctxt, tag, msg, msg_len, aad, aad_len, g_party);
    else
        g_rd->encrypt(g_aead_c, g_io, ctxt, tag, msg, msg_len, aad, aad_len, g_party);
    
    print_mpc("ctxt", ctxt, msg_len);
    print_mpc("tag", tag, 16);

    return 1;
}

int dec_aesgcm_mpc(unsigned char* msg, const unsigned char* ctxt, size_t ctxt_len, const unsigned char* tag, const unsigned char* aad, size_t aad_len, const unsigned char* iv, size_t iv_len, int finish) {
    unsigned char buf[12];
    memcpy(buf, g_hs->server_iv_oct, 4);
    memcpy(buf + 4, iv, 8);
    g_aead_s = new AEAD<PadoIO>(g_io, g_cot, g_hs->server_write_key, buf, 12);
    
    print_mpc("ctxt", ctxt, ctxt_len);
    print_mpc("aad", aad, aad_len);
    print_mpc("tag", tag, 16);

    bool res;
    if (finish)
        res = g_hs->decrypt_and_check_server_finished_msg(*g_aead_s, msg, ctxt, ctxt_len, tag, aad, aad_len, g_party);
    else
        res = g_rd->decrypt(g_aead_s, g_io, msg, ctxt, ctxt_len, tag, aad, aad_len, g_party);

    print_mpc("msg", msg, ctxt_len);

    if (!res)
        printf("bad mac\n");
    return 1;
}
