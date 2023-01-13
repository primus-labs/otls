// #include <openssl/mpc_tls.h>
// #include <openssl/mpc_tls_meth.h>
#include "mpc_tls.h"
#include "mpc_tls_meth.h"
#include "handshake/handshake.h"
#include "backend/backend.h"
#include <iostream>

using namespace std;
using namespace emp;

static EC_GROUP* g_group = nullptr;
static int g_party = -1;
static HandShake<NetIO>* g_hs = nullptr;
static NetIO* g_io = nullptr;
static BN_CTX* g_ctx = nullptr;
static BIGNUM* g_q = nullptr;
static BIGNUM* g_priv_key = nullptr;
static EC_POINT* g_pub_key = nullptr;

int init_mpc(int party) {
    g_io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", 8081);
    setup_backend(g_io, party);
    auto prot = (PADOParty<NetIO>*)(ProtocolExecution::prot_exec);
    IKNP<NetIO>* cot = prot->ot;

    g_party = party;

    g_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    g_hs = new HandShake<NetIO>(g_io, cot, g_group);
	g_ctx = g_hs->ctx;
	g_q = g_hs->q;

	g_priv_key = BN_new();
	BN_rand_range(g_priv_key, g_q);
	g_pub_key = EC_POINT_new(g_group);
	EC_POINT_mul(g_group, g_pub_key, g_priv_key, NULL, NULL, g_ctx);

    return 1;
}

static int send_point(EC_POINT* pub_key) {
        unsigned char buf[65];
        int size = EC_POINT_point2oct(g_group, pub_key, POINT_CONVERSION_UNCOMPRESSED, buf, 65, g_ctx);
        g_io->send_data(buf, size);
		return 1;
}

static int recv_point(EC_POINT* pub_key) {
        unsigned char buf[65];
        g_io->recv_data(buf, 65);

        if (!EC_POINT_oct2point(g_group, pub_key, buf, 65, g_ctx))
            printf("error in converting oct to TA\n");
		return 1;
}


int EC_POINT_mul_mpc(EC_POINT* out, EC_POINT* pub_key) {
    if (g_party == ALICE) {
		recv_point(pub_key);
    } else {
		send_point(pub_key);
    }

	EC_POINT_mul(g_group, out, NULL, pub_key, g_priv_key, g_ctx);
    
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

	return 1;
}

int get_pms_mpc(BIGNUM *pms, EC_POINT* Z) {
    g_hs->compute_pms_offline(g_party);

    g_hs->compute_pms_online(pms, Z, g_party);
	return 1;
}
	

int tls1_prf_P_hash_mpc(const unsigned char* sec, size_t sec_len, const unsigned char* seed, size_t seed_len, unsigned char* out, size_t olen) {
	return 1;
}
