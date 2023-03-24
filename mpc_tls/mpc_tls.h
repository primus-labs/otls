#ifndef MPC_TLS_HEADER_
#define MPC_TLS_HEADER_

#include <openssl/bn.h>
#include <openssl/ec.h>

#define DEBUG_PRINT_MPC 0
#ifdef __cplusplus
extern "C" {
#endif

int init_mpc(int party);

EC_POINT* EC_POINT_new_mpc();

void EC_POINT_free_mpc(EC_POINT* p);

int get_pms_mpc(EC_POINT* Tc, EC_POINT* Ts);

int tls1_prf_master_secret_mpc(const unsigned char* sec, size_t sec_len, const unsigned char* seed, size_t seed_len, unsigned char* out, size_t olen);

int tls1_prf_block_key_mpc(const unsigned char* sec, size_t sec_len, const unsigned char* rc, size_t rc_len, const unsigned char* rs, size_t rs_len, unsigned char* out, size_t olen);

int tls1_prf_finish_mac_mpc(const unsigned char* sec, size_t sec_len, const unsigned char* seed, size_t seed_len, unsigned char* out, size_t olen, int client);

int enc_aesgcm_mpc(unsigned char* ctxt, unsigned char* tag, const unsigned char* msg, size_t msg_len, const unsigned char* aad, size_t aad_len, const unsigned char* iv, size_t iv_len, int finish);

int dec_aesgcm_mpc(unsigned char* msg, const unsigned char* ctxt, size_t ctxt_len, const unsigned char* tag, const unsigned char* aad, size_t aad_len, const unsigned char* iv, size_t iv_len, int finish);

int transfer_hash_mpc(unsigned char* hash, size_t n);

void debug_print(const char* s);

void print_mpc(const char* str, const unsigned char* data, size_t n);
#ifdef __cplusplus
}
#endif

#endif
