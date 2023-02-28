#ifndef MPC_TLS_METH_HEADER_
#define MPC_TLS_METH_HEADER_

#include <openssl/bn.h>
#include <openssl/ec.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*get_pms_meth)(EC_POINT *Tc, EC_POINT* Ts);

typedef int (*tls1_prf_master_secret_meth)(const unsigned char* sec, size_t sec_len, const unsigned char* seed, size_t seed_len, unsigned char* out, size_t olen);

typedef int (*tls1_prf_key_block_meth)(const unsigned char* sec, size_t sec_len, const unsigned char* rc, size_t rc_len, const unsigned char* rs, size_t rs_len, unsigned char* out, size_t olen);

typedef int (*tls1_prf_finish_mac_meth)(const unsigned char* sec, size_t sec_len, const unsigned char* seed, size_t seed_len, unsigned char* out, size_t olen, int client);

typedef int (*enc_aesgcm_meth)(unsigned char* ctxt, unsigned char* tag, const unsigned char* msg, size_t msg_len, const unsigned char* aad, size_t aad_len, const unsigned char* iv, size_t iv_len, int finish);

typedef int (*dec_aesgcm_meth)(unsigned char* msg, const unsigned char* ctxt, size_t ctxt_len, const unsigned char* tag, const unsigned char* aad, size_t aad_len, const unsigned char* iv, size_t iv_len, int finish);

typedef int (*transfer_hash_meth)(unsigned char* hash, size_t n);

typedef struct custom_meth_st {
    get_pms_meth get_pms;
    tls1_prf_master_secret_meth master_secret;
    tls1_prf_key_block_meth key_block;
    tls1_prf_finish_mac_meth finish_mac;
    enc_aesgcm_meth enc_aesgcm;
    dec_aesgcm_meth dec_aesgcm;
    transfer_hash_meth hash;
} MPC_METH;

const EC_POINT* set_pub_key_tls(EVP_PKEY* ckey, EC_POINT* pt);

const EC_POINT* get_pub_key_tls(EVP_PKEY* ckey);

int get_pms_tls(EC_POINT* Tc, EC_POINT* Ts);

int tls1_prf_master_secret_tls(const unsigned char* sec, size_t sec_len, const unsigned char* seed, size_t seed_len, unsigned char* out, size_t olen);

int tls1_prf_key_block_tls(const unsigned char* sec, size_t sec_len, const unsigned char* rc, size_t rc_len, const unsigned char* rs, size_t rs_len, unsigned char* out, size_t olen);

int tls1_prf_finish_mac_tls(const unsigned char* sec, size_t sec_len, const unsigned char* seed, size_t seed_len, unsigned char* out, size_t olen, int client);

int enc_aesgcm_tls(unsigned char* ctxt, unsigned char* tag, const unsigned char* msg, size_t msg_len, const unsigned char* aad, size_t aad_len, const unsigned char* iv, size_t iv_len, int finish);

int dec_aesgcm_tls(unsigned char* msg, const unsigned char* ctxt, size_t ctxt_len, const unsigned char* tag, const unsigned char* aad, size_t aad_len, const unsigned char* iv, size_t iv_len, int finish);

int transfer_hash_tls(unsigned char* hash, size_t n);

void OPENSSL_init_MPC_METH(
    get_pms_meth get_pms,
    tls1_prf_master_secret_meth master_secret,
    tls1_prf_key_block_meth key_block,
    tls1_prf_finish_mac_meth finish_mac,
    enc_aesgcm_meth enc_aesgcm,
    dec_aesgcm_meth dec_aesgcm,
    transfer_hash_meth hash);

int need_mpc();




#ifdef __cplusplus
}
#endif

#endif
