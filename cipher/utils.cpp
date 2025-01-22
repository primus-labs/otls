
#include "cipher/utils.h"
#ifndef THREADING
BristolFormat* aes_ks = nullptr;
BristolFormat* aes_enc_ks = nullptr;
#else
__thread BristolFormat* aes_ks = nullptr;
__thread BristolFormat* aes_enc_ks = nullptr;
#endif

#ifdef LOAD_CIRCUIT_FROM_MEM
extern std::string aes128_ks_data;
extern std::string aes128_with_ks_data;
#else
static const char* aes_ks_file = "cipher/circuit_files/aes128_ks.txt";
static const char* aes_enc_file = "cipher/circuit_files/aes128_with_ks.txt";
#endif

void init_files() {
#ifdef LOAD_CIRCUIT_FROM_MEM
    aes_ks = new BristolFormat(aes128_ks_data);
    aes_enc_ks = new BristolFormat(aes128_with_ks_data);
#else
    aes_ks = new BristolFormat(aes_ks_file);
    aes_enc_ks = new BristolFormat(aes_enc_file);
#endif
}

void uninit_files() {
    delete aes_ks;
    delete aes_enc_ks;
}
