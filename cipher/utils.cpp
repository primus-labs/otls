
#include "cipher/utils.h"
#ifndef THREADING
BristolFormat *aes_ks = nullptr;
BristolFormat *aes_enc_ks = nullptr;
#else
__thread BristolFormat *aes_ks = nullptr;
__thread BristolFormat *aes_enc_ks = nullptr;
#endif

#if LOAD_CERT_FROM_FILE
static const char* aes_ks_file = "cipher/circuit_files/aes128_ks.txt";
static const char* aes_enc_file = "cipher/circuit_files/aes128_with_ks.txt";
#else
extern std::string aes128_ks_data;
extern std::string aes128_with_ks_data;
#endif

void init_files() {
    #if LOAD_CERT_FROM_FILE
    aes_ks = new BristolFormat(aes_ks_file);
    aes_enc_ks = new BristolFormat(aes_enc_file);
    #else
    aes_ks = new BristolFormat(aes128_ks_data);
    aes_enc_ks = new BristolFormat(aes128_with_ks_data);
    #endif
}

void uninit_files() {
    delete aes_ks;
    delete aes_enc_ks;
}
