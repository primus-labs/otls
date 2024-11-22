
#include "cipher/utils.h"
#ifndef THREADING
BristolFormat* aes_ks = nullptr;
BristolFormat* aes_enc_ks = nullptr;
#else
__thread BristolFormat* aes_ks = nullptr;
__thread BristolFormat* aes_enc_ks = nullptr;
#endif

static const char* aes_ks_file = "cipher/circuit_files/aes128_ks.txt";

static const char* aes_enc_file = "cipher/circuit_files/aes128_with_ks.txt";

void init_files() {
    aes_ks = new BristolFormat(aes_ks_file);
    aes_enc_ks = new BristolFormat(aes_enc_file);
}

void uninit_files() {
    delete aes_ks;
    delete aes_enc_ks;
}
