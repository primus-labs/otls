#include<stdio.h>
#include<stdlib.h>
#include<string.h>


#include<openssl/mpc_tls.h>
#include<openssl/mpc_tls_meth.h>
#include<openssl/bn.h>

void print_random(char* title, unsigned char* r, int rlen) {
    printf("%s:", title);
    for (int i = 0; i < rlen; i++)
        printf("%2x ", r[i]);
    printf("\n");
}

void run_pado() {
    OPENSSL_init_MPC_METH(set_priv_key_mpc, EC_POINT_mul_mpc, get_client_pub_key_mpc, get_pms_mpc, tls1_prf_P_hash_mpc, tls1_prf_master_secret_mpc, tls1_prf_block_key_mpc, tls1_prf_finish_mac_mpc, transfer_hash_mpc);
    init_mpc(1);
    
    printf("begin tranfer client random\n");
    unsigned char client_random[32];
    transfer_hash_tls(client_random);
    print_random("client random", client_random, 32);
    printf("end transfer client random\n");

    printf("begin tranfer server random\n");
    unsigned char server_random[32];
    transfer_hash_tls(server_random);
    print_random("server random", server_random, 32);
    printf("end transfer server random\n");

    EC_POINT* s_pub_key = EC_POINT_new_mpc();
    EC_POINT* z_pub_key = EC_POINT_new_mpc();
    printf("begin mul tls\n");
    EC_POINT_mul_tls(z_pub_key, s_pub_key);
    printf("end mul tls\n");
    
    printf("begin get pms\n");
    BIGNUM* x = BN_new();
    get_pms_tls(x, z_pub_key);
    size_t len = BN_num_bytes(x);
    unsigned char* pmsbuf = new unsigned char[len];
    BN_bn2bin(x, pmsbuf);
    printf("end get pms\n");

    printf("begin get client key\n");
    get_client_pub_key_tls(NULL);
    printf("end get client key\n");

    printf("begin transfer hash\n");
    unsigned char hash[32];
    transfer_hash_tls(hash);
    printf("end transfer hash\n");

    printf("begin generate master secret\n");
    tls1_prf_master_secret_tls(pmsbuf, 32, hash, 32, NULL, 48);
    printf("end generate master secret\n");

    printf("begin generate block key\n");
    unsigned char** block_key = new unsigned char*;
    char random[64];
    memcpy(random, server_random, 32);
    memcpy(random + 32, client_random, 32);
    tls1_prf_key_block_tls(pmsbuf, 48, (unsigned char*)random, 64, (unsigned char*)block_key, 56);
    printf("end generate block key\n");

    printf("begin transfer finish hash\n");
    unsigned char finish_hash[32];
    transfer_hash_tls(finish_hash);
    printf("end transfer finish hash\n");

    printf("begin generate finish mac\n");
    tls1_prf_finish_mac_tls(pmsbuf, 48, finish_hash, 32, NULL, 12);
    printf("end generate finish mac\n");
}

int main(int argc, char* argv[]) {
    run_pado();
    return 0;
}
