#include<stdio.h>
#include<stdlib.h>
#include<string.h>


#include<otls/mpc_tls.h>
#include<openssl/mpc_tls_meth.h>
#include<openssl/bn.h>

void print_random(const char* title, unsigned char* r, int rlen) {
    printf("%s:", title);
    for (int i = 0; i < rlen; i++)
        printf("%2x ", r[i]);
    printf("\n");
}

void transfer_data(unsigned char* &data, size_t *size, int transfer_flag) {
    size_t n;
    transfer_hash_tls((unsigned char*)&n, sizeof(size_t));
    data = new unsigned char[n];
    if (transfer_flag)
        transfer_hash_tls(data, n);
    *size = n;
}

void enc_msg(int finish) {
    printf("begin transfer aad\n");
    unsigned char *aad; // 13
    size_t aad_len;
    transfer_data(aad, &aad_len, 1);
    printf("end transfer aad\n");
    int transfer_flag = aad[8] == 0x17 ? 0: 1;

    printf("begin transfer msg\n");
    unsigned char *msg; // 16
    size_t msg_len;
    transfer_data(msg, &msg_len, transfer_flag);
    printf("end transfer msg\n");

    printf("begin transfer iv\n");
    unsigned char *iv; // 8
    size_t iv_len;
    transfer_data(iv, &iv_len, 1);
    printf("end transfer iv\n");

    unsigned char *ctxt = new unsigned char[msg_len]; // 16
    unsigned char tag[32]; // 16
    printf("begin enc aesgcm\n");
    enc_aesgcm_tls(ctxt, tag, msg, msg_len, aad, aad_len, iv, iv_len, finish);
    printf("end enc aesgcm\n");

    delete []aad;
    delete []msg;
    delete []iv;

    delete []ctxt;
}

void dec_msg(int finish) {
    printf("begin transfer aad\n");
    unsigned char *aad; // 13
    size_t aad_len = 13;
    transfer_data(aad, &aad_len, 1);
    printf("end transfer aad\n");
    int transfer_flag = aad[8] == 0x17 ? 0: 1;

    printf("begin transfer msg\n");
    unsigned char *ctxt; // 16
    size_t ctxt_len = 16;
    transfer_data(ctxt, &ctxt_len, transfer_flag);
    printf("end transfer msg\n");

    printf("begin transfer iv\n");
    unsigned char *iv; // 8
    size_t iv_len = 8;
    transfer_data(iv, &iv_len, 1);
    printf("end transfer iv\n");

    printf("begin transfer tag\n");
    unsigned char *tag; // 16
    size_t tag_len;
    transfer_data(tag, &tag_len, 1);
    printf("end transfer tag\n");

    unsigned char *msg = new unsigned char[ctxt_len]; // 16
    printf("begin dec aesgcm\n");
    dec_aesgcm_tls(msg, ctxt, ctxt_len, tag, aad, aad_len, iv, iv_len, finish);
    printf("end dec aesgcm\n");

    delete []aad;
    delete []ctxt;
    delete []iv;
    delete []tag;

    delete []msg;
}

void run_pado() {
    init_mpc(1);
    
    printf("begin tranfer client random\n");
    unsigned char client_random[32];
    transfer_hash_tls(client_random, 32);
    print_random("client random", client_random, 32);
    printf("end transfer client random\n");

    printf("begin tranfer server random\n");
    unsigned char server_random[32];
    transfer_hash_tls(server_random, 32);
    print_random("server random", server_random, 32);
    printf("end transfer server random\n");

    get_pms_tls(NULL, NULL);

//    EC_POINT* s_pub_key = EC_POINT_new_mpc();
//    EC_POINT* z_pub_key = EC_POINT_new_mpc();
//    printf("begin mul tls\n");
//    EC_POINT_mul_tls(z_pub_key, s_pub_key);
//    printf("end mul tls\n");
//    
//    printf("begin get pms\n");
//    BIGNUM* x = BN_new();
//    get_pms_tls(x, z_pub_key);
//    size_t len = BN_num_bytes(x);
//    unsigned char* pmsbuf = new unsigned char[len];
//    BN_bn2bin(x, pmsbuf);
//    printf("end get pms\n");
//
//    printf("begin get client key\n");
//    get_client_pub_key_tls(NULL);
//    printf("end get client key\n");

    printf("begin transfer hash\n");
    unsigned char hash[32];
    transfer_hash_tls(hash, 32);
    printf("end transfer hash\n");

    printf("begin generate master secret\n");
    tls1_prf_master_secret_tls(NULL, 32, hash, 32, NULL, 48);
    printf("end generate master secret\n");

    printf("begin generate block key\n");
    unsigned char** block_key = new unsigned char*;
    char random[64];
    memcpy(random, server_random, 32);
    memcpy(random + 32, client_random, 32);
    tls1_prf_key_block_tls(NULL, 48, (unsigned char*)client_random, 32, (unsigned char*)server_random, 32, (unsigned char*)block_key, 56);
    printf("end generate block key\n");

    printf("begin transfer finish hash\n");
    unsigned char finish_hash[32];
    transfer_hash_tls(finish_hash, 32);
    printf("end transfer finish hash\n");

    printf("begin generate client finish mac\n");
    unsigned char finish_md[12];
    tls1_prf_finish_mac_tls(NULL, 48, finish_hash, 32, finish_md, 12, 1);
    printf("end generate client finish mac\n");

    // ==================encrypt aesgcm=============
    enc_msg(1);
    
    // ==================decrypt aesgcm=============
    dec_msg(1);

    printf("begin transfer server finish hash\n");
    unsigned char server_finish_hash[32];
    transfer_hash_tls(server_finish_hash, 32);
    printf("end transfer server finish hash\n");

    printf("begin generate server finish mac\n");
    unsigned char server_finish_md[12];
    tls1_prf_finish_mac_tls(NULL, 48, server_finish_hash, 32, server_finish_md, 12, 0);
    printf("end generate server finish mac\n");


    while (1) {
        enc_msg(0);
        dec_msg(0);
    }

}

int main(int argc, char* argv[]) {
    run_pado();
    return 0;
}
