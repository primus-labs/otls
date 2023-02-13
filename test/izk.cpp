#include "emp-zk/emp-zk.h"
#include <iostream>
#include "emp-tool/emp-tool.h"
#include "protocol/izk.h"
using namespace emp;
using namespace std;

const int threads = 1;

void izk_test(EC_GROUP* group, int party) {
    IZK<NetIO>* izk = new IZK<NetIO>(group);

    Integer ms, key, key_c, key_s, iv;

    unsigned char* rc = new unsigned char[32];
    unsigned char* rs = new unsigned char[32];

    unsigned char* ufinc = new unsigned char[finished_msg_bit_length / 8];
    unsigned char* ufins = new unsigned char[finished_msg_bit_length / 8];

    unsigned char* tau_c = new unsigned char[32];
    unsigned char* tau_s = new unsigned char[32];

    unsigned char* iv_oct = new unsigned char[24];

    memset(rc, 0x11, 32);
    memset(rs, 0x22, 32);
    memset(tau_c, 0x33, 32);
    memset(tau_s, 0x44, 32);

    BIGNUM* pms_a = BN_new();
    BIGNUM* pms_b = BN_new();

    BN_rand_range(pms_a, izk->q);
    BN_rand_range(pms_b, izk->q);

    auto start = emp::clock_start();
    izk->prove_master_and_expansion_keys(ms, key, pms_a, pms_b, rc, 32, rs, 32, party);

    iv.bits.insert(iv.bits.begin(), key.bits.begin(), key.bits.begin() + 96 * 2);
    key_s.bits.insert(key_s.bits.begin(), key.bits.begin() + 2 * 96,
                      key.bits.begin() + 2 * 96 + 128);
    key_c.bits.insert(key_c.bits.begin(), key.bits.begin() + 2 * 96 + 128,
                      key.bits.begin() + 2 * (96 + 128));

    iv.reveal<unsigned char>((unsigned char*)iv_oct, PUBLIC);

    izk->prove_compute_finished_msg(ufinc, ms, client_finished_label,
                                    client_finished_label_length, tau_c, 32);

    AEAD_IZK aead_c(key_c, iv_oct + 12, 12);
    AEAD_IZK aead_s(key_s, iv_oct, 12);

    Integer ctxt, msg;
    izk->prove_encrypt_client_finished_msg(aead_c, ctxt, finished_msg_bit_length);

    izk->prove_compute_finished_msg(ufins, ms, server_finished_label,
                                    server_finished_label_length, tau_s, 32);

    izk->prove_decrypt_server_finished_msg(aead_s, msg, finished_msg_bit_length);

    size_t q_length = 2 * 1024 * 8;
    size_t r_length = 2 * 1024 * 8;

    izk->prove_encrypt_record_msg(aead_c, ctxt, q_length);
    izk->prove_decrypt_record_msg(aead_s, msg, r_length);
    cout << "time: " << emp::time_from(start) << " us" << endl;

    BN_free(pms_a);
    BN_free(pms_b);

    delete[] rc;
    delete[] rs;
    delete[] ufinc;
    delete[] ufins;
    delete[] tau_c;
    delete[] tau_s;
    delete[] iv_oct;
    delete izk;
}
int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);

    BoolIO<NetIO>* ios[threads];
    for (int i = 0; i < threads; ++i)
        ios[i] = new BoolIO<NetIO>(new NetIO(party == ALICE ? nullptr : "127.0.0.1", port),
                                   party == ALICE);

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    auto start0 = emp::clock_start();
    setup_zk_bool<BoolIO<NetIO>>(ios, threads, party);
    cout << "setup time: " << emp::time_from(start0) << " us" << endl;
    izk_test(group, party);
    cout << "AND gates: " << CircuitExecution::circ_exec->num_and() << endl;
    ios[0]->flush();
    cout << "communication: " << ios[0]->counter << " Bytes" << endl;

    bool cheat = finalize_zk_bool<BoolIO<NetIO>>();
    if (cheat)
        error("cheat!\n");
    EC_GROUP_free(group);

    for (int i = 0; i < threads; ++i) {
        delete ios[i]->io;
        delete ios[i];
    }
    return 0;
}