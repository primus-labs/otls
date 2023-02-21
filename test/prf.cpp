#include "emp-tool/emp-tool.h"
#include "backend/backend.h"
#include "cipher/prf.h"
#include "cipher/hmac_sha256.h"
#include "backend/switch.h"
#include "backend/checkzero.h"

#include <iostream>
#include <vector>

using namespace std;
using namespace emp;

void prf_test() {
    vector<unsigned char> secret_u = {0x9b, 0xbe, 0x43, 0x6b, 0xa9, 0x40, 0xf0, 0x17,
                                      0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71, 0xdb, 0x35};
    vector<unsigned char> seed_u = {0xa0, 0xba, 0x9f, 0x93, 0x6c, 0xda, 0x31, 0x18,
                                    0x27, 0xa6, 0xf7, 0x96, 0xff, 0xd5, 0x19, 0x8c};
    vector<unsigned char> label_u = {0x74, 0x65, 0x73, 0x74, 0x20,
                                     0x6c, 0x61, 0x62, 0x65, 0x6c};

    vector<unsigned char> output_u = {
      0xe3, 0xf2, 0x29, 0xba, 0x72, 0x7b, 0xe1, 0x7b, 0x8d, 0x12, 0x26, 0x20, 0x55, 0x7c, 0xd4,
      0x53, 0xc2, 0xaa, 0xb2, 0x1d, 0x07, 0xc3, 0xd4, 0x95, 0x32, 0x9b, 0x52, 0xd4, 0xe6, 0x1e,
      0xdb, 0x5a, 0x6b, 0x30, 0x17, 0x91, 0xe9, 0x0d, 0x35, 0xc9, 0xc9, 0xa4, 0x6b, 0x4e, 0x14,
      0xba, 0xf9, 0xaf, 0x0f, 0xa0, 0x22, 0xf7, 0x07, 0x7d, 0xef, 0x17, 0xab, 0xfd, 0x37, 0x97,
      0xc0, 0x56, 0x4b, 0xab, 0x4f, 0xbc, 0x91, 0x66, 0x6e, 0x9d, 0xef, 0x9b, 0x97, 0xfc, 0xe3,
      0x4f, 0x79, 0x67, 0x89, 0xba, 0xa4, 0x80, 0x82, 0xd1, 0x22, 0xee, 0x42, 0xc5, 0xa7, 0x2e,
      0x5a, 0x51, 0x10, 0xff, 0xf7, 0x01, 0x87, 0x34, 0x7b, 0x66};

    reverse(secret_u.begin(), secret_u.end());
    reverse(seed_u.begin(), seed_u.end());
    reverse(label_u.begin(), label_u.end());
    reverse(output_u.begin(), output_u.end());

    Integer secret(128, secret_u.data());
    Integer seed(128, seed_u.data());
    Integer label(80, label_u.data());
    Integer output(800, output_u.data());

    Integer res;
    PRF prf;
    HMAC_SHA256 hmac;
    prf.init(hmac, secret);
    prf.compute(hmac, res, 800, secret, label, seed);

    //assert(output == res);
    if ((output == res).reveal<bool>(PUBLIC)) {
        cout << "test passed!" << endl;
    } else {
        cout << "test failed!" << endl;
    }
    cout << hmac.compression_calls() << endl;
}

void opt_prf_test() {
    vector<unsigned char> secret_u = {0x9b, 0xbe, 0x43, 0x6b, 0xa9, 0x40, 0xf0, 0x17,
                                      0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71, 0xdb, 0x35};
    vector<unsigned char> seed_u = {0xa0, 0xba, 0x9f, 0x93, 0x6c, 0xda, 0x31, 0x18,
                                    0x27, 0xa6, 0xf7, 0x96, 0xff, 0xd5, 0x19, 0x8c};
    vector<unsigned char> label_u = {0x74, 0x65, 0x73, 0x74, 0x20,
                                     0x6c, 0x61, 0x62, 0x65, 0x6c};

    vector<unsigned char> output_u = {
      0xe3, 0xf2, 0x29, 0xba, 0x72, 0x7b, 0xe1, 0x7b, 0x8d, 0x12, 0x26, 0x20, 0x55, 0x7c, 0xd4,
      0x53, 0xc2, 0xaa, 0xb2, 0x1d, 0x07, 0xc3, 0xd4, 0x95, 0x32, 0x9b, 0x52, 0xd4, 0xe6, 0x1e,
      0xdb, 0x5a, 0x6b, 0x30, 0x17, 0x91, 0xe9, 0x0d, 0x35, 0xc9, 0xc9, 0xa4, 0x6b, 0x4e, 0x14,
      0xba, 0xf9, 0xaf, 0x0f, 0xa0, 0x22, 0xf7, 0x07, 0x7d, 0xef, 0x17, 0xab, 0xfd, 0x37, 0x97,
      0xc0, 0x56, 0x4b, 0xab, 0x4f, 0xbc, 0x91, 0x66, 0x6e, 0x9d, 0xef, 0x9b, 0x97, 0xfc, 0xe3,
      0x4f, 0x79, 0x67, 0x89, 0xba, 0xa4, 0x80, 0x82, 0xd1, 0x22, 0xee, 0x42, 0xc5, 0xa7, 0x2e,
      0x5a, 0x51, 0x10, 0xff, 0xf7, 0x01, 0x87, 0x34, 0x7b, 0x66};

    reverse(secret_u.begin(), secret_u.end());
    //reverse(seed_u.begin(), seed_u.end());
    //reverse(label_u.begin(), label_u.end());
    reverse(output_u.begin(), output_u.end());

    Integer secret(128, secret_u.data(), ALICE);
    unsigned char* seed = seed_u.data();
    unsigned char* label = label_u.data();

    Integer output(800, output_u.data());

    Integer res;
    PRF prf;
    HMAC_SHA256 hmac;
    prf.init(hmac, secret);
    prf.opt_compute(hmac, res, 800, secret, label, label_u.size(), seed, seed_u.size(), true,
                    true);

    //assert(output == res);
    if ((output == res).reveal<bool>(PUBLIC)) {
        cout << "test passed!" << endl;
    } else {
        cout << "test failed" << endl;
    }
    cout << hmac.compression_calls() << endl;
}

void opt_prf_circ_test() {
    vector<unsigned char> secret_u = {0x9b, 0xbe, 0x43, 0x6b, 0xa9, 0x40, 0xf0, 0x17,
                                      0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71, 0xdb, 0x35,
                                      0x9b, 0xbe, 0x43, 0x6b, 0xa9, 0x40, 0xf0, 0x17,
                                      0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71, 0xdb, 0x35};

    unsigned char label[] = {"master key"};
    unsigned char seed[] = {
      "0123456789012345678901234567890123456789012345678901234567890123"};
    size_t sec_len = 256;
    size_t label_len = 10;
    size_t seed_len = 64;
    Integer secret(sec_len, secret_u.data(), ALICE);
    PRF prf;
    Integer res;
    HMAC_SHA256 hmac;

    prf.init(hmac, secret);
    //prf.opt_compute(hmac, res, 48 * 8, secret, label, label_len, seed, seed_len, true, true);
    prf.opt_compute(hmac, res, 96, secret, label, label_len, seed, seed_len, true, true);

    cout << "Call Compression Function: " << hmac.compression_calls() << " times" << endl;
    cout << "Call HMAC-SHA256: " << prf.hmac_calls() << " times" << endl;
}

void handshake_prf_circ_test() {
    vector<unsigned char> pms_u = {0x9b, 0xbe, 0x43, 0x6b, 0xa9, 0x40, 0xf0, 0x17,
                                   0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71, 0xdb, 0x35,
                                   0x9b, 0xbe, 0x43, 0x6b, 0xa9, 0x40, 0xf0, 0x17,
                                   0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71, 0xdb, 0x35};
    size_t pms_len = 256;

    unsigned char mk_label[] = {"master key"};
    size_t mk_label_len = 10;

    unsigned char ke_label[] = {"key expansion"};
    size_t ke_label_len = 13;

    unsigned char cfin_label[] = {"client finished"};
    size_t cfin_label_len = 15;

    unsigned char sfin_label[] = {"server finished"};
    size_t sfin_label_len = 15;

    unsigned char mk_seed[] = {
      "0123456789012345678901234567890123456789012345678901234567890123"};
    size_t mk_seed_len = 64;

    unsigned char ke_seed[] = {
      "2345678901234567890123456789012301234567890123456789012345678901"};
    size_t ke_seed_len = 64;

    unsigned char ctau[] = {"01234567890123456789012345678901"};
    size_t ctau_len = 32;

    unsigned char stau[] = {"67890123456789010123456789012345"};
    size_t stau_len = 32;

    PRF prf;
    Integer pms(pms_len, pms_u.data(), ALICE);

    HMAC_SHA256 hmac;

    Integer ms;
    auto start = emp::clock_start();
    prf.init(hmac, pms);
    prf.opt_compute(hmac, ms, 384, pms, mk_label, mk_label_len, mk_seed, mk_seed_len, true,
                    true);

    Integer sk;
    prf.init(hmac, ms);
    prf.opt_compute(hmac, sk, 448, ms, ke_label, ke_label_len, ke_seed, ke_seed_len, true,
                    true);

    Integer ucfin;
    prf.opt_compute(hmac, ucfin, 96, ms, cfin_label, cfin_label_len, ctau, ctau_len, true,
                    true);

    Integer usfin;
    prf.opt_compute(hmac, usfin, 96, ms, sfin_label, sfin_label_len, stau, stau_len, true,
                    true);

    cout << "time: " << emp::time_from(start) << " us" << endl;
    cout << "Call Compression Function: " << hmac.compression_calls() << " times" << endl;
    cout << "Call HMAC-SHA256: " << prf.hmac_calls() << " times" << endl;
}

void nopt_handshake_prf_circ_test() {
    vector<unsigned char> pms_u = {0x9b, 0xbe, 0x43, 0x6b, 0xa9, 0x40, 0xf0, 0x17,
                                   0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71, 0xdb, 0x35,
                                   0x9b, 0xbe, 0x43, 0x6b, 0xa9, 0x40, 0xf0, 0x17,
                                   0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71, 0xdb, 0x35};
    size_t pms_len = 256;

    unsigned char mk_label[] = {"master key"};
    // size_t mk_label_len = 10;

    unsigned char ke_label[] = {"key expansion"};
    // size_t ke_label_len = 13;

    unsigned char cfin_label[] = {"client finished"};
    // size_t cfin_label_len = 15;

    unsigned char sfin_label[] = {"server finished"};
    // size_t sfin_label_len = 15;

    unsigned char mk_seed[] = {
      "0123456789012345678901234567890123456789012345678901234567890123"};
    // size_t mk_seed_len = 64;

    unsigned char ke_seed[] = {
      "2345678901234567890123456789012301234567890123456789012345678901"};
    // size_t ke_seed_len = 64;

    unsigned char ctau[] = {"01234567890123456789012345678901"};
    // size_t ctau_len = 32;

    unsigned char stau[] = {"67890123456789010123456789012345"};
    // size_t stau_len = 32;

    PRF prf;
    Integer pms(pms_len, pms_u.data(), ALICE);

    HMAC_SHA256 hmac;

    Integer ms;
    auto start = emp::clock_start();
    prf.init(hmac, pms);
    // prf.opt_compute(hmac, ms, 384, pms, mk_label, mk_label_len, mk_seed, mk_seed_len, true,
    //                 true);
    Integer mk_label_int(mk_label, PUBLIC);
    Integer mk_seed_int(mk_seed, PUBLIC);
    prf.compute(hmac, ms, 384, pms, mk_label_int, mk_seed_int);

    Integer sk;
    prf.init(hmac, ms);
    // prf.opt_compute(hmac, sk, 320, ms, ke_label, ke_label_len, ke_seed, ke_seed_len, true,
    //                 true);
    Integer ke_label_int(ke_label, PUBLIC);
    Integer ke_seed_int(ke_seed, PUBLIC);
    prf.compute(hmac, sk, 448, ms, ke_label_int, ke_seed_int);

    Integer ucfin;
    Integer cfin_label_int(cfin_label, PUBLIC);
    Integer cfin_seed_int(ctau, PUBLIC);
    prf.compute(hmac, ucfin, 96, ms, cfin_label_int, cfin_seed_int);
    // prf.opt_compute(hmac, ucfin, 96, ms, cfin_label, cfin_label_len, ctau, ctau_len, true,
    //                 true);

    Integer usfin;
    Integer sfin_label_int(sfin_label, PUBLIC);
    Integer sfin_seed_int(stau, PUBLIC);
    prf.compute(hmac, usfin, 96, ms, sfin_label_int, sfin_seed_int);
    // prf.opt_compute(hmac, usfin, 96, ms, sfin_label, sfin_label_len, stau, stau_len, true,
    //                 true);

    cout << "time: " << emp::time_from(start) << " us" << endl;
    cout << "Call Compression Function: " << hmac.compression_calls() << " times" << endl;
    cout << "Call HMAC-SHA256: " << prf.hmac_calls() << " times" << endl;
}

void zk_gc_prf_test(int party) {
    vector<unsigned char> secret_u = {0x9b, 0xbe, 0x43, 0x6b, 0xa9, 0x40, 0xf0, 0x17,
                                      0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71, 0xdb, 0x35};
    vector<unsigned char> seed_u = {0xa0, 0xba, 0x9f, 0x93, 0x6c, 0xda, 0x31, 0x18,
                                    0x27, 0xa6, 0xf7, 0x96, 0xff, 0xd5, 0x19, 0x8c};
    vector<unsigned char> label_u = {0x74, 0x65, 0x73, 0x74, 0x20,
                                     0x6c, 0x61, 0x62, 0x65, 0x6c};

    vector<unsigned char> output_u = {
      0xe3, 0xf2, 0x29, 0xba, 0x72, 0x7b, 0xe1, 0x7b, 0x8d, 0x12, 0x26, 0x20, 0x55, 0x7c, 0xd4,
      0x53, 0xc2, 0xaa, 0xb2, 0x1d, 0x07, 0xc3, 0xd4, 0x95, 0x32, 0x9b, 0x52, 0xd4, 0xe6, 0x1e,
      0xdb, 0x5a, 0x6b, 0x30, 0x17, 0x91, 0xe9, 0x0d, 0x35, 0xc9, 0xc9, 0xa4, 0x6b, 0x4e, 0x14,
      0xba, 0xf9, 0xaf, 0x0f, 0xa0, 0x22, 0xf7, 0x07, 0x7d, 0xef, 0x17, 0xab, 0xfd, 0x37, 0x97,
      0xc0, 0x56, 0x4b, 0xab, 0x4f, 0xbc, 0x91, 0x66, 0x6e, 0x9d, 0xef, 0x9b, 0x97, 0xfc, 0xe3,
      0x4f, 0x79, 0x67, 0x89, 0xba, 0xa4, 0x80, 0x82, 0xd1, 0x22, 0xee, 0x42, 0xc5, 0xa7, 0x2e,
      0x5a, 0x51, 0x10, 0xff, 0xf7, 0x01, 0x87, 0x34, 0x7b, 0x66};

    reverse(secret_u.begin(), secret_u.end());
    //reverse(seed_u.begin(), seed_u.end());
    //reverse(label_u.begin(), label_u.end());
    reverse(output_u.begin(), output_u.end());

    Integer secret(128, secret_u.data(), ALICE);
    unsigned char* seed = seed_u.data();
    unsigned char* label = label_u.data();

    Integer output(800, output_u.data());

    Integer res;
    PRF prf;
    HMAC_SHA256 hmac;
    prf.init(hmac, secret);
    prf.opt_compute(hmac, res, 800, secret, label, label_u.size(), seed, seed_u.size(), true,
                    true);

    //assert(output == res);
    if ((output == res).reveal<bool>(PUBLIC)) {
        cout << "test passed!" << endl;
    } else {
        cout << "test failed" << endl;
    }

    switch_to_zk();
    secret = Integer(128, secret_u.data(), ALICE);
    prf.init(hmac, secret);
    prf.opt_compute(hmac, res, 800, secret, label, label_u.size(), seed, seed_u.size(), true,
                    true, true);
    if ((output == res).reveal<bool>(PUBLIC)) {
        cout << "zk test passed!" << endl;
    } else {
        cout << "zk test failed" << endl;
    }

    // if (prf.pub_M.size() != prf.zk_sec_M.size()) {
    //     error("error!\n");
    // } else {
    //     for (int i = 0; i < prf.pub_M.size(); i++) {
    //         Integer M(256, prf.pub_M[i], PUBLIC);
    //         Integer diff = prf.zk_sec_M[i] ^ M;
    //         check_zero<NetIO>(diff, party);
    //     }
    // }

    // for (int i = 0; i < hmac.DIGLEN; i++) {
    //     Integer iv(32, hmac.iv_in_hash[i], PUBLIC);
    //     Integer diff = hmac.zk_iv_in_hash[i] ^ iv;
    //     check_zero<NetIO>(diff, party);
    // }
    sync_zk_gc<NetIO>();
    switch_to_gc();
}

int threads = 1;
int main(int argc, char** argv) {
    // setup_plain_prot(false, "");
    // prf_test();
    // opt_prf_test();
    // finalize_plain_prot();

    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
    BoolIO<NetIO>* ios[threads];
    for (int i = 0; i < threads; i++)
        ios[i] = new BoolIO<NetIO>(io, party == ALICE);
    //setup_backend(io, party);

    //prf_test();
    //opt_prf_test();
    //opt_prf_circ_test();
    //handshake_prf_circ_test();
    //cout << "AND gates: " << dec << CircuitExecution::circ_exec->num_and() << endl;
    //finalize_backend();

    setup_protocol(io, ios, threads, party);
    zk_gc_prf_test(party);
    finalize_protocol();

    for (int i = 0; i < CheatRecord::message.size(); i++) {
        cout << CheatRecord::message[i] << endl;
    }
    bool cheat = CheatRecord::cheated();
    if (cheat)
        error("cheat!\n");
    delete io;
    for (int i = 0; i < threads; i++) {
        delete ios[i];
    }
}