#include "emp-tool/emp-tool.h"
#include "backend/backend.h"
#include "cipher/prf.h"
#include "cipher/hmac_sha256.h"
#include "backend/switch.h"
#include "backend/check_zero.h"

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

    if ((output == res).reveal<bool>(PUBLIC)) {
        cout << "test passed!" << endl;
    } else {
        cout << "test failed!" << endl;
    }
    cout << hmac.compression_calls() << endl;
}

void opt_prf_test() {
    vector<unsigned char> secret_u = {
      0xb1, 0xbb, 0x9a, 0x9a, 0x98, 0x2e, 0x6d, 0x6d, 0x6b, 0x2a, 0x46, 0xc3,
      0x80, 0x19, 0x94, 0x1e, 0x31, 0x66, 0x63, 0x49, 0x72, 0x24, 0x49, 0xcf,
      0x61, 0x01, 0x4c, 0x2b, 0xd1, 0xc1, 0x2c, 0xe5, 0xd6, 0x23, 0xc2, 0x03,
      0x75, 0x9d, 0x4d, 0x60, 0x9e, 0x1a, 0xaa, 0xf1, 0x2e, 0x52, 0x77, 0x6f};
    vector<unsigned char> seed_u = {
      0xf3, 0xce, 0x67, 0x46, 0x1d, 0x7f, 0x88, 0x0b, 0x35, 0x02, 0x59, 0xdc, 0x67,
      0xd1, 0xe3, 0x18, 0x13, 0xa0, 0x24, 0x9d, 0xd9, 0x68, 0xd3, 0x43, 0x44, 0x4f,
      0x57, 0x4e, 0x47, 0x52, 0x44, 0x01, 0xeb, 0xf5, 0x1a, 0x10, 0x78, 0x55, 0x03,
      0x25, 0x22, 0xda, 0x84, 0x31, 0xbd, 0x3f, 0x37, 0x71, 0x4b, 0x0d, 0x82, 0x25,
      0x2a, 0x9f, 0x6c, 0x6c, 0x79, 0x6c, 0xf7, 0xda, 0xd5, 0x4d, 0xa5, 0x84};

    vector<unsigned char> label_u = {0x6B, 0x65, 0x79, 0x20, 0x65, 0x78, 0x70,
                                     0x61, 0x6E, 0x73, 0x69, 0x6F, 0x6E};
    vector<unsigned char> output_u = {
      0xf9, 0xee, 0xad, 0x8d, 0x05, 0xd5, 0xfb, 0x1d, 0xfb, 0x62, 0x5a, 0x67, 0xcf, 0xa0,
      0x78, 0x4f, 0x34, 0xaf, 0x34, 0xac, 0xd7, 0x7c, 0x23, 0x15, 0xbf, 0x98, 0xd7, 0x4e,
      0xea, 0x9c, 0x68, 0x9e, 0xbf, 0x0d, 0x54, 0x88, 0x38, 0x90, 0xf2, 0xa3, 0x7a, 0x17,
      0x44, 0x3e, 0xb6, 0x8c, 0x46, 0x77, 0xdc, 0x84, 0xaa, 0x21, 0x85, 0x00, 0x36, 0x3b};

    reverse(secret_u.begin(), secret_u.end());
    reverse(output_u.begin(), output_u.end());

    Integer secret(48 * 8, secret_u.data(), ALICE);
    unsigned char* seed = seed_u.data();
    unsigned char* label = label_u.data();

    Integer output(56 * 8, output_u.data());

    Integer res;
    PRF prf;
    HMAC_SHA256 hmac;
    prf.init(hmac, secret);
    prf.opt_compute(hmac, res, 40 * 8, secret, label, label_u.size(), seed, seed_u.size(),
                    true, true);
    if ((output == res).reveal<bool>(PUBLIC)) {
        cout << "test passed!" << endl;
    } else {
        cout << "test failed" << endl;
    }
    cout << hmac.compression_calls() << endl;
    Integer iv, client_write_key, server_write_key;
    iv.bits.insert(iv.bits.end(), res.bits.begin(), res.bits.begin() + 8 * 8);
    server_write_key.bits.insert(server_write_key.bits.begin(), res.bits.begin() + 8 * 8,
                                 res.bits.begin() + 8 * 8 + 16 * 8);

    client_write_key.bits.insert(client_write_key.bits.end(),
                                 res.bits.begin() + 8 * 8 + 16 * 8,
                                 res.bits.begin() + 8 * 8 + 16 * 8 * 2);
    unsigned char iv_oct[8], iv_c[4], iv_s[4], c_key[16], s_key[16];

    server_write_key.reveal(s_key, PUBLIC);
    client_write_key.reveal(c_key, PUBLIC);
    iv.reveal(iv_oct, PUBLIC);

    reverse(s_key, s_key + 16);
    reverse(c_key, c_key + 16);
    reverse(iv_oct, iv_oct + 8);

    memcpy(iv_c, iv_oct, 4);
    memcpy(iv_s, iv_oct + 4, 4);

    cout << "server_write_key: ";
    for (int i = 0; i < 16; i++) {
        cout << hex << (int)s_key[i] << " ";
    }
    cout << endl;

    cout << "client_write_key: ";
    for (int i = 0; i < 16; i++) {
        cout << hex << (int)c_key[i] << " ";
    }
    cout << endl;

    cout << "iv_server: ";
    for (int i = 0; i < 4; i++) {
        cout << hex << (int)iv_s[i] << " ";
    }
    cout << endl;

    cout << "iv_client: ";
    for (int i = 0; i < 4; i++) {
        cout << hex << (int)iv_c[i] << " ";
    }
    cout << endl;
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

    unsigned char ke_label[] = {"key expansion"};

    unsigned char cfin_label[] = {"client finished"};

    unsigned char sfin_label[] = {"server finished"};

    unsigned char mk_seed[] = {
      "0123456789012345678901234567890123456789012345678901234567890123"};

    unsigned char ke_seed[] = {
      "2345678901234567890123456789012301234567890123456789012345678901"};

    unsigned char ctau[] = {"01234567890123456789012345678901"};

    unsigned char stau[] = {"67890123456789010123456789012345"};

    PRF prf;
    Integer pms(pms_len, pms_u.data(), ALICE);

    HMAC_SHA256 hmac;

    Integer ms;
    auto start = emp::clock_start();
    prf.init(hmac, pms);
    Integer mk_label_int(mk_label, PUBLIC);
    Integer mk_seed_int(mk_seed, PUBLIC);
    prf.compute(hmac, ms, 384, pms, mk_label_int, mk_seed_int);

    Integer sk;
    prf.init(hmac, ms);
    Integer ke_label_int(ke_label, PUBLIC);
    Integer ke_seed_int(ke_seed, PUBLIC);
    prf.compute(hmac, sk, 448, ms, ke_label_int, ke_seed_int);

    Integer ucfin;
    Integer cfin_label_int(cfin_label, PUBLIC);
    Integer cfin_seed_int(ctau, PUBLIC);
    prf.compute(hmac, ucfin, 96, ms, cfin_label_int, cfin_seed_int);

    Integer usfin;
    Integer sfin_label_int(sfin_label, PUBLIC);
    Integer sfin_seed_int(stau, PUBLIC);
    prf.compute(hmac, usfin, 96, ms, sfin_label_int, sfin_seed_int);

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
    reverse(output_u.begin(), output_u.end());

    Integer secret(128, secret_u.data(), ALICE);
    unsigned char* seed = seed_u.data();
    unsigned char* label = label_u.data();

    Integer output(800, output_u.data());

    Integer res;
    PRF prf;
    HMAC_SHA256 hmac;
    prf.init(hmac, secret);
    prf.opt_rounds_compute(hmac, res, 800, secret, label, label_u.size(), seed, seed_u.size(),
                           true, true);

    if ((output == res).reveal<bool>(PUBLIC)) {
        cout << "test passed!" << endl;
    } else {
        cout << "test failed" << endl;
    }

    switch_to_zk();
    res = Integer();
    secret = Integer(128, secret_u.data(), ALICE);
    output = Integer(800, output_u.data());
    prf.init(hmac, secret);
    prf.opt_rounds_compute(hmac, res, 800, secret, label, label_u.size(), seed, seed_u.size(),
                           true, true, true);
    if ((output == res).reveal<bool>(PUBLIC)) {
        cout << "zk test passed!" << endl;
    } else {
        cout << "zk test failed" << endl;
    }

    prf.prf_check<NetIO>(party);
    hmac.sha256_check<NetIO>(party);

    sync_zk_gc<NetIO>();
    switch_to_gc();
}

int threads = 4;
int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io[threads];
    BoolIO<NetIO>* ios[threads];
    for (int i = 0; i < threads; i++) {
        io[i] = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port + i);
        ios[i] = new BoolIO<NetIO>(io[i], party == ALICE);
    }

    setup_protocol(io[0], ios, threads, party);
    zk_gc_prf_test(party);
    finalize_protocol();

    bool cheat = CheatRecord::cheated();
    if (cheat)
        error("cheat!\n");
    for (int i = 0; i < threads; i++) {
        delete ios[i];
        delete io[i];
    }
}
