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

void zk_gc_prf_test(int party, bool flag = false) {
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
    if (flag) {
        switch_to_zk();
        secret = Integer(128, secret_u.data(), ALICE);
        output = Integer(800, output_u.data());
        prf.init(hmac, secret);
        prf.opt_compute(hmac, res, 800, secret, label, label_u.size(), seed, seed_u.size(),
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
}

int threads = 1;
int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
    BoolIO<NetIO>* ios[threads];
    for (int i = 0; i < threads; i++)
        ios[i] = new BoolIO<NetIO>(io, party == ALICE);

    auto start = emp::clock_start();
    auto rounds = io->rounds;
    setup_protocol(io, ios, threads, party, true);
    cout << "setup rounds: " << io->rounds << endl;

    rounds = io->rounds;
    zk_gc_prf_test(party);
    cout << "offline rounds: " << io->rounds - rounds << endl;

    rounds = io->rounds;
    cout << "offline time: " << emp::time_from(start) << " us" << endl;
    auto comm = io->counter;
    cout << "offline comm: " << comm << endl;

    switch_to_online<NetIO>(party);

    start = emp::clock_start();
    zk_gc_prf_test(party, true);
    cout << "online rounds: " << io->rounds - rounds << endl;
    cout << "online time: " << emp::time_from(start) << " us" << endl;
    if (party == ALICE)
        cout << "ALICE online comm: " << io->counter - comm << endl;
    else
        cout << "BOB online comm: " << io->counter - comm << endl;

    finalize_protocol();
    bool cheat = CheatRecord::cheated();
    if (cheat)
        error("cheat!\n");
    delete io;
    for (int i = 0; i < threads; i++) {
        delete ios[i];
    }
}