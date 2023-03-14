#include "backend/check_zero.h"
#include "backend/switch.h"

using namespace emp;

template <typename IO>
void check_zero_test(int party) {
    int len = 10;
    unsigned char* data = new unsigned char[len];
    uint32_t* data2 = new uint32_t[len];
    //prg.random_data(data, len);
    for (int i = 0; i < len; i++) {
        data[i] = 0x11;
        data2[i] = 0x11223344;
    }

    Integer a(len * 8, data, ALICE);
    Integer b(len * 32, data2, ALICE);
    check_zero<IO>(a, data, len, party);
    check_zero<IO>(b, data2, len, party);
}

template <typename IO>
void gc_zk_check_test(int party) {
    Integer A(128, 2, ALICE);
    Integer z = A + A;
    uint32_t pz;
    pz = z.reveal<uint32_t>(PUBLIC);

    switch_to_zk();
    A = Integer(128, 2, ALICE);
    Integer z0 = A + A;
    Integer z1(128, 4, PUBLIC);
    check_zero<IO>(z0 ^ z1, party);

    sync_zk_gc<IO>();
    switch_to_gc();
}

const int threads = 1;

int main(int argc, char** argv) {
    int party, port;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
    BoolIO<NetIO>* ios[threads];
    for (int i = 0; i < threads; i++)
        ios[i] = new BoolIO<NetIO>(io, party == ALICE);
    // setup_zk_bool<BoolIO<NetIO>>(ios, threads, party);
    // check_zero_test<NetIO>(party);
    // bool cheat = finalize_zk_bool<BoolIO<NetIO>>();
    // if (cheat)
    //     error("cheat!\n");

    setup_protocol<NetIO>(io, ios, threads, party);
    //gc_zk_check_test<NetIO>(party);
    switch_to_zk();
    check_zero_test<NetIO>(party);
    sync_zk_gc<NetIO>();
    switch_to_gc();
    finalize_protocol();

    bool cheat = CheatRecord::cheated();
    if (cheat)
        error("cheat!\n");

    delete io;
    for (int i = 0; i < threads; i++) {
        delete ios[i];
    }
    return 0;
}