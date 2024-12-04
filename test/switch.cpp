#include "backend/switch.h"
#include "backend/backend.h"
#include <emp-zk/emp-zk.h>
#include "emp-tool/emp-tool.h"

using namespace emp;

void switch_test() {
    Integer a(32, 1, ALICE);
    Integer b(32, 2, ALICE);

    std::cout << (a + b).reveal<uint32_t>(PUBLIC) << endl;
}

const int threads = 1;

int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
    BoolIO<NetIO>* ios[threads];
    for (int i = 0; i < threads; i++)
        ios[i] = new BoolIO<NetIO>(io, party == ALICE);

    setup_protocol<NetIO>(io, ios, threads, party);
    switch_test();

    switch_to_zk();
    switch_test();

    sync_zk_gc<NetIO>();

    switch_to_gc();
    switch_test();
    switch_to_zk();

    switch_test();
    sync_zk_gc<NetIO>();

    switch_to_gc();
    switch_test();

    finalize_protocol();
    bool cheat = CheatRecord::cheated();
    if (cheat)
        error("cheat!\n");
        
    delete io;
    for (int i = 0; i < threads; i++) {
        delete ios[i];
    }
}
