#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-zk.h"
#include <iostream>

using namespace std;
using namespace emp;

bool compare(Integer& in, size_t value) {
    size_t len = (in.size() > sizeof(size_t) * 8) ? in.size() : sizeof(size_t) * 8;
    Integer ivalue(len, value, PUBLIC);

    Bit res = in.geq(ivalue);
    return res.reveal();
}

const int threads = 1;
int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
    BoolIO<NetIO>* ios[threads];
    for (int i = 0; i < threads; i++)
        ios[i] = new BoolIO<NetIO>(io, party == ALICE);

    setup_zk_bool<BoolIO<NetIO>>(ios, threads, party);
    Integer in(64, 11, ALICE);
    size_t value = 10;
    bool res = compare(in, value);
    cout << "res: " << res << endl;

    bool cheat = finalize_zk_bool<BoolIO<NetIO>>();
    if (cheat)
        error("cheat!\n");

    delete io;
    for (int i = 0; i < threads; i++) {
        delete ios[i];
    }
    return 0;
}