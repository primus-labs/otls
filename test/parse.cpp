#include "backend/backend.h"
#include <iostream>
#include "backend/switch.h"
#include "backend/check_zero.h"

using namespace std;
using namespace emp;

void is_equal(Bit& res, const Integer a, const unsigned char b) {
    assert(a.size() == 8);
    Integer intb(8, b, PUBLIC);
    res = (a == intb);
}

// If select is true, choose a, else choose b
Integer select(Bit& selector, const Integer a, const Integer b) {
    assert(a.size() == b.size());
    Integer res(a.size(), 0, PUBLIC);
    Bit one(true, PUBLIC);
    Bit not_selector = one ^ selector;

    for (int i = 0; i < a.size(); i++) {
        res[i] = (selector & a[i]) ^ (not_selector & b[i]);
    }

    return res;
}

int threads = 1;
int main(int argc, char** argv) {
    int party, port;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);

    BoolIO<NetIO>* ios[threads];
    for (int i = 0; i < threads; i++)
        ios[i] = new BoolIO<NetIO>(io, party == ALICE);

    setup_protocol<NetIO>(io, ios, threads, party);

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
