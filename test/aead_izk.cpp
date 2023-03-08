#include "cipher/aead_izk.h"
#include "emp-tool/emp-tool.h"
#include "cipher/utils.h"
#include "backend/backend.h"
#include "backend/switch.h"
#include "backend/checkzero.h"

using namespace emp;

template <typename IO>
void it_mac_add_test(IO* io, int party) {
    Integer a(128, 1, ALICE);
    block A = integer_to_block(a);

    switch_to_zk();
    Integer aa(128, 1, ALICE);
    Integer b(128, &A, ALICE);

    itmac_hom_add_check<IO>(aa, b, party, A);
    sync_zk_gc<IO>();
    switch_to_gc();

    PRG prg;
    int len = 4;
    unsigned char* buf = new unsigned char[len];
    unsigned char* buff = new unsigned char[len];
    prg.random_data(buf, len);

    Integer ac(len * 8, buf, ALICE);

    integer_to_chars(buff, ac);

    switch_to_zk();
    Integer aac(len * 8, buf, ALICE);
    reverse(buff, buff + len);
    Integer bc(len * 8, buff, ALICE);

    itmac_hom_add_check<IO>(aac, bc, party, buff, len);
    sync_zk_gc<IO>();
    switch_to_gc();

    delete[] buf;
    delete[] buff;
}

const int threads = 1;

int main(int argc, char** argv) {
    int party, port;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
    BoolIO<NetIO>* ios[threads];
    for (int i = 0; i < threads; i++)
        ios[i] = new BoolIO<NetIO>(io, party == ALICE);

    setup_protocol<NetIO>(io, ios, threads, party);
    it_mac_add_test<NetIO>(io, party);
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