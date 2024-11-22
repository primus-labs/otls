#include "backend/backend.h"
#include "protocol/addmod.h"
#include "backend/switch.h"
#include <iostream>

using namespace std;

int threads = 1;
int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
    BoolIO<NetIO>* ios[threads];
    for (int i = 0; i < threads; i++)
        ios[i] = new BoolIO<NetIO>(io, party == ALICE);

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM* q = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    EC_GROUP_get_curve(group, q, NULL, NULL, ctx);

    setup_protocol(io, ios, threads, party, true);

    Integer a(BN_num_bytes(q) * 8, 0, ALICE);
    Integer b(BN_num_bytes(q) * 8, 0, BOB);
    Integer res;
    addmod(res, a, b, q);
    unsigned char tmp1[32];
    res.reveal(tmp1, PUBLIC);
    switch_to_online<NetIO>(party);

    unsigned char* achar = new unsigned char[32];
    unsigned char* bchar = new unsigned char[32];
    unsigned char* cchar = new unsigned char[32];

    BIGNUM* aint = BN_new();
    BIGNUM* bint = BN_new();
    BIGNUM* cint = BN_new();

    if (party == ALICE) {
        BN_rand(aint, 256, 0, 0);
        BN_mod(aint, aint, q, ctx);

        BN_bn2bin(aint, achar);

        io->send_data(achar, 32);
        io->recv_data(bchar, 32);

        unsigned char* aachar = new unsigned char[32];
        memcpy(aachar, achar, 32);
        reverse(aachar, aachar + 32);

        a = Integer(BN_num_bytes(q) * 8, aachar, ALICE);
        b = Integer(BN_num_bytes(q) * 8, 0, BOB);

        delete[] aachar;
    } else {
        BN_rand(bint, 256, 0, 0);
        BN_mod(bint, bint, q, ctx);

        BN_bn2bin(bint, bchar);

        io->recv_data(achar, 32);
        io->send_data(bchar, 32);

        unsigned char* bbchar = new unsigned char[32];
        memcpy(bbchar, bchar, 32);
        reverse(bbchar, bbchar + 32);

        a = Integer(BN_num_bytes(q) * 8, 0, ALICE);
        b = Integer(BN_num_bytes(q) * 8, bbchar, BOB);

        delete[] bbchar;
    }

    BN_bin2bn(achar, 32, aint);
    BN_bin2bn(bchar, 32, bint);
    BN_mod_add(cint, aint, bint, q, ctx);
    BN_bn2bin(cint, cchar);

    reverse(cchar, cchar + 32);

    addmod(res, a, b, q);
    unsigned char tmp[32];
    res.reveal(tmp, PUBLIC);

    int check = memcmp(tmp, cchar, 32);
    if (check == 0)
        cout << "test passed!" << endl;
    else
        cout << "test failed!" << endl;

    cout << "AND gates: " << dec << CircuitExecution::circ_exec->num_and() << endl;

    delete[] bchar;
    delete[] achar;
    delete[] cchar;
    BN_free(bint);
    BN_free(aint);
    BN_free(cint);
    BN_free(q);
    BN_CTX_free(ctx);
    finalize_backend();
    delete io;
}