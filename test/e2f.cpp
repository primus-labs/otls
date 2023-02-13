#include "backend/backend.h"
#include "backend/ole.h"
#include "protocol/e2f.h"
#include <iostream>

using namespace std;
using namespace emp;

int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* ios[1];
    for (int i = 0; i < 1; ++i)
        ios[i] = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port + i);

    setup_backend(ios[0], party);

    //	FerretCOT<NetIO> * cot = new FerretCOT<NetIO>(party, 1, ios, true, true, ferret_b13);

    auto prot = (PADOParty<NetIO>*)(ProtocolExecution::prot_exec);
    IKNP<NetIO>* cot = prot->ot;

    // BIGNUM *q = BN_new(), *n19 = BN_new();
    // BN_set_bit(q, 255);
    // BN_set_word(n19, 19);
    // BN_sub(q, q, n19); //2^255-19

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM* q = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    EC_GROUP_get_curve(group, q, NULL, NULL, ctx);

    E2F<NetIO> e2f(ios[0], cot, q, 256);

    auto start = emp::clock_start();
    e2f.compute_offline(party);
    cout << "offline: " << emp::time_from(start) << " us" << endl;

    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();

    BN_rand(x, 256, 0, 0);
    BN_mod(x, x, q, ctx);
    BN_rand(y, 256, 0, 0);
    BN_mod(y, y, q, ctx);

    BIGNUM* out = BN_new();
    start = emp::clock_start();
    e2f.compute_online(out, x, y, party);
    cout << "online: " << emp::time_from(start) << " us" << endl;

    BIGNUM* xa = BN_new();
    BIGNUM* ya = BN_new();

    e2f.open(out, party);

    if (party == ALICE) {
        send_bn(ios[0], x);
        send_bn(ios[0], y);
    } else {
        recv_bn(ios[0], xa);
        recv_bn(ios[0], ya);

        BIGNUM* xba = BN_new();
        BN_mod_sub(xba, x, xa, q, ctx);
        BN_mod_inverse(xba, xba, q, ctx);

        BIGNUM* yba = BN_new();
        BN_mod_sub(yba, y, ya, q, ctx);
        BN_mod_mul(yba, yba, xba, q, ctx);

        BN_mod_sqr(yba, yba, q, ctx);
        BN_mod_sub(yba, yba, xa, q, ctx);
        BN_mod_sub(yba, yba, x, q, ctx);

        BN_mod_sub(out, out, yba, q, ctx);
        if (BN_is_zero(out)) {
            cout << "test passed!" << endl;
        } else {
            cout << "test failed!" << endl;
        }
        BN_free(xba);
        BN_free(yba);
    }

    BN_free(xa);
    BN_free(ya);
    BN_free(out);
    BN_free(x);
    BN_free(y);
    BN_free(q);
    BN_CTX_free(ctx);

    finalize_backend();

    for (int i = 0; i < 1; ++i)
        delete ios[i];
}