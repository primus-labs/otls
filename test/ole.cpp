#include "backend/backend.h"
#include "backend/ole.h"
#include "emp-zk/emp-zk.h"
#include "backend/switch.h"
#include <iostream>

using namespace std;
using namespace emp;

template <typename IO>
void ole_test(IO* io, COT<IO>* cot, int party) {
    const int num_ole = 6;
    vector<BIGNUM*> in, out;
    in.resize(num_ole);
    out.resize(num_ole);

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM* q = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    EC_GROUP_get_curve(group, q, NULL, NULL, ctx);

    for (int i = 0; i < num_ole; ++i) {
        in[i] = BN_new();
        out[i] = BN_new();
        BN_rand(in[i], 256, 0, 0);
        BN_mod(in[i], in[i], q, ctx);
    }

    auto t1 = clock_start();
    OLE<IO> ole(io, cot, q, 256);
    cout << "setup" << time_from(t1) << endl;
    t1 = clock_start();
    ole.compute(out, in);
    cout << "execute" << time_from(t1) << endl;

    BIGNUM* tmp = BN_new();
    BIGNUM* tmp2 = BN_new();
    unsigned char arr[1000];
    if (party == ALICE) {
        for (int i = 0; i < num_ole; ++i) {
            int length = BN_bn2bin(in[i], arr);
            io->send_data(&length, sizeof(int));
            io->send_data(arr, length);

            length = BN_bn2bin(out[i], arr);
            io->send_data(&length, sizeof(int));
            io->send_data(arr, length);
        }
    } else {
        for (int i = 0; i < num_ole; ++i) {
            int length = -1;
            io->recv_data(&length, sizeof(int));
            io->recv_data(arr, length);
            BN_bin2bn(arr, length, tmp);

            io->recv_data(&length, sizeof(int));
            io->recv_data(arr, length);
            BN_bin2bn(arr, length, tmp2);

            BN_mod_mul(tmp, tmp, in[i], q, ctx);
            BN_mod_sub(tmp, tmp, out[i], q, ctx);
            BN_mod_sub(tmp, tmp, tmp2, q, ctx);
            if (!BN_is_zero(tmp))
                cout << "wrong!2\n";
        }
    }
}

const int threads = 1;
int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io[threads];
    BoolIO<NetIO>* ios[threads];
    for (int i = 0; i < threads; i++) {
        io[i] = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port + i);
        ios[i] = new BoolIO<NetIO>(io[i], party == ALICE);
    }

    auto start = emp::clock_start();
    setup_protocol<NetIO>(io[0], ios, threads, party);
    cout << "protocol setup: " << emp::time_from(start) << " us" << endl;

    auto prot = (PrimusParty<NetIO>*)(ProtocolExecution::prot_exec);
    IKNP<NetIO>* cot = prot->ot;
    ole_test<NetIO>(io[0], cot, party);

    finalize_protocol();

    bool cheat = CheatRecord::cheated();
    if (cheat)
        error("cheat!\n");

    for (int i = 0; i < threads; i++) {
        delete ios[i];
        delete io[i];
    }
    return 0;
}
