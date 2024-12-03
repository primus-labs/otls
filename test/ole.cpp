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
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
    BoolIO<NetIO>* ios[threads];
    for (int i = 0; i < threads; i++)
        ios[i] = new BoolIO<NetIO>(io, party == ALICE);

    auto start = emp::clock_start();
    setup_protocol<NetIO>(io, ios, threads, party);
    cout << "protocol setup: " << emp::time_from(start) << " us" << endl;
    //setup_backend(io, party);

    auto prot = (PADOParty<NetIO>*)(ProtocolExecution::prot_exec);
    IKNP<NetIO>* cot = prot->ot;
    ole_test<NetIO>(io, cot, party);

    finalize_protocol();

    bool cheat = CheatRecord::cheated();
    if (cheat)
        error("cheat!\n");
    //finalize_backend();

    delete io;
    for (int i = 0; i < threads; i++) {
        delete ios[i];
    }
    return 0;
    // int port, party;
    // const int num_ole = 6;
    // parse_party_and_port(argv, &party, &port);
    // NetIO* ios[1];
    // for (int i = 0; i < 1; ++i)
    //     ios[i] = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port + i);

    // setup_backend(ios[0], party);

    // //    FerretCOT<NetIO> * cot = new FerretCOT<NetIO>(party, 1, ios, true, true, ferret_b13);

    // auto prot = (PADOParty<NetIO>*)(ProtocolExecution::prot_exec);
    // IKNP<NetIO>* cot = prot->ot;
    // vector<BIGNUM*> in, out;
    // in.resize(num_ole);
    // out.resize(num_ole);
    // // BIGNUM * q = BN_new(), *n19 = BN_new();
    // // BN_CTX * ctx = BN_CTX_new();
    // // BN_set_bit(q, 255);
    // // BN_set_word(n19, 19);
    // // BN_sub(q, q, n19);//2^255-19

    // EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    // BIGNUM* q = BN_new();
    // BN_CTX* ctx = BN_CTX_new();
    // EC_GROUP_get_curve(group, q, NULL, NULL, ctx);

    // for (int i = 0; i < num_ole; ++i) {
    //     in[i] = BN_new();
    //     out[i] = BN_new();
    //     BN_rand(in[i], 256, 0, 0);
    //     BN_mod(in[i], in[i], q, ctx);
    // }

    // auto t1 = clock_start();
    // OLE<NetIO> ole(ios[0], cot, q, 256);
    // cout << "setup" << time_from(t1) << endl;
    // t1 = clock_start();
    // ole.compute(out, in);
    // cout << "execute" << time_from(t1) << endl;

    // BIGNUM* tmp = BN_new();
    // BIGNUM* tmp2 = BN_new();
    // unsigned char arr[1000];
    // if (party == ALICE) {
    //     for (int i = 0; i < num_ole; ++i) {
    //         int length = BN_bn2bin(in[i], arr);
    //         ios[0]->send_data(&length, sizeof(int));
    //         ios[0]->send_data(arr, length);

    //         length = BN_bn2bin(out[i], arr);
    //         ios[0]->send_data(&length, sizeof(int));
    //         ios[0]->send_data(arr, length);
    //     }
    // } else {
    //     for (int i = 0; i < num_ole; ++i) {
    //         int length = -1;
    //         ios[0]->recv_data(&length, sizeof(int));
    //         ios[0]->recv_data(arr, length);
    //         BN_bin2bn(arr, length, tmp);

    //         ios[0]->recv_data(&length, sizeof(int));
    //         ios[0]->recv_data(arr, length);
    //         BN_bin2bn(arr, length, tmp2);

    //         BN_mod_mul(tmp, tmp, in[i], q, ctx);
    //         BN_mod_sub(tmp, tmp, out[i], q, ctx);
    //         BN_mod_sub(tmp, tmp, tmp2, q, ctx);
    //         if (!BN_is_zero(tmp))
    //             cout << "wrong!2\n";
    //     }
    // }
    // //    delete cot;
    // finalize_backend();
    // for (int i = 0; i < 1; ++i)
    //     delete ios[i];
}
