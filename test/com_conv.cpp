#include "protocol/com_conv.h"
#include "backend/backend.h"
#include "emp-zk/emp-zk.h"
#include "emp-ot/emp-ot.h"
#include <iostream>
#include "backend/switch.h"

using namespace std;
using namespace emp;

template <typename IO>
void com_conv_test(IO* io, COT<IO>* cot, int party) {
    // size_t array_len = 4 * 1024 * 8;
    size_t array_len = 128;
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM* q = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    //EC_GROUP_get_curve(group, q, NULL, NULL, ctx);
    BN_copy(q, EC_GROUP_get0_order(group));

    BIGNUM* sa = BN_new();
    BIGNUM* sb = BN_new();
    BIGNUM* s = BN_new();
    if (party == ALICE) {
        BN_rand_range(sa, EC_GROUP_get0_order(group));
        send_bn(io, sa);
        recv_bn(io, sb);
    } else {
        BN_rand_range(sb, EC_GROUP_get0_order(group));
        recv_bn(io, sa);
        send_bn(io, sb);
    }
    BN_mod_add(s, sa, sb, EC_GROUP_get0_order(group), ctx);
    EC_POINT* h = EC_POINT_new(group);
    EC_POINT_mul(group, h, s, NULL, NULL, ctx);

    PRG prg;
    //bool* val = new bool[array_len];
    unsigned char* val = new unsigned char[array_len / 8];
    prg.random_data(val, array_len / 8);
    //prg.random_bool(val, array_len);
    if (party == ALICE) {
        cout << "ALICE: ";
        for (int i = 0; i < array_len / 8; i++)
            cout << (int)val[i];
        cout << endl;
    }

    Integer input(array_len, val, ALICE);
    cout << "reveal: " << input.reveal<string>() << endl;
    vector<block> raw(array_len);
    for (int i = 0; i < raw.size(); i++) {
        raw[i] = input[i].bit;
        cout << getLSB(raw[i]);
    }
    cout << endl;

    size_t chunk_len = (array_len + BN_num_bits(q) - 1) / BN_num_bits(q);
    vector<EC_POINT*> coms;
    vector<BIGNUM*> rnds;

    coms.resize(chunk_len);
    rnds.resize(chunk_len);

    for (int i = 0; i < chunk_len; i++) {
        coms[i] = EC_POINT_new(group);
        rnds[i] = BN_new();
    }
    ComConv<NetIO> conv(io, cot, q);
    PedersenComm pc(h, group);
    if (party == ALICE) {
        auto start = emp::clock_start();
        bool res = conv.compute_com_send(coms, raw, pc);
        if (res) {
            cout << "ALICE check passed" << endl;
        } else {
            cout << "ALICE check failed" << endl;
        }
        cout << "ALICE time: " << emp::time_from(start) << " us" << endl;
    } else {
        auto start = emp::clock_start();
        bool res = conv.compute_com_recv(coms, rnds, raw, pc);
        if (res) {
            cout << "BOB check passed" << endl;
        } else {
            cout << "BOB check failed" << endl;
        }
        cout << "BOB time: " << emp::time_from(start) << " us" << endl;
    }
}

void zk_test(int party) {
    PRG prg;
    size_t a;
    prg.random_data(&a, sizeof(size_t));
    if (party == ALICE)
        cout << "ALICE: " << a << endl;
    else
        cout << "BOB:" << a << endl;
    Integer ia(64, a, ALICE);
    cout << ia.reveal<string>() << endl;

    for (int i = 0; i < 64; i++) {
        cout << getLSB(ia[i].bit);
    }
    cout << endl;
}
const int threads = 1;
int main(int argc, char** argv) {
    // int port, party;
    // parse_party_and_port(argv, &party, &port);
    // NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
    // BoolIO<NetIO>* ios[threads];
    // for (int i = 0; i < threads; i++)
    //     ios[i] = new BoolIO<NetIO>(io, party == ALICE);

    // setup_protocol<NetIO>(io, ios, threads, party);
    // switch_to_zk();

    // FerretCOT<NetIO>* cot;
    // if (party == ALICE) {
    //     cot = ((ZKProver<NetIO>*)(zk_prot_buf))->ostriple->ferret;
    // } else {
    //     cot = ((ZKVerifier<NetIO>*)(zk_prot_buf))->ostriple->ferret;
    // }

    // com_conv_test<NetIO>(io, cot, party);
    // //zk_test(party);
    // finalize_protocol();

    // bool cheat = CheatRecord::cheated();
    // if (cheat)
    //     error("cheat!\n");

    // delete io;
    // for (int i = 0; i < threads; i++) {
    //     delete ios[i];
    // }
    // return 0;




        int port, party;
    size_t array_len = 4 * 1024 * 8;
    parse_party_and_port(argv, &party, &port);
    NetIO* ios[1];
    for (int i = 0; i < 1; ++i)
        ios[i] = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port + i);

    setup_backend(ios[0], party);

    // BIGNUM *q = BN_new(), *n19 = BN_new();
    // BN_CTX* ctx = BN_CTX_new();
    // BN_set_bit(q, 255);
    // BN_set_word(n19, 19);
    // BN_sub(q, q, n19); //2^255-19

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM* q = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    //EC_GROUP_get_curve(group, q, NULL, NULL, ctx);
    BN_copy(q, EC_GROUP_get0_order(group));

    BIGNUM* sa = BN_new();
    BIGNUM* sb = BN_new();
    BIGNUM* s = BN_new();
    if (party == ALICE) {
        BN_rand_range(sa, EC_GROUP_get0_order(group));
        send_bn(ios[0], sa);
        recv_bn(ios[0], sb);
    } else {
        BN_rand_range(sb, EC_GROUP_get0_order(group));
        recv_bn(ios[0], sa);
        send_bn(ios[0], sb);
    }
    BN_mod_add(s, sa, sb, EC_GROUP_get0_order(group), ctx);
    EC_POINT* h = EC_POINT_new(group);
    EC_POINT_mul(group, h, s, NULL, NULL, ctx);
    //EC_POINT_copy(h, EC_GROUP_get0_generator(group));

    auto prot = (PADOParty<NetIO>*)(ProtocolExecution::prot_exec);
    IKNP<NetIO>* cot = prot->ot;

    ComConv<NetIO> conv(ios[0], cot, q);
    PedersenComm pc(h, group);

    bool* val = new bool[array_len];
    vector<block> raw(array_len);

    size_t chunk_len = (array_len + BN_num_bits(q) - 1) / BN_num_bits(q);
    vector<EC_POINT*> coms;
    vector<BIGNUM*> rnds;

    coms.resize(chunk_len);
    rnds.resize(chunk_len);

    for (int i = 0; i < chunk_len; i++) {
        coms[i] = EC_POINT_new(group);
        rnds[i] = BN_new();
    }

    if (party == ALICE) {
        //cot->send_cot(raw.data(), array_len);
        ios[0]->recv_bool(val, array_len);
        ios[0]->recv_block(raw.data(), array_len);
        for (int i = 0; i < array_len; i++) {
            if (val[i])
                raw[i] ^= cot->Delta;
        }

        auto start = emp::clock_start();
        bool res = conv.compute_com_send(coms, raw, pc);
        if (res) {
            cout << "ALICE check passed" << endl;
        } else {
            cout << "ALICE check failed" << endl;
        }
        cout << "ALICE time: " << emp::time_from(start) << " us" << endl;
    } else {
        PRG prg;
        prg.random_bool(val, array_len);
		//cot->recv_cot(raw.data(), val, array_len);
        ios[0]->send_bool(val, array_len);

        prg.random_block(raw.data(), array_len);
        for (int i = 0; i < array_len; i++) {
            uint64_t* tmp = (uint64_t*)&raw[i];
            tmp[0] = tmp[0] << 1;
            if (val[i])
                raw[i] = set_bit(raw[i], 0);
            // cout << raw[i] << endl;
        }
        ios[0]->send_block(raw.data(), array_len);

        auto start = emp::clock_start();
        bool res = conv.compute_com_recv(coms, rnds, raw, pc);
        if (res) {
            cout << "BOB check passed" << endl;
        } else {
            cout << "BOB check failed" << endl;
        }
        cout << "BOB time: " << emp::time_from(start) << " us" << endl;
    }
    
    finalize_backend();
    for (int i = 0; i < 1; ++i)
        delete ios[i];
}