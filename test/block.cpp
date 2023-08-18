#include "emp-tool/emp-tool.h"
#include "emp-ot/emp-ot.h"
#include <iostream>
#include "cipher/utils.h"

using namespace std;
using namespace emp;

void clmul_test() {
    // PRG prg;
    // block* b = new block[4];
    // // b[0] = zero_block;
    // // b[1] = zero_block;
    // // b[2] = zero_block;
    // // b[3] = zero_block;

    // prg.random_block(b, 4);

    // auto start = emp::clock_start();
    // mul128(b[0], b[1], &b[2], &b[3]);
    // mul128(b[1], b[2], &b[3], &b[0]);
    // mul128(b[2], b[3], &b[0], &b[1]);
    // mul128(b[3], b[0], &b[1], &b[2]);
    // // for (int i = 0; i < 1000000; i++)
    // //     mul128(b[(i) % 4], b[(i + 1) % 4], &b[(i + 2) % 4], &b[(i + 3) % 4]);

    // cout << "time: " << emp::time_from(start) * 250 << " ns" << endl;
    // cout << b[0] << endl;
    // cout << b[1] << endl;
    // cout << b[2] << endl;
    // cout << b[3] << endl;
    // delete[] b;
    block x = makeBlock(0x7b5b546573745665, 0x63746f725d53475d);
    block y = makeBlock(0x4869285368617929, 0x5b477565726f6e5d);
    block res1 = zero_block;
    block res2 = zero_block;
    block res3 = zero_block;
    block res4 = x ^ y;
    mul128(x, y, &res1, &res2);
    //gfmul(x, y, &res3);
    res3 = mulBlock(x, y);
    cout << "x: " << x << endl;
    cout << "y: " << y << endl;
    cout << "no reduce 1: " << res1 << endl;
    cout << "no reduce 2: " << res2 << endl;
    cout << "gfmul : " << res3 << endl;
    cout << "xor : " << res4 << endl;
    // cout << getLSB(x) << endl;
    // cout << getLSB(y) << endl;
    // cout << getLSB(res3) << endl;

    block res5 = zero_block;
    block res6 = zero_block;
    uint64_t exp = 0;
    PRG prg;
    prg.random_data(&exp, 8);

    auto start = emp::clock_start();
    for (int i = 0; i < 1000; i++)
        res5 = powBlock(x, 10);
    cout << "time pow: " << emp::time_from(start) << endl;

    start = emp::clock_start();
    for (int i = 0; i < 1000; i++)
        res6 = invBlock(x);
    cout << "time inv: " << emp::time_from(start) << endl;

    cout << "x: " << x << endl;
    cout << "power_10: " << res5 << endl;
    cout << "inverse : " << res6 << endl;
    block iden = mulBlock(x, res6);
    cout << "identity: " << iden << endl;
    cout << set_bit(zero_block, 127) << endl;
    cout << "lsb : " << getLSB(set_bit(zero_block, 127)) << endl;
    block x_2 = zero_block;
    x_2 = mulBlock(x, x);
    cout << "x^2: " << x_2 << endl;

    block x_sqaure = powBlock(x, 2);
    cout << "x square: " << x_sqaure << endl;

    block make_x = makeBlock(0x7b5b546573745665, 0x63746f725d53475d);
    cout << "make_x: " << make_x << endl;

    AES_KEY aes;
    block key = zero_block;
    block blks[16];
    for (int i = 0; i < 8; i++) {
        blks[i] = zero_block;
    }

    start = emp::clock_start();
    for (long long i = 0; i < 10000000000; i++) {
        AES_set_encrypt_key(key, &aes);
    }
    cout << "set key time: " << emp::time_from(start) << " ps" << endl;

    start = emp::clock_start();
    for (int i = 0; i < 8; i++) {
        AES_ecb_encrypt_blks<1>(&key, &aes);
    }
    cout << "enc one block time: " << emp::time_from(start) << " ps" << endl;

    start = emp::clock_start();
    for (int i = 0; i < 1000; i++) {
        AES_ecb_encrypt_blks<16>(blks, &aes);
    }
    cout << "enc many blocks time: " << emp::time_from(start) << " ns" << endl;
}

void aes_test() {
    AES_KEY key[2];
    block blks[4];
    blks[0] = zero_block;
    blks[1] = all_one_block;
    blks[2] = zero_block;
    blks[3] = all_one_block;

    AES_set_encrypt_key(zero_block, &key[0]);
    AES_set_encrypt_key(all_one_block, &key[1]);

    ParaEnc<2, 2>(blks, key);

    // AES_ecb_encrypt_blks<1>(&msg, &key);
    // cout << msg << endl;
    for (int i = 0; i < 4; i++) {
        cout << blks[i] << endl;
    }
}

void hash_test() {
    CRH crh;
    cout << crh.H(all_one_block) << endl;
    CCRH ccrh;
    cout << ccrh.H(all_one_block) << endl;
    TCCRH tccrh;
    cout << tccrh.H(all_one_block, 1) << endl;

    cout << "sigma(ones): " << sigma(all_one_block) << endl;
}

template <typename IO>
void ggm_test(IO* io) {
    size_t depth = 1 << 25;
    SPCOT_Sender<IO> sps(io, depth);
    block* k0 = new block[depth - 1];
    block* k1 = new block[depth - 1];
    block* ggm_tree_mem = new block[1 << (depth - 1)];

    auto start = emp::clock_start();
    sps.ggm_tree_gen(k0, k1, ggm_tree_mem);
    cout << "time: " << emp::time_from(start) << " us" << endl;

    delete[] k0;
    delete[] k1;
    delete[] ggm_tree_mem;
}

template <typename IO>
void lpn_test(IO* io, int party, int threads) {
    int64_t n = 10000000;
    int64_t k = 588160;
    ThreadPool* pool = new ThreadPool(threads);
    LpnF2<IO, 10> lpn(party, n, k, pool, io, threads);

    block* nn = new block[n];
    block* kk = new block[k];
    PRG prg;
    prg.random_block(nn, n);
    prg.random_block(kk, k);

    auto start = emp::clock_start();
    lpn.compute(nn, kk);
    cout << "time: " << emp::time_from(start) << " us" << endl;

    delete[] nn;
    delete[] kk;
    delete pool;
}

int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
    lpn_test<NetIO>(io, party, 8);
    //ggm_test<NetIO>(io);
}
// int main() {
//     // clmul_test();
//     aes_test();
//     // hash_test();
//     return 0;
// }