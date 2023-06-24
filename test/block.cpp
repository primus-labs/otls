#include "emp-tool/emp-tool.h"
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

int main() {
    clmul_test();
    return 0;
}