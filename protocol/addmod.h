#ifndef _ADDMOD_H_
#define _ADDMOD_H_
#include "emp-tool/emp-tool.h"
#include <openssl/bn.h>

using namespace std;
using namespace emp;

/* Compute the (a+b) mod Q circuit, where Q is a shared value */
inline void addmod(Integer& res, const Integer& a, const Integer& b, Integer& Q) {
    Integer aa(a);
    Integer bb(b);
    aa.bits.push_back(Bit(0, PUBLIC));
    bb.bits.push_back(Bit(0, PUBLIC));
    Integer c = aa + bb;

    c.bits.push_back(Bit(0, PUBLIC));
    Q.bits.push_back(Bit(0, PUBLIC));
    Q.bits.push_back(Bit(0, PUBLIC));

    Bit sel = c.geq(Q);
    res = c.select(sel, c - Q);
    res.bits.pop_back();
    res.bits.pop_back();
}

/* Compute the (a+b) mod q circuit */
inline void addmod(Integer& res, const Integer& a, const Integer& b, BIGNUM* q) {
    unsigned char* intq = new unsigned char[BN_num_bytes(q)];
    BN_bn2bin(q, intq);
    reverse(intq, intq + BN_num_bytes(q));

    Integer Q(BN_num_bytes(q) * 8, intq, PUBLIC);
    addmod(res, a, b, Q);

    delete[] intq;
}

#endif