#ifndef PRIMUS_BN_UTILS_H__
#define PRIMUS_BN_UTILS_H__

#include <openssl/bn.h>
#include "emp-tool/emp-tool.h"
using namespace emp;

/* Hash the 128-bit block into a large field with a ccrh hasher */
inline void H(BIGNUM* out, block b, BIGNUM* q, BN_CTX* ctx, CCRH& ccrh) {
    block arr[2];
    arr[0] = b ^ makeBlock(0, 1);
    arr[1] = b ^ makeBlock(0, 2);
    ccrh.H<2>(arr, arr);

    BN_bin2bn((unsigned char*)arr, 32, out);
    BN_mod(out, out, q, ctx);
}

/* Send a big integer with IO */
template <typename IO>
inline void send_bn(IO* io, BIGNUM* bn, Hash* hash = nullptr) {
    unsigned char arr[1000];
    uint32_t length = BN_bn2bin(bn, arr);
    io->send_data(&length, sizeof(uint32_t));
    io->send_data(arr, length);
    if (hash != nullptr)
        hash->put(arr, length);
}

/* Receive a big integer with IO */
template <typename IO>
inline void recv_bn(IO* io, BIGNUM* bn, Hash* hash = nullptr) {
    unsigned char arr[1000];
    uint32_t length = -1;
    io->recv_data(&length, sizeof(uint32_t));
    io->recv_data(arr, length);
    if (hash != nullptr)
        hash->put(arr, length);
    BN_bin2bn(arr, length, bn);
}

/* Garbling an AND gate with half gates*/
inline void garble_gate_garble_halfgates(block LA0,
                                         block A1,
                                         block LB0,
                                         block B1,
                                         block* out0,
                                         block* out1,
                                         block delta,
                                         block* table,
                                         uint64_t idx,
                                         const AES_KEY* key) {
    long pa = getLSB(LA0);
    long pb = getLSB(LB0);
    block tweak1, tweak2;
    block HLA0, HA1, HLB0, HB1;
    block tmp, W0;

    tweak1 = makeBlock(2 * idx, (uint64_t)0);
    tweak2 = makeBlock(2 * idx + 1, (uint64_t)0);

    {
        block masks[4], keys[4];

        keys[0] = sigma(LA0) ^ tweak1;
        keys[1] = sigma(A1) ^ tweak1;
        keys[2] = sigma(LB0) ^ tweak2;
        keys[3] = sigma(B1) ^ tweak2;
        memcpy(masks, keys, sizeof keys);
        AES_ecb_encrypt_blks(keys, 4, key);
        HLA0 = keys[0] ^ masks[0];
        HA1 = keys[1] ^ masks[1];
        HLB0 = keys[2] ^ masks[2];
        HB1 = keys[3] ^ masks[3];
    }

    table[0] = HLA0 ^ HA1;
    table[0] = table[0] ^ (select_mask[pb] & delta);
    W0 = HLA0;
    W0 = W0 ^ (select_mask[pa] & table[0]);
    tmp = HLB0 ^ HB1;
    table[1] = tmp ^ LA0;
    W0 = W0 ^ HLB0;
    W0 = W0 ^ (select_mask[pb] & tmp);

    *out0 = W0;
    *out1 = *out0 ^ delta;
}

/* Check the block is zero */
inline bool isZero(const block* b) { return _mm_testz_si128(*b, *b) > 0; }

/* Check the block is one */
inline bool isOne(const block* b) {
    __m128i neq = _mm_xor_si128(*b, all_one_block);
    return _mm_testz_si128(neq, neq) > 0;
}

/* Evaluating an AND gate with half gates*/
inline void garble_gate_eval_halfgates(
  block A, block B, block* out, const block* table, uint64_t idx, const AES_KEY* key) {
    block HA, HB, W;
    int sa, sb;
    block tweak1, tweak2;

    sa = getLSB(A);
    sb = getLSB(B);

    tweak1 = makeBlock(2 * idx, (long)0);
    tweak2 = makeBlock(2 * idx + 1, (long)0);

    {
        block keys[2];
        block masks[2];

        keys[0] = sigma(A) ^ tweak1;
        keys[1] = sigma(B) ^ tweak2;
        masks[0] = keys[0];
        masks[1] = keys[1];
        AES_ecb_encrypt_blks(keys, 2, key);
        HA = keys[0] ^ masks[0];
        HB = keys[1] ^ masks[1];
    }

    W = HA ^ HB;
    W = W ^ (select_mask[sa] & table[0]);
    W = W ^ (select_mask[sb] & table[1]);
    W = W ^ (select_mask[sb] & A);

    *out = W;
}

#endif // PRIMUS_BN_UTILS_H__
