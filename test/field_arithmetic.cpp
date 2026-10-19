#include "cipher/utils.h"
#include <cstdint>
#include <cstring>
#include <iostream>
#include <random>

// Bitwise multiplication in the reflected representation used by GHASH.
// The field identity is bit 127; shifting right multiplies by x, reducing
// modulo x^128 + x^7 + x^2 + x + 1 when bit 0 is shifted out.
static block reference_multiply(block a, block b) {
    uint64_t value[2], multiplier[2];
    std::memcpy(value, &a, sizeof(a));
    std::memcpy(multiplier, &b, sizeof(b));
    uint64_t result[2] = {0, 0};

    for (int bit = 127; bit >= 0; --bit) {
        if ((multiplier[bit / 64] >> (bit % 64)) & 1) {
            result[0] ^= value[0];
            result[1] ^= value[1];
        }
        const bool reduce = (value[0] & 1) != 0;
        value[0] = (value[0] >> 1) | (value[1] << 63);
        value[1] >>= 1;
        if (reduce)
            value[1] ^= UINT64_C(0xe100000000000000);
    }

    return makeBlock(result[1], result[0]);
}

static bool check_product(block a, block b) {
    block expected = reference_multiply(a, b);
    block actual = mulBlock(a, b);
    if (!cmpBlock(&actual, &expected, 1)) {
        std::cerr << "Reflected multiplication mismatch: " << a << " * " << b
                  << ", expected " << expected << ", got " << actual << '\n';
        return false;
    }
    return true;
}

int main() {
    // Every pair of basis vectors exercises multiplication and reduction at
    // all bit positions, including across the 32-bit and 64-bit SIMD lanes.
    for (int i = 0; i < 128; ++i)
        for (int j = 0; j < 128; ++j)
            if (!check_product(set_bit(zero_block, i), set_bit(zero_block, j)))
                return 1;

    const block identity = set_bit(zero_block, 127);
    const block edges[] = {
        zero_block, identity, set_bit(zero_block, 0), all_one_block,
        makeBlock(UINT64_C(0xaaaaaaaaaaaaaaaa), UINT64_C(0x5555555555555555)),
        makeBlock(UINT64_C(0x5555555555555555), UINT64_C(0xaaaaaaaaaaaaaaaa))
    };
    for (block a : edges)
        for (block b : edges)
            if (!check_product(a, b))
                return 1;

    std::mt19937_64 random(0x6f746c73);
    for (int i = 0; i < 1024; ++i) {
        const uint64_t a_high = random(), a_low = random();
        const uint64_t b_high = random(), b_low = random();
        if (!check_product(makeBlock(a_high, a_low), makeBlock(b_high, b_low)))
            return 1;
    }

    // Verify the helpers that consume mulBlock keep the same representation.
    const block h = makeBlock(UINT64_C(0x66e94bd4ef8a2c3b), UINT64_C(0x884cfa59ca342b2e));
    block power = identity;
    for (uint64_t exponent = 0; exponent < 16; ++exponent) {
        block actual = powBlock(h, exponent);
        if (!cmpBlock(&actual, &power, 1)) {
            std::cerr << "Field exponentiation mismatch at " << exponent << '\n';
            return 1;
        }
        power = reference_multiply(power, h);
    }
    block inverse_product = reference_multiply(h, invBlock(h));
    if (!cmpBlock(&inverse_product, &identity, 1)) {
        std::cerr << "Field inverse mismatch\n";
        return 1;
    }

    block input[] = {all_one_block, identity, h};
    block expected_hash = zero_block;
    for (block value : input)
        expected_hash = reference_multiply(expected_hash ^ value, h);
    block actual_hash = ghash(h, input, 3);
    if (!cmpBlock(&actual_hash, &expected_hash, 1)) {
        std::cerr << "GHASH mismatch\n";
        return 1;
    }

    std::cout << "Reflected field arithmetic passed\n";
    return 0;
}
