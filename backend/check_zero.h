#ifndef _CHECK_ZERO_H
#define _CHECK_ZERO_H
#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-zk.h"
#include "compat/primus_compat.h"  // FULLPORT: Integer alias + getLSB/from_bool

using namespace emp;

// FULLPORT: the old fork absorbed the MAC/key block of the authenticated-bit to be
// proven zero into ZKProver/Verifier's `ostriple->auth_helper->hash` (the output MAC
// accumulator); at finalize the prover sends the digest, the verifier compares, and on
// mismatch it rejects. The upstream emp-zk-bool folds this into
// ZKBoolBase::auth_hash -- prover/verifier share the same field, and it is exactly the
// transcript checked by verify_output/finalize_macs (zk_bool_{prover,verifier}.h:
// mismatch -> error()).
// So both sides uniformly call `get_bool_backend()->auth_hash.put_block(...)`, with no party branch.
// Security I5/I2: zero wire MAC==key (val=0) -> digest matches; non-zero wire MAC=key^Delta -> digest mismatches -> hard reject.

template <typename IO>
inline void check_zero(const block* blk, size_t length, int party) {
    get_bool_backend()->auth_hash.put_block(blk, length);
}

template <typename IO>
inline void check_zero(const Integer& input, int party) {
    // FULLPORT: input[i] (operator[]) now returns a Bit_T temporary; take the
    // address of the wire block from the .bits storage (a stable lvalue) instead.
    for (size_t i = 0; i < (size_t)input.size(); i++)
        get_bool_backend()->auth_hash.put_block(&input.bits[i].label, 1);
}

/* For the caller, must ensure that T is a fixed size */
// data should be the same for ALICE and BOB.
template <typename IO, typename T>
inline void check_zero(const Integer& input, const T* data, size_t len, int party) {
    if (input.size() != len * sizeof(T) * 8)
        error("inconsistent length!\n");
    bool* tmp = new bool[input.size()];
    if (party == ALICE) {
        for (size_t i = 0; i < (size_t)input.size(); i++)
            tmp[i] = getLSB(input.bits[i].label);

        T* expected_data = new T[len];
        from_bool(tmp, expected_data, len * sizeof(T) * 8);

        if (memcmp(expected_data, data, len) != 0)
            error("opened data is not consistent in ALICE side!\n");
        delete[] expected_data;
    }

    Integer expected_input(len * sizeof(T) * 8, data, PUBLIC);
    check_zero<IO>(expected_input ^ input, party);

    delete[] tmp;
}
#endif
