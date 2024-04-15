#ifndef _CHECK_ZERO_H
#define _CHECK_ZERO_H
#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-zk.h"

using namespace emp;

template <typename IO>
inline void check_zero(const block* blk, size_t length, int party) {
    if (party == ALICE) {
        (((ZKProver<IO>*)(ProtocolExecution::prot_exec))->ostriple->auth_helper->hash)
          .put_block(blk, length);
    } else {
        (((ZKVerifier<IO>*)(ProtocolExecution::prot_exec))->ostriple->auth_helper->hash)
          .put_block(blk, length);
    }
}

template <typename IO>
inline void check_zero(const Integer& input, int party) {
    if (party == ALICE) {
        for (size_t i = 0; i < input.size(); i++) {
            (((ZKProver<IO>*)(ProtocolExecution::prot_exec))->ostriple->auth_helper->hash)
              .put_block(&input[i].bit, 1);
        }
    } else {
        for (size_t i = 0; i < input.size(); i++) {
            (((ZKVerifier<IO>*)(ProtocolExecution::prot_exec))->ostriple->auth_helper->hash)
              .put_block(&input[i].bit, 1);
        }
    }
}

/*ujnss typefix: for the caller, must ensure that T is a fixed size*/
// data should be the same for ALICE and BOB.
template <typename IO, typename T>
inline void check_zero(const Integer& input, const T* data, size_t len, int party) {
    if (input.size() != len * sizeof(T) * 8)
        error("inconsistent length!\n");
    bool* tmp = new bool[input.size()];
    if (party == ALICE) {
        for (size_t i = 0; i < input.size(); i++)
            tmp[i] = getLSB(input[i].bit);

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
