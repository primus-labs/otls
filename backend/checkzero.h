#ifndef _CHECK_ZERO_H
#define _CHECK_ZERO_H
#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-zk.h"

using namespace emp;

template <typename IO>
void check_zero(const block* blk, size_t length, int party) {
    if (party == ALICE) {
        (((ZKProver<IO>*)(ProtocolExecution::prot_exec))->ostriple->auth_helper->hash)
          .put_block(blk, length);
    } else {
        (((ZKVerifier<IO>*)(ProtocolExecution::prot_exec))->ostriple->auth_helper->hash)
          .put_block(blk, length);
    }
}

template <typename IO>
void check_zero(const Integer input, int party) {
    if (party == ALICE) {
        for (int i = 0; i < input.size(); i++) {
            (((ZKProver<IO>*)(ProtocolExecution::prot_exec))->ostriple->auth_helper->hash)
              .put_block(&input[i].bit, 1);
        }
    } else {
        for (int i = 0; i < input.size(); i++) {
            (((ZKVerifier<IO>*)(ProtocolExecution::prot_exec))->ostriple->auth_helper->hash)
              .put_block(&input[i].bit, 1);
        }
    }
}
#endif