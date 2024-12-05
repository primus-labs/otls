#ifndef Online_PRIMUS_GEN_H__
#define Online_PRIMUS_GEN_H__
#include "backend/primus_party.h"

/* Offline evaluator (ALICE) of the protocol */
template <typename IO>
class OnlinePrimusGen : public PrimusParty<IO> {
   public:
    OnlineHalfGateGen<IO>* gc;
    PRG prg;
    Hash hash;
    OnlinePrimusGen(IO* io, OnlineHalfGateGen<IO>* gc, IKNP<IO>* in_ot = nullptr)
        : PrimusParty<IO>(io, ALICE, in_ot) {
        this->gc = gc;
        if (in_ot == nullptr) {
            bool delta_bool[128];
            block_to_bool(delta_bool, gc->delta);
            this->ot->setup_send(delta_bool);
        }
    }
    void set_seed(block seed) { prg = PRG(&seed); }

    void feed(block* label, int party, const bool* b, int length) {
        block* label2 = new block[length];
        prg.random_block(label, length);
        for (int i = 0; i < length; ++i)
            label2[i] = label[i] ^ gc->delta;

        if (party == ALICE) {
            for (int i = 0; i < length; ++i) {
                if (b[i])
                    this->io->send_block(label2 + i, 1);
                else
                    this->io->send_block(label + i, 1);
            }
        } else {
            this->ot->send(label, label2, length);
        }
        delete[] label2;
    }

    //reveal with check
    void reveal(bool* b, int party, const block* label, int length) {
        for (int i = 0; i < length; ++i) {
            bool lsb = getLSB(label[i]);
            if (party == BOB) {
                this->io->send_data(&lsb, 1);
                b[i] = false;
            } else if (party == ALICE) {
                bool tmp;
                this->io->recv_data(&tmp, 1);
                b[i] = (tmp != lsb);
            }
        }
        if (party == PUBLIC) {
            this->io->recv_data(b, length);
            unsigned char tmp[Hash::DIGEST_SIZE];
            unsigned char recv_hash[Hash::DIGEST_SIZE];
            block blk = zero_block;
            this->io->recv_data(recv_hash, Hash::DIGEST_SIZE);
            for (int i = 0; i < length; i++) {
                blk = b[i] ? label[i] ^ (gc->delta) : label[i];
                hash.put_block(&blk, 1);
            }

            hash.digest(tmp);
            if (memcmp(tmp, recv_hash, Hash::DIGEST_SIZE) != 0)
                error("Evaluator cheated in revealing msgs!\n");
        }
    }
};
#endif
