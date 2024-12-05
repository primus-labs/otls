#ifndef PRIMUS_GEN_H__
#define PRIMUS_GEN_H__
#include "backend/primus_party.h"

/* The generator (ALICE) in the protocol */
template <typename IO>
class PrimusGen : public PrimusParty<IO> {
   public:
    OptHalfGateGen<IO>* gc;
    Hash hash;
    PrimusGen(IO* io, OptHalfGateGen<IO>* gc, IKNP<IO>* in_ot = nullptr)
        : PrimusParty<IO>(io, ALICE, in_ot) {
        this->gc = gc;
        if (in_ot == nullptr) {
            bool delta_bool[128];
            block_to_bool(delta_bool, gc->delta);
            this->ot->setup_send(delta_bool);
        }
        refill();
        block seed;
        PRG prg;
        prg.random_block(&seed, 1);
        this->io->send_block(&seed, 1);
        this->shared_prg.reseed(&seed);
    }

    void refill() {
        this->ot->send_cot(this->buf, this->batch_size);
        this->top = 0;
    }

    void feed(block* label, int party, const bool* b, int length) {
        if (party == ALICE) {
            this->shared_prg.random_block(label, length);
            for (int i = 0; i < length; ++i) {
                if (b[i])
                    label[i] = label[i] ^ gc->delta;
            }
        } else {
            if (length > this->batch_size) {
                this->ot->send_cot(label, length);
            } else {
                bool* tmp = new bool[length];
                if (length > this->batch_size - this->top) {
                    memcpy(label, this->buf + this->top,
                           (this->batch_size - this->top) * sizeof(block));
                    int filled = this->batch_size - this->top;
                    refill();
                    memcpy(label + filled, this->buf, (length - filled) * sizeof(block));
                    this->top = (length - filled);
                } else {
                    memcpy(label, this->buf + this->top, length * sizeof(block));
                    this->top += length;
                }

                this->io->recv_data(tmp, length);
                for (int i = 0; i < length; ++i)
                    if (tmp[i])
                        label[i] = label[i] ^ gc->delta;
                delete[] tmp;
            }
        }
    }

    //reveal with check
    void reveal(bool* b, int party, const block* label, int length) {
        for (int i = 0; i < length; ++i) {
            if (isOne(&label[i])) {
                b[i] = true;
            } else if (isZero(&label[i])) {
                b[i] = false;
            } else {
                bool lsb = getLSB(label[i]);
                if (party == BOB or party == PUBLIC) {
                    this->io->send_data(&lsb, 1);
                    b[i] = false;
                } else if (party == ALICE) {
                    bool tmp;
                    this->io->recv_data(&tmp, 1);
                    b[i] = (tmp != lsb);
                }
            }
        }
        if (party == PUBLIC) {
            this->io->recv_data(b, length);
            unsigned char tmp[Hash::DIGEST_SIZE];
            unsigned char recv_hash[Hash::DIGEST_SIZE];
            block blk = zero_block;
            this->io->recv_data(recv_hash, Hash::DIGEST_SIZE);
            for (int i = 0; i < length; i++) {
                blk = gc->is_public(label[i], PUBLIC)? label[i]: (b[i] ? label[i] ^ (gc->delta) : label[i]);
                hash.put_block(&blk, 1);
            }
            hash.digest(tmp);
            if (memcmp(tmp, recv_hash, Hash::DIGEST_SIZE) != 0)
                error("Evaluator cheated in revealing msgs!\n");
        }
    }
};
#endif
