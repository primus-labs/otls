#ifndef Online_PADO_EVA_H__
#define Online_PADO_EVA_H__
#include "backend/pado_party.h"

template <typename IO>
class OnlinePADOEva : public PADOParty<IO> {
   public:
    OnlineHalfGateEva<IO>* gc;
    PRG prg;
    vector<bool> pub_values;
    vector<bool> pub_values2;
    vector<bool>* p_pub_values = nullptr;
    uint64_t reveal_counter = 0;
    uint64_t reveal_counter2 = 0;
    uint64_t* p_reveal_counter = nullptr;
    Hash hash;
    OnlinePADOEva(IO* io, OnlineHalfGateEva<IO>* gc, IKNP<IO>* in_ot = nullptr)
        : PADOParty<IO>(io, BOB, in_ot) {
        this->gc = gc;
        if (in_ot == nullptr) {
            this->ot->setup_recv();
            this->ot->Delta = zero_block;
        }
        p_pub_values = &pub_values;
        p_reveal_counter = &reveal_counter;
    }

    void feed(block* label, int party, const bool* b, int length) {
        if (party == ALICE)
            this->io->recv_block(label, length);
        else
            this->ot->recv(label, b, length);
    }

    void reveal(bool* b, int party, const block* label, int length) {
        for (int i = 0; i < length; ++i) {
            bool lsb = getLSB(label[i]), tmp;
            //if (party == BOB or party == PUBLIC) {
            if (party == BOB) {
                this->io->recv_data(&tmp, 1);
                b[i] = (tmp != lsb);
            } else if (party == ALICE) {
                this->io->send_data(&lsb, 1);
                b[i] = false;
            } else if (party == PUBLIC) {
                b[i] = ((*p_pub_values)[(*p_reveal_counter)++] != lsb);
            }
        }
        if (party == PUBLIC) {
            this->io->send_data(b, length);
            unsigned char tmp[Hash::DIGEST_SIZE];
            hash.hash_once(tmp, label, length * sizeof(block));
            this->io->send_data(tmp, Hash::DIGEST_SIZE);
        }
    }

    void switch_status() {
        gc->switch_status();
        if (gc->server_finish) {
            p_pub_values = &pub_values2;
            p_reveal_counter = &reveal_counter2;
        }
        else {
            p_pub_values = &pub_values;
            p_reveal_counter = &reveal_counter;
        }
    }
};

#endif // GARBLE_CIRCUIT_SEMIHONEST_H__
