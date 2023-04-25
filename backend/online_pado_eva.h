#ifndef Online_PADO_EVA_H__
#define Online_PADO_EVA_H__
#include "backend/pado_party.h"

template <typename IO>
class OnlinePADOEva : public PADOParty<IO> {
   public:
    OnlineHalfGateEva<IO>* gc;
    PRG prg;
    OnlinePADOEva(IO* io, OnlineHalfGateEva<IO>* gc, IKNP<IO>* in_ot = nullptr)
        : PADOParty<IO>(io, BOB, in_ot) {
        this->gc = gc;
        if (in_ot == nullptr) {
            this->ot->setup_recv();
            this->ot->Delta = zero_block;
        }
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
            if (party == BOB or party == PUBLIC) {
                this->io->recv_data(&tmp, 1);
                b[i] = (tmp != lsb);
            } else if (party == ALICE) {
                this->io->send_data(&lsb, 1);
                b[i] = false;
            }
        }
        if (party == PUBLIC)
            this->io->send_data(b, length);
    }
};

#endif // GARBLE_CIRCUIT_SEMIHONEST_H__