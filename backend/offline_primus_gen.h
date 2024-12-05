#ifndef Offline_PRIMUS_GEN_H__
#define Offline_PRIMUS_GEN_H__
#include "offline_primus_party.h"
#include "offline_hg_gen.h"

/* Offline generator (ALICE) of the protocol */
template <typename IO>
class OfflinePrimusGen : public OfflinePrimusParty {
   public:
    IO* io;
    OfflineHalfGateGen<IO>* gc;
    block seed;
    PRG prg;

    OfflinePrimusGen(IO* io, OfflineHalfGateGen<IO>* gc) : OfflinePrimusParty(ALICE) {
        this->io = io;
        this->gc = gc;
        PRG().random_block(&seed, 1);
        prg = PRG(&seed);
    }

    void feed(block* label, int party, const bool* b, int length) {
        prg.random_block(label, length);
    }

    void reveal(bool* b, int party, const block* label, int length) {
        if (party == PUBLIC)
            for (int i = 0; i < length; ++i) {
                bool lsb = getLSB(label[i]);
                this->io->send_data(&lsb, 1);
            }
    }
};
#endif
